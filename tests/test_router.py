import contextlib

import io

import logging
import requests

from typing import Iterator
from enum import IntEnum

import pytest
from mocket import Mocket, MocketEntry, mocketize
from mocket.mocket import MocketSocket, true_gethostbyname

import threading
import subprocess
import socket
import socks

from socks_router.models import (
    SOCKS_VERSION,
    Socks5Method,
    Socks5MethodSelectionRequest,
    Socks5MethodSelectionResponse,
    Socks5Command,
    Socks5Request,
    Socks5ReplyType,
    Socks5Reply,
    Socks5AddressType,
    Socks5Address,
    IPv4,
    IPv6,
    Host,
    UpstreamAddress,
    UpstreamScheme,
    Socks5State,
    SSHUpstream,
    Pattern,
    ApplicationContext,
    RetryOptions,
)
from socks_router.router import (
    create_socket,
    with_proxy,
    connect_remote,
    match_upstream,
    SocksRouter,
    SocksRouterRequestHandler,
)
from socks_router.utils import read_socket, write_socket, free_port

logger = logging.getLogger(__name__)


def ids(value) -> str:
    if isinstance(value, IntEnum):
        return value.name
    return f"{value}"


@pytest.fixture
def client(mocker):
    return mocker.Mock(socks.socksocket)


def describe_free_port():
    @mocketize(strict_mode=True)
    @pytest.mark.parametrize(
        "address,port",
        [
            ("", 12345),
            ("127.0.0.1", 12345),
        ],
    )
    def it_should_return_a_free_port(mocker, address: str, port: int):
        mocker.patch("socket.gethostbyname").side_effect = true_gethostbyname
        mocker.patch("mocket.mocket.MocketSocket._address", new_callable=mocker.PropertyMock).return_value = (
            address or "0.0.0.0",
            port,
        )

        Mocket.register(MocketEntry((address, 0), []))
        MocketSocket._address = (address or "0.0.0.0", port)
        assert free_port() == (address or "0.0.0.0", port)
        MocketSocket._address = None


def describe_create_socket():
    @pytest.mark.parametrize(
        "type",
        [Socks5AddressType.IPv4, Socks5AddressType.DOMAINNAME, Socks5AddressType.IPv6],
        ids=ids,
    )
    def it_should_create_the_socket(type):
        assert isinstance(create_socket(type), socks.socksocket)


def describe_with_proxy():
    @pytest.mark.parametrize("proxy_server", [IPv4("8.8.8.8", 443)], ids=ids)
    def it_should_work_with_proxy_server(client, proxy_server):
        with_proxy(client, proxy_server)
        client.set_proxy.assert_called_with(socks.SOCKS5, *proxy_server.sockaddr)

    def it_should_work_without_proxy_server(client):
        with_proxy(client, None)
        client.set_proxy.assert_not_called()


def describe_connect_remote():
    def it_should_connect_to_socket(mocker, client):
        mocker.patch("socks_router.router.create_socket").__enter__.return_value = client
        connect_remote(IPv4("127.0.0.1", 12345), logger=logger)


@contextlib.contextmanager
def daemonize(
    # NOTE: if we have to use server.address we have to bind with an actual address instead of 0.0.0.0 or ::
    address: str = "127.0.0.1",
    type: type[IPv4] | type[IPv6] | type[Host] = IPv4,
    handler: type = SocksRouterRequestHandler,
    **kwargs,
) -> Iterator[SocksRouter]:
    _, port = free_port("127.0.0.1")
    server = SocksRouter(
        (address, port),
        handler,
        address_family={IPv4: socket.AF_INET, IPv6: socket.AF_INET6, Host: socket.AF_INET}[type],
        **kwargs,
    )
    try:
        threading.Thread(target=server.serve_forever, name=server.context.name, daemon=True).start()
        yield server
    finally:
        server.shutdown()


def describe_match_upstream():
    @pytest.mark.parametrize(
        "routing_table,destination,upstream",
        [
            ({}, IPv4("127.0.0.1", 443), None),
            (
                {
                    UpstreamAddress(UpstreamScheme.SSH, IPv4("127.0.0.1", 22)): [],
                    UpstreamAddress(UpstreamScheme.SOCKS5, IPv4("127.0.0.1", 1080)): [Pattern(Host("*"))],
                    UpstreamAddress(UpstreamScheme.SOCKS5H, IPv4("127.0.0.1", 1080)): [],
                },
                IPv4("127.0.0.1", 443),
                UpstreamAddress(UpstreamScheme.SOCKS5, IPv4("127.0.0.1", 1080)),
            ),
        ],
        ids=ids,
    )
    def it_should_match_accordingly(routing_table, destination, upstream):
        assert match_upstream(routing_table, destination) == upstream


def describe_SocksRouter():
    @pytest.fixture(scope="session")
    def httpserver_listen_address():
        # must listen on ipv6 to work for both ipv4 and ipv6
        return ("::", 0)

    def when_used_with_empty_routing_table():
        @pytest.mark.parametrize("address_type,address", [(IPv4, "127.0.0.1"), (Host, "localhost"), (IPv6, "::1")])
        def it_should_transparently_go_through(httpserver, address_type, address):
            destination = address_type(address, httpserver.port)
            httpserver.expect_request("/").respond_with_json(mocked_response := {"foo": "bar"})
            # we use a server without routing table to be a pass-through socks5 server
            with daemonize(address, context=ApplicationContext("passthrough"), type=address_type) as passthrough:
                # using the pass-through server from client
                assert (
                    requests.get(
                        f"http://{destination}/",
                        proxies=dict.fromkeys(["http", "https"], f"socks5h://{passthrough.address}"),
                    ).json()
                    == mocked_response
                )

    def when_used_with_transparent_socks5_upstream():
        @pytest.mark.parametrize("address_type,address", [(IPv4, "127.0.0.1"), (Host, "localhost"), (IPv6, "::1")])
        @pytest.mark.parametrize("scheme", [UpstreamScheme.SOCKS5, UpstreamScheme.SOCKS5H])
        def it_should_relay_through_upstream(httpserver, scheme, address_type, address):
            destination = address_type(address, httpserver.port)
            httpserver.expect_request("/").respond_with_json(mocked_response := {"foo": "bar"})
            # we use a server without routing table to be a pass-through socks5 server
            with daemonize(address, context=ApplicationContext("passthrough"), type=address_type) as passthrough:
                # using the passthrough as catch-all
                context = ApplicationContext(
                    routing_table={
                        UpstreamAddress(scheme, passthrough.address): [Pattern(Host("*"))],
                    },
                )
                with daemonize(address, context=context, type=address_type) as proxy:
                    # using the proxy server from client
                    assert (
                        requests.get(
                            f"http://{destination}/",
                            proxies=dict.fromkeys(["http", "https"], f"socks5h://{proxy.address}"),
                        ).json()
                        == mocked_response
                    )
                    # re-request it to trigger reusing the upstream
                    assert (
                        requests.get(
                            f"http://{destination}/",
                            proxies=dict.fromkeys(["http", "https"], f"socks5h://{proxy.address}"),
                        ).json()
                        == mocked_response
                    )

    def when_used_with_ssh_upstream():
        @pytest.mark.parametrize("address_type,address", [(IPv4, "127.0.0.1"), (Host, "localhost"), (IPv6, "::1")])
        @pytest.mark.parametrize("proxy_address_type,proxy_address", [(IPv4, "127.0.0.1"), (Host, "localhost"), (IPv6, "::1")])
        def it_should_successfully_return_and_resuse_ssh_upstream_in_second_pass(
            httpserver, address_type, address, proxy_address_type, proxy_address
        ):
            destination = address_type(address, httpserver.port)
            httpserver.expect_request("/").respond_with_json(mocked_response := {"foo": "bar"})
            context = ApplicationContext(
                routing_table={
                    UpstreamAddress(UpstreamScheme.SSH, Host("localhost")): [Pattern(Host("*"))],
                },
                proxy_retry_options=RetryOptions(tries=10),
            )
            with daemonize(proxy_address, context=context, type=proxy_address_type) as proxy:
                # using the proxy server from client
                assert (
                    requests.get(
                        f"http://{destination}/",
                        proxies=dict.fromkeys(["http", "https"], f"socks5h://{proxy.address}"),
                        timeout=10,
                    ).json()
                    == mocked_response
                )
                # re-request it to trigger reusing the upstream
                assert (
                    requests.get(
                        f"http://{destination}/",
                        proxies=dict.fromkeys(["http", "https"], f"socks5h://{proxy.address}"),
                        timeout=10,
                    ).json()
                    == mocked_response
                )

        @pytest.mark.parametrize("address_type,address", [(IPv4, "127.0.0.1"), (Host, "localhost"), (IPv6, "::1")])
        def it_should_recreate_ssh_upstream_if_subprocess_is_dead(mocker, httpserver, address_type, address):
            destination = address_type(address, httpserver.port)
            httpserver.expect_request("/").respond_with_json(mocked_response := {"foo": "bar"})

            ssh_client = mocker.Mock(subprocess.Popen, stdout=io.StringIO(), stderr=io.StringIO())
            ssh_client.poll.return_value = 1

            upstream_address = UpstreamAddress(UpstreamScheme.SSH, Host("127.0.0.1"))
            original_upstream = SSHUpstream(ssh_client, upstream_address.address.with_port(-1))
            context = ApplicationContext(
                routing_table={
                    upstream_address: [Pattern(Host("*"))],
                },
                upstreams={
                    upstream_address: original_upstream,
                },
                proxy_retry_options=RetryOptions(tries=10),
            )
            with daemonize(address, type=address_type, context=context) as proxy:
                # using the proxy server from client
                assert (
                    requests.get(
                        f"http://{destination}/",
                        proxies=dict.fromkeys(["http", "https"], f"socks5h://{proxy.address}"),
                    ).json()
                    == mocked_response
                )
                ssh_client.poll.assert_called_with()
                assert context.upstreams[upstream_address] != original_upstream

        def it_should_not_explicitly_kill_ssh_client_if_dead_on_shutdown(mocker):
            ssh_client = mocker.Mock(subprocess.Popen, stdout=io.StringIO(), stderr=io.StringIO())
            upstream_address = UpstreamAddress(UpstreamScheme.SSH, Host("127.0.0.1", -1))
            upstream = SSHUpstream(ssh_client, upstream_address.address)
            # dead upstream
            ssh_client.poll.return_value = 1

            context = ApplicationContext(
                routing_table={
                    upstream_address: [],
                },
                upstreams={
                    upstream_address: upstream,
                },
            )
            with daemonize(context=context) as proxy:
                proxy.shutdown()

            ssh_client.kill.assert_not_called()

    def when_client_attempt_to_use_socks4():
        @pytest.mark.parametrize("address_type,address", [(IPv4, "127.0.0.1"), (Host, "localhost"), (IPv6, "::1")])
        def it_should_close_socket(httpserver, address_type, address):
            destination = address_type(address, httpserver.port)
            with daemonize(address, type=address_type) as proxy:
                with pytest.raises(
                    requests.exceptions.ConnectionError, match=r".*(Connection reset by peer|Connection closed unexpectedly).*"
                ):
                    requests.get(
                        f"http://{destination}/",
                        proxies=dict.fromkeys(["http", "https"], f"socks4://{proxy.address}"),
                    ).json()

    def when_client_attempt_to_use_unacceptable_methods():
        def it_should_reply_no_acceptable_methods():
            with daemonize() as proxy:
                with connect_remote(proxy.address) as client:
                    # handshake
                    write_socket(client, Socks5MethodSelectionRequest(SOCKS_VERSION, methods=[Socks5Method.USERNAME_PASSWORD]))
                    assert read_socket(client, Socks5MethodSelectionResponse) == Socks5MethodSelectionResponse(
                        SOCKS_VERSION, Socks5Method.NO_ACCEPTABLE_METHODS
                    )

    def when_client_attempt_to_use_command_other_than_connect():
        def it_should_reply_command_not_supported():
            with daemonize() as proxy:
                # handshake
                with connect_remote(proxy.address) as client:
                    # handshake
                    write_socket(
                        client, Socks5MethodSelectionRequest(SOCKS_VERSION, methods=[Socks5Method.NO_AUTHENTICATION_REQUIRED])
                    )
                    assert read_socket(client, Socks5MethodSelectionResponse) == Socks5MethodSelectionResponse(
                        SOCKS_VERSION, Socks5Method.NO_AUTHENTICATION_REQUIRED
                    )
                    # request
                    write_socket(
                        client,
                        Socks5Request(SOCKS_VERSION, Socks5Command.BIND, 0x00, Socks5Address.from_address(Host("localhost", 80))),
                    )
                    assert read_socket(client, Socks5Reply) == Socks5Reply(
                        SOCKS_VERSION,
                        Socks5ReplyType.COMMAND_NOT_SUPPORTED,
                        server_bound_address=Socks5Address.from_address(proxy.address),
                    )

    def when_client_attempt_to_access_unreachable_destination():
        @pytest.mark.parametrize(
            "url,reply",
            [
                # TLD invalid. is guarenteed to be failing in DNS resolution
                # SEE: https://www.rfc-editor.org/rfc/rfc6761#section-6.4
                (
                    "http://non-existent.invalid",
                    Socks5ReplyType.NETWORK_UNREACHABLE,
                ),
                (
                    "http://127.0.0.1:65535",
                    Socks5ReplyType.CONNECTION_REFUSED,
                ),
            ],
            ids=ids,
        )
        @pytest.mark.parametrize("scheme", [UpstreamScheme.SOCKS5, UpstreamScheme.SOCKS5H])
        def it_should_fail_gracefully(scheme, url, reply):
            with daemonize(context=ApplicationContext("passthrough")) as passthrough:
                context = ApplicationContext(
                    routing_table={
                        UpstreamAddress(scheme, passthrough.address): [Pattern(Host("*"))],
                    },
                    proxy_retry_options=RetryOptions(tries=1),
                )
                with daemonize(context=context) as proxy:
                    with pytest.raises(requests.exceptions.ConnectionError, match=f".*{reply.message}.*"):
                        requests.get(url, proxies=dict.fromkeys(["http", "https"], f"socks5h://{proxy.address}"))

    def when_routing_table_contains_unreachable_upstream():
        @pytest.mark.parametrize(
            "upstream_address,reply",
            [
                # blackholes
                # IPv4: 198.51.100.0/24
                (UpstreamAddress(UpstreamScheme.SSH, IPv4("198.51.100.1")), Socks5ReplyType.CONNECTION_REFUSED),
                (UpstreamAddress(UpstreamScheme.SOCKS5, IPv4("198.51.100.1")), Socks5ReplyType.HOST_UNREACHABLE),
                (UpstreamAddress(UpstreamScheme.SOCKS5H, IPv4("198.51.100.1")), Socks5ReplyType.HOST_UNREACHABLE),
                # IPv6: 100::/64
                (UpstreamAddress(UpstreamScheme.SSH, IPv6("100::")), Socks5ReplyType.CONNECTION_REFUSED),
                (UpstreamAddress(UpstreamScheme.SOCKS5, IPv6("100::")), Socks5ReplyType.HOST_UNREACHABLE),
                (UpstreamAddress(UpstreamScheme.SOCKS5H, IPv6("100::")), Socks5ReplyType.HOST_UNREACHABLE),
                # DNS: invalid. TLD
                (UpstreamAddress(UpstreamScheme.SSH, Host("non-existent.invalid")), Socks5ReplyType.CONNECTION_REFUSED),
                (UpstreamAddress(UpstreamScheme.SOCKS5, Host("non-existent.invalid")), Socks5ReplyType.CONNECTION_REFUSED),
                (UpstreamAddress(UpstreamScheme.SOCKS5H, Host("non-existent.invalid")), Socks5ReplyType.NETWORK_UNREACHABLE),
            ],
            ids=ids,
        )
        def it_should_fail_gracefully(httpserver, upstream_address, reply):
            httpserver.expect_request("/").respond_with_json({})

            context = ApplicationContext(
                routing_table={
                    upstream_address: [Pattern(Host("*"))],
                },
                proxy_retry_options=RetryOptions(tries=1),
            )
            with daemonize(context=context) as proxy:
                with pytest.raises(requests.exceptions.ConnectionError, match=f".*{reply.message}.*"):
                    requests.get(httpserver.url_for("/"), proxies=dict.fromkeys(["http", "https"], f"socks5h://{proxy.address}"))

    def when_an_unrecognized_exception_raised_during_handle_request():
        @pytest.mark.parametrize("exception", [Exception, OSError])
        def it_should_reply_GENERAL_SOCKS_SERVER_FAILURE(mocker, httpserver, exception):
            mocker.patch("socks_router.router.connect_remote", side_effect=exception)
            httpserver.expect_request("/").respond_with_json({})
            with daemonize() as proxy:
                with pytest.raises(
                    requests.exceptions.ConnectionError, match=f".*{Socks5ReplyType.GENERAL_SOCKS_SERVER_FAILURE.message}.*"
                ):
                    requests.get(httpserver.url_for("/"), proxies=dict.fromkeys(["http", "https"], f"socks5h://{proxy.address}"))

    def when_socket_exceptions_raised_during_handle_request():
        @pytest.mark.parametrize("errno", ["EAI_NODATA", "EAI_NONAME", "EAI_ADDRFAMILY", "EAI_FAMILY"])
        def it_should_reply_other_than_GENERAL_SOCKS_SERVER_FAILURE(mocker, httpserver, errno):
            mocker.patch("socks_router.router.connect_remote", side_effect=OSError(getattr(socket, errno), ""))
            with daemonize() as proxy:
                # NOTE: do not remove the .* after the negative look ahead
                with pytest.raises(
                    requests.exceptions.ConnectionError, match=f"(?!{Socks5ReplyType.GENERAL_SOCKS_SERVER_FAILURE.message}).*"
                ):
                    requests.get(httpserver.url_for("/"), proxies=dict.fromkeys(["http", "https"], f"socks5h://{proxy.address}"))

    def when_upstream_server_does_not_behave():
        @pytest.mark.parametrize("scheme", [UpstreamScheme.SOCKS5, UpstreamScheme.SOCKS5H])
        def it_should_reply_with_GENERAL_SOCKS_SERVER_FAILURE(httpserver, scheme):
            httpserver.expect_request("/").respond_with_json({})

            class MalformedRequestHandler(SocksRouterRequestHandler):
                def handle_request(self):
                    _ = read_socket(self.connection, Socks5Request)
                    # reply something doesn't make sense
                    self.connection.sendall(b"\x04")
                    self.state = Socks5State.CLOSED

            with daemonize(handler=MalformedRequestHandler) as passthrough:
                context = ApplicationContext(
                    routing_table={
                        UpstreamAddress(scheme, passthrough.address): [Pattern(Host("*"))],
                    },
                )
                with daemonize(context=context) as proxy:
                    with pytest.raises(
                        requests.exceptions.ConnectionError, match=f".*{Socks5ReplyType.GENERAL_SOCKS_SERVER_FAILURE.message}.*"
                    ):
                        requests.get(
                            httpserver.url_for("/"), proxies=dict.fromkeys(["http", "https"], f"socks5h://{proxy.address}")
                        )

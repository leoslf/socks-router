import contextlib

import logging
import requests

from typing import Iterator

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
    )
    def it_should_create_the_socket(type):
        assert isinstance(create_socket(type), socks.socksocket)


def describe_with_proxy():
    @pytest.mark.parametrize("proxy_server", [IPv4("8.8.8.8", 443)])
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
    address: str = "127.0.0.1",
    type: type[IPv4] | type[IPv6] | type[Host] = IPv4,
    **kwargs,
) -> Iterator[SocksRouter]:
    _, port = free_port("127.0.0.1")
    server = SocksRouter(
        (address, port),
        SocksRouterRequestHandler,
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
                },
                IPv4("127.0.0.1", 443),
                UpstreamAddress(UpstreamScheme.SOCKS5, IPv4("127.0.0.1", 1080)),
            ),
        ],
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
                        proxies={type: f"socks5://{passthrough.address}" for type in ["http", "https"]},
                    ).json()
                    == mocked_response
                )

    def when_used_with_transparent_socks5_upstream():
        @pytest.mark.parametrize("address_type,address", [(IPv4, "127.0.0.1"), (Host, "localhost"), (IPv6, "::1")])
        def it_should_relay_through_upstream(httpserver, address_type, address):
            destination = address_type(address, httpserver.port)
            httpserver.expect_request("/").respond_with_json(mocked_response := {"foo": "bar"})
            # we use a server without routing table to be a pass-through socks5 server
            with daemonize(address, context=ApplicationContext("passthrough"), type=address_type) as passthrough:
                # using the passthrough as catch-all
                context = ApplicationContext(
                    routing_table={
                        UpstreamAddress(UpstreamScheme.SOCKS5, passthrough.address): [Pattern(Host("*"))],
                    },
                )
                with daemonize(address, context=context, type=address_type) as proxy:
                    # using the proxy server from client
                    assert (
                        requests.get(
                            f"http://{destination}/",
                            proxies={type: f"socks5://{proxy.address}" for type in ["http", "https"]},
                        ).json()
                        == mocked_response
                    )
                    # re-request it to trigger reusing the upstream
                    assert (
                        requests.get(
                            f"http://{destination}/",
                            proxies={type: f"socks5://{proxy.address}" for type in ["http", "https"]},
                        ).json()
                        == mocked_response
                    )

    def when_used_with_ssh_upstream():
        @pytest.mark.parametrize("address_type,address", [(IPv4, "127.0.0.1"), (Host, "localhost"), (IPv6, "::1")])
        @pytest.mark.parametrize("proxy_address_type,proxy_address", [(IPv4, "127.0.0.1"), (Host, "localhost"), (IPv6, "::1")])
        def it_should_successfully_return_and_resuse_ssh_upstream_in_second_pass(
            httpserver, address_type, address, proxy_address_type, proxy_address
        ):
            # TODO: ensure we have sshd listening on port 22
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
                        proxies={type: f"socks5://{proxy.address}" for type in ["http", "https"]},
                        timeout=10,
                    ).json()
                    == mocked_response
                )
                # re-request it to trigger reusing the upstream
                assert (
                    requests.get(
                        f"http://{destination}/",
                        proxies={type: f"socks5://{proxy.address}" for type in ["http", "https"]},
                        timeout=10,
                    ).json()
                    == mocked_response
                )

        @pytest.mark.parametrize("address_type,address", [(IPv4, "127.0.0.1"), (Host, "localhost"), (IPv6, "::1")])
        def it_should_recreate_ssh_upstream_if_subprocess_is_dead(mocker, httpserver, address_type, address):
            # TODO: ensure we have sshd listening on port 22
            destination = address_type(address, httpserver.port)
            httpserver.expect_request("/").respond_with_json(mocked_response := {"foo": "bar"})
            #
            ssh_client = mocker.Mock(subprocess.Popen)
            ssh_client.poll.return_value = False

            original_upstream = SSHUpstream(ssh_client, Host("127.0.0.1", -1))
            upstream_address = UpstreamAddress(UpstreamScheme.SSH, Host("127.0.0.1"))
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
                        proxies={type: f"socks5://{proxy.address}" for type in ["http", "https"]},
                    ).json()
                    == mocked_response
                )
                ssh_client.poll.assert_called_with()
                assert context.upstreams[upstream_address] != original_upstream

    def when_client_attempt_to_use_socks4():
        @pytest.mark.parametrize("address_type,address", [(IPv4, "127.0.0.1"), (Host, "localhost"), (IPv6, "::1")])
        def it_should_close_socket(httpserver, address_type, address):
            destination = address_type(address, httpserver.port)
            with daemonize(address, type=address_type) as proxy:
                with pytest.raises(
                    requests.exceptions.ConnectionError, match=r".*(Connection reset by peer|Connection closed unexpectedly).*"
                ):
                    requests.get(
                        f"http://{destination}/", proxies={type: f"socks4://{proxy.address}" for type in ["http", "https"]}
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
                    assert read_socket(client, Socks5Reply) == Socks5Reply(SOCKS_VERSION, Socks5ReplyType.COMMAND_NOT_SUPPORTED)

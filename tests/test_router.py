import sys
import os
import logging

import io
import itertools
import functools
import contextlib
import resource
import ipaddress
import threading
import subprocess

import requests

from typing import Iterator
from enum import IntEnum

import pytest
from mocket import Mocket, MocketEntry, mocketize
from mocket.mocket import MocketSocket, true_gethostbyname

import struct
import socket
import socks

from socks_router.models import (
    SOCKS_VERSION,
    Socks5Method,
    Socks5MethodSelectionRequest,
    Socks5MethodSelectionResponse,
    Socks5GSSAPIClientInitialTokenV1,
    Socks5GSSAPIMessageProtectionSubnegotiationV1,
    Socks5GSSAPIPerMessageProtectionV1,
    Socks5GSSAPISecurityContextFailureV1,
    Socks5UsernamePasswordStatus,
    Socks5UsernamePasswordInitialNegotiationV1,
    Socks5UsernamePasswordInitialNegotiationResponseV1,
    Socks5Command,
    Socks5Request,
    Socks5ReplyType,
    Socks5Reply,
    Socks5AddressType,
    Socks5Address,
    IPv4,
    IPv6,
    Host,
    Address,
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


def helper(f):
    @functools.wraps(f)
    @pytest.fixture
    def wrapped():
        return f

    return wrapped


def ids(value, depth: int = 0):
    match value:
        case IntEnum():
            return value.name
        case list() | dict() if depth == 0:
            return f"{ids(value, 1)}"
        case list():
            return list(map(functools.partial(ids, depth=depth + 1), value))
        case dict():
            return {ids(k, depth + 1): ids(v, depth + 1) for k, v in value.items()}
        case _:
            return f"{value}"


def proxies(proxy_server: Address, scheme: str = "socks5h") -> dict[str, str]:
    return dict.fromkeys(["http", "https"], f"{scheme}://{proxy_server}")


# SEE: https://en.wikipedia.org/wiki/Reserved_IP_addresses
blackholes: dict[type[IPv4] | type[IPv6] | type[Host], Address] = {
    # IPv4: 198.51.100.0/24 is reserved for use in documentation and examples; while the RFC advises that the addresses in this range are not routed, this is not a requirement
    IPv4: IPv4(str(next(ipaddress.IPv4Network("198.51.100.0/24").hosts()))),
    # IPv6 discard prefix: 100::/64
    IPv6: IPv6(str(next(ipaddress.IPv6Network("100::/64").hosts()))),
    # TLD invalid. is guarenteed to be failing in DNS resolution
    # SEE: https://www.rfc-editor.org/rfc/rfc6761#section-6.4
    Host: Host("non-existent.invalid"),
}


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
        with create_socket(type) as socket:
            assert isinstance(socket, socks.socksocket)


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


def describe_match_upstream():
    @pytest.mark.parametrize(
        "routing_table,destination,upstream",
        [
            ({}, IPv4("127.0.0.1", 443), None),
            (
                {
                    UpstreamAddress(UpstreamScheme.SSH, IPv4("127.0.0.1", 22)): [],
                    UpstreamAddress(UpstreamScheme.SOCKS5, IPv4("127.0.0.1", 1080)): [Pattern("*")],
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

    @pytest.fixture
    def daemonize(reraise):
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
                threading.Thread(target=reraise.wrap(server.serve_forever), name=server.context.name, daemon=True).start()
                yield server
            finally:
                server.shutdown()

        return daemonize

    def when_used_with_empty_routing_table():
        @pytest.mark.parametrize("address_type,address", [(IPv4, "127.0.0.1"), (Host, "localhost"), (IPv6, "::1")])
        def it_should_transparently_go_through(daemonize, httpserver, address_type, address):
            destination = address_type(address, httpserver.port)
            httpserver.expect_request("/").respond_with_json(mocked_response := {"foo": "bar"})
            # we use a server without routing table to be a pass-through socks5 server
            with daemonize(address, context=ApplicationContext("passthrough"), type=address_type) as passthrough:
                # using the pass-through server from client
                assert (
                    requests.get(
                        f"http://{destination}/",
                        proxies=proxies(passthrough.address),
                    ).json()
                    == mocked_response
                )

    def when_used_with_transparent_socks5_upstream():
        @pytest.mark.parametrize("address_type,address", [(IPv4, "127.0.0.1"), (Host, "localhost"), (IPv6, "::1")])
        @pytest.mark.parametrize("scheme", [UpstreamScheme.SOCKS5, UpstreamScheme.SOCKS5H])
        def it_should_relay_through_upstream(daemonize, httpserver, scheme, address_type, address):
            destination = address_type(address, httpserver.port)
            httpserver.expect_request("/").respond_with_json(mocked_response := {"foo": "bar"})
            # we use a server without routing table to be a pass-through socks5 server
            with daemonize(address, context=ApplicationContext("passthrough"), type=address_type) as passthrough:
                # using the passthrough as catch-all
                context = ApplicationContext(
                    routing_table={
                        UpstreamAddress(scheme, passthrough.address): [Pattern("*")],
                    },
                )
                with daemonize(address, context=context, type=address_type) as proxy:
                    # using the proxy server from client
                    assert (
                        requests.get(
                            f"http://{destination}/",
                            proxies=proxies(proxy.address),
                        ).json()
                        == mocked_response
                    )
                    # re-request it to trigger reusing the upstream
                    assert (
                        requests.get(
                            f"http://{destination}/",
                            proxies=proxies(proxy.address),
                        ).json()
                        == mocked_response
                    )

    def when_used_with_ssh_upstream():
        @pytest.mark.parametrize("address_type,address", [(IPv4, "127.0.0.1"), (Host, "localhost"), (IPv6, "::1")])
        @pytest.mark.parametrize("proxy_address_type,proxy_address", [(IPv4, "127.0.0.1"), (Host, "localhost"), (IPv6, "::1")])
        def it_should_successfully_return_and_resuse_ssh_upstream_in_second_pass(
            mocker, daemonize, httpserver, address_type, address, proxy_address_type, proxy_address
        ):
            if sys.platform == "linux" and any(type == IPv6 for type in [address_type, proxy_address_type]):
                return pytest.skip("skip IPv6 tests on linux to avoid address family not supported")

            create = mocker.spy(SSHUpstream, "create")
            destination = address_type(address, httpserver.port)
            httpserver.expect_request("/").respond_with_json(mocked_response := {"foo": "bar"})
            context = ApplicationContext(
                routing_table={
                    UpstreamAddress(UpstreamScheme.SSH, Host("localhost")): [Pattern("*")],
                },
                proxy_retry_options=RetryOptions(delay=0.25, tries=10),
            )
            with daemonize(proxy_address, context=context, type=proxy_address_type) as proxy:
                # using the proxy server from client
                assert (
                    requests.get(
                        f"http://{destination}/",
                        proxies=proxies(proxy.address),
                        timeout=10,
                    ).json()
                    == mocked_response
                )
                create.assert_called_once()
                # re-request it to trigger reusing the upstream
                assert (
                    requests.get(
                        f"http://{destination}/",
                        proxies=proxies(proxy.address),
                        timeout=10,
                    ).json()
                    == mocked_response
                )
                create.assert_called_once()

        @pytest.mark.parametrize("address_type,address", [(IPv4, "127.0.0.1"), (Host, "localhost"), (IPv6, "::1")])
        def it_should_recreate_ssh_upstream_if_subprocess_is_dead(mocker, daemonize, httpserver, address_type, address):
            if sys.platform == "linux" and address_type == IPv6:
                return pytest.skip("skip IPv6 tests on linux to avoid address family not supported")

            destination = address_type(address, httpserver.port)
            httpserver.expect_request("/").respond_with_json(mocked_response := {"foo": "bar"})

            ssh_client = mocker.Mock(subprocess.Popen, stdout=io.StringIO(), stderr=io.StringIO())
            ssh_client.poll.return_value = 1

            upstream_address = UpstreamAddress(UpstreamScheme.SSH, Host("127.0.0.1"))
            original_upstream = SSHUpstream(ssh_client, upstream_address.address.with_port(-1))
            context = ApplicationContext(
                routing_table={
                    upstream_address: [Pattern("*")],
                },
                upstreams={
                    upstream_address: original_upstream,
                },
                proxy_retry_options=RetryOptions(delay=0.25, tries=10),
            )
            with daemonize(address, type=address_type, context=context) as proxy:
                # using the proxy server from client
                assert (
                    requests.get(
                        f"http://{destination}/",
                        proxies=proxies(proxy.address),
                    ).json()
                    == mocked_response
                )
                ssh_client.poll.assert_called_with()
                assert context.upstreams[upstream_address] != original_upstream

        def it_should_not_explicitly_kill_ssh_client_if_dead_on_shutdown(mocker, daemonize):
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
        def it_should_close_socket(daemonize, httpserver, address_type, address):
            with daemonize(address, type=address_type) as proxy:
                with connect_remote(proxy.address) as client:
                    with pytest.raises(struct.error, match=r"unpack requires a buffer of \d+"):
                        # handshake
                        write_socket(client, Socks5MethodSelectionRequest(0x04, methods=[Socks5Method.USERNAME_PASSWORD]))
                        assert read_socket(client, Socks5MethodSelectionResponse) == Socks5MethodSelectionResponse(
                            SOCKS_VERSION, Socks5Method.NO_ACCEPTABLE_METHODS
                        )

    def when_client_attempt_to_use_unacceptable_methods():
        def it_should_reply_no_acceptable_methods(daemonize):
            with daemonize() as proxy:
                with connect_remote(proxy.address) as client:
                    # handshake
                    write_socket(client, Socks5MethodSelectionRequest(SOCKS_VERSION, methods=[Socks5Method.NO_ACCEPTABLE_METHODS]))
                    assert read_socket(client, Socks5MethodSelectionResponse) == Socks5MethodSelectionResponse(
                        SOCKS_VERSION,
                        Socks5Method.NO_ACCEPTABLE_METHODS,
                    )

    def when_client_attempt_to_use_GSSAPI():
        @helper
        def handshake(client):
            write_socket(client, Socks5MethodSelectionRequest(SOCKS_VERSION, methods=[Socks5Method.GSSAPI]))
            return read_socket(client, Socks5MethodSelectionResponse)

        def when_disable_gssapi():
            def it_should_reply_no_acceptable_methods(daemonize):
                with daemonize(context=ApplicationContext(enable_gssapi=False)) as proxy:
                    with connect_remote(proxy.address) as client:
                        # handshake
                        write_socket(client, Socks5MethodSelectionRequest(SOCKS_VERSION, methods=[Socks5Method.USERNAME_PASSWORD]))
                        assert read_socket(client, Socks5MethodSelectionResponse) == Socks5MethodSelectionResponse(
                            SOCKS_VERSION,
                            Socks5Method.NO_ACCEPTABLE_METHODS,
                        )

        def when_enable_gssapi():
            def it_should_reply_GSSAPI_selected(daemonize, handshake):
                with daemonize(context=ApplicationContext(enable_gssapi=True)) as proxy:
                    with connect_remote(proxy.address) as client:
                        assert handshake(client) == Socks5MethodSelectionResponse(SOCKS_VERSION, Socks5Method.GSSAPI)

            def when_invalid_request():
                @pytest.mark.parametrize(
                    "requests,",
                    list(
                        itertools.accumulate(
                            map(
                                lambda x: (x,),
                                [
                                    {
                                        "type": Socks5GSSAPIClientInitialTokenV1,
                                        "token": b"fakepassword",
                                        "incorrect_token": b"fakeincorrectpassword",
                                    },
                                    {
                                        "type": Socks5GSSAPIMessageProtectionSubnegotiationV1,
                                        "token": b"fakepassword",
                                        "incorrect_token": b"fakeincorrectpassword",
                                    },
                                    {
                                        "type": Socks5GSSAPIPerMessageProtectionV1,
                                        "token": b"fakepassword",
                                        "incorrect_token": b"fakeincorrectpassword",
                                    },
                                ],
                            )
                        )
                    ),
                )
                def it_should_reject_subnegotiation(daemonize, handshake, requests):
                    with daemonize(context=ApplicationContext(enable_gssapi=True)) as proxy:
                        with connect_remote(proxy.address) as client:
                            assert handshake(client) == Socks5MethodSelectionResponse(SOCKS_VERSION, Socks5Method.GSSAPI)
                            for request in requests[:-1]:
                                write_socket(client, payload := request["type"](token=request["token"]))
                                assert read_socket(client, request["type"]) == payload

                            write_socket(client, requests[-1]["type"](token=requests[-1]["incorrect_token"]))
                            assert (
                                read_socket(client, Socks5GSSAPISecurityContextFailureV1) == Socks5GSSAPISecurityContextFailureV1()
                            )

            def when_everything_is_valid():
                def it_should_handle_subnegotiation(daemonize, handshake):
                    with daemonize(context=ApplicationContext(enable_gssapi=True)) as proxy:
                        with connect_remote(proxy.address) as client:
                            assert handshake(client) == Socks5MethodSelectionResponse(SOCKS_VERSION, Socks5Method.GSSAPI)

                            write_socket(client, initial_negotiation := Socks5GSSAPIClientInitialTokenV1(token=b"fakepassword"))
                            assert read_socket(client, Socks5GSSAPIClientInitialTokenV1) == initial_negotiation

                            write_socket(
                                client, message_protection := Socks5GSSAPIMessageProtectionSubnegotiationV1(token=b"fakepassword")
                            )
                            assert read_socket(client, Socks5GSSAPIMessageProtectionSubnegotiationV1) == message_protection

                            write_socket(
                                client, per_message_protection := Socks5GSSAPIPerMessageProtectionV1(token=b"fakepassword")
                            )
                            assert read_socket(client, Socks5GSSAPIPerMessageProtectionV1) == per_message_protection

    def when_client_attempt_to_use_username_password():
        def when_no_users_given_in_context():
            def it_should_reply_no_acceptable_methods(daemonize):
                with daemonize() as proxy:
                    with connect_remote(proxy.address) as client:
                        # handshake
                        write_socket(client, Socks5MethodSelectionRequest(SOCKS_VERSION, methods=[Socks5Method.USERNAME_PASSWORD]))
                        assert read_socket(client, Socks5MethodSelectionResponse) == Socks5MethodSelectionResponse(
                            SOCKS_VERSION,
                            Socks5Method.NO_ACCEPTABLE_METHODS,
                        )

        def when_users_given_in_the_context():
            def it_should_reply_USERNAME_PASSWORD_selected(daemonize):
                with daemonize(context=ApplicationContext(users={})) as proxy:
                    with connect_remote(proxy.address) as client:
                        write_socket(client, Socks5MethodSelectionRequest(SOCKS_VERSION, methods=[Socks5Method.USERNAME_PASSWORD]))
                        assert read_socket(client, Socks5MethodSelectionResponse) == Socks5MethodSelectionResponse(
                            SOCKS_VERSION,
                            Socks5Method.USERNAME_PASSWORD,
                        )

            @pytest.mark.parametrize(
                "users,username,password,status",
                [
                    ({"foo": "fakepassword"}, "foo", "fakepassword", Socks5UsernamePasswordStatus.SUCCESS),
                    ({}, "foo", "fakepassword", Socks5UsernamePasswordStatus.FAILURE),
                ],
            )
            def it_should_handle_subnegotiation_on_request(daemonize, users, username, password, status):
                with daemonize(context=ApplicationContext(users=users)) as proxy:
                    with connect_remote(proxy.address) as client:
                        write_socket(client, Socks5MethodSelectionRequest(SOCKS_VERSION, methods=[Socks5Method.USERNAME_PASSWORD]))
                        assert read_socket(client, Socks5MethodSelectionResponse) == Socks5MethodSelectionResponse(
                            SOCKS_VERSION,
                            Socks5Method.USERNAME_PASSWORD,
                        )
                        write_socket(client, Socks5UsernamePasswordInitialNegotiationV1(username=username, password=password))
                        assert read_socket(
                            client, Socks5UsernamePasswordInitialNegotiationResponseV1
                        ) == Socks5UsernamePasswordInitialNegotiationResponseV1(status=status)

    def when_client_attempt_to_use_command_other_than_connect():
        def it_should_reply_command_not_supported(daemonize):
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
            "scheme,destination,reply",
            [
                (UpstreamScheme.SOCKS5, blackholes[IPv4], Socks5ReplyType.HOST_UNREACHABLE),
                (UpstreamScheme.SOCKS5H, blackholes[IPv4], Socks5ReplyType.HOST_UNREACHABLE),
                (UpstreamScheme.SOCKS5, blackholes[IPv6], Socks5ReplyType.HOST_UNREACHABLE),
                (UpstreamScheme.SOCKS5H, blackholes[IPv6], Socks5ReplyType.HOST_UNREACHABLE),
                (UpstreamScheme.SOCKS5, blackholes[Host], Socks5ReplyType.CONNECTION_REFUSED),
                (UpstreamScheme.SOCKS5H, blackholes[Host], Socks5ReplyType.NETWORK_UNREACHABLE),
            ],
            ids=ids,
        )
        def it_should_fail_gracefully(daemonize, scheme, destination, reply):
            if sys.platform == "linux" and isinstance(destination, IPv6):
                return pytest.skip("skip IPv6 tests on linux to avoid address family not supported")

            with daemonize(context=ApplicationContext("passthrough")) as passthrough:
                context = ApplicationContext(
                    routing_table={
                        UpstreamAddress(scheme, passthrough.address): [Pattern("*")],
                    },
                    remote_socket_timeout=0.1,
                    proxy_retry_options=RetryOptions(delay=0.1, tries=1),
                )
                with daemonize(context=context) as proxy:
                    with pytest.raises(requests.exceptions.ConnectionError, match=f".*{reply.message}.*"):
                        requests.get(f"http://{destination.url_literal}", proxies=proxies(proxy.address))

    def when_routing_table_contains_unreachable_upstream():
        @pytest.mark.parametrize(
            "upstream_address,replies",
            [
                (UpstreamAddress(UpstreamScheme.SSH, blackholes[IPv4]), [Socks5ReplyType.CONNECTION_REFUSED]),
                (UpstreamAddress(UpstreamScheme.SOCKS5, blackholes[IPv4]), [Socks5ReplyType.HOST_UNREACHABLE]),
                (UpstreamAddress(UpstreamScheme.SOCKS5H, blackholes[IPv4]), [Socks5ReplyType.HOST_UNREACHABLE]),
                (UpstreamAddress(UpstreamScheme.SSH, blackholes[IPv6]), [Socks5ReplyType.CONNECTION_REFUSED]),
                (
                    UpstreamAddress(UpstreamScheme.SOCKS5, blackholes[IPv6]),
                    [Socks5ReplyType.HOST_UNREACHABLE, Socks5ReplyType.NETWORK_UNREACHABLE],
                ),
                (
                    UpstreamAddress(UpstreamScheme.SOCKS5H, blackholes[IPv6]),
                    [Socks5ReplyType.HOST_UNREACHABLE, Socks5ReplyType.NETWORK_UNREACHABLE],
                ),
                (
                    UpstreamAddress(UpstreamScheme.SSH, blackholes[Host]),
                    [Socks5ReplyType.CONNECTION_REFUSED, Socks5ReplyType.NETWORK_UNREACHABLE],
                ),
                (
                    UpstreamAddress(UpstreamScheme.SOCKS5, blackholes[Host]),
                    [Socks5ReplyType.CONNECTION_REFUSED, Socks5ReplyType.NETWORK_UNREACHABLE],
                ),
                (
                    UpstreamAddress(UpstreamScheme.SOCKS5H, blackholes[Host]),
                    [Socks5ReplyType.CONNECTION_REFUSED, Socks5ReplyType.NETWORK_UNREACHABLE],
                ),
            ],
            ids=ids,
        )
        def it_should_fail_gracefully(daemonize, httpserver, upstream_address, replies):
            httpserver.expect_request("/").respond_with_json({})

            context = ApplicationContext(
                routing_table={
                    upstream_address: [Pattern("*")],
                },
                ssh_connection_timeout=1,
                proxy_retry_options=RetryOptions(delay=0.1, tries=1),
            )
            with daemonize(context=context) as proxy:
                with pytest.raises(
                    requests.exceptions.ConnectionError, match=f".*{'|'.join(map(lambda reply: reply.message, replies))}.*"
                ):
                    requests.get(httpserver.url_for("/"), proxies=proxies(proxy.address)).json()

    def when_an_unrecognized_exception_raised_during_handle_request():
        @pytest.mark.parametrize("exception", [Exception, OSError])
        def it_should_reply_GENERAL_SOCKS_SERVER_FAILURE(mocker, daemonize, httpserver, exception):
            mocker.patch("socks_router.router.connect_remote", side_effect=exception)
            httpserver.expect_request("/").respond_with_json({})
            with daemonize() as proxy:
                with pytest.raises(
                    requests.exceptions.ConnectionError, match=f".*{Socks5ReplyType.GENERAL_SOCKS_SERVER_FAILURE.message}.*"
                ):
                    requests.get(httpserver.url_for("/"), proxies=proxies(proxy.address)).json()

    def when_socket_exceptions_raised_during_handle_request():
        @pytest.mark.parametrize("errno", ["EAI_NODATA", "EAI_NONAME", "EAI_ADDRFAMILY", "EAI_FAMILY"])
        def it_should_reply_other_than_GENERAL_SOCKS_SERVER_FAILURE(mocker, daemonize, httpserver, errno):
            mocker.patch("socks_router.router.connect_remote", side_effect=OSError(getattr(socket, errno), ""))
            httpserver.expect_request("/").respond_with_json({})
            with daemonize() as proxy:
                # NOTE: do not remove the .* after the negative look ahead
                with pytest.raises(
                    requests.exceptions.ConnectionError, match=f"(?!{Socks5ReplyType.GENERAL_SOCKS_SERVER_FAILURE.message}).*"
                ):
                    requests.get(httpserver.url_for("/"), proxies=proxies(proxy.address)).json()

    def when_an_unrecognized_exception_raised_elsewhere():
        def it_should_handle_it_gracefully(daemonize, httpserver):
            httpserver.expect_request("/").respond_with_json({})

            class ExceptionRaisingRequestHandler(SocksRouterRequestHandler):
                def handshake(self):
                    raise NotImplementedError

            with daemonize(handler=ExceptionRaisingRequestHandler) as proxy:
                with pytest.raises(
                    requests.exceptions.ConnectionError, match=".*(?:Connection closed unexpectedly|Connection reset by peer).*"
                ):
                    requests.get(httpserver.url_for("/"), proxies=proxies(proxy.address)).json()

    def when_upstream_server_does_not_behave():
        @pytest.mark.parametrize("scheme", [UpstreamScheme.SOCKS5, UpstreamScheme.SOCKS5H])
        def it_should_reply_with_GENERAL_SOCKS_SERVER_FAILURE(daemonize, httpserver, scheme):
            destination = IPv4("127.0.0.1", httpserver.port)
            httpserver.expect_request("/").respond_with_json({})

            class MalformedRequestHandler(SocksRouterRequestHandler):
                def handle_request(self):
                    _ = read_socket(self.connection, Socks5Request)
                    # reply something doesn't make sense
                    self.connection.sendall(b"\xff")
                    self.state = Socks5State.CLOSED

            with daemonize(handler=MalformedRequestHandler) as passthrough:
                context = ApplicationContext(
                    routing_table={
                        UpstreamAddress(scheme, passthrough.address): [Pattern("*")],
                    },
                )
                with daemonize(context=context) as proxy:
                    with pytest.raises(
                        requests.exceptions.ConnectionError, match=f".*{Socks5ReplyType.GENERAL_SOCKS_SERVER_FAILURE.message}.*"
                    ):
                        requests.get(
                            f"http://{destination}/",
                            proxies=proxies(proxy.address),
                        ).json()

    def when_filedesctiprors_get_out_of_FD_SETSIZE():
        @pytest.mark.parametrize("address_type,address", [(IPv4, "127.0.0.1")])
        def it_should_not_throw_filedescriptor_out_of_range(daemonize, httpserver, address_type, address):
            FD_SETSIZE = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
            # create arbitrary pipes to use up the file descriptors
            pipes = []
            while True:
                pipes.append(pipe := os.pipe())
                # reserve file descriptors for the followings
                # 1. client HTTP socket
                # 2. client socks socket
                # 3. server side connection to client
                # 4. server side remote
                # 5. http server connection to client
                if any(fd >= (FD_SETSIZE - 5) for fd in pipe):
                    break

            destination = address_type(address, httpserver.port)
            httpserver.expect_request("/").respond_with_json(mocked_response := {"foo": "bar"})
            with pytest.raises(requests.exceptions.ConnectionError):
                # we use a server without routing table to be a pass-through socks5 server
                with daemonize(address, context=ApplicationContext("passthrough"), type=address_type) as passthrough:
                    # using the pass-through server from client
                    assert (
                        requests.get(
                            f"http://{destination}/",
                            proxies=proxies(passthrough.address),
                        ).json()
                        == mocked_response
                    )

            for pipe in pipes:
                for fd in pipe:
                    os.close(fd)

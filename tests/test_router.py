import contextlib

import logging
import requests

from typing import Iterator, Optional

import pytest
from mocket import Mocket, MocketEntry, mocketize
from mocket.mocket import MocketSocket, true_gethostbyname

import threading
import socks

from socks_router.models import (
    SOCKS_VERSION,
    Socks5Method,
    Socks5MethodSelectionRequest,
    Socks5MethodSelectionResponse,
    Socks5AddressType,
    IPv4,
    Host,
    Address,
    UpstreamAddress,
    UpstreamScheme,
    Pattern,
    ApplicationContext,
)
from socks_router.router import (
    free_port,
    # read_request,
    # read_address,
    # read_method_selection_request,
    create_socket,
    with_proxy,
    connect_remote,
    match_upstream,
    SocksRouter,
    SocksRouterRequestHandler,
)
from socks_router.utils import read_socket, write_socket

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


# def describe_read_address():
#     @pytest.mark.parametrize("ipv4", ["1.2.3.4"])
#     def it_should_successfully_read_ipv4(mocker, client, ipv4):
#         client.recv.side_effect = [socket.inet_pton(socket.AF_INET, ipv4)]
#         assert read_address(Socks5AddressType.IPv4, client) == ipv4
#
#     @pytest.mark.parametrize("domainname", ["foo.com"])
#     def it_should_successfully_read_domainname(client, domainname):
#         encoded = domainname.encode("utf-8")
#         client.recv.side_effect = [struct.pack("!B", len(encoded)), encoded]
#         assert read_address(Socks5AddressType.DOMAINNAME, client) == domainname
#
#     @pytest.mark.parametrize("ipv6", ["::1"])
#     def it_should_successfully_read_ipv6(client, ipv6):
#         client.recv.return_value = socket.inet_pton(socket.AF_INET6, ipv6)
#         assert read_address(Socks5AddressType.IPv6, client) == ipv6


# def describe_read_request():
#     @pytest.mark.parametrize(
#         "version,command,address_type,address,port",
#         [
#             (
#                 SOCKS_VERSION,
#                 Socks5Command.CONNECT,
#                 Socks5AddressType.IPv4,
#                 "127.0.0.1",
#                 1234,
#             ),
#         ],
#     )
#     def it_should_successfully_read(mocker, client, version, command, address_type, address, port):
#         client.recv.side_effect = [
#             struct.pack("!BBBB", version, command, 0, address_type),
#             struct.pack("!H", port),
#         ]
#         mocker.patch("socks_router.router.read_address").return_value = address
#         assert read_request(client) == Socks5Request(version, command, 0x00, address_type, address, port)


# def describe_read_method_selection_request():
#     @pytest.mark.parametrize(
#         "version,methods",
#         [
#             (SOCKS_VERSION, []),
#             (SOCKS_VERSION, [1, 2, 3]),
#         ],
#     )
#     def it_should_correctly_read(client, version, methods):
#         client.recv.side_effect = [struct.pack("!BB", version, len(methods)), methods]
#         assert read_method_selection_request(client) == Socks5MethodSelectionRequest(version, methods)


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
        client.set_proxy.assert_called_with(socks.SOCKS5, f"{proxy_server.address}", proxy_server.port)

    def it_should_work_without_proxy_server(client):
        with_proxy(client, None)
        client.set_proxy.assert_not_called()


def describe_connect_remote():
    def it_should_connect_to_socket(mocker, client):
        mocker.patch("socks_router.router.create_socket").__enter__.return_value = client
        connect_remote(IPv4("127.0.0.1", 12345), logger=logger)


@contextlib.contextmanager
def daemonize(
    sockaddr: Optional[tuple[str, int]] = None,
    context: Optional[ApplicationContext] = None,
) -> Iterator[SocksRouter]:
    server = SocksRouter(sockaddr or free_port("127.0.0.1"), SocksRouterRequestHandler, context=context)
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
    mock_server_port = 5000

    @pytest.fixture
    def destination():
        return IPv4("127.0.0.1", mock_server_port)

    @pytest.mark.server(url="/", response=(mocked_response := {"foo": "bar"}), method="GET")
    @pytest.mark.server_settings(port=mock_server_port)
    def when_used_with_empty_routing_table():
        def it_should_transparently_go_through(destination: Address):
            # we use a server without routing table to be a pass-through socks5 server
            with daemonize(context=ApplicationContext("passthrough")) as passthrough:
                # using the pass-through server from client
                assert (
                    requests.get(
                        f"http://{destination}/",
                        proxies={type: f"socks5://{passthrough.address}" for type in ["http", "https"]},
                    ).json()
                    == mocked_response
                )

    # @pytest.mark.server(url="/", response=(mocked_response := {"foo": "bar"}), method="GET")
    # @pytest.mark.server_settings(port=mock_server_port)
    def when_used_with_transparent_upstream():
        def it_should_relay_through_upstream(destination: Address):
            # we use a server without routing table to be a pass-through socks5 server
            with daemonize(context=ApplicationContext("passthrough")) as passthrough:
                # using the passthrough as catch-all
                context = ApplicationContext(
                    routing_table={UpstreamAddress(UpstreamScheme.SOCKS5, passthrough.address): [Pattern(Host("*"))]}
                )
                with daemonize(context=context) as proxy:
                    # using the proxy server from client
                    assert (
                        requests.get(
                            f"http://{destination}/",
                            proxies={type: f"socks5://{proxy.address}" for type in ["http", "https"]},
                        ).json()
                        == mocked_response
                    )
                    # re-request it to trigger reuse the upstream
                    assert (
                        requests.get(
                            f"http://{destination}/",
                            proxies={type: f"socks5://{proxy.address}" for type in ["http", "https"]},
                        ).json()
                        == mocked_response
                    )

    # @pytest.mark.server(url="/", response=(mocked_response := {"foo": "bar"}), method="GET")
    # @pytest.mark.server_settings(port=mock_server_port)
    def when_client_attempt_to_use_socks4():
        def it_should_close_socket(destination):
            with daemonize() as proxy:
                with pytest.raises(
                    requests.exceptions.ConnectionError, match=r".*(Connection reset by peer|Connection closed unexpectedly).*"
                ):
                    requests.get(
                        f"http://{destination}/", proxies={type: f"socks4://{proxy.address}" for type in ["http", "https"]}
                    ).json()

    def when_client_attempt_to_use_unacceptable_methods():
        def it_should_reply_no_acceptable_methods():
            with daemonize() as proxy:
                # handshake
                with connect_remote(proxy.address) as client:
                    write_socket(client, Socks5MethodSelectionRequest(SOCKS_VERSION, methods=[Socks5Method.USERNAME_PASSWORD]))
                    assert read_socket(client, Socks5MethodSelectionResponse) == Socks5MethodSelectionResponse(
                        SOCKS_VERSION, method=Socks5Method.NO_ACCEPTABLE_METHODS
                    )

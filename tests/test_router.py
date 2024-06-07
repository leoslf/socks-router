import os
import pytest
from mocket import Mocket, MocketEntry, mocketize
from mocket.mocket import MocketSocket, true_gethostbyname

import struct
import socket
import socks

from socks_router.models import (
    Socks5AddressType,
    Socks5Command,
    Socks5Addresses,
    IPv4,
)
from socks_router.router import (
    SOCKS_VERSION,
    free_port,
    read_request,
    read_address,
    read_header,
    exchange_loop,
    reply,
    create_socket,
    with_proxy,
    connect_socket,
    SocksRouter,
    SocksRouterRequestHandler,
)

@pytest.fixture
def client(mocker):
    return mocker.Mock(socks.socksocket)

def describe_free_port():
    @mocketize(strict_mode=True)
    @pytest.mark.parametrize("address,port", [
        ("", 12345),
        ("127.0.0.1", 12345),
    ])
    def it_should_return_a_free_port(mocker, address: str, port: int):
        socket.gethostbyname = socket.__dict__["gethostbyname"] = true_gethostbyname
        mocker.patch("mocket.Mocket._address")
        Mocket.register(MocketEntry((address, 0), []))
        MocketSocket._address = (address or "0.0.0.0", port)
        assert free_port() == (address or "0.0.0.0", port)
        MocketSocket._address = None

def describe_read_address():
    @pytest.mark.parametrize("ipv4", ["1.2.3.4"])
    def it_should_successfully_read_ipv4(mocker, client, ipv4):
        client.recv.side_effect = [socket.inet_pton(socket.AF_INET, ipv4)]
        assert read_address(Socks5AddressType.IPv4, client) == ipv4

    @pytest.mark.parametrize("domainname", ["foo.com"])
    def it_should_successfully_read_domainname(client, domainname):
        encoded = domainname.encode("utf-8")
        client.recv.side_effect = [struct.pack("!B", len(encoded)), encoded]
        assert read_address(Socks5AddressType.DOMAINNAME, client) == domainname

    @pytest.mark.parametrize("ipv6", ["::1"])
    def it_should_successfully_read_ipv6(client, ipv6):
        client.recv.return_value = socket.inet_pton(socket.AF_INET6, ipv6)
        assert read_address(Socks5AddressType.IPv6, client) == ipv6

    # def it_should_throw_on_unknown(client):
    #     with pytest.raises(ValueError):
    #         read_address(-1, client)

def describe_read_request():
    @pytest.mark.parametrize("version,cmd,address_type,address,port", [
        (SOCKS_VERSION, Socks5Command.CONNECT, Socks5AddressType.IPv4, "127.0.0.1", 1234),
    ])
    def it_should_successfully_read(mocker, client, version, cmd, address_type, address, port):
        client.recv.side_effect = [struct.pack("!BBBB", version, cmd, 0, address_type), struct.pack("!H", port)]
        mocker.patch("socks_router.router.read_address").return_value = address
        assert read_request(client) == (version, cmd, Socks5Addresses[address_type](address, port))

def describe_read_header():
    @pytest.mark.parametrize("version,methods", [
        (SOCKS_VERSION, set()),
        (SOCKS_VERSION, set([1, 2, 3])),
    ])
    def it_should_correctly_read(client, version, methods):
        client.recv.side_effect = [struct.pack("!BB", version, len(methods)), methods]
        assert read_header(client) == (version, methods)

def describe_create_socket():
    @pytest.mark.parametrize("type", [Socks5AddressType.IPv4, Socks5AddressType.DOMAINNAME, Socks5AddressType.IPv6])
    def it_should_create_the_socket(type):
        assert isinstance(create_socket(type), socks.socksocket)

def describe_with_proxy():
    @pytest.mark.parametrize("proxy_server", [IPv4("8.8.8.8", 443)])
    def with_proxy_server(client, proxy_server):
        with_proxy(client, proxy_server)
        client.set_proxy.assert_called_with(socks.SOCKS5, proxy_server.address, proxy_server.port)

    def without_proxy_server(client):
        with_proxy(client, None)
        client.set_proxy.assert_not_called()


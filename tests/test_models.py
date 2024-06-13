import pytest

from socks_router.models import (
    IPv4,
    IPv6,
    Host,
    Socks5Address,
)


@pytest.mark.parametrize(
    "address,port,ipv4",
    [
        ("10.0.0.1", None, IPv4("10.0.0.1")),
        ("10.0.0.1", 443, IPv4("10.0.0.1", 443)),
    ],
)
def test_IPv4(address, port, ipv4):
    assert IPv4(address, port) == ipv4
    assert repr(ipv4)
    assert str(ipv4)
    assert bytes(ipv4.address)
    assert ipv4.url_literal
    assert Socks5Address.from_address(ipv4).sockaddr == ipv4


@pytest.mark.parametrize(
    "address,port,ipv6",
    [
        ("::1", None, IPv6("::1")),
        ("::1", 443, IPv6("::1", 443)),
    ],
)
def test_IPv6(address, port, ipv6):
    assert IPv6(address, port) == ipv6
    assert repr(ipv6)
    assert str(ipv6)
    assert bytes(ipv6.address)
    assert ipv6.url_literal
    assert Socks5Address.from_address(ipv6).sockaddr == ipv6


@pytest.mark.parametrize(
    "address,port,host",
    [
        ("localhost", None, Host("localhost")),
        ("localhost", 443, Host("localhost", 443)),
    ],
)
def test_Host(address, port, host):
    assert Host(address, port) == host
    assert repr(host)
    assert str(host)
    assert host.url_literal
    assert Socks5Address.from_address(host).sockaddr == host

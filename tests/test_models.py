import pytest

from socks_router.models import (
    SOCKS_VERSION,
    IPv4,
    IPv6,
    Host,
    Socks5Method,
    Socks5MethodSelectionRequest,
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
    assert bytes(ipv4)
    assert ipv4.pattern


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
    assert bytes(ipv6)
    assert ipv6.pattern


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
    assert bytes(host)
    assert host.pattern


@pytest.mark.parametrize(
    "method_selection_request",
    [
        Socks5MethodSelectionRequest(SOCKS_VERSION, [Socks5Method.NO_AUTHENTICATION_REQUIRED]),
    ],
)
def test_Socks5MethodSelectionRequest(method_selection_request):
    assert bytes(method_selection_request)

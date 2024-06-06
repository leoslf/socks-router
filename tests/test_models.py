import pytest

from socks_router.models import *

@pytest.mark.parametrize("address,port,ipv4", [
    ("10.0.0.1", None, IPv4("10.0.0.1")),
    ("10.0.0.1", 443, IPv4("10.0.0.1", 443)),
])
def test_IPv4(address, port, ipv4):
    assert IPv4(address, port) == ipv4
    assert repr(ipv4)
    assert str(ipv4)

@pytest.mark.parametrize("address,port,ipv6", [
    ("::1", None, IPv6("::1")),
    ("::1", 443, IPv6("::1", 443)),
])
def test_IPv6(address, port, ipv6):
    assert IPv6(address, port) == ipv6
    assert repr(ipv6)
    assert str(ipv6)

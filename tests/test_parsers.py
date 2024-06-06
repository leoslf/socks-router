from __future__ import annotations

import pytest

from parsec import ParseError
from socks_router.models import Host, IPv4, IPv6, Address, Pattern, RoutingTable
from socks_router.parsers import (
    trace,
    ipv4_octet,
    ipv4,
    ipv4_address,
    ipv6,
    ipv6_address,
    pattern,
    configuration_entry,
    configuration,
)

def test_trace():
    assert trace(1) == 1

def test_ipv4_octet():
    assert ipv4_octet.parse("0") == 0
    assert ipv4_octet.parse("255") == 255

    with pytest.raises(ParseError):
        ipv4_octet.parse("256")

@pytest.mark.parametrize("input", [
    "127.0.0.1",
    "10.0.0.1",
    "172.0.0.1",
    "192.168.1.1",
    "255.255.255.255",
])
def test_ipv4(input: str):
    assert ipv4.parse(input) == input

@pytest.mark.parametrize("input,result", [
    ("127.0.0.1", IPv4("127.0.0.1")),
    ("127.0.0.1:443", IPv4("127.0.0.1", 443)),
])
def test_ipv4_address(input: str, result: IPv4):
    assert ipv4_address.parse(input) == result

@pytest.mark.parametrize("input", [
    "::",
    "::1",
    "::127.0.0.1",
    # cloudflare 1.1.1.1
    "2606:4700:4700::1111",
    # cloudflare 1.0.0.1
    "2606:4700:4700::1001",
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
])
def test_ipv6(input: str):
    assert ipv6.parse(input) == input

@pytest.mark.parametrize("input,result", [
    ("::", IPv6("::")),
    ("[::]:443", IPv6("::", 443)),
])
def test_ipv6_address(input: str, result: IPv6):
    assert ipv6_address.parse(input) == result

@pytest.mark.parametrize("input,result", [
    ("foo", Pattern(True, Host("foo"))),
    ("!bar", Pattern(False, Host("bar",))),
    ("*.bar", Pattern(True, Host("*.bar"))),
    ("foo-*.baz", Pattern(True, Host("foo-*.baz"))),
    ("*", Pattern(True, Host("*"))),
])
def test_pattern(input: str, result: Pattern):
    assert pattern.parse(input) == result

@pytest.mark.parametrize("input,result", [
    ("foo bar baz", (Host("foo"), [Pattern(True, Host("bar")), Pattern(True, Host("baz"))])),
    ("foo !bar baz", (Host("foo"), [Pattern(False, Host("bar")), Pattern(True, Host("baz"))])),
    ("foo *.bar foo-*.baz", (Host("foo"), [Pattern(True, Host("*.bar")), Pattern(True, Host("foo-*.baz"))])),
])
def test_configuration_entry(input: str, result: tuple[Address, list[Pattern]]):
    assert configuration_entry.parse(input) == result

@pytest.mark.parametrize("input", [
    "!foo",
])
def test_configuration_entry_failures(input: str):
    with pytest.raises(ParseError):
        configuration_entry.parse(input)

@pytest.mark.parametrize("input,routing_table", [
    ("test foo bar\n", { Host("test"): [Pattern(True, Host("foo")), Pattern(True, Host("bar"))] }),
    ("test foo bar\ntest2 f* !foo baz\n", { Host("test"): [Pattern(True, Host("foo")), Pattern(True, Host("bar"))], Host("test2"): [Pattern(True, Host("f*")), Pattern(False, Host("foo")), Pattern(True, Host("baz"))] }),
])
def test_configuration(input: str, routing_table: RoutingTable):
    assert configuration.parse(input) == routing_table

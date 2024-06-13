from __future__ import annotations

import pytest

from typing import cast

from parsec import ParseError
from socks_router.models import (
    Host,
    IPv4,
    IPv6,
    Address,
    UpstreamScheme,
    UpstreamAddress,
    Pattern,
    RoutingEntry,
    RoutingTable,
)
from socks_router.parsers import (
    trace,
    ipv4_octet,
    ipv4,
    ipv4_address,
    ipv6,
    ipv6_address,
    scheme,
    upstream_address,
    pattern,
    routing_rule,
    routing_table,
)


def test_trace():
    assert trace(1) == 1


def test_ipv4_octet():
    assert ipv4_octet.parse("0") == 0
    assert ipv4_octet.parse("255") == 255

    with pytest.raises(ParseError):
        ipv4_octet.parse("256")


@pytest.mark.parametrize(
    "input",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.0.0.1",
        "192.168.1.1",
        "255.255.255.255",
    ],
)
def test_ipv4(input: str):
    assert ipv4.parse(input) == input


@pytest.mark.parametrize(
    "input,result",
    [
        ("127.0.0.1", IPv4("127.0.0.1")),
        ("127.0.0.1:443", IPv4("127.0.0.1", 443)),
    ],
)
def test_ipv4_address(input: str, result: IPv4):
    assert ipv4_address.parse(input) == result


@pytest.mark.parametrize(
    "input",
    [
        "::",
        "::1",
        "::127.0.0.1",
        # cloudflare 1.1.1.1
        "2606:4700:4700::1111",
        # cloudflare 1.0.0.1
        "2606:4700:4700::1001",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ],
)
def test_ipv6(input: str):
    assert ipv6.parse(input) == input


@pytest.mark.parametrize(
    "input,result",
    [
        ("::", IPv6("::")),
        ("[::]:443", IPv6("::", 443)),
    ],
)
def test_ipv6_address(input: str, result: IPv6):
    assert ipv6_address.parse(input) == result


@pytest.mark.parametrize("input,upstream_scheme", [(f"{scheme}://", scheme) for scheme in UpstreamScheme])
def test_scheme(input: str, upstream_scheme: UpstreamScheme):
    assert scheme.parse(input) == upstream_scheme


@pytest.mark.parametrize(
    "input,upstream",
    [
        (f"{scheme_string}{upstream_addr.address}", upstream_addr)
        for (scheme_string, scheme) in ([("", UpstreamScheme.SSH)] + [(f"{scheme}://", scheme) for scheme in UpstreamScheme])
        for address in [IPv4("127.0.0.1"), IPv6("::1"), Host("localhost")]
        for use_default_port in [True, False]
        if (upstream := UpstreamAddress(scheme, cast(Address, address)))
        and (upstream_addr := upstream.with_default_port() if use_default_port else upstream)
    ],
)
def test_upstream_address(input: str, upstream: UpstreamAddress):
    assert upstream_address.parse(input) == upstream


@pytest.mark.parametrize(
    "input,result",
    [
        ("foo", Pattern("foo")),
        ("!bar", Pattern("bar", False)),
        ("*.bar", Pattern("*.bar")),
        ("foo-*.baz", Pattern("foo-*.baz")),
        ("*", Pattern("*")),
        ("::1", Pattern("::1")),
        ("[::1]:12345", Pattern("[::1]:12345")),
        ("[::1]:123?5", Pattern("[::1]:123?5")),
        ("[*::1]:12345", Pattern("[*::1]:12345")),
    ],
    ids=str,
)
def test_pattern(input: str, result: Pattern):
    assert pattern.parse(input) == result


@pytest.mark.parametrize(
    "input,result",
    [
        (
            "foo bar baz",
            (
                UpstreamAddress(UpstreamScheme.SSH, Host("foo")),
                [Pattern("bar"), Pattern("baz")],
            ),
        ),
        (
            "foo !bar baz",
            (
                UpstreamAddress(UpstreamScheme.SSH, Host("foo")),
                [Pattern("bar", False), Pattern("baz")],
            ),
        ),
        (
            "foo *.bar foo-*.baz",
            (
                UpstreamAddress(UpstreamScheme.SSH, Host("foo")),
                [Pattern("*.bar"), Pattern("foo-*.baz")],
            ),
        ),
        (
            "foo:22 *.bar foo-*.baz",
            (
                UpstreamAddress(UpstreamScheme.SSH, Host("foo", 22)),
                [Pattern("*.bar"), Pattern("foo-*.baz")],
            ),
        ),
        # arbitrary spacing
        (
            "foo  bar baz",
            (
                UpstreamAddress(UpstreamScheme.SSH, Host("foo")),
                [Pattern("bar"), Pattern("baz")],
            ),
        ),
    ],
)
def test_routing_entry(input: str, result: tuple[UpstreamAddress, RoutingEntry]):
    assert routing_rule.parse(input) == result


@pytest.mark.parametrize(
    "input",
    [
        "!foo",
    ],
)
def test_routing_entry_failures(input: str):
    with pytest.raises(ParseError):
        routing_rule.parse(input)


@pytest.mark.parametrize(
    "input,routing",
    [
        # empty routing file
        (
            "",
            {},
        ),
        (
            "test foo bar\n",
            {
                UpstreamAddress(UpstreamScheme.SSH, Host("test")): [
                    Pattern("foo"),
                    Pattern("bar"),
                ]
            },
        ),
        (
            "test foo bar\r\n",
            {
                UpstreamAddress(UpstreamScheme.SSH, Host("test")): [
                    Pattern("foo"),
                    Pattern("bar"),
                ]
            },
        ),
        (
            "test foo bar\ntest2 f* !foo baz\n",
            {
                UpstreamAddress(UpstreamScheme.SSH, Host("test")): [
                    Pattern("foo"),
                    Pattern("bar"),
                ],
                UpstreamAddress(UpstreamScheme.SSH, Host("test2")): [
                    Pattern("f*"),
                    Pattern("foo", False),
                    Pattern("baz"),
                ],
            },
        ),
        # line-based comment
        (
            "test foo bar # this comment should be ignored \ntest2 f* !foo baz\n",
            {
                UpstreamAddress(UpstreamScheme.SSH, Host("test")): [
                    Pattern("foo"),
                    Pattern("bar"),
                ],
                UpstreamAddress(UpstreamScheme.SSH, Host("test2")): [
                    Pattern("f*"),
                    Pattern("foo", False),
                    Pattern("baz"),
                ],
            },
        ),
        # arbitrary empty lines should be ignored
        (
            "test foo bar\n",
            {
                UpstreamAddress(UpstreamScheme.SSH, Host("test")): [
                    Pattern("foo"),
                    Pattern("bar"),
                ]
            },
        ),
    ],
)
def test_routing_table(input: str, routing: RoutingTable):
    assert routing_table.parse(input) == routing

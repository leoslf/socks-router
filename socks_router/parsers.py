from __future__ import annotations


import logging

# from collection.abc import Callable

from parsec import (
    Parser,
    string,
    regex,
    optional,
    end_of_line,
    times,
    many,
    one_of,
    sepBy,
    between,
    joint,
    separated,
    try_choices_longest,
    fail_with,
    validate,
    decimal_number,
    hexadecimal_number,
)
from socks_router.models import Address, IPv4, IPv6, Host, Pattern, RoutingTable
from socks_router.utils import to_hex

logger = logging.getLogger(__name__)

def trace[T](value: T) -> T:
    logger.debug(f"value: {value}")
    return value

ipv4_octet: Parser[int] = (decimal_number >= validate(lambda value: 0 <= value < (1 << 8))) | fail_with(f"ipv4_octet can only carry a value ranged from 0 to {1 << 8} exclusive")
ipv6_doublet: Parser[int] = (hexadecimal_number >= validate(lambda value: 0 <= value < (1 << 16))) | fail_with("doublet can only carry a value from 0 to {1 << 16} exclusive")

ipv4: Parser[str] = separated(ipv4_octet.map(str), string("."), 4, end=False).map(".".join)

# SEE: https://datatracker.ietf.org/doc/html/draft-main-ipaddr-text-rep-00#section-3.2
h16: Parser[str] = ipv6_doublet.map(to_hex)
ls32: Parser[str] = joint(h16, string(":"), h16).map("".join) ^ ipv4

ipv6: Parser[str] = try_choices_longest(
    joint(separated(h16, string(":"), 6, end=False).map(":".join), string(":"), ls32).map("".join),
    *[joint(separated(h16, string(":"), 0, i, end=False).map(":".join), string("::"), times((h16 + string(":")).map("".join), 5 - i).map("".join), ls32).map("".join) for i in range(6)],
    joint(separated(h16, string(":"), 0, 6, end=False).map(":".join), string("::"), h16).map("".join),
    joint(separated(h16, string(":"), 0, 7, end=False).map(":".join), string("::")).map("".join),
)

port = (decimal_number >= validate(lambda value: 0 <= value < 65536)) | fail_with("port can only carry between 0 to 65536 exclusive")

ipv4_address: Parser[IPv4] = (ipv4 + optional(string(":") > port)).map(IPv4, star=True)

ipv6_address: Parser[IPv6] = ((between(string("["), string("]"), ipv6) + (string(":") > port)) ^ ipv6.map(lambda ipv6: (ipv6, None))).map(IPv6, star=True)

hostname: Parser[str] = regex(r"(?P<hostname>\b(?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])\b)")

host_address: Parser[Host] = (hostname + optional(string(":") > port)).map(Host, star=True)

upstream: Parser[Address] = ipv4_address ^ ipv6_address ^ host_address

wildcard_hostname = regex(r"(?:\S*[*]\S*)|(?:(?:[*]|(?:(?:[a-zA-Z0-9?*]|[a-zA-Z0-9?*][a-zA-Z0-9\-?*]*[a-zA-Z0-9?*]))\.)*(?:[*]|(?:[A-Za-z0-9?*]|[A-Za-z0-9?*][A-Za-z0-9\-?*]*[A-Za-z0-9?*]))\b)")

wildcard_host_address: Parser[Host] = (wildcard_hostname + optional(string(":") > port)).map(Host, star=True)

pattern: Parser[Pattern] = (optional(string("!").result(False), True) + wildcard_host_address).map(Pattern, star=True)

whitespace: Parser[list[str]] = many(one_of(" \t"))

configuration_entry: Parser[tuple[Address, list[Pattern]]] = (upstream << whitespace) + sepBy(pattern, whitespace).desc("patterns")

configuration: Parser[RoutingTable] = many(configuration_entry << end_of_line()).map(dict)
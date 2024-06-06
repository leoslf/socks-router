from typing import Mapping, Optional, Callable, Iterable
from enum import IntEnum, StrEnum, auto
from dataclasses import dataclass
from threading import Lock
from subprocess import Popen

class Socks5AddressType(IntEnum):
    IPv4 = 0x01
    DOMAINNAME = 0x03
    IPv6 = 0x04

class Socks5Command(IntEnum):
    CONNECT = 0x01
    BIND = 0x02
    UDP_ASSOCIATE = 0x03

class Socks5Method(IntEnum):
    """ SEE: https://datatracker.ietf.org/doc/html/rfc1928 """
    NO_AUTHENTICATION_REQUIRED = 0x00
    GSSAPI = 0x01
    USERNAME_PASSWORD = 0x02
    # IANA_ASSIGNED = 0x03
    # RESERVED_FOR_PRIVATE_METHODS = frozenset(range(0x80, 0xFF)) # 0x80..0xFE
    NO_ACCEPTABLE_METHDOS = 0xFF

class Socks5Reply(IntEnum):
    SUCCEEDED = 0x00
    GENERAL_SOCKS_SERVER_FAILURE = 0x01
    CONNECTION_NOT_ALLOWED_BY_RULESET = 0x02
    NETWORK_UNREACHABLE = 0x03
    HOST_UNREACHABLE = 0x04
    CONNECTION_REFUSED = 0x05
    TTL_EXPIRED = 0x06
    COMMAND_NOT_SUPPORTED = 0x07
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08
    # UNASSIGNED = frozenset(range(0x09, 0x100)) # 0x09..0xFF

class Socks5State(StrEnum):
    LISTEN = auto()
    HANDSHAKE = auto()
    REQUEST = auto()
    ESTABLISHED = auto()
    CLOSED = auto()

@dataclass(frozen=True)
class SocketAddress:
    address: str
    port: Optional[int] = None

    def __str__(self):
        if self.port is None:
            return self.address
        return f"{self.address}:{self.port}"

@dataclass(frozen=True)
class IPv4(SocketAddress):
    @property
    def type(self):
        return Socks5AddressType.IPv4

@dataclass(frozen=True)
class IPv6(SocketAddress):
    @property
    def type(self):
        return Socks5AddressType.IPv6

    def __str__(self):
        if self.port is None:
            return self.address
        return f"[{self.address}]:{self.port}"

@dataclass(frozen=True)
class Host(SocketAddress):
    @property
    def type(self):
        return Socks5AddressType.DOMAINNAME

type Address = IPv4 | IPv6 | Host

@dataclass(frozen=True)
class Pattern:
    is_positive_match: bool
    address: Address

type RoutingTable = Mapping[Address, list[Pattern]]

Socks5Addresses: Mapping[Socks5AddressType, Address] = {
    Socks5AddressType.IPv4: IPv4,
    Socks5AddressType.IPv6: IPv6,
    Socks5AddressType.DOMAINNAME: Host,
}

@dataclass
class ApplicationContext:
    routing_table: RoutingTable
    mutex: Lock
    upstreams: Mapping[Address, tuple[Popen, Address]]


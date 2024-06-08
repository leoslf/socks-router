from __future__ import annotations
from typing import Literal, Optional
from subprocess import Popen
from abc import abstractmethod
from collections.abc import Callable, Mapping, MutableMapping
from enum import IntEnum, StrEnum, auto
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address

import struct
import threading

SOCKS_VERSION: Literal[5] = 5


@dataclass(frozen=True)
class SocketAddress:
    address: str
    port: Optional[int] = None

    def __str__(self):
        if self.port is None:
            return self.address
        return f"{self.address}:{self.port}"

    @property
    def pattern(self) -> str:
        return f"{self.address}:{self.port or '*'}"

    @property
    def sockaddr(self) -> tuple[str, int]:
        return self.address, self.port or 0

    @property
    @abstractmethod
    def type(self) -> Socks5AddressType: ...

    @property
    def packed_type(self) -> bytes:
        return struct.pack("!B", self.type)

    @property
    @abstractmethod
    def packed_address(self) -> bytes: ...

    @property
    def packed_port(self) -> bytes:
        return struct.pack("!H", self.port or 0)

    def __bytes__(self) -> bytes:
        return self.packed_type + self.packed_address + self.packed_port


@dataclass(frozen=True)
class IPv4(SocketAddress):
    @property
    def type(self) -> Socks5AddressType:
        return Socks5AddressType.IPv4

    @property
    def packed_address(self) -> bytes:
        return IPv4Address(self.address).packed


@dataclass(frozen=True)
class IPv6(SocketAddress):
    @property
    def type(self) -> Socks5AddressType:
        return Socks5AddressType.IPv6

    def __str__(self):
        if self.port is None:
            return f"{self.address}"
        return f"[{self.address}]:{self.port}"

    @property
    def pattern(self):
        return f"[{self.address}]:{self.port or '*'}"

    @property
    def packed_address(self) -> bytes:
        return IPv6Address(self.address).packed


@dataclass(frozen=True)
class Host(SocketAddress):
    @property
    def type(self) -> Socks5AddressType:
        return Socks5AddressType.DOMAINNAME

    @property
    def packed_address(self) -> bytes:
        encoded = self.address.encode("utf-8")
        assert len(encoded) < 255, "can only carry less than 255 bytes for host"
        return struct.pack("!B", len(encoded)) + encoded


type Address = IPv4 | IPv6 | Host


class Socks5Method(IntEnum):
    """SEE: https://datatracker.ietf.org/doc/html/rfc1928#section-3"""

    NO_AUTHENTICATION_REQUIRED = 0x00
    GSSAPI = 0x01
    USERNAME_PASSWORD = 0x02
    # IANA_ASSIGNED = 0x03
    # RESERVED_FOR_PRIVATE_METHODS = frozenset(range(0x80, 0xFF)) # 0x80..0xFE
    NO_ACCEPTABLE_METHODS = 0xFF


class Socks5Command(IntEnum):
    """SEE: https://datatracker.ietf.org/doc/html/rfc1928#section-4"""

    CONNECT = 0x01
    BIND = 0x02
    UDP_ASSOCIATE = 0x03


class Socks5AddressType(IntEnum):
    """SEE: https://datatracker.ietf.org/doc/html/rfc1928#section-4"""

    IPv4 = 0x01
    DOMAINNAME = 0x03
    IPv6 = 0x04


@dataclass
class Socks5MethodSelectionRequest:
    """Socks5 Header.
    SEE: https://datatracker.ietf.org/doc/html/rfc1928#section-3
    Header
    ------
    | version | method_count | methods              |
    | 1 byte  | 1 byte       | [method_count] bytes |
    """

    version: int
    methods: list[int]

    def __bytes__(self) -> bytes:
        assert len(self.methods) < 256
        return struct.pack("!BB", self.version, len(self.methods)) + bytes(self.methods)


@dataclass
class Socks5MethodSelectionResponse:
    """Socks5 Method Selection Response
    Method Selection Response
    -------------------------
    | version | method |
    | 1 byte  | 1 byte |
    """

    version: int
    method: Socks5Method

    def __bytes__(self) -> bytes:
        return struct.pack("!BB", self.version, self.method)


@dataclass(frozen=True)
class Socks5Request:
    """SEE: https://datatracker.ietf.org/doc/html/rfc1928#section-4"""

    version: int
    command: Socks5Command
    reserved: Literal[0x00]
    address_type: Socks5AddressType
    destination_address: str
    destination_port: int

    @property
    def destination(self):
        return Socks5Addresses[self.address_type](self.destination_address, self.destination_port)


class Socks5ReplyType(IntEnum):
    """SEE: https://datatracker.ietf.org/doc/html/rfc1928#section-6"""

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


@dataclass
class Socks5Reply:
    """Socks5 Reply
    Reply
    -----
    | version | reply  | rsv  | atyp   | dst.addr    | dst.port |
    | 1 byte  | 1 byte | 0x00 | 1 byte | 4-255 bytes | 2 bytes  |
    """

    version: Literal[5]
    reply: Socks5ReplyType
    reserved: Literal[0] = 0x00
    address: Address = IPv4("0.0.0.0", 0)

    def __bytes__(self) -> bytes:
        return struct.pack("!BBB", self.version, self.reply, self.reserved) + bytes(self.address)


class Socks5State(StrEnum):
    LISTEN = auto()
    HANDSHAKE = auto()
    REQUEST = auto()
    ESTABLISHED = auto()
    CLOSED = auto()


@dataclass(frozen=True)
class Pattern:
    address: Address
    is_positive_match: bool = True

    def __str__(self):
        return ("" if self.is_positive_match else "!") + "%s" % self.address


class UpstreamScheme(StrEnum):
    SSH = auto()
    SOCKS5 = auto()


@dataclass(frozen=True)
class UpstreamAddress(object):
    scheme: UpstreamScheme
    address: Address

    def __str__(self):
        return f"{self.scheme}://{self.address}"


type RoutingEntry = list[Pattern]

type RoutingTable = Mapping[UpstreamAddress, RoutingEntry]

Socks5Addresses: Mapping[Socks5AddressType, Callable[[str, Optional[int]], Address]] = {
    Socks5AddressType.IPv4: IPv4,
    Socks5AddressType.IPv6: IPv6,
    Socks5AddressType.DOMAINNAME: Host,
}


@dataclass
class SSHUpstream:
    ssh_client: Popen
    proxy_server: Address


@dataclass
class ProxyUpstream:
    proxy_server: Address


type Upstream = SSHUpstream | ProxyUpstream


@dataclass(frozen=True)
class RetryOptions:
    tries: int = -1
    delay: int = 1
    max_delay: Optional[int] = None
    backoff: int = 1
    jitter: int = 0

    @classmethod
    def exponential_backoff(cls, *argv, backoff=2, **kwargs):
        return cls(*argv, backoff=backoff, **kwargs)


@dataclass
class ApplicationContext:
    name: str = "socks-router"
    routing_table: RoutingTable = field(default_factory=dict)
    # seconds
    request_timeout: Optional[float] = 1
    proxy_retry_options: RetryOptions = field(default_factory=RetryOptions.exponential_backoff)
    mutex: threading.Lock = field(default_factory=threading.Lock)
    upstreams: MutableMapping[UpstreamAddress, Upstream] = field(default_factory=dict)
    is_terminating: bool = False

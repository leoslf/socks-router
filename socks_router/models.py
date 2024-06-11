from __future__ import annotations

from typing import Any, Annotated, Final, Literal, Optional, Type, Self, Protocol, runtime_checkable, overload, assert_never
from abc import abstractmethod
from collections.abc import Mapping, MutableMapping
from enum import IntEnum, StrEnum, auto
from dataclasses import dataclass, field
from subprocess import Popen

import threading
import ipaddress

SOCKS_VERSION: Literal[5] = 5

type PackingSequence = str | tuple[str, str]

type RecursiveMapping[K, V] = Mapping[K, V | RecursiveMapping[K, V]]

PACKABLE_DEFERRED_FORMAT: Final[str] = "&"
PACKABLE_VARIABLE_LENGTH_DECLARATION_FORMAT: Final[str] = "%*"


@runtime_checkable
class Packable(Protocol):
    @classmethod
    def __pack_format__(cls) -> str: ...


@runtime_checkable
class SupportsUnbytes(Protocol):
    @classmethod
    @abstractmethod
    def __unbytes__(cls, input: bytes) -> Self: ...


@dataclass(frozen=True)
class SocketAddress:
    address: Any = field()
    port: Annotated[Optional[int], "!H"] = None

    def __str__(self):
        if self.port is None:
            return f"{self.address}"
        return f"{self.address}:{self.port}"

    @property
    def pattern(self) -> str:
        return f"{self.address}:{self.port or '*'}"

    @property
    def sockaddr(self) -> tuple[str, int]:
        return f"{self.address}", self.port or 0


@dataclass(frozen=True)
class IPv4(SocketAddress):
    address: IPv4.IPv4Address

    class IPv4Address(ipaddress.IPv4Address):
        @classmethod
        def __pack_format__(cls) -> str:
            return "!4B"

        def __bytes__(self) -> bytes:
            return self.packed

        @classmethod
        def __unbytes__(cls, input: bytes) -> Self:
            return cls(input)

    def __init__(self, address: str | IPv4.IPv4Address, *argv, **kwargs):
        if isinstance(address, str):
            address = IPv4.IPv4Address(address)
        super().__init__(address, *argv, **kwargs)


@dataclass(frozen=True)
class IPv6(SocketAddress):
    address: IPv6.IPv6Address

    class IPv6Address(ipaddress.IPv6Address):
        @classmethod
        def __pack_format__(cls) -> str:
            return "!16B"

        def __bytes__(self) -> bytes:
            return self.packed

        @classmethod
        def __unbytes__(cls, input: bytes) -> Self:
            return cls(input)

    def __init__(self, address: str | IPv6.IPv6Address, *argv, **kwargs):
        if isinstance(address, str):
            address = IPv6.IPv6Address(address)
        super().__init__(address, *argv, **kwargs)

    def __str__(self):
        if self.port is None:
            return f"{self.address}"
        return f"[{self.address}]:{self.port}"

    @property
    def pattern(self):
        return f"[{self.address}]:{self.port or '*'}"


@dataclass(frozen=True)
class Host(SocketAddress):
    address: Annotated[str, "!B%*s"]


type Address = IPv4 | IPv6 | Host


class Socks5Method(IntEnum):
    """SEE: https://datatracker.ietf.org/doc/html/rfc1928#section-3"""

    NO_AUTHENTICATION_REQUIRED = 0x00
    GSSAPI = 0x01
    USERNAME_PASSWORD = 0x02
    # IANA_ASSIGNED = 0x03
    # RESERVED_FOR_PRIVATE_METHODS = frozenset(range(0x80, 0xFF)) # 0x80..0xFE
    NO_ACCEPTABLE_METHODS = 0xFF

    @classmethod
    def __pack_format__(cls) -> str:
        return "!B"


class Socks5Command(IntEnum):
    """SEE: https://datatracker.ietf.org/doc/html/rfc1928#section-4"""

    CONNECT = 0x01
    BIND = 0x02
    UDP_ASSOCIATE = 0x03

    @classmethod
    def __pack_format__(cls) -> str:
        return "!B"


class Socks5AddressType(IntEnum):
    """SEE: https://datatracker.ietf.org/doc/html/rfc1928#section-4"""

    IPv4 = 0x01
    # A fully-qualified domain name.  The first octet of the address field contains the number of octets of name that follow, there is no terminating NUL octet.
    DOMAINNAME = 0x03
    IPv6 = 0x04

    @classmethod
    def __pack_format__(cls) -> str:
        return "!B"


@dataclass
class Socks5MethodSelectionRequest:
    """Socks5 Header.
    SEE: https://datatracker.ietf.org/doc/html/rfc1928#section-3
    Header
    ------
    | version | method_count | methods              |
    | 1 byte  | 1 byte       | [method_count] bytes |
    """

    version: Annotated[int, "!B"]
    methods: Annotated[list[int], "!B%*B"]


@dataclass
class Socks5MethodSelectionResponse:
    """Socks5 Method Selection Response
    Method Selection Response
    -------------------------
    | version | method |
    | 1 byte  | 1 byte |
    """

    version: Annotated[int, "!B"]
    method: Socks5Method


@dataclass(frozen=True)
class Socks5Address:
    @classmethod
    @overload
    def address_type(cls, type: Literal[Socks5AddressType.IPv4]) -> Type[IPv4]: ...
    @classmethod
    @overload
    def address_type(cls, type: Literal[Socks5AddressType.DOMAINNAME]) -> Type[Host]: ...
    @classmethod
    @overload
    def address_type(cls, type: Literal[Socks5AddressType.IPv6]) -> Type[IPv6]: ...

    @classmethod
    def address_type(cls, type: Socks5AddressType) -> Type[IPv4] | Type[Host] | Type[IPv6]:
        match type:
            case Socks5AddressType.IPv4:
                return IPv4
            case Socks5AddressType.DOMAINNAME:
                return Host
            case Socks5AddressType.IPv6:
                return IPv6
            case _ as unreachable:
                assert_never(unreachable)

    type: Socks5AddressType
    sockaddr: Annotated[Address, "&", "type", "address_type"]

    @classmethod
    def from_address(cls, address: Address) -> Self:
        match address:
            case IPv4():
                return cls(Socks5AddressType.IPv4, address)
            case Host():
                return cls(Socks5AddressType.DOMAINNAME, address)
            case IPv6():
                return cls(Socks5AddressType.IPv6, address)
            case _ as unreachable:
                assert_never(unreachable)


@dataclass(frozen=True)
class Socks5Request:
    """SEE: https://datatracker.ietf.org/doc/html/rfc1928#section-4
    Request
    -------
    | version | cmd    | rsv  | atyp   | dst.addr    | dst.port |
    | 1 byte  | 1 byte | 0x00 | 1 byte | 4-255 bytes | 2 bytes  |
    """

    version: Annotated[int, "!B"]
    command: Socks5Command
    reserved: Annotated[int, "!B"]
    destination: Socks5Address


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

    @classmethod
    def __pack_format__(cls) -> str:
        return "!B"


@dataclass(frozen=True)
class Socks5Reply:
    """Socks5 Reply
    Reply
    -----
    | version | reply  | rsv  | atyp   | dst.addr    | dst.port |
    | 1 byte  | 1 byte | 0x00 | 1 byte | 4-255 bytes | 2 bytes  |
    """

    version: Annotated[int, "!B"]
    reply: Socks5ReplyType
    reserved: Annotated[int, "!B"] = 0x00
    server_bound_address: Socks5Address = Socks5Address.from_address(IPv4("0.0.0.0", 0))


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

Socks5Addresses: Mapping[Socks5AddressType, type[Address]] = {
    Socks5AddressType.IPv4: IPv4,
    Socks5AddressType.IPv6: IPv6,
    Socks5AddressType.DOMAINNAME: Host,
}

Socks5AddressTypes = {
    IPv4: Socks5AddressType.IPv4,
    IPv6: Socks5AddressType.IPv6,
    Host: Socks5AddressType.DOMAINNAME,
}


@dataclass(frozen=True)
class SSHUpstream:
    ssh_client: Popen
    proxy_server: Address


@dataclass(frozen=True)
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
        return cls(*argv, **dict(backoff=backoff, **kwargs))


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

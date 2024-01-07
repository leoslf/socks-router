import os
import logging
import traceback

import time
import struct
import fnmatch
import shlex

import socket
import socks

from typing import Mapping, Optional, Callable, Iterable
from itertools import tee, filterfalse
from enum import IntEnum
from select import select
from threading import Thread, Lock
from subprocess import Popen, PIPE
from socketserver import StreamRequestHandler

SOCKS_VERSION = 5
CHUNK_SIZE = 4096

logger = logging.getLogger(__name__)

def partition[T](predicate: Callable[[T], bool],
                 iterable: Iterable[T]) -> tuple[Iterable[T], Iterable[T]]:
    a, b = tee(iterable)
    return filter(predicate, a), filterfalse(predicate, b)

def read_routes() -> list[str]:
    if "SOCKS_ROUTER_ROUTES" in os.environ:
        return [line for line in os.environ["SOCKS_ROUTER_ROUTES"].split("\n")]

    routes_file = os.environ.get("SOCKS_ROUTER_ROUTES_FILE", "~/.ssh/routes")
    if not os.path.isfile(os.path.expanduser(routes_file)):
        logger.warning(f"SOCKS_ROUTER_ROUTES_FILE {routes_file} file not found")
        return []

    with open(os.path.expanduser(routes_file)) as f:
        return f.readlines()

def read_routing_table() -> Mapping[str, list[str]]:
    return { upstream: patterns for upstream, *patterns in map(lambda line: line.strip().split(), read_routes()) }

def free_port() -> int:
    with socket.socket() as s:
        s.bind(('', 0))
        return s.getsockname()[1]

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
    # RESERVED_FOR_PRIVATE_METHODS = 0x80 ... 0xFE
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
    # 0x09 - 0xFF unassigned

def read_request(connection: socket.socket) -> tuple[int, Socks5Command, Socks5AddressType, str, int]:
    # request
    # | version | cmd    | rsv  | atyp   | dst.addr    | dst.port |
    # | 1 byte  | 1 byte | 0x00 | 1 byte | 4-255 bytes | 2 bytes  |
    version, cmd, _, address_type = struct.unpack("!BBBB", connection.recv(4))
    address = read_address(address_type, connection)
    port, = struct.unpack("!H", connection.recv(2))
    return version, cmd, address_type, address, port

def read_address(type: Socks5AddressType,
                 connection: socket.socket) -> str:
    logger.info(f"type: {type}")
    match type:
        case Socks5AddressType.IPv4:
            return socket.inet_ntop(socket.AF_INET, connection.recv(4))
        case Socks5AddressType.DOMAINNAME:
            address_length, = connection.recv(1)
            return connection.recv(address_length).decode("utf-8")
        case Socks5AddressType.IPv6:
            return socket.inet_ntop(socket.AF_INET6, connection.recv(6))
        case _:
            raise ValueError(f"unsupported type: {type}")

def read_header(connection: socket.socket) -> tuple[int, set[int]]:
    """ Handle incoming connections """
    # header
    # | version | method_count | methods              |
    # | 1 byte  | 1 byte       | [method_count] bytes |
    version, method_count = struct.unpack("!BB", connection.recv(2))

    # get available methods
    return version, set(connection.recv(method_count))

def exchange_loop(client: socket.socket, remote: socket.socket):
    while True:
        r, w, e = select([client, remote], [], [])
        if client in r:
            data = client.recv(CHUNK_SIZE)
            if remote.send(data) <= 0:
                break

        if remote in r:
            data = remote.recv(CHUNK_SIZE)
            if client.send(data) <= 0:
                break

def reply(reply: Socks5Reply,
          address_type: Socks5AddressType = Socks5AddressType.IPv4,
          bind_address: Optional[str] = None,
          bind_port: Optional[int] = None):
    return struct.pack("!BBBBIH",
                       SOCKS_VERSION,
                       reply,
                       0x00,
                       address_type,
                       0 if bind_address is None else struct.unpack("!I", socket.inet_aton(bind_address))[0],
                       0 if bind_port is None else bind_port)

def create_remote(type: Socks5AddressType) -> socket.socket:
    match type:
        case Socks5AddressType.IPv4 | Socks5AddressType.DOMAINNAME:
            return socks.sockssocket()
        case Socks5AddressType.IPv6:
            return socks.sockssocket(socket.AF_INET6, socket.SOCK_STREAM, 0)

def is_ready(type: Socks5AddressType, address: str, port: int) -> bool:
    with create_remote(type) as remote:
        remote.settimeout(1)
        return remote.connect_ex((address, port)) == 0

class SocksRouter(StreamRequestHandler):
    routing_table: Mapping[str, list[str]]

    mutex: Lock
    ssh_clients: Mapping[str, Popen]
    upstreams: Mapping[str, int]

    def __init__(self,
                 routing_table: Mapping[str, list[str]],
                 mutex: Lock,
                 ssh_clients: Mapping[str, Popen],
                 upstreams: Mapping[str, int],
                 *argv,
                 **kwargs):
        self.routing_table = routing_table
        self.mutex = mutex
        self.ssh_clients = ssh_clients
        self.upstreams = upstreams
        super().__init__(*argv, **kwargs)

    def __call__(self):
        return self

    def match_upstream(self, address, port) -> str:
        for upstream, patterns in self.routing_table.items():
            logger.debug(f"[match_upstream] matching upstream: {upstream}, patterns: {patterns}, address: {address}")
            denied, allowed = partition(lambda pattern: pattern.startswith("!"), patterns)
            if any(fnmatch.filter([address], patterns) for pattern in allowed) and all(not fnmatch.filter([address], pattern.removeprefix("!")) for pattern in denied):
                logger.debug(f"[match_upstream] matched upstream: {upstream}, patterns: {patterns}, address: {address}")
                return upstream

        logger.debug(f"fallback upstream: {None}")
        return None

    def acquire_upstream(self, address, port) -> Optional[int]:
        upstream = self.match_upstream(address, port)
        if upstream is None:
            return None

        if upstream in self.upstreams:
            return self.upstreams[upstream]

        with self.mutex:
            proxy_port = free_port()
            logger.debug(f"Free port: {proxy_port}")
            command = shlex.split(f"ssh -NT -D {proxy_port} -o ServerAliveInterval=240 -o ExitOnForwardFailure=yes {upstream}")
            logger.debug(f"command: {command}")
            process = Popen(command)

            def connectable():
                for _ in range(10):
                    if is_ready(Socks5AddressType.IPv4, '127.0.0.1', proxy_port):
                        return True
                    time.sleep(1)
                return False

            if connectable():
                self.ssh_clients[upstream] = process
                self.upstreams[upstream] = proxy_port
                return proxy_port

            return None

    def connect_remote(self, type: Socks5AddressType, address: str, port: int) -> socket.socket:
        remote = create_remote(type)

        if proxy_port := self.acquire_upstream(address, port):
            logger.info(f"setting proxy localhost:{proxy_port} for address: {address}, port: {port}")
            remote.set_proxy(socks.SOCKS5, "localhost", proxy_port)
        remote.connect((address, port))
        return remote

    def handle(self):
        """ Handle incoming connections """

        # handshake
        version, methods = read_header(self.connection)
        if version != SOCKS_VERSION or Socks5Method.NO_AUTHENTICATION_REQUIRED not in methods:
            logger.error(f"invalid request: version: {version}, methods: {methods}")
            # close connection
            self.server.close_request(self.request)
            return

        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, Socks5Method, NO_AUTHENTICATION_REQUIRED))

        # request
        version, cmd, address_type, address, port = read_request(self.connection)
        # reply
        try:
            match cmd:
                case Socks5Command.CONNECT:
                    remote = self.connect_remote(address_type, address, port)
                    bind_address, bind_port = remote.getsockname()
                    logger.info(f"Connected to {address}:{port}, bind_address: {bind_address}:{bind_port}")
                    self.connection.sendall(reply(Socks5Reply.SUCCEEDED))
                    exchange_loop(self.connection, remote)
                case _:
                    self.connection.sendall(reply(Socks5Reply.COMMAND_NOT_SUPPORTED))
        except Exception as e:
            traceback.print_exc()
            logger.error(e)
            self.connection.sendall(reply(Socks5Reply.CONNECTION_REFUSED))

        self.server.close_request(self.request)

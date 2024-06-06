import logging
import traceback

import time
import struct
import fnmatch

import socket
import socks

from typing import Optional
from more_itertools import partition
from select import select
from subprocess import Popen
from socketserver import StreamRequestHandler

from socks_router.models import (
    Socks5Command,
    Socks5Method,
    Socks5AddressType,
    Socks5Reply,
    Socks5State,
    Socks5Addresses,
    Address,
    IPv4,
    ApplicationContext,
    RoutingTable,
)

SOCKS_VERSION = 5
CHUNK_SIZE = 4096

logger = logging.getLogger(__name__)

def free_port() -> int:
    with socket.socket() as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def read_request(connection: socket.socket) -> tuple[int, Socks5Command, Socks5AddressType, str, int]:
    """ Read Request.
    Request
    -------
    | version | cmd    | rsv  | atyp   | dst.addr    | dst.port |
    | 1 byte  | 1 byte | 0x00 | 1 byte | 4-255 bytes | 2 bytes  |
    """
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
    """ Read Socks5 Header.
    Header
    ------
    | version | method_count | methods              |
    | 1 byte  | 1 byte       | [method_count] bytes |
    """
    version, method_count = struct.unpack("!BB", connection.recv(2))

    # get available methods
    return version, set(connection.recv(method_count))

def exchange_loop(client: socket.socket, remote: socket.socket):
    while True:
        r, w, e = select([client, remote], [client, remote], [], 0.0)
        if client in r and remote in w:
            data = client.recv(CHUNK_SIZE)
            if remote.send(data) <= 0:
                break

        if remote in r and client in w:
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
            return socks.socksocket()
        case Socks5AddressType.IPv6:
            return socks.socksocket(socket.AF_INET6, socket.SOCK_STREAM, 0)

def is_ready(address: Address, timeout: float = 1.0) -> bool:
    logger.debug(f"checking if {address} is ready")
    with create_remote(address.type) as remote:
        remote.settimeout(timeout)
        return remote.connect_ex((address.address, address.port)) == 0

class SocksRouter(StreamRequestHandler):
    context: ApplicationContext

    state: Socks5State = Socks5State.LISTEN
    remote: Optional[socket.socket] = None

    def __init__(self, context: ApplicationContext, *argv, **kwargs):
        self.context = context
        super().__init__(*argv, **kwargs)

    def __call__(self):
        return self

    @staticmethod
    def match_upstream(routing_table: RoutingTable, address: Address) -> Optional[Address]:
        for upstream, patterns in routing_table.items():
            logger.debug(f"[match_upstream] matching upstream: {upstream}, patterns: {patterns}, address: {address}")
            denied, allowed = partition(lambda pattern: pattern.is_positive_match, patterns)
            if any(fnmatch.filter([str(address)], str(pattern.address)) for pattern in allowed) and not any(fnmatch.filter([str(address)], str(pattern.address)) for pattern in denied):
                logger.debug(f"[match_upstream] matched upstream: {upstream}, patterns: {patterns}, address: {address}")
                return upstream
        logger.debug(f"fallback upstream: {None}")
        return None

    def acquire_upstream(self, address: Address, retries: int = 10, timeout: float = 0.1) -> Optional[Address]:
        upstream = self.match_upstream(self.context.routing_table, address)
        if upstream is None:
            return None

        if upstream in self.context.upstreams:
            ssh_client, proxy_server = self.context.upstreams[upstream]
            if ssh_client.poll() is None:
                logger.debug(f"found working upstream: {upstream} -> {proxy_server}")
                return upstream

            with self.context.mutex:
                logger.info(f"upstream {upstream}, proxy_server: {proxy_server} connection is dead, removing from upstreams")
                del self.context.upstreams[upstream]
        else:
            logger.debug(f"upstream: {upstream} does not appear in self.upstreams")

        with self.context.mutex:
            proxy_server = IPv4("127.0.0.1", free_port())
            logger.debug(f"Free port: {proxy_server.port}")
            process = Popen(["ssh", "-NT", "-D", f"{proxy_server.port}", "-o", "ServerAliveInterval=240", "-o", "ExitOnForwardFailure=yes", f"{upstream}"])

            def connectable():
                for i in range(retries):
                    if is_ready(proxy_server, timeout):
                        return True
                    time.sleep(timeout * 2 ** i)
                return False

            if connectable():
                self.context.upstreams[upstream] = (process, proxy_server)
                return upstream

        return None

    def connect_remote(self, address: Address) -> socket.socket:
        remote = create_remote(address.type)
        if upstream := self.acquire_upstream(address):
            _, proxy_server = self.context.upstreams[upstream]
            logger.info(f"setting proxy {proxy_server.address}:{proxy_server.port} for address: {address}")
            remote.set_proxy(socks.SOCKS5, proxy_server.address, proxy_server.port)
        logger.info(f"connecting to address: {address}")
        remote.connect((address.address, address.port))
        return remote

    def handshake(self):
        version, methods = read_header(self.connection)
        if version != SOCKS_VERSION or Socks5Method.NO_AUTHENTICATION_REQUIRED not in methods:
            logger.error(f"invalid request: version: {version}, methods: {methods}")
            # close connection
            self.server.close_request(self.request)
            return

        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, Socks5Method.NO_AUTHENTICATION_REQUIRED))
        self.state = Socks5State.REQUEST

    def handle_request(self):
        # request
        version, cmd, address_type, address, port = read_request(self.connection)
        # reply
        try:
            match cmd:
                case Socks5Command.CONNECT:
                    self.remote = self.connect_remote(Socks5Addresses[address_type](address, port))
                    bind_address, bind_port = self.remote.getsockname()
                    logger.info(f"Connected to {address}:{port}, bind_address: {bind_address}:{bind_port}")
                    self.connection.sendall(reply(Socks5Reply.SUCCEEDED))
                    self.state = Socks5State.ESTABLISHED
                case _:
                    logger.warn(f"COMMAND_NOT_SUPPORTED: {cmd}")
                    self.connection.sendall(reply(Socks5Reply.COMMAND_NOT_SUPPORTED))
                    self.state = Socks5State.CLOSED
        except (socks.ProxyConnectionError, ConnectionRefusedError) as e:
            logger.error(e)
            self.connection.sendall(reply(Socks5Reply.CONNECTION_REFUSED))
            self.state = Socks5State.CLOSED

        except Exception as e:
            traceback.print_exc()
            logger.error(e)
            self.connection.sendall(reply(Socks5Reply.CONNECTION_REFUSED))
            self.state = Socks5State.CLOSED

    def exchange(self):
        try:
            exchange_loop(self.connection, self.remote)
        except Exception as e:
            logger.error(e)
        self.state = Socks5State.CLOSED

    def handle(self):
        """ Handle incoming connections """

        while True:
            logging.info(f"state: {self.state.upper()}")
            match self.state:
                case Socks5State.LISTEN:
                    self.state = Socks5State.HANDSHAKE
                case Socks5State.HANDSHAKE:
                    self.handshake()
                case Socks5State.REQUEST:
                    self.handle_request()
                case Socks5State.ESTABLISHED:
                    self.exchange()
                case Socks5State.CLOSED:
                    self.remote = None
                    self.server.close_request(self.request)
                    return


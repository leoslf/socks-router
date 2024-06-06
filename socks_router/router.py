import logging
import traceback

import time
import struct
import fnmatch
import signal

import socket
import socks

from types import FrameType
from typing import Optional
from collections.abc import Callable
from more_itertools import partition
from select import select
from subprocess import Popen
from socketserver import ThreadingTCPServer, StreamRequestHandler

from retry.api import retry_call

from socks_router.models import (
    Socks5Command,
    Socks5Method,
    Socks5AddressType,
    Socks5Reply,
    Socks5State,
    Socks5Addresses,
    Address,
    IPv4,
    Upstream,
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

def read_request(connection: socket.socket) -> tuple[int, Socks5Command, Address]:
    """ Read Request.
    Request
    -------
    | version | cmd    | rsv  | atyp   | dst.addr    | dst.port |
    | 1 byte  | 1 byte | 0x00 | 1 byte | 4-255 bytes | 2 bytes  |
    """
    version, cmd, _, address_type = struct.unpack("!BBBB", connection.recv(4))
    address = read_address(address_type, connection)
    port, = struct.unpack("!H", connection.recv(2))
    return version, cmd, Socks5Addresses[address_type](address, port)

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

def exchange_loop(client: socket.socket,
                  remote: socket.socket,
                  chunk_size: int = CHUNK_SIZE,
                  timeout: Optional[float] = None):
    while True:
        r, w, e = select([client, remote], [client, remote], [], timeout)
        if client in r and remote in w:
            data = client.recv(chunk_size)
            if remote.send(data) <= 0:
                break

        if remote in r and client in w:
            data = remote.recv(chunk_size)
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

def create_socket(type: Socks5AddressType) -> socks.socksocket:
    match type:
        case Socks5AddressType.IPv4 | Socks5AddressType.DOMAINNAME:
            return socks.socksocket(socket.AF_INET, socket.SOCK_STREAM, proto=0)
        case Socks5AddressType.IPv6:
            return socks.socksocket(socket.AF_INET6, socket.SOCK_STREAM, proto=0)

def with_proxy(socket: socks.socksocket, proxy_server: Optional[Address] = None) -> socks.socksocket:
    if proxy_server is not None:
        socket.set_proxy(socks.SOCKS5, proxy_server.address, proxy_server.port)
    return socket

def connect_socket(address: Address, timeout: float = 0.1):
    with create_socket(address.type) as socket:
        socket.settimeout(timeout)
        socket.connect((address.address, address.port))

class SocksRouter(ThreadingTCPServer):
    reuse_address = True
    daemon_threads = True
    block_on_close = True

    context: ApplicationContext
    is_interrupted: bool = False

    def __init__(self, context: ApplicationContext, *argv, **kwargs):
        self.context = context
        super().__init__(*argv, **kwargs)

    def server_activate(self) -> None:
        logger.info("Server started on %s:%s", *self.server_address)
        super().server_activate()

    def get_request(self) -> tuple[socket.socket, str]:
        conn, addr = super().get_request()
        logger.info("Starting connection from %s:%s", *addr)
        return conn, addr

    def shutdown_request(self, request: socket.socket | tuple[bytes, socket.socket]) -> None:
        if isinstance(request, socket.socket):
            logger.info("Closing connection  %s:%s", *request.getpeername())
        super().shutdown_request(request)

    def shutdown(self) -> None:
        logger.info("Server is shutting down")
        super().shutdown()

    def handle_signal(self, timeout: int, delay: int = 1) -> Callable[[int, Optional[FrameType]], None]:
        """ Signal Handler Factory  """
        def handler(signum: int, _: Optional[FrameType]) -> None:
            deadline = time.monotonic() + timeout
            signal_name = signal.Signals(signum).name
            self.is_interrupted = True

            while (current_time := time.monotonic()) < deadline:
                logger.info("%s received, closing server in %d seconds...", signal_name, int(deadline - current_time) + delay)
                time.sleep(delay)

            self.server_close()
            self.shutdown()

        return handler

class SocksRouterRequestHandler(StreamRequestHandler):
    server: SocksRouter
    state: Socks5State = Socks5State.LISTEN
    remote: Optional[socks.socksocket] = None

    @property
    def context(self) -> ApplicationContext:
        return self.server.context

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

    def acquire_upstream(self, address: Address) -> Optional[Address]:
        upstream = self.match_upstream(self.context.routing_table, address)
        if upstream is None:
            return None

        match self.context.upstreams.get(upstream):
            case Upstream(ssh_client, proxy_server):
                if ssh_client.poll() is None:
                    logger.debug(f"found working upstream: {upstream} -> {proxy_server}")
                    return upstream

                with self.context.mutex:
                    logger.debug(f"upstream {upstream}, proxy_server: {proxy_server} connection is dead, removing from upstreams")
                    del self.context.upstreams[upstream]
            case None:
                logger.debug(f"upstream: {upstream} does not appear in self.upstreams")

        with self.context.mutex:
            proxy_server = IPv4("127.0.0.1", free_port())
            logger.debug(f"Free port: {proxy_server.port}")
            ssh_client = Popen(["ssh", "-NT", "-D", f"{proxy_server.port}", "-o", "ServerAliveInterval=240", "-o", "ExitOnForwardFailure=yes", f"{upstream.address}"] + ([] if upstream.port is None else ["-p", f"{upstream.port}"]))

            self.context.upstreams[upstream] = Upstream(ssh_client, proxy_server)
            return upstream

        return None

    def acquire_proxy(self, address: Address) -> Optional[Address]:
        if upstream := self.acquire_upstream(address):
            proxy_server = self.context.upstreams[upstream].proxy_server
            logger.debug(f"acquired upstream {upstream} with proxy_server {repr(proxy_server)} for address {address}")
            return proxy_server
        return None

    def create_remote(self, address: Address, retries: int = -1) -> socks.socksocket:
        if proxy_server := self.acquire_proxy(address):
            # retry with exponential backoff until proxy is up
            retry_call(connect_socket, (proxy_server,), exceptions=(ConnectionRefusedError,), tries=retries, delay=1, backoff=2)

        return with_proxy(
            create_socket(address.type),
            proxy_server,
        )

    def handshake(self):
        version, methods = read_header(self.connection)
        if version != SOCKS_VERSION or Socks5Method.NO_AUTHENTICATION_REQUIRED not in methods:
            logger.error(f"invalid request: version: {version}, methods: {methods}")
            self.state = Socks5State.CLOSE
            return

        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, Socks5Method.NO_AUTHENTICATION_REQUIRED))
        self.state = Socks5State.REQUEST

    def handle_request(self):
        # request
        version, cmd, address = read_request(self.connection)
        # reply
        try:
            match cmd:
                case Socks5Command.CONNECT:
                    remote = self.create_remote(address)
                    remote.connect((address.address, address.port))
                    logger.info(f"Connected to {address}, bind_address: {remote.getsockname()}")
                    self.connection.sendall(reply(Socks5Reply.SUCCEEDED))
                    self.remote = remote
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
            self.state = Socks5State.CLOSED

    def exchange(self):
        try:
            exchange_loop(self.connection, self.remote, timeout=0)
        except Exception as e:
            logger.error(e)
        self.state = Socks5State.CLOSED

    def setup(self):
        logger.info("setup")
        super().setup()

    def handle(self):
        """ Handle incoming connections """

        while True:
            logger.info(f"state: {self.state.upper()}")
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
                    if self.remote is not None:
                        self.remote.close()
                    self.remote = None
                    # self.server.close_request(self.request)
                    break

    def finish(self):
        logger.info("finish")
        super().finish()

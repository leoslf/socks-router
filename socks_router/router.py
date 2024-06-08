import logging
import traceback
import dataclasses

import struct
import fnmatch

import socket
import socks

from typing import Optional, assert_never, cast
from collections.abc import Callable
from more_itertools import partition
from select import select
from subprocess import Popen
from socketserver import ThreadingTCPServer, StreamRequestHandler

from retry.api import retry_call

from socks_router.parsers import parse_sockaddr

from socks_router.models import (
    SOCKS_VERSION,
    Socks5Method,
    Socks5Command,
    Socks5AddressType,
    Socks5MethodSelectionRequest,
    Socks5MethodSelectionResponse,
    Socks5Request,
    Socks5ReplyType,
    Socks5Reply,
    Socks5State,
    Address,
    IPv4,
    UpstreamScheme,
    UpstreamAddress,
    SSHUpstream,
    ProxyUpstream,
    RetryOptions,
    ApplicationContext,
    RoutingTable,
)

CHUNK_SIZE = 4096

logger = logging.getLogger(__name__)


def free_port(address: str = "") -> tuple[str, int]:
    with socket.socket() as s:
        s.bind((address, 0))
        return s.getsockname()


def read_address(type: Socks5AddressType, connection: socket.socket) -> str:
    match type:
        case Socks5AddressType.IPv4:
            return socket.inet_ntop(socket.AF_INET, connection.recv(4))
        case Socks5AddressType.DOMAINNAME:
            (address_length,) = connection.recv(1)
            return connection.recv(address_length).decode("utf-8")
        case Socks5AddressType.IPv6:
            return socket.inet_ntop(socket.AF_INET6, connection.recv(6))
        case _ as unreachable:
            assert_never(unreachable)


def read_method_selection_request(
    connection: socket.socket,
) -> Socks5MethodSelectionRequest:
    """Read Socks5 Method Selection Request.
    SEE: https://datatracker.ietf.org/doc/html/rfc1928#section-3
    Method Selection Request
    ------------------------
    | version | method_count | methods              |
    | 1 byte  | 1 byte       | [method_count] bytes |
    """
    version, method_count = struct.unpack("!BB", connection.recv(2))
    # get available methods
    methods = connection.recv(method_count)

    return Socks5MethodSelectionRequest(version, list(map(int, methods)))


def read_request(connection: socket.socket) -> Socks5Request:
    """Read Request.
    SEE: https://datatracker.ietf.org/doc/html/rfc1928#section-4
    Request
    -------
    | version | cmd    | rsv  | atyp   | dst.addr    | dst.port |
    | 1 byte  | 1 byte | 0x00 | 1 byte | 4-255 bytes | 2 bytes  |
    """
    version, command, reserved, address_type = struct.unpack("!BBBB", connection.recv(4))
    address = read_address(address_type, connection)
    (port,) = struct.unpack("!H", connection.recv(2))
    return Socks5Request(version, command, reserved, address_type, address, port)


def create_socket(type: Socks5AddressType) -> socks.socksocket:
    match type:
        case Socks5AddressType.IPv4 | Socks5AddressType.DOMAINNAME:
            return socks.socksocket(socket.AF_INET, socket.SOCK_STREAM, proto=0)
        case Socks5AddressType.IPv6:
            return socks.socksocket(socket.AF_INET6, socket.SOCK_STREAM, proto=0)
        case _ as unreachable:
            assert_never(unreachable)


def with_proxy(socket: socks.socksocket, proxy_server: Optional[Address] = None) -> socks.socksocket:
    if proxy_server is not None:
        socket.set_proxy(socks.SOCKS5, proxy_server.address, proxy_server.port)
    return socket


def poll_socket(destination: Address, timeout: float = 0.1):
    with create_socket(destination.type) as socket:
        socket.settimeout(timeout)
        socket.connect(destination.sockaddr)
        socket.close()


def create_remote(address: Address, proxy_server: Optional[Address] = None) -> socks.socksocket:
    return with_proxy(create_socket(address.type), proxy_server)


def connect_remote(
    destination: Address,
    proxy_factory: Callable[[Address], Optional[Address]] = lambda _: None,
    poll_proxy_factory: Callable[[Address], bool] = lambda _: True,
    proxy_retry_options: Optional[RetryOptions] = None,
    logger: logging.Logger = logger,
) -> socks.socksocket:
    if (proxy_server := proxy_factory(destination)) is not None and poll_proxy_factory(destination):
        retry_options: RetryOptions = proxy_retry_options or RetryOptions.exponential_backoff()
        logger.debug(
            f"polling proxy_server: {proxy_server} before connecting to destination {destination} with retry_options {retry_options}"
        )
        retry_call(
            poll_socket,
            (proxy_server,),
            exceptions=(ConnectionRefusedError,),
            **dataclasses.asdict(retry_options),
        )
        logger.debug(f"proxy_server {proxy_server} ready")

    logger.debug(f"creating remote to destination {destination} with proxy_server {proxy_server}")
    remote = create_remote(destination, proxy_server)
    remote.bind(("", 0))
    logger.debug(f"connecting to {destination.sockaddr}, binding client socket: {remote.getsockname()}")
    remote.connect(destination.sockaddr)
    logger.debug(f"connected to {destination.sockaddr}, binding client socket: {remote.getsockname()}")
    return remote


def exchange_loop(
    client: socket.socket,
    remote: socket.socket,
    chunk_size: int = CHUNK_SIZE,
    timeout: Optional[float] = None,
):
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


def match_upstream(routing_table: RoutingTable, destination: Address) -> Optional[UpstreamAddress]:
    for upstream, patterns in routing_table.items():
        logger.debug(f"matching upstream: {upstream}, patterns: {list(map(str, patterns))}, destination: {destination}")
        denied, allowed = partition(lambda pattern: pattern.is_positive_match, patterns)
        if any(fnmatch.filter([str(destination)], pattern.address.pattern) for pattern in allowed) and not any(
            fnmatch.filter([str(destination)], pattern.address.pattern) for pattern in denied
        ):
            logger.debug(f"matched upstream: {upstream}, patterns: {list(map(str, patterns))}, destination: {destination}")
            return upstream
    logger.debug(f"fallback upstream: {None}")
    return None


class SocksRouter(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = True

    context: ApplicationContext
    logger: logging.Logger

    def __init__(self, *argv, context: Optional[ApplicationContext] = None, **kwargs):
        self.context = context or ApplicationContext()
        self.logger = logging.getLogger(self.context.name)
        super().__init__(*argv, **kwargs)

    @property
    def address(self) -> Address:
        return parse_sockaddr(cast(tuple[str, int], self.server_address))

    def server_activate(self) -> None:
        self.logger.info("Server started on %s:%d", *self.server_address)
        super().server_activate()

    def get_request(self) -> tuple[socket.socket, str]:
        conn, addr = super().get_request()
        self.logger.info("Starting connection from client %s:%d", *addr)
        return conn, addr

    def shutdown_request(self, request: socket.socket | tuple[bytes, socket.socket]) -> None:
        if isinstance(request, socket.socket):
            try:
                self.logger.info("Closing connection from client %s:%d", *request.getpeername())
            except (OSError, TypeError):
                self.logger.info("Closing connection from client, request: %r", request)

        super().shutdown_request(request)

    def shutdown(self) -> None:
        self.logger.info("Server is shutting down")
        super().shutdown()


class SocksRouterRequestHandler(StreamRequestHandler):
    server: SocksRouter
    state: Socks5State = Socks5State.LISTEN
    remote: Optional[socks.socksocket] = None

    @property
    def timeout(self):
        return self.server.context.request_timeout

    @property
    def logger(self):
        client_address = parse_sockaddr(self.client_address)
        return self.server.logger.getChild(f"handler-{client_address}")

    def acquire_upstream(self, destination: Address) -> Optional[UpstreamAddress]:
        if (upstream := match_upstream(self.server.context.routing_table, destination)) is None:
            return None

        with self.server.context.mutex:
            match self.server.context.upstreams.get(upstream):
                case SSHUpstream(ssh_client, proxy_server):
                    if ssh_client.poll() is None:
                        self.logger.debug(f"found working upstream: {upstream} -> {proxy_server}")
                        return upstream

                    self.logger.debug(
                        f"upstream {upstream}, proxy_server: {proxy_server} connection is dead, removing from upstreams"
                    )
                    del self.server.context.upstreams[upstream]
                case ProxyUpstream(proxy_server):
                    self.logger.debug(f"found existing proxy upstream {upstream} -> {proxy_server}")
                    return upstream
                case None:
                    self.logger.debug(f"upstream: {upstream} does not appear in self.upstreams, creating...")
                case _ as unreachable:
                    assert_never(unreachable)

            match upstream.scheme:
                case UpstreamScheme.SSH:
                    proxy_server = IPv4(*free_port("127.0.0.1"))
                    self.logger.debug(f"Free port: {proxy_server.port}")
                    ssh_client = Popen(
                        [
                            "ssh",
                            "-NT",
                            "-D",
                            f"{proxy_server.port}",
                            "-o",
                            "ServerAliveInterval=240",
                            "-o",
                            "ExitOnForwardFailure=yes",
                            f"{upstream.address}",
                        ]
                        + ([] if upstream.address.port is None else ["-p", f"{upstream.address.port}"])
                    )

                    self.server.context.upstreams[upstream] = SSHUpstream(ssh_client, proxy_server)
                    return upstream
                case UpstreamScheme.SOCKS5:
                    self.server.context.upstreams[upstream] = ProxyUpstream(upstream.address)
                    return upstream
                case _ as unreachable:  # type: ignore[misc]
                    assert_never(unreachable)

    def acquire_proxy(self, destination: Address) -> Optional[Address]:
        if upstream := self.acquire_upstream(destination):
            proxy_server = self.server.context.upstreams[upstream].proxy_server
            self.logger.debug(f"acquired upstream {upstream} with proxy_server {proxy_server} for destination {destination}")
            return proxy_server
        return None

    def handshake(self):
        request = read_method_selection_request(self.connection)
        if request.version != SOCKS_VERSION:
            self.logger.error(f"invalid request: version: {request.version}, methods: {request.methods}")
            self.state = Socks5State.CLOSED
            return

        # select method from server side
        for method in request.methods:
            match method:
                case Socks5Method.NO_AUTHENTICATION_REQUIRED:
                    self.connection.sendall(
                        bytes(Socks5MethodSelectionResponse(SOCKS_VERSION, Socks5Method.NO_AUTHENTICATION_REQUIRED))
                    )
                    self.state = Socks5State.REQUEST
                    return
                case _:
                    pass

        # none of the methods listed by the client are acceptable
        # notify the client
        self.connection.sendall(bytes(Socks5MethodSelectionResponse(SOCKS_VERSION, Socks5Method.NO_ACCEPTABLE_METHDOS)))
        # the client MUST close the connection
        self.state = Socks5State.CLOSED

    def handle_request(self):
        request = read_request(self.connection)

        try:
            match request.command:
                case Socks5Command.CONNECT:
                    self.remote = connect_remote(
                        request.destination,
                        proxy_factory=self.acquire_proxy,
                        # poll_proxy_factory=lambda destination: (upstream := self.acquire_upstream(destination)) is not None and upstream.scheme == UpstreamScheme.SSH,
                        proxy_retry_options=self.server.context.proxy_retry_options,
                        logger=self.logger,
                    )

                    self.logger.info(
                        f"Connected to destination {request.destination}, binding client socket: {self.remote.getsockname()}"
                    )
                    self.connection.sendall(bytes(Socks5Reply(Socks5ReplyType.SUCCEEDED)))
                    self.state = Socks5State.ESTABLISHED
                    return
                case _:
                    self.logger.warn(f"COMMAND_NOT_SUPPORTED: {request.command}")
                    self.connection.sendall(bytes(Socks5Reply(Socks5ReplyType.COMMAND_NOT_SUPPORTED)))
                    self.state = Socks5State.CLOSED
        except ConnectionRefusedError as e:
            self.logger.error(f"ConnectionRefused when connecting to request.destination: {request.destination}")
            self.logger.error(e)
            self.connection.sendall(bytes(Socks5Reply(Socks5ReplyType.CONNECTION_REFUSED)))
            self.state = Socks5State.CLOSED
            return
        except socks.ProxyConnectionError as e:
            self.logger.error(e)
            self.connection.sendall(bytes(Socks5Reply(Socks5ReplyType.CONNECTION_REFUSED)))
            self.state = Socks5State.CLOSED
        except socks.ProxyError as e:
            if isinstance(e.socket_err, socket.error):
                self.logger.error(type(e.socket_err))
                self.logger.error(e.socket_err)
            self.logger.error(type(e))
            self.logger.error(e)
            self.connection.sendall(bytes(Socks5Reply(Socks5ReplyType.GENERAL_SOCKS_SERVER_FAILURE)))
            self.state = Socks5State.CLOSED
        except Exception as e:
            traceback.print_exc()
            self.logger.error(type(e))
            self.logger.error(e)
            self.connection.sendall(bytes(Socks5Reply(Socks5ReplyType.GENERAL_SOCKS_SERVER_FAILURE)))
            self.state = Socks5State.CLOSED

    def exchange(self):
        exchange_loop(self.connection, self.remote, timeout=0)
        self.state = Socks5State.CLOSED

    def setup(self):
        self.logger.info("setup")
        super().setup()

    def handle(self):
        """Handle incoming connections"""
        while True:
            try:
                self.logger.info(f"state: {self.state.upper()}")
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
                        break
                    case _ as unreachable:
                        assert_never(unreachable)
            except struct.error:
                # ignore: socket has nothing to read
                self.state = Socks5State.CLOSED
            except TimeoutError as e:
                self.logger.warning(e)
                self.state = Socks5State.CLOSED
            except Exception as e:
                self.logger.error(e)
                self.state = Socks5State.CLOSED

    def finish(self):
        if self.remote is not None:
            self.remote.close()
            self.remote = None

        self.logger.info("finish")
        super().finish()

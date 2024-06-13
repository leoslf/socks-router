import logging
import dataclasses

import struct
import fnmatch

import errno
import socket
import socks

from typing import Optional, assert_never, cast
from collections.abc import Callable
from more_itertools import partition
from select import select
from socketserver import ThreadingTCPServer, StreamRequestHandler

from retry.api import retry_call

from socks_router.parsers import parse_sockaddr, pysocks_socks5_error

from socks_router.models import (
    SOCKS_VERSION,
    Socks5Method,
    Socks5Command,
    Socks5AddressType,
    Socks5MethodSelectionRequest,
    Socks5MethodSelectionResponse,
    Socks5Request,
    Socks5Address,
    Socks5ReplyType,
    Socks5Reply,
    Socks5State,
    Address,
    IPv4,
    IPv6,
    Host,
    UpstreamScheme,
    UpstreamAddress,
    SSHUpstream,
    ProxyUpstream,
    RetryOptions,
    ApplicationContext,
    RoutingTable,
    Socks5AddressTypes,
)

from socks_router.utils import read_socket, write_socket, free_port

CHUNK_SIZE = 4096

logger = logging.getLogger(__name__)


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
        socket.set_proxy(socks.SOCKS5, *proxy_server.sockaddr)
    return socket


def poll_socket(destination: Address, timeout: float = 0.1):
    with create_socket(Socks5AddressTypes[type(destination)]) as socket:
        socket.settimeout(timeout)
        socket.connect(destination.sockaddr)
        socket.close()


def resolve_address(address: Address, logger: logging.Logger = logger, **kwargs) -> Address:
    match address:
        case IPv4() | IPv6():
            return address
        case Host(hostname, port):
            # TODO: consider using socket.getaddrinfo
            return IPv4(socket.gethostbyname(hostname), port)
        case _ as unreachable:
            assert_never(unreachable)


def create_remote(address: Address, proxy_server: Optional[Address] = None) -> socks.socksocket:
    return with_proxy(create_socket(Socks5AddressTypes[type(address)]), proxy_server)


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

    def __init__(
        self,
        *argv,
        context: Optional[ApplicationContext] = None,
        address_family: socket.AddressFamily = socket.AF_INET,
        **kwargs,
    ):
        self.context = context or ApplicationContext()
        self.address_family = address_family
        self.logger = logging.getLogger(self.context.name)
        super().__init__(*argv, **kwargs)

    @property
    def address(self) -> Address:
        return parse_sockaddr(cast(tuple[str, int], self.server_address))

    def server_activate(self) -> None:
        self.logger.info("Server started on %r", self.server_address)
        super().server_activate()

    def get_request(self):
        conn, addr = super().get_request()
        self.logger.info("Starting connection from client %r", addr)
        return conn, addr

    def shutdown_request(self, request: socket.socket | tuple[bytes, socket.socket]) -> None:
        assert isinstance(request, socket.socket)
        try:
            self.logger.info("Closing connection from client %s:%d", *request.getpeername())
        except (OSError, TypeError):
            self.logger.info("Closing connection from client, request: %r", request)

        super().shutdown_request(request)

    def shutdown(self) -> None:
        self.logger.info("Server is shutting down")
        for upstream_address, upstream in self.context.upstreams.items():
            match upstream:
                case SSHUpstream(ssh_client, _):
                    if ssh_client.poll() is None:
                        ssh_client.kill()

                    self.logger.debug("ssh_client.stdout: %r" % ssh_client.stdout)
                    self.logger.debug("ssh_client.stderr: %r" % ssh_client.stderr)
                case _:
                    pass
        self.context.upstreams.clear()
        super().shutdown()


class SocksRouterRequestHandler(StreamRequestHandler):
    server: SocksRouter
    state: Socks5State = Socks5State.LISTEN
    remote: Optional[socks.socksocket] = None

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
                        f"upstream {upstream}, proxy_server: {proxy_server} connection is dead, removing from upstreams, stdout: %r, stderr: %r"
                        % (ssh_client.stdout, ssh_client.stderr)
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
                    # check if ssh is reachable
                    self.server.context.upstreams[upstream] = SSHUpstream.create(
                        upstream.address,
                        proxy_server := IPv4(*free_port("127.0.0.1")),
                        ssh_options={
                            "StrictHostKeyChecking": "accept-new",
                            "ConnectTimeout": self.server.context.ssh_connection_timeout,
                            "ServerAliveInterval": 240,
                            "ExitOnForwardFailure": "yes",
                        },
                    )
                    self.logger.debug(f"proxy_server: {proxy_server}")
                    return upstream
                case UpstreamScheme.SOCKS5:
                    # resolve hostname before passing to upstream
                    self.server.context.upstreams[upstream] = ProxyUpstream(resolve_address(upstream.with_default_port().address))
                    return upstream
                case UpstreamScheme.SOCKS5H:
                    self.server.context.upstreams[upstream] = ProxyUpstream(upstream.with_default_port().address)
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
        request = read_socket(self.connection, Socks5MethodSelectionRequest)
        if request.version != SOCKS_VERSION:
            self.logger.error(f"invalid request: version: {request.version}, methods: {request.methods}")
            self.state = Socks5State.CLOSED
            return

        # select method from server side
        for method in request.methods:
            match method:
                case Socks5Method.NO_AUTHENTICATION_REQUIRED:
                    self.logger.debug("accept no authentication required")
                    write_socket(
                        self.connection, Socks5MethodSelectionResponse(SOCKS_VERSION, Socks5Method.NO_AUTHENTICATION_REQUIRED)
                    )
                    self.state = Socks5State.REQUEST
                    return
                case _:
                    pass

        # none of the methods listed by the client are acceptable
        # notify the client
        self.logger.debug("notify client no Socks5Method.NO_ACCEPTABLE_METHODS")
        write_socket(self.connection, Socks5MethodSelectionResponse(SOCKS_VERSION, Socks5Method.NO_ACCEPTABLE_METHODS))
        # the client MUST close the connection
        self.state = Socks5State.CLOSED

    def reply(self, type: Socks5ReplyType):
        self.logger.debug(f"Replying {type.name}")
        write_socket(
            self.connection, Socks5Reply(SOCKS_VERSION, type, server_bound_address=Socks5Address.from_address(self.server.address))
        )

    def handle_request(self):
        request = read_socket(self.connection, Socks5Request)

        try:
            match request.command:
                case Socks5Command.CONNECT:
                    try:
                        self.remote = connect_remote(
                            request.destination.sockaddr,
                            proxy_factory=self.acquire_proxy,
                            # poll_proxy_factory=lambda destination: (upstream := self.acquire_upstream(destination)) is not None and upstream.scheme == UpstreamScheme.SSH,
                            proxy_retry_options=self.server.context.proxy_retry_options,
                            logger=self.logger,
                        )

                        self.logger.info(
                            f"Connected to destination {request.destination.sockaddr}, binding client socket: {self.remote.getsockname()}"
                        )
                        self.reply(Socks5ReplyType.SUCCEEDED)
                        self.state = Socks5State.ESTABLISHED
                        return
                    except socks.ProxyError as exception:
                        e = exception
                        while isinstance(e, socks.ProxyError) and e.socket_err is not None:
                            self.logger.debug(f"Unwrapping {type(e).__name__}: {e}")
                            e = e.socket_err
                        # rethrow the inner-most socks.ProxyError
                        raise e from exception
                case _ as command:
                    self.logger.warning(f"COMMAND_NOT_SUPPORTED: {command}")
                    self.reply(Socks5ReplyType.COMMAND_NOT_SUPPORTED)
                    self.state = Socks5State.CLOSED
                    return
        except socks.SOCKS5Error as e:
            # upstream server returned an error to our socks client
            status, error_message = pysocks_socks5_error.parse(e.msg)
            self.logger.debug(f"Upstream server returned error: {status:#04x}: {error_message}")
            self.reply(status)
        except socks.GeneralProxyError as e:
            self.logger.warning(e)
            self.reply(Socks5ReplyType.GENERAL_SOCKS_SERVER_FAILURE)
        except TimeoutError:
            self.reply(Socks5ReplyType.HOST_UNREACHABLE)
        except OSError as e:
            self.logger.debug(e)
            match e.errno:
                case errno.ENETUNREACH | socket.EAI_NODATA | socket.EAI_NONAME:
                    self.reply(Socks5ReplyType.NETWORK_UNREACHABLE)
                case errno.EHOSTUNREACH | errno.ETIMEDOUT:
                    self.reply(Socks5ReplyType.HOST_UNREACHABLE)
                case errno.ECONNREFUSED:
                    self.reply(Socks5ReplyType.CONNECTION_REFUSED)
                case socket.EAI_ADDRFAMILY | socket.EAI_FAMILY:
                    self.reply(Socks5ReplyType.ADDRESS_TYPE_NOT_SUPPORTED)
                case _:
                    self.logger.exception(f"unexpected exception occured: {type(e)} {(e.errno, e.strerror)}")
                    self.reply(Socks5ReplyType.GENERAL_SOCKS_SERVER_FAILURE)
        except Exception as e:
            self.logger.exception(f"unexpected exception occurred: {type(e)}")
            self.reply(Socks5ReplyType.GENERAL_SOCKS_SERVER_FAILURE)

        self.state = Socks5State.CLOSED
        return

        # TODO: When a reply (REP value other than X'00') indicates a failure, the SOCKS server MUST terminate the TCP connection shortly after sending the reply.  This must be no more than 10 seconds after detecting the condition that caused a failure.

    def exchange(self):
        assert self.remote is not None
        exchange_loop(self.connection, self.remote, timeout=0)
        self.state = Socks5State.CLOSED

    def setup(self):
        self.logger.info("setup")
        super().setup()

    def handle(self):
        """Handle incoming connections"""
        while True:
            try:
                self.logger.info(f"state: {self.state.name}")
                match self.state:
                    case Socks5State.LISTEN:
                        self.state = Socks5State.HANDSHAKE
                    case Socks5State.HANDSHAKE:
                        self.handshake()
                        # TODO: The client and server then enter a method-specific sub-negotiation.
                        # Descriptions of the method-dependent sub-negotiations appear in separate memos.
                        # Compliant implementations MUST support GSSAPI and SHOULD support USERNAME/PASSWORD authentication methods.
                    case Socks5State.REQUEST:
                        # Once the method-dependent subnegotiation has completed, the client sends the request details.  If the negotiated method includes encapsulation for purposes of integrity checking and/or confidentiality, these requests MUST be encapsulated in the method-dependent encapsulation.
                        # The SOCKS server will typically evaluate the request based on source and destination addresses, and return one or more reply messages, as appropriate for the request type.
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
            except BrokenPipeError:
                self.logger.exception("seems the client closed the socket")
                # we cannot send anything now
                self.state = Socks5State.CLOSED
            except Exception as e:
                self.logger.exception(f"unexpected exception occurred: {type(e)}")
                self.state = Socks5State.CLOSED

    def finish(self):
        if self.remote is not None:
            self.remote.close()
            self.remote = None

        self.logger.info("finish")
        super().finish()

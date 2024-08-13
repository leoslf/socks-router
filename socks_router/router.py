import logging
import dataclasses

import struct
import fnmatch

import errno
import socket
import selectors
import socks


from typing import Optional, Never, assert_never, cast
from collections.abc import Iterator, Set
from more_itertools import partition
from functools import cached_property
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
    Socks5GSSAPINegotiationState,
    Socks5GSSAPIClientInitialTokenV1,
    Socks5GSSAPIMessageProtectionSubnegotiationV1,
    Socks5GSSAPIPerMessageProtectionV1,
    Socks5GSSAPISecurityContextFailureV1,
    Socks5UsernamePasswordStatus,
    Socks5UsernamePasswordInitialNegotiationV1,
    Socks5UsernamePasswordInitialNegotiationResponseV1,
    Socks5Request,
    Socks5Address,
    Socks5ReplyType,
    Socks5Reply,
    Socks5State,
    Address,
    IPv4,
    IPv6,
    Host,
    Pattern,
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


def create_socket[**P](type: Socks5AddressType, *args: P.args, **kwargs: P.kwargs) -> socks.socksocket:
    logger.info("create_socket")
    match type:
        case Socks5AddressType.IPv4 | Socks5AddressType.DOMAINNAME:
            return socks.socksocket(socket.AF_INET, socket.SOCK_STREAM, proto=0, *args, **kwargs)
        case Socks5AddressType.IPv6:
            return socks.socksocket(socket.AF_INET6, socket.SOCK_STREAM, proto=0, *args, **kwargs)
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
    proxy_server: Optional[Address] = None,
    remote_socket_timeout: Optional[float] = None,
    proxy_poll_socket_timeout: float = 0.1,
    proxy_retry_options: Optional[RetryOptions] = None,
    logger: logging.Logger = logger,
) -> socks.socksocket:
    if proxy_server is not None:
        retry_options: RetryOptions = proxy_retry_options or RetryOptions.exponential_backoff()
        logger.debug(
            f"polling proxy_server: {proxy_server} before connecting to destination {destination} with retry_options {retry_options}, timeout: {proxy_poll_socket_timeout}s"
        )
        retry_call(
            poll_socket,
            (proxy_server,),
            dict(timeout=proxy_poll_socket_timeout),
            exceptions=(ConnectionRefusedError,),
            **dataclasses.asdict(retry_options),
        )
        logger.debug(f"proxy_server {proxy_server} ready")

    logger.debug(
        f"creating remote to destination {destination} with proxy_server {proxy_server}, socket timeout: {remote_socket_timeout}"
    )
    remote = create_remote(destination, proxy_server)
    remote.bind(("", 0))
    logger.debug(f"connecting to {destination.sockaddr}, binding client socket: {remote.getsockname()}")
    remote.settimeout(remote_socket_timeout)
    remote.connect(destination.sockaddr)
    logger.debug(f"connected to {destination.sockaddr}, binding client socket: {remote.getsockname()}")
    return remote


def exchange_loop(
    client: socket.socket,
    remote: socket.socket,
    chunk_size: int = CHUNK_SIZE,
    timeout: Optional[float] = None,
):
    with selectors.DefaultSelector() as selector:
        selector.register(client, selectors.EVENT_READ, remote)
        selector.register(remote, selectors.EVENT_READ, client)

        while len(selector.get_map().keys()) == 2:
            for key, mask in selector.select(timeout):
                if data := cast(socket.socket, key.fileobj).recv(chunk_size):
                    cast(socket.socket, key.data).sendall(data)
                else:
                    selector.unregister(key.fileobj)


def match_upstream(routing_table: RoutingTable, destination: Address, logger: logging.Logger = logger) -> Optional[UpstreamAddress]:
    def matches(patterns: Iterator[Pattern]) -> Iterator[list[str]]:
        return (fnmatch.filter([f"{destination}", f"{destination.address}"], pattern.address) for pattern in patterns)

    for upstream, patterns in routing_table.items():
        logger.debug(f"matching upstream: {upstream}, patterns: {list(map(str, patterns))}, destination: {destination}")
        denied, allowed = partition(lambda pattern: pattern.is_positive_match, patterns)
        if any(matches(allowed)) and not any(matches(denied)):
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

    @cached_property
    def supported_methods(self) -> Set[Socks5Method]:
        return {
            key
            for key, condition in {
                Socks5Method.NO_AUTHENTICATION_REQUIRED: True,
                Socks5Method.GSSAPI: self.context.enable_gssapi,
                Socks5Method.USERNAME_PASSWORD: self.context.users is not None,
            }.items()
            if condition
        }

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
    accepted_method: Optional[Socks5Method] = None
    remote: Optional[socks.socksocket] = None

    @property
    def logger(self):
        client_address = parse_sockaddr(self.client_address)
        return self.server.logger.getChild(f"handler-{client_address}")

    def acquire_upstream(self, destination: Address) -> Optional[UpstreamAddress]:
        if (upstream := match_upstream(self.server.context.routing_table, destination, logger=self.logger)) is None:
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
                    self.logger.debug("ssh: %r, proxy_server: %r" % (upstream.address, proxy_server))
                    return upstream
                case UpstreamScheme.SOCKS5 | UpstreamScheme.SOCKS5H:
                    self.server.context.upstreams[upstream] = ProxyUpstream(upstream.with_default_port().address)
                    return upstream
                case _ as unreachable:  # type: ignore[misc]
                    assert_never(unreachable)

    def handshake(self):
        request = read_socket(self.connection, Socks5MethodSelectionRequest)
        if request.version != SOCKS_VERSION:
            self.logger.error(f"invalid request: version: {request.version}, methods: {request.methods}")
            self.state = Socks5State.CLOSED
            return

        # select method from server side
        for method in request.methods:
            if method in self.server.supported_methods:
                self.accepted_method = method
                self.logger.debug(f"accept method: {self.accepted_method.name}")
                write_socket(self.connection, Socks5MethodSelectionResponse(SOCKS_VERSION, self.accepted_method))
                self.state = Socks5State.METHOD_SUBNEGOTIATION
                return

        # none of the methods listed by the client are acceptable
        # notify the client
        self.logger.debug(
            f"notify client {Socks5Method.NO_ACCEPTABLE_METHODS}, client requested: {[method.name for method in request.methods]}"
        )
        write_socket(self.connection, Socks5MethodSelectionResponse(SOCKS_VERSION, Socks5Method.NO_ACCEPTABLE_METHODS))
        # the client MUST close the connection
        self.state = Socks5State.CLOSED

    def handle_method_subnegotiation(self):
        match self.accepted_method:
            case Socks5Method.NO_AUTHENTICATION_REQUIRED:
                self.state = Socks5State.REQUEST
            case Socks5Method.GSSAPI:
                # GSS-API peers achieve interoperability by establishing a common security mechanism for security context establishment - either through administrative action, or through negotiation.
                # SEE: https://datatracker.ietf.org/doc/html/rfc1961
                # NOTE: prior to use of GSS-API primitives, the client and server should be locally authenticated, and have established default GSS-API credentials.
                # The client should call gss_import_name to obtain an internal representation of the server name.
                # For maximal portability, the default name_type GSS_C_NULL_OID should be used to specify the default name space and the input name_string should be treated by the client's code as an opaque name-space specific input.
                # NOTE: in all continue/confirmation cases, the server uses the same message type as for the client -> server interaction.
                state = Socks5GSSAPINegotiationState.CLIENT_INITIAL_TOKEN
                while True:
                    self.logger.debug(f"GSSAPI negotiation state: {state.name}")
                    match state:
                        case Socks5GSSAPINegotiationState.CLIENT_INITIAL_TOKEN:
                            initial_negotiation = read_socket(self.connection, Socks5GSSAPIClientInitialTokenV1)
                            if initial_negotiation.token == b"fakepassword":
                                write_socket(self.connection, initial_negotiation)
                                state = Socks5GSSAPINegotiationState.MESSAGE_PROTECTION_SUBNEGOTIATION
                                continue
                            self.logger.debug(f"failed given: {initial_negotiation}")
                            break
                        case Socks5GSSAPINegotiationState.MESSAGE_PROTECTION_SUBNEGOTIATION:
                            message_protection = read_socket(self.connection, Socks5GSSAPIMessageProtectionSubnegotiationV1)
                            if message_protection.token == b"fakepassword":
                                write_socket(self.connection, message_protection)
                                state = Socks5GSSAPINegotiationState.PER_MESSAGE_PROTECTION
                                continue
                            self.logger.debug(f"failed given: {message_protection}")
                            break
                        case Socks5GSSAPINegotiationState.PER_MESSAGE_PROTECTION:
                            per_message_protection = read_socket(self.connection, Socks5GSSAPIPerMessageProtectionV1)
                            if per_message_protection.token == b"fakepassword":
                                write_socket(self.connection, per_message_protection)
                                state = Socks5GSSAPINegotiationState.SUCCESS
                                continue
                            self.logger.debug(f"failed given: {per_message_protection}")
                            break
                        case Socks5GSSAPINegotiationState.SUCCESS:
                            self.state = Socks5State.REQUEST
                            return
                        case _ as unreachable:
                            assert_never(unreachable)
                # failure
                write_socket(self.connection, Socks5GSSAPISecurityContextFailureV1())
                self.state = Socks5State.CLOSED
            case Socks5Method.USERNAME_PASSWORD:
                # SEE: https://datatracker.ietf.org/doc/html/rfc1929
                assert self.server.context.users is not None
                auth = read_socket(self.connection, Socks5UsernamePasswordInitialNegotiationV1)
                if auth.version == 1 and self.server.context.users.get(auth.username) == auth.password:
                    write_socket(
                        self.connection,
                        Socks5UsernamePasswordInitialNegotiationResponseV1(status=Socks5UsernamePasswordStatus.SUCCESS),
                    )
                    self.state = Socks5State.REQUEST
                    return
                self.logger.debug(
                    f"failed given: {auth}, users: {self.server.context.users}, auth.username in users: {auth.username in self.server.context.users}, password equality: {self.server.context.users.get(auth.username) == auth.password}"
                )
                write_socket(
                    self.connection, Socks5UsernamePasswordInitialNegotiationResponseV1(status=Socks5UsernamePasswordStatus.FAILURE)
                )
                self.state = Socks5State.CLOSED
            case _ as unreachable:
                assert_never(cast(Never, unreachable))

    def reply(self, type: Socks5ReplyType):
        self.logger.debug(f"Replying {type.name}")
        try:
            write_socket(
                self.connection,
                Socks5Reply(SOCKS_VERSION, type, server_bound_address=Socks5Address.from_address(self.server.address)),
            )
        except BrokenPipeError:
            pass

    def connect_remote(self, destination: Address) -> socks.socksocket:
        proxy_server = None
        if (upstream := self.acquire_upstream(destination)) is not None:
            proxy_server = self.server.context.upstreams[upstream].proxy_server
            if upstream.scheme == UpstreamScheme.SOCKS5:
                destination = resolve_address(destination)
            self.logger.debug(f"acquired upstream {upstream} with proxy_server {proxy_server} for destination {destination}")

        return connect_remote(
            destination,
            proxy_server,
            remote_socket_timeout=self.server.context.remote_socket_timeout,
            proxy_poll_socket_timeout=self.server.context.proxy_poll_socket_timeout,
            proxy_retry_options=self.server.context.proxy_retry_options,
            logger=self.logger,
        )

    def handle_request(self):
        request = read_socket(self.connection, Socks5Request)

        try:
            match request.command:
                case Socks5Command.CONNECT:
                    try:
                        self.remote = self.connect_remote(request.destination.sockaddr)

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
                    case Socks5State.METHOD_SUBNEGOTIATION:
                        # The client and server then enter a method-specific sub-negotiation.
                        # Compliant implementations MUST support GSSAPI and SHOULD support USERNAME/PASSWORD authentication methods.
                        self.handle_method_subnegotiation()
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
            except Exception as e:
                self.logger.exception(f"unexpected exception occurred: {type(e)}")
                self.state = Socks5State.CLOSED

    def finish(self):
        if self.remote is not None:
            self.remote.close()
            self.remote = None

        self.logger.info("finish")
        super().finish()

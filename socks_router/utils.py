from __future__ import annotations
from types import ModuleType
from typing import (
    Annotated,
    Any,
    Callable,
    ForwardRef,
    Optional,
    SupportsBytes,
    TypeGuard,
    Union,
    get_args,
    get_origin,
    assert_never,
    cast,
    overload,
)
from collections.abc import Iterator, Sequence, MutableSequence

import builtins
import operator
import inspect
import re
import struct
import dataclasses
import socket

from socks_router.models import (
    SupportsUnbytes,
    Packable,
    PackingSequence,
)

import socks_router.models

type TypeComparator = Callable[[builtins.type, builtins.type], bool]


def resolve_type(type: str, module: Optional[ModuleType] = None) -> type:
    from typing import _eval_type  # type: ignore[attr-defined]

    return _eval_type(
        ForwardRef(type),
        {**globals(), **{name: getattr(module, name) for module in filter(None, [module]) for name in dir(module)}},
        globals(),
    )


def to_bin(value: int) -> str:
    return format(value, "b")


def to_oct(value: int) -> str:
    return format(value, "o")


def to_hex(value: int) -> str:
    return format(value, "x")


def is_optional(field):
    return get_origin(field) is Union and type(None) in get_args(field)


def is_[T](type: builtins.type, target: builtins.type[T], comparator: TypeComparator = issubclass) -> TypeGuard[T]:
    return inspect.isclass(type) and comparator(type, target)


def generic_is_[T](type: builtins.type, target: builtins.type[T], comparator: TypeComparator = issubclass) -> TypeGuard[T]:
    return (
        is_(type, target, comparator)
        or (origin := get_origin(type)) is not None
        and is_(cast(builtins.type, origin), target, comparator)
    )


def is_sequence[T](type: builtins.type, comparator: TypeComparator = issubclass) -> TypeGuard[Sequence[T]]:
    return generic_is_(type, cast(builtins.type[Sequence[T]], Sequence), comparator)


def is_bytes(type: builtins.type, comparator: TypeComparator = issubclass) -> TypeGuard[bytes]:
    return is_(type, bytes, comparator)


def is_str(type: builtins.type, comparator: TypeComparator = issubclass) -> TypeGuard[str]:
    return is_(type, str, comparator)


def construct[T, **P](type: builtins.type[T]) -> Callable[P, T]:
    def wrapped(*argv: P.args, **kwargs: P.kwargs) -> T:
        if not is_str(type) and is_sequence(type):
            origin = cast(
                Callable[P, T],
                list
                if any(generic_is_(cast(builtins.type, type), target, operator.eq) for target in (Sequence, MutableSequence))  # type: ignore [type-abstract]
                else type,
            )
            match get_args(type):
                case tuple([element]) if element is not Any:
                    return cast(T, origin(cast(P.args, map(construct(element), *argv, **kwargs))))
                case _:
                    return cast(T, origin(*argv, **kwargs))
        return type(*argv, **kwargs)

    return wrapped


def tokenize_pack_format(format: str) -> Iterator[PackingSequence]:
    ordering, format = cast(re.Match[str], re.fullmatch(r"(?P<ordering>[@=<>!]?)(?P<format>.*)", format or "")).groups()

    # unsigned integers
    length_pattern = r"[BHILQ]"
    element_format = r"[cbB?hHiIlLqQnNefdspP]"
    for segment in re.split(
        f"({length_pattern}{re.escape(socks_router.models.PACKABLE_VARIABLE_LENGTH_DECLARATION_FORMAT)}{element_format})", format
    ):
        if matches := re.fullmatch(
            f"(?P<length>{length_pattern}){re.escape(socks_router.models.PACKABLE_VARIABLE_LENGTH_DECLARATION_FORMAT)}(?P<element>{element_format})",
            segment,
        ):
            yield (ordering + matches["length"], ordering + "%d" + matches["element"])
            continue

        for field in re.findall(rf"\d*{element_format}", segment):
            yield ordering + field


def read_socket[T](sock: socket.socket, type: builtins.type[T], format: Optional[str] = None) -> T:
    def read(sock: socket.socket, format: str):
        return struct.unpack(format, sock.recv(struct.calcsize(format)))

    def read_sequence(sock: socket.socket, length_format: str, element_format: str):
        (length,) = read(sock, length_format)
        return read(sock, element_format % length)

    if get_origin(type) == Annotated:
        match get_args(type):
            case tuple([type, format]):
                pass
            case tuple(arguments):
                raise TypeError(f"Annotated[{arguments}] given")
            case _ as unreachable:
                assert_never(unreachable)

    if is_optional(type):
        type = get_args(type)[0]

    if format is None and inspect.isclass(type) and issubclass(type, Packable):
        format = type.__pack_format__()

    # primitives
    is_primitive = inspect.isclass(type) and issubclass(type, (bool, int, float))
    supports_unbytes = inspect.isclass(type) and issubclass(type, SupportsUnbytes)

    if is_primitive or is_bytes(type) or is_str(type) or is_sequence(type) or supports_unbytes:
        if format is None:
            raise TypeError(f"cannot read {type} from socket without format")

        sequence = list(tokenize_pack_format(format))

        if not sequence:
            raise TypeError(f"no segments in format {format}")

        if len(sequence) > 1:
            raise TypeError(f"sequence has more than 1 segment: {sequence}")

        if supports_unbytes:
            return cast(T, cast(SupportsUnbytes, type).__unbytes__(sock.recv(struct.calcsize(format))))

        match sequence[0]:
            case tuple([length_format, element_format]):
                if is_bytes(type):
                    return cast(T, bytes(read_sequence(sock, length_format, element_format)))
                if is_str(type):
                    return read_sequence(sock, length_format, element_format)[0].decode("utf-8")
                if is_sequence(type):
                    content = read_sequence(sock, length_format, element_format)
                    return construct(type)(content)  # type: ignore [arg-type]
                raise TypeError(f"variable-length format {format} is not allowed on non-sequence type, given type: {type}")
            case _ as fmt:
                return construct(type)(*read(sock, cast(str, fmt)))

    if dataclasses.is_dataclass(type):
        field_descriptors = {field.name: field for field in dataclasses.fields(type)}
        results: dict[str, Any] = {}
        for name, field in field_descriptors.items():
            if isinstance(field.type, str):
                field.type = resolve_type(field.type, module=inspect.getmodule(type))

            if get_origin(field.type) == Annotated:
                match get_args(field.type):
                    case tuple([field_type, "&", discriminator, type_factory]):
                        if discriminator not in results:
                            if discriminator not in field_descriptors:
                                raise TypeError(
                                    f"discriminator {discriminator} for field {name} of type {field_type} not in fields of {type.__name__}"
                                )
                            raise TypeError(f"discriminator {discriminator} has to be declared before field {name}")

                        if isinstance(type_factory, str):
                            if not hasattr(type, type_factory):
                                raise TypeError(
                                    f"type_factory {type_factory} for field {name} of type {field_type} not in {type.__name__}"
                                )
                            type_factory = getattr(type, type_factory)

                        if not callable(type_factory):
                            raise TypeError(f"type_factory not callable, given: {type_factory}")

                        field_type = type_factory(results[discriminator])
                        results[name] = read_socket(sock, field_type)
                    case tuple([field_type, format]):
                        results[name] = read_socket(sock, field_type, format)
                    case tuple(arguments):
                        raise TypeError(f"Annotated[{arguments}] given")
                    case _ as unreachable:
                        assert_never(unreachable)
            else:
                results[name] = read_socket(sock, field.type)

        return cast(T, construct(type)(**results))

    # we have no way to deserialize
    raise TypeError(
        f"read_socket can only handle primitives, list, str, SupportsUnbytes or dataclasses, but type {type} ({builtins.type(type)}) given"
    )


def write_socket[T](
    sock: socket.socket, instance: T, format: Optional[str] = None, type: Optional[builtins.type[T]] = None
) -> None:
    @overload
    def write_sequence(sock: socket.socket, length_format: str, element_format: str, sequence: bytes): ...
    @overload
    def write_sequence(sock: socket.socket, length_format: str, element_format: str, sequence: str): ...
    @overload
    def write_sequence[V](sock: socket.socket, length_format: str, element_format: str, sequence: Sequence[V]): ...

    def write_sequence(sock, length_format, element_format, sequence):
        return sock.sendall(
            struct.pack(length_format, length := len(sequence))
            + (
                struct.pack(
                    element_format % length,
                    *([sequence.encode("utf-8")] if isinstance(sequence, str) else sequence) if length > 0 else bytes(),
                )
            )
        )

    if type is None:
        type = builtins.type(instance)

    if format is None and get_origin(type) == Annotated:
        match get_args(type):
            case tuple([type, format]):
                pass
            case tuple() as arguments:
                raise TypeError(f"Annotated[{arguments}] given")
            case _ as unreachable:
                assert_never(unreachable)

    if format is None and isinstance(instance, Packable):
        format = instance.__pack_format__()

    is_primitive: TypeGuard[bool | int | float] = isinstance(instance, (bool, int, float))
    is_bytes: TypeGuard[bytes] = isinstance(instance, bytes)
    is_str: TypeGuard[str] = isinstance(instance, str)

    if format is not None and (is_primitive or is_bytes or is_str or is_sequence(type)):
        sequence = list(tokenize_pack_format(format))

        if not sequence:
            raise TypeError(f"no segments in format {format}")

        if len(sequence) > 1:
            raise TypeError(f"type is {type} but sequence has more than 1 segment: {sequence}")

        match sequence[0]:
            case tuple([length_format, element_format]):
                match instance:
                    case bytes() | str() | list():
                        return write_sequence(sock, length_format, element_format, instance)
                    case _:
                        raise TypeError(f"variable-length format {format} is not allowed on non-sequence type, given type: {type}")
            case str() as fmt:
                return sock.sendall(struct.pack(fmt, instance))

    if isinstance(instance, SupportsBytes):
        return sock.sendall(bytes(instance))

    if dataclasses.is_dataclass(instance):
        # format is ignored for dataclass
        field_descriptors = {field.name: field for field in dataclasses.fields(instance)}
        for name, field in field_descriptors.items():
            if isinstance(field.type, str):
                field.type = resolve_type(field.type, module=inspect.getmodule(type))

            if get_origin(field.type) == Annotated:
                match get_args(field.type):
                    case tuple([_, format, _, _]):
                        write_socket(sock, getattr(instance, name))
                    case tuple([_, format]):
                        write_socket(sock, getattr(instance, name), format)
                    case tuple() as arguments:
                        raise TypeError(f"Annotated[{arguments}] given")
                    case _ as unreachable:
                        assert_never(unreachable)
            else:
                write_socket(sock, getattr(instance, name))
        return

    # we have no way to serialize
    raise TypeError(
        f"write_socket can only handle primitives, str, Sequence, SupportsBytes or dataclasses, but type {type} ({builtins.type(type)}) given, instance: {instance}"
    )


def free_port(address: str = "") -> tuple[str, int]:
    with socket.socket() as sock:
        sock.bind((address, 0))
        return sock.getsockname()

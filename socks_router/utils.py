from __future__ import annotations
from types import ModuleType
from typing import (
    Annotated,
    Any,
    ForwardRef,
    SupportsBytes,
    Optional,
    Union,
    Type,
    get_args,
    get_origin,
    overload,
    assert_never,
    cast,
)
from collections.abc import Iterator

import builtins
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


def is_list(type: builtins.type) -> bool:
    return (
        inspect.isclass(type) and issubclass(type, list) or inspect.isclass(origin := get_origin(type)) and issubclass(origin, list)
    )


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


@overload
def read_socket[T: SupportsUnbytes](sock: socket.socket, type: type[T]) -> T: ...
@overload
def read_socket[T](sock: socket.socket, type: type[T], format: str) -> T: ...


def read_socket[T](sock: socket.socket, type: type[T], format: Optional[str | tuple[str, str]] = None) -> T:
    def read(sock: socket.socket, format: str):
        return struct.unpack(format, sock.recv(struct.calcsize(format)))

    if is_optional(type):
        type = get_args(type)[0]

    if format is None and inspect.isclass(type) and issubclass(type, Packable):
        format = type.__pack_format__()

    if inspect.isclass(type) and issubclass(type, SupportsUnbytes):
        return cast(T, type.__unbytes__(sock.recv(struct.calcsize(cast(str, format)))))

    # primitives
    if inspect.isclass(type) and issubclass(type, (bool, int, float)):
        if format is None:
            raise TypeError(f"cannot read {type} from socket without format")
        if not isinstance(format, str):
            raise TypeError("cannot use variable-length format on primitives")
        # NOTE: type is not an instance of SupportsUnbytes
        return cast(T, type(*read(sock, format)))

    if is_list(type) or inspect.isclass(type) and issubclass(type, str):
        if format is None:
            raise ValueError(f"format cannot be none with type: {type.__name__}")

        if not isinstance(format, str):
            raise ValueError(f"format cannot be anything other than str here, {format} given")

        sequence = list(tokenize_pack_format(format))

        if not sequence:
            raise TypeError(f"no segments in format {format}")

        if len(sequence) > 1:
            raise TypeError(f"type is list or str but sequence has more than 1 segments: {sequence}")

        match sequence[0]:
            case tuple([length_format, element_format]):
                (length,) = read(sock, length_format)
                content = read(sock, element_format % length)

                if issubclass(type, list) or isinstance(origin := get_origin(type), builtins.type) and issubclass(origin, list):
                    return type(content)  # type: ignore[call-arg]

                if issubclass(type, str):
                    return content[0].decode("utf-8")

                raise TypeError(f"cannot read variable-length format into type {type}")
            case _ as format:
                return type(*read(sock, cast(str, format)))

    if not dataclasses.is_dataclass(type):
        raise TypeError(f"cannot read non-dataclass, un-SupportsUnbytes type {type.__name__} from socket")

    field_descriptors = {field.name: field for field in dataclasses.fields(type)}
    results: dict[str, Any] = {}
    for name, field in field_descriptors.items():
        if isinstance(field.type, str):
            field.type = resolve_type(field.type, module=inspect.getmodule(type))

        if get_origin(field.type) == Annotated:
            match get_args(field.type):
                case tuple([field_type_union, "&", discriminator, type_factory]):
                    if discriminator not in results:
                        if discriminator in field_descriptors:
                            raise TypeError(
                                f"discriminator for field {name} of type {field_type_union} not in fields of {type.__name__}"
                            )
                        raise TypeError(f"discriminator {discriminator} has to be declared before field {name}")
                    if not (hasattr(type, type_factory) and callable(getattr(type, type_factory))):
                        raise TypeError(
                            f"type_factory {type_factory} for field {name} of type {field_type_union} not in {type.__name__}"
                        )
                    field_type: Type = getattr(type, type_factory)(type, results[discriminator])
                    if isinstance(field_type, str):
                        field_type = type(field_type)
                    results[name] = read_socket(sock, field_type)
                case tuple([field_type, format]):
                    if isinstance(field_type, str):
                        field_type = type(field_type)  # type: ignore[call-arg,assignment]
                    results[name] = read_socket(sock, field_type, format)
                case tuple() as remaining:
                    raise TypeError(f"{remaining} given")
                case _ as unreachable:
                    assert_never(unreachable)
        else:
            results[name] = read_socket(sock, field.type)

    return cast(T, type(**results))


@overload
def write_socket[T: (SupportsBytes, Packable)](sock: socket.socket, instance: T) -> None: ...
@overload
def write_socket[T](sock: socket.socket, instance: T, format: str) -> None: ...


def write_socket[T](sock: socket.socket, instance: T, format: Optional[str] = None) -> None:
    if format is None and isinstance(instance, Packable):
        format = instance.__pack_format__()

    # handle __bytes__ if no format given
    if format is None and isinstance(instance, SupportsBytes):
        sock.sendall(bytes(instance))
        return

    if isinstance(instance, SupportsBytes):
        sock.sendall(bytes(instance))
        return

    if not dataclasses.is_dataclass(instance):
        if isinstance(instance, (bool, int, float)):
            if format is None:
                raise ValueError(f"format cannot be None with instance {instance} of type {type(instance)}")
            sock.sendall(struct.pack(format, instance))
            return

        if is_list(type(instance)) or isinstance(instance, str):
            if format is None:
                raise TypeError("format cannot be None with list or str")

            sequence = list(tokenize_pack_format(format))

            if not sequence:
                raise TypeError(f"no segments in format {format}")

            if len(sequence) > 1:
                raise TypeError(f"type is list or str but sequence has more than 1 segments: {sequence}")

            match sequence[0]:
                case tuple([length_format, element_format]):
                    if isinstance(instance, str):
                        content = instance.encode("utf-8")
                        content_length = len(content)
                        sock.sendall(struct.pack(length_format, content_length))
                        sock.sendall(struct.pack(element_format % content_length, content))
                        return

                    if isinstance(instance, list):
                        sock.sendall(struct.pack(length_format, len(instance)))
                        sock.sendall(struct.pack(element_format % len(instance), *instance))
                        return
                    raise TypeError(f"cannot write variable-length format from type {type(instance)} instance {instance}")
                case _:
                    raise TypeError(f"cannot handle {sequence[0]} on instance {instance} of type {type(instance)}")

        if format is not None:
            sock.sendall(struct.pack(format, instance))
            return

        if isinstance(instance, SupportsBytes):
            sock.sendall(bytes(instance))
            return

        raise TypeError(f"cannot write {instance} to socket with format {format}")

    if format is not None:
        raise TypeError(
            f"instance {instance} of dataclass {type(instance)} should not have a format assigned to it, format: {format}"
        )

    field_descriptors = {field.name: field for field in dataclasses.fields(instance)}
    for name, field in field_descriptors.items():
        if isinstance(field.type, str):
            field.type = resolve_type(field.type, module=inspect.getmodule(type(instance)))

        if get_origin(field.type) == Annotated:
            match get_args(field.type):
                case tuple([_, "&", _, _]):
                    write_socket(sock, getattr(instance, name))
                case tuple([_, format]):
                    write_socket(sock, getattr(instance, name), format)
                case tuple() as remaining:
                    raise TypeError(f"{remaining} given")
                case _ as unreachable:
                    assert_never(unreachable)
        else:
            write_socket(sock, getattr(instance, name))


def free_port(address: str = "") -> tuple[str, int]:
    with socket.socket() as sock:
        sock.bind((address, 0))
        return sock.getsockname()

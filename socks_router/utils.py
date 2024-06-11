from __future__ import annotations
from types import ModuleType
from typing import (
    Annotated,
    Any,
    ForwardRef,
    SupportsBytes,
    Never,
    Optional,
    Union,
    get_args,
    get_origin,
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


def read_socket[T](sock: socket.socket, type: builtins.type[T], format: Optional[str] = None) -> T:
    def read(sock: socket.socket, format: str):
        return struct.unpack(format, sock.recv(struct.calcsize(format)))

    if get_origin(type) == Annotated:
        match get_args(type):
            case tuple([type, format]):
                pass
            case tuple(annotation):
                raise TypeError(f"invalid arguments for Annotated: {annotation}")
            case _ as unreachable:
                assert_never(unreachable)

    if is_optional(type):
        type = get_args(type)[0]

    if format is None and inspect.isclass(type) and issubclass(type, Packable):
        format = type.__pack_format__()

    # primitives
    is_primitive = inspect.isclass(type) and issubclass(type, (bool, int, float))
    is_list = (
        inspect.isclass(type) and issubclass(type, list) or inspect.isclass(origin := get_origin(type)) and issubclass(origin, list)
    )
    is_str = inspect.isclass(type) and issubclass(type, str)
    supports_unbytes = inspect.isclass(type) and issubclass(type, SupportsUnbytes)

    if is_primitive or is_list or is_str or supports_unbytes:
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
                if is_primitive:
                    raise TypeError(f"variable-length format {format} is not allowed on primitive type, given type: {type}")

                (length,) = read(sock, length_format)
                content = read(sock, element_format % length)

                if is_str:
                    return content[0].decode("utf-8")

                return type(content)  # type: ignore[call-arg]
            case _ as fmt:
                return type(*read(sock, cast(str, fmt)))

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
                    case _ as unreachable:
                        assert_never(cast(Never, unreachable))
            else:
                results[name] = read_socket(sock, field.type)

        return cast(T, type(**results))

    # we have no way to deserialize
    raise TypeError(
        f"read_socket can only handle primitives, list, str, SupportsUnbytes or dataclasses, but type {type} ({builtins.type(type)}) given"
    )


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
            return sock.sendall(struct.pack(format, instance))

        if is_list(type(instance)) or isinstance(instance, str):
            if format is None:
                raise TypeError("format cannot be None with list or str")

            sequence = list(tokenize_pack_format(format))

            if not sequence:
                raise TypeError(f"no segments in format {format}")

            if len(sequence) > 1:
                raise TypeError(f"type is list or str but sequence has more than 1 segment: {sequence}")

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

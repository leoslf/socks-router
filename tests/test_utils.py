from __future__ import annotations
import pytest

import re
import socket

from typing import Annotated

from dataclasses import dataclass

from socks_router.utils import to_bin, to_oct, to_hex, tokenize_pack_format, read_socket, write_socket


def test_to_bin():
    assert to_bin(0b10) == "10"


def test_to_oct():
    assert to_oct(0o10) == "10"


def test_to_hex():
    assert to_hex(0x10) == "10"


def describe_tokenize_pack_format():
    def it_should_tokenize_variable_length_str():
        assert list(tokenize_pack_format("!B%*s")) == [("!B", "!%ds")]

    def it_should_tokenize_anything_else():
        assert list(tokenize_pack_format("!BBBB%*s4BH")) == ["!B", "!B", "!B", ("!B", "!%ds"), "!4B", "!H"]


type Byte = Annotated[int, "!B"]
type VariableLengthString = Annotated[str, "!B%*s"]


def describe_read_socket():
    @pytest.fixture
    def sock(mocker) -> socket.socket:
        sock = mocker.Mock(socket.socket)
        sock.recv.side_effect = lambda n: bytes([0 for _ in range(n)])
        return sock

    @pytest.mark.parametrize("type", [bool, int, float, list[int], list, str])
    def it_should_throw_if_non_dataclasss_type_is_not_given_a_format(sock, type):
        with pytest.raises(TypeError, match=re.escape(f"cannot read {type} from socket without format")):
            read_socket(sock, type, format=None)

    @pytest.mark.parametrize("type", [bool, int, float])
    def it_should_throw_if_variable_length_format_given_on_primitive(sock, type):
        with pytest.raises(TypeError, match="variable-length format .* is not allowed on non-sequence type"):
            read_socket(sock, type, format="!B%*s")

    @pytest.mark.parametrize("type", [bool, int, float, list[int], list, str])
    def it_should_throw_if_non_dataclass_type_has_a_format_without_any_segments(sock, type):
        with pytest.raises(TypeError, match="no segments in format.*"):
            read_socket(sock, type, format="")

    @pytest.mark.parametrize("type", [bool, int, float, list[int], list, str])
    def it_should_throw_if_non_dataclass_type_has_a_longer_format(sock, type):
        with pytest.raises(TypeError, match="sequence has more than 1 segment.*"):
            read_socket(sock, type, format="!BB")

    def it_should_throw_if_no_way_to_deserialize_the_type(sock):
        # none of: primitives, list, str, SupportUnbytes or dataclass
        class ArbitraryType:
            pass

        with pytest.raises(TypeError, match="read_socket can only handle.*"):
            read_socket(sock, ArbitraryType, format="")

    def it_should_throw_if_discriminated_field_reference_non_existent_discriminator(sock):
        @dataclass
        class Foo:
            data: Annotated[Annotated[int, "!B"] | Annotated[str, "!B%*s"], "&", "non_existent", "data_type"]

            @classmethod
            def data_type(cls, type: Annotated[bool, "!?"]):
                return Byte if type else VariableLengthString

        with pytest.raises(TypeError, match="discriminator .* for field .* of type .* not in fields of .*"):
            read_socket(sock, Foo)

    def it_should_throw_if_discriminator_field_is_declared_later_than_the_field_depending_on_it(sock):
        @dataclass
        class Foo:
            data: Annotated[Annotated[int, "!B"] | Annotated[str, "!B%*s"], "&", "type", "data_type"]
            type: Annotated[bool, "!?"]

            @classmethod
            def data_type(cls, type: Annotated[bool, "!?"]):
                return Byte if type else VariableLengthString

        with pytest.raises(TypeError, match="discriminator .* has to be declared before field .*"):
            read_socket(sock, Foo)

    def it_should_throw_if_discriminated_field_references_non_existent_type_factory(sock):
        @dataclass
        class Foo:
            type: Annotated[bool, "!?"]
            data: Annotated[Byte | VariableLengthString, "&", "type", "non_existent"]

        with pytest.raises(TypeError, match="type_factory .* for field .* of type .* not in .*"):
            read_socket(sock, Foo)

    def it_should_throw_if_discriminated_field_type_factory_not_callable(sock):
        @dataclass
        class Foo:
            type: Annotated[bool, "!?"]
            data: Annotated[Byte | VariableLengthString, "&", "type", None]

        with pytest.raises(TypeError, match="type_factory not callable, given: .*"):
            read_socket(sock, Foo)

    def it_should_correctly_read_annotated_type_without_explicit_format(sock):
        assert read_socket(sock, Byte.__value__) == 0
        sock.recv.assert_called_with(1)

    def it_should_throw_if_arguments_for_Annotated_type_are_invalid(sock):
        with pytest.raises(TypeError, match=r"Annotated\[.*\] given"):
            read_socket(sock, Annotated[bool, "&", "", ""])  # type: ignore[arg-type]

    def it_should_throw_if_arguments_for_Annotated_dataclass_field_are_invalid(sock):
        @dataclass
        class Foo:
            bar: Annotated[bool, ..., ...]

        with pytest.raises(TypeError, match=r"Annotated\[.*\] given"):
            read_socket(sock, Foo)


def describe_write_socket():
    @pytest.fixture
    def sock(mocker) -> socket.socket:
        return mocker.Mock(socket.socket)

    def it_should_use_annotated_format_if_available(sock):
        write_socket(sock, True, type=Annotated[bool, "!?"])  # type: ignore[arg-type]

    def it_should_throw_if_arguments_for_Annotated_type_are_invalid(sock):
        with pytest.raises(TypeError, match=r"Annotated\[.*\] given"):
            write_socket(sock, True, type=Annotated[bool, "&", "", ""])  # type: ignore[arg-type]

    @pytest.mark.parametrize("type", [bool, int, float, list[int], list, str], ids=str)
    def it_should_throw_if_non_dataclass_type_has_a_format_without_any_segments(sock, type):
        with pytest.raises(TypeError, match="no segments in format.*"):
            write_socket(sock, type(), format="")

    @pytest.mark.parametrize("type", [bool, int, float, list[int], list, str], ids=str)
    def it_should_throw_if_non_dataclass_type_has_a_longer_format(sock, type):
        with pytest.raises(TypeError, match="sequence has more than 1 segment.*"):
            write_socket(sock, type(), format="!BB")

    def it_should_throw_if_no_way_to_deserialize_the_type(sock):
        # none of: primitives, list, str, SupportUnbytes or dataclass
        class ArbitraryType:
            pass

        with pytest.raises(TypeError, match="write_socket can only handle.*"):
            write_socket(sock, ArbitraryType(), format="")

    @pytest.mark.parametrize("type", [bool, int, float])
    def it_should_throw_if_variable_length_format_given_on_primitive(sock, type):
        with pytest.raises(TypeError, match="variable-length format .* is not allowed on non-sequence type"):
            write_socket(sock, type(), format="!B%*s")

    def it_should_throw_if_arguments_for_Annotated_dataclass_field_are_invalid(sock):
        @dataclass
        class Foo:
            bar: Annotated[bool, ..., ...]

        with pytest.raises(TypeError, match=r"Annotated\[.*\] given"):
            write_socket(sock, Foo(True))

from socks_router.utils import to_bin, to_oct, to_hex, tokenize_pack_format


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

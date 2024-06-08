from socks_router.utils import to_bin, to_oct, to_hex


def test_to_bin():
    assert to_bin(0b10) == "10"


def test_to_oct():
    assert to_oct(0o10) == "10"


def test_to_hex():
    assert to_hex(0x10) == "10"

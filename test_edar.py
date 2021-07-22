from edar import *

from pathlib import Path


def ed_key(key):

    cipher = encrypt(key, b"hello world!")
    result = decrypt(key, cipher)

    assert result == b"hello world!"


def test_encrypt_decrypt(tmpdir):
    tmpdir = Path(tmpdir)
    p = tmpdir / "key"
    create_key(p, b"1234")
    key = load_key(p, b"1234")
    public_key = load_public_key(p)

    ed_key(key)
    cipher = encrypt(public_key, b"hello")
    result = decrypt(key, cipher)

    assert b"hello" == result


def test_rotate(tmpdir):
    tmpdir = Path(tmpdir)
    p = tmpdir / "key"
    create_key(p, b"1234")

    rotate_keys(p, b"1234", b"6789")

    test_encrypt_decrypt(tmpdir)

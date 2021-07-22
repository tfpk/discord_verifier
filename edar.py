#!/web/cs1511/bin/python3
# Encrypt Data At Rest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

from pathlib import Path

import base64


def dump_key(path: Path, private_key, password):
    public_path = path.with_suffix(".pub")
    private_path = path.with_suffix(".pem")
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(pem)
    public_path.write_bytes(public_pem)


def create_key(path: Path, password: bytes):
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    dump_key(path, private_key, password)


def load_key(path: Path, password: bytes):
    private_path = path.with_suffix(".pem")
    private_key = serialization.load_pem_private_key(
        private_path.read_bytes(), password=password, backend=default_backend()
    )
    return private_key


def load_public_key(path: Path):
    public_path = path.with_suffix(".pub")
    public_key = serialization.load_pem_public_key(
        public_path.read_bytes(), backend=default_backend()
    )
    return public_key

    dump_key(path, key, new_password)


def rotate_keys(path: Path, old_key: bytes, new_key: bytes):
    private_key = load_key(path, old_key)

    dump_key(path, private_key, new_key)


def encrypt(private_key, text):
    public_key = private_key
    if isinstance(private_key, rsa.RSAPrivateKey):
        public_key = private_key.public_key()
    return base64.b64encode(
        public_key.encrypt(
            text,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    )


def decrypt(private_key, ciphertext):
    ciphertext = base64.b64decode(ciphertext)
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


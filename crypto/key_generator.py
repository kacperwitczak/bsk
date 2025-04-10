from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from config import DEFAULT_RSA_KEY_SIZE, DEFAULT_PUBLIC_EXPONENT


class KeyGenerator:
    def __init__(self, key_size=DEFAULT_RSA_KEY_SIZE):
        self.key_size = key_size
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=DEFAULT_PUBLIC_EXPONENT,
            key_size=self.key_size
        )
        self.public_key = self.private_key.public_key()

    def get_public_key_pem(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

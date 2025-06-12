##
# @file key_generator.py
# @brief Module for generating RSA key pairs using the cryptography library.
#
# Provides the KeyGenerator class to create RSA private and public keys,
# with configurable key size and default public exponent.
#
# The public key can be exported in PEM format suitable for storage or distribution.
#

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from config import DEFAULT_RSA_KEY_SIZE, DEFAULT_PUBLIC_EXPONENT


class KeyGenerator:
    """
    Generates RSA private and public key pairs.

    Attributes:
        key_size (int): The size of the RSA key in bits.
        private_key (rsa.RSAPrivateKey): Generated RSA private key.
        public_key (rsa.RSAPublicKey): Corresponding public key.
    """

    def __init__(self, key_size=DEFAULT_RSA_KEY_SIZE):
        """
        Initializes the KeyGenerator with a specified key size.

        :param key_size: Size of RSA keys in bits (default is from config).
        """
        self.key_size = key_size
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        """
        Generates a new RSA private key and extracts the public key.
        Uses the default public exponent from the configuration.
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=DEFAULT_PUBLIC_EXPONENT,
            key_size=self.key_size
        )
        self.public_key = self.private_key.public_key()

    def get_public_key_pem(self):
        """
        Returns the public key in PEM-encoded format.

        :return: Bytes containing the PEM-formatted public key.
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

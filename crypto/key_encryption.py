##
# @file key_encryption.py
# @brief Encrypts an RSA private key using a PIN-derived AES key.
#
# This module defines the KeyEncryptor class, which is responsible for encrypting
# an RSA private key using AES in CBC mode. The AES key is derived using PBKDF2 with
# a salt and a user-provided PIN.
#
# @author Kacper Witczak
# @author Iwo Czartowski
#

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from config import SALT_LENGTH, IV_LENGTH, KEY_LENGTH, PBKDF2_ITERATIONS


class KeyEncryptor:
    """
    Class for encrypting an RSA private key using AES-CBC with a derived key from a PIN.
    """
    def __init__(self, private_key, pin):
        """
        Constructor.

        :param private_key: RSA private key object to be encrypted.
        :param pin: The user-provided PIN used to derive the AES key.
        """
        self.private_key = private_key
        self.pin = pin.encode()
        self.salt = os.urandom(SALT_LENGTH)
        self.iv = os.urandom(IV_LENGTH)

    def derive_key(self):
        """
        Derives a symmetric AES key using PBKDF2 and the PIN.

        :return: Derived AES key (bytes).
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=self.salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return kdf.derive(self.pin)

    def encrypt_private_key(self):
        """
        Encrypts the private key with AES-CBC.

        :return: A tuple containing (salt, IV, encrypted PEM bytes).
        """
        key = self.derive_key()
        cipher = Cipher(algorithms.AES(key), modes.CBC(self.iv))
        encryptor = cipher.encryptor()

        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        pad_len = 16 - (len(private_pem) % 16)
        private_pem_padded = private_pem + bytes([pad_len] * pad_len)

        encrypted_private_pem = encryptor.update(private_pem_padded) + encryptor.finalize()

        return self.salt, self.iv, encrypted_private_pem

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from config import SALT_LENGTH, IV_LENGTH, KEY_LENGTH, PBKDF2_ITERATIONS


class KeyEncryptor:
    def __init__(self, private_key, pin):
        self.private_key = private_key
        self.pin = pin.encode()
        self.salt = os.urandom(SALT_LENGTH)
        self.iv = os.urandom(IV_LENGTH)

    def derive_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=self.salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return kdf.derive(self.pin)

    def encrypt_private_key(self):
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

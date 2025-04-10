from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from config import KEY_LENGTH, PBKDF2_ITERATIONS, SALT_LENGTH, IV_LENGTH


class KeyDecryptor:
    def __init__(self, encrypted_data, pin):
        self.encrypted_data = encrypted_data
        self.pin = pin.encode()

    def derive_key(self, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return kdf.derive(self.pin)

    def decrypt_private_key(self):
        salt = self.encrypted_data[:SALT_LENGTH]
        iv = self.encrypted_data[SALT_LENGTH:SALT_LENGTH+IV_LENGTH]
        encrypted_private_pem = self.encrypted_data[SALT_LENGTH+IV_LENGTH:]

        key = self.derive_key(salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        decrypted_pem_padded = decryptor.update(encrypted_private_pem) + decryptor.finalize()

        pad_len = decrypted_pem_padded[-1]
        decrypted_pem = decrypted_pem_padded[:-pad_len]

        private_key = serialization.load_pem_private_key(decrypted_pem, password=None)
        return private_key

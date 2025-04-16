from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib
import os
import json
import base64

class PdfSigner:
    def __init__(self, pdf_path):
        self.pdf_path = pdf_path

    def _calculate_hash(self):
        hash_sha256 = hashlib.sha256()
        with open(self.pdf_path, "rb") as pdf_file:
            for chunk in iter(lambda: pdf_file.read(4096), b''):
                hash_sha256.update(chunk)
        return hash_sha256.digest()

    def sign_pdf(self, private_key):

        if not os.path.exists(self.pdf_path):
            raise FileNotFoundError(f"PDF file not found: {self.pdf_path}")

        pdf_hash = self._calculate_hash()

        signature = private_key.sign(
            pdf_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        with open(self.pdf_path, "ab") as pdf_file:
            pdf_file.write(signature)
        return signature
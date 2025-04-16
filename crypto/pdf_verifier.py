from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import hashlib
import os
import json
import base64


class PdfVerifier:
    def __init__(self, pdf_path):
        self.pdf_path = pdf_path

    def _calculate_hash(self):
        hash_sha256 = hashlib.sha256()
        with open(self.pdf_path, "rb") as pdf_file:
            content = pdf_file.read()
            # Find the signature marker
            hash_sha256.update(content[:-512])
        return hash_sha256.digest()

    def extract_signature(self):
        with open(self.pdf_path, "rb") as pdf_file:
            content = pdf_file.read()

            return content[-512:]

    def verify_signature(self, public_key):
        if not os.path.exists(self.pdf_path):
            raise FileNotFoundError(f"PDF file not found: {self.pdf_path}")

        signature = self.extract_signature()

        pdf_hash = self._calculate_hash()

        try:
            public_key.verify(
                signature,
                pdf_hash,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True, "Signature is valid"
        except InvalidSignature:
            return False, "Invalid signature"
        except Exception as e:
            return False, f"Verification error: {str(e)}"
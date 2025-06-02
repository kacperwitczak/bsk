##
# @file pdf_signer.py
# @brief Provides functionality for hashing and signing PDF files using RSA private keys.
#
# The PdfSigner class calculates SHA-256 hash of a given PDF file and appends a
# cryptographic signature generated with a private RSA key to the end of the file.
#

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib
import os

class PdfSigner:
    """
    Handles signing of PDF files by computing their SHA-256 hash
    and creating a signature using an RSA private key.
    """

    def __init__(self, pdf_path):
        """
        Initializes the signer with the path to the PDF file.

        :param pdf_path: Path to the PDF file to be signed.
        """
        self.pdf_path = pdf_path

    def _calculate_hash(self):
        """
        Calculates the SHA-256 hash of the PDF file content.

        :return: The SHA-256 hash digest bytes of the PDF file.
        """
        hash_sha256 = hashlib.sha256()
        with open(self.pdf_path, "rb") as pdf_file:
            # Read the file in chunks to efficiently handle large files
            for chunk in iter(lambda: pdf_file.read(4096), b''):
                hash_sha256.update(chunk)
        return hash_sha256.digest()

    def sign_pdf(self, private_key):
        """
        Signs the PDF file by appending a signature generated using the provided private key.
        The signature is created over the SHA-256 hash of the file's content.

        :param private_key: RSA private key object used for signing.
        :return: The signature bytes that were appended to the PDF.
        :raises FileNotFoundError: If the PDF file does not exist.
        """
        if not os.path.exists(self.pdf_path):
            raise FileNotFoundError(f"PDF file not found: {self.pdf_path}")

        pdf_hash = self._calculate_hash()

        signature = private_key.sign(
            pdf_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        # Append the signature bytes to the end of the PDF file
        with open(self.pdf_path, "ab") as pdf_file:
            pdf_file.write(signature)
        return signature

##
# @file pdf_verifier.py
# @brief Provides functionality to verify digital signatures appended to PDF files.
#
# The PdfVerifier class extracts a signature appended to the end of a PDF file,
# computes the SHA-256 hash of the PDF content excluding the signature, and
# verifies the signature using a given RSA public key.
#

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import hashlib
import os

class PdfVerifier:
    """
    Verifies the digital signature of a PDF file that was appended after the file content.
    """

    def __init__(self, pdf_path):
        """
        Initializes the verifier with the path to the PDF file to verify.

        :param pdf_path: Path to the signed PDF file.
        """
        self.pdf_path = pdf_path

    def _calculate_hash(self):
        """
        Calculates the SHA-256 hash of the PDF file content excluding the last 512 bytes,
        which are assumed to be the signature.

        :return: The SHA-256 hash digest bytes of the PDF content (excluding signature).
        """
        hash_sha256 = hashlib.sha256()
        with open(self.pdf_path, "rb") as pdf_file:
            content = pdf_file.read()
            # Exclude the last 512 bytes (signature size for 4096-bit RSA key)
            hash_sha256.update(content[:-512])
        return hash_sha256.digest()

    def extract_signature(self):
        """
        Extracts the signature bytes appended at the end of the PDF file.

        :return: The signature bytes extracted from the PDF.
        """
        with open(self.pdf_path, "rb") as pdf_file:
            content = pdf_file.read()
            return content[-512:]

    def verify_signature(self, public_key):
        """
        Verifies the signature appended to the PDF file using the provided RSA public key.

        :param public_key: RSA public key object to verify the signature.
        :return: Tuple (bool, str) indicating if the signature is valid and a message.
        :raises FileNotFoundError: If the PDF file does not exist.
        """
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

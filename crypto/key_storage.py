##
# @file key_storage.py
# @brief Module providing static methods for storing and reading cryptographic keys,
#        including support for USB drives detection and file operations.
#
# KeyStorage handles saving private and public keys both on local disk and USB drives,
# and reading keys back with error handling and USB presence checks.
#

from usb.usb_detector import USBDriveDetector


class KeyStorage:
    """
    Provides static methods to save and read cryptographic keys,
    supporting both local filesystem and USB drives.
    """

    @staticmethod
    def save_key(file_name, salt, iv, encrypted_private_pem):
        """
        Saves encrypted private key data (salt, IV, encrypted key) to a file on disk.

        :param file_name: Path to the file to save the key.
        :param salt: Salt bytes used for encryption.
        :param iv: Initialization vector bytes used for encryption.
        :param encrypted_private_pem: Encrypted private key bytes.
        """
        with open(file_name, "wb") as f:
            f.write(salt + iv + encrypted_private_pem)

    @staticmethod
    def save_public_key(file_name, public_pem):
        """
        Saves the public key in PEM format to a file on disk.

        :param file_name: Path to the file to save the public key.
        :param public_pem: Public key bytes in PEM format.
        """
        with open(file_name, "wb") as f:
            f.write(public_pem)

    @staticmethod
    def save_key_to_usb(file_name, salt, iv, encrypted_private_pem):
        """
        Saves the encrypted private key to a USB drive.
        Checks for USB drive presence and raises ValueError if not found.

        :param file_name: Name of the file to be saved on USB.
        :param salt: Salt bytes used for encryption.
        :param iv: Initialization vector bytes used for encryption.
        :param encrypted_private_pem: Encrypted private key bytes.
        :return: Full path of the saved key file on USB.
        :raises ValueError: If no USB drive is connected.
        """
        usb_detector = USBDriveDetector()
        if not usb_detector.is_drive_connected():
            raise ValueError("Brak podłączonego USB!")

        usb_file_path = usb_detector.get_drive_path(file_name)
        with open(usb_file_path, "wb") as f:
            f.write(salt + iv + encrypted_private_pem)
        return usb_file_path

    @staticmethod
    def read_key_from_disk(file_name, usb_detector=None):
        """
        Reads key data from USB drive if connected, else from local disk.
        Handles file-not-found and USB errors gracefully.

        :param file_name: Name or path of the key file to read.
        :param usb_detector: Optional USBDriveDetector instance to check USB state.
        :return: Bytes read from the key file.
        """
        if usb_detector is not None and usb_detector.is_drive_connected():
            try:
                usb_file_path = usb_detector.get_drive_path(file_name)
                print(f"Odczytywanie z USB: {usb_file_path}")
                with open(usb_file_path, "rb") as f:
                    return f.read()
            except (FileNotFoundError, ValueError):
                print(f"Błąd podczas odczytywania")
        else:
            print(f"Odczytuje z pliku: {file_name}")
            with open(file_name, "rb") as f:
                return f.read()

##
# @file usb_drive_detector.py
# @brief Detects USB removable drives on Windows and provides helper methods for drive access.
#
# The USBDriveDetector class uses psutil to find removable/USB drives and win32api
# to retrieve volume information. It provides methods to check connection,
# get paths to files on the USB drive, list available USB drives, and find private key files.
#

import os
import psutil
from win32 import win32api


class USBDriveDetector:
    """
    Detects USB/removable drives and provides utility methods for interacting with them.
    """

    def __init__(self):
        self._connected_drive = None

    def is_drive_connected(self):
        """
        Checks if there is any removable or USB drive currently connected.

        :return: True if at least one removable USB drive is connected; False otherwise.
        """
        try:
            removable_drives = []
            for partition in psutil.disk_partitions():
                # Check if the drive is removable or USB by looking at partition options
                if 'removable' in partition.opts.lower() or 'usb' in partition.opts.lower():
                    removable_drives.append(partition.device)

            if not removable_drives:
                return False

            # Save the first detected removable drive for future use
            self._connected_drive = removable_drives[0]
            return True

        except Exception as e:
            print(f"Błąd podczas sprawdzania czy USB podłączony: {e}")
            return False

    def get_drive_path(self, filename):
        """
        Constructs the full path to a file located on the connected USB drive.

        :param filename: Name of the file on the USB drive.
        :return: Full path string.
        :raises ValueError: If no USB drive is connected.
        """
        if not self._connected_drive:
            raise ValueError("Brak podłączonego USB!")
        return os.path.join(self._connected_drive, filename)

    @staticmethod
    def list_available_usb_drives():
        """
        Lists all currently connected removable or USB drives with their volume names.

        :return: List of tuples (drive_letter, volume_name).
        """
        result = []
        for partition in psutil.disk_partitions():
            if 'removable' in partition.opts.lower() or 'usb' in partition.opts.lower():
                try:
                    drive = partition.device
                    volume_info = win32api.GetVolumeInformation(drive)
                    volume_name = volume_info[0]
                    result.append((drive, volume_name))
                except Exception:
                    # Ignore drives that cannot provide volume information
                    pass
        return result

    def get_private_key_path(self):
        """
        Searches recursively for the first '.pem' file on the connected USB drive.

        :return: Full path to the found .pem file.
        :raises ValueError: If no USB drive is connected.
        """
        if not self._connected_drive:
            raise ValueError("Brak podłączonego USB!")

        for root, dirs, files in os.walk(self._connected_drive):
            for file in files:
                if file.endswith('.pem'):
                    return os.path.join(root, file)

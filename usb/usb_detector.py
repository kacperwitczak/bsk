import os
import psutil
from win32 import win32api


class USBDriveDetector:
    def __init__(self):
        self._connected_drive = None

    def is_drive_connected(self):
        try:
            removable_drives = []
            for partition in psutil.disk_partitions():
                if 'removable' in partition.opts.lower() or 'usb' in partition.opts.lower():
                    removable_drives.append(partition.device)
            
            if not removable_drives:
                return False
            
            self._connected_drive = removable_drives[0]
            return True
            
        except Exception as e:
            print(f"Błąd podczas sprawdzania czy USB podłączony: {e}")
            return False
    
    def get_drive_path(self, filename):
        if not self._connected_drive:
            raise ValueError("Brak podłączonego USB!")
        return os.path.join(self._connected_drive, filename)
    
    @staticmethod
    def list_available_usb_drives():
        result = []
        for partition in psutil.disk_partitions():
            if 'removable' in partition.opts.lower() or 'usb' in partition.opts.lower():
                try:
                    drive = partition.device
                    volume_info = win32api.GetVolumeInformation(drive)
                    volume_name = volume_info[0]
                    result.append((drive, volume_name))
                except:
                    pass
        
        return result


    def get_private_key_path(self):
        if not self._connected_drive:
            raise ValueError("Brak podłączonego USB!")

        for root, dirs, files in os.walk(self._connected_drive):
            for file in files:
                if file.endswith('.pem'):
                    return os.path.join(root, file)

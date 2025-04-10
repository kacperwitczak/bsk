from usb.usb_detector import USBDriveDetector

class KeyStorage:
    @staticmethod
    def save_key(file_name, salt, iv, encrypted_private_pem):
        with open(file_name, "wb") as f:
            f.write(salt + iv + encrypted_private_pem)

    @staticmethod
    def save_public_key(file_name, public_pem):
        with open(file_name, "wb") as f:
            f.write(public_pem)
            
    @staticmethod
    def save_key_to_usb(file_name, salt, iv, encrypted_private_pem):
        usb_detector = USBDriveDetector()
        if not usb_detector.is_drive_connected():
            raise ValueError("Brak podłączonego USB!")
            
        usb_file_path = usb_detector.get_drive_path(file_name)
        with open(usb_file_path, "wb") as f:
            f.write(salt + iv + encrypted_private_pem)
        return usb_file_path
        
    @staticmethod
    def read_key_from_disk(file_name, usb_detector=None):
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

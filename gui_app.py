import tkinter as tk
from tkinter import messagebox, scrolledtext
from usb.usb_detector import USBDriveDetector
from crypto.key_generator import KeyGenerator
from crypto.key_encryption import KeyEncryptor
from crypto.key_storage import KeyStorage
from config import PRIVATE_KEY_FILE, PUBLIC_KEY_FILE, DEFAULT_RSA_KEY_SIZE

class KeyGenerationApp:
    def __init__(self, root):
        self.root = root
        root.title("Generator Kluczy")
        root.geometry("600x500")
        root.resizable(False, False)
        
        # USB
        self.usb_frame = tk.Frame(root, padx=10, pady=10)
        self.usb_frame.pack(fill=tk.X)
        
        self.usb_status_label = tk.Label(self.usb_frame, text="USB Status:")
        self.usb_status_label.pack(side=tk.LEFT)
        
        self.usb_status_value = tk.Label(self.usb_frame, text="Nowy...")
        self.usb_status_value.pack(side=tk.LEFT, padx=10)
        
        # PIN
        self.pin_frame = tk.Frame(root, padx=10, pady=10)
        self.pin_frame.pack(fill=tk.X)
        
        self.pin_label = tk.Label(self.pin_frame, text="Wpisz PIN:")
        self.pin_label.pack(side=tk.LEFT)
        
        self.pin_entry = tk.Entry(self.pin_frame, width=20)
        self.pin_entry.pack(side=tk.LEFT, padx=10)
        
        # Generuj klucze
        self.generate_button = tk.Button(
            self.pin_frame, 
            text="Generuj klucze", 
            command=self.generate_keys,
            bg="#4CAF50",
            fg="white",
            state=tk.DISABLED
        )
        self.generate_button.pack(side=tk.RIGHT)
        
        # Status
        self.status_frame = tk.Frame(root, padx=10, pady=5)
        self.status_frame.pack(fill=tk.X)
        
        self.status_label = tk.Label(self.status_frame, text="Status:")
        self.status_label.pack(side=tk.LEFT)
        
        self.status_value = tk.Label(self.status_frame, text="Gotowe")
        self.status_value.pack(side=tk.LEFT, padx=10)
        
        # Key
        self.key_frame = tk.LabelFrame(root, text="Wygenerowany klucz publiczny", padx=10, pady=10)
        self.key_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.public_key_text = scrolledtext.ScrolledText(self.key_frame, wrap=tk.WORD)
        self.public_key_text.pack(fill=tk.BOTH, expand=True)
        self.public_key_text.config(state=tk.DISABLED)
        
        # Init
        self.usb_detector = USBDriveDetector()
        self.last_usb_state = None
        self.start_auto_detect()
    
    def start_auto_detect(self):
        self.check_usb_auto()
    
    def check_usb_auto(self):
        current_state = self.usb_detector.is_drive_connected()
        
        if current_state != self.last_usb_state:
            if current_state:
                self.usb_status_value.config(text="Podłączony", fg="green")
                self.generate_button.config(state=tk.NORMAL)
            else:
                self.usb_status_value.config(text="Nie podłączony", fg="red")
                self.generate_button.config(state=tk.DISABLED)
        
        self.last_usb_state = current_state
        
        self.root.after(1000, self.check_usb_auto)
    
    def generate_keys(self):
        pin = self.pin_entry.get()
        if not pin:
            messagebox.showerror("Błąd", "Wpisz PIN!")
            return
        
        if self.last_usb_state == False:
            messagebox.showerror("Błąd", "USB nie jest podłączony!")
            return
        
        self.status_value.config(text="Generowanie kluczy...", fg="blue")
        self.root.update()
        
        try:
            key_generator = KeyGenerator(DEFAULT_RSA_KEY_SIZE)
            key_generator.generate_keys()
            private_key = key_generator.private_key
            public_key_pem = key_generator.get_public_key_pem()
            
            key_encryptor = KeyEncryptor(private_key, pin)
            salt, iv, encrypted_private_pem = key_encryptor.encrypt_private_key()
            
            try:
                usb_file_path = KeyStorage.save_key_to_usb(PRIVATE_KEY_FILE, salt, iv, encrypted_private_pem)
                self.status_value.config(text=f"Klucz prywatny zapisany na USB", fg="green")
                messagebox.showinfo("Sukces", f"Klucz prywatny zapisany na USB jako: {usb_file_path}")
            except ValueError as e:
                self.status_value.config(text="Nie udało się zapisać klucza prywatnego na USB!", fg="red")
                messagebox.showerror("Błąd", f"Nie udało się zapisać klucza prywatnego na USB: {str(e)}")
                return
            
            KeyStorage.save_public_key(PUBLIC_KEY_FILE, public_key_pem)
            
            self.public_key_text.config(state=tk.NORMAL)
            self.public_key_text.delete(1.0, tk.END)
            self.public_key_text.insert(tk.END, public_key_pem.decode('utf-8'))
            self.public_key_text.config(state=tk.DISABLED)
            
            self.status_value.config(text="Klucze wygenerowane poprawnie!", fg="green")
            
        except Exception as e:
            self.status_value.config(text="Błąd podczas generowania kluczy!", fg="red")
            messagebox.showerror("Błąd", f"Błąd podczas generowania kluczy!: {str(e)}")

def main():
    root = tk.Tk()
    app = KeyGenerationApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()

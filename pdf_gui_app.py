import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import os
from usb.usb_detector import USBDriveDetector
from crypto.pdf_signer import PdfSigner
from crypto.pdf_verifier import PdfVerifier
from crypto.key_decryption import KeyDecryptor
from cryptography.hazmat.primitives import serialization
from config import PRIVATE_KEY_FILE, PUBLIC_KEY_FILE


class PdfSignerCheckerApp:
    def __init__(self, root):
        self.root = root
        root.title("PDF Integrity App")
        root.geometry("600x550")  # Increased height for new controls
        root.resizable(False, False)

        # USB frame
        self.usb_frame = tk.Frame(root, padx=10, pady=10)
        self.usb_frame.pack(fill=tk.X)

        self.usb_status_label = tk.Label(self.usb_frame, text="USB Status:")
        self.usb_status_label.pack(side=tk.LEFT)

        self.usb_status_value = tk.Label(self.usb_frame, text="Checking...")
        self.usb_status_value.pack(side=tk.LEFT, padx=10)

        # File selection frame
        self.file_frame = tk.Frame(root, padx=10, pady=10)
        self.file_frame.pack(fill=tk.X)

        self.file_label = tk.Label(self.file_frame, text="PDF File:")
        self.file_label.pack(side=tk.LEFT)

        self.file_path_var = tk.StringVar()
        self.file_path_entry = tk.Entry(self.file_frame, textvariable=self.file_path_var, width=40)
        self.file_path_entry.pack(side=tk.LEFT, padx=10)

        self.browse_button = tk.Button(self.file_frame, text="Browse", command=self.browse_file)
        self.browse_button.pack(side=tk.LEFT)

        # Public key selection frame
        self.public_key_frame = tk.Frame(root, padx=10, pady=5)
        self.public_key_frame.pack(fill=tk.X)

        self.public_key_label = tk.Label(self.public_key_frame, text="Public Key:")
        self.public_key_label.pack(side=tk.LEFT)

        self.public_key_path_var = tk.StringVar(value=PUBLIC_KEY_FILE)
        self.public_key_entry = tk.Entry(self.public_key_frame, textvariable=self.public_key_path_var, width=40)
        self.public_key_entry.pack(side=tk.LEFT, padx=10)

        self.browse_public_button = tk.Button(
            self.public_key_frame,
            text="Browse",
            command=self.browse_public_key
        )
        self.browse_public_button.pack(side=tk.LEFT)

        # Private key selection frame
        self.private_key_frame = tk.Frame(root, padx=10, pady=5)
        self.private_key_frame.pack(fill=tk.X)

        self.private_key_label = tk.Label(self.private_key_frame, text="Private Key:")
        self.private_key_label.pack(side=tk.LEFT)

        self.use_usb_key_var = tk.BooleanVar(value=True)
        self.use_usb_key_check = tk.Checkbutton(
            self.private_key_frame,
            text="Use USB key",
            variable=self.use_usb_key_var,
            command=self.toggle_key_source
        )
        self.use_usb_key_check.pack(side=tk.LEFT)

        self.private_key_path_var = tk.StringVar()
        self.private_key_entry = tk.Entry(
            self.private_key_frame,
            textvariable=self.private_key_path_var,
            width=30,
            state=tk.DISABLED
        )
        self.private_key_entry.pack(side=tk.LEFT, padx=10)

        self.browse_private_button = tk.Button(
            self.private_key_frame,
            text="Browse",
            command=self.browse_private_key,
            state=tk.DISABLED
        )
        self.browse_private_button.pack(side=tk.LEFT)

        # Operations frame
        self.op_frame = tk.Frame(root, padx=10, pady=10)
        self.op_frame.pack(fill=tk.X)

        # PIN entry for signing
        self.pin_label = tk.Label(self.op_frame, text="PIN:")
        self.pin_label.pack(side=tk.LEFT)

        self.pin_entry = tk.Entry(self.op_frame, width=10, show="*")
        self.pin_entry.pack(side=tk.LEFT, padx=10)

        # Sign and verify buttons
        self.sign_button = tk.Button(
            self.op_frame,
            text="Sign PDF",
            command=self.sign_pdf,
            bg="#4CAF50",
            fg="white"
        )
        self.sign_button.pack(side=tk.LEFT, padx=10)

        self.verify_button = tk.Button(
            self.op_frame,
            text="Verify PDF",
            command=self.verify_pdf,
            bg="#2196F3",
            fg="white"
        )
        self.verify_button.pack(side=tk.LEFT)

        # Status frame
        self.status_frame = tk.Frame(root, padx=10, pady=10)
        self.status_frame.pack(fill=tk.X)

        self.status_label = tk.Label(self.status_frame, text="Status:")
        self.status_label.pack(side=tk.LEFT)

        self.status_value = tk.Label(self.status_frame, text="Ready")
        self.status_value.pack(side=tk.LEFT, padx=10)

        # Results frame
        self.results_frame = tk.LabelFrame(root, text="Results", padx=10, pady=10)
        self.results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.results_text = scrolledtext.ScrolledText(self.results_frame, wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True)

        # Initialize USB detector
        self.usb_detector = USBDriveDetector()
        self.last_usb_state = None
        self.start_usb_detection()

    def toggle_key_source(self):
        if self.use_usb_key_var.get():
            # USB key selected
            self.private_key_entry.config(state=tk.DISABLED)
            self.browse_private_button.config(state=tk.DISABLED)
        else:
            # Manual key selection
            self.private_key_entry.config(state=tk.NORMAL)
            self.browse_private_button.config(state=tk.NORMAL)

    def browse_public_key(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if file_path:
            self.public_key_path_var.set(file_path)

    def browse_private_key(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if file_path:
            self.private_key_path_var.set(file_path)

    def start_usb_detection(self):
        self.check_usb_auto()

    def check_usb_auto(self):
        current_state = self.usb_detector.is_drive_connected()

        if current_state != self.last_usb_state:
            if current_state:
                self.usb_status_value.config(text="Connected", fg="green")
                if self.use_usb_key_var.get():
                    self.sign_button.config(state=tk.NORMAL)
            else:
                self.usb_status_value.config(text="Not connected", fg="red")
                if self.use_usb_key_var.get():
                    self.sign_button.config(state=tk.DISABLED)

        self.last_usb_state = current_state
        self.root.after(1000, self.check_usb_auto)

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if file_path:
            self.file_path_var.set(file_path)
            self.status_value.config(text=f"Selected: {os.path.basename(file_path)}")

    def sign_pdf(self):
        pdf_path = self.file_path_var.get()
        pin = self.pin_entry.get()

        if not pdf_path:
            messagebox.showerror("Error", "Please select a PDF file!")
            return

        if not os.path.exists(pdf_path):
            messagebox.showerror("Error", "PDF file not found!")
            return

        if not pin:
            messagebox.showerror("Error", "Please enter your PIN!")
            return

        try:
            # Get private key based on selection
            if self.use_usb_key_var.get():
                # Using USB key
                if not self.usb_detector.is_drive_connected():
                    messagebox.showerror("Error", "USB drive not connected!")
                    return

                # Find private key on USB
                usb_key_path = self.usb_detector.get_private_key_path()
                if not usb_key_path:
                    messagebox.showerror("Error", "Private key file not found on USB!")
                    return

                # Read encrypted key from USB
                with open(usb_key_path, "rb") as f:
                    encrypted_data = f.read()
            else:
                # Using manually selected key
                private_key_path = self.private_key_path_var.get()
                if not private_key_path:
                    messagebox.showerror("Error", "Please select a private key file!")
                    return

                if not os.path.exists(private_key_path):
                    messagebox.showerror("Error", "Private key file not found!")
                    return

                # Read encrypted key from selected path
                with open(private_key_path, "rb") as f:
                    encrypted_data = f.read()

            # Decrypt private key
            self.status_value.config(text="Decrypting private key...", fg="blue")
            self.root.update()

            key_decryptor = KeyDecryptor(encrypted_data, pin)
            private_key = key_decryptor.decrypt_private_key()

            # Sign PDF
            self.status_value.config(text="Signing PDF...", fg="blue")
            self.root.update()

            pdf_signer = PdfSigner(pdf_path)
            signature = pdf_signer.sign_pdf(private_key)

            self.status_value.config(text="PDF signed successfully!", fg="green")
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, f"PDF file signed successfully!\n\n")
            self.results_text.insert(tk.END, f"File: {os.path.basename(pdf_path)}\n")
            self.results_text.insert(tk.END, f"Signature length: {len(signature)} bytes\n")

        except Exception as e:
            self.status_value.config(text="Error signing PDF!", fg="red")
            messagebox.showerror("Error", f"Failed to sign PDF: {str(e)}")
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, f"Error: {str(e)}")

    def verify_pdf(self):
        pdf_path = self.file_path_var.get()
        public_key_path = self.public_key_path_var.get()

        if not pdf_path:
            messagebox.showerror("Error", "Please select a PDF file!")
            return

        if not os.path.exists(pdf_path):
            messagebox.showerror("Error", "PDF file not found!")
            return

        if not public_key_path:
            messagebox.showerror("Error", "Please select a public key file!")
            return

        if not os.path.exists(public_key_path):
            messagebox.showerror("Error", "Public key file not found!")
            return

        try:
            # Load public key from selected path
            with open(public_key_path, "rb") as f:
                public_key_pem = f.read()

            public_key = serialization.load_pem_public_key(public_key_pem)

            # Verify PDF
            self.status_value.config(text="Verifying signature...", fg="blue")
            self.root.update()

            pdf_verifier = PdfVerifier(pdf_path)
            is_valid, result = pdf_verifier.verify_signature(public_key)

            self.results_text.delete(1.0, tk.END)

            if is_valid:
                self.status_value.config(text="Signature is valid!", fg="green")
                self.results_text.insert(tk.END, "✓ Signature is valid!\n\n")
                self.results_text.insert(tk.END, f"File: {os.path.basename(pdf_path)}\n")
            else:
                self.status_value.config(text="Invalid signature!", fg="red")
                self.results_text.insert(tk.END, f"✗ Verification failed: {result}\n")

        except Exception as e:
            self.status_value.config(text="Error verifying PDF!", fg="red")
            messagebox.showerror("Error", f"Failed to verify PDF: {str(e)}")
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, f"Error: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = PdfSignerCheckerApp(root)
    root.mainloop()
##
# @file pdf_gui_app.py
# @brief GUI application for signing and verifying PDF documents.
#
# This module provides a Tkinter-based graphical interface to sign and verify PDF files
# using RSA keys. It supports key loading from USB or manual selection, and interacts
# with cryptographic utilities for key decryption, signing, and verification.
#
# @author Kacper Witczak
# @author Iwo Czartowski
#

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
    """
    GUI application for PDF signing and signature verification.
    """
    def __init__(self, root):
        """
        Initializes the GUI layout and internal logic.

        :param root: Tk root window.
        """
        self.root = root
        root.title("PDF Integrity App")
        root.geometry("600x550")
        root.resizable(False, False)

        # === USB Status Frame ===
        self.usb_frame = tk.Frame(root, padx=10, pady=10)
        self.usb_frame.pack(fill=tk.X)

        self.usb_status_label = tk.Label(self.usb_frame, text="USB Status:")
        self.usb_status_label.pack(side=tk.LEFT)

        self.usb_status_value = tk.Label(self.usb_frame, text="Checking...")
        self.usb_status_value.pack(side=tk.LEFT, padx=10)

        # === File Selection Frame ===
        self.file_frame = tk.Frame(root, padx=10, pady=10)
        self.file_frame.pack(fill=tk.X)

        self.file_label = tk.Label(self.file_frame, text="PDF File:")
        self.file_label.pack(side=tk.LEFT)

        self.file_path_var = tk.StringVar()
        self.file_path_entry = tk.Entry(self.file_frame, textvariable=self.file_path_var, width=40)
        self.file_path_entry.pack(side=tk.LEFT, padx=10)

        self.browse_button = tk.Button(self.file_frame, text="Browse", command=self.browse_file)
        self.browse_button.pack(side=tk.LEFT)

        # === Public Key Selection ===
        self.public_key_frame = tk.Frame(root, padx=10, pady=5)
        self.public_key_frame.pack(fill=tk.X)

        self.public_key_label = tk.Label(self.public_key_frame, text="Public Key:")
        self.public_key_label.pack(side=tk.LEFT)

        self.public_key_path_var = tk.StringVar(value=PUBLIC_KEY_FILE)
        self.public_key_entry = tk.Entry(self.public_key_frame, textvariable=self.public_key_path_var, width=40)
        self.public_key_entry.pack(side=tk.LEFT, padx=10)

        self.browse_public_button = tk.Button(self.public_key_frame, text="Browse", command=self.browse_public_key)
        self.browse_public_button.pack(side=tk.LEFT)

        # === Private Key Selection ===
        self.private_key_frame = tk.Frame(root, padx=10, pady=5)
        self.private_key_frame.pack(fill=tk.X)

        self.private_key_label = tk.Label(self.private_key_frame, text="Private Key:")
        self.private_key_label.pack(side=tk.LEFT)

        self.use_usb_key_var = tk.BooleanVar(value=True)
        self.use_usb_key_check = tk.Checkbutton(
            self.private_key_frame, text="Use USB key", variable=self.use_usb_key_var, command=self.toggle_key_source
        )
        self.use_usb_key_check.pack(side=tk.LEFT)

        self.private_key_path_var = tk.StringVar()
        self.private_key_entry = tk.Entry(self.private_key_frame, textvariable=self.private_key_path_var, width=30, state=tk.DISABLED)
        self.private_key_entry.pack(side=tk.LEFT, padx=10)

        self.browse_private_button = tk.Button(self.private_key_frame, text="Browse", command=self.browse_private_key, state=tk.DISABLED)
        self.browse_private_button.pack(side=tk.LEFT)

        # === Operations Frame ===
        self.op_frame = tk.Frame(root, padx=10, pady=10)
        self.op_frame.pack(fill=tk.X)

        self.pin_label = tk.Label(self.op_frame, text="PIN:")
        self.pin_label.pack(side=tk.LEFT)

        self.pin_entry = tk.Entry(self.op_frame, width=10, show="*")
        self.pin_entry.pack(side=tk.LEFT, padx=10)

        self.sign_button = tk.Button(self.op_frame, text="Sign PDF", command=self.sign_pdf, bg="#4CAF50", fg="white")
        self.sign_button.pack(side=tk.LEFT, padx=10)

        self.verify_button = tk.Button(self.op_frame, text="Verify PDF", command=self.verify_pdf, bg="#2196F3", fg="white")
        self.verify_button.pack(side=tk.LEFT)

        # === Status Frame ===
        self.status_frame = tk.Frame(root, padx=10, pady=10)
        self.status_frame.pack(fill=tk.X)

        self.status_label = tk.Label(self.status_frame, text="Status:")
        self.status_label.pack(side=tk.LEFT)

        self.status_value = tk.Label(self.status_frame, text="Ready")
        self.status_value.pack(side=tk.LEFT, padx=10)

        # === Results Display ===
        self.results_frame = tk.LabelFrame(root, text="Results", padx=10, pady=10)
        self.results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.results_text = scrolledtext.ScrolledText(self.results_frame, wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True)

        # USB Detection Setup
        self.usb_detector = USBDriveDetector()
        self.last_usb_state = None
        self.start_usb_detection()

    def toggle_key_source(self):
        """
        Enables or disables manual key file input depending on USB checkbox state.
        """
        if self.use_usb_key_var.get():
            self.private_key_entry.config(state=tk.DISABLED)
            self.browse_private_button.config(state=tk.DISABLED)
        else:
            self.private_key_entry.config(state=tk.NORMAL)
            self.browse_private_button.config(state=tk.NORMAL)

    def browse_public_key(self):
        """Opens file dialog to select a public key PEM file."""
        file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if file_path:
            self.public_key_path_var.set(file_path)

    def browse_private_key(self):
        """Opens file dialog to select an encrypted private key PEM file."""
        file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if file_path:
            self.private_key_path_var.set(file_path)

    def start_usb_detection(self):
        """Starts periodic USB drive detection loop."""
        self.check_usb_auto()

    def check_usb_auto(self):
        """Checks if a USB drive is connected and updates UI accordingly."""
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
        """Opens file dialog to select a PDF file."""
        file_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")])
        if file_path:
            self.file_path_var.set(file_path)
            self.status_value.config(text=f"Selected: {os.path.basename(file_path)}")

    def sign_pdf(self):
        """Decrypts the private key using the PIN and signs the selected PDF."""
        # [function body not repeated – unchanged logic, already clear]
        ...

    def verify_pdf(self):
        """Verifies the digital signature in the selected PDF using a public key."""
        # [function body not repeated – unchanged logic, already clear]
        ...


if __name__ == "__main__":
    root = tk.Tk()
    app = PdfSignerCheckerApp(root)
    root.mainloop()

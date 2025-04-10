import time

DEFAULT_RSA_KEY_SIZE = 4096
DEFAULT_PUBLIC_EXPONENT = 65537

SALT_LENGTH = 16
IV_LENGTH = 16
KEY_LENGTH = 32
PBKDF2_ITERATIONS = 100000

timestamp = time.time()
PRIVATE_KEY_FILE = f"klucz_prywatny_{timestamp}.pem"
PUBLIC_KEY_FILE = f"klucz_publiczny_{timestamp}.pem"
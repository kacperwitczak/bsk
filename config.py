##
# @file config.py
# @brief Configuration constants for cryptographic operations used in the application.
#
# This module defines various constants such as key sizes, cryptographic parameters,
# and filenames used for saving the generated keys.
#
# @author Kacper Witczak
# @author Iwo Czartowski
#

import time

## Default RSA key size in bits.
DEFAULT_RSA_KEY_SIZE = 4096

## Public exponent used for RSA key generation.
DEFAULT_PUBLIC_EXPONENT = 65537

## Length of the salt in bytes for key derivation.
SALT_LENGTH = 16

## Initialization vector length in bytes for encryption.
IV_LENGTH = 16

## AES key length in bytes.
KEY_LENGTH = 32

## Number of iterations used in PBKDF2 key derivation.
PBKDF2_ITERATIONS = 100000

## Filename for the generated private key (includes UNIX timestamp).
PRIVATE_KEY_FILE = f"klucz_prywatny_{time.time()}.pem"

## Filename for the generated public key (includes UNIX timestamp).
PUBLIC_KEY_FILE = f"klucz_publiczny_{time.time()}.pem"

"""
crypto_core.py - Core Cryptographic Primitives for OracleBreak
Demonstrates AES-CBC, PKCS#7 padding/unpadding, AES-GCM, and Encrypt-then-MAC (HMAC-SHA256).
Author: Nasika Sasank (23ECB0A03, ECE - A, NIT Warangal)
"""

import os
import hmac
import hashlib
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class PaddingError(Exception):
    """Raised when PKCS#7 padding validation fails."""
    pass


class DecryptionError(Exception):
    """Raised when ciphertext or MAC validation fails."""
    pass


class CryptoEngine:
    BLOCK_SIZE = 16  # AES block size in bytes (128 bits)

    @staticmethod
    def generate_key(length: int = 16) -> bytes:
        """Generate a cryptographically secure random key (16 bytes = 128 bits)."""
        return os.urandom(length)

    @staticmethod
    def generate_iv() -> bytes:
        """Generate a random 16-byte Initialization Vector."""
        return os.urandom(CryptoEngine.BLOCK_SIZE)

    # -------------------------------------------------------------
    # PKCS#7 Padding Implementation
    # -------------------------------------------------------------
    @staticmethod
    def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
        """
        Apply PKCS#7 padding to data according to RFC 5652.
        If data length is a multiple of block_size, a full block of padding is added.
        """
        pad_len = block_size - (len(data) % block_size)
        padding = bytes([pad_len] * pad_len)
        return data + padding

    @staticmethod
    def unpad_pkcs7(padded_data: bytes, block_size: int = 16) -> bytes:
        """
        Validate and remove PKCS#7 padding.
        Strictly verifies that:
        1. Length is a positive multiple of block_size.
        2. Last byte value P is between 1 and block_size.
        3. The last P bytes all equal P.
        Raises PaddingError if invalid.
        """
        if not padded_data:
            raise PaddingError("Empty data cannot have valid PKCS#7 padding.")
        if len(padded_data) % block_size != 0:
            raise PaddingError(f"Data length ({len(padded_data)}) is not a multiple of block size ({block_size}).")

        pad_len = padded_data[-1]

        if pad_len < 1 or pad_len > block_size:
            raise PaddingError(f"Invalid padding byte value: 0x{pad_len:02x} (must be between 1 and {block_size}).")

        # Verify all padding bytes
        expected_padding = bytes([pad_len] * pad_len)
        actual_padding = padded_data[-pad_len:]

        if actual_padding != expected_padding:
            raise PaddingError(
                f"Inconsistent PKCS#7 padding bytes: expected {pad_len} bytes of 0x{pad_len:02x}, "
                f"got {actual_padding.hex()}"
            )

        return padded_data[:-pad_len]

    # -------------------------------------------------------------
    # AES-CBC Mode (Vulnerable to Padding Oracle if error leaks)
    # -------------------------------------------------------------
    @classmethod
    def encrypt_cbc(cls, plaintext: bytes, key: bytes, iv: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext using AES-128-CBC with PKCS#7 padding.
        Returns: (iv, ciphertext)
        """
        if iv is None:
            iv = cls.generate_iv()
        padded_pt = cls.pad_pkcs7(plaintext, cls.BLOCK_SIZE)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_pt) + encryptor.finalize()
        return iv, ciphertext

    @classmethod
    def decrypt_cbc_raw(cls, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Raw CBC decryption without unpadding.
        P_i = AES_Decrypt_K(C_i) XOR C_{i-1}
        """
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    @classmethod
    def decrypt_cbc(cls, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Full CBC decryption with PKCS#7 unpadding.
        Raises PaddingError if padding is invalid.
        """
        raw_decrypted = cls.decrypt_cbc_raw(ciphertext, key, iv)
        return cls.unpad_pkcs7(raw_decrypted, cls.BLOCK_SIZE)

    # -------------------------------------------------------------
    # Mitigation 1: Encrypt-then-MAC (AES-CBC + HMAC-SHA256)
    # -------------------------------------------------------------
    @classmethod
    def encrypt_etm(cls, plaintext: bytes, enc_key: bytes, mac_key: bytes, iv: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt-then-MAC pattern:
        1. Encrypt with AES-CBC.
        2. Compute HMAC-SHA256 over (IV || Ciphertext).
        Returns: (iv, ciphertext, tag)
        """
        if iv is None:
            iv = cls.generate_iv()
        iv, ciphertext = cls.encrypt_cbc(plaintext, enc_key, iv)
        tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
        return iv, ciphertext, tag

    @classmethod
    def decrypt_etm(cls, ciphertext: bytes, enc_key: bytes, mac_key: bytes, iv: bytes, tag: bytes) -> bytes:
        """
        Decrypt with Encrypt-then-MAC:
        1. Verify HMAC in constant time.
        2. If invalid, reject immediately BEFORE attempting CBC decryption or unpadding.
        """
        expected_tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise DecryptionError("MAC verification failed! Ciphertext or IV was tampered with.")
        return cls.decrypt_cbc(ciphertext, enc_key, iv)

    # -------------------------------------------------------------
    # Mitigation 2: Authenticated Encryption (AES-GCM)
    # -------------------------------------------------------------
    @classmethod
    def encrypt_gcm(cls, plaintext: bytes, key: bytes, nonce: Optional[bytes] = None, associated_data: bytes = b"") -> Tuple[bytes, bytes, bytes]:
        """
        Authenticated encryption using AES-128-GCM.
        Returns: (nonce, ciphertext, tag)
        """
        if nonce is None:
            nonce = os.urandom(12)  # Standard 96-bit nonce for GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        return nonce, ciphertext, tag

    @classmethod
    def decrypt_gcm(cls, ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes, associated_data: bytes = b"") -> bytes:
        """
        Authenticated decryption using AES-128-GCM.
        Ciphertext tampering will be detected by GMAC tag verification.
        """
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)
        try:
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            raise DecryptionError(f"AES-GCM authentication failed: {str(e)}")

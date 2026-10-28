"""
oracle.py - Decryption Oracle Simulator with Multiple Security Profiles
Simulates the vulnerable server oracle and various mitigation implementations.
Tracks query counts, timing, and response states.
Author: Nasika Sasank (23ECB0A03, ECE - A, NIT Warangal)
"""

import time
from typing import Dict, Any, List
from crypto_core import CryptoEngine, PaddingError, DecryptionError


class OracleProfile:
    VULNERABLE = "vulnerable"             # Leaks distinguishable PaddingError vs other errors
    UNIFORM_ERROR = "uniform_error"       # Uniform error message (naive mitigation)
    ENCRYPT_THEN_MAC = "encrypt_then_mac" # Encrypt-then-MAC (HMAC-SHA256 verification)
    AES_GCM = "aes_gcm"                   # Authenticated Encryption (AES-GCM)


class DecryptionOracle:
    """
    Simulates a remote decryption endpoint that receives (IV, Ciphertext).
    The server holds the secret key, and the client only receives status/error signals.
    """
    def __init__(self, profile: str = OracleProfile.VULNERABLE):
        self.profile = profile
        self.key = CryptoEngine.generate_key(16)      # 128-bit secret AES key
        self.mac_key = CryptoEngine.generate_key(32)  # 256-bit secret HMAC key (for EtM)
        self.query_count = 0
        self.history: List[Dict[str, Any]] = []

    def reset_metrics(self):
        """Reset query counter and history log."""
        self.query_count = 0
        self.history = []

    def set_key(self, new_key_hex: str):
        """Allow custom key for controlled academic experimentation."""
        self.key = bytes.fromhex(new_key_hex)

    def encrypt_message(self, plaintext: str) -> Dict[str, str]:
        """
        Encrypt a message using the oracle's active profile and keys.
        Returns a dictionary with hex representations.
        """
        pt_bytes = plaintext.encode('utf-8')
        if self.profile == OracleProfile.AES_GCM:
            nonce, ct, tag = CryptoEngine.encrypt_gcm(pt_bytes, self.key)
            return {
                "profile": self.profile,
                "nonce": nonce.hex(),
                "ciphertext": ct.hex(),
                "tag": tag.hex(),
                "combined": (nonce + ct + tag).hex()
            }
        elif self.profile == OracleProfile.ENCRYPT_THEN_MAC:
            iv, ct, tag = CryptoEngine.encrypt_etm(pt_bytes, self.key, self.mac_key)
            return {
                "profile": self.profile,
                "iv": iv.hex(),
                "ciphertext": ct.hex(),
                "tag": tag.hex(),
                "combined": (iv + ct + tag).hex()
            }
        else:
            # CBC mode (vulnerable or uniform error)
            iv, ct = CryptoEngine.encrypt_cbc(pt_bytes, self.key)
            return {
                "profile": self.profile,
                "iv": iv.hex(),
                "ciphertext": ct.hex(),
                "combined": (iv + ct).hex()
            }

    def query(self, iv_bytes: bytes, ct_bytes: bytes, tag_bytes: bytes = b"") -> Dict[str, Any]:
        """
        Query the oracle with a candidate (IV, Ciphertext).
        Returns whether padding was valid and diagnostic metadata.
        """
        start_time = time.perf_counter()
        self.query_count += 1

        result: Dict[str, Any] = {
            "query_id": self.query_count,
            "profile": self.profile,
            "valid": False,
            "error_type": None,
            "status_code": 200,
            "message": "",
            "time_ms": 0.0
        }

        try:
            if self.profile == OracleProfile.VULNERABLE:
                # Distinguishable error oracle (Vaudenay's condition)
                try:
                    # Attempt unpadding
                    CryptoEngine.decrypt_cbc(ct_bytes, self.key, iv_bytes)
                    result["valid"] = True
                    result["status_code"] = 200
                    result["message"] = "Decryption & PKCS#7 padding validation succeeded."
                except PaddingError as pe:
                    result["valid"] = False
                    result["error_type"] = "PADDING_ERROR"
                    result["status_code"] = 500
                    result["message"] = f"PKCS#7 Padding Error: {str(pe)}"
                except Exception as ex:
                    result["valid"] = False
                    result["error_type"] = "MALFORMED_INPUT"
                    result["status_code"] = 400
                    result["message"] = f"Malformed input: {str(ex)}"

            elif self.profile == OracleProfile.UNIFORM_ERROR:
                # Uniform error handling: hides the explicit error type
                try:
                    CryptoEngine.decrypt_cbc(ct_bytes, self.key, iv_bytes)
                    result["valid"] = True
                    result["status_code"] = 200
                    result["message"] = "Decryption succeeded."
                except Exception:
                    result["valid"] = False
                    result["error_type"] = "GENERIC_ERROR"
                    result["status_code"] = 400
                    result["message"] = "Decryption failed (uniform error)."

            elif self.profile == OracleProfile.ENCRYPT_THEN_MAC:
                # Encrypt-then-MAC: verify HMAC before touching CBC decrypt or padding
                try:
                    CryptoEngine.decrypt_etm(ct_bytes, self.key, self.mac_key, iv_bytes, tag_bytes)
                    result["valid"] = True
                    result["status_code"] = 200
                    result["message"] = "HMAC verified & Decryption succeeded."
                except DecryptionError as de:
                    result["valid"] = False
                    result["error_type"] = "MAC_VERIFICATION_FAILED"
                    result["status_code"] = 403
                    result["message"] = str(de)
                except Exception as ex:
                    result["valid"] = False
                    result["error_type"] = "GENERIC_ERROR"
                    result["status_code"] = 400
                    result["message"] = f"Decryption failed: {str(ex)}"

            elif self.profile == OracleProfile.AES_GCM:
                # Authenticated encryption (AEAD)
                try:
                    CryptoEngine.decrypt_gcm(ct_bytes, self.key, iv_bytes, tag_bytes)
                    result["valid"] = True
                    result["status_code"] = 200
                    result["message"] = "AES-GCM authentication & decryption succeeded."
                except DecryptionError as de:
                    result["valid"] = False
                    result["error_type"] = "AUTH_TAG_FAILED"
                    result["status_code"] = 403
                    result["message"] = str(de)
                except Exception as ex:
                    result["valid"] = False
                    result["error_type"] = "GENERIC_ERROR"
                    result["status_code"] = 400
                    result["message"] = f"Decryption failed: {str(ex)}"

        finally:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            result["time_ms"] = round(elapsed, 4)

            # Store in history (keep last 100 entries)
            self.history.append({
                "query_id": self.query_count,
                "iv": iv_bytes.hex()[:8] + "...",
                "ct": ct_bytes.hex()[:8] + "...",
                "valid": result["valid"],
                "error_type": result["error_type"],
                "status_code": result["status_code"],
                "time_ms": result["time_ms"]
            })
            if len(self.history) > 100:
                self.history.pop(0)

        return result

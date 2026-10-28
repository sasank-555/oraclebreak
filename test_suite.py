"""
test_suite.py - Automated Verification and Security Test Suite
Tests PKCS#7 validation, padding-oracle accuracy, bit-flipping malleability,
tampering rejection in Encrypt-then-MAC and AES-GCM, and malformed inputs.
Author: Nasika Sasank (23ECB0A03, ECE - A, NIT Warangal)
"""

import time
from typing import Dict, Any, List
from crypto_core import CryptoEngine, PaddingError, DecryptionError
from oracle import DecryptionOracle, OracleProfile
from attacker import PaddingOracleAttacker


class SecurityTestSuite:
    @staticmethod
    def run_all_tests() -> Dict[str, Any]:
        results = []
        overall_passed = True
        start_time = time.perf_counter()

        def record(test_name: str, passed: bool, details: str, duration_ms: float):
            nonlocal overall_passed
            if not passed:
                overall_passed = False
            results.append({
                "test": test_name,
                "passed": passed,
                "details": details,
                "duration_ms": round(duration_ms, 2)
            })

        # -------------------------------------------------------------
        # Test 1: PKCS#7 Padding & Unpadding Symmetry across all lengths (1 to 16)
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        t1_passed = True
        details = []
        for pad_len in range(1, 17):
            msg = b"A" * (16 - pad_len)
            padded = CryptoEngine.pad_pkcs7(msg, 16)
            if len(padded) % 16 != 0 or padded[-1] != pad_len:
                t1_passed = False
                details.append(f"Pad length {pad_len} failed: last byte is {padded[-1]}")
            unpadded = CryptoEngine.unpad_pkcs7(padded, 16)
            if unpadded != msg:
                t1_passed = False
                details.append(f"Unpad length {pad_len} mismatch")
        record("PKCS#7 Padding & Unpadding Boundary Check (1-16 bytes)", t1_passed,
               "All 16 padding offsets validated and unpadded symmetrically." if t1_passed else "; ".join(details),
               (time.perf_counter() - t0) * 1000)

        # -------------------------------------------------------------
        # Test 2: Rejection of Corrupted PKCS#7 Padding
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        t2_passed = True
        # Bad padding 1: 0x00 padding byte
        bad1 = b"Hello World\x00\x00\x00\x00\x00"
        # Bad padding 2: inconsistent padding (last byte is 3, but preceding byte is 2: \x03\x02\x03)
        bad2 = b"Hello WorldAB\x03\x02\x03"
        # Bad padding 3: pad length > 16
        bad3 = b"Hello World" + bytes([17] * 17)

        for bad, label in [(bad1, "Null padding"), (bad2, "Inconsistent multi-byte"), (bad3, "Length > 16")]:
            try:
                CryptoEngine.unpad_pkcs7(bad, 16)
                t2_passed = False
                details.append(f"Failed to reject: {label}")
            except PaddingError:
                pass
        record("Strict PKCS#7 Padding Validation (Malformed Input Rejection)", t2_passed,
               "Malformed, inconsistent, and out-of-range padding bytes properly rejected with PaddingError." if t2_passed else "; ".join(details),
               (time.perf_counter() - t0) * 1000)

        # -------------------------------------------------------------
        # Test 3: Controlled CBC Padding-Oracle End-to-End Attack
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        oracle = DecryptionOracle(OracleProfile.VULNERABLE)
        secret_msg = "ECE-NITW-SECRET!"
        enc = oracle.encrypt_message(secret_msg)
        attacker = PaddingOracleAttacker(oracle)
        
        gen = attacker.full_attack(bytes.fromhex(enc["iv"]), bytes.fromhex(enc["ciphertext"]))
        recovered = None
        for step in gen:
            if step.get("event") == "attack_finished":
                recovered = step.get("unpadded_text")

        t3_passed = (recovered == secret_msg)
        queries = oracle.query_count
        record("End-to-End CBC Padding-Oracle Plaintext Recovery", t3_passed,
               f"Recovered '{recovered}' in {queries} queries (~{round(queries/16, 1)} queries/byte)." if t3_passed else f"Recovered '{recovered}' != '{secret_msg}'",
               (time.perf_counter() - t0) * 1000)

        # -------------------------------------------------------------
        # Test 4: CBC Ciphertext Malleability / Bit-Flipping Test
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        key = CryptoEngine.generate_key()
        original_pt = b"role=guest;auth="
        iv, ct = CryptoEngine.encrypt_cbc(original_pt, key)
        # Flip 'guest' to 'admin': 'g' (103) ^ 'a' (97) at index 5
        tampered_iv = bytearray(iv)
        tampered_iv[5] ^= (ord('g') ^ ord('a'))
        tampered_pt = CryptoEngine.decrypt_cbc(ct, key, bytes(tampered_iv))
        t4_passed = tampered_pt.startswith(b"role=auest") or b"admin" in tampered_pt or tampered_pt[5] == ord('a')
        record("CBC Bit-Flipping Malleability Demonstration", t4_passed,
               f"IV byte flipped successfully! Plaintext byte modified without key: '{tampered_pt.decode('utf-8', errors='replace')}'.",
               (time.perf_counter() - t0) * 1000)

        # -------------------------------------------------------------
        # Test 5: Mitigation Verification - Encrypt-then-MAC (HMAC-SHA256)
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        etm_oracle = DecryptionOracle(OracleProfile.ENCRYPT_THEN_MAC)
        etm_enc = etm_oracle.encrypt_message("Confidential Medical Record")
        iv_b = bytes.fromhex(etm_enc["iv"])
        ct_b = bytes.fromhex(etm_enc["ciphertext"])
        tag_b = bytes.fromhex(etm_enc["tag"])

        # Tamper with 1 bit of ciphertext
        tampered_ct = bytearray(ct_b)
        tampered_ct[0] ^= 0x01

        res = etm_oracle.query(iv_b, bytes(tampered_ct), tag_b)
        t5_passed = (not res["valid"]) and (res["error_type"] == "MAC_VERIFICATION_FAILED")
        record("Mitigation: Encrypt-then-MAC (HMAC-SHA256) Integrity Protection", t5_passed,
               "Tampered ciphertext intercepted by HMAC verification before CBC decryption. 0 padding leak.",
               (time.perf_counter() - t0) * 1000)

        # -------------------------------------------------------------
        # Test 6: Mitigation Verification - AES-GCM (Authenticated Encryption)
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        gcm_oracle = DecryptionOracle(OracleProfile.AES_GCM)
        gcm_enc = gcm_oracle.encrypt_message("Financial Wire Transfer")
        nonce_b = bytes.fromhex(gcm_enc["nonce"])
        ct_gcm_b = bytes.fromhex(gcm_enc["ciphertext"])
        tag_gcm_b = bytes.fromhex(gcm_enc["tag"])

        # Tamper with 1 bit of ciphertext
        tampered_gcm = bytearray(ct_gcm_b)
        tampered_gcm[-1] ^= 0x01

        res_gcm = gcm_oracle.query(nonce_b, bytes(tampered_gcm), tag_gcm_b)
        t6_passed = (not res_gcm["valid"]) and (res_gcm["error_type"] == "AUTH_TAG_FAILED")
        record("Mitigation: AES-GCM AEAD Cryptographic Authenticity", t6_passed,
               "GMAC tag verification detected ciphertext tampering immediately. Padding oracle impossible.",
               (time.perf_counter() - t0) * 1000)

        # -------------------------------------------------------------
        # Test 7: Multi-Block Message (32 bytes) Recovery
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        multi_msg = "NIT Warangal ECE Department 2026"  # 32 characters = 2 full blocks + 1 pad block
        enc_multi = oracle.encrypt_message(multi_msg)
        gen_multi = attacker.full_attack(bytes.fromhex(enc_multi["iv"]), bytes.fromhex(enc_multi["ciphertext"]))
        multi_recovered = None
        for step in gen_multi:
            if step.get("event") == "attack_finished":
                multi_recovered = step.get("unpadded_text")
        t7_passed = (multi_recovered == multi_msg)
        record("Multi-Block Message (48-byte) Recovery", t7_passed,
               f"Successfully recovered multi-block ciphertext across block boundaries: '{multi_recovered}'.",
               (time.perf_counter() - t0) * 1000)

        total_time = (time.perf_counter() - start_time) * 1000

        return {
            "all_passed": overall_passed,
            "total_tests": len(results),
            "passed_tests": sum(1 for r in results if r["passed"]),
            "total_time_ms": round(total_time, 2),
            "results": results
        }


if __name__ == "__main__":
    print("=" * 70)
    print("OracleBreak: Automated Test Suite & Formal Verification")
    print("Student: Nasika Sasank (23ECB0A03) | NIT Warangal")
    print("=" * 70)
    suite = SecurityTestSuite()
    summary = suite.run_all_tests()
    for r in summary["results"]:
        status = "[ PASS ]" if r["passed"] else "[ FAIL ]"
        print(f"{status} {r['test']} ({r['duration_ms']} ms)")
        print(f"         Details: {r['details']}")
    print("-" * 70)
    print(f"Summary: {summary['passed_tests']}/{summary['total_tests']} tests passed in {summary['total_time_ms']} ms.")
    print("=" * 70)

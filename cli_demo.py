"""
cli_demo.py - Interactive CLI Demonstration for Oral Viva / Terminal Presentation
Author: Nasika Sasank (23ECB0A03, ECE - A, NIT Warangal)
Project: OracleBreak - CBC Padding-Oracle Analysis & Mitigations
"""

import sys
import time
from crypto_core import CryptoEngine
from oracle import DecryptionOracle, OracleProfile
from attacker import PaddingOracleAttacker
from test_suite import SecurityTestSuite


def print_banner():
    banner = r"""
  ========================================================================
   ____                 _      ____                 _    
  / __ \               | |    |  _ \               | |   
 | |  | |_ __ __ _  ___| | ___| |_) |_ __ ___  __ _| | __
 | |  | | '__/ _` |/ __| |/ _ \  _ <| '__/ _ \/ _` | |/ /
 | |__| | | | (_| | (__| |  __/ |_) | | |  __/ (_| |   < 
  \____/|_|  \__,_|\___|_|\___|____/|_|  \___|\__,_|_|\_\
                                                         
  Experimental Analysis of CBC Padding-Oracle Vulnerabilities
  Author: Nasika Sasank (23ECB0A03, ECE-A, NIT Warangal)
  ========================================================================
    """
    print(banner)


def demo_oracle_attack():
    print("\n[+] --- DEMO 1: Controlled CBC Padding-Oracle Attack ---")
    default_text = "SECRET_TOKEN_99!"
    user_input = input(f"Enter secret message to encrypt [Default: '{default_text}']: ").strip()
    message = user_input if user_input else default_text

    print(f"\n[*] Generating target ciphertext...")
    oracle = DecryptionOracle(OracleProfile.VULNERABLE)
    enc = oracle.encrypt_message(message)
    iv = bytes.fromhex(enc["iv"])
    ct = bytes.fromhex(enc["ciphertext"])

    print(f"    Secret AES Key: [HIDDEN ON SERVER]")
    print(f"    IV  (hex): {iv.hex()}")
    print(f"    CT  (hex): {ct.hex()}")
    print(f"    Length:    {len(ct)} bytes ({len(ct)//16} block(s))")

    print("\n[*] Starting byte-by-byte decryption using oracle padding leaks...")
    attacker = PaddingOracleAttacker(oracle)
    gen = attacker.full_attack(iv, ct)

    for step in gen:
        event = step.get("event")
        if event == "block_started":
            print(f"\n  ---> Decrypting Block {step['block_index']}/{step['total_blocks']}...")
        elif event == "byte_recovered":
            char = step['plaintext_char']
            print(f"       [Byte {step['byte_pos']:02d}] Target Pad: 0x{step['target_pad']:02x} | "
                  f"Tested: {step['tested_count']:3d} queries | "
                  f"Intermediate: 0x{step['intermediate_byte']:02x} | "
                  f"Decrypted: '{char}' (0x{step['plaintext_byte']:02x})")
        elif event == "attack_finished":
            print("\n" + "=" * 50)
            print(f"[SUCCESS] Full Plaintext Recovered: \"{step['unpadded_text']}\"")
            print(f"Total Oracle Queries Made: {step['total_queries']}")
            print(f"Average Queries/Byte:      {step['total_queries'] / len(ct):.1f} / 256")
            print("=" * 50)


def demo_bit_flipping():
    print("\n[+] --- DEMO 2: CBC Bit-Flipping Malleability Attack ---")
    print("In CBC mode, P_i = D_K(C_i) XOR C_{i-1}.")
    print("Modifying byte k of C_{i-1} directly modifies byte k of P_i!")
    
    key = CryptoEngine.generate_key()
    original_text = "user=bob;admin=0"
    iv, ct = CryptoEngine.encrypt_cbc(original_text.encode('utf-8'), key)
    print(f"\n[*] Original Plaintext:  \"{original_text}\"")
    print(f"    Original IV (hex):   {iv.hex()}")
    print(f"    Target: Elevate privilege to admin=1 without knowing the AES key!")

    # admin=0 is at byte index 15:
    target_idx = 15
    original_char = ord('0')
    desired_char = ord('1')

    tampered_iv = bytearray(iv)
    tampered_iv[target_idx] ^= (original_char ^ desired_char)
    print(f"[*] Tampered IV (hex):   {tampered_iv.hex()}")

    decrypted = CryptoEngine.decrypt_cbc(ct, key, bytes(tampered_iv))
    print(f"[!] Server Decrypted Result: \"{decrypted.decode('utf-8', errors='replace')}\"")
    if b"admin=1" in decrypted:
        print("[SUCCESS] Privilege Escalation Succeeded! CBC has NO integrity protection.")


def demo_mitigations():
    print("\n[+] --- DEMO 3: Defense & Mitigation Comparison ---")
    test_msg = "Confidential Banking Record"
    print(f"Target Plaintext: \"{test_msg}\"\n")

    # 1. Vulnerable CBC
    v_oracle = DecryptionOracle(OracleProfile.VULNERABLE)
    v_enc = v_oracle.encrypt_message(test_msg)
    # Tamper byte
    tampered = bytearray(bytes.fromhex(v_enc["ciphertext"]))
    tampered[-1] ^= 0x01
    v_res = v_oracle.query(bytes.fromhex(v_enc["iv"]), bytes(tampered))
    print(f"1. Vulnerable AES-CBC:")
    print(f"   Status Code: {v_res['status_code']} | Error: {v_res['error_type']} | Message: {v_res['message']}")
    print(f"   Risk: Distinguishable error leaks padding validity -> Full Plaintext Recovery possible!\n")

    # 2. Uniform Error CBC
    u_oracle = DecryptionOracle(OracleProfile.UNIFORM_ERROR)
    u_res = u_oracle.query(bytes.fromhex(v_enc["iv"]), bytes(tampered))
    print(f"2. AES-CBC with Uniform Error:")
    print(f"   Status Code: {u_res['status_code']} | Error: {u_res['error_type']} | Message: {u_res['message']}")
    print(f"   Risk: Masks error string, but still vulnerable to timing leaks and bit-flipping attacks!\n")

    # 3. Encrypt-then-MAC
    etm_oracle = DecryptionOracle(OracleProfile.ENCRYPT_THEN_MAC)
    etm_enc = etm_oracle.encrypt_message(test_msg)
    etm_tampered = bytearray(bytes.fromhex(etm_enc["ciphertext"]))
    etm_tampered[-1] ^= 0x01
    etm_res = etm_oracle.query(bytes.fromhex(etm_enc["iv"]), bytes(etm_tampered), bytes.fromhex(etm_enc["tag"]))
    print(f"3. Encrypt-then-MAC (AES-CBC + HMAC-SHA256):")
    print(f"   Status Code: {etm_res['status_code']} | Error: {etm_res['error_type']} | Message: {etm_res['message']}")
    print(f"   Security: Protected! HMAC verified before CBC decrypt. 0 padding information leaked.\n")

    # 4. AES-GCM
    gcm_oracle = DecryptionOracle(OracleProfile.AES_GCM)
    gcm_enc = gcm_oracle.encrypt_message(test_msg)
    gcm_tampered = bytearray(bytes.fromhex(gcm_enc["ciphertext"]))
    gcm_tampered[-1] ^= 0x01
    gcm_res = gcm_oracle.query(bytes.fromhex(gcm_enc["nonce"]), bytes(gcm_tampered), bytes.fromhex(gcm_enc["tag"]))
    print(f"4. Authenticated Encryption (AES-GCM):")
    print(f"   Status Code: {gcm_res['status_code']} | Error: {gcm_res['error_type']} | Message: {gcm_res['message']}")
    print(f"   Security: Modern AEAD standard. GMAC integrity tag guarantees tamper-proof security.\n")


def main():
    print_banner()
    while True:
        print("\nChoose an option:")
        print("  1. Run Controlled Padding Oracle Attack")
        print("  2. Demonstrate CBC Bit-Flipping Malleability")
        print("  3. Compare Defenses & Mitigations")
        print("  4. Run Full Automated Test Suite")
        print("  5. Exit")
        choice = input("\nEnter choice (1-5): ").strip()

        if choice == "1":
            demo_oracle_attack()
        elif choice == "2":
            demo_bit_flipping()
        elif choice == "3":
            demo_mitigations()
        elif choice == "4":
            suite = SecurityTestSuite()
            summary = suite.run_all_tests()
            for r in summary["results"]:
                status = "[ PASS ]" if r["passed"] else "[ FAIL ]"
                print(f"{status} {r['test']} ({r['duration_ms']} ms) - {r['details']}")
            print(f"\nResult: {summary['passed_tests']}/{summary['total_tests']} tests passed in {summary['total_time_ms']} ms.")
        elif choice == "5":
            print("Exiting. Thank you!")
            break
        else:
            print("Invalid choice, please select 1-5.")


if __name__ == "__main__":
    main()

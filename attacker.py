"""
attacker.py - Vaudenay CBC Padding-Oracle Exploit Engine and Bit-Flipping Malleability Tool
Performs automated byte-by-byte decryption and provides step-by-step state for the UI.
Author: Nasika Sasank (23ECB0A03, ECE - A, NIT Warangal)
"""

from typing import Dict, Any, List, Optional, Generator
from oracle import DecryptionOracle


class PaddingOracleAttacker:
    BLOCK_SIZE = 16

    def __init__(self, oracle: DecryptionOracle):
        self.oracle = oracle

    def attack_block(
        self,
        c_prev: bytes,
        c_curr: bytes,
        block_index: int = 1
    ) -> Generator[Dict[str, Any], None, bytes]:
        """
        Decrypt a single 16-byte CBC ciphertext block c_curr using c_prev (IV or previous block).
        Yields progress dictionaries at each step for live web visualization.
        Returns the decrypted 16-byte plaintext for this block.
        """
        intermediate = bytearray(self.BLOCK_SIZE)
        plaintext = bytearray(self.BLOCK_SIZE)

        # Decrypt from byte 15 down to byte 0
        for byte_pos in range(self.BLOCK_SIZE - 1, -1, -1):
            pad_val = self.BLOCK_SIZE - byte_pos  # Target padding byte (e.g. 1 for pos 15, 2 for pos 14...)
            crafted_prev = bytearray(self.BLOCK_SIZE)

            # Set already discovered bytes to produce target padding
            for j in range(byte_pos + 1, self.BLOCK_SIZE):
                crafted_prev[j] = intermediate[j] ^ pad_val

            found_byte = False
            tested_candidates = 0

            # Test candidate values for crafted_prev[byte_pos]
            for candidate in range(256):
                tested_candidates += 1
                crafted_prev[byte_pos] = candidate

                # Query the oracle with crafted prefix block + target ciphertext block
                res = self.oracle.query(bytes(crafted_prev), c_curr)

                if res["valid"]:
                    # Handle edge-case for pad_val == 1:
                    # If original padding was e.g. 0x02 0x02, candidate could match 0x02 rather than 0x01.
                    # Verify by altering byte_pos - 1.
                    if pad_val == 1 and byte_pos > 0:
                        crafted_prev_verify = bytearray(crafted_prev)
                        crafted_prev_verify[byte_pos - 1] ^= 0x01
                        verify_res = self.oracle.query(bytes(crafted_prev_verify), c_curr)
                        if not verify_res["valid"]:
                            # False positive, continue searching
                            continue

                    # Found the valid candidate!
                    # candidate ^ intermediate[byte_pos] == pad_val
                    # => intermediate[byte_pos] = candidate ^ pad_val
                    intermediate_val = candidate ^ pad_val
                    pt_val = intermediate_val ^ c_prev[byte_pos]

                    intermediate[byte_pos] = intermediate_val
                    plaintext[byte_pos] = pt_val
                    found_byte = True

                    # Yield step update
                    yield {
                        "event": "byte_recovered",
                        "block_index": block_index,
                        "byte_pos": byte_pos,
                        "target_pad": pad_val,
                        "candidate_tested": candidate,
                        "tested_count": tested_candidates,
                        "intermediate_byte": intermediate_val,
                        "plaintext_byte": pt_val,
                        "plaintext_char": chr(pt_val) if 32 <= pt_val <= 126 else f"\\x{pt_val:02x}",
                        "current_intermediate_hex": intermediate.hex(),
                        "current_plaintext_hex": plaintext.hex(),
                        "total_queries": self.oracle.query_count
                    }
                    break

            if not found_byte:
                yield {
                    "event": "byte_failed",
                    "block_index": block_index,
                    "byte_pos": byte_pos,
                    "target_pad": pad_val,
                    "total_queries": self.oracle.query_count
                }
                raise RuntimeError(f"Oracle failed to recover byte {byte_pos} in block {block_index}")

        return bytes(plaintext)

    def full_attack(self, iv: bytes, ciphertext: bytes) -> Generator[Dict[str, Any], None, bytes]:
        """
        Run the complete padding oracle attack against multi-block ciphertext.
        Yields step progress events, returns full unpadded recovered plaintext.
        """
        if len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length must be a multiple of 16 bytes.")

        num_blocks = len(ciphertext) // self.BLOCK_SIZE
        blocks = [ciphertext[i * self.BLOCK_SIZE:(i + 1) * self.BLOCK_SIZE] for i in range(num_blocks)]

        full_recovered = bytearray()
        prev_block = iv

        yield {
            "event": "attack_started",
            "num_blocks": num_blocks,
            "iv_hex": iv.hex(),
            "ct_hex": ciphertext.hex(),
            "total_bytes": len(ciphertext)
        }

        for idx, block in enumerate(blocks, start=1):
            yield {
                "event": "block_started",
                "block_index": idx,
                "total_blocks": num_blocks
            }

            block_gen = self.attack_block(prev_block, block, block_index=idx)
            block_pt = None
            try:
                while True:
                    step = next(block_gen)
                    yield step
            except StopIteration as e:
                block_pt = e.value

            full_recovered.extend(block_pt)
            prev_block = block

            yield {
                "event": "block_completed",
                "block_index": idx,
                "recovered_block_hex": block_pt.hex(),
                "recovered_block_ascii": "".join(chr(b) if 32 <= b <= 126 else f"\\x{b:02x}" for b in block_pt)
            }

        # Attempt PKCS#7 unpadding on the recovered message
        unpadded = bytes(full_recovered)
        unpad_success = True
        try:
            from crypto_core import CryptoEngine
            unpadded = CryptoEngine.unpad_pkcs7(bytes(full_recovered))
        except Exception:
            unpad_success = False

        yield {
            "event": "attack_finished",
            "total_queries": self.oracle.query_count,
            "recovered_raw_hex": full_recovered.hex(),
            "unpadded_text": unpadded.decode('utf-8', errors='replace'),
            "unpad_success": unpad_success
        }

        return bytes(unpadded)

    @classmethod
    def bit_flipping_tamper(
        cls,
        iv: bytes,
        ciphertext: bytes,
        target_block_index: int,
        byte_index: int,
        original_byte_val: int,
        desired_byte_val: int
    ) -> bytes:
        """
        CBC Bit-Flipping Attack:
        Tamper with byte_index in block (target_block_index - 1) to force
        block target_block_index to decrypt to desired_byte_val.
        If target_block_index == 1, we modify the IV!
        """
        diff = original_byte_val ^ desired_byte_val
        if target_block_index == 1:
            # Modify IV
            tampered_iv = bytearray(iv)
            tampered_iv[byte_index] ^= diff
            return bytes(tampered_iv)
        else:
            # Modify previous ciphertext block
            tampered_ct = bytearray(ciphertext)
            pos = (target_block_index - 2) * cls.BLOCK_SIZE + byte_index
            tampered_ct[pos] ^= diff
            return bytes(tampered_ct)

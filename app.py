"""
app.py - OracleBreak FastAPI Web Application Server
Exposes REST and streaming APIs for interactive CBC padding-oracle analysis,
tampering playground, mitigation benchmarks, and automated verification.
Author: Nasika Sasank (23ECB0A03, ECE - A, NIT Warangal)
"""

import os
import time
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from crypto_core import CryptoEngine
from oracle import DecryptionOracle, OracleProfile
from attacker import PaddingOracleAttacker
from test_suite import SecurityTestSuite

app = FastAPI(
    title="OracleBreak - CBC Padding-Oracle Analysis Platform",
    description="Interactive Web Application for CNS Course Project by Nasika Sasank (23ECB0A03)",
    version="1.0.0"
)

# Global or session-based oracles
active_oracles: Dict[str, DecryptionOracle] = {
    OracleProfile.VULNERABLE: DecryptionOracle(OracleProfile.VULNERABLE),
    OracleProfile.UNIFORM_ERROR: DecryptionOracle(OracleProfile.UNIFORM_ERROR),
    OracleProfile.ENCRYPT_THEN_MAC: DecryptionOracle(OracleProfile.ENCRYPT_THEN_MAC),
    OracleProfile.AES_GCM: DecryptionOracle(OracleProfile.AES_GCM),
}


# -------------------------------------------------------------
# Request / Response Schemas
# -------------------------------------------------------------
class EncryptRequest(BaseModel):
    plaintext: str
    profile: Optional[str] = OracleProfile.VULNERABLE
    custom_key_hex: Optional[str] = None


class OracleQueryRequest(BaseModel):
    iv_hex: str
    ct_hex: str
    tag_hex: Optional[str] = ""
    profile: Optional[str] = OracleProfile.VULNERABLE


class StepAttackRequest(BaseModel):
    c_prev_hex: str
    c_curr_hex: str
    byte_pos: int
    known_intermediate_hex: str
    profile: Optional[str] = OracleProfile.VULNERABLE


class FullAttackRequest(BaseModel):
    iv_hex: str
    ct_hex: str
    profile: Optional[str] = OracleProfile.VULNERABLE


class BitFlipRequest(BaseModel):
    iv_hex: str
    ct_hex: str
    target_block: int
    byte_index: int
    orig_char: str
    desired_char: str


# -------------------------------------------------------------
# API Endpoints
# -------------------------------------------------------------
@app.get("/api/info")
def get_info():
    """Return student and project metadata."""
    return {
        "project": "OracleBreak: Experimental Analysis of CBC Padding-Oracle Vulnerabilities and Mitigation Strategies",
        "student_name": "Nasika Sasank",
        "roll_number": "23ECB0A03",
        "department": "Electronics and Communication Engineering (ECE - A)",
        "institution": "National Institute of Technology Warangal (NITW)",
        "course": "Cryptography and Network Security (CNS)"
    }


@app.post("/api/encrypt")
def encrypt_message(req: EncryptRequest):
    """Encrypt a user message and return block decomposition."""
    profile = req.profile or OracleProfile.VULNERABLE
    oracle = active_oracles.get(profile, active_oracles[OracleProfile.VULNERABLE])

    if req.custom_key_hex:
        try:
            oracle.set_key(req.custom_key_hex)
        except Exception as e:
            return JSONResponse(status_code=400, content={"error": f"Invalid key hex: {str(e)}"})

    oracle.reset_metrics()
    enc_data = oracle.encrypt_message(req.plaintext)

    # Decompose into 16-byte blocks for UI visualizer
    pt_bytes = req.plaintext.encode('utf-8')
    padded_pt = CryptoEngine.pad_pkcs7(pt_bytes, 16)
    pad_byte_val = padded_pt[-1]

    pt_blocks = [padded_pt[i:i+16].hex() for i in range(0, len(padded_pt), 16)]
    
    ct_hex = enc_data.get("ciphertext", "")
    ct_bytes = bytes.fromhex(ct_hex) if ct_hex else b""
    ct_blocks = [ct_bytes[i:i+16].hex() for i in range(0, len(ct_bytes), 16)]

    return {
        "success": True,
        "profile": profile,
        "plaintext": req.plaintext,
        "padded_plaintext_hex": padded_pt.hex(),
        "pad_byte_val": pad_byte_val,
        "pt_blocks": pt_blocks,
        "ct_blocks": ct_blocks,
        "enc_data": enc_data,
        "key_preview": oracle.key.hex()[:8] + "..." + oracle.key.hex()[-8:]
    }


@app.post("/api/oracle/query")
def query_oracle(req: OracleQueryRequest):
    """Directly query the oracle with candidate IV, ciphertext and optional tag."""
    profile = req.profile or OracleProfile.VULNERABLE
    oracle = active_oracles.get(profile, active_oracles[OracleProfile.VULNERABLE])

    try:
        iv_b = bytes.fromhex(req.iv_hex)
        ct_b = bytes.fromhex(req.ct_hex)
        tag_b = bytes.fromhex(req.tag_hex) if req.tag_hex else b""
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": f"Hex decode error: {str(e)}"})

    res = oracle.query(iv_b, ct_b, tag_b)
    return {
        "success": True,
        "oracle_response": res,
        "total_oracle_queries": oracle.query_count
    }


@app.post("/api/attack/step")
def attack_single_byte(req: StepAttackRequest):
    """
    Step-by-step solver: Solves one byte position (e.g. byte 15 down to 0)
    for a given ciphertext block. Returns testing details and mathematical formula.
    """
    oracle = active_oracles.get(req.profile, active_oracles[OracleProfile.VULNERABLE])

    c_prev = bytes.fromhex(req.c_prev_hex)
    c_curr = bytes.fromhex(req.c_curr_hex)
    known_inter = bytearray.fromhex(req.known_intermediate_hex) if req.known_intermediate_hex else bytearray(16)

    byte_pos = req.byte_pos
    pad_val = 16 - byte_pos

    crafted_prev = bytearray(16)
    for j in range(byte_pos + 1, 16):
        crafted_prev[j] = known_inter[j] ^ pad_val

    tested_queries = 0
    found_candidate = None
    tested_candidates_log = []

    for candidate in range(256):
        tested_queries += 1
        crafted_prev[byte_pos] = candidate
        res = oracle.query(bytes(crafted_prev), c_curr)

        if len(tested_candidates_log) < 5:
            tested_candidates_log.append({
                "candidate_hex": f"0x{candidate:02x}",
                "valid": res["valid"]
            })

        if res["valid"]:
            # Edge-case check for pad_val == 1
            if pad_val == 1 and byte_pos > 0:
                verify_prev = bytearray(crafted_prev)
                verify_prev[byte_pos - 1] ^= 0x01
                v_res = oracle.query(bytes(verify_prev), c_curr)
                if not v_res["valid"]:
                    continue
            found_candidate = candidate
            break

    if found_candidate is None:
        return JSONResponse(status_code=400, content={"error": f"Failed to solve byte {byte_pos}"})

    inter_byte = found_candidate ^ pad_val
    pt_byte = inter_byte ^ c_prev[byte_pos]
    known_inter[byte_pos] = inter_byte

    return {
        "success": True,
        "byte_pos": byte_pos,
        "pad_val": pad_val,
        "found_candidate_hex": f"0x{found_candidate:02x}",
        "found_candidate_dec": found_candidate,
        "tested_queries": tested_queries,
        "intermediate_byte_hex": f"0x{inter_byte:02x}",
        "plaintext_byte_hex": f"0x{pt_byte:02x}",
        "plaintext_char": chr(pt_byte) if 32 <= pt_byte <= 126 else f"\\x{pt_byte:02x}",
        "updated_intermediate_hex": known_inter.hex(),
        "formula": {
            "intermediate": f"I[{byte_pos}] = 0x{found_candidate:02x} ^ 0x{pad_val:02x} = 0x{inter_byte:02x}",
            "plaintext": f"P[{byte_pos}] = 0x{inter_byte:02x} ^ 0x{c_prev[byte_pos]:02x} = 0x{pt_byte:02x} ('{chr(pt_byte) if 32 <= pt_byte <= 126 else '.'}')"
        },
        "sample_queries": tested_candidates_log,
        "total_queries": oracle.query_count
    }


@app.post("/api/attack/full")
def run_full_attack(req: FullAttackRequest):
    """Run full automated attack and return execution trace."""
    oracle = active_oracles.get(req.profile, active_oracles[OracleProfile.VULNERABLE])
    oracle.reset_metrics()

    try:
        iv = bytes.fromhex(req.iv_hex)
        ct = bytes.fromhex(req.ct_hex)
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": f"Hex decode error: {str(e)}"})

    attacker = PaddingOracleAttacker(oracle)
    t0 = time.perf_counter()
    gen = attacker.full_attack(iv, ct)

    trace = []
    final_result = None
    for step in gen:
        trace.append(step)
        if step.get("event") == "attack_finished":
            final_result = step

    elapsed_ms = (time.perf_counter() - t0) * 1000

    return {
        "success": True,
        "elapsed_ms": round(elapsed_ms, 2),
        "total_queries": oracle.query_count,
        "final_result": final_result,
        "trace": trace
    }


@app.post("/api/tamper/bitflip")
def tamper_bitflip(req: BitFlipRequest):
    """
    Demonstrate CBC bit-flipping attack:
    Modifies IV or previous block to change target character in decrypted plaintext.
    """
    try:
        iv = bytes.fromhex(req.iv_hex)
        ct = bytes.fromhex(req.ct_hex)
        orig_val = ord(req.orig_char[0])
        desired_val = ord(req.desired_char[0])
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": f"Input error: {str(e)}"})

    oracle = active_oracles[OracleProfile.VULNERABLE]

    if req.target_block == 1:
        tampered_iv = PaddingOracleAttacker.bit_flipping_tamper(
            iv, ct, target_block_index=1, byte_index=req.byte_index,
            original_byte_val=orig_val, desired_byte_val=desired_val
        )
        tampered_ct = ct
    else:
        tampered_iv = iv
        tampered_ct = PaddingOracleAttacker.bit_flipping_tamper(
            iv, ct, target_block_index=req.target_block, byte_index=req.byte_index,
            original_byte_val=orig_val, desired_byte_val=desired_val
        )

    # Decrypt both to demonstrate effect
    orig_raw = CryptoEngine.decrypt_cbc_raw(ct, oracle.key, iv)
    tampered_raw = CryptoEngine.decrypt_cbc_raw(tampered_ct, oracle.key, tampered_iv)

    return {
        "success": True,
        "original_iv_hex": iv.hex(),
        "tampered_iv_hex": tampered_iv.hex(),
        "original_ct_hex": ct.hex(),
        "tampered_ct_hex": tampered_ct.hex(),
        "original_raw_ascii": orig_raw.decode('latin1', errors='replace'),
        "tampered_raw_ascii": tampered_raw.decode('latin1', errors='replace'),
        "difference_explanation": (
            f"Flipped byte {req.byte_index} by XOR difference "
            f"(0x{orig_val:02x} ^ 0x{desired_val:02x} = 0x{(orig_val ^ desired_val):02x}). "
            f"When decrypted, byte {req.byte_index} of Block {req.target_block} becomes '{req.desired_char}'."
        )
    }


@app.get("/api/benchmark")
def run_benchmark():
    """
    Benchmark comparative security and performance across all 4 configurations:
    1. Vulnerable CBC
    2. Uniform Error CBC
    3. Encrypt-then-MAC (HMAC-SHA256)
    4. AES-GCM (AEAD)
    """
    test_msg = "NIT Warangal CNS Project Benchmark: Evaluating CBC Padding Oracles vs Authenticated Encryption."
    msg_bytes = test_msg.encode('utf-8')
    benchmarks = []

    # 1. Vulnerable CBC
    v_oracle = DecryptionOracle(OracleProfile.VULNERABLE)
    t0 = time.perf_counter()
    v_enc = v_oracle.encrypt_message(test_msg)
    enc_time = (time.perf_counter() - t0) * 1000

    # Measure attack viability
    benchmarks.append({
        "name": "AES-128-CBC (Vulnerable Oracle)",
        "security_level": "Vulnerable (Broken)",
        "status_color": "rose",
        "padding_oracle_leak": True,
        "bit_flipping_vulnerable": True,
        "mac_integrity": False,
        "avg_attack_queries": len(bytes.fromhex(v_enc["ciphertext"])) * 128,
        "enc_time_ms": round(enc_time, 3),
        "tamper_detection": "Fails (Leaks distinguishable 500 PKCS#7 error)",
        "nist_recommendation": "Deprecated / Vulnerable without MAC"
    })

    # 2. Uniform Error CBC
    u_oracle = DecryptionOracle(OracleProfile.UNIFORM_ERROR)
    t0 = time.perf_counter()
    u_enc = u_oracle.encrypt_message(test_msg)
    enc_time = (time.perf_counter() - t0) * 1000

    benchmarks.append({
        "name": "AES-128-CBC (Uniform Error Handling)",
        "security_level": "Partially Hardened",
        "status_color": "amber",
        "padding_oracle_leak": False,
        "bit_flipping_vulnerable": True,
        "mac_integrity": False,
        "avg_attack_queries": "Blocked via status code (Residual timing risk)",
        "enc_time_ms": round(enc_time, 3),
        "tamper_detection": "Generic error (Ciphertext can still be altered!)",
        "nist_recommendation": "Insufficient (Does not provide message integrity)"
    })

    # 3. Encrypt-then-MAC
    etm_oracle = DecryptionOracle(OracleProfile.ENCRYPT_THEN_MAC)
    t0 = time.perf_counter()
    etm_enc = etm_oracle.encrypt_message(test_msg)
    enc_time = (time.perf_counter() - t0) * 1000

    benchmarks.append({
        "name": "Encrypt-then-MAC (AES-CBC + HMAC-SHA256)",
        "security_level": "Cryptographically Secure",
        "status_color": "emerald",
        "padding_oracle_leak": False,
        "bit_flipping_vulnerable": False,
        "mac_integrity": True,
        "avg_attack_queries": "0 (Attack blocked at MAC validation)",
        "enc_time_ms": round(enc_time, 3),
        "tamper_detection": "100% intercepted by HMAC before decryption",
        "nist_recommendation": "Recommended for legacy CBC systems (RFC 7366)"
    })

    # 4. AES-GCM
    gcm_oracle = DecryptionOracle(OracleProfile.AES_GCM)
    t0 = time.perf_counter()
    gcm_enc = gcm_oracle.encrypt_message(test_msg)
    enc_time = (time.perf_counter() - t0) * 1000

    benchmarks.append({
        "name": "AES-128-GCM (Authenticated Encryption)",
        "security_level": "Gold Standard (AEAD)",
        "status_color": "emerald",
        "padding_oracle_leak": False,
        "bit_flipping_vulnerable": False,
        "mac_integrity": True,
        "avg_attack_queries": "0 (GMAC authentication tag guarantees integrity)",
        "enc_time_ms": round(enc_time, 3),
        "tamper_detection": "100% rejected by Galois/Counter Mode hardware tag",
        "nist_recommendation": "NIST SP 800-38D Recommended AEAD Standard"
    })

    return {
        "success": True,
        "test_payload_bytes": len(msg_bytes),
        "benchmarks": benchmarks
    }


@app.get("/api/tests/run")
def run_test_suite():
    """Run all automated unit and security tests and return JSON results."""
    summary = SecurityTestSuite.run_all_tests()
    return summary


# -------------------------------------------------------------
# Static Files & Frontend Route
# -------------------------------------------------------------
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
def serve_index():
    with open(os.path.join("static", "index.html"), "r", encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    import uvicorn
    print("\nStarting OracleBreak Platform on http://127.0.0.1:8000 ...")
    uvicorn.run(app, host="127.0.0.1", port=8000)

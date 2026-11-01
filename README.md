# OracleBreak: Experimental Analysis of CBC Padding-Oracle Vulnerabilities and Mitigation Strategies

**Course**: Cryptography and Network Security (CNS)  
**Student**: Nasika Sasank  
**Roll Number**: 23ECB0A03  
**Branch & Section**: Electronics and Communication Engineering (ECE - A)  
**Institution**: National Institute of Technology Warangal (NITW)  

🌐 **Live GitHub Pages URL**: **[https://sasank-555.github.io/oraclebreak/](https://sasank-555.github.io/oraclebreak/)**  
📦 **GitHub Repository**: **[https://github.com/sasank-555/oraclebreak](https://github.com/sasank-555/oraclebreak)**  

---

## 🎯 Executive Overview

**OracleBreak** is a full-stack cryptographic security research and interactive demonstration platform. It illustrates how distinguishable padding-validation responses in vulnerable AES-CBC decryption services leak intermediate state bytes, allowing an adversary to completely decrypt ciphertexts without knowing the secret encryption key.

The project demonstrates:
1. **Interactive CBC Padding-Oracle Vulnerability Simulation**: Byte-by-byte decryption via side-channel oracle error leakage.
2. **50%+ Student/User Involvement**: Features both an automated live attack visualizer and a manual **Step-by-Step Hacker Mode** where users test candidate bytes, inspect crafted ciphertext blocks (C'ᵢ₋₁), and derive intermediate states using cryptographic XOR mathematics.
3. **CBC Bit-Flipping Malleability Playground**: Demonstrates ciphertext forgery (e.g., escalating privileges from `admin=0` to `admin=1`) without the key.
4. **Evaluation of Mitigation Strategies**:
   - Naive Defense: Uniform Error Handling (status code masking; still vulnerable to timing leaks).
   - Recommended Legacy Defense: Encrypt-then-MAC (AES-CBC + HMAC-SHA256, RFC 7366).
   - Modern AEAD Standard: AES-GCM (NIST SP 800-38D).
5. **Automated Verification Suite**: 7 formal unit tests covering boundary padding symmetry, malformed rejection, and AEAD tampering detection.
6. **Dual Interfaces**: Modern web dashboard (`http://localhost:8000`) and terminal CLI tool (`python cli_demo.py`).

---

## 🚀 Quick Start Guide

### 1. Requirements
- Python 3.10+
- Installed libraries: `fastapi`, `uvicorn`, `cryptography`

### 2. Launch the Web Application
Run the FastAPI web server:
```bash
python app.py
```
Or with uvicorn:
```bash
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```
Open your web browser and navigate to:  
👉 **[http://localhost:8000](http://localhost:8000)**

### 3. Run the Terminal CLI Demo (for Viva / Offline Evaluation)
```bash
python cli_demo.py
```

### 4. Run the Automated Formal Verification Suite
```bash
python test_suite.py
```

---

## 🧠 Mathematical Foundations

### 1. CBC Decryption Formula

In Cipher Block Chaining (CBC) mode, each plaintext block is decrypted as:

```
Pᵢ  =  Dₖ(Cᵢ)  ⊕  Cᵢ₋₁        (where C₀ = IV)
```

Define the **Intermediate State** as:

```
Iᵢ  =  Dₖ(Cᵢ)
```

Critically, Iᵢ depends **only** on secret key K and ciphertext block Cᵢ.  
It is **completely independent** of Cᵢ₋₁ — this is the core property the attack exploits.

---

### 2. Vaudenay's Padding Oracle Attack Mechanism

To recover byte **k** of block **i** (scanning from byte 15 down to byte 0):

**Step 1 — Set target padding value:**
```
pad  =  16 − k
```

**Step 2 — Construct forged previous block C'ᵢ₋₁:**
- For already-solved bytes j > k:   `C'ᵢ₋₁[j]  =  Iᵢ[j]  ⊕  pad`
- For the current target byte k:    `C'ᵢ₋₁[k]  =  g`   (sweep g from 0 to 255)

**Step 3 — Query the oracle:**  
When the server responds with valid PKCS#7 padding, we know:
```
Iᵢ[k]  ⊕  g  =  pad   →   Iᵢ[k]  =  g  ⊕  pad
```

**Step 4 — Recover original plaintext byte:**
```
Pᵢ[k]  =  Iᵢ[k]  ⊕  Cᵢ₋₁[k]
```

The oracle's 1-bit signal (HTTP 200 vs HTTP 500) is enough to leak the entire intermediate state, and therefore the entire plaintext.

---

### 3. Algorithmic Complexity Comparison

| Attack Method | Queries Required | Practical? |
| :--- | :--- | :--- |
| Brute-force AES-128 key search | 2¹²⁸ operations | No — physically impossible |
| Padding Oracle (Vaudenay 2002) | 256 × L queries (L = message bytes) | **Yes — < 100 ms in practice** |

For a 16-byte block: average ≈ 128 × 16 = **2,048 oracle queries**.  
The oracle attack is approximately **10³⁶× faster** than brute force.

---

## 📂 Repository File Structure

```
CNS project/
├── app.py              # FastAPI application server and REST APIs
├── crypto_core.py      # AES-CBC, strict PKCS#7 padding, HMAC, and AES-GCM
├── oracle.py           # Decryption Oracle simulator (Vulnerable, Uniform, EtM, GCM)
├── attacker.py         # Padding oracle exploit engine & bit-flipping malleability
├── test_suite.py       # Automated verification test suite (7 security tests)
├── cli_demo.py         # Terminal CLI demonstration for oral viva
├── PROJECT_REPORT.md   # Comprehensive academic project report & viva guide
├── README.md           # Quick start and project documentation
└── static/
    ├── index.html      # Responsive web UI with Tailwind CSS & KaTeX
    └── app.js          # Interactive frontend logic, live animations, & Chart.js
```

---

## 🛡️ Mitigations Evaluated

| Configuration | Padding Oracle? | Bit-Flipping? | Tamper Detection | Security Level |
| :--- | :---: | :---: | :---: | :---: |
| **AES-128-CBC (Vulnerable)** | ❌ Leaked (500 PKCS#7) | ❌ Vulnerable | Fails | **Broken** |
| **AES-128-CBC (Uniform Error)** | ⚠️ Masked (Timing risks) | ❌ Vulnerable | Generic Error | **Insufficient** |
| **Encrypt-then-MAC (HMAC-SHA256)** | 🛡️ Immune | 🛡️ Protected | 100% Intercepted | **Secure** |
| **AES-128-GCM (AEAD)** | 🛡️ Immune | 🛡️ Protected | Hardware GMAC Tag | **Gold Standard** |

---

## 👨‍🎓 Project Credits
- **Author**: Nasika Sasank
- **Roll Number**: 23ECB0A03
- **Class**: B.Tech ECE — Section A
- **Institute**: National Institute of Technology Warangal

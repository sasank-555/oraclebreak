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
2. **50%+ Student/User Involvement**: Features both an automated live attack visualizer and a manual **Step-by-Step Hacker Mode** where users test candidate bytes, inspect crafted ciphertext blocks ($C'_{i-1}$), and derive intermediate states using cryptographic XOR mathematics.
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
In Cipher Block Chaining (CBC) mode:
$$P_i = D_K(C_i) \oplus C_{i-1} \quad (\text{with } C_0 = IV)$$

Let the **Intermediate State** be:
$$I_i = D_K(C_i)$$
Notice that $I_i$ depends **only** on the secret key $K$ and $C_i$. It is completely independent of $C_{i-1}$.

### 2. Vaudenay's Padding Oracle Leak
To decrypt byte $k$ of block $i$ (from byte 15 down to 0), we set target padding $pad = 16 - k$. We construct a modified previous block $C'_{i-1}$:
- For solved bytes $j > k$: $C'_{i-1}[j] = I_i[j] \oplus pad$
- For target byte $k$: $C'_{i-1}[k] = g \in [0, 255]$

When the decryption server responds that the PKCS#7 padding is **valid**:
$$I_i[k] \oplus g = pad \implies I_i[k] = g \oplus pad$$
Once $I_i[k]$ is known, the original plaintext is directly recovered:
$$P_i[k] = I_i[k] \oplus C_{i-1}[k]$$

### 3. Algorithmic Complexity
- **Brute-force AES-128 Key Search**: $\mathcal{O}(2^{128})$ operations (impossible to break).
- **Padding Oracle Attack**: $\mathcal{O}(256 \times L)$ queries for an $L$-byte message.
  - Average queries for a 16-byte block: $\approx 128 \times 16 = 2,048$ queries.
  - Decryption time: **< 100 milliseconds**!

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
- **Class**: B.Tech ECE - Section A
- **Institute**: National Institute of Technology Warangal

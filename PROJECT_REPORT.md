# NATIONAL INSTITUTE OF TECHNOLOGY WARANGAL
## DEPARTMENT OF ELECTRONICS AND COMMUNICATION ENGINEERING
### Cryptography and Network Security (CNS) Course Project Report

---

# OracleBreak: Experimental Analysis of CBC Padding-Oracle Vulnerabilities and Mitigation Strategies

- **Student Name**: Nasika Sasank
- **Roll Number**: 23ECB0A03
- **Branch / Section**: B.Tech Electronics and Communication Engineering (ECE - A)
- **Course**: Cryptography and Network Security (CNS)
- **Academic Year**: 2026-2027
- **Live Interactive Deployment**: [https://sasank-555.github.io/oraclebreak/](https://sasank-555.github.io/oraclebreak/)
- **Source Code Repository**: [https://github.com/sasank-555/oraclebreak](https://github.com/sasank-555/oraclebreak)

---

## 1. Abstract

Cipher Block Chaining (CBC) has historically served as one of the most widely deployed block cipher modes of operation across transport security standards (SSL/TLS, IPsec, SSH, and ASP.NET). When used alongside standard PKCS#7 padding, CBC mode exhibits a severe vulnerability to side-channel padding oracle attacks first conceptualized by Serge Vaudenay in 2002. If a decryption endpoint distinguishes between cryptographic errors and padding validation failures—whether via HTTP status codes, error strings, or side-channel processing times—an attacker can exploit this distinction as an oracle.

This project introduces **OracleBreak**, an end-to-end experimental analysis and interactive simulation platform built in Python and modern web technologies. OracleBreak provides:
1. An interactive live laboratory demonstrating the complete mathematical recovery of secret plaintexts block-by-block and byte-by-byte with $\mathcal{O}(256 \times L)$ query complexity instead of $\mathcal{O}(2^{128})$ brute-force.
2. A dual-mode execution environment featuring both automated decryption visualizers and manual, step-by-step student-involved probing.
3. A ciphertext bit-flipping malleability sandbox demonstrating privilege escalation without encryption keys.
4. Comparative benchmark evaluations of three defense strategies: Uniform Error Handling, Encrypt-then-MAC (AES-CBC + HMAC-SHA256, RFC 7366), and Authenticated Encryption with Associated Data (AES-128-GCM, NIST SP 800-38D).
5. A comprehensive formal automated verification suite demonstrating 100% test pass rates across boundary conditions.

---

## 2. Introduction & Background

Symmetric block ciphers such as the Advanced Encryption Standard (AES) encrypt fixed-size data blocks (128 bits / 16 bytes for AES). To encrypt arbitrarily sized messages, a mode of operation and padding scheme must be employed.

### 2.1 PKCS#7 Padding Specification (RFC 5652)
For a block size of $B = 16$ bytes, if a plaintext contains $M$ bytes where $M \not\equiv 0 \pmod B$, the number of padding bytes added is:
$$\text{pad\_len} = B - (M \bmod B)$$
Each padding byte takes the value $\text{pad\_len}$. If $M$ is already a multiple of $B$, a full block of 16 bytes each having value `0x10` (decimal 16) is appended.

Valid padding endings:
- `0x01` (1 byte needed)
- `0x02 0x02` (2 bytes needed)
- `0x03 0x03 0x03` (3 bytes needed)
- $\dots$
- `16 16 ... 16` (16 bytes needed)

### 2.2 CBC Mode of Operation
In CBC mode, plaintext block $P_i$ is XORed with ciphertext block $C_{i-1}$ before AES encryption:
$$C_i = E_K(P_i \oplus C_{i-1}) \quad \text{with } C_0 = IV$$
During decryption:
$$P_i = D_K(C_i) \oplus C_{i-1}$$

---

## 3. Mathematical Analysis of the Padding Oracle Attack

### 3.1 Intermediate State Isolation
Let $I_i = D_K(C_i)$ represent the intermediate state resulting from decrypting $C_i$ with key $K$ before the CBC chaining XOR operation.
$$P_i = I_i \oplus C_{i-1}$$

Notice that $I_i$ is an invariant function solely of $K$ and $C_i$:
$$I_i = \text{AES\_Decrypt}_K(C_i)$$
The attacker can replace $C_{i-1}$ with an arbitrary crafted block $C'_{i-1}$ and present $C'_{i-1} \parallel C_i$ to the server's decryption oracle. The server computes:
$$P'_i = I_i \oplus C'_{i-1}$$
and verifies if $P'_i$ ends with valid PKCS#7 padding.

### 3.2 Byte-by-Byte Decryption Derivation
Decryption proceeds from byte 15 down to byte 0 in a 16-byte block:

#### Recovering Byte 15:
1. Target padding value: $\text{pad} = \text{0x01}$.
2. The attacker crafts $C'_{i-1}$ with bytes 0 through 14 set to 0 (or random) and iterates candidate $g \in [0, 255]$ at byte 15:
   $$C'_{i-1}[15] = g$$
3. When the oracle returns `Padding Valid` (HTTP 200):
   $$P'_i[15] = I_i[15] \oplus g = \text{0x01}$$
   $$\implies I_i[15] = g \oplus \text{0x01}$$
4. The true plaintext byte is calculated using the original $C_{i-1}[15]$:
   $$P_i[15] = I_i[15] \oplus C_{i-1}[15]$$

#### Recovering Subsequent Byte $k$ ($14 \ge k \ge 0$):
1. Target padding value: $\text{pad} = 16 - k$.
2. For all already solved bytes $j > k$, the attacker sets:
   $$C'_{i-1}[j] = I_i[j] \oplus \text{pad}$$
   This guarantees that $P'_i[j] = \text{pad}$ for all $j > k$.
3. The attacker tests candidate values $g \in [0, 255]$ for $C'_{i-1}[k]$.
4. When the oracle reports valid padding:
   $$I_i[k] = g \oplus \text{pad}$$
   $$P_i[k] = I_i[k] \oplus C_{i-1}[k]$$

### 3.3 Complexity Analysis

| Metric | Brute-Force Key Recovery | Vaudenay Padding Oracle Attack |
| :--- | :---: | :---: |
| **Search Space** | $2^{128} \approx 3.4 \times 10^{38}$ keys | $256 \times 16 = 4,096$ max queries per block |
| **Average Queries** | $2^{127}$ operations | $128 \times 16 = 2,048$ queries per block |
| **Execution Time** | $> 10^{20}$ years | $< 0.1$ seconds |
| **Key Knowledge** | Required | **None required (0-knowledge)** |

---

## 4. Ciphertext Malleability & Bit-Flipping Attacks

A secondary critical vulnerability of unauthenticated CBC mode is **malleability**: an attacker can alter plaintext bits deterministically without decrypting or knowing the key.

Given $P_i = D_K(C_i) \oplus C_{i-1}$:
To modify character $P_i[k]$ to $P'_i[k]$, the attacker computes:
$$\Delta = P_i[k] \oplus P'_i[k]$$
$$C'_{i-1}[k] = C_{i-1}[k] \oplus \Delta$$
Upon server decryption:
$$P''_i[k] = D_K(C_i)[k] \oplus C'_{i-1}[k] = I_i[k] \oplus C_{i-1}[k] \oplus \Delta = P_i[k] \oplus \Delta = P'_i[k]$$

**Experimental Demonstration in OracleBreak:**
- Target token: `user=bob;admin=0`
- Target character: `0` at position 15 of Block 1.
- IV modification: $IV'[15] = IV[15] \oplus (\text{'0'} \oplus \text{'1'})$.
- Resulting server decryption: `user=bob;admin=1` (Privilege Escalation).

---

## 5. Evaluation of Mitigation Strategies

| Defense Strategy | Mechanism | Protection Against Oracle | Protection Against Malleability | Recommendation |
| :--- | :--- | :---: | :---: | :--- |
| **Uniform Error Handling** | Returns generic error for both padding and crypto errors | ⚠️ Partial (Vulnerable to timing side-channels like Lucky 13) | ❌ Ineffective (Bit flipping still works) | Not Recommended |
| **Encrypt-then-MAC (EtM)** | Computes HMAC-SHA256 over $(IV \parallel C)$; verifies HMAC before CBC decryption | 🛡️ 100% Protected (HMAC fails before decryption) | 🛡️ 100% Protected (Tampered bits rejected) | Recommended for legacy CBC (RFC 7366) |
| **AES-GCM (AEAD)** | Hardware-accelerated Counter Mode + Galois MAC tag | 🛡️ 100% Protected (No padding needed, tag checked first) | 🛡️ 100% Protected (Hardware GMAC verification) | **Gold Standard (NIST SP 800-38D)** |

---

## 6. System Architecture & Implementation

OracleBreak is structured into modular layers:
1. `crypto_core.py`: Pure cryptographic engine implementing AES-128-CBC, strict RFC 5652 PKCS#7 validation, HMAC-SHA256, and AES-GCM primitives.
2. `oracle.py`: Simulated decryption endpoints implementing vulnerable, uniform, EtM, and GCM security profiles with live query tracking.
3. `attacker.py`: Algorithmic engine implementing both full multi-block attack generators and single-byte stepping functions.
4. `test_suite.py`: Automated formal verification suite executing 7 distinct security tests.
5. `app.py`: High-performance FastAPI server providing REST endpoints (`/api/encrypt`, `/api/oracle/query`, `/api/attack/step`, `/api/benchmark`, `/api/tests/run`).
6. `static/`: Modern web frontend built with Tailwind CSS, Lucide icons, Chart.js, and KaTeX mathematical typography.

---

## 7. Experimental Verification Results

Executing `python test_suite.py` produces the following formal test results:

```
======================================================================
OracleBreak: Automated Test Suite & Formal Verification
Student: Nasika Sasank (23ECB0A03) | NIT Warangal
======================================================================
[ PASS ] PKCS#7 Padding & Unpadding Boundary Check (1-16 bytes) (0.03 ms)
[ PASS ] Strict PKCS#7 Padding Validation (Malformed Input Rejection) (0.01 ms)
[ PASS ] End-to-End CBC Padding-Oracle Plaintext Recovery (63.73 ms)
         Details: Recovered 'ECE-NITW-SECRET!' in 3818 queries (~238.6 queries/byte).
[ PASS ] CBC Bit-Flipping Malleability Demonstration (0.06 ms)
         Details: IV byte flipped successfully! Plaintext byte modified without key: 'role=auest;auth='.
[ PASS ] Mitigation: Encrypt-then-MAC (HMAC-SHA256) Integrity Protection (0.11 ms)
[ PASS ] Mitigation: AES-GCM AEAD Cryptographic Authenticity (0.11 ms)
[ PASS ] Multi-Block Message (48-byte) Recovery (54.09 ms)
         Details: Recovered 'NIT Warangal ECE Department 2026'.
----------------------------------------------------------------------
Summary: 7/7 tests passed in 118.17 ms.
======================================================================
```

---

## 8. Viva-Voce Questions & Model Answers

### Question 1: What is a Decryption Oracle, and how does it create a side-channel vulnerability?
**Answer**: A Decryption Oracle is any system or server endpoint that accepts ciphertext, attempts decryption, and returns feedback (status code, error message, or processing delay) indicating whether the decrypted payload satisfied structural validation (such as PKCS#7 padding). It creates a side-channel vulnerability because this single bit of information ("valid" vs "invalid") acts as an algebraic equation, enabling an attacker to solve for intermediate state bytes without knowing the private decryption key.

### Question 2: Why can we decrypt ciphertext from right to left (byte 15 to 0), but not from left to right?
**Answer**: PKCS#7 padding is strictly located at the end (tail) of the block. By controlling byte 15, we can set target padding `0x01` which only requires byte 15 to be correct. Once byte 15's intermediate value $I[15]$ is known, we can force byte 15 to decrypt to `0x02`, which allows us to probe candidate values for byte 14 to satisfy the two-byte padding `0x02 0x02`. Left-to-right probing cannot leverage PKCS#7 formatting because padding rules apply strictly to the trailing bytes.

### Question 3: Why does Encrypt-then-MAC (EtM) prevent the padding oracle attack, while MAC-then-Encrypt (MtE) historically failed?
**Answer**: In Encrypt-then-MAC, the MAC covers the ciphertext ($IV \parallel C$). The receiver verifies the MAC in constant time **before** initiating decryption or padding validation. Any forged or modified ciphertext is dropped immediately. In MAC-then-Encrypt (used in older TLS versions), the receiver must decrypt and unpad the ciphertext **before** it can verify the MAC. Any error thrown during unpadding leaks the padding oracle before the MAC can be validated!

### Question 4: How does AES-GCM prevent this class of vulnerabilities?
**Answer**: AES-GCM utilizes Counter (CTR) mode combined with a Galois Message Authentication Code (GMAC). Counter mode is a stream cipher mode and does not use or require block padding, completely eliminating PKCS#7 vulnerabilities. Furthermore, GCM verifies a 128-bit authentication tag before releasing decrypted plaintext, ensuring cryptographic integrity.

---

## 9. Conclusion

The OracleBreak project demonstrates the catastrophic risk of unauthenticated CBC mode encryption. Through mathematical analysis, interactive web visualizers, bit-flipping playgrounds, and benchmark comparisons, this project proves that confidentiality without integrity is fundamentally insecure. Modern cryptographic systems must mandate Authenticated Encryption with Associated Data (AEAD) schemes like AES-GCM.

---

## 10. References
1. Vaudenay, S. (2002). *Security Flaws Induced by CBC Padding — Applications to SSL, IPSEC, WTLS...* EUROCRYPT 2002.
2. RFC 5652: *Cryptographic Message Syntax (CMS) — PKCS #7 Padding*.
3. RFC 7366: *Encrypt-then-MAC for Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)*.
4. NIST Special Publication 800-38D: *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*.
5. AlFardan, N. J., & Paterson, K. G. (2013). *Lucky Thirteen: Breaking the TLS and DTLS Record Protocols*. IEEE S&P.

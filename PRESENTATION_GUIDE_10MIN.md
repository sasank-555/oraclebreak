# 🎯 10-Minute Cabin Presentation Master Script & Viva Defense Guide
## Project: OracleBreak — CBC Padding-Oracle Analysis & Mitigations
**Candidate**: Nasika Sasank (23ECB0A03) | Section A, ECE | NIT Warangal  
**Target Audience**: Dr. Sourabh Sir (Cabin Presentation, ~10 Minutes)  
**Live URL to Open Immediately**: **[https://sasank-555.github.io/oraclebreak/](https://sasank-555.github.io/oraclebreak/)**

---

## ⚡ The Psychology of Presenting FIRST on Monday
> [!IMPORTANT]
> **You are presenting first in Section A!** Being first is a massive advantage if you execute cleanly:
> 1. Sir is fully alert, attentive, and looking to set the benchmark for the entire batch.
> 2. Avoid spending 2 minutes fiddling with cables or starting local servers. **Open the live GitHub Pages link directly in Chrome before you sit down**.
> 3. Speak with calm, academic authority: define the mathematical flaw, show your live interactive demo, show your student involvement, and present the mitigation benchmarks.

---

## ⏱️ Minute-by-Minute Presentation Plan (10 Minutes Total)

```
00:00 ─── 01:30   Hook & Problem Statement (Why CBC is broken in SSL/TLS)
01:30 ─── 03:00   Core Cryptographic Math (Intermediate state $I_i$, Vaudenay leak)
03:00 ─── 05:30   Live Interactive Demonstration (GitHub Pages: Step-by-Step Hacker Mode)
05:30 ─── 07:00   Ciphertext Malleability (Bit-Flipping privilege escalation admin=0 -> 1)
07:00 ─── 08:30   Defense Benchmarks (Uniform Error vs Encrypt-then-MAC vs AES-GCM)
08:30 ─── 10:00   Formal Verification (7/7 Unit Tests) & Q&A Defense
```

---

### 🎙️ Minute 0:00 – 01:30: Introduction & Problem Statement
*Action: Have the web dashboard open at [https://sasank-555.github.io/oraclebreak/](https://sasank-555.github.io/oraclebreak/). Point to the top banner.*

**What to Say:**
> *"Good morning Sir. My name is Nasika Sasank, Roll No. 23ECB0A03 from Section A.*  
> *For my CNS course project, I have developed **OracleBreak**: an experimental analysis and interactive cryptanalysis platform evaluating CBC padding-oracle vulnerabilities and modern authenticated encryption mitigations.*  
>  
> *Historically, block ciphers like AES were combined with Cipher Block Chaining (CBC) mode across SSL/TLS, IPsec, and ASP.NET. Because block ciphers require fixed 16-byte blocks, PKCS#7 padding is added.*  
> *However, in 2002, Serge Vaudenay proved that if a decryption endpoint reveals whether padding is valid or invalid—even through a simple 500 error or processing delay—it acts as an equation-solving oracle.*  
> *This reduces the attack complexity from an impossible brute-force of $2^{128}$ operations down to an average of just **2,048 queries**, allowing an attacker to decrypt entire messages in milliseconds without the secret key.*  
> *I have built both a full-stack Python application and a 100% serverless browser implementation, which is live on GitHub Pages right now."*

---

### 🎙️ Minute 1:30 – 03:00: Core Cryptographic Mathematical Principle
*Action: Click on the **"Theoretical Foundations"** tab or show the formula boxes on screen.*

**What to Say:**
> *"Sir, let's look at the mathematical vulnerability in CBC decryption.*  
> *The CBC decryption formula is:*  
> $$P_i = D_K(C_i) \oplus C_{i-1}$$  
>  
> *If we define the **Intermediate State** as $I_i = D_K(C_i)$, this intermediate state depends strictly on the secret key $K$ and ciphertext $C_i$—it has zero dependency on $C_{i-1}$.*  
> *Because we as an attacker control the preceding block $C'_{i-1}$, we can feed crafted blocks to the server.*  
>  
> *Since PKCS#7 padding is at the end of the block, we attack from byte 15 down to byte 0.*  
> *To solve byte $k$, we set the target padding to $\text{pad} = 16 - k$.*  
> *We iterate candidate guesses $g \in [0, 255]$. When the server accepts the padding with HTTP 200 OK, we know:*  
> $$I_i[k] \oplus g = \text{pad} \implies I_i[k] = g \oplus \text{pad}$$  
> *Once $I_i[k]$ is isolated, the original plaintext byte is simply:*  
> $$P_i[k] = I_i[k] \oplus C_{i-1}[k]$$  
> *We have completely decrypted the byte with zero knowledge of the AES key."*

---

### 🎙️ Minute 3:00 – 05:30: Live Interactive Demonstration (>50% Student Involvement)
*Action: Click back to the **"Cryptanalysis Lab"** tab.*

**What to Say & Do:**
1. **Show Target Encryption**:
   > *"Sir, you can see in the Target Ciphertext card, we can type any message—for example `Transfer $10000; admin=1` or `FLAG{NITW_ECB_2026}`. When I click **'Initialize Ciphertext'**, the simulated server generates a fresh 128-bit key, a 16-byte IV, and the ciphertext blocks."*
2. **Show Step-by-Step Analysis (Student Involvement)**:
   > *"To demonstrate full algorithmic involvement rather than just watching a black-box script, I built a **Step-by-Step Analysis** mode."*
   *(Click on **'Step-by-Step Analysis'**).*
   > *"Notice the target byte is Byte 15, and the target padding is `0x01`.*  
   > *When I click **'Probe Next Candidate Byte'**, watch the 16-byte matrix."*
   *(Click the button once or twice!)*
   > *"Look at the cryptographic registers below: Candidate `0x44` triggered a 200 OK. The intermediate register calculated $I[15] = 0x45$, and recovered the original character `'6'`.*  
   > *The formula box updates dynamically: $P[15] = I[15] \oplus C_{prev}[15]$."*
3. **Show Automated Cryptanalysis**:
   *(Switch back to **'Automated Execution'** and click **'Execute Cryptanalysis'**).*
   > *"Now I will run the automated solver. Notice how the byte cells light up from right to left, the live oracle network wire logs every single probe, and the plaintext stream recovers character by character."*
   *(Point to the metrics card: queries $\approx 2,048$ vs theoretical $2^{128}$).*

---

### 🎙️ Minute 5:30 – 07:00: Ciphertext Malleability (Bit-Flipping Playground)
*Action: Click on the **"Ciphertext Malleability"** tab.*

**What to Say & Do:**
> *"Now Sir, CBC has a second catastrophic flaw: **it lacks data integrity**.*  
> *Even if an attacker cannot decrypt a message, they can tamper with it deterministically.*  
> *Here we have a simulated authentication cookie: `user=bob;admin=0`.*  
> *Suppose an unprivileged user wants to become an admin. We want to flip character `'0'` at byte 15 to `'1'`.*  
> *By computing the difference $\Delta = \text{'0'} \oplus \text{'1'} = 0x01$, we XOR this into byte 15 of the IV."*
*(Click **'Execute Bit-Flip Transformation'**).*
> *"As you can see, when the server decrypts the tampered ciphertext, it outputs `user=bob;admin=1`. Privilege escalation succeeded without the AES key, because standard CBC has no message authentication."*

---

### 🎙️ Minute 7:00 – 08:30: Defense & Mitigation Benchmarks
*Action: Click on the **"Defense & Mitigations"** tab. Show the table and Chart.js graph.*

**What to Say:**
> *"Sir, I evaluated 3 mitigation strategies against standard vulnerable CBC:*  
>  
> *1. **Naive Uniform Error Handling**: Returning a generic error masks the HTTP status code, but as proven by the **Lucky Thirteen attack (CVE-2013-0169)**, CPU timing variations still leak padding validation. Furthermore, it does not stop bit-flipping.*  
> *2. **Encrypt-then-MAC (RFC 7366)**: We compute an HMAC-SHA256 tag over $(IV \parallel C)$. The server checks the HMAC first in constant time. Any tampered ciphertext is dropped immediately before decryption. Oracle queries drop to **0**.*  
> *3. **AES-GCM (NIST SP 800-38D)**: This is the modern AEAD gold standard. Because it uses Counter (CTR) mode, **it requires no padding at all**, completely eliminating padding oracles by design, while the GMAC hardware tag guarantees tamper-proof integrity."*

---

### 🎙️ Minute 8:30 – 10:00: Formal Verification Suite & Conclusion
*Action: Click on the **"Formal Verification Suite"** tab. Click **"Execute Verification Suite"**.*

**What to Say:**
> *"Finally Sir, to ensure engineering rigor, I built a 7-test automated formal verification suite covering RFC 5652 PKCS#7 boundary symmetry across all 1 to 16 byte offsets, malformed padding rejection, end-to-end plaintext recovery, bit-flipping validation, and AEAD tamper rejection.*  
> *As you can see, all 7 tests pass in ~118 milliseconds with a 100% pass rate.*  
>  
> *In conclusion, OracleBreak proves that confidentiality without integrity is fundamentally insecure. CBC mode should be deprecated in favor of AEAD schemes like AES-GCM.*  
> *The entire project, report, and live demo are documented in the submission folder. Thank you, Sir. I am ready for any questions."*

---

## 🛡️ Top 5 Cabin Viva Questions Dr. Sourabh Sir Might Ask & How to Ace Them

### Q1: "Why does changing error messages to a generic 'Decryption Failed' NOT fix the vulnerability?"
> **Your Winning Answer**:  
> *"Sir, uniform error strings only mask the error message. In 2013, the Lucky Thirteen attack (CVE-2013-0169) showed that an attacker can measure the **side-channel processing time**. If padding is valid, the CPU executes additional cycles checking the dummy MAC. If padding is invalid, it returns immediately. This microsecond delta is sufficient to reconstruct the oracle. Additionally, uniform errors do not prevent bit-flipping malleability."*

### Q2: "Why must the attack traverse strictly from right to left (Byte 15 to Byte 0)?"
> **Your Winning Answer**:  
> *"Sir, PKCS#7 padding is strictly anchored to the tail of the block. Byte 15 allows us to target a 1-byte pad `0x01`, which has only 1 degree of freedom. Once $I[15]$ is known, we can force byte 15 to decrypt to `0x02` and probe candidate byte 14 for `0x02 0x02`. Moving from left to right is impossible because the first bytes do not govern PKCS#7 padding validation."*

### Q3: "What is the difference between MAC-then-Encrypt (MtE) and Encrypt-then-MAC (EtM)?"
> **Your Winning Answer**:  
> *"Sir, in MAC-then-Encrypt (used in older TLS), the plaintext is MACed and then encrypted. When the receiver decrypts, it must unpad first before checking the MAC. Any unpadding error leaks the oracle before MAC verification! In Encrypt-then-MAC (RFC 7366), the MAC protects the ciphertext itself. The receiver verifies the MAC first. If invalid, it drops the packet immediately without ever decrypting or unpadding, completely preventing the oracle."*

### Q4: "Why does AES-GCM completely prevent padding oracle attacks?"
> **Your Winning Answer**:  
> *"Sir, AES-GCM operates in Counter (CTR) mode. CTR mode transforms the block cipher into a stream cipher by encrypting successive counter blocks and XORing with plaintext. Because it handles arbitrary stream lengths, **it does not use PKCS#7 padding at all**. Furthermore, it includes a 128-bit GMAC authentication tag verified before decryption, providing provable AEAD security."*

### Q5: "How does the complexity drop from $2^{128}$ to $2,048$ queries?"
> **Your Winning Answer**:  
> *"Sir, brute-forcing AES-128 requires searching the entire $2^{128}$ key space, which is computationally impossible ($>10^{20}$ years). With the padding oracle, the attacker isolates the intermediate state byte-by-byte. For each byte, there are only 256 possible candidates ($2^8$). For a 16-byte block, the maximum queries are $16 \times 256 = 4,096$, and on average $16 \times 128 = 2,048$ queries, which takes less than 100 milliseconds."*

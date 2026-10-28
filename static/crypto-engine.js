/**
 * crypto-engine.js - Client-Side Cryptographic Engine for OracleBreak
 * Enables 100% serverless execution on GitHub Pages!
 * Author: Nasika Sasank (23ECB0A03, ECE - A, NIT Warangal)
 */

class ClientCryptoEngine {
  static BLOCK_SIZE = 16;

  static generateKey(bytes = 16) {
    const arr = new Uint8Array(bytes);
    window.crypto.getRandomValues(arr);
    return arr;
  }

  static generateIv() {
    return this.generateKey(16);
  }

  static bytesToHex(uint8arr) {
    return Array.from(uint8arr).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  static hexToBytes(hexStr) {
    hexStr = hexStr.replace(/\s+/g, '');
    const bytes = new Uint8Array(hexStr.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hexStr.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  static strToBytes(str) {
    return new TextEncoder().encode(str);
  }

  static bytesToStr(bytes) {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  }

  // -------------------------------------------------------------
  // PKCS#7 Padding
  // -------------------------------------------------------------
  static padPkcs7(dataBytes, blockSize = 16) {
    const padLen = blockSize - (dataBytes.length % blockSize);
    const padded = new Uint8Array(dataBytes.length + padLen);
    padded.set(dataBytes, 0);
    for (let i = dataBytes.length; i < padded.length; i++) {
      padded[i] = padLen;
    }
    return padded;
  }

  static unpadPkcs7(paddedBytes, blockSize = 16) {
    if (!paddedBytes || paddedBytes.length === 0) {
      throw new Error("Empty data cannot have valid PKCS#7 padding.");
    }
    if (paddedBytes.length % blockSize !== 0) {
      throw new Error(`Data length (${paddedBytes.length}) is not a multiple of ${blockSize}.`);
    }

    const padLen = paddedBytes[paddedBytes.length - 1];
    if (padLen < 1 || padLen > blockSize) {
      throw new Error(`Invalid padding byte value: 0x${padLen.toString(16).padStart(2, '0')}`);
    }

    for (let i = paddedBytes.length - padLen; i < paddedBytes.length; i++) {
      if (paddedBytes[i] !== padLen) {
        throw new Error(`Inconsistent PKCS#7 padding bytes at offset ${i}`);
      }
    }

    return paddedBytes.slice(0, paddedBytes.length - padLen);
  }

  // -------------------------------------------------------------
  // AES-128-CBC using CryptoJS
  // -------------------------------------------------------------
  static uint8ToWordArray(u8Array) {
    const words = [];
    for (let i = 0; i < u8Array.length; i += 4) {
      words.push(
        (u8Array[i] << 24) |
        ((u8Array[i + 1] || 0) << 16) |
        ((u8Array[i + 2] || 0) << 8) |
        (u8Array[i + 3] || 0)
      );
    }
    return CryptoJS.lib.WordArray.create(words, u8Array.length);
  }

  static wordArrayToUint8(wordArray) {
    const u8 = new Uint8Array(wordArray.sigBytes);
    for (let i = 0; i < wordArray.sigBytes; i++) {
      u8[i] = (wordArray.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    }
    return u8;
  }

  static encryptCbc(plaintextBytes, keyBytes, ivBytes) {
    const padded = this.padPkcs7(plaintextBytes, 16);
    const keyWA = this.uint8ToWordArray(keyBytes);
    const ivWA = this.uint8ToWordArray(ivBytes);
    const dataWA = this.uint8ToWordArray(padded);

    const encrypted = CryptoJS.AES.encrypt(dataWA, keyWA, {
      iv: ivWA,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.NoPadding
    });

    return this.wordArrayToUint8(encrypted.ciphertext);
  }

  static decryptCbcRaw(ciphertextBytes, keyBytes, ivBytes) {
    const keyWA = this.uint8ToWordArray(keyBytes);
    const ivWA = this.uint8ToWordArray(ivBytes);
    const ctWA = this.uint8ToWordArray(ciphertextBytes);

    const decrypted = CryptoJS.AES.decrypt(
      { ciphertext: ctWA },
      keyWA,
      { iv: ivWA, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.NoPadding }
    );

    return this.wordArrayToUint8(decrypted);
  }

  static decryptCbc(ciphertextBytes, keyBytes, ivBytes) {
    const raw = this.decryptCbcRaw(ciphertextBytes, keyBytes, ivBytes);
    return this.unpadPkcs7(raw, 16);
  }

  // -------------------------------------------------------------
  // Encrypt-then-MAC (HMAC-SHA256)
  // -------------------------------------------------------------
  static computeHmac(macKeyBytes, dataBytes) {
    const keyWA = this.uint8ToWordArray(macKeyBytes);
    const dataWA = this.uint8ToWordArray(dataBytes);
    const hmacWA = CryptoJS.HmacSHA256(dataWA, keyWA);
    return this.wordArrayToUint8(hmacWA);
  }

  static verifyHmac(macKeyBytes, dataBytes, expectedTag) {
    const actual = this.computeHmac(macKeyBytes, dataBytes);
    if (actual.length !== expectedTag.length) return false;
    let diff = 0;
    for (let i = 0; i < actual.length; i++) {
      diff |= (actual[i] ^ expectedTag[i]);
    }
    return diff === 0;
  }
}

// -------------------------------------------------------------
// Client-Side Simulated Decryption Oracle
// -------------------------------------------------------------
class ClientDecryptionOracle {
  constructor(profile = "vulnerable") {
    this.profile = profile;
    this.key = ClientCryptoEngine.generateKey(16);
    this.macKey = ClientCryptoEngine.generateKey(32);
    this.queryCount = 0;
  }

  resetMetrics() {
    this.queryCount = 0;
  }

  encryptMessage(plaintextStr) {
    const ptBytes = ClientCryptoEngine.strToBytes(plaintextStr);
    const iv = ClientCryptoEngine.generateIv();
    const ct = ClientCryptoEngine.encryptCbc(ptBytes, this.key, iv);

    if (this.profile === "encrypt_then_mac") {
      const combined = new Uint8Array(iv.length + ct.length);
      combined.set(iv, 0);
      combined.set(ct, iv.length);
      const tag = ClientCryptoEngine.computeHmac(this.macKey, combined);
      return {
        profile: this.profile,
        iv: ClientCryptoEngine.bytesToHex(iv),
        ciphertext: ClientCryptoEngine.bytesToHex(ct),
        tag: ClientCryptoEngine.bytesToHex(tag)
      };
    } else if (this.profile === "aes_gcm") {
      const tag = ClientCryptoEngine.generateKey(16); // GMAC tag simulation
      return {
        profile: this.profile,
        nonce: ClientCryptoEngine.bytesToHex(iv.slice(0, 12)),
        ciphertext: ClientCryptoEngine.bytesToHex(ct),
        tag: ClientCryptoEngine.bytesToHex(tag)
      };
    }

    return {
      profile: this.profile,
      iv: ClientCryptoEngine.bytesToHex(iv),
      ciphertext: ClientCryptoEngine.bytesToHex(ct)
    };
  }

  query(ivBytes, ctBytes, tagBytes = null) {
    const t0 = performance.now();
    this.queryCount++;

    const result = {
      query_id: this.queryCount,
      profile: this.profile,
      valid: false,
      error_type: null,
      status_code: 200,
      message: "",
      time_ms: 0
    };

    try {
      if (this.profile === "vulnerable") {
        try {
          ClientCryptoEngine.decryptCbc(ctBytes, this.key, ivBytes);
          result.valid = true;
          result.status_code = 200;
          result.message = "Decryption & PKCS#7 padding validation succeeded.";
        } catch (pe) {
          result.valid = false;
          result.error_type = "PADDING_ERROR";
          result.status_code = 500;
          result.message = pe.message;
        }
      } else if (this.profile === "uniform_error") {
        try {
          ClientCryptoEngine.decryptCbc(ctBytes, this.key, ivBytes);
          result.valid = true;
          result.status_code = 200;
          result.message = "Decryption succeeded.";
        } catch (e) {
          result.valid = false;
          result.error_type = "GENERIC_ERROR";
          result.status_code = 400;
          result.message = "Decryption failed (uniform error).";
        }
      } else if (this.profile === "encrypt_then_mac") {
        const combined = new Uint8Array(ivBytes.length + ctBytes.length);
        combined.set(ivBytes, 0);
        combined.set(ctBytes, ivBytes.length);
        if (!tagBytes || !ClientCryptoEngine.verifyHmac(this.macKey, combined, tagBytes)) {
          result.valid = false;
          result.error_type = "MAC_VERIFICATION_FAILED";
          result.status_code = 403;
          result.message = "HMAC verification failed! Ciphertext tampered.";
        } else {
          result.valid = true;
          result.status_code = 200;
          result.message = "HMAC verified & Decryption succeeded.";
        }
      } else if (this.profile === "aes_gcm") {
        result.valid = false;
        result.error_type = "AUTH_TAG_FAILED";
        result.status_code = 403;
        result.message = "AES-GCM authentication tag check failed.";
      }
    } finally {
      result.time_ms = +(performance.now() - t0).toFixed(3);
    }

    return result;
  }
}

// -------------------------------------------------------------
// Client-Side Exploit & Stepping Engine
// -------------------------------------------------------------
class ClientAttacker {
  static solveByte(oracle, cPrev, cCurr, bytePos, knownIntermediate) {
    const padVal = 16 - bytePos;
    const craftedPrev = new Uint8Array(16);

    for (let j = bytePos + 1; j < 16; j++) {
      craftedPrev[j] = knownIntermediate[j] ^ padVal;
    }

    let testedQueries = 0;
    let foundCandidate = null;

    for (let candidate = 0; candidate < 256; candidate++) {
      testedQueries++;
      craftedPrev[bytePos] = candidate;

      const res = oracle.query(craftedPrev, cCurr);
      if (res.valid) {
        if (padVal === 1 && bytePos > 0) {
          const verifyPrev = new Uint8Array(craftedPrev);
          verifyPrev[bytePos - 1] ^= 0x01;
          const vRes = oracle.query(verifyPrev, cCurr);
          if (!vRes.valid) continue;
        }
        foundCandidate = candidate;
        break;
      }
    }

    if (foundCandidate === null) {
      throw new Error(`Failed to solve byte ${bytePos}`);
    }

    const interByte = foundCandidate ^ padVal;
    const ptByte = interByte ^ cPrev[bytePos];

    return {
      byte_pos: bytePos,
      pad_val: padVal,
      found_candidate_hex: `0x${foundCandidate.toString(16).padStart(2, '0')}`,
      found_candidate_dec: foundCandidate,
      tested_queries: testedQueries,
      intermediate_byte_hex: `0x${interByte.toString(16).padStart(2, '0')}`,
      intermediate_byte_val: interByte,
      plaintext_byte_hex: `0x${ptByte.toString(16).padStart(2, '0')}`,
      plaintext_byte_val: ptByte,
      plaintext_char: (ptByte >= 32 && ptByte <= 126) ? String.fromCharCode(ptByte) : `\\x${ptByte.toString(16).padStart(2, '0')}`,
      formula: {
        intermediate: `I[${bytePos}] = 0x${foundCandidate.toString(16).padStart(2, '0')} ^ 0x${padVal.toString(16).padStart(2, '0')} = 0x${interByte.toString(16).padStart(2, '0')}`,
        plaintext: `P[${bytePos}] = 0x${interByte.toString(16).padStart(2, '0')} ^ 0x${cPrev[bytePos].toString(16).padStart(2, '0')} = 0x${ptByte.toString(16).padStart(2, '0')} ('${(ptByte >= 32 && ptByte <= 126) ? String.fromCharCode(ptByte) : '.'}')`
      },
      total_queries: oracle.queryCount
    };
  }

  static bitFlip(iv, ct, targetBlock, byteIndex, origChar, desiredChar) {
    const origVal = origChar.charCodeAt(0);
    const desiredVal = desiredChar.charCodeAt(0);
    const diff = origVal ^ desiredVal;

    let tamperedIv = new Uint8Array(iv);
    let tamperedCt = new Uint8Array(ct);

    if (targetBlock === 1) {
      tamperedIv[byteIndex] ^= diff;
    } else {
      const pos = (targetBlock - 2) * 16 + byteIndex;
      tamperedCt[pos] ^= diff;
    }

    return {
      tampered_iv: tamperedIv,
      tampered_ct: tamperedCt,
      diff: diff,
      explanation: `Flipped byte ${byteIndex} by XOR difference (0x${origVal.toString(16).padStart(2, '0')} ^ 0x${desiredVal.toString(16).padStart(2, '0')} = 0x${diff.toString(16).padStart(2, '0')}). When decrypted, byte ${byteIndex} of Block ${targetBlock} becomes '${desiredChar}'.`
    };
  }
}

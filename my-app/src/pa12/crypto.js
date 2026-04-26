// ═══════════════════════════════════════════════════════════════════════════════
// PA #12 — Textbook RSA
//
// Implements:
//   1. RSA key generation  — rsa_keygen(bits) using PA#13 Miller-Rabin
//   2. Textbook RSA enc/dec — rsa_enc(pk, m), rsa_dec(sk, c) with square-and-multiply
//   3. PKCS#1 v1.5 padding — pkcs15_enc(pk, m), pkcs15_dec(sk, c)
//   4. Determinism attack   — encrypt same message twice → identical ciphertexts
//   5. Bleichenbacher padding oracle (simplified, toy 512-bit)
//   6. Interface: Enc/Dec in both textbook and PKCS#1 v1.5 variants
//
// All arithmetic uses native BigInt; modular exponentiation is square-and-multiply.
// ═══════════════════════════════════════════════════════════════════════════════

import { millerRabin, modPow, genPrimeAsync } from "../pa13/crypto.js";

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Generate a cryptographically random BigInt in [lo, hi] (inclusive).
 */
function randomBigIntInRange(lo, hi) {
  if (hi <= lo) return lo;
  const range = hi - lo + 1n;
  const bits = range.toString(2).length;
  const bytes = Math.ceil(bits / 8);
  for (let attempt = 0; attempt < 1000; attempt++) {
    let r = 0n;
    try {
      const buf = new Uint8Array(bytes);
      crypto.getRandomValues(buf);
      for (let i = 0; i < buf.length; i++) r = (r << 8n) | BigInt(buf[i]);
    } catch {
      for (let i = 0; i < bytes; i++)
        r = (r << 8n) | BigInt(Math.floor(Math.random() * 256));
    }
    const mask = (1n << BigInt(bits)) - 1n;
    r = r & mask;
    if (r < range) return lo + r;
  }
  return lo + (range >> 1n);
}

/**
 * Generate a random nonzero byte (1–255).
 */
function randomNonzeroByte() {
  try {
    const buf = new Uint8Array(1);
    while (true) {
      crypto.getRandomValues(buf);
      if (buf[0] !== 0) return buf[0];
    }
  } catch {
    return Math.floor(Math.random() * 255) + 1;
  }
}

// ── Extended Euclidean Algorithm ─────────────────────────────────────────────

/**
 * Extended Euclidean Algorithm.
 * Returns { gcd, x, y } such that a*x + b*y = gcd(a, b).
 */
export function extendedGcd(a, b) {
  if (a < 0n) a = -a;
  if (b < 0n) b = -b;
  let old_r = a, r = b;
  let old_s = 1n, s = 0n;
  let old_t = 0n, t = 1n;

  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
    [old_t, t] = [t, old_t - q * t];
  }
  return { gcd: old_r, x: old_s, y: old_t };
}

/**
 * Compute modular inverse of a mod m using extended Euclidean algorithm.
 * Returns d such that a*d ≡ 1 (mod m), or throws if gcd(a,m) ≠ 1.
 */
export function modInverse(a, m) {
  a = ((a % m) + m) % m;
  const { gcd, x } = extendedGcd(a, m);
  if (gcd !== 1n) throw new Error(`No modular inverse: gcd(${a}, ${m}) = ${gcd}`);
  return ((x % m) + m) % m;
}

/**
 * GCD for BigInt.
 */
function bigGcd(a, b) {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b > 0n) { const t = b; b = a % b; a = t; }
  return a;
}

// ── BigInt ↔ byte array conversion ───────────────────────────────────────────

/**
 * Convert a BigInt to a Uint8Array of exactly `len` bytes (big-endian).
 */
function bigintToBytes(n, len) {
  const hex = n.toString(16).padStart(len * 2, "0");
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert a Uint8Array to a BigInt (big-endian).
 */
function bytesToBigint(bytes) {
  let n = 0n;
  for (let i = 0; i < bytes.length; i++) {
    n = (n << 8n) | BigInt(bytes[i]);
  }
  return n;
}

/**
 * Convert a string to a Uint8Array (UTF-8).
 */
function stringToBytes(s) {
  return new TextEncoder().encode(s);
}

/**
 * Convert a Uint8Array to a string (UTF-8).
 */
function bytesToString(bytes) {
  return new TextDecoder().decode(bytes);
}

/**
 * Convert a Uint8Array to a hex string.
 */
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Number of bytes needed to represent N.
 */
function byteLength(n) {
  if (n === 0n) return 1;
  return Math.ceil(n.toString(16).length / 2);
}

// ── RSA Key Generation ───────────────────────────────────────────────────────

/**
 * Synchronous prime generation for small bit sizes.
 * Uses Miller-Rabin with k=40 rounds.
 */
function genPrimeSync(bits) {
  const lo = 1n << BigInt(bits - 1);
  const hi = (1n << BigInt(bits)) - 1n;
  let candidates = 0;
  while (true) {
    let n = randomBigIntInRange(lo, hi);
    n = n | 1n; // ensure odd
    candidates++;
    if (millerRabin(n, 40).prime) {
      return { prime: n, candidates };
    }
    if (candidates > 100000) throw new Error("Too many attempts to find prime");
  }
}

/**
 * RSA Key Generation (synchronous, for small key sizes like 512-bit).
 *
 * rsa_keygen(bits):
 *   1. Choose large primes p, q of ⌊bits/2⌋ bits each using Miller-Rabin.
 *   2. N = p * q
 *   3. φ(N) = (p-1)(q-1)
 *   4. e = 65537
 *   5. d = e⁻¹ mod φ(N) via extended Euclidean algorithm
 *
 * Returns { p, q, N, phi, e, d, dp, dq, qInv, bits, timeMs }
 */
export function rsaKeygen(bits = 512) {
  const t0 = performance.now();
  const halfBits = Math.floor(bits / 2);

  // Generate two primes p and q
  const { prime: p } = genPrimeSync(halfBits);
  let q;
  do {
    ({ prime: q } = genPrimeSync(halfBits));
  } while (q === p); // ensure p ≠ q

  const N = p * q;
  const phi = (p - 1n) * (q - 1n);

  // Choose e = 65537
  const e = 65537n;
  if (bigGcd(e, phi) !== 1n) {
    throw new Error("gcd(e, φ(N)) ≠ 1; try again");
  }

  // Compute d = e⁻¹ mod φ(N)
  const d = modInverse(e, phi);

  // CRT components for PA#14
  const dp = d % (p - 1n);
  const dq = d % (q - 1n);
  const qInv = modInverse(q, p);

  const timeMs = performance.now() - t0;
  return { p, q, N, phi, e, d, dp, dq, qInv, bits, timeMs };
}

/**
 * Async RSA key generation (yields to event loop for larger keys).
 */
export async function rsaKeygenAsync(bits = 512, onProgress) {
  const t0 = performance.now();
  const halfBits = Math.floor(bits / 2);

  if (onProgress) onProgress("Generating p...");
  const pResult = await genPrimeAsync(halfBits, () => {});
  const p = pResult.prime;

  if (onProgress) onProgress("Generating q...");
  let q;
  do {
    const qResult = await genPrimeAsync(halfBits, () => {});
    q = qResult.prime;
  } while (q === p);

  const N = p * q;
  const phi = (p - 1n) * (q - 1n);
  const e = 65537n;
  if (bigGcd(e, phi) !== 1n) {
    throw new Error("gcd(e, φ(N)) ≠ 1; try again");
  }
  const d = modInverse(e, phi);
  const dp = d % (p - 1n);
  const dq = d % (q - 1n);
  const qInv = modInverse(q, p);

  const timeMs = performance.now() - t0;
  return { p, q, N, phi, e, d, dp, dq, qInv, bits, timeMs };
}

// ── Textbook RSA Encryption / Decryption ─────────────────────────────────────

/**
 * Textbook RSA encryption: C = M^e mod N
 * m can be a BigInt or a string (converted to BigInt via UTF-8 encoding).
 */
export function rsaEnc(pk, m) {
  const { N, e } = pk;
  let M;
  let mBytes = null;
  if (typeof m === "string") {
    mBytes = stringToBytes(m);
    M = bytesToBigint(mBytes);
  } else {
    M = BigInt(m);
  }
  if (M >= N) throw new Error("Message must be less than N");
  const C = modPow(M, e, N);
  return { C, M, mHex: M.toString(16) };
}

/**
 * Textbook RSA decryption: M = C^d mod N
 * Returns { M, mHex, mStr } where mStr is the UTF-8 decoded message (if valid).
 */
export function rsaDec(sk, c) {
  const { N, d } = sk;
  const C = BigInt(c);
  const M = modPow(C, d, N);
  const mHex = M.toString(16);

  // Try to decode as UTF-8 string
  let mStr = null;
  try {
    const k = byteLength(N);
    const mBytes = bigintToBytes(M, k);
    // Find first nonzero byte for the actual message
    let start = 0;
    while (start < mBytes.length && mBytes[start] === 0) start++;
    if (start < mBytes.length) {
      mStr = bytesToString(mBytes.slice(start));
    }
  } catch {
    // Not valid UTF-8
  }

  return { M, mHex, mStr };
}

// ── PKCS#1 v1.5 Padding ─────────────────────────────────────────────────────

/**
 * PKCS#1 v1.5 Encryption Padding.
 *
 * Padded plaintext EM:
 *   EM = 0x00 || 0x02 || PS (random nonzero bytes, ≥8) || 0x00 || message
 *
 * Total length of EM = k (modulus byte length).
 *
 * @param {Uint8Array} mBytes — message bytes
 * @param {number} k — modulus byte length
 * @returns {{ em: Uint8Array, ps: Uint8Array }} padded message and the PS bytes
 */
export function pkcs15Pad(mBytes, k) {
  if (mBytes.length > k - 11) {
    throw new Error(`Message too long: ${mBytes.length} bytes, max ${k - 11}`);
  }

  const psLen = k - mBytes.length - 3; // at least 8
  const ps = new Uint8Array(psLen);
  for (let i = 0; i < psLen; i++) {
    ps[i] = randomNonzeroByte();
  }

  const em = new Uint8Array(k);
  em[0] = 0x00;
  em[1] = 0x02;
  em.set(ps, 2);
  em[2 + psLen] = 0x00;
  em.set(mBytes, 3 + psLen);

  return { em, ps };
}

/**
 * PKCS#1 v1.5 Unpadding.
 *
 * Validates the format: 0x00 || 0x02 || PS (≥8 nonzero bytes) || 0x00 || message
 *
 * @param {Uint8Array} em — padded message
 * @returns {{ valid: boolean, message: Uint8Array|null, ps: Uint8Array|null }}
 */
export function pkcs15Unpad(em) {
  if (em.length < 11) return { valid: false, message: null, ps: null };
  if (em[0] !== 0x00 || em[1] !== 0x02) return { valid: false, message: null, ps: null };

  // Find the 0x00 separator after PS (PS must be at least 8 bytes)
  let sepIdx = -1;
  for (let i = 2; i < em.length; i++) {
    if (em[i] === 0x00) {
      if (i - 2 >= 8) {
        sepIdx = i;
        break;
      } else {
        // PS too short
        return { valid: false, message: null, ps: null };
      }
    }
  }

  if (sepIdx === -1) return { valid: false, message: null, ps: null };

  const ps = em.slice(2, sepIdx);
  const message = em.slice(sepIdx + 1);
  return { valid: true, message, ps };
}

/**
 * PKCS#1 v1.5 RSA Encryption.
 * Pads m as 00||02||PS||00||m, then applies textbook RSA.
 */
export function pkcs15Enc(pk, m) {
  const { N, e } = pk;
  const k = byteLength(N);

  let mBytes;
  if (typeof m === "string") {
    mBytes = stringToBytes(m);
  } else if (m instanceof Uint8Array) {
    mBytes = m;
  } else {
    // BigInt — convert to bytes
    const hex = BigInt(m).toString(16);
    mBytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < mBytes.length; i++) {
      mBytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
  }

  const { em, ps } = pkcs15Pad(mBytes, k);
  const M = bytesToBigint(em);
  const C = modPow(M, e, N);

  return {
    C,
    em,
    ps,
    psHex: bytesToHex(ps),
    emHex: bytesToHex(em),
  };
}

/**
 * PKCS#1 v1.5 RSA Decryption.
 * Applies textbook RSA, then strips and validates padding.
 * Returns ⊥ (null) on malformed padding.
 */
export function pkcs15Dec(sk, c) {
  const { N, d } = sk;
  const C = BigInt(c);
  const M = modPow(C, d, N);

  const k = byteLength(N);
  const emBytes = bigintToBytes(M, k);

  const result = pkcs15Unpad(emBytes);
  if (!result.valid) {
    return { valid: false, message: null, mStr: null, ps: null, emHex: bytesToHex(emBytes) };
  }

  let mStr = null;
  try {
    mStr = bytesToString(result.message);
  } catch {
    // Not valid UTF-8
  }

  return {
    valid: true,
    message: result.message,
    mStr,
    mHex: bytesToHex(result.message),
    ps: result.ps,
    psHex: bytesToHex(result.ps),
    emHex: bytesToHex(emBytes),
  };
}

// ── Determinism Attack on Textbook RSA ───────────────────────────────────────

/**
 * Demonstrates that textbook RSA is deterministic:
 * encrypting the same message twice produces identical ciphertexts.
 *
 * Contrast with PKCS#1 v1.5 where random PS bytes make each encryption different.
 */
export function determinismAttack(pk, message) {
  // Textbook RSA — encrypt twice
  const tb1 = rsaEnc(pk, message);
  const tb2 = rsaEnc(pk, message);
  const textbookIdentical = tb1.C === tb2.C;

  // PKCS#1 v1.5 — encrypt twice
  const pkcs1 = pkcs15Enc(pk, message);
  const pkcs2 = pkcs15Enc(pk, message);
  const pkcsIdentical = pkcs1.C === pkcs2.C;

  return {
    message,
    textbook: {
      c1: tb1.C,
      c2: tb2.C,
      identical: textbookIdentical,
    },
    pkcs15: {
      c1: pkcs1.C,
      c2: pkcs2.C,
      ps1Hex: pkcs1.psHex,
      ps2Hex: pkcs2.psHex,
      identical: pkcsIdentical,
    },
  };
}

// ── Simplified Bleichenbacher Padding Oracle Attack ───────────────────────────

/**
 * Padding validation oracle: returns true if ciphertext decrypts to valid
 * PKCS#1 v1.5 format (0x00 || 0x02 || PS || 0x00 || m).
 */
export function paddingOracle(sk, c) {
  const result = pkcs15Dec(sk, c);
  return result.valid;
}

/**
 * Simplified Bleichenbacher attack demo.
 *
 * This is a toy demonstration with small N (≈512 bits).
 * Given a ciphertext c and access to the padding oracle, we show
 * adaptive chosen-ciphertext queries that exploit the oracle.
 *
 * For the demo, we show a limited number of queries to illustrate
 * the attack principle rather than a full plaintext recovery.
 *
 * Returns { queries, oracleCallCount, explanation }
 */
export function bleichenbacherDemo(pk, sk, ciphertext, maxQueries = 200) {
  const { N, e } = pk;
  const k = byteLength(N);
  const B = 1n << (BigInt(k - 2) * 8n); // 2^(8*(k-2))
  const C = BigInt(ciphertext);

  const queries = [];
  let oracleCallCount = 0;
  let validCount = 0;

  // Phase 1: Blinding — find s₁ such that (c · s₁^e mod N) decrypts to valid PKCS
  // For the demo, try small values of s
  let s1 = null;
  for (let s = 1n; s <= BigInt(maxQueries); s++) {
    oracleCallCount++;
    const cPrime = (C * modPow(s, e, N)) % N;
    const valid = paddingOracle(sk, cPrime);
    queries.push({
      s: s.toString(),
      cPrimeHex: cPrime.toString(16).slice(0, 24) + "…",
      valid,
      phase: "Blinding (Phase 1)",
    });

    if (valid) {
      validCount++;
      if (s1 === null) {
        s1 = s;
        // Found first valid s, continue a few more to show statistics
      }
    }
    if (validCount >= 5 || oracleCallCount >= maxQueries) break;
  }

  // The original ciphertext itself should be valid (s=1 query)
  const explanation = s1 !== null
    ? `Found blinding factor s₁ = ${s1} after ${oracleCallCount} oracle queries. ` +
      `${validCount} of ${oracleCallCount} queries returned valid padding. ` +
      `In a full attack, this narrows the plaintext to the range [2B, 3B-1] where B = 2^(8(k-2)). ` +
      `Subsequent phases would iteratively tighten this interval using ~2²⁰ total queries.`
    : `No valid blinding factor found in ${oracleCallCount} queries. ` +
      `The full attack typically requires ~2²⁰ adaptive queries.`;

  return {
    queries,
    oracleCallCount,
    validCount,
    s1: s1 ? s1.toString() : null,
    B: B.toString(16),
    k,
    explanation,
  };
}

// ── Interface exports (for use by PA#14, PA#15, PA#18) ───────────────────────

/**
 * Enc(pk, m) -> c  (textbook variant)
 */
export function Enc(pk, m) {
  return rsaEnc(pk, m).C;
}

/**
 * Dec(sk, c) -> m  (textbook variant)
 */
export function Dec(sk, c) {
  return rsaDec(sk, c).M;
}

/**
 * Enc_PKCS(pk, m) -> c  (PKCS#1 v1.5 variant)
 */
export function EncPKCS(pk, m) {
  return pkcs15Enc(pk, m).C;
}

/**
 * Dec_PKCS(sk, c) -> { message, valid }  (PKCS#1 v1.5 variant)
 */
export function DecPKCS(sk, c) {
  const result = pkcs15Dec(sk, c);
  return { message: result.message, valid: result.valid, mStr: result.mStr };
}

// ── Re-export modPow for convenience ─────────────────────────────────────────
export { modPow };

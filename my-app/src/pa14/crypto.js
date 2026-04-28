// ═══════════════════════════════════════════════════════════════════════════════
// PA #14 — Chinese Remainder Theorem & Breaking Textbook RSA
//
// Implements:
//   1. Constructive CRT solver
//   2. CRT-based RSA decryption using Garner recombination
//   3. Standard-vs-CRT RSA correctness and benchmark helpers
//   4. Håstad broadcast attack for textbook RSA with small exponent e = 3
//   5. Randomized-padding contrast showing why Håstad fails when plaintexts differ
//
// No external crypto libraries are used. RSA arithmetic reuses PA#12, and prime
// generation reuses PA#13 Miller-Rabin.
// ═══════════════════════════════════════════════════════════════════════════════

import {
  rsaKeygen,
  rsaEnc,
  rsaDec,
  modPow,
  modInverse,
} from "../pa12/crypto.js";
import { genPrime } from "../pa13/crypto.js";

// ── Basic BigInt helpers ─────────────────────────────────────────────────────

export function bigGcd(a, b) {
  a = BigInt(a);
  b = BigInt(b);
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b !== 0n) {
    const t = b;
    b = a % b;
    a = t;
  }
  return a;
}

function mod(a, n) {
  a = BigInt(a);
  n = BigInt(n);
  return ((a % n) + n) % n;
}

export function bigintToHex(n) {
  return BigInt(n).toString(16);
}

export function truncMiddle(s, keep = 18) {
  s = String(s);
  if (s.length <= keep * 2 + 1) return s;
  return `${s.slice(0, keep)}…${s.slice(-keep)}`;
}

export function textToBigInt(text) {
  const bytes = new TextEncoder().encode(text);
  let out = 0n;
  for (const b of bytes) out = (out << 8n) | BigInt(b);
  return out;
}

export function bigIntToText(n) {
  n = BigInt(n);
  if (n === 0n) return "";
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  try {
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

function randomBigIntBelow(n) {
  n = BigInt(n);
  const bits = n.toString(2).length;
  const bytes = Math.ceil(bits / 8);

  for (let attempt = 0; attempt < 1000; attempt++) {
    let r = 0n;
    try {
      const buf = new Uint8Array(bytes);
      crypto.getRandomValues(buf);
      for (const b of buf) r = (r << 8n) | BigInt(b);
    } catch {
      for (let i = 0; i < bytes; i++) {
        r = (r << 8n) | BigInt(Math.floor(Math.random() * 256));
      }
    }
    r &= (1n << BigInt(bits)) - 1n;
    if (r < n) return r;
  }

  return n / 2n;
}

// ── 1. Constructive CRT solver ───────────────────────────────────────────────

/**
 * crt(residues, moduli) -> { x, modulus, steps }
 *
 * Solves x ≡ residues[i] (mod moduli[i]) for pairwise-coprime moduli.
 * Uses the constructive formula:
 *   x = Σ ai · Mi · (Mi^{-1} mod ni) mod N, where Mi = N / ni.
 */
export function crt(residues, moduli) {
  if (!Array.isArray(residues) || !Array.isArray(moduli)) {
    throw new Error("residues and moduli must be arrays");
  }
  if (residues.length !== moduli.length || residues.length === 0) {
    throw new Error("residues and moduli must have the same nonzero length");
  }

  const a = residues.map(BigInt);
  const n = moduli.map(BigInt);

  for (let i = 0; i < n.length; i++) {
    if (n[i] <= 1n) throw new Error("all moduli must be > 1");
    for (let j = i + 1; j < n.length; j++) {
      const g = bigGcd(n[i], n[j]);
      if (g !== 1n) {
        throw new Error(`moduli must be pairwise coprime; gcd(n${i + 1}, n${j + 1}) = ${g}`);
      }
    }
  }

  const N = n.reduce((acc, ni) => acc * ni, 1n);
  let x = 0n;
  const steps = [];

  for (let i = 0; i < n.length; i++) {
    const ai = mod(a[i], n[i]);
    const Mi = N / n[i];
    const inv = modInverse(Mi, n[i]);
    const term = ai * Mi * inv;
    steps.push({
      index: i,
      residue: ai,
      modulus: n[i],
      Mi,
      inverse: inv,
      term,
      termModN: mod(term, N),
    });
    x += term;
  }

  x = mod(x, N);
  return { x, modulus: N, steps };
}

export function verifyCrtSolution(x, residues, moduli) {
  const X = BigInt(x);
  return residues.map((ai, i) => ({
    residue: BigInt(ai),
    modulus: BigInt(moduli[i]),
    observed: mod(X, BigInt(moduli[i])),
    pass: mod(X, BigInt(moduli[i])) === mod(BigInt(ai), BigInt(moduli[i])),
  }));
}

// ── 2. CRT-based RSA decryption via Garner recombination ─────────────────────

/**
 * rsaDecCrt(sk, c) computes textbook RSA decryption using the CRT components
 * p, q, dp, dq, qInv included in PA#12's key object.
 */
export function rsaDecCrt(sk, c) {
  const { p, q, N, dp, dq, qInv } = sk;
  if ([p, q, N, dp, dq, qInv].some(v => v === undefined || v === null)) {
    throw new Error("CRT decryption needs sk = { p, q, N, dp, dq, qInv }");
  }

  const C = BigInt(c);
  const mp = modPow(C, dp, p);
  const mq = modPow(C, dq, q);
  const h = mod(qInv * (mp - mq), p);
  const M = mq + h * q;

  return {
    M,
    mHex: M.toString(16),
    mStr: bigIntToText(M),
    mp,
    mq,
    h,
    recombined: M,
    formula: "mp = C^dp mod p; mq = C^dq mod q; h = qInv(mp - mq) mod p; M = mq + hq",
  };
}

export function decryptCompare(sk, message) {
  const pk = { N: sk.N, e: sk.e };
  const enc = rsaEnc(pk, message);

  const tStd0 = performance.now();
  const standard = rsaDec({ N: sk.N, d: sk.d }, enc.C);
  const tStd1 = performance.now();

  const tCrt0 = performance.now();
  const crtDec = rsaDecCrt(sk, enc.C);
  const tCrt1 = performance.now();

  return {
    ciphertext: enc.C,
    plaintextInt: enc.M,
    standard,
    crt: crtDec,
    equal: standard.M === crtDec.M,
    standardMs: tStd1 - tStd0,
    crtMs: tCrt1 - tCrt0,
    speedup: (tStd1 - tStd0) / Math.max(tCrt1 - tCrt0, 0.000001),
  };
}

export function testCrtRsaCorrectness(sk, count = 100) {
  const failures = [];
  const samples = [];

  for (let i = 0; i < count; i++) {
    const m = 2n + randomBigIntBelow(sk.N - 3n);
    const c = modPow(m, sk.e, sk.N);
    const standard = modPow(c, sk.d, sk.N);
    const crtDec = rsaDecCrt(sk, c).M;
    const pass = standard === crtDec && standard === m;

    if (i < 5) samples.push({ i, m, c, standard, crt: crtDec, pass });
    if (!pass) failures.push({ i, m, c, standard, crt: crtDec });
  }

  return {
    count,
    passed: failures.length === 0,
    failures,
    samples,
    failureCount: failures.length,
  };
}

export function benchmarkRsaCrt(sk, trials = 100) {
  const ciphertexts = [];
  for (let i = 0; i < trials; i++) {
    const m = 2n + randomBigIntBelow(sk.N - 3n);
    ciphertexts.push(modPow(m, sk.e, sk.N));
  }

  const tStd0 = performance.now();
  for (const c of ciphertexts) modPow(c, sk.d, sk.N);
  const tStd1 = performance.now();

  const tCrt0 = performance.now();
  for (const c of ciphertexts) rsaDecCrt(sk, c).M;
  const tCrt1 = performance.now();

  const standardMs = tStd1 - tStd0;
  const crtMs = tCrt1 - tCrt0;

  return {
    trials,
    standardMs,
    crtMs,
    speedup: standardMs / Math.max(crtMs, 0.000001),
    standardPerOpMs: standardMs / trials,
    crtPerOpMs: crtMs / trials,
  };
}

// ── 3. Håstad broadcast attack ───────────────────────────────────────────────

/**
 * Integer n-th root by binary search.
 * Returns floor(value^(1/n)) and whether the root is exact.
 */
export function integerNthRoot(value, n) {
  value = BigInt(value);
  n = BigInt(n);
  if (value < 0n) throw new Error("integerNthRoot only supports nonnegative values");
  if (n <= 0n) throw new Error("root degree must be positive");
  if (value < 2n) return { root: value, exact: true };

  let lo = 0n;
  let hi = 1n << ((BigInt(value.toString(2).length) + n - 1n) / n + 1n);

  while (lo + 1n < hi) {
    const mid = (lo + hi) >> 1n;
    const p = mid ** n;
    if (p <= value) lo = mid;
    else hi = mid;
  }

  return { root: lo, exact: lo ** n === value };
}

/**
 * Generate a toy RSA keypair with caller-chosen public exponent e.
 * Used only for the Håstad demo because PA#12 fixes e = 65537.
 */
export function rsaKeygenWithExponent(bits = 192, e = 3n) {
  const t0 = performance.now();
  const half = Math.floor(bits / 2);
  let p, q, phi;

  while (true) {
    p = genPrime(half).prime;
    do { q = genPrime(half).prime; } while (q === p);
    phi = (p - 1n) * (q - 1n);
    if (bigGcd(e, phi) === 1n) break;
  }

  const N = p * q;
  const d = modInverse(e, phi);
  const dp = d % (p - 1n);
  const dq = d % (q - 1n);
  const qInv = modInverse(q, p);

  return { p, q, N, phi, e, d, dp, dq, qInv, bits, timeMs: performance.now() - t0 };
}

export function hastadBroadcastAttack(ciphertexts, moduli, e = 3n) {
  const crtResult = crt(ciphertexts, moduli);
  const rootResult = integerNthRoot(crtResult.x, e);

  return {
    recovered: rootResult.root,
    recoveredText: bigIntToText(rootResult.root),
    exact: rootResult.exact,
    crtValue: crtResult.x,
    combinedModulus: crtResult.modulus,
    crtSteps: crtResult.steps,
    e: BigInt(e),
  };
}

export function runHastadDemo(message = "attack", bits = 192, e = 3n) {
  e = BigInt(e);
  const M = textToBigInt(message);
  const recipients = [];
  const ciphertexts = [];
  const moduli = [];

  for (let i = 0; i < Number(e); i++) {
    const sk = rsaKeygenWithExponent(bits, e);
    if (M >= sk.N) {
      throw new Error(`message integer is too large for recipient ${i + 1}'s modulus; use a shorter message or larger key`);
    }
    const C = modPow(M, e, sk.N);
    recipients.push({ index: i + 1, pk: { N: sk.N, e: sk.e }, sk, ciphertext: C });
    ciphertexts.push(C);
    moduli.push(sk.N);
  }

  const attack = hastadBroadcastAttack(ciphertexts, moduli, e);
  return {
    message,
    messageInt: M,
    recipients,
    ciphertexts,
    moduli,
    attack,
    success: attack.exact && attack.recovered === M,
  };
}

/**
 * Illustrates why Håstad fails when each recipient encrypts a different padded
 * value. This is a lightweight stand-in for randomized padding such as PKCS#1.
 */
export function runRandomizedPaddingContrast(message = "attack", bits = 192, e = 3n) {
  e = BigInt(e);
  const M = textToBigInt(message);
  const recipients = [];
  const ciphertexts = [];
  const moduli = [];
  const paddedValues = [];

  for (let i = 0; i < Number(e); i++) {
    const sk = rsaKeygenWithExponent(bits, e);
    const randomPad = 1n + randomBigIntBelow(0xffffffffn);
    const padded = (M << 40n) + (BigInt(i + 1) << 32n) + randomPad;
    if (padded >= sk.N) {
      throw new Error("randomized padded value is too large; increase key size");
    }
    const C = modPow(padded, e, sk.N);
    recipients.push({ index: i + 1, pk: { N: sk.N, e: sk.e }, padded, ciphertext: C });
    ciphertexts.push(C);
    moduli.push(sk.N);
    paddedValues.push(padded);
  }

  const attack = hastadBroadcastAttack(ciphertexts, moduli, e);
  return {
    message,
    messageInt: M,
    paddedValues,
    recipients,
    attack,
    originalRecovered: attack.recovered === M,
    exactRoot: attack.exact,
    explanation: "Because each recipient encrypted a different randomized padded integer, CRT reconstructs no single m^e. The integer-root step therefore does not recover the original message.",
  };
}

// Convenience export for the panel: normal PA#12 keygen for CRT-RSA section.
export { rsaKeygen };

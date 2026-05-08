// ═══════════════════════════════════════════════════════════════════════════════
// PA #16 — ElGamal Public-Key Cryptosystem
//
// Implements:
//   1. ElGamal key generation over the PA#11 safe-prime subgroup
//   2. Encryption / decryption based on DDH hardness
//   3. Randomized-encryption demo: same message → different ciphertexts
//   4. IND-CPA simulation with a dummy adversary
//   5. Malleability demo: (c1, c2) → (c1, 2·c2 mod p) decrypts to 2m mod p
//
// No external crypto libraries are used. Modular arithmetic reuses PA#11/PA#13.
// ═══════════════════════════════════════════════════════════════════════════════

import { TOY_P, TOY_Q, TOY_G, modPow } from "../pa11/crypto.js";

// ── Default group from PA#11 ─────────────────────────────────────────────────

export const DEFAULT_GROUP = {
  p: TOY_P,
  q: TOY_Q,
  g: TOY_G,
  label: "PA#11 toy safe-prime subgroup",
};

// ── Basic helpers ────────────────────────────────────────────────────────────

export function mod(a, n) {
  a = BigInt(a);
  n = BigInt(n);
  return ((a % n) + n) % n;
}

export function truncMiddle(value, keep = 18) {
  const s = typeof value === "bigint" ? value.toString() : String(value);
  if (s.length <= keep * 2 + 1) return s;
  return `${s.slice(0, keep)}…${s.slice(-keep)}`;
}

export function bigintToHex(n) {
  return BigInt(n).toString(16);
}

export function parseMessageRepresentative(value, p = DEFAULT_GROUP.p) {
  const raw = String(value ?? "").trim();
  if (!raw) throw new Error("Message cannot be empty");

  let m;
  if (/^0x[0-9a-fA-F]+$/.test(raw)) m = BigInt(raw);
  else if (/^[0-9]+$/.test(raw)) m = BigInt(raw);
  else {
    // Convenience mode for short text: encode UTF-8 bytes as an integer.
    const bytes = new TextEncoder().encode(raw);
    m = 0n;
    for (const b of bytes) m = (m << 8n) | BigInt(b);
  }

  if (m <= 0n || m >= p) {
    throw new Error(`Message representative must satisfy 1 ≤ m < p. Got m = ${m}`);
  }
  return m;
}

export function representativeToMaybeText(m) {
  m = BigInt(m);
  if (m === 0n) return "";
  let hex = m.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    // Avoid showing control-heavy garbage as text.
    if (/^[\x20-\x7E\n\r\t]+$/.test(decoded)) return decoded;
  } catch {
    // not text
  }
  return null;
}

export function randomBigIntInRange(lo, hi) {
  lo = BigInt(lo);
  hi = BigInt(hi);
  if (hi <= lo) return lo;

  const range = hi - lo + 1n;
  const bits = range.toString(2).length;
  const bytes = Math.ceil(bits / 8);

  for (let attempt = 0; attempt < 1000; attempt++) {
    let r = 0n;
    try {
      const buf = new Uint8Array(bytes);
      crypto.getRandomValues(buf);
      for (const b of buf) r = (r << 8n) | BigInt(b);
    } catch {
      for (let i = 0; i < bytes; i++) r = (r << 8n) | BigInt(Math.floor(Math.random() * 256));
    }

    r &= (1n << BigInt(bits)) - 1n;
    if (r < range) return lo + r;
  }

  return lo + (range >> 1n);
}

// ── ElGamal core ─────────────────────────────────────────────────────────────

/**
 * Key generation:
 *   secret x ← Z_q
 *   public h = g^x mod p
 */
export function elgamalKeygen(group = DEFAULT_GROUP, xOverride = null) {
  const { p, q, g } = group;
  const x = xOverride !== null && xOverride !== undefined
    ? mod(BigInt(xOverride), q)
    : randomBigIntInRange(2n, q - 1n);
  if (x === 0n) throw new Error("Secret exponent x cannot be 0");
  const h = modPow(g, x, p);
  return {
    pk: { p, q, g, h },
    sk: { p, q, g, h, x },
  };
}

/**
 * Encrypt group/integer representative m:
 *   r ← Z_q
 *   c1 = g^r mod p
 *   s  = h^r mod p
 *   c2 = m · s mod p
 */
export function elgamalEncrypt(pk, messageRepresentative, rOverride = null) {
  const { p, q, g, h } = pk;
  const m = mod(BigInt(messageRepresentative), p);
  if (m <= 0n || m >= p) throw new Error("ElGamal message representative must be in {1, ..., p-1}");

  const r = rOverride !== null && rOverride !== undefined
    ? mod(BigInt(rOverride), q)
    : randomBigIntInRange(2n, q - 1n);
  if (r === 0n) throw new Error("Ephemeral randomness r cannot be 0");

  const c1 = modPow(g, r, p);
  const sharedMask = modPow(h, r, p);
  const c2 = (m * sharedMask) % p;

  return { c1, c2, r, sharedMask, m };
}

/**
 * Decrypt:
 *   s = c1^x mod p
 *   m = c2 · s^{-1} mod p
 * Since p is prime, s^{-1} = s^(p-2) mod p.
 */
export function elgamalDecrypt(sk, ciphertext) {
  const { p, x } = sk;
  const c1 = BigInt(ciphertext.c1);
  const c2 = BigInt(ciphertext.c2);
  const sharedMask = modPow(c1, x, p);
  const inverseMask = modPow(sharedMask, p - 2n, p);
  const m = (mod(c2, p) * inverseMask) % p;
  return { m, sharedMask, inverseMask };
}

export function encryptDecryptDemo(keys, messageValue) {
  const m = parseMessageRepresentative(messageValue, keys.pk.p);
  const enc = elgamalEncrypt(keys.pk, m);
  const dec = elgamalDecrypt(keys.sk, enc);
  return {
    message: m,
    ciphertext: enc,
    decrypted: dec,
    pass: dec.m === m,
    maybeText: representativeToMaybeText(dec.m),
  };
}

// ── Randomization demo ───────────────────────────────────────────────────────

export function randomizedEncryptionDemo(keys, messageValue) {
  const m = parseMessageRepresentative(messageValue, keys.pk.p);
  const enc1 = elgamalEncrypt(keys.pk, m);
  const enc2 = elgamalEncrypt(keys.pk, m);
  const dec1 = elgamalDecrypt(keys.sk, enc1);
  const dec2 = elgamalDecrypt(keys.sk, enc2);
  return {
    message: m,
    enc1,
    enc2,
    dec1,
    dec2,
    ciphertextsDiffer: enc1.c1 !== enc2.c1 || enc1.c2 !== enc2.c2,
    bothDecrypt: dec1.m === m && dec2.m === m,
  };
}

// ── Required malleability demo ───────────────────────────────────────────────

export function malleabilityDemo(keys, messageValue, factor = 2n) {
  const m = parseMessageRepresentative(messageValue, keys.pk.p);
  const enc = elgamalEncrypt(keys.pk, m);
  const originalDec = elgamalDecrypt(keys.sk, enc);

  const k = mod(BigInt(factor), keys.pk.p);
  const modified = {
    c1: enc.c1,
    c2: (k * enc.c2) % keys.pk.p,
  };
  const modifiedDec = elgamalDecrypt(keys.sk, modified);
  const expected = (k * m) % keys.pk.p;

  return {
    factor: k,
    message: m,
    original: enc,
    originalDec,
    modified,
    modifiedDec,
    expected,
    pass: originalDec.m === m && modifiedDec.m === expected,
  };
}

// ── IND-CPA simulation ───────────────────────────────────────────────────────

export function runIndCpaSimulation(keys, m0Value, m1Value, rounds = 50) {
  const m0 = parseMessageRepresentative(m0Value, keys.pk.p);
  const m1 = parseMessageRepresentative(m1Value, keys.pk.p);
  if (m0 === m1) throw new Error("m0 and m1 must be different for the IND-CPA game");

  let correct = 0;
  const log = [];
  const total = Math.max(1, Number.parseInt(rounds, 10) || 50);

  for (let i = 0; i < total; i++) {
    const b = Math.random() < 0.5 ? 0 : 1;
    const chosen = b === 0 ? m0 : m1;
    const challenge = elgamalEncrypt(keys.pk, chosen);

    // Honest dummy adversary: without the secret exponent and under DDH, it has no
    // useful signal, so it guesses randomly. Advantage should hover near 0.
    const guess = Math.random() < 0.5 ? 0 : 1;
    if (guess === b) correct++;

    if (i < 8) {
      log.push({
        round: i + 1,
        b,
        guess,
        win: guess === b,
        c1: challenge.c1,
        c2: challenge.c2,
      });
    }
  }

  const successRate = correct / total;
  return {
    rounds: total,
    correct,
    successRate,
    advantage: Math.abs(successRate - 0.5) * 2,
    log,
  };
}

// ── DDH tuple helper for proof intuition ─────────────────────────────────────

export function sampleDdhTuples(group = DEFAULT_GROUP) {
  const { p, q, g } = group;
  const a = randomBigIntInRange(2n, q - 1n);
  const b = randomBigIntInRange(2n, q - 1n);
  const z = randomBigIntInRange(2n, q - 1n);

  const A = modPow(g, a, p);
  const B = modPow(g, b, p);
  const real = modPow(g, (a * b) % q, p);
  const random = modPow(g, z, p);

  return {
    a,
    b,
    z,
    A,
    B,
    realTuple: { A, B, C: real, kind: "DDH real: (g^a, g^b, g^{ab})" },
    randomTuple: { A, B, C: random, kind: "DDH random: (g^a, g^b, g^z)" },
  };
}

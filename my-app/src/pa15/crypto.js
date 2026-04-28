// ═══════════════════════════════════════════════════════════════════════════════
// PA #15 — Digital Signatures
//
// Implements:
//   1. RSA hash-then-sign using PA#12 RSA and PA#8 DLP Hash
//   2. Verification with visible intermediate values
//   3. Raw RSA multiplicative forgery demo
//   4. Hash-then-sign contrast showing the forgery fails after hashing
//   5. EUF-CMA signing-oracle game demo
//
// No external crypto libraries are used. RSA arithmetic comes from PA#12, and
// hashing comes from PA#8.
// ═══════════════════════════════════════════════════════════════════════════════

import { rsaKeygen, modPow } from "../pa12/crypto.js";
import { dlpHash, setupGroup } from "../pa8/crypto.js";

// Use one stable PA#8 DLP-hash parameter set for the whole module/session.
// This is important: Sign and Verify must use the same public hash parameters.
export const SIGNATURE_HASH_PARAMS = setupGroup();

// ── Basic helpers ────────────────────────────────────────────────────────────

function mod(a, n) {
  a = BigInt(a);
  n = BigInt(n);
  return ((a % n) + n) % n;
}

export function truncMiddle(value, keep = 18) {
  const s = typeof value === "bigint" ? value.toString(16) : String(value);
  if (s.length <= keep * 2 + 1) return s;
  return `${s.slice(0, keep)}…${s.slice(-keep)}`;
}

export function textToBigInt(text) {
  const bytes = new TextEncoder().encode(String(text));
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
  if (n <= 2n) return 1n;
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
    if (r > 0n && r < n) return r;
  }

  return 2n;
}

export function tamperMessageOneBit(message) {
  const bytes = new TextEncoder().encode(String(message));
  if (bytes.length === 0) return "\u0001";
  const out = new Uint8Array(bytes);
  out[0] = out[0] ^ 0x01; // flip the lowest bit of the first byte
  return new TextDecoder().decode(out);
}

// ── PA#8 hash bridge for signatures ─────────────────────────────────────────

/**
 * Hash a message with PA#8 DLP_Hash, then reduce the digest into Z_N.
 * Returns the digest hex and integer representative.
 */
export function hashMessageToInt(message, N, params = SIGNATURE_HASH_PARAMS) {
  const digestHex = dlpHash(String(message), params);
  const digestInt = BigInt("0x" + digestHex);
  const hInt = mod(digestInt, BigInt(N));
  return { digestHex, digestInt, hInt };
}

// ── 1. RSA hash-then-sign ────────────────────────────────────────────────────

/**
 * Sign(sk, m) -> sigma
 * Concrete scheme: sigma = H(m)^d mod N.
 */
export function Sign(sk, message, params = SIGNATURE_HASH_PARAMS) {
  const { N, d } = sk;
  const hash = hashMessageToInt(message, N, params);
  const sigma = modPow(hash.hInt, d, N);
  return {
    sigma,
    sigmaHex: sigma.toString(16),
    hash,
    message: String(message),
    formula: "sigma = H(m)^d mod N",
  };
}

/**
 * Verify(vk, m, sigma) -> bool
 * Checks sigma^e mod N == H(m).
 */
export function Verify(pk, message, sigma, params = SIGNATURE_HASH_PARAMS) {
  const { N, e } = pk;
  const sig = BigInt(sigma);
  const lhs = modPow(sig, e, N);
  const hash = hashMessageToInt(message, N, params);
  const rhs = hash.hInt;
  return {
    valid: lhs === rhs,
    lhs,
    rhs,
    lhsHex: lhs.toString(16),
    rhsHex: rhs.toString(16),
    hash,
    message: String(message),
    formula: "sigma^e mod N ?= H(m)",
  };
}

export function signAndVerify(keys, message, params = SIGNATURE_HASH_PARAMS) {
  const pk = { N: keys.N, e: keys.e };
  const sk = { N: keys.N, d: keys.d };
  const sig = Sign(sk, message, params);
  const verification = Verify(pk, message, sig.sigma, params);
  return { signature: sig, verification };
}

export function verifyTampered(keys, originalMessage, sigma, params = SIGNATURE_HASH_PARAMS) {
  const pk = { N: keys.N, e: keys.e };
  const tamperedMessage = tamperMessageOneBit(originalMessage);
  const verification = Verify(pk, tamperedMessage, sigma, params);
  return { tamperedMessage, verification };
}

// ── 2. Raw RSA signing and multiplicative forgery ───────────────────────────

export function rawRsaSign(sk, mInt) {
  const { N, d } = sk;
  const m = mod(BigInt(mInt), N);
  const sigma = modPow(m, d, N);
  return { m, sigma, sigmaHex: sigma.toString(16) };
}

export function rawRsaVerify(pk, mInt, sigma) {
  const { N, e } = pk;
  const m = mod(BigInt(mInt), N);
  const recovered = modPow(BigInt(sigma), e, N);
  return { valid: recovered === m, recovered, expected: m };
}

/**
 * Raw RSA is multiplicatively homomorphic:
 *   Sign(m1) * Sign(m2) mod N = Sign(m1*m2 mod N)
 */
export function rawMultiplicativeForgeryDemo(keys, m1Input = 7n, m2Input = 12n) {
  const pk = { N: keys.N, e: keys.e };
  const sk = { N: keys.N, d: keys.d };
  const m1 = mod(BigInt(m1Input), keys.N);
  const m2 = mod(BigInt(m2Input), keys.N);
  const sig1 = rawRsaSign(sk, m1);
  const sig2 = rawRsaSign(sk, m2);
  const forgedMessage = mod(m1 * m2, keys.N);
  const forgedSigma = mod(sig1.sigma * sig2.sigma, keys.N);
  const verification = rawRsaVerify(pk, forgedMessage, forgedSigma);

  return {
    m1,
    m2,
    sig1,
    sig2,
    forgedMessage,
    forgedSigma,
    forgedSigmaHex: forgedSigma.toString(16),
    verification,
    attackSuccess: verification.valid,
  };
}

/**
 * Try the same multiplication trick against hash-then-sign.
 * It should fail because H(m1*m2) is not H(m1)*H(m2).
 */
export function hashThenSignForgeryContrast(keys, m1Input = 7n, m2Input = 12n, params = SIGNATURE_HASH_PARAMS) {
  const pk = { N: keys.N, e: keys.e };
  const sk = { N: keys.N, d: keys.d };

  const m1 = String(m1Input);
  const m2 = String(m2Input);
  const targetMessage = String(BigInt(m1Input) * BigInt(m2Input));

  const sig1 = Sign(sk, m1, params);
  const sig2 = Sign(sk, m2, params);
  const forgedSigma = mod(sig1.sigma * sig2.sigma, keys.N);
  const verification = Verify(pk, targetMessage, forgedSigma, params);

  return {
    m1,
    m2,
    targetMessage,
    sig1,
    sig2,
    forgedSigma,
    forgedSigmaHex: forgedSigma.toString(16),
    verification,
    attackSuccess: verification.valid,
  };
}

// ── 3. EUF-CMA game demo ─────────────────────────────────────────────────────

export function runEufCmaGame(keys, queryCount = 50, params = SIGNATURE_HASH_PARAMS) {
  const pk = { N: keys.N, e: keys.e };
  const sk = { N: keys.N, d: keys.d };
  const q = Math.max(1, Math.min(Number.parseInt(queryCount, 10) || 50, 50));

  const transcript = [];
  const seen = new Set();

  for (let i = 0; i < q; i++) {
    const msg = `signed-query-${i}-${Math.floor(Math.random() * 1_000_000)}`;
    seen.add(msg);
    const sig = Sign(sk, msg, params);
    transcript.push({
      index: i + 1,
      message: msg,
      digestHex: sig.hash.digestHex,
      sigmaHex: sig.sigmaHex,
    });
  }

  // Naive existential forger: choose a new message and a random signature.
  // Success probability is negligible for a large RSA modulus.
  let forgedMessage = `new-forgery-${Math.floor(Math.random() * 1_000_000_000)}`;
  while (seen.has(forgedMessage)) forgedMessage += "x";
  const forgedSigma = randomBigIntBelow(keys.N);
  const verification = Verify(pk, forgedMessage, forgedSigma, params);

  // Replay is not a valid EUF-CMA win because the message was already queried.
  const replay = transcript[0];
  const replayVerification = Verify(pk, replay.message, BigInt("0x" + replay.sigmaHex), params);

  return {
    queryCount: q,
    transcript: transcript.slice(0, 8),
    totalTranscriptSize: transcript.length,
    forgedMessage,
    forgedSigma,
    forgedSigmaHex: forgedSigma.toString(16),
    verification,
    acceptedAsNewForgery: verification.valid && !seen.has(forgedMessage),
    replay: {
      message: replay.message,
      sigmaHex: replay.sigmaHex,
      valid: replayVerification.valid,
      countsAsForgery: false,
    },
  };
}

// ── 4. Required external interface for later PAs ─────────────────────────────

export function keygen(bits = 512) {
  return rsaKeygen(bits);
}

export function publicKey(keys) {
  return { N: keys.N, e: keys.e };
}

export function privateKey(keys) {
  return { N: keys.N, d: keys.d };
}

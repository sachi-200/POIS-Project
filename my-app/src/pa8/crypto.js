// ═══════════════════════════════════════════════════════════════════════════════
// PA #8 — DLP-based Collision-Resistant Hash Function
// Safe-prime subgroup of Z*_p with p = 2q+1, q prime, group order q.
// h(x, y) = g^x · ĥ^y mod p   (full version)
// h(x, y) = g^(x+y) mod p      (simplified, h = g)
// ═══════════════════════════════════════════════════════════════════════════════

// ── Small safe primes for toy/demo (q ≈ 2^16) ────────────────────────────────
// p = 2q+1 both prime. We use BigInt throughout for correctness.

export const TOY_Q  = 65537n;          // q prime
export const TOY_P  = 131075n;         // p = 2q+1 — NOTE: we use a real safe prime below
// Real safe prime pair (128-bit range isn't needed; 32-bit toy suffices for demo)
// p = 2 * 65537 + 1 = 131075 — not prime, so use a verified pair:
// q = 32771, p = 65543 (both prime, safe prime)
export const DEMO_Q = 32771n;
export const DEMO_P = 65543n;          // p = 2*32771+1 = 65543 ✓ prime

// For collision demo we want n=16-bit output, birthday ≈ 2^8 = 256 hashes.
// We truncate the group element to 16 bits for the collision hunt.

// ── Modular exponentiation (BigInt) ──────────────────────────────────────────

export function modpow(base, exp, mod) {
  base = ((base % mod) + mod) % mod;
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) result = result * base % mod;
    base = base * base % mod;
    exp >>= 1n;
  }
  return result;
}

// ── Group setup ───────────────────────────────────────────────────────────────

/**
 * Generate DLP group parameters.
 * Returns { p, q, g, h, alpha } where alpha is discarded in production.
 * g is a generator of the prime-order-q subgroup of Z*_p.
 * ĥ = g^alpha for a random alpha (unknown to adversary).
 */
export function setupGroup(p = DEMO_P, q = DEMO_Q) {
  // Find a generator g of order q in Z*_p
  // For safe prime p=2q+1: elements of order q are quadratic residues ≠ 1
  // g = any element s.t. g^q ≡ 1 (mod p) and g ≠ 1
  let g = 2n;
  while (modpow(g, q, p) !== 1n || g === 1n) g++;

  // Choose random alpha in [2, q-1]
  const alpha = BigInt(Math.floor(Math.random() * (Number(q) - 3)) + 2);
  const hGen  = modpow(g, alpha, p);   // ĥ = g^alpha

  return { p, q, g, h: hGen, alpha };  // alpha would be discarded in real usage
}

// ── DLP compression function ──────────────────────────────────────────────────

/**
 * h(x, y) = g^x · ĥ^y mod p
 * x, y are BigInts in Z_q.
 * Returns BigInt group element.
 */
export function dlpCompress(x, y, g, hGen, p) {
  return modpow(g, x, p) * modpow(hGen, y, p) % p;
}

/**
 * Simplified: h(x, y) = g^(x+y) mod p  (sets ĥ = g)
 */
export function dlpCompressSimple(x, y, g, p, q) {
  const exp = ((x + y) % q + q) % q;
  return modpow(g, exp, p);
}

// ── Chaining-value bridge ─────────────────────────────────────────────────────

/**
 * Wrap dlpCompress so it matches the PA#7 interface:
 *   compress(zHex: string, blockBytes: number[]) → string (hex of group element)
 *
 * zHex        → x (chaining value, reduced mod q)
 * blockBytes  → y (block folded to a Z_q integer)
 */
export function makeDLPCompressFn({ p, q, g, h: hGen }) {
  return function dlpCompressBridge(zHex, blockBytes) {
    const x = BigInt("0x" + zHex) % q;
    // Fold 8-byte block into a BigInt, reduce mod q
    let y = 0n;
    for (const b of blockBytes) y = (y * 256n + BigInt(b)) % q;
    const out = dlpCompress(x, y, g, hGen, p);
    // Return as 8-char hex (low 32 bits) to stay compatible with PA#7 chain
    return (out & 0xFFFFFFFFn).toString(16).padStart(8, "0");
  };
}

// ── Full CRHF (DLP_Hash) ──────────────────────────────────────────────────────

import { mdPad, parseBlocks, IV } from "../pa7/crypto.js";

/**
 * DLP_Hash(message) → hex string (group element)
 * Plugs dlpCompress into the PA#7 MD framework.
 */
export function dlpHash(message, params) {
  const bytes   = typeof message === "string"
    ? (message.startsWith("0x")
        ? Array.from({ length: Math.ceil((message.length - 2) / 2) }, (_, i) =>
            parseInt(message.slice(2 + i * 2, 4 + i * 2) || "00", 16))
        : Array.from(new TextEncoder().encode(message)))
    : message;

  const padded  = mdPad(bytes);
  const blocks  = parseBlocks(padded);
  const bridge  = makeDLPCompressFn(params);

  let z = IV;
  for (const b of blocks) z = bridge(z, b);
  return z;
}

// ── Collision resistance demo (birthday attack, toy n=16) ────────────────────

/**
 * Run birthday attack on truncated (16-bit) DLP hash.
 * Returns { found, count, input1, input2, digest } or { found: false, count }
 * Calls onProgress(count) every `reportEvery` steps.
 */
export function birthdayAttack(params, onProgress, maxIter = 2000, reportEvery = 50) {
  const bridge = makeDLPCompressFn(params);
  const seen   = new Map();   // digest16 → input bytes

  for (let i = 0; i < maxIter; i++) {
    // Random 1-block message (8 bytes)
    const input = Array.from({ length: 8 }, () => Math.floor(Math.random() * 256));
    const padded = mdPad(input);
    const blocks = parseBlocks(padded);
    let z = IV;
    for (const b of blocks) z = bridge(z, b);
    const d16 = parseInt(z.slice(-4), 16) & 0xFFFF;  // truncate to 16 bits

    if (seen.has(d16)) {
      const prev = seen.get(d16);
      const hex1 = prev.map(b => b.toString(16).padStart(2,"0")).join("");
      const hex2 = input.map(b => b.toString(16).padStart(2,"0")).join("");
      if (hex1 !== hex2) {
        onProgress && onProgress(i + 1);
        return { found: true, count: i + 1, input1: hex1, input2: hex2, digest: d16.toString(16).padStart(4, "0") };
      }
    }
    seen.set(d16, input);
    if (i % reportEvery === 0) onProgress && onProgress(i);
  }
  onProgress && onProgress(maxIter);
  return { found: false, count: maxIter };
}
// ═══════════════════════════════════════════════════════════════════════════════
// PA #11 — Diffie-Hellman Key Exchange (SKE)
//
// Implements:
//   1. Group parameter generation (safe prime p = 2q+1, generator g)
//   2. DH key exchange protocol (Alice & Bob steps)
//   3. MITM attack demo (active adversary Eve)
//   4. CDH hardness demo (brute-force search for small params)
//
// Uses PA#13's Miller-Rabin for primality testing / safe prime generation.
// All arithmetic uses native BigInt; modular exponentiation is square-and-multiply.
// ═══════════════════════════════════════════════════════════════════════════════

import { millerRabin, modPow } from "../pa13/crypto.js";

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

// ── Safe Prime Generation ────────────────────────────────────────────────────

/**
 * Generate a safe prime p = 2q + 1 of approximately `bits` bits.
 * Uses PA#13 Miller-Rabin for primality testing.
 * Returns { p, q, candidates, timeMs }
 */
export function genSafePrime(bits, rounds = 20) {
  const lo = 1n << BigInt(bits - 1);
  const hi = (1n << BigInt(bits)) - 1n;
  let candidates = 0;
  const t0 = performance.now();

  while (true) {
    candidates++;
    // Generate random odd number for q
    let q = randomBigIntInRange(lo >> 1n, hi >> 1n);
    q = q | 1n; // ensure odd

    // Quick check: q must be prime
    if (!millerRabin(q, rounds).prime) continue;

    // p = 2q + 1
    const p = 2n * q + 1n;
    if (p > hi) continue;

    // p must also be prime
    if (millerRabin(p, rounds).prime) {
      const timeMs = performance.now() - t0;
      return { p, q, candidates, timeMs };
    }
  }
}

/**
 * Async version that yields to the event loop.
 */
export async function genSafePrimeAsync(bits, onProgress, rounds = 20) {
  const lo = 1n << BigInt(bits - 1);
  const hi = (1n << BigInt(bits)) - 1n;
  let candidates = 0;
  const t0 = performance.now();
  const YIELD_EVERY = 5;

  while (true) {
    candidates++;
    let q = randomBigIntInRange(lo >> 1n, hi >> 1n);
    q = q | 1n;

    if (!millerRabin(q, rounds).prime) {
      if (candidates % YIELD_EVERY === 0) {
        if (onProgress) onProgress(candidates);
        await new Promise(r => setTimeout(r, 0));
      }
      continue;
    }

    const p = 2n * q + 1n;
    if (p > hi) continue;

    if (millerRabin(p, rounds).prime) {
      const timeMs = performance.now() - t0;
      return { p, q, candidates, timeMs };
    }

    if (candidates % YIELD_EVERY === 0) {
      if (onProgress) onProgress(candidates);
      await new Promise(r => setTimeout(r, 0));
    }
  }
}

/**
 * Find a generator g of the prime-order subgroup of Z*_p (order q)
 * where p = 2q + 1 is a safe prime.
 *
 * For a safe prime p = 2q + 1, Z*_p has order p-1 = 2q.
 * The subgroups have orders: 1, 2, q, 2q.
 * We want a generator of the order-q subgroup:
 *   Pick random h in [2, p-2], set g = h^2 mod p.
 *   If g != 1, then g has order q (since h^(2q) = 1, so g^q = h^(2q) = 1,
 *   and g != 1 means g is not the identity, so order is q).
 */
export function findGenerator(p, q) {
  while (true) {
    const h = randomBigIntInRange(2n, p - 2n);
    const g = modPow(h, 2n, p); // g = h^2 mod p => g has order q or 1
    if (g !== 1n) {
      // Verify: g^q mod p should be 1
      if (modPow(g, q, p) === 1n) return g;
    }
  }
}

// ── Pre-built Toy Parameters ─────────────────────────────────────────────────

// ~32-bit safe prime: p = 4294967387, q = 2147483693
// Both verified prime; p = 2q + 1.
export const TOY_P = 4294967387n;
export const TOY_Q = 2147483693n;
// g = 3^2 mod p = 9;  g^q mod p = 1 ✓  (generator of order-q subgroup)
export const TOY_G = 9n;

// Small safe prime for CDH brute-force demo (q ≈ 2^20):
// p = 2097779, q = 1048889.  Both verified prime; p = 2q + 1.
export const SMALL_P = 2097779n;
export const SMALL_Q = 1048889n;
// g = 3^2 mod p = 9;  g^q mod p = 1 ✓
export const SMALL_G = 9n;

// ── DH Protocol ──────────────────────────────────────────────────────────────

/**
 * DH Alice Step 1: Sample private exponent a, compute public value A = g^a mod p.
 * Returns { a, A }
 */
export function dhAliceStep1(p, g, q, aOverride = null) {
  const a = aOverride !== null ? BigInt(aOverride) : randomBigIntInRange(2n, q - 1n);
  const A = modPow(g, a, p);
  return { a, A };
}

/**
 * DH Bob Step 1: Sample private exponent b, compute public value B = g^b mod p.
 * Returns { b, B }
 */
export function dhBobStep1(p, g, q, bOverride = null) {
  const b = bOverride !== null ? BigInt(bOverride) : randomBigIntInRange(2n, q - 1n);
  const B = modPow(g, b, p);
  return { b, B };
}

/**
 * DH Alice Step 2: Compute shared secret K = B^a mod p.
 */
export function dhAliceStep2(a, B, p) {
  return modPow(B, a, p);
}

/**
 * DH Bob Step 2: Compute shared secret K = A^b mod p.
 */
export function dhBobStep2(b, A, p) {
  return modPow(A, b, p);
}

/**
 * Full DH exchange: Both parties compute the shared secret.
 * Returns { alice: { a, A, K }, bob: { b, B, K }, match }
 */
export function dhExchange(p, g, q, aOverride = null, bOverride = null) {
  const alice = dhAliceStep1(p, g, q, aOverride);
  const bob = dhBobStep1(p, g, q, bOverride);
  const Ka = dhAliceStep2(alice.a, bob.B, p);
  const Kb = dhBobStep2(bob.b, alice.A, p);
  return {
    alice: { a: alice.a, A: alice.A, K: Ka },
    bob: { b: bob.b, B: bob.B, K: Kb },
    match: Ka === Kb,
  };
}

// ── MITM Attack ──────────────────────────────────────────────────────────────

/**
 * MITM attack: Eve intercepts the key exchange.
 *
 * Eve samples her own exponent e, sends g^e to both Alice and Bob.
 * Alice thinks she's talking to Bob but shares K_AE = g^(a·e) with Eve.
 * Bob thinks he's talking to Alice but shares K_BE = g^(b·e) with Eve.
 *
 * Returns {
 *   alice: { a, A, K_AE },  // Alice's view
 *   bob:   { b, B, K_BE },  // Bob's view
 *   eve:   { e, E, K_AE, K_BE },  // Eve's knowledge
 *   aliceBobMatch: false,
 * }
 */
export function mitmAttack(p, g, q, aOverride = null, bOverride = null) {
  const alice = dhAliceStep1(p, g, q, aOverride);
  const bob = dhBobStep1(p, g, q, bOverride);

  // Eve intercepts and generates her own key pair
  const e = randomBigIntInRange(2n, q - 1n);
  const E = modPow(g, e, p);

  // Eve intercepts A from Alice, sends E to Bob instead
  // Eve intercepts B from Bob, sends E to Alice instead

  // Alice computes K = E^a mod p (she thinks E is Bob's public value)
  const K_AE = modPow(E, alice.a, p);

  // Bob computes K = E^b mod p (he thinks E is Alice's public value)
  const K_BE = modPow(E, bob.b, p);

  // Eve can compute both:
  // K_AE = A^e mod p  (shared with Alice)
  const eveK_AE = modPow(alice.A, e, p);
  // K_BE = B^e mod p  (shared with Bob)
  const eveK_BE = modPow(bob.B, e, p);

  return {
    alice: { a: alice.a, A: alice.A, K: K_AE },
    bob: { b: bob.b, B: bob.B, K: K_BE },
    eve: {
      e,
      E,
      K_AE: eveK_AE,
      K_BE: eveK_BE,
      matchAlice: K_AE === eveK_AE,
      matchBob: K_BE === eveK_BE,
    },
    aliceBobMatch: K_AE === K_BE,  // Should be false!
  };
}

// ── CDH Hardness Demo ────────────────────────────────────────────────────────

/**
 * Brute-force CDH: Given g^a and g^b (and g, p, q), try to find g^(ab) mod p
 * by trying all possible exponents. This demonstrates the computational hardness.
 *
 * For small q (≈ 2^20), this is feasible but takes time.
 * Returns { found, gab, a, attempts, timeMs }
 */
export function cdhBruteForce(p, g, q, ga, gb, maxAttempts = 1_100_000) {
  const t0 = performance.now();
  let attempts = 0;
  // Try to find x such that g^x = ga, then compute gb^x = g^(bx) = g^(ab)
  for (let x = 1n; x < q && attempts < maxAttempts; x++, attempts++) {
    if (modPow(g, x, p) === ga) {
      // Found a! Now compute g^(ab) = gb^a
      const gab = modPow(gb, x, p);
      const timeMs = performance.now() - t0;
      return { found: true, gab, a: x, attempts, timeMs };
    }
  }
  const timeMs = performance.now() - t0;
  return { found: false, gab: null, a: null, attempts, timeMs };
}

/**
 * Async CDH brute-force that yields to the event loop.
 */
export async function cdhBruteForceAsync(p, g, q, ga, gb, onProgress, maxAttempts = 1_100_000) {
  const t0 = performance.now();
  const YIELD_EVERY = 10000;
  let attempts = 0;

  for (let x = 1n; x < q && attempts < maxAttempts; x++, attempts++) {
    if (modPow(g, x, p) === ga) {
      const gab = modPow(gb, x, p);
      const timeMs = performance.now() - t0;
      return { found: true, gab, a: x, attempts, timeMs };
    }
    if (attempts % YIELD_EVERY === 0 && attempts > 0) {
      if (onProgress) onProgress(attempts);
      await new Promise(r => setTimeout(r, 0));
    }
  }
  const timeMs = performance.now() - t0;
  return { found: false, gab: null, a: null, attempts, timeMs };
}

// ── Re-export modPow for convenience ─────────────────────────────────────────
export { modPow };

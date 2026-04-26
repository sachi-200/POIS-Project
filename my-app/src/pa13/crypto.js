// ═══════════════════════════════════════════════════════════════════════════════
// PA #13 — Miller-Rabin Primality Testing
//
// Implements:
//   1. miller_rabin(n, k)  — probabilistic primality test
//   2. gen_prime(bits)     — random prime generation
//   3. Carmichael demo     — 561 vs Fermat/Miller-Rabin
//   4. Performance bench   — average candidates for 512/1024/2048-bit primes
//   5. Interface:  is_prime(n) -> bool,  gen_prime(bits) -> bigint
//
// All arithmetic uses native BigInt; modular exponentiation is square-and-multiply.
// ═══════════════════════════════════════════════════════════════════════════════

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Modular exponentiation via square-and-multiply.
 * Returns base^exp mod m   (all BigInt).
 */
export function modPow(base, exp, m) {
  if (m === 1n) return 0n;
  let result = 1n;
  base = ((base % m) + m) % m;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % m;
    exp >>= 1n;
    base = (base * base) % m;
  }
  return result;
}

/**
 * Generate a cryptographically random BigInt in [lo, hi] (inclusive).
 * Falls back to Math.random when crypto.getRandomValues is unavailable.
 */
function randomBigIntInRange(lo, hi) {
  if (hi <= lo) return lo;
  const range = hi - lo + 1n;
  const bits = range.toString(2).length;
  const bytes = Math.ceil(bits / 8);
  // rejection sampling to avoid modulo bias
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
    // mask to exactly `bits` bits
    const mask = (1n << BigInt(bits)) - 1n;
    r = r & mask;
    if (r < range) return lo + r;
  }
  // should never happen, but safe fallback
  return lo + (range >> 1n);
}

// ── Miller-Rabin Test ────────────────────────────────────────────────────────

/**
 * Run one Miller-Rabin witness check for witness `a` against odd n > 2.
 * Returns { witness: a, composite: bool, values: [...] }
 *   where `values` contains x at each squaring step (for the demo log).
 */
export function millerRabinWitness(n, a) {
  // write n - 1 = 2^s · d  with d odd
  let s = 0n;
  let d = n - 1n;
  while ((d & 1n) === 0n) { s++; d >>= 1n; }

  let x = modPow(a, d, n);
  const values = [{ label: `a^d mod n`, value: x }];

  if (x === 1n || x === n - 1n) {
    return { witness: a, composite: false, values, s, d };
  }

  for (let r = 1n; r < s; r++) {
    x = (x * x) % n;
    values.push({ label: `x² mod n (r=${r})`, value: x });
    if (x === n - 1n) {
      return { witness: a, composite: false, values, s, d };
    }
  }

  return { witness: a, composite: true, values, s, d };
}

/**
 * miller_rabin(n, k)
 *   n — odd integer > 2 (BigInt)
 *   k — number of rounds (integer)
 * Returns { prime: bool, rounds: [witnessInfo, ...], s, d }
 */
export function millerRabin(n, k = 40) {
  n = BigInt(n);
  if (n < 2n) return { prime: false, rounds: [], reason: "n < 2" };
  if (n === 2n || n === 3n) return { prime: true, rounds: [], reason: "small prime" };
  if ((n & 1n) === 0n) return { prime: false, rounds: [], reason: "even" };

  const rounds = [];
  for (let i = 0; i < k; i++) {
    const a = randomBigIntInRange(2n, n - 2n);
    const info = millerRabinWitness(n, a);
    rounds.push(info);
    if (info.composite) {
      return { prime: false, rounds, s: info.s, d: info.d };
    }
  }
  return { prime: true, rounds, s: rounds[0]?.s, d: rounds[0]?.d };
}

// ── Fermat Test (naïve, for Carmichael demo) ─────────────────────────────────

/**
 * GCD for BigInt.
 */
function bigGcd(a, b) {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b > 0n) { const t = b; b = a % b; a = t; }
  return a;
}

/**
 * Naïve Fermat primality test: a^(n-1) ≡ 1 (mod n) for k random bases
 * that are coprime to n. Carmichael numbers fool this test because
 * a^(n-1) ≡ 1 (mod n) for ALL a coprime to n when n is Carmichael.
 */
export function fermatTest(n, k = 20) {
  n = BigInt(n);
  if (n < 2n) return { prime: false, rounds: [] };
  if (n === 2n || n === 3n) return { prime: true, rounds: [] };
  if ((n & 1n) === 0n) return { prime: false, rounds: [] };

  const rounds = [];
  let found = 0;
  let attempts = 0;
  while (found < k && attempts < k * 10) {
    attempts++;
    const a = randomBigIntInRange(2n, n - 2n);
    // Fermat test only considers bases coprime to n
    if (bigGcd(a, n) !== 1n) continue;
    const result = modPow(a, n - 1n, n);
    const pass = result === 1n;
    rounds.push({ witness: a, result, pass });
    found++;
    if (!pass) return { prime: false, rounds };
  }
  return { prime: true, rounds };
}

// ── Interface functions ──────────────────────────────────────────────────────

/**
 * is_prime(n) → bool
 * Uses Miller-Rabin with k = 40 rounds.
 */
export function isPrime(n) {
  return millerRabin(n, 40).prime;
}

/**
 * gen_prime(bits) → { prime, candidates, timeMs }
 * Generates a random b-bit probable prime (k=40).
 * Verifies with 100 rounds as sanity check.
 */
export function genPrime(bits) {
  const lo = 1n << BigInt(bits - 1);         // 2^(bits-1)
  const hi = (1n << BigInt(bits)) - 1n;      // 2^bits - 1
  let candidates = 0;
  const t0 = performance.now();

  while (true) {
    let n = randomBigIntInRange(lo, hi);
    // make sure it's odd
    n = n | 1n;
    candidates++;

    if (millerRabin(n, 40).prime) {
      // sanity check with 100 rounds
      const sanity = millerRabin(n, 100);
      const timeMs = performance.now() - t0;
      return { prime: n, candidates, timeMs, bits, sanityPass: sanity.prime };
    }
  }
}

/**
 * Async wrapper for genPrime that yields to the event loop every N candidates.
 */
export async function genPrimeAsync(bits, onProgress) {
  const lo = 1n << BigInt(bits - 1);
  const hi = (1n << BigInt(bits)) - 1n;
  let candidates = 0;
  const t0 = performance.now();
  const YIELD_EVERY = 10;

  while (true) {
    let n = randomBigIntInRange(lo, hi);
    n = n | 1n;
    candidates++;

    if (millerRabin(n, 40).prime) {
      const sanity = millerRabin(n, 100);
      const timeMs = performance.now() - t0;
      return { prime: n, candidates, timeMs, bits, sanityPass: sanity.prime };
    }

    if (candidates % YIELD_EVERY === 0) {
      if (onProgress) onProgress(candidates);
      await new Promise(r => setTimeout(r, 0));
    }
  }
}

// ── Carmichael Demo ──────────────────────────────────────────────────────────

/** Well-known Carmichael numbers for the demo. */
export const CARMICHAEL_NUMBERS = [561n, 1105n, 1729n, 2465n, 2821n];

/**
 * Run both Fermat and Miller-Rabin on a Carmichael number to show
 * that Fermat is fooled but Miller-Rabin catches it.
 */
export function carmichaelDemo(n = 561n) {
  n = BigInt(n);
  const fermat = fermatTest(n, 20);
  const mr = millerRabin(n, 20);
  return {
    n,
    fermat,
    millerRabin: mr,
    fermatSaysPrime: fermat.prime,
    mrSaysPrime: mr.prime,
  };
}

// ── Performance Benchmark ────────────────────────────────────────────────────

/**
 * Run a prime-generation benchmark for the given bit-size.
 * Returns { bits, prime, candidates, timeMs, theoreticalCandidates }.
 */
export async function benchmarkPrimeGen(bits, onProgress) {
  const result = await genPrimeAsync(bits, onProgress);
  // theoretical expected candidates ~ ln(2^bits) = bits * ln(2)
  const theoreticalCandidates = Math.round(bits * Math.LN2);
  return {
    ...result,
    theoreticalCandidates,
    ratio: (result.candidates / theoreticalCandidates).toFixed(2),
  };
}

// ── Pre-loaded examples ──────────────────────────────────────────────────────

// A well-known safe prime  p = 2q+1 where q is also prime
// This is the 512-bit MODP group prime from RFC 2409 (IKE Group 1)
export const KNOWN_512_PRIME = BigInt(
  "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
  "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
);

// A known odd composite for testing (product of two primes)
export const KNOWN_COMPOSITE = 1000000007n * 1000000009n;  // 1000000016000000063n

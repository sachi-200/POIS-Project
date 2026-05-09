/**
 * PA19 — Secure AND Gate
 * ============================================================
 * Implements:
 *   • 1-of-2 Oblivious Transfer (PA18 subroutine, RSA-based)
 *   • Secure_AND(a, b)  — via OT
 *   • Secure_XOR(a, b)  — via additive secret sharing over ℤ₂  (free)
 *   • Secure_NOT(a)     — local bit-flip on Alice's share       (free)
 *
 * Public interface for PA20 composition:
 *   AND(a, b) → bit
 *   XOR(a, b) → bit
 *   NOT(a)    → bit
 *
 * Privacy argument (informal):
 *   Secure_AND uses OT with sender messages (m₀, m₁) = (0, a).
 *   (a) BOB'S PRIVACY: Alice plays OT sender and never learns Bob's choice bit b.
 *       This is the OT sender-privacy guarantee: the sender sees only the
 *       blinded value v = (x_b + k^e) mod n and cannot distinguish which
 *       x_i Bob chose without solving RSA (recovering d).
 *   (b) ALICE'S PRIVACY: Bob receives exactly m_b = a·b. He already knows b,
 *       so he learns a only when b = 1. When b = 0 he gets m₀ = 0, revealing
 *       nothing about a. The OT receiver-privacy guarantee ensures Bob cannot
 *       decrypt m_{1-b} (he would need (v - x_{1-b})^d which requires d).
 *
 * OT Protocol (Even-Goldreich-Lempel, educational RSA variant):
 *   STEP 1  Alice → Bob  : (n, e, x₀, x₁)   — public key + random challenges
 *   STEP 2  Bob → Alice  : v                  — blinded choice
 *   STEP 3  Alice → Bob  : (ε₀, ε₁)          — doubly-encrypted messages
 *   STEP 4  Bob decrypts : m_b = ε_b ⊕ lsb(k)
 */

// ============================================================
// BigInt modular arithmetic helpers
// ============================================================

/** Fast modular exponentiation with BigInt. */
export function modpow(base, exp, mod) {
  base = BigInt(base);
  exp  = BigInt(exp);
  mod  = BigInt(mod);
  let result = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp  >>= 1n;
    base  = (base * base) % mod;
  }
  return result;
}

/** Extended-Euclidean GCD. */
function gcd(a, b) {
  a = BigInt(a); b = BigInt(b);
  while (b) { [a, b] = [b, a % b]; }
  return a;
}

/** Modular multiplicative inverse via extended Euclidean algorithm. */
export function modInverse(a, m) {
  a = BigInt(a); m = BigInt(m);
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return ((old_s % m) + m) % m;
}

// ============================================================
// Small prime pool (educational — keeps numbers human-readable)
// ============================================================

const SMALL_PRIMES = [
  101n, 103n, 107n, 109n, 113n, 127n, 131n, 137n, 139n, 149n,
  151n, 157n, 163n, 167n, 173n, 179n, 181n, 191n, 193n, 197n,
  199n, 211n, 223n, 227n, 229n, 233n, 239n, 241n, 251n, 257n,
];

function randomPrime(exclude = null) {
  const pool = exclude ? SMALL_PRIMES.filter(p => p !== exclude) : SMALL_PRIMES;
  return pool[Math.floor(Math.random() * pool.length)];
}

function randomInZn(n) {
  // Uniform in [2, n-2] to avoid degenerate cases
  const maxNum = Number(n) - 3;
  return BigInt(2 + Math.floor(Math.random() * maxNum));
}

// ============================================================
// OT Step 1 — Alice's setup
// ============================================================
/**
 * Alice generates an RSA key pair and two random challenges x₀, x₁.
 * Returns private key (kept by Alice) and public params (sent to Bob).
 */
export function otStep1_AliceSetup() {
  const p = randomPrime();
  let q = randomPrime(p);
  // Guarantee distinct primes
  while (q === p) q = randomPrime(p);

  const n   = p * q;
  const phi = (p - 1n) * (q - 1n);

  // Find smallest odd e coprime with φ(n)
  let e = 3n;
  while (gcd(e, phi) !== 1n) e += 2n;

  const d  = modInverse(e, phi);
  const x0 = randomInZn(n);
  const x1 = randomInZn(n);

  return {
    /** Kept private by Alice */
    privateKey: { p, q, n, phi, e, d },
    /** Sent to Bob in Step 1 */
    publicParams: { n, e, x0, x1 },
  };
}

// ============================================================
// OT Step 2 — Bob blinds his choice
// ============================================================
/**
 * Bob picks random k, computes v = (x_b + k^e) mod n, and sends v.
 * k is Bob's secret blinding factor — never sent to Alice.
 *
 * @param {object} publicParams  — Alice's public parameters
 * @param {0|1}    b             — Bob's choice bit
 */
export function otStep2_BobBlind(publicParams, b) {
  const { n, e, x0, x1 } = publicParams;
  const xb = b === 0 ? x0 : x1;

  const k  = randomInZn(n);
  const ke = modpow(k, e, n);
  const v  = (xb + ke) % n;

  return {
    /** Bob sends this to Alice */
    v,
    /** Bob keeps this secret */
    k_secret: k,
  };
}

// ============================================================
// OT Step 3 — Alice encrypts both messages
// ============================================================
/**
 * Alice computes candidate blinding keys:
 *   k₀ = (v − x₀)^d mod n
 *   k₁ = (v − x₁)^d mod n
 * Then encrypts: εᵢ = mᵢ ⊕ lsb(kᵢ)
 *
 * Only one of {k₀, k₁} equals Bob's true k; the other is pseudorandom.
 */
export function otStep3_AliceEncrypt(privateKey, publicParams, v, m0, m1) {
  const { d, n } = privateKey;
  const { x0, x1 } = publicParams;

  const diff0 = ((v - x0) % n + n) % n;
  const diff1 = ((v - x1) % n + n) % n;

  const k0 = modpow(diff0, d, n);
  const k1 = modpow(diff1, d, n);

  const lsb0 = Number(k0 % 2n);
  const lsb1 = Number(k1 % 2n);

  const e0 = m0 ^ lsb0;
  const e1 = m1 ^ lsb1;

  return {
    /** Sent to Bob */
    e0,
    e1,
    /** For educational display only — Alice would NOT share these */
    _k0: k0,
    _k1: k1,
  };
}

// ============================================================
// OT Step 4 — Bob decrypts his message
// ============================================================
/**
 * Bob decrypts: m_b = ε_b ⊕ lsb(k)
 * Because k_b = (v − x_b)^d = (k^e)^d = k  (RSA correctness)
 */
export function otStep4_BobDecrypt(e0, e1, k_secret, b) {
  const lsb_k = Number(k_secret % 2n);
  const eb    = b === 0 ? e0 : e1;
  return eb ^ lsb_k;
}

// ============================================================
// Full OT execution (returns detailed transcript)
// ============================================================
/**
 * Runs a complete 1-of-2 OT.
 * Alice sends (m₀, m₁); Bob chooses b; Bob receives m_b.
 *
 * @returns {{ result, transcript, steps, aliceView, bobView }}
 */
export function runOT(m0, m1, b) {
  // --- Step 1 ---
  const { privateKey, publicParams } = otStep1_AliceSetup();

  // --- Step 2 ---
  const { v, k_secret } = otStep2_BobBlind(publicParams, b);

  // --- Step 3 ---
  const { e0, e1, _k0, _k1 } = otStep3_AliceEncrypt(privateKey, publicParams, v, m0, m1);

  // --- Step 4 ---
  const result = otStep4_BobDecrypt(e0, e1, k_secret, b);

  return {
    result,

    /** Wire-level transcript — what an eavesdropper sees */
    transcript: {
      step1_AliceToBob: {
        n:  publicParams.n.toString(),
        e:  publicParams.e.toString(),
        x0: publicParams.x0.toString(),
        x1: publicParams.x1.toString(),
      },
      step2_BobToAlice: {
        v: v.toString(),
      },
      step3_AliceToBob: {
        e0: e0.toString(),
        e1: e1.toString(),
      },
    },

    /** Internals shown only for educational inspection */
    steps: [
      {
        label: 'Step 1 — Alice → Bob',
        desc:  'Alice generates RSA keys and two random challenges.',
        detail: `n = ${publicParams.n}  (= ${privateKey.p} × ${privateKey.q})\n` +
                `e = ${publicParams.e},  d = [secret]\n` +
                `x₀ = ${publicParams.x0},  x₁ = ${publicParams.x1}`,
      },
      {
        label: 'Step 2 — Bob → Alice',
        desc:  `Bob (choice b = ${b}) picks random k and blinds x_b.`,
        detail: `k  = [secret: ${k_secret}]\n` +
                `v  = (x_${b} + k^e) mod n\n` +
                `v  = ${v}   ← sent to Alice`,
      },
      {
        label: 'Step 3 — Alice → Bob',
        desc:  'Alice computes candidate keys and encrypts both messages.',
        detail: `k₀ = (v−x₀)^d mod n = ${_k0}   lsb = ${Number(_k0 % 2n)}\n` +
                `k₁ = (v−x₁)^d mod n = ${_k1}   lsb = ${Number(_k1 % 2n)}\n` +
                `ε₀ = m₀ ⊕ lsb(k₀) = ${m0} ⊕ ${Number(_k0 % 2n)} = ${e0}\n` +
                `ε₁ = m₁ ⊕ lsb(k₁) = ${m1} ⊕ ${Number(_k1 % 2n)} = ${e1}`,
      },
      {
        label: 'Step 4 — Bob decrypts',
        desc:  `Bob uses his secret k to recover m_${b}.`,
        detail: `lsb(k) = ${Number(k_secret % 2n)}\n` +
                `m_${b} = ε_${b} ⊕ lsb(k) = ${b === 0 ? e0 : e1} ⊕ ${Number(k_secret % 2n)} = ${result}`,
      },
    ],

    /** What each party actually knows */
    aliceView: {
      knows:    [`m₀ = ${m0}`, `m₁ = ${m1}`, `v (blinded) = ${v}`],
      doesNot:  [`b (Bob's choice)`, `k (Bob's blinding factor)`],
    },
    bobView: {
      knows:    [`b = ${b}`, `m_b = ${result}`],
      doesNot:  [`m_${1 - b} (the other message)`, `d (Alice's RSA private key)`],
    },
  };
}

// ============================================================
// Secure AND via OT
// ============================================================
/**
 * Secure_AND(a, b):
 *   Alice is OT sender with (m₀, m₁) = (0, a)
 *   Bob   is OT receiver with choice bit b
 *   Bob receives m_b = 0·(1−b) + a·b = a ∧ b
 *
 * Both parties output a ∧ b.
 *
 * Privacy:
 *   • Bob learns only m_b. He cannot learn m_{1-b} (OT receiver-privacy).
 *     - If b=0 → he gets 0 (learns nothing about a).
 *     - If b=1 → he gets a (but he was always going to learn a∧b = a).
 *   • Alice learns nothing about b (OT sender-privacy).
 */
export function secureAND(a, b) {
  const ot = runOT(0, a, b);          // m₀=0, m₁=a
  const result = ot.result;           // = a ∧ b
  return {
    result,
    otDetail: ot,
    description: `Secure AND: Alice set OT messages (m₀=0, m₁=${a}). ` +
                 `Bob chose b=${b} → received m_${b} = ${result} = ${a} ∧ ${b}.`,
  };
}

// ============================================================
// Secure XOR — additive secret sharing over ℤ₂  (no OT needed)
// ============================================================
/**
 * Secure_XOR(a, b):
 *   Alice samples r ← {0,1} uniformly at random.
 *   Alice sends r to Bob.
 *   Alice's share:  sₐ = a ⊕ r
 *   Bob's share:    s_b = b ⊕ r    (Bob XORs his own bit with Alice's r)
 *   Output = sₐ ⊕ s_b = (a ⊕ r) ⊕ (b ⊕ r) = a ⊕ b  ✓
 *
 * Privacy: Alice sees only r (uniform). Bob sees only r and his own b.
 * Neither party learns the other's bit from the transcript alone.
 */
export function secureXOR(a, b) {
  const r      = Math.round(Math.random());   // r ∈ {0, 1}
  const shareA = a ^ r;                       // Alice's local share
  const shareB = b ^ r;                       // Bob's local share
  const result = shareA ^ shareB;             // a ⊕ b

  return {
    result,
    r,
    shareA,
    shareB,
    transcript: { r_sent_to_bob: r },
    steps: [
      {
        label:  'Step 1 — Alice samples r',
        detail: `r = ${r}   (random bit, sent to Bob)`,
      },
      {
        label:  'Step 2 — Shares computed locally',
        detail: `Alice's share: sₐ = a ⊕ r = ${a} ⊕ ${r} = ${shareA}\n` +
                `Bob's share:   s_b = b ⊕ r = ${b} ⊕ ${r} = ${shareB}`,
      },
      {
        label:  'Step 3 — Output reconstruction',
        detail: `sₐ ⊕ s_b = ${shareA} ⊕ ${shareB} = ${result} = ${a} ⊕ ${b}  ✓`,
      },
    ],
    aliceView: {
      knows:   [`a = ${a}`, `r = ${r}`, `sₐ = ${shareA}`],
      doesNot: [`b (Bob's bit)`],
    },
    bobView: {
      knows:   [`b = ${b}`, `r = ${r}`, `s_b = ${shareB}`],
      doesNot: [`a (Alice's bit)`],
    },
  };
}

// ============================================================
// Secure NOT — local, zero communication
// ============================================================
/**
 * Secure_NOT(a):
 *   If a is held as Alice's share sₐ (with implicit Bob share 0),
 *   Alice locally computes sₐ' = 1 ⊕ sₐ. No communication needed.
 *   NOT(a) = 1 ⊕ a.
 */
export function secureNOT(a) {
  return a ^ 1;
}

// ============================================================
// Clean PA20-composable interface
// ============================================================
/** AND(a, b) → bit  (uses OT internally) */
export const AND = (a, b) => secureAND(a, b).result;

/** XOR(a, b) → bit  (uses secret sharing, no OT) */
export const XOR = (a, b) => secureXOR(a, b).result;

/** NOT(a) → bit  (local flip, no communication) */
export const NOT = (a)    => secureNOT(a);

// ============================================================
// Truth-table verification (50 runs per combination)
// ============================================================
/**
 * Runs `runs` repetitions for every (a, b) ∈ {0,1}² and confirms:
 *   • AND output always equals a & b
 *   • XOR output always equals a ^ b
 *
 * @param {number} runs — default 50
 * @returns {Array<{a, b, expectedAND, expectedXOR, andPasses, xorPasses, andOk, xorOk}>}
 */
export function runTruthTableTests(runs = 50) {
  const results = [];
  for (const a of [0, 1]) {
    for (const b of [0, 1]) {
      let andPasses = 0, xorPasses = 0;
      for (let i = 0; i < runs; i++) {
        if (AND(a, b) === (a & b)) andPasses++;
        if (XOR(a, b) === (a ^ b)) xorPasses++;
      }
      results.push({
        a,
        b,
        expectedAND: a & b,
        expectedXOR: a ^ b,
        andPasses,
        xorPasses,
        andOk: andPasses === runs,
        xorOk: xorPasses === runs,
      });
    }
  }
  return results;
}

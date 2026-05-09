// ═══════════════════════════════════════════════════════════════════════════════
// PA #18 — Oblivious Transfer (OT)
//
// Implements a 1-out-of-2 Bellare–Micali Oblivious Transfer protocol built
// entirely on top of PA #16 ElGamal.  No external crypto libraries are used.
//
// Protocol overview (Bellare–Micali from PKC):
//   Step 1  [Receiver, input b ∈ {0,1}]:
//           • Generate one honest key-pair (pk_b, sk_b) via ElGamal KeyGen.
//           • Construct pk_{1-b} by sampling a *random* group element as the
//             public key h — there is no corresponding secret key.
//           • Send (pk_0, pk_1) to Sender; keep sk_b private.
//   Step 2  [Sender, input (pk_0, pk_1, m_0, m_1)]:
//           • Encrypt m_0 under pk_0 → C_0 = Enc_{pk_0}(m_0)
//           • Encrypt m_1 under pk_1 → C_1 = Enc_{pk_1}(m_1)
//           • Send (C_0, C_1) to Receiver.
//   Step 3  [Receiver]:
//           • Decrypt C_b using sk_b → m_b.
//           • Cannot decrypt C_{1-b}: no sk_{1-b} exists.
//
// Security:
//   Receiver privacy  — (pk_0, pk_1) sent to Sender look identical whether
//                       or not a trapdoor exists; Sender cannot tell which key
//                       is "real" under DDH.
//   Sender privacy    — Receiver has no sk_{1-b}; decrypting C_{1-b} requires
//                       solving DLP (computing discrete log of a random h).
// ═══════════════════════════════════════════════════════════════════════════════

import {
  DEFAULT_GROUP,
  mod,
  randomBigIntInRange,
  elgamalKeygen,
  elgamalEncrypt,
  elgamalDecrypt,
  parseMessageRepresentative,
  representativeToMaybeText,
  truncMiddle,
  bigintToHex,
} from "../pa16/crypto.js";

// Re-export PA#16 helpers so PA#19 can import everything from one place.
export {
  DEFAULT_GROUP,
  mod,
  randomBigIntInRange,
  elgamalKeygen,
  elgamalEncrypt,
  elgamalDecrypt,
  parseMessageRepresentative,
  representativeToMaybeText,
  truncMiddle,
  bigintToHex,
};

// ── Group from PA#11 (via PA#16) ─────────────────────────────────────────────

export const OT_GROUP = DEFAULT_GROUP;

// ── Utility: sample a random subgroup element without knowing discrete log ───
//
// We pick r ← Z_q and output g^r mod p.  This is indistinguishable from an
// honest public key h = g^x mod p under the DDH assumption, but we throw away
// r so no private key is retained.

function randomSubgroupElement(group = OT_GROUP) {
  const { p, q, g } = group;
  const r = randomBigIntInRange(2n, q - 1n);
  // We deliberately do NOT keep r — there is no associated secret key.
  const { modPow } = (() => {
    // Inline modPow to keep the import surface small.
    function modPow(base, exp, mod) {
      base = ((BigInt(base) % BigInt(mod)) + BigInt(mod)) % BigInt(mod);
      exp  = BigInt(exp);
      mod  = BigInt(mod);
      let result = 1n;
      while (exp > 0n) {
        if (exp & 1n) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1n;
      }
      return result;
    }
    return { modPow };
  })();
  return modPow(g, r, p);
}

// ── Three-step OT API ─────────────────────────────────────────────────────────

/**
 * OT_Receiver_Step1(b) → { pk0, pk1, state }
 *
 * Receiver runs before seeing Sender's messages.  Returns:
 *   pk0, pk1   — two public keys to send to Sender
 *   state      — opaque blob kept by Receiver for Step 3
 *                (contains b and sk_b; never revealed to Sender)
 */
export function OT_Receiver_Step1(b, group = OT_GROUP) {
  if (b !== 0 && b !== 1) throw new Error("Choice bit b must be 0 or 1");

  // Honest key pair for the chosen index.
  const honestKeys = elgamalKeygen(group);

  // Trapdoor-free public key for the other index:
  // pick a random group element; nobody knows its discrete log.
  const trapFreeH = randomSubgroupElement(group);
  const trapFreePk = { p: group.p, q: group.q, g: group.g, h: trapFreeH };

  const pk0 = b === 0 ? honestKeys.pk : trapFreePk;
  const pk1 = b === 1 ? honestKeys.pk : trapFreePk;

  return {
    pk0,
    pk1,
    state: {
      b,
      sk: honestKeys.sk,           // sk for pk_b; sk_{1-b} was never created
      honestPkH: honestKeys.pk.h,  // for display / verification
      trapFreeH,                   // for display
    },
  };
}

/**
 * OT_Sender_Step(pk0, pk1, m0, m1) → { C0, C1, m0Rep, m1Rep }
 *
 * Sender knows nothing about b; encrypts both messages independently.
 */
export function OT_Sender_Step(pk0, pk1, m0Value, m1Value) {
  const m0 = parseMessageRepresentative(m0Value, pk0.p);
  const m1 = parseMessageRepresentative(m1Value, pk1.p);

  const C0 = elgamalEncrypt(pk0, m0);
  const C1 = elgamalEncrypt(pk1, m1);

  return { C0, C1, m0Rep: m0, m1Rep: m1 };
}

/**
 * OT_Receiver_Step2(state, C0, C1) → { mb, mbText, decrypted }
 *
 * Receiver decrypts exactly C_b; C_{1-b} is left alone.
 */
export function OT_Receiver_Step2(state, C0, C1) {
  const { b, sk } = state;
  const targetC = b === 0 ? C0 : C1;
  const { m, sharedMask, inverseMask } = elgamalDecrypt(sk, targetC);
  return {
    b,
    mb: m,
    mbText: representativeToMaybeText(m),
    decrypted: { m, sharedMask, inverseMask },
  };
}

// ── Full single-run helper (useful for testing and PA#19) ────────────────────

export function runOT(b, m0Value, m1Value, group = OT_GROUP) {
  const { pk0, pk1, state }   = OT_Receiver_Step1(b, group);
  const { C0, C1, m0Rep, m1Rep } = OT_Sender_Step(pk0, pk1, m0Value, m1Value);
  const result                = OT_Receiver_Step2(state, C0, C1);

  return { pk0, pk1, state, C0, C1, m0Rep, m1Rep, result };
}

// ── Correctness test: 100 random trials ──────────────────────────────────────

export function runCorrectnessTest(group = OT_GROUP, trials = 100) {
  // Fixed message pool; we parse once so we know the representatives.
  const messagePool = [
    "12345", "99999", "54321", "11111", "77777",
    "22222", "33333", "44444", "55555", "66666",
  ];

  let pass = 0;
  const failures = [];

  for (let i = 0; i < trials; i++) {
    const b  = Math.random() < 0.5 ? 0 : 1;
    const m0v = messagePool[Math.floor(Math.random() * messagePool.length)];
    let m1v;
    do { m1v = messagePool[Math.floor(Math.random() * messagePool.length)]; }
    while (m1v === m0v);

    try {
      const { m0Rep, m1Rep, result } = runOT(b, m0v, m1v, group);
      const expected = b === 0 ? m0Rep : m1Rep;
      if (result.mb === expected) {
        pass++;
      } else {
        failures.push({ trial: i + 1, b, m0v, m1v, expected: expected.toString(), got: result.mb.toString() });
      }
    } catch (e) {
      failures.push({ trial: i + 1, b, m0v, m1v, error: e.message });
    }
  }

  return {
    trials,
    pass,
    fail: trials - pass,
    successRate: pass / trials,
    failures: failures.slice(0, 5), // at most 5 for display
  };
}

// ── Receiver privacy demo ────────────────────────────────────────────────────
//
// Sender sees (pk0, pk1).  Both are just group elements — the trapdoor-free h
// was sampled as g^r for unknown r, so it is computationally indistinguishable
// from an honest h = g^x under DDH.  We demonstrate this by running Step 1
// for b=0 and b=1 and showing that the h values in pk0, pk1 have the same
// statistical profile (both look like uniform random group elements).

export function receiverPrivacyDemo(trials = 20, group = OT_GROUP) {
  const samples = [];
  for (let i = 0; i < trials; i++) {
    const b = i % 2 === 0 ? 0 : 1;
    const { pk0, pk1, state } = OT_Receiver_Step1(b, group);
    samples.push({
      trial: i + 1,
      b,
      h0: pk0.h,
      h1: pk1.h,
      // Which is the "real" one (has a secret key)?
      realIndex: b,
      note: "Sender cannot distinguish real from trapdoor-free",
    });
  }
  return { samples };
}

// ── Sender privacy demo ──────────────────────────────────────────────────────
//
// Receiver only has sk_b.  Decrypting C_{1-b} with the wrong key yields a
// random element of the group — not m_{1-b}.  For small parameters one could
// brute-force the DLP, but with the PA#11 subgroup that is infeasible.
// We simulate a "brute-force DLP" against the toy parameters up to a budget.

export function senderPrivacyDemo(b, m0Value, m1Value, dlpBudget = 10000n, group = OT_GROUP) {
  const { pk0, pk1, state } = OT_Receiver_Step1(b, group);
  const { C0, C1, m0Rep, m1Rep } = OT_Sender_Step(pk0, pk1, m0Value, m1Value);

  // Receiver correctly decrypts C_b.
  const correctResult = OT_Receiver_Step2(state, C0, C1);

  // Now try to decrypt the other ciphertext — the receiver has NO sk_{1-b}.
  // Attempt 1: use sk_b (the wrong key). Result is a random group element.
  const wrongDec = elgamalDecrypt(state.sk, b === 0 ? C1 : C0);
  const wrongM   = wrongDec.m;

  // Attempt 2: brute-force DLP on the trapdoor-free h_{1-b} to find its
  // discrete log.  We search g^1, g^2, … up to dlpBudget.
  const targetPk = b === 0 ? pk1 : pk0;
  const { p, g } = group;
  let dlpFound = false;
  let dlpLog   = null;
  let dlpIters = 0n;

  {
    // Inline modPow to avoid a circular dep issue at module evaluation time.
    function mp(base, exp, mod) {
      base = ((BigInt(base) % BigInt(mod)) + BigInt(mod)) % BigInt(mod);
      exp  = BigInt(exp);
      mod  = BigInt(mod);
      let r = 1n;
      while (exp > 0n) {
        if (exp & 1n) r = (r * base) % mod;
        base = (base * base) % mod;
        exp >>= 1n;
      }
      return r;
    }

    let cur = BigInt(g);
    const target = BigInt(targetPk.h);
    const cap = dlpBudget < 1n ? 1n : dlpBudget;

    for (let k = 1n; k <= cap; k++) {
      dlpIters++;
      if (cur === target) {
        dlpFound = true;
        dlpLog   = k;
        break;
      }
      cur = (cur * BigInt(g)) % BigInt(p);
    }
  }

  return {
    b,
    m0Rep,
    m1Rep,
    correctMb: correctResult.mb,
    wrongDecResult: wrongM,
    wrongMatchesTarget: wrongM === (b === 0 ? m1Rep : m0Rep),
    dlpBudget,
    dlpIters,
    dlpFound,
    dlpLog,
    message: dlpFound
      ? `DLP solved in ${dlpIters} iterations — toy group is tiny! Real groups have q ≈ 2^256.`
      : `Brute-force gave up after ${dlpIters} iterations — DLP not found within budget.`,
  };
}

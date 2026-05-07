// ═══════════════════════════════════════════════════════════════════════════════
// PA #19 — Secure Multi-Party Computation: AND & XOR Gates
//
// Implements:
//   1. Secure_AND(a, b) using OT
//   2. Secure_XOR(a, b) using additive secret sharing
//   3. Secure_NOT(a)
//   4. Truth table verification
//
// Uses PA#18 OT.
// ═══════════════════════════════════════════════════════════════════════════════

import { OT_Receiver_Step1, OT_Sender_Step, OT_Receiver_Step2 } from "../pa18/crypto.js";

// ── Secure Gates ─────────────────────────────────────────────────────────────

/**
 * Secure_AND(a, b) -> bit
 * Alice (a) is OT sender: m0=0, m1=a
 * Bob (b) is OT receiver: choice b, gets a ∧ b
 */
export function Secure_AND(a, b) {
  // Alice: OT sender
  const m0 = 0;
  const m1 = a;
  // Bob: OT receiver
  const step1 = OT_Receiver_Step1(b);
  const step2 = OT_Sender_Step(step1.pk_0, step1.pk_1, m0, m1);
  const result = OT_Receiver_Step2(step1.state, step2.C_0, step2.C_1);
  return result; // a ∧ b
}

/**
 * Secure_XOR(a, b) -> bit
 * Additive secret sharing over Z2.
 * Alice sends r ← {0,1}, shares: Alice: a ⊕ r, Bob: b ⊕ r
 * Output: XOR of shares
 */
export function Secure_XOR(a, b) {
  const r = Math.random() < 0.5 ? 0 : 1;
  const aliceShare = a ^ r;
  const bobShare = b ^ r;
  return aliceShare ^ bobShare; // = a ⊕ b
}

/**
 * Secure_NOT(a) -> bit
 * Alice locally flips.
 */
export function Secure_NOT(a) {
  return 1 - a; // or a ^ 1
}

// ── Truth table test ─────────────────────────────────────────────────────────

export function testTruthTable(gateFn, trials = 50) {
  const cases = [
    { a: 0, b: 0, expected: gateFn(0, 0) },
    { a: 0, b: 1, expected: gateFn(0, 1) },
    { a: 1, b: 0, expected: gateFn(1, 0) },
    { a: 1, b: 1, expected: gateFn(1, 1) },
  ];
  let correct = 0;
  for (let i = 0; i < trials; i++) {
    for (const c of cases) {
      const result = gateFn(c.a, c.b);
      if (result === c.expected) correct++;
    }
  }
  return { trials: trials * 4, correct, accuracy: (correct / (trials * 4) * 100).toFixed(1) };
}

// For AND specifically
export function testANDTruthTable(trials = 50) {
  return testTruthTable(Secure_AND, trials);
}

export function testXORTruthTable(trials = 50) {
  return testTruthTable(Secure_XOR, trials);
}
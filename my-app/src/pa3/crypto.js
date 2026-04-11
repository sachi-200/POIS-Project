// ═══════════════════════════════════════════════════════════════════════════════
// PA #3 — CPA-Secure Symmetric Encryption
//
// Construction: C = (r, F_k(r) ⊕ m)
//   Enc(k, m): sample fresh r, output (r, F_k(r) XOR m)
//   Dec(k, (r,c)): output F_k(r) XOR c
//
// Multi-block: counter mode — F_k(r), F_k(r+1), F_k(r+2), …
// Broken variant: r = F_k(0) always — same m → same C.
// ═══════════════════════════════════════════════════════════════════════════════

import { fakeHex, seedFromHex, freshRandom, hexXOR, padHex, unpadHex, BLOCK_HEX_LEN } from "../utils/crypto.js";
import { aesPRF, ggmPRF } from "../pa2/crypto.js";

function prfBlock(keyHex, rHex, counter, prfType) {
  const cHex = ((seedFromHex(rHex) + counter) >>> 0).toString(16).padStart(8, "0");
  if (prfType === "AES") return aesPRF(keyHex, cHex);
  return ggmPRF(keyHex, (counter % 256).toString(2).padStart(8, "0")).value;
}

/** Enc(k, m) → { r, c, blocks, ciphertext } */
export function encCPA(keyHex, msgHex, prfType = "GGM", reuseNonce = false) {
  const r = reuseNonce ? prfBlock(keyHex, "00000000", 0, prfType) : freshRandom();
  const padded = padHex(msgHex);
  const blocks = [];
  let cipherHex = "";
  for (let i = 0; i < padded.length; i += BLOCK_HEX_LEN) {
    const mBlock = padded.slice(i, i + BLOCK_HEX_LEN).padEnd(BLOCK_HEX_LEN, "0");
    const keyStream = prfBlock(keyHex, r, i / BLOCK_HEX_LEN, prfType);
    const cBlock = hexXOR(mBlock, keyStream);
    blocks.push({ counter: i / BLOCK_HEX_LEN, r, mBlock, keyStream, cBlock });
    cipherHex += cBlock;
  }
  return { r, c: cipherHex, blocks, ciphertext: `${r}:${cipherHex}` };
}

/** Dec(k, r, c) → { msgHex, blocks } */
export function decCPA(keyHex, rHex, cipherHex, prfType = "GGM") {
  const blocks = [];
  let plainHex = "";
  for (let i = 0; i < cipherHex.length; i += BLOCK_HEX_LEN) {
    const cBlock = cipherHex.slice(i, i + BLOCK_HEX_LEN).padEnd(BLOCK_HEX_LEN, "0");
    const keyStream = prfBlock(keyHex, rHex, i / BLOCK_HEX_LEN, prfType);
    const mBlock = hexXOR(cBlock, keyStream);
    blocks.push({ counter: i / BLOCK_HEX_LEN, cBlock, keyStream, mBlock });
    plainHex += mBlock;
  }
  return { msgHex: unpadHex(plainHex), blocks };
}

/** One round of the IND-CPA game */
export function playCPAGameRound(keyHex, m0hex, m1hex, prfType, reuseNonce) {
  if (m0hex.length !== m1hex.length) return { error: "m₀ and m₁ must be the same length" };
  const b = Math.random() < 0.5 ? 0 : 1;
  const enc = encCPA(keyHex, b === 0 ? m0hex : m1hex, prfType, reuseNonce);
  return { b, r: enc.r, c: enc.c, ciphertext: enc.ciphertext, blocks: enc.blocks };
}

/** Dummy adversary simulation — 50 rounds */
export function runCPASimulation(keyHex, prfType, reuseNonce, rounds = 50) {
  let correct = 0;
  const log = [];
  for (let i = 0; i < rounds; i++) {
    const m0 = fakeHex(i * 0x1111, 8), m1 = fakeHex(i * 0x2222, 8);
    const round = playCPAGameRound(keyHex, m0, m1, prfType, reuseNonce);
    let guess;
    if (reuseNonce) { const testEnc = encCPA(keyHex, m0, prfType, true); guess = testEnc.c === round.c ? 0 : 1; }
    else guess = Math.random() < 0.5 ? 0 : 1;
    if (guess === round.b) correct++;
    if (i < 5) log.push({ i, m0, m1, b: round.b, guess, win: guess === round.b, c: round.ciphertext.slice(0, 20) + "…" });
  }
  return { rounds, correct, advantage: (Math.abs((correct / rounds) - 0.5) * 2).toFixed(3), log };
}

/** Demonstrate nonce-reuse attack: Enc(m) twice → C₁ = C₂ */
export function demonstrateNonceReuseAttack(keyHex, prfType) {
  const m = fakeHex(0xdeadbeef, 8);
  const enc1 = encCPA(keyHex, m, prfType, true), enc2 = encCPA(keyHex, m, prfType, true);
  return { m, ct1: enc1.ciphertext, ct2: enc2.ciphertext, detected: enc1.ciphertext === enc2.ciphertext };
}
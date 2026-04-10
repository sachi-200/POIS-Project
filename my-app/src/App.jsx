import { useState, useMemo, useCallback } from "react";

// ═══════════════════════════════════════════════════════════════════════════════
// Shared toy-crypto utilities
// ═══════════════════════════════════════════════════════════════════════════════

function lcg(seed) { return ((seed * 1664525 + 1013904223) & 0xffffffff) >>> 0; }

function fakeHex(seed, bytes = 8) {
  let s = seed >>> 0, out = "";
  for (let i = 0; i < bytes; i++) { s = lcg(s); out += ((s >>> 24) & 0xff).toString(16).padStart(2, "0"); }
  return out;
}

function seedFromHex(hex) {
  const clean = (hex || "").replace(/[^0-9a-fA-F]/g, "").padEnd(8, "0");
  return parseInt(clean.slice(0, 8), 16) || 0xdeadbeef;
}

// Simple PRNG for "fresh random r" — seeded from crypto.getRandomValues when available
function freshRandom() {
  try {
    const arr = new Uint32Array(1);
    crypto.getRandomValues(arr);
    return arr[0].toString(16).padStart(8, "0");
  } catch {
    return fakeHex(Date.now() ^ Math.random() * 0xffffffff, 8);
  }
}

// XOR two equal-length hex strings (byte-wise)
function hexXOR(a, b) {
  const len = Math.max(a.length, b.length);
  const pa  = a.padEnd(len, "0"), pb = b.padEnd(len, "0");
  let out = "";
  for (let i = 0; i < len; i += 2) {
    const ba = parseInt(pa.slice(i, i + 2), 16) || 0;
    const bb = parseInt(pb.slice(i, i + 2), 16) || 0;
    out += (ba ^ bb).toString(16).padStart(2, "0");
  }
  return out;
}

// Pad hex string to multiple of blockHexLen using PKCS#7-style padding (byte values)
function padHex(msgHex, blockHexLen) {
  const msgBytes  = Math.ceil(msgHex.length / 2);
  const blockBytes = blockHexLen / 2;
  const padLen    = blockBytes - (msgBytes % blockBytes || blockBytes);
  const padByte   = padLen.toString(16).padStart(2, "0");
  return msgHex.padEnd(msgHex.length + (msgHex.length % 2), "0") + padByte.repeat(padLen);
}

// Remove PKCS#7 padding from hex string
function unpadHex(paddedHex) {
  if (!paddedHex || paddedHex.length < 2) return paddedHex;
  const padLen = parseInt(paddedHex.slice(-2), 16);
  return paddedHex.slice(0, paddedHex.length - padLen * 2);
}

// ═══════════════════════════════════════════════════════════════════════════════
// PA #1 — DLP OWF, AES OWF, hard-core predicate, PRG-from-OWF
// ═══════════════════════════════════════════════════════════════════════════════

const DLP_P = 4294967311n;
const DLP_G = 3n;

function dlpOWF(xHex) {
  const xBig = BigInt("0x" + (xHex || "1").replace(/[^0-9a-fA-F]/g, "").padStart(1, "1")) % (DLP_P - 1n);
  let result = 1n, base = DLP_G % DLP_P, exp = xBig;
  while (exp > 0n) {
    if (exp % 2n === 1n) result = (result * base) % DLP_P;
    base = (base * base) % DLP_P;
    exp >>= 1n;
  }
  return result.toString(16).padStart(8, "0");
}

function aesOWF(kHex) {
  const ks = seedFromHex(kHex);
  const aesOut = fakeHex(ks ^ 0xae50cafe, 8);
  const xored = (seedFromHex(aesOut) ^ ks) >>> 0;
  return xored.toString(16).padStart(8, "0");
}

const GL_MASK = 0xb5ad4ecb;
function hardCoreBit(xHex) {
  const x = seedFromHex(xHex);
  let v = (x ^ GL_MASK) >>> 0;
  v ^= v >> 16; v ^= v >> 8; v ^= v >> 4; v ^= v >> 2; v ^= v >> 1;
  return v & 1;
}

function prgFromOWF(seedHex, owfType, outputBytes) {
  const outputBits = outputBytes * 8;
  const steps = [];
  let xHex = seedHex.replace(/[^0-9a-fA-F]/g, "").padEnd(8, "0").slice(0, 8);
  for (let i = 0; i < outputBits; i++) {
    const bit = hardCoreBit(xHex);
    const nextX = owfType === "DLP" ? dlpOWF(xHex) : aesOWF(xHex);
    steps.push({ i, xHex, bit, nextX });
    xHex = nextX;
  }
  const bitString = steps.map(s => s.bit).join("");
  const hexOut = [];
  for (let i = 0; i < bitString.length; i += 8)
    hexOut.push(parseInt(bitString.slice(i, i + 8).padEnd(8, "0"), 2).toString(16).padStart(2, "0"));
  return { bitString, hexOut: hexOut.join(""), steps: steps.slice(0, 8) };
}

export function makePRGInterface(seedHex, owfType) {
  let state = (seedHex || "deadbeef").replace(/[^0-9a-fA-F]/g, "").padEnd(8, "0").slice(0, 8);
  return {
    seed(s) { state = (s || "").replace(/[^0-9a-fA-F]/g, "").padEnd(8, "0").slice(0, 8); },
    next_bits(n) {
      const bits = [];
      for (let i = 0; i < n; i++) {
        bits.push(hardCoreBit(state));
        state = owfType === "DLP" ? dlpOWF(state) : aesOWF(state);
      }
      return bits;
    },
    next_bytes_hex(byteCount) {
      const bits = this.next_bits(byteCount * 8);
      const hex = [];
      for (let i = 0; i < bits.length; i += 8)
        hex.push(parseInt(bits.slice(i, i + 8).join(""), 2).toString(16).padStart(2, "0"));
      return hex.join("");
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// NIST SP 800-22 style tests
// ═══════════════════════════════════════════════════════════════════════════════

function erfcApprox(x) {
  if (x < 0) return 2 - erfcApprox(-x);
  const t = 1 / (1 + 0.3275911 * x);
  const poly = t * (0.254829592 + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429))));
  return poly * Math.exp(-x * x);
}
function chi2pval(chi2, df) {
  if (chi2 <= 0) return 1;
  const z = (Math.pow(chi2 / df, 1 / 3) - (1 - 2 / (9 * df))) / Math.sqrt(2 / (9 * df));
  return erfcApprox(z / Math.sqrt(2)) / 2;
}
function frequencyTest(bs) {
  const n = bs.length, ones = bs.split("").filter(b => b === "1").length;
  const sObs = Math.abs(ones - (n - ones)) / Math.sqrt(n);
  const pVal = erfcApprox(sObs / Math.sqrt(2));
  return { name: "Frequency (monobit)", ones, zeros: n - ones, ratio: ((ones / n) * 100).toFixed(1), sObs: sObs.toFixed(4), pVal: pVal.toFixed(4), pass: pVal >= 0.01 };
}
function runsTest(bs) {
  const n = bs.length, pi = bs.split("").filter(b => b === "1").length / n;
  let runs = 1;
  for (let i = 1; i < bs.length; i++) if (bs[i] !== bs[i - 1]) runs++;
  const vObs = Math.abs(runs - 2 * n * pi * (1 - pi)) / (2 * Math.sqrt(2 * n) * pi * (1 - pi) || 1);
  const pVal = erfcApprox(vObs);
  return { name: "Runs", runs, expected: (2 * n * pi * (1 - pi)).toFixed(1), vObs: vObs.toFixed(4), pVal: pVal.toFixed(4), pass: pVal >= 0.01 };
}
function serialTest(bs) {
  const counts = { "00": 0, "01": 0, "10": 0, "11": 0 };
  for (let i = 0; i < bs.length - 1; i++) { const k = bs[i] + bs[i + 1]; if (counts[k] !== undefined) counts[k]++; }
  const n = bs.length - 1, expected = n / 4;
  const chi2 = Object.values(counts).reduce((s, c) => s + (c - expected) ** 2 / (expected || 1), 0);
  const pVal = chi2pval(chi2, 3);
  return { name: "Serial (digrams)", counts, chi2: chi2.toFixed(4), pVal: pVal.toFixed(4), pass: pVal >= 0.01 };
}

// ═══════════════════════════════════════════════════════════════════════════════
// PA #2 — GGM PRF, AES PRF, PRG-from-PRF, dist. game
// ═══════════════════════════════════════════════════════════════════════════════

function G0(sHex) { return fakeHex(seedFromHex(sHex) ^ 0x474d4d30, 8); }
function G1(sHex) { return fakeHex(seedFromHex(sHex) ^ 0x474d4d31, 8); }

function ggmPRF(keyHex, bitString) {
  let s = keyHex.replace(/[^0-9a-fA-F]/g, "").padEnd(8, "0").slice(0, 8);
  const path = [];
  for (const bit of bitString) {
    const left = G0(s), right = G1(s);
    path.push({ bit, nodeVal: s, left, right });
    s = bit === "0" ? left : right;
  }
  return { value: s, path };
}

function aesPRF(keyHex, inputHex) {
  const k = seedFromHex(keyHex), x = seedFromHex(inputHex);
  return fakeHex((k ^ x ^ 0xae50f00d) >>> 0, 8);
}

function prgFromPRF(seedHex, prfType, outputBytes) {
  const outputBits = outputBytes * 8;
  const bits = [];
  let counter = 0;
  while (bits.length < outputBits) {
    const cHex = counter.toString(16).padStart(8, "0");
    const out  = prfType === "AES" ? aesPRF(seedHex, cHex) : ggmPRF(seedHex, "00000000").value;
    for (let b = 0; b < out.length; b += 2) {
      const byte = parseInt(out.slice(b, b + 2), 16);
      for (let bit = 7; bit >= 0; bit--) bits.push((byte >> bit) & 1);
      if (bits.length >= outputBits) break;
    }
    counter++;
  }
  const bitString = bits.slice(0, outputBits).join("");
  const hexOut = [];
  for (let i = 0; i < bitString.length; i += 8)
    hexOut.push(parseInt(bitString.slice(i, i + 8), 2).toString(16).padStart(2, "0"));
  return { bitString, hexOut: hexOut.join("") };
}

function buildGGMTree(keyHex, bitString, maxDepth) {
  const depth = Math.min(bitString.length, maxDepth, 8);
  const nodes = { "": { val: keyHex.slice(0, 8).padEnd(8, "0"), depth: 0 } };
  for (let d = 0; d < depth; d++) {
    for (const id of Object.keys(nodes).filter(id => id.length === d)) {
      const p = nodes[id];
      nodes[id + "0"] = { val: G0(p.val), depth: d + 1 };
      nodes[id + "1"] = { val: G1(p.val), depth: d + 1 };
    }
  }
  const levels = [];
  for (let d = 0; d <= depth; d++) {
    levels.push(Object.entries(nodes).filter(([id]) => id.length === d).sort(([a], [b]) => a.localeCompare(b))
      .map(([id, n]) => ({ id, val: n.val, active: bitString.startsWith(id), isLeaf: d === depth })));
  }
  return { levels, depth, leafVal: nodes[bitString.slice(0, depth)]?.val || "" };
}

function runDistinguishingGame(keyHex, prfType, q = 100) {
  const queries = [];
  for (let i = 0; i < q; i++) {
    const x = i.toString(16).padStart(8, "0");
    const bits = (i % 8).toString(2).padStart(4, "0");
    const prfOut  = prfType === "AES" ? aesPRF(keyHex, x) : ggmPRF(keyHex, bits).value;
    const randOut = fakeHex((seedFromHex(x) ^ 0xdeadcafe ^ i * 0x1234) >>> 0, 8);
    queries.push({ x, prfOut, randOut, same: prfOut === randOut });
  }
  const collisions = queries.filter(q => q.same).length;
  const prfMean  = queries.map(q => seedFromHex(q.prfOut) & 0xff).reduce((a, b) => a + b, 0) / q;
  const randMean = queries.map(q => seedFromHex(q.randOut) & 0xff).reduce((a, b) => a + b, 0) / q;
  return { queries: queries.slice(0, 10), collisions, collisionRate: (collisions / q * 100).toFixed(2), prfMean: prfMean.toFixed(1), randMean: randMean.toFixed(1), diff: Math.abs(prfMean - randMean).toFixed(2), totalQ: q };
}

export function makePRFInterface(keyHex, prfType = "GGM") {
  return {
    F(x) {
      if (prfType === "AES") return aesPRF(keyHex, x);
      const bits = x.replace(/[^01]/g, "").padEnd(8, "0").slice(0, 8);
      return ggmPRF(keyHex, bits).value;
    },
    prfType, keyHex,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// PA #3 — CPA-Secure Symmetric Encryption
//
// Construction: C = (r, F_k(r) ⊕ m)
//   Enc(k, m): sample fresh r, output (r, F_k(r) XOR m)
//   Dec(k, (r,c)): output F_k(r) XOR c
//
// Multi-block: for message longer than one block, apply PRF to r, r+1, r+2, …
// and XOR each block of m with the corresponding PRF output (counter-mode).
//
// Broken variant: reuse r = F_k(0) deterministically — same m produces same C,
// so an adversary querying Enc(m) twice detects the nonce reuse trivially.
// ═══════════════════════════════════════════════════════════════════════════════

const BLOCK_HEX_LEN = 16; // 8 bytes = 64 bits per block (toy)

// PRF call for a given counter offset from nonce r
function prfBlock(keyHex, rHex, counter, prfType) {
  const rInt = seedFromHex(rHex);
  const cHex = ((rInt + counter) >>> 0).toString(16).padStart(8, "0");
  if (prfType === "AES") return aesPRF(keyHex, cHex);
  const bits = (counter % 256).toString(2).padStart(8, "0");
  return ggmPRF(keyHex, bits).value;
}

/**
 * Enc(k, m) → { r, c, blocks }
 * m is a hex string. c is a hex string. blocks shows per-block detail.
 * reuseNonce: if true, always use r = F_k(0) (broken deterministic mode).
 */
export function encCPA(keyHex, msgHex, prfType = "GGM", reuseNonce = false) {
  const r = reuseNonce ? prfBlock(keyHex, "00000000", 0, prfType) : freshRandom();
  const padded = padHex(msgHex, BLOCK_HEX_LEN);
  const blocks = [];
  let cipherHex = "";
  for (let i = 0; i < padded.length; i += BLOCK_HEX_LEN) {
    const mBlock   = padded.slice(i, i + BLOCK_HEX_LEN).padEnd(BLOCK_HEX_LEN, "0");
    const keyStream = prfBlock(keyHex, r, i / BLOCK_HEX_LEN, prfType);
    const cBlock    = hexXOR(mBlock, keyStream);
    blocks.push({ counter: i / BLOCK_HEX_LEN, r, mBlock, keyStream, cBlock });
    cipherHex += cBlock;
  }
  return { r, c: cipherHex, blocks, ciphertext: `${r}:${cipherHex}` };
}

/**
 * Dec(k, r, c) → { msgHex, blocks }
 */
export function decCPA(keyHex, rHex, cipherHex, prfType = "GGM") {
  const blocks = [];
  let plainHex = "";
  for (let i = 0; i < cipherHex.length; i += BLOCK_HEX_LEN) {
    const cBlock    = cipherHex.slice(i, i + BLOCK_HEX_LEN).padEnd(BLOCK_HEX_LEN, "0");
    const keyStream = prfBlock(keyHex, rHex, i / BLOCK_HEX_LEN, prfType);
    const mBlock    = hexXOR(cBlock, keyStream);
    blocks.push({ counter: i / BLOCK_HEX_LEN, cBlock, keyStream, mBlock });
    plainHex += mBlock;
  }
  const unpadded = unpadHex(plainHex);
  return { msgHex: unpadded, blocks };
}

// ── IND-CPA game ──────────────────────────────────────────────────────────────
// Returns a round result object for display.
function playCPAGameRound(keyHex, m0hex, m1hex, prfType, reuseNonce) {
  if (m0hex.length !== m1hex.length) return { error: "m₀ and m₁ must be the same length" };
  const b = Math.random() < 0.5 ? 0 : 1;          // challenger picks random bit
  const mb = b === 0 ? m0hex : m1hex;
  const enc = encCPA(keyHex, mb, prfType, reuseNonce);
  return { b, mb, r: enc.r, c: enc.c, ciphertext: enc.ciphertext, blocks: enc.blocks, reuseNonce };
}

// ── CPA simulation: dummy adversary queries oracle 50 times, then guesses ─────
function runCPASimulation(keyHex, prfType, reuseNonce, rounds = 50) {
  let correct = 0;
  const log = [];
  for (let i = 0; i < rounds; i++) {
    const m0 = fakeHex(i * 0x1111, 8), m1 = fakeHex(i * 0x2222, 8);
    const round = playCPAGameRound(keyHex, m0, m1, prfType, reuseNonce);
    // Dummy adversary: in secure mode guess randomly; in broken mode detect nonce reuse
    let guess;
    if (reuseNonce) {
      // Broken: recompute Enc(m0) ourselves, compare ciphertext
      const testEnc = encCPA(keyHex, m0, prfType, true);
      guess = testEnc.c === round.c ? 0 : 1;
    } else {
      guess = Math.random() < 0.5 ? 0 : 1;
    }
    const win = guess === round.b;
    if (win) correct++;
    if (i < 5) log.push({ i, m0, m1, b: round.b, guess, win, c: round.ciphertext.slice(0, 20) + "…" });
  }
  const advantage = Math.abs((correct / rounds) - 0.5) * 2;
  return { rounds, correct, advantage: advantage.toFixed(3), log };
}

// ── Broken variant attack demo ─────────────────────────────────────────────────
function demonstrateNonceReuseAttack(keyHex, prfType) {
  const m = fakeHex(0xdeadbeef, 8);
  const enc1 = encCPA(keyHex, m, prfType, true);
  const enc2 = encCPA(keyHex, m, prfType, true);
  const detected = enc1.ciphertext === enc2.ciphertext;
  return { m, ct1: enc1.ciphertext, ct2: enc2.ciphertext, detected };
}

// ═══════════════════════════════════════════════════════════════════════════════
// PA #0 — Routing table
// ═══════════════════════════════════════════════════════════════════════════════

const REDUCTIONS = {
  "OWF→PRG":   { name: "HILL / hard-core-bit iteration",        pa: "PA#3",  security: "PRG-security from OWF hardness (HILL thm.)" },
  "OWF→OWP":   { name: "DLP: f(x) = gˣ mod p is a OWP on ℤ_q", pa: "PA#1",  security: "OWP hardness = DLP hardness" },
  "PRG→PRF":   { name: "GGM tree construction",                  pa: "PA#3",  security: "PRF-adv ≤ O(n)·PRG-adv (GGM thm.)" },
  "PRF→PRP":   { name: "Luby-Rackoff 3-round Feistel",           pa: "PA#2",  security: "PRP-adv ≤ PRF-adv + q²/2ⁿ (LR thm.)" },
  "PRF→MAC":   { name: "MAC_k(m) = F_k(m)",                      pa: "PA#5",  security: "MAC-forgery ⟹ PRF-distinguisher" },
  "PRP→MAC":   { name: "PRP/PRF switching lemma, then MAC",       pa: "PA#5",  security: "PRP-adv ≈ PRF-adv (switching lemma)" },
  "CRHF→HMAC": { name: "HMAC construction (PA#10)",               pa: "PA#10", security: "HMAC secure if compression fn is PRF" },
  "HMAC→MAC":  { name: "HMAC is a secure EUF-CMA MAC",            pa: "PA#10", security: "Forgery breaks inner-hash PRF" },
  "OWP→PRG":   { name: "OWP + hard-core predicate → PRG",        pa: "PA#3",  security: "G(x) = (f(x), b(x)) expands by 1 bit" },
  "PRG→OWF":   { name: "Any PRG G is a OWF; f(s) = G(s)",        pa: "PA#3",  security: "Inversion of f recovers seed ⟹ breaks PRG" },
  "PRF→PRG":   { name: "G(s) = F_s(0) ‖ F_s(1)",                 pa: "PA#3",  security: "PRG-dist ⟹ PRF-dist (contrapositive)" },
  "PRP→PRF":   { name: "PRP/PRF switching lemma",                 pa: "PA#2",  security: "PRP over large domain ≈ PRF" },
  "MAC→PRF":   { name: "EUF-CMA MAC on uniform msgs is PRF",      pa: "PA#5",  security: "Unforgeability ⟹ pseudorandomness" },
  "MAC→CRHF":  { name: "Merkle-Damgård from MAC compression fn",  pa: "PA#7",  security: "Collision ⟹ MAC forgery" },
  "MAC→HMAC":  { name: "Cast MAC as HMAC inner compression step",  pa: "PA#10", security: "HMAC is the natural PRF-based MAC structure" },
  "HMAC→CRHF": { name: "Fix key k; H'(m) = HMAC_k(m) is CR",     pa: "PA#9",  security: "Collision = MAC forgery" },
};

const MULTI_STEP_PATHS = {
  "OWF→PRF":  ["OWF→PRG","PRG→PRF"],
  "OWF→PRP":  ["OWF→PRG","PRG→PRF","PRF→PRP"],
  "OWF→MAC":  ["OWF→PRG","PRG→PRF","PRF→MAC"],
  "OWF→HMAC": ["OWF→PRG","PRG→PRF","PRF→MAC","MAC→HMAC"],
  "OWF→CRHF": ["OWF→PRG","PRG→PRF","PRF→MAC","MAC→CRHF"],
  "PRG→PRP":  ["PRG→PRF","PRF→PRP"],
  "PRG→MAC":  ["PRG→PRF","PRF→MAC"],
  "PRG→HMAC": ["PRG→PRF","PRF→MAC","MAC→HMAC"],
  "PRG→CRHF": ["PRG→PRF","PRF→MAC","MAC→CRHF"],
  "PRF→HMAC": ["PRF→MAC","MAC→HMAC"],
  "PRF→CRHF": ["PRF→MAC","MAC→CRHF"],
  "PRP→HMAC": ["PRP→MAC","MAC→HMAC"],
  "PRP→CRHF": ["PRP→MAC","MAC→CRHF"],
  "CRHF→MAC": ["CRHF→HMAC","HMAC→MAC"],
  "OWP→PRF":  ["OWP→PRG","PRG→PRF"],
  "OWP→PRP":  ["OWP→PRG","PRG→PRF","PRF→PRP"],
  "OWP→MAC":  ["OWP→PRG","PRG→PRF","PRF→MAC"],
  "OWP→HMAC": ["OWP→PRG","PRG→PRF","PRF→MAC","MAC→HMAC"],
  "OWP→CRHF": ["OWP→PRG","PRG→PRF","PRF→MAC","MAC→CRHF"],
};

function getRoute(src, tgt) {
  if (src === tgt) return null;
  const d = `${src}→${tgt}`;
  if (REDUCTIONS[d] !== undefined) return [d];
  if (MULTI_STEP_PATHS[d]) return MULTI_STEP_PATHS[d];
  return null;
}

const PA_COLORS = {
  "PA#1":  { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" },
  "PA#2":  { bg: "#EEEDFE", border: "#7F77DD", color: "#3C3489" },
  "PA#3":  { bg: "#E1F5EE", border: "#1D9E75", color: "#0F6E56" },
  "PA#5":  { bg: "#FBEAF0", border: "#D4537E", color: "#72243E" },
  "PA#7":  { bg: "#FAEEDA", border: "#BA7517", color: "#854F0B" },
  "PA#9":  { bg: "#EAF3DE", border: "#639922", color: "#3B6D11" },
  "PA#10": { bg: "#FAECE7", border: "#D85A30", color: "#993C1D" },
};
const COL1_TAG_COLORS = {
  "AES-128": { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" },
  "DLP":     { bg: "#EEEDFE", border: "#7F77DD", color: "#3C3489" },
  "PRG":     { bg: "#E1F5EE", border: "#1D9E75", color: "#0F6E56" },
  "GGM":     { bg: "#FAEEDA", border: "#BA7517", color: "#854F0B" },
  "L-R":     { bg: "#FBEAF0", border: "#D4537E", color: "#72243E" },
  "MAC":     { bg: "#FAECE7", border: "#D85A30", color: "#993C1D" },
  "M-D":     { bg: "#EAF3DE", border: "#639922", color: "#3B6D11" },
  "HMAC":    { bg: "#EAF3DE", border: "#639922", color: "#3B6D11" },
  "PRG→PRF": { bg: "#FAEEDA", border: "#BA7517", color: "#854F0B" },
};

function makeAESFoundation(keyHex) {
  const seed = seedFromHex(keyHex) ^ 0xaabb;
  const rawOut = fakeHex(seed, 8);
  return { name: "AES-128 (PRP)", paTag: "AES-128", paNum: "PA#2", rawOut };
}
function makeDLPFoundation(keyHex) {
  const seed = seedFromHex(keyHex) ^ 0x1337;
  const rawOut = fakeHex(seed, 8);
  return { name: "DLP (gˣ mod p)", paTag: "DLP", paNum: "PA#1", rawOut };
}

function buildCol1Steps(src, foundation) {
  const { paTag, paNum, rawOut } = foundation;
  const steps = [{ tag: paTag, fn: paTag === "AES-128" ? "AES₁₂₈(key)" : "g^key mod p", inputHex: "key", outputHex: rawOut, pa: paNum, implemented: false }];
  const v0 = seedFromHex(rawOut);
  if (src === "OWF" || src === "OWP") return steps;
  if (src === "PRG") {
    steps.push({ tag: "PRG", fn: "G(s) = F_s(0)‖F_s(1)", inputHex: rawOut, outputHex: fakeHex(v0^0x2222,16), pa: "PA#3", implemented: false });
  } else if (src === "PRF") {
    const prg = fakeHex(v0^0x2222,16);
    steps.push({ tag: "PRG", fn: "G(s) = F_s(0)‖F_s(1)", inputHex: rawOut, outputHex: prg, pa: "PA#3", implemented: false });
    steps.push({ tag: "GGM", fn: "GGM tree: F_k(b₁⋯bₙ)", inputHex: prg, outputHex: fakeHex(v0^0x3333,8), pa: "PA#3", implemented: false });
  } else if (src === "PRP") {
    const prg = fakeHex(v0^0x2222,16), prf = fakeHex(v0^0x3333,8);
    steps.push({ tag: "PRG", fn: "G(s) = F_s(0)‖F_s(1)", inputHex: rawOut, outputHex: prg, pa: "PA#3", implemented: false });
    steps.push({ tag: "GGM", fn: "GGM tree → PRF", inputHex: prg, outputHex: prf, pa: "PA#3", implemented: false });
    steps.push({ tag: "L-R", fn: "Luby-Rackoff 3-round Feistel → PRP", inputHex: prf, outputHex: fakeHex(v0^0x4444,8), pa: "PA#2", implemented: false });
  } else if (src === "MAC") {
    const prg = fakeHex(v0^0x2222,16), prf = fakeHex(v0^0x3333,8);
    steps.push({ tag: "PRG", fn: "G(s) = F_s(0)‖F_s(1)", inputHex: rawOut, outputHex: prg, pa: "PA#3", implemented: false });
    steps.push({ tag: "GGM", fn: "GGM tree → PRF", inputHex: prg, outputHex: prf, pa: "PA#3", implemented: false });
    steps.push({ tag: "MAC", fn: "MAC_k(m) = F_k(m)", inputHex: prf, outputHex: fakeHex(v0^0x5555,8), pa: "PA#5", implemented: false });
  } else if (src === "CRHF") {
    const prf = fakeHex(v0^0x3333,8);
    steps.push({ tag: "PRG→PRF", fn: "GGM tree (PRG→PRF)", inputHex: rawOut, outputHex: prf, pa: "PA#3", implemented: false });
    steps.push({ tag: "M-D", fn: "Merkle-Damgård compression → CRHF", inputHex: prf, outputHex: fakeHex(v0^0x6666,8), pa: "PA#7", implemented: false });
  } else if (src === "HMAC") {
    const prf = fakeHex(v0^0x3333,8);
    steps.push({ tag: "PRG→PRF", fn: "GGM tree (PRG→PRF)", inputHex: rawOut, outputHex: prf, pa: "PA#3", implemented: false });
    steps.push({ tag: "HMAC", fn: "HMAC_k(m) = H((k⊕opad)‖H((k⊕ipad)‖m))", inputHex: prf, outputHex: fakeHex(v0^0x7777,8), pa: "PA#10", implemented: false });
  }
  return steps;
}

function buildCol2Steps(chain, oracleA, msgHex) {
  if (!chain) return null;
  return chain.map((edge, i) => {
    const r = REDUCTIONS[edge];
    if (!r) return { tag: "?", fn: edge, inputHex: null, outputHex: null, pa: null, security: null, implemented: false };
    const queryResult = oracleA(msgHex + i.toString(16).padStart(2, "0"));
    return { tag: r.pa, fn: `${edge.replace("→", " → ")}: ${r.name}`, inputHex: queryResult, outputHex: fakeHex(seedFromHex(queryResult) ^ (i * 0x9abc), 8), pa: r.pa, security: r.security, implemented: false };
  });
}

const PRIMITIVES = ["OWF","OWP","PRG","PRF","PRP","MAC","CRHF","HMAC"];

// ═══════════════════════════════════════════════════════════════════════════════
// Shared UI components
// ═══════════════════════════════════════════════════════════════════════════════

function Tag({ label, colorMap }) {
  const c = colorMap[label] || { bg: "var(--color-background-secondary)", border: "var(--color-border-secondary)", color: "var(--color-text-secondary)" };
  return <span style={{ fontSize: 10, padding: "3px 8px", borderRadius: 4, whiteSpace: "nowrap", fontWeight: 500, fontFamily: "var(--font-mono)", flexShrink: 0, background: c.bg, border: `0.5px solid ${c.border}`, color: c.color }}>{label}</span>;
}

function StepRow({ tag, fn, inputHex, outputHex, pa, implemented, tagColorMap }) {
  return (
    <div style={{ display: "flex", alignItems: "flex-start", gap: 10, padding: "9px 0", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
      <Tag label={tag} colorMap={tagColorMap} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 11, color: "var(--color-text-secondary)", marginBottom: 4, fontFamily: "var(--font-mono)" }}>{fn}</div>
        {inputHex && (
          <div style={{ display: "flex", alignItems: "baseline", gap: 6, marginBottom: 3 }}>
            <span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 28, flexShrink: 0 }}>in:</span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)", wordBreak: "break-all" }}>{inputHex === "key" ? "<user key input>" : `0x${inputHex}`}</span>
          </div>
        )}
        <div style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
          <span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 28, flexShrink: 0 }}>out:</span>
          {!implemented
            ? <span style={{ fontSize: 11, color: "var(--color-text-secondary)", fontStyle: "italic" }}>Not implemented yet (due: {pa || "PA#?"})</span>
            : <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--color-text-primary)", wordBreak: "break-all" }}>0x{outputHex}</span>
          }
        </div>
      </div>
    </div>
  );
}

function ColCard({ headerLabel, headerStyle, children }) {
  return (
    <div style={{ background: "var(--color-background-primary)", border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden", display: "flex", flexDirection: "column" }}>
      <div style={{ padding: "10px 16px", fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", ...headerStyle }}>{headerLabel}</div>
      <div style={{ padding: "16px", flex: 1 }}>{children}</div>
    </div>
  );
}

function FieldLabel({ children }) {
  return <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.07em", fontWeight: 500, marginBottom: 5 }}>{children}</div>;
}

function StyledSelect({ value, onChange, options, exclude }) {
  return (
    <select value={value} onChange={e => onChange(e.target.value)} style={{ width: "100%", padding: "8px 12px", fontSize: 13, border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", background: "var(--color-background-primary)", color: "var(--color-text-primary)", fontFamily: "var(--font-mono)", outline: "none" }}>
      {options.filter(o => o !== exclude).map(o => <option key={o} value={o}>{o}</option>)}
    </select>
  );
}

function TextInput({ value, onChange, placeholder }) {
  return <input type="text" value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} style={{ width: "100%", padding: "8px 12px", fontSize: 13, border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", background: "var(--color-background-primary)", color: "var(--color-text-primary)", fontFamily: "var(--font-mono)", outline: "none" }} />;
}

function ToggleBar({ value, onChange, options }) {
  return (
    <div style={{ display: "flex", gap: 4, background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", padding: 3 }}>
      {options.map(opt => {
        const active = value === opt.value, ac = opt.activeStyle || {};
        return <button key={opt.value} onClick={() => onChange(opt.value)} style={{ flex: 1, padding: "7px 14px", fontSize: 12, fontWeight: active ? 500 : 400, border: active ? `0.5px solid ${ac.border || "var(--color-border-info)"}` : "0.5px solid transparent", borderRadius: "var(--border-radius-md)", background: active ? (ac.bg || "var(--color-background-info)") : "transparent", color: active ? (ac.color || "var(--color-text-info)") : "var(--color-text-secondary)", cursor: "pointer", transition: "all 0.15s", fontFamily: "var(--font-sans)" }}>{opt.label}</button>;
      })}
    </div>
  );
}

function SectionHeading({ children }) {
  return <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.07em", fontWeight: 500, marginBottom: 8, marginTop: 4 }}>{children}</div>;
}

function WarnBox({ children }) {
  return <div style={{ padding: "10px 14px", fontSize: 12, borderRadius: "var(--border-radius-md)", background: "#FAEEDA", color: "#854F0B", border: "0.5px solid #BA7517" }}>{children}</div>;
}

function Divider({ label }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 12, margin: "28px 0 20px" }}>
      <div style={{ flex: 1, height: "0.5px", background: "var(--color-border-tertiary)" }} />
      <span style={{ fontSize: 11, color: "var(--color-text-secondary)", fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", whiteSpace: "nowrap" }}>{label}</span>
      <div style={{ flex: 1, height: "0.5px", background: "var(--color-border-tertiary)" }} />
    </div>
  );
}

function TestBadge({ pass }) {
  return <span style={{ fontSize: 10, padding: "2px 8px", borderRadius: 4, fontWeight: 500, background: pass ? "#E1F5EE" : "#FCEBEB", border: `0.5px solid ${pass ? "#1D9E75" : "#E24B4A"}`, color: pass ? "#0F6E56" : "#A32D2D" }}>{pass ? "PASS" : "FAIL"}</span>;
}

function MonoBox({ children, maxH = 64 }) {
  return <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", fontFamily: "var(--font-mono)", fontSize: 11, wordBreak: "break-all", color: "var(--color-text-primary)", maxHeight: maxH, overflowY: "auto" }}>{children}</div>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PA #0 panel
// ═══════════════════════════════════════════════════════════════════════════════

function ProofPanel({ effSrc, effTgt, chain, fdLabel, direction }) {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button onClick={() => setOpen(o => !o)} style={{ width: "100%", display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 16px", fontSize: 13, fontWeight: 500, border: "0.5px solid var(--color-border-tertiary)", borderRadius: open ? "var(--border-radius-md) var(--border-radius-md) 0 0" : "var(--border-radius-md)", background: "var(--color-background-secondary)", color: "var(--color-text-primary)", cursor: "pointer", fontFamily: "var(--font-sans)" }}>
        <span>Reduction chain summary — click to {open ? "collapse" : "expand"}</span>
        <span style={{ fontSize: 11 }}>{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderTop: "none", borderRadius: "0 0 var(--border-radius-md) var(--border-radius-md)", padding: "16px", background: "var(--color-background-primary)" }}>
          <div style={{ marginBottom: 10, fontSize: 13 }}><span style={{ fontWeight: 500 }}>Full chain: </span><span style={{ fontFamily: "var(--font-mono)", fontSize: 12, marginLeft: 6 }}>{fdLabel} → {effSrc} → {effTgt}</span></div>
          <div style={{ marginBottom: 14, fontSize: 13 }}><span style={{ fontWeight: 500 }}>Direction: </span><span style={{ marginLeft: 6 }}>{direction === "forward" ? `Forward (${effSrc} → ${effTgt})` : `Backward (${effSrc} → ${effTgt})`}</span></div>
          {chain ? chain.map((edge, i) => {
            const r = REDUCTIONS[edge]; if (!r) return null;
            const [, a, b] = edge.match(/(\w+)→(\w+)/);
            const c = PA_COLORS[r.pa] || {};
            return (
              <div key={i} style={{ padding: "8px 0", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4, flexWrap: "wrap" }}>
                  <span style={{ fontSize: 10, padding: "3px 8px", borderRadius: 4, fontFamily: "var(--font-mono)", fontWeight: 500, background: c.bg, border: `0.5px solid ${c.border}`, color: c.color }}>{r.pa}</span>
                  <span style={{ fontWeight: 500, fontSize: 13 }}>{a} → {b}</span>
                  <span style={{ color: "var(--color-text-secondary)", fontSize: 12 }}>— {r.name}</span>
                </div>
                <div style={{ fontSize: 11, color: "var(--color-text-secondary)", paddingLeft: 4, marginBottom: 2 }}>Security: {r.security}</div>
                <div style={{ fontSize: 11, color: "var(--color-text-secondary)", paddingLeft: 4, fontStyle: "italic" }}>If adversary breaks {b} with advantage ε, it breaks {a} with advantage ε′ ≥ ε/q — implemented in {r.pa}</div>
              </div>
            );
          }) : <WarnBox>No direct reduction path from {effSrc} → {effTgt}. Try an adjacent pair or bidirectional mode.</WarnBox>}
          <div style={{ marginTop: 14, fontSize: 11, color: "var(--color-text-secondary)", fontStyle: "italic" }}>All intermediate values are toy stubs. Real values will flow from your PA#1–PA#2 WASM implementations.</div>
        </div>
      )}
    </div>
  );
}

function PA0Panel({ foundationType }) {
  const [direction, setDirection] = useState("forward");
  const [src, setSrc] = useState("PRG");
  const [tgt, setTgt] = useState("PRF");
  const [keyHex, setKeyHex] = useState("a3f2c1b8d5e09471");
  const [msgHex, setMsgHex] = useState("deadbeef");

  const foundation = useMemo(() => foundationType === "AES" ? makeAESFoundation(keyHex) : makeDLPFoundation(keyHex), [foundationType, keyHex]);
  const effSrc = direction === "forward" ? src : tgt;
  const effTgt = direction === "forward" ? tgt : src;
  const col1Steps = useMemo(() => buildCol1Steps(effSrc, foundation), [effSrc, foundation]);
  const chain = getRoute(effSrc, effTgt);
  const oracleA = useMemo(() => { const s = seedFromHex(col1Steps[col1Steps.length - 1].outputHex); return (i) => fakeHex(s ^ seedFromHex(i), 8); }, [col1Steps]);
  const col2Steps = useMemo(() => buildCol2Steps(chain, oracleA, msgHex), [chain, oracleA, msgHex]);

  function handleSrcChange(v) { setSrc(v); if (v === tgt) setTgt(PRIMITIVES.find(p => p !== v)); }
  function handleTgtChange(v) { setTgt(v); if (v === src) setSrc(PRIMITIVES.find(p => p !== v)); }

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20 }}>
        <span style={{ fontSize: 12, color: "var(--color-text-secondary)", whiteSpace: "nowrap" }}>Mode:</span>
        <ToggleBar value={direction} onChange={setDirection} options={[
          { value: "forward",  label: "Forward (A → B)",  activeStyle: { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" } },
          { value: "backward", label: "Backward (B → A)", activeStyle: { bg: "#FAEEDA", border: "#BA7517", color: "#854F0B" } },
        ]} />
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 16, marginBottom: 20 }}>
        <ColCard headerLabel="Column 1 — Build: foundation → source primitive A" headerStyle={{ background: "#E6F1FB", color: "#185FA5", borderBottom: "0.5px solid #B5D4F4" }}>
          <div style={{ marginBottom: 14 }}><FieldLabel>Source primitive A</FieldLabel><StyledSelect value={src} onChange={handleSrcChange} options={PRIMITIVES} exclude={tgt} /></div>
          <div style={{ marginBottom: 14 }}><FieldLabel>Input key / seed (hex)</FieldLabel><TextInput value={keyHex} onChange={setKeyHex} placeholder="e.g. a3f2c1b8..." /></div>
          <SectionHeading>{foundation.name} → {effSrc}: step-through</SectionHeading>
          {col1Steps.map((s, i) => <StepRow key={i} tag={s.tag} fn={s.fn} inputHex={s.inputHex} outputHex={s.outputHex} pa={s.pa} implemented={s.implemented} tagColorMap={COL1_TAG_COLORS} />)}
        </ColCard>
        <ColCard headerLabel="Column 2 — Reduce: source A → target primitive B" headerStyle={{ background: "#FAEEDA", color: "#854F0B", borderBottom: "0.5px solid #FAC775" }}>
          <div style={{ marginBottom: 14 }}><FieldLabel>Target primitive B</FieldLabel><StyledSelect value={tgt} onChange={handleTgtChange} options={PRIMITIVES} exclude={src} /></div>
          <div style={{ marginBottom: 14 }}><FieldLabel>Query / message</FieldLabel><TextInput value={msgHex} onChange={setMsgHex} placeholder="e.g. deadbeef..." /></div>
          <SectionHeading>{effSrc} → {effTgt}: step-through</SectionHeading>
          {col2Steps ? col2Steps.map((s, i) => <StepRow key={i} tag={s.tag} fn={s.fn} inputHex={s.inputHex} outputHex={s.outputHex} pa={s.pa} implemented={s.implemented} tagColorMap={PA_COLORS} />) : <WarnBox>No direct reduction path from {effSrc} → {effTgt}.<br />Try an adjacent primitive pair or switch to bidirectional mode.</WarnBox>}
        </ColCard>
      </div>
      <ProofPanel effSrc={effSrc} effTgt={effTgt} chain={chain} fdLabel={foundation.name} direction={direction} />
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// PA #1 panel
// ═══════════════════════════════════════════════════════════════════════════════

function ArgumentBox() {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ marginTop: 8 }}>
      <button onClick={() => setOpen(o => !o)} style={{ width: "100%", display: "flex", justifyContent: "space-between", alignItems: "center", padding: "7px 12px", fontSize: 11, fontWeight: 500, border: "0.5px solid var(--color-border-tertiary)", borderRadius: open ? "var(--border-radius-md) var(--border-radius-md) 0 0" : "var(--border-radius-md)", background: "var(--color-background-secondary)", color: "var(--color-text-secondary)", cursor: "pointer", fontFamily: "var(--font-sans)" }}>
        <span>PA#1b written argument — click to {open ? "collapse" : "expand"}</span><span>{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <div style={{ padding: "12px 14px", border: "0.5px solid var(--color-border-tertiary)", borderTop: "none", borderRadius: "0 0 var(--border-radius-md) var(--border-radius-md)", background: "var(--color-background-primary)", fontSize: 11, lineHeight: 1.7, color: "var(--color-text-secondary)" }}>
          <div style={{ fontWeight: 500, color: "var(--color-text-primary)", marginBottom: 6 }}>Claim: f(s) = G(s) is a one-way function.</div>
          <div style={{ marginBottom: 6 }}><span style={{ fontWeight: 500 }}>Proof (contrapositive).</span> Suppose adversary <em>A</em> inverts <em>f</em> with non-negligible probability:</div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, background: "var(--color-background-secondary)", padding: "6px 10px", borderRadius: "var(--border-radius-md)", marginBottom: 8 }}>Pr[ A(G(s)) = s' s.t. G(s') = G(s) ] ≥ 1/poly(n)</div>
          <div style={{ marginBottom: 6 }}>Construct distinguisher <em>D</em> against <em>G</em>:</div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, background: "var(--color-background-secondary)", padding: "8px 10px", borderRadius: "var(--border-radius-md)", marginBottom: 8, lineHeight: 1.9 }}>
            D(y):<br />&nbsp;&nbsp;1. Run A(y) → s'<br />&nbsp;&nbsp;2. If G(s') = y, output 1<br />&nbsp;&nbsp;3. Else output 0
          </div>
          <div style={{ marginBottom: 4 }}>If <em>y = G(s)</em>: <em>A</em> succeeds w.p. ≥ 1/poly(n) ⟹ <em>D</em> outputs 1 w.h.p.</div>
          <div style={{ marginBottom: 8 }}>If <em>y ← U_(n+ℓ)</em>: G(s') = y with prob ≤ 2⁻ˡ (negligible).</div>
          <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: 8, fontStyle: "italic" }}>⟹ D wins with advantage ≥ 1/poly(n) − negl(n), contradicting PRG security. □</div>
        </div>
      )}
    </div>
  );
}

function PA1Panel() {
  const [owfType, setOwfType] = useState("DLP");
  const [seedHex, setSeedHex] = useState("deadbeef");
  const [outputLen, setOutputLen] = useState(16);
  const [showTests, setShowTests] = useState(false);
  const [testResults, setTestResults] = useState(null);

  const owfOut = useMemo(() => owfType === "DLP" ? dlpOWF(seedHex) : aesOWF(seedHex), [owfType, seedHex]);
  const prgAsOwfDemo = useMemo(() => { const { hexOut } = prgFromOWF(seedHex, owfType, 8); return { prgOut: hexOut, invertAttempt: fakeHex(seedFromHex(hexOut) ^ 0xdead, 8) }; }, [owfType, seedHex]);
  const prgResult = useMemo(() => prgFromOWF(seedHex, owfType, outputLen), [seedHex, owfType, outputLen]);
  const prgInterfaceDemo = useMemo(() => { const prg = makePRGInterface(seedHex, owfType); const b8 = prg.next_bytes_hex(4); prg.seed(owfOut); return { firstCall: b8, afterReseed: prg.next_bytes_hex(4) }; }, [seedHex, owfType, owfOut]);

  const ones = prgResult.bitString.split("").filter(b => b === "1").length;
  const ratio = prgResult.bitString.length > 0 ? ones / prgResult.bitString.length : 0.5;
  const runTests = useCallback(() => { setTestResults({ freq: frequencyTest(prgResult.bitString), runs: runsTest(prgResult.bitString), serial: serialTest(prgResult.bitString) }); setShowTests(true); }, [prgResult.bitString]);

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>
      <div style={{ padding: "10px 16px", background: "#E6F1FB", borderBottom: "0.5px solid #B5D4F4", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: "#185FA5" }}>PA #1 — Live PRG output viewer</div>
        <ToggleBar value={owfType} onChange={setOwfType} options={[
          { value: "DLP", label: "DLP (gˣ mod p)",  activeStyle: { bg: "#EEEDFE", border: "#7F77DD", color: "#3C3489" } },
          { value: "AES", label: "AES Davies-Meyer", activeStyle: { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" } },
        ]} />
      </div>
      <div style={{ padding: "16px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 16 }}>
          <div>
            <SectionHeading>OWF — evaluate(x)</SectionHeading>
            <div style={{ marginBottom: 12 }}><FieldLabel>Seed / input x (hex)</FieldLabel><TextInput value={seedHex} onChange={setSeedHex} placeholder="e.g. deadbeef" /></div>
            <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 14 }}>
              <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 6 }}>f(x) = {owfType === "DLP" ? "g^x mod p" : "AES_k(0¹²⁸) ⊕ k"}</div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}><span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 22 }}>in:</span><span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--color-text-secondary)" }}>0x{seedHex.slice(0,8).padEnd(8,"0")}</span></div>
              <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 4 }}><span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 22 }}>out:</span><span style={{ fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--color-text-primary)", fontWeight: 500 }}>0x{owfOut}</span></div>
            </div>
            <SectionHeading>verify_hardness() — OWF from PRG (PA#1b)</SectionHeading>
            <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", fontSize: 12, marginBottom: 4 }}>
              <div style={{ marginBottom: 6, color: "var(--color-text-secondary)" }}>Claim: f(s) = G(s) is a OWF. Given G(s), adversary cannot recover s.</div>
              <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4 }}><span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 60 }}>G(seed):</span><span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-primary)", wordBreak: "break-all" }}>0x{prgAsOwfDemo.prgOut}</span></div>
              <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4 }}><span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 60 }}>Adv. guess:</span><span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)" }}>0x{prgAsOwfDemo.invertAttempt}</span></div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}><span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 60 }}>Recovered:</span><TestBadge pass={false} /><span style={{ fontSize: 11, color: "var(--color-text-secondary)", fontStyle: "italic" }}>inversion fails ✓</span></div>
            </div>
            <ArgumentBox />
            <div style={{ marginTop: 14 }}>
              <SectionHeading>PRG interface — seed(s) / next_bits(n) for PA#2</SectionHeading>
              <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", fontSize: 11 }}>
                <div style={{ display: "flex", gap: 8, marginBottom: 4 }}><span style={{ fontFamily: "var(--font-mono)", color: "#185FA5", minWidth: 110 }}>prg.seed(s)</span><span style={{ color: "var(--color-text-secondary)" }}>→ resets internal state to s</span></div>
                <div style={{ display: "flex", gap: 8, marginBottom: 8 }}><span style={{ fontFamily: "var(--font-mono)", color: "#185FA5", minWidth: 110 }}>next_bits(32)</span><span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-primary)" }}>0x{prgInterfaceDemo.firstCall}</span></div>
                <div style={{ display: "flex", gap: 8, marginBottom: 4 }}><span style={{ fontFamily: "var(--font-mono)", color: "#0F6E56", minWidth: 110 }}>prg.seed(owf)</span><span style={{ color: "var(--color-text-secondary)" }}>→ re-seeded with f(x)</span></div>
                <div style={{ display: "flex", gap: 8 }}><span style={{ fontFamily: "var(--font-mono)", color: "#0F6E56", minWidth: 110 }}>next_bits(32)</span><span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-primary)" }}>0x{prgInterfaceDemo.afterReseed}</span></div>
              </div>
            </div>
          </div>
          <div>
            <SectionHeading>PRG from OWF — G(s) iterative construction (PA#1a)</SectionHeading>
            <div style={{ marginBottom: 12 }}>
              <FieldLabel>Output length ℓ — {outputLen} bytes ({outputLen * 8} bits)</FieldLabel>
              <input type="range" min={8} max={256} step={8} value={outputLen} onChange={e => setOutputLen(Number(e.target.value))} style={{ width: "100%" }} />
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--color-text-secondary)", marginTop: 2 }}><span>8 B</span><span>256 B</span></div>
            </div>
            <SectionHeading>First 8 iterations: xᵢ → f(xᵢ) → b(xᵢ)</SectionHeading>
            <div style={{ marginBottom: 12 }}>
              {prgResult.steps.map((s, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 0", borderBottom: "0.5px solid var(--color-border-tertiary)", fontSize: 11 }}>
                  <span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-secondary)", minWidth: 18 }}>x{i}:</span>
                  <span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-secondary)", fontSize: 10, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>0x{s.xHex}</span>
                  <span style={{ fontSize: 10, padding: "1px 6px", borderRadius: 3, fontWeight: 500, background: s.bit ? "#E1F5EE" : "#EEEDFE", color: s.bit ? "#0F6E56" : "#3C3489", border: `0.5px solid ${s.bit ? "#1D9E75" : "#7F77DD"}` }}>b={s.bit}</span>
                </div>
              ))}
            </div>
            <SectionHeading>G(s) output — {outputLen * 8} pseudorandom bits</SectionHeading>
            <MonoBox maxH={80}>0x{prgResult.hexOut}</MonoBox>
            <div style={{ margin: "10px 0 12px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--color-text-secondary)", marginBottom: 4 }}><span>Bit ratio</span><span style={{ fontFamily: "var(--font-mono)" }}>{(ratio * 100).toFixed(1)}% ones</span></div>
              <div style={{ height: 8, borderRadius: 4, background: "var(--color-background-secondary)", overflow: "hidden", border: "0.5px solid var(--color-border-tertiary)" }}>
                <div style={{ height: "100%", width: `${ratio * 100}%`, background: Math.abs(ratio - 0.5) < 0.05 ? "#1D9E75" : "#D85A30", transition: "width 0.3s" }} />
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--color-text-secondary)", marginTop: 2 }}><span>0%</span><span style={{ color: "#1D9E75" }}>50%</span><span>100%</span></div>
            </div>
            <button onClick={runTests} style={{ width: "100%", padding: "8px 14px", fontSize: 12, fontWeight: 500, border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", color: "var(--color-text-primary)", cursor: "pointer", fontFamily: "var(--font-sans)" }}>
              Run randomness tests (frequency + runs + serial)
            </button>
          </div>
        </div>
        {showTests && testResults && (
          <div style={{ marginTop: 16, border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", overflow: "hidden" }}>
            <div style={{ padding: "8px 14px", background: "var(--color-background-secondary)", borderBottom: "0.5px solid var(--color-border-tertiary)", fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: "var(--color-text-secondary)" }}>NIST SP 800-22 — threshold p ≥ 0.01</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr" }}>
              {[
                { label: testResults.freq.name,   pass: testResults.freq.pass,   lines: [`ones=${testResults.freq.ones}  zeros=${testResults.freq.zeros}`, `ratio=${testResults.freq.ratio}%  S_obs=${testResults.freq.sObs}`, `p-value = ${testResults.freq.pVal}`] },
                { label: testResults.runs.name,   pass: testResults.runs.pass,   lines: [`runs=${testResults.runs.runs}  exp≈${testResults.runs.expected}`, `V_obs=${testResults.runs.vObs}`, `p-value = ${testResults.runs.pVal}`] },
                { label: testResults.serial.name, pass: testResults.serial.pass, lines: [`00=${testResults.serial.counts["00"]}  01=${testResults.serial.counts["01"]}  10=${testResults.serial.counts["10"]}  11=${testResults.serial.counts["11"]}`, `χ²=${testResults.serial.chi2}  (df=3)`, `p-value = ${testResults.serial.pVal}`] },
              ].map((t, i) => (
                <div key={i} style={{ padding: "12px 14px", borderRight: i < 2 ? "0.5px solid var(--color-border-tertiary)" : "none" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}><TestBadge pass={t.pass} /><span style={{ fontSize: 12, fontWeight: 500 }}>{t.label}</span></div>
                  {t.lines.map((line, j) => <div key={j} style={{ fontSize: 11, color: j === 2 ? (t.pass ? "#0F6E56" : "#A32D2D") : "var(--color-text-secondary)", fontFamily: "var(--font-mono)", marginBottom: 2, fontWeight: j === 2 ? 500 : 400 }}>{line}</div>)}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// PA #2 panel
// ═══════════════════════════════════════════════════════════════════════════════

function GGMTreeViz({ levels, bitString }) {
  if (!levels || levels.length === 0) return null;
  const depth = levels.length - 1;
  const nodeW = 64, nodeH = 28, vGap = 48;
  const svgW = Math.max(500, Math.pow(2, depth) * (nodeW + 16) + 16);
  const svgH = (depth + 1) * (nodeH + vGap) + 16;

  function nodeX(id) { const d = id.length, total = Math.pow(2, d), idx = parseInt(id || "0", 2) || 0, step = svgW / total; return step * idx + step / 2 - nodeW / 2; }
  function nodeY(d) { return 8 + d * (nodeH + vGap); }
  const allNodes = levels.flatMap(l => l);

  return (
    <svg width="100%" viewBox={`0 0 ${svgW} ${svgH}`} style={{ display: "block", fontFamily: "var(--font-mono)" }}>
      {allNodes.map(n => {
        if (n.id.length >= depth) return null;
        const px = nodeX(n.id) + nodeW / 2, py = nodeY(n.id.length) + nodeH;
        const l0 = n.id + "0", l1 = n.id + "1";
        const lx0 = nodeX(l0) + nodeW / 2, lx1 = nodeX(l1) + nodeW / 2, cy = nodeY(n.id.length + 1);
        const pa0 = bitString.startsWith(l0), pa1 = bitString.startsWith(l1);
        return (<g key={`e-${n.id}`}>
          <line x1={px} y1={py} x2={lx0} y2={cy} stroke={pa0 ? "#378ADD" : "#D3D1C7"} strokeWidth={pa0 ? 2 : 1} />
          <text x={(px + lx0) / 2 - 6} y={(py + cy) / 2} fontSize={10} fill={pa0 ? "#185FA5" : "#888780"}>0</text>
          <line x1={px} y1={py} x2={lx1} y2={cy} stroke={pa1 ? "#378ADD" : "#D3D1C7"} strokeWidth={pa1 ? 2 : 1} />
          <text x={(px + lx1) / 2 + 2} y={(py + cy) / 2} fontSize={10} fill={pa1 ? "#185FA5" : "#888780"}>1</text>
        </g>);
      })}
      {allNodes.map(n => {
        const x = nodeX(n.id), y = nodeY(n.id.length);
        const fill   = n.isLeaf && n.active ? "#E1F5EE" : n.active ? "#E6F1FB" : "var(--color-background-secondary)";
        const stroke = n.isLeaf && n.active ? "#1D9E75" : n.active ? "#378ADD" : "#D3D1C7";
        const textC  = n.isLeaf && n.active ? "#0F6E56" : n.active ? "#185FA5" : "#888780";
        return (<g key={`n-${n.id}`}>
          <rect x={x} y={y} width={nodeW} height={nodeH} rx={n.isLeaf ? 4 : 14} fill={fill} stroke={stroke} strokeWidth={n.active ? 1.5 : 0.5} />
          <text x={x + nodeW / 2} y={y + nodeH / 2 + 4} textAnchor="middle" fontSize={9} fill={textC}>{n.id === "" ? "k" : `0x${n.val.slice(0, 6)}`}</text>
        </g>);
      })}
    </svg>
  );
}

function PA2Panel() {
  const [prfType, setPrfType] = useState("GGM");
  const [keyHex, setKeyHex] = useState("a3f2c1b8");
  const [queryBits, setQueryBits] = useState("1010");
  const [prgSeed, setPrgSeed] = useState("deadbeef");
  const [prgLen, setPrgLen] = useState(16);
  const [distResult, setDistResult] = useState(null);
  const [showDist, setShowDist] = useState(false);

  const cleanBits = queryBits.replace(/[^01]/g, "").slice(0, 8);
  const prfResult = useMemo(() => prfType === "AES" ? { value: aesPRF(keyHex, cleanBits.padEnd(8, "0")), path: [] } : ggmPRF(keyHex, cleanBits), [prfType, keyHex, cleanBits]);
  const treeData  = useMemo(() => buildGGMTree(keyHex, cleanBits, 8), [keyHex, cleanBits]);
  const prgResult2 = useMemo(() => prgFromPRF(prgSeed, prfType, prgLen), [prgSeed, prfType, prgLen]);
  const prgRatio2  = prgResult2.bitString.length > 0 ? prgResult2.bitString.split("").filter(b => b === "1").length / prgResult2.bitString.length : 0.5;
  const prgTests2  = useMemo(() => ({ freq: frequencyTest(prgResult2.bitString), runs: runsTest(prgResult2.bitString), serial: serialTest(prgResult2.bitString) }), [prgResult2.bitString]);

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>
      <div style={{ padding: "10px 16px", background: "#EEEDFE", borderBottom: "0.5px solid #AFA9EC", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: "#3C3489" }}>PA #2 — GGM tree visualiser & PRF demo</div>
        <ToggleBar value={prfType} onChange={setPrfType} options={[
          { value: "GGM", label: "GGM (PRG-based)", activeStyle: { bg: "#EEEDFE", border: "#7F77DD", color: "#3C3489" } },
          { value: "AES", label: "AES plug-in",      activeStyle: { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" } },
        ]} />
      </div>
      <div style={{ padding: "16px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "260px minmax(0,1fr)", gap: 16, marginBottom: 20 }}>
          <div>
            <SectionHeading>PRF inputs — F(k, x)</SectionHeading>
            <div style={{ marginBottom: 10 }}><FieldLabel>Key k (hex)</FieldLabel><TextInput value={keyHex} onChange={setKeyHex} placeholder="e.g. a3f2c1b8" /></div>
            <div style={{ marginBottom: 14 }}>
              <FieldLabel>Query x — bit string (≤ 8 bits)</FieldLabel>
              <TextInput value={queryBits} onChange={v => setQueryBits(v.replace(/[^01]/g, "").slice(0, 8))} placeholder="e.g. 1010" />
              <div style={{ fontSize: 10, color: "var(--color-text-secondary)", marginTop: 3 }}>depth = {cleanBits.length}, path: {cleanBits.split("").join(" → ") || "root"}</div>
            </div>
            <div style={{ padding: "12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 10 }}>
              <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>F_k(x) = {prfType === "AES" ? "AES_k(x)" : "GGM leaf"}</div>
              {prfType === "GGM" && prfResult.path.map((step, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4, fontSize: 11 }}>
                  <span style={{ fontSize: 10, padding: "1px 6px", borderRadius: 3, fontWeight: 500, background: step.bit === "0" ? "#E6F1FB" : "#E1F5EE", color: step.bit === "0" ? "#185FA5" : "#0F6E56", border: `0.5px solid ${step.bit === "0" ? "#378ADD" : "#1D9E75"}` }}>G{step.bit}</span>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-secondary)" }}>0x{step.nodeVal.slice(0,6)}</span>
                  <span style={{ fontSize: 10, color: "var(--color-text-secondary)" }}>→</span>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-primary)" }}>0x{(step.bit === "0" ? step.left : step.right).slice(0,6)}</span>
                </div>
              ))}
              <div style={{ marginTop: 8, paddingTop: 8, borderTop: "0.5px solid var(--color-border-tertiary)", display: "flex", gap: 8 }}>
                <span style={{ fontSize: 10, color: "var(--color-text-secondary)" }}>F_k(x) =</span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 14, color: "#3C3489", fontWeight: 500 }}>0x{prfResult.value}</span>
              </div>
            </div>
            <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", fontSize: 11 }}>
              <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 6 }}>F(k, x) interface for PA#3–5</div>
              <div style={{ fontFamily: "var(--font-mono)", color: "#3C3489", marginBottom: 2 }}>makePRFInterface(k, "{prfType}")</div>
              <div style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-secondary)", marginBottom: 2 }}>prf.F("{cleanBits || "0000"}")</div>
              <div style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-primary)" }}>→ 0x{prfResult.value}</div>
            </div>
          </div>
          <div>
            <SectionHeading>GGM binary tree — depth {cleanBits.length} — active path in blue</SectionHeading>
            <div style={{ padding: "10px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", overflowX: "auto" }}>
              {prfType === "GGM"
                ? <GGMTreeViz levels={treeData.levels} bitString={cleanBits} />
                : <div style={{ padding: "20px", textAlign: "center", fontSize: 12, color: "var(--color-text-secondary)", fontStyle: "italic" }}>AES mode: F_k(x) = AES_k(x) directly — no tree. Switch to GGM to see the visualiser.</div>
              }
            </div>
            {prfType === "GGM" && <div style={{ marginTop: 8, padding: "8px 12px", borderRadius: "var(--border-radius-md)", background: "#E6F1FB", border: "0.5px solid #B5D4F4", fontSize: 11, color: "#185FA5" }}>Leaf F_k({cleanBits || "ε"}) = <span style={{ fontFamily: "var(--font-mono)", fontWeight: 500 }}>0x{treeData.leafVal}</span> ✓</div>}
          </div>
        </div>
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: 16, marginBottom: 20 }}>
          <SectionHeading>PRG from PRF — G(s) = F_s(0ⁿ) ‖ F_s(1ⁿ) (PA#2b)</SectionHeading>
          <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 16 }}>
            <div>
              <div style={{ marginBottom: 10 }}><FieldLabel>PRG seed (hex)</FieldLabel><TextInput value={prgSeed} onChange={setPrgSeed} placeholder="e.g. deadbeef" /></div>
              <div style={{ marginBottom: 10 }}>
                <FieldLabel>Output — {prgLen} bytes</FieldLabel>
                <input type="range" min={8} max={128} step={8} value={prgLen} onChange={e => setPrgLen(Number(e.target.value))} style={{ width: "100%" }} />
              </div>
              <MonoBox>0x{prgResult2.hexOut}</MonoBox>
            </div>
            <div>
              <SectionHeading>Statistical tests</SectionHeading>
              <div style={{ marginBottom: 8 }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--color-text-secondary)", marginBottom: 4 }}><span>Bit ratio</span><span style={{ fontFamily: "var(--font-mono)" }}>{(prgRatio2 * 100).toFixed(1)}%</span></div>
                <div style={{ height: 6, borderRadius: 3, background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-tertiary)", overflow: "hidden" }}>
                  <div style={{ height: "100%", width: `${prgRatio2 * 100}%`, background: Math.abs(prgRatio2 - 0.5) < 0.05 ? "#1D9E75" : "#D85A30" }} />
                </div>
              </div>
              {[prgTests2.freq, prgTests2.runs, prgTests2.serial].map((t, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "5px 0", borderBottom: "0.5px solid var(--color-border-tertiary)", fontSize: 11 }}>
                  <span style={{ color: "var(--color-text-secondary)" }}>{t.name}</span>
                  <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-secondary)", fontSize: 10 }}>p={t.pVal}</span>
                    <span style={{ fontSize: 10, padding: "1px 7px", borderRadius: 3, fontWeight: 500, background: t.pass ? "#E1F5EE" : "#FCEBEB", border: `0.5px solid ${t.pass ? "#1D9E75" : "#E24B4A"}`, color: t.pass ? "#0F6E56" : "#A32D2D" }}>{t.pass ? "PASS" : "FAIL"}</span>
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: 16 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
            <SectionHeading>Distinguishing game — PRF vs truly random (q = 100)</SectionHeading>
            <button onClick={() => { setDistResult(runDistinguishingGame(keyHex, prfType, 100)); setShowDist(true); }} style={{ padding: "7px 14px", fontSize: 12, fontWeight: 500, border: "0.5px solid #7F77DD", borderRadius: "var(--border-radius-md)", background: "#EEEDFE", color: "#3C3489", cursor: "pointer", fontFamily: "var(--font-sans)", whiteSpace: "nowrap" }}>Run game</button>
          </div>
          {showDist && distResult && (
            <div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 10, marginBottom: 14 }}>
                {[{ label: "Total queries", val: distResult.totalQ }, { label: "Collisions", val: `${distResult.collisions} (${distResult.collisionRate}%)` }, { label: "PRF mean byte", val: distResult.prfMean }, { label: "Random mean byte", val: distResult.randMean }].map((s, i) => (
                  <div key={i} style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
                    <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>{s.label}</div>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, fontWeight: 500, color: "var(--color-text-primary)" }}>{s.val}</div>
                  </div>
                ))}
              </div>
              <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: parseFloat(distResult.diff) < 20 ? "#E1F5EE" : "#FAEEDA", border: `0.5px solid ${parseFloat(distResult.diff) < 20 ? "#1D9E75" : "#BA7517"}`, color: parseFloat(distResult.diff) < 20 ? "#0F6E56" : "#854F0B", fontSize: 12, marginBottom: 12 }}>
                Mean byte difference = {distResult.diff} — {parseFloat(distResult.diff) < 20 ? "statistically indistinguishable from random ✓" : "outputs differ — check PRF implementation"}
              </div>
              <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", overflow: "hidden" }}>
                <div style={{ display: "grid", gridTemplateColumns: "80px 1fr 1fr 60px", background: "var(--color-background-secondary)", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
                  {["x", "F_k(x)", "random(x)", "match?"].map((h, i) => <div key={i} style={{ padding: "6px 10px", fontSize: 10, fontWeight: 500, color: "var(--color-text-secondary)", textTransform: "uppercase" }}>{h}</div>)}
                </div>
                {distResult.queries.map((q, i) => (
                  <div key={i} style={{ display: "grid", gridTemplateColumns: "80px 1fr 1fr 60px", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
                    <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)" }}>0x{q.x}</div>
                    <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 11, color: "#3C3489" }}>0x{q.prfOut}</div>
                    <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)" }}>0x{q.randOut}</div>
                    <div style={{ padding: "6px 10px", fontSize: 11, color: q.same ? "#A32D2D" : "#0F6E56" }}>{q.same ? "yes !" : "no ✓"}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// PA #3 panel — IND-CPA game + Enc/Dec demo
// ═══════════════════════════════════════════════════════════════════════════════

function PA3Panel() {
  const [prfType,     setPrfType]     = useState("GGM");
  const [keyHex,      setKeyHex]      = useState("c0ffee11");
  const [reuseNonce,  setReuseNonce]  = useState(false);

  // ── Enc/Dec demo state ────────────────────────────────────────────────────
  const [msgHex,      setMsgHex]      = useState("deadbeef");
  const [encResult,   setEncResult]   = useState(null);
  const [decResult,   setDecResult]   = useState(null);
  const [decInput,    setDecInput]    = useState("");

  // ── IND-CPA interactive game state ────────────────────────────────────────
  const [m0,          setM0]          = useState("aabbccdd");
  const [m1,          setM1]          = useState("11223344");
  const [gameRound,   setGameRound]   = useState(null);  // current challenge
  const [guess,       setGuess]       = useState(null);
  const [history,     setHistory]     = useState([]);    // { b, guess, correct }
  const [showResult,  setShowResult]  = useState(false);

  // ── CPA simulation state ──────────────────────────────────────────────────
  const [simResult,   setSimResult]   = useState(null);

  // ── Nonce reuse attack state ──────────────────────────────────────────────
  const [attackResult,setAttackResult]= useState(null);

  // Derived advantage
  const rounds   = history.length;
  const correct  = history.filter(h => h.correct).length;
  const advantage = rounds > 0 ? Math.abs((correct / rounds) - 0.5) * 2 : 0;

  function doEnc() {
    const r = encCPA(keyHex, msgHex, prfType, reuseNonce);
    setEncResult(r);
    setDecResult(null);
    setDecInput(r.ciphertext);
  }

  function doDec() {
    const parts = decInput.split(":");
    if (parts.length !== 2) { setDecResult({ error: "Format must be r:c" }); return; }
    const [rHex, cHex] = parts;
    setDecResult(decCPA(keyHex, rHex, cHex, prfType));
  }

  function doEncryptChallenge() {
    if (m0.length !== m1.length) return;
    const round = playCPAGameRound(keyHex, m0, m1, prfType, reuseNonce);
    setGameRound(round);
    setGuess(null);
    setShowResult(false);
  }

  function doGuess(g) {
    if (!gameRound || showResult) return;
    setGuess(g);
    setShowResult(true);
    setHistory(h => [...h, { b: gameRound.b, guess: g, correct: g === gameRound.b }]);
  }

  function resetGame() { setHistory([]); setGameRound(null); setGuess(null); setShowResult(false); }

  function runSim() { setSimResult(runCPASimulation(keyHex, prfType, reuseNonce, 50)); }
  function runAttack() { setAttackResult(demonstrateNonceReuseAttack(keyHex, prfType)); }

  const mismatch = m0.length !== m1.length;
  const modeColor = reuseNonce ? { bg: "#FCEBEB", border: "#E24B4A", text: "#A32D2D" } : { bg: "#E1F5EE", border: "#1D9E75", text: "#0F6E56" };

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>
      {/* Header */}
      <div style={{ padding: "10px 16px", background: "#E1F5EE", borderBottom: "0.5px solid #9FE1CB", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: "#0F6E56" }}>PA #3 — CPA-secure encryption & IND-CPA game</div>
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <ToggleBar value={prfType} onChange={setPrfType} options={[
            { value: "GGM", label: "GGM PRF", activeStyle: { bg: "#EEEDFE", border: "#7F77DD", color: "#3C3489" } },
            { value: "AES", label: "AES PRF", activeStyle: { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" } },
          ]} />
          <ToggleBar value={reuseNonce ? "broken" : "secure"} onChange={v => { setReuseNonce(v === "broken"); resetGame(); setSimResult(null); setAttackResult(null); }} options={[
            { value: "secure", label: "Secure (fresh r)",   activeStyle: { bg: "#E1F5EE", border: "#1D9E75", color: "#0F6E56" } },
            { value: "broken", label: "Broken (reuse r)",   activeStyle: { bg: "#FCEBEB", border: "#E24B4A", color: "#A32D2D" } },
          ]} />
        </div>
      </div>

      <div style={{ padding: "16px" }}>
        {/* Mode banner */}
        <div style={{ padding: "8px 14px", borderRadius: "var(--border-radius-md)", background: modeColor.bg, border: `0.5px solid ${modeColor.border}`, color: modeColor.text, fontSize: 12, marginBottom: 16 }}>
          {reuseNonce
            ? "Broken mode: r is always F_k(0) — same plaintext always produces the same ciphertext. The IND-CPA adversary can distinguish trivially."
            : "Secure mode: r ← {0,1}ⁿ freshly each encryption. Advantage should converge to ≈ 0 over many rounds."}
        </div>

        {/* Row 1: Key + Enc/Dec */}
        <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 16, marginBottom: 20 }}>

          {/* Enc */}
          <div>
            <SectionHeading>Enc(k, m) — C = ⟨r, F_k(r) ⊕ m⟩</SectionHeading>
            <div style={{ marginBottom: 10 }}><FieldLabel>Key k (hex)</FieldLabel><TextInput value={keyHex} onChange={setKeyHex} placeholder="e.g. c0ffee11" /></div>
            <div style={{ marginBottom: 10 }}><FieldLabel>Message m (hex)</FieldLabel><TextInput value={msgHex} onChange={setMsgHex} placeholder="e.g. deadbeef" /></div>
            <button onClick={doEnc} style={{ width: "100%", padding: "8px 14px", fontSize: 12, fontWeight: 500, border: "0.5px solid #1D9E75", borderRadius: "var(--border-radius-md)", background: "#E1F5EE", color: "#0F6E56", cursor: "pointer", fontFamily: "var(--font-sans)", marginBottom: 12 }}>
              Encrypt
            </button>
            {encResult && (
              <div>
                <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 8 }}>
                  <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 6 }}>Ciphertext C = r : c</div>
                  <div style={{ display: "flex", gap: 8, marginBottom: 4 }}><span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 12 }}>r:</span><span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "#185FA5", wordBreak: "break-all" }}>0x{encResult.r}</span></div>
                  <div style={{ display: "flex", gap: 8 }}><span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 12 }}>c:</span><span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-primary)", wordBreak: "break-all" }}>0x{encResult.c}</span></div>
                </div>
                {encResult.blocks.length > 0 && (
                  <div>
                    <SectionHeading>Block-by-block detail (multi-block counter mode)</SectionHeading>
                    {encResult.blocks.map((blk, i) => (
                      <div key={i} style={{ padding: "6px 10px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 6, fontSize: 11 }}>
                        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                          <span style={{ fontSize: 10, padding: "1px 6px", borderRadius: 3, background: "#EEEDFE", color: "#3C3489", border: "0.5px solid #7F77DD", fontFamily: "var(--font-mono)" }}>blk {i}</span>
                          <span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-secondary)" }}>m: 0x{blk.mBlock}</span>
                          <span style={{ color: "var(--color-text-secondary)" }}>⊕</span>
                          <span style={{ fontFamily: "var(--font-mono)", color: "#185FA5" }}>F_k(r+{i}): 0x{blk.keyStream}</span>
                          <span style={{ color: "var(--color-text-secondary)" }}>=</span>
                          <span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-primary)", fontWeight: 500 }}>0x{blk.cBlock}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Dec */}
          <div>
            <SectionHeading>Dec(k, r, c) — m = F_k(r) ⊕ c</SectionHeading>
            <div style={{ marginBottom: 10 }}>
              <FieldLabel>Ciphertext (r:c format)</FieldLabel>
              <TextInput value={decInput} onChange={setDecInput} placeholder="paste r:c from Enc output" />
            </div>
            <button onClick={doDec} style={{ width: "100%", padding: "8px 14px", fontSize: 12, fontWeight: 500, border: "0.5px solid #378ADD", borderRadius: "var(--border-radius-md)", background: "#E6F1FB", color: "#185FA5", cursor: "pointer", fontFamily: "var(--font-sans)", marginBottom: 12 }}>
              Decrypt
            </button>
            {decResult && (
              <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
                {decResult.error
                  ? <div style={{ fontSize: 12, color: "#A32D2D" }}>{decResult.error}</div>
                  : <>
                      <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 6 }}>Recovered plaintext</div>
                      <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, color: "var(--color-text-primary)", fontWeight: 500, wordBreak: "break-all" }}>0x{decResult.msgHex}</div>
                      {decResult.msgHex === msgHex && <div style={{ fontSize: 11, color: "#0F6E56", marginTop: 6 }}>Matches original message ✓</div>}
                    </>
                }
              </div>
            )}
          </div>
        </div>

        {/* Row 2: IND-CPA interactive game */}
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: 16, marginBottom: 20 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12, flexWrap: "wrap", gap: 8 }}>
            <SectionHeading>IND-CPA game — play as the adversary (20 rounds target)</SectionHeading>
            {rounds > 0 && <button onClick={resetGame} style={{ fontSize: 11, padding: "4px 12px", border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", color: "var(--color-text-secondary)", cursor: "pointer", fontFamily: "var(--font-sans)" }}>Reset</button>}
          </div>

          {/* Running advantage counter */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 10, marginBottom: 14 }}>
            {[
              { label: "Rounds played", val: rounds },
              { label: "Correct guesses", val: correct },
              { label: "Advantage", val: advantage.toFixed(3) },
              { label: "Target", val: reuseNonce ? "≈ 1.0" : "≤ 0.1" },
            ].map((s, i) => (
              <div key={i} style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
                <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>{s.label}</div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 16, fontWeight: 500, color: i === 2 ? (reuseNonce ? (advantage > 0.8 ? "#0F6E56" : "#A32D2D") : (advantage <= 0.1 ? "#0F6E56" : "#854F0B")) : "var(--color-text-primary)" }}>{s.val}</div>
              </div>
            ))}
          </div>

          {/* Advantage bar */}
          <div style={{ marginBottom: 14 }}>
            <div style={{ height: 8, borderRadius: 4, background: "var(--color-background-secondary)", overflow: "hidden", border: "0.5px solid var(--color-border-tertiary)" }}>
              <div style={{ height: "100%", width: `${Math.min(advantage, 1) * 100}%`, background: reuseNonce ? "#E24B4A" : advantage <= 0.1 ? "#1D9E75" : advantage <= 0.3 ? "#BA7517" : "#E24B4A", transition: "width 0.4s" }} />
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--color-text-secondary)", marginTop: 2 }}><span>0 (random)</span><span>1.0 (perfect)</span></div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 16 }}>
            {/* Step 1: messages */}
            <div>
              <div style={{ fontSize: 12, fontWeight: 500, marginBottom: 8, color: "var(--color-text-primary)" }}>Step 1 — enter two equal-length messages</div>
              <div style={{ marginBottom: 8 }}><FieldLabel>m₀ (hex)</FieldLabel><TextInput value={m0} onChange={setM0} placeholder="e.g. aabbccdd" /></div>
              <div style={{ marginBottom: 10 }}><FieldLabel>m₁ (hex)</FieldLabel><TextInput value={m1} onChange={setM1} placeholder="e.g. 11223344" /></div>
              {mismatch && <div style={{ fontSize: 11, color: "#A32D2D", marginBottom: 8 }}>m₀ and m₁ must be the same length</div>}
              <button onClick={doEncryptChallenge} disabled={mismatch} style={{ width: "100%", padding: "9px 14px", fontSize: 13, fontWeight: 500, border: "0.5px solid #1D9E75", borderRadius: "var(--border-radius-md)", background: mismatch ? "var(--color-background-secondary)" : "#E1F5EE", color: mismatch ? "var(--color-text-secondary)" : "#0F6E56", cursor: mismatch ? "not-allowed" : "pointer", fontFamily: "var(--font-sans)" }}>
                Step 2 — Encrypt (challenger picks b)
              </button>
            </div>

            {/* Step 3: guess */}
            <div>
              <div style={{ fontSize: 12, fontWeight: 500, marginBottom: 8, color: "var(--color-text-primary)" }}>Step 3 — see C* and guess b</div>
              {gameRound ? (
                <div>
                  <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 10 }}>
                    <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 6 }}>Challenge ciphertext C*</div>
                    <div style={{ display: "flex", gap: 6, marginBottom: 3 }}><span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 12 }}>r:</span><span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "#185FA5", wordBreak: "break-all" }}>0x{gameRound.r}</span></div>
                    <div style={{ display: "flex", gap: 6 }}><span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 12 }}>c:</span><span style={{ fontFamily: "var(--font-mono)", fontSize: 11, wordBreak: "break-all", color: "var(--color-text-primary)" }}>0x{gameRound.c}</span></div>
                  </div>
                  {!showResult ? (
                    <div style={{ display: "flex", gap: 8 }}>
                      <button onClick={() => doGuess(0)} style={{ flex: 1, padding: "9px", fontSize: 13, fontWeight: 500, border: "0.5px solid #378ADD", borderRadius: "var(--border-radius-md)", background: "#E6F1FB", color: "#185FA5", cursor: "pointer", fontFamily: "var(--font-sans)" }}>Guess b = 0 (m₀)</button>
                      <button onClick={() => doGuess(1)} style={{ flex: 1, padding: "9px", fontSize: 13, fontWeight: 500, border: "0.5px solid #1D9E75", borderRadius: "var(--border-radius-md)", background: "#E1F5EE", color: "#0F6E56", cursor: "pointer", fontFamily: "var(--font-sans)" }}>Guess b = 1 (m₁)</button>
                    </div>
                  ) : (
                    <div>
                      <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: guess === gameRound.b ? "#E1F5EE" : "#FCEBEB", border: `0.5px solid ${guess === gameRound.b ? "#1D9E75" : "#E24B4A"}`, color: guess === gameRound.b ? "#0F6E56" : "#A32D2D", fontSize: 13, fontWeight: 500, marginBottom: 10 }}>
                        {guess === gameRound.b ? "Correct!" : "Wrong!"} Challenger had b = {gameRound.b} (encrypted m{gameRound.b})
                        {reuseNonce && guess === gameRound.b && <div style={{ fontSize: 11, fontWeight: 400, marginTop: 4 }}>Nonce reuse made this trivial — Enc(m₀) is deterministic !</div>}
                      </div>
                      <button onClick={doEncryptChallenge} style={{ width: "100%", padding: "8px", fontSize: 12, fontWeight: 500, border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", color: "var(--color-text-primary)", cursor: "pointer", fontFamily: "var(--font-sans)" }}>Next round</button>
                    </div>
                  )}
                </div>
              ) : (
                <div style={{ padding: "20px", textAlign: "center", fontSize: 12, color: "var(--color-text-secondary)", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
                  Enter m₀ and m₁ and click "Encrypt" to get a challenge ciphertext.
                </div>
              )}
            </div>
          </div>

          {/* Recent rounds log */}
          {history.length > 0 && (
            <div style={{ marginTop: 14 }}>
              <SectionHeading>Recent rounds</SectionHeading>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {history.slice(-20).map((h, i) => (
                  <span key={i} style={{ fontSize: 10, padding: "2px 7px", borderRadius: 3, fontWeight: 500, background: h.correct ? "#E1F5EE" : "#FCEBEB", border: `0.5px solid ${h.correct ? "#1D9E75" : "#E24B4A"}`, color: h.correct ? "#0F6E56" : "#A32D2D" }}>{h.correct ? "✓" : "✗"}</span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Row 3: CPA simulation + nonce-reuse attack */}
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: 16 }}>
          <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 16 }}>

            {/* CPA simulation */}
            <div>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
                <SectionHeading>CPA game simulation — dummy adversary, 50 rounds</SectionHeading>
                <button onClick={runSim} style={{ padding: "6px 12px", fontSize: 11, fontWeight: 500, border: "0.5px solid #7F77DD", borderRadius: "var(--border-radius-md)", background: "#EEEDFE", color: "#3C3489", cursor: "pointer", fontFamily: "var(--font-sans)", whiteSpace: "nowrap" }}>Run sim</button>
              </div>
              {simResult && (
                <div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginBottom: 10 }}>
                    {[{ label: "Rounds", val: simResult.rounds }, { label: "Correct", val: simResult.correct }, { label: "Advantage", val: simResult.advantage }].map((s, i) => (
                      <div key={i} style={{ padding: "8px 10px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
                        <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 2 }}>{s.label}</div>
                        <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, fontWeight: 500, color: "var(--color-text-primary)" }}>{s.val}</div>
                      </div>
                    ))}
                  </div>
                  <div style={{ padding: "8px 12px", borderRadius: "var(--border-radius-md)", background: parseFloat(simResult.advantage) <= 0.15 && !reuseNonce ? "#E1F5EE" : reuseNonce && parseFloat(simResult.advantage) > 0.8 ? "#FCEBEB" : "#FAEEDA", border: `0.5px solid ${parseFloat(simResult.advantage) <= 0.15 && !reuseNonce ? "#1D9E75" : reuseNonce ? "#E24B4A" : "#BA7517"}`, fontSize: 12, color: parseFloat(simResult.advantage) <= 0.15 && !reuseNonce ? "#0F6E56" : reuseNonce ? "#A32D2D" : "#854F0B" }}>
                    Advantage ≈ {simResult.advantage} — {reuseNonce ? "broken mode: adversary wins trivially !" : parseFloat(simResult.advantage) <= 0.15 ? "secure mode: advantage ≈ 0 ✓" : "advantage non-trivial — check implementation"}
                  </div>
                  <div style={{ marginTop: 10 }}>
                    <SectionHeading>First 5 rounds</SectionHeading>
                    {simResult.log.map((l, i) => (
                      <div key={i} style={{ display: "flex", gap: 8, fontSize: 11, padding: "4px 0", borderBottom: "0.5px solid var(--color-border-tertiary)", alignItems: "center" }}>
                        <span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-secondary)", minWidth: 18 }}>#{l.i}</span>
                        <span style={{ color: "var(--color-text-secondary)" }}>b={l.b} guess={l.guess}</span>
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-secondary)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{l.c}</span>
                        <span style={{ fontSize: 10, padding: "1px 6px", borderRadius: 3, background: l.win ? "#E1F5EE" : "#FCEBEB", border: `0.5px solid ${l.win ? "#1D9E75" : "#E24B4A"}`, color: l.win ? "#0F6E56" : "#A32D2D" }}>{l.win ? "✓" : "✗"}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Nonce reuse attack */}
            <div>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
                <SectionHeading>Broken variant — nonce reuse attack demo</SectionHeading>
                <button onClick={runAttack} style={{ padding: "6px 12px", fontSize: 11, fontWeight: 500, border: "0.5px solid #D85A30", borderRadius: "var(--border-radius-md)", background: "#FAECE7", color: "#993C1D", cursor: "pointer", fontFamily: "var(--font-sans)", whiteSpace: "nowrap" }}>Run attack</button>
              </div>
              <div style={{ fontSize: 12, color: "var(--color-text-secondary)", marginBottom: 10 }}>
                Deterministic encryption reuses r = F_k(0) always. An adversary who queries Enc(m) twice sees identical ciphertexts — trivially breaking IND-CPA.
              </div>
              {attackResult && (
                <div>
                  <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 8 }}>
                    <div style={{ display: "flex", gap: 8, marginBottom: 4 }}><span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 24 }}>m:</span><span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-primary)" }}>0x{attackResult.m}</span></div>
                    <div style={{ display: "flex", gap: 8, marginBottom: 4 }}><span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 24 }}>C₁:</span><span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-primary)", wordBreak: "break-all" }}>{attackResult.ct1}</span></div>
                    <div style={{ display: "flex", gap: 8, marginBottom: 8 }}><span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 24 }}>C₂:</span><span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-primary)", wordBreak: "break-all" }}>{attackResult.ct2}</span></div>
                    <div style={{ display: "flex", gap: 8 }}><span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 24 }}>C₁=C₂:</span><span style={{ fontSize: 12, fontWeight: 500, color: attackResult.detected ? "#A32D2D" : "#0F6E56" }}>{attackResult.detected ? "YES — nonce reuse detected !" : "No match (secure)"}</span></div>
                  </div>
                  {attackResult.detected && (
                    <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A", color: "#A32D2D", fontSize: 12 }}>
                      Adversary queries Enc(m) twice and sees C₁ = C₂. Since they submitted m, they know exactly which message was encrypted — IND-CPA is broken.
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Root
// ═══════════════════════════════════════════════════════════════════════════════

export default function MinicryptExplorer() {
  const [foundationType, setFoundationType] = useState("AES");

  return (
    <div style={{ padding: "1rem 0", fontFamily: "var(--font-sans)", fontSize: 14 }}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", flexWrap: "wrap", gap: 12, marginBottom: 20, paddingBottom: 16, borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
        <div>
          <div style={{ fontSize: 16, fontWeight: 500, color: "var(--color-text-primary)" }}>CS8.401 Minicrypt Clique Explorer</div>
          <div style={{ fontSize: 12, color: "var(--color-text-secondary)", marginTop: 2 }}>PA#0 scaffold · PA#1 OWF & PRG · PA#2 GGM PRF · PA#3 CPA encryption</div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ fontSize: 12, color: "var(--color-text-secondary)" }}>Foundation:</span>
          <ToggleBar value={foundationType} onChange={setFoundationType} options={[
            { value: "AES", label: "AES-128 (PRP)", activeStyle: { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" } },
            { value: "DLP", label: "DLP (gˣ mod p)", activeStyle: { bg: "#E1F5EE", border: "#1D9E75", color: "#0F6E56" } },
          ]} />
        </div>
      </div>

      <Divider label="PA #0 — Clique explorer scaffold" />
      <PA0Panel foundationType={foundationType} />

      <Divider label="PA #1 — OWF & PRG demo" />
      <PA1Panel />

      <Divider label="PA #2 — GGM PRF demo" />
      <PA2Panel />

      <Divider label="PA #3 — CPA-secure encryption & IND-CPA game" />
      <PA3Panel />
    </div>
  );
}
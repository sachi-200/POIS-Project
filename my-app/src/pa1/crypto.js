// ═══════════════════════════════════════════════════════════════════════════════
// PA #1 — OWF & PRG implementations
// ═══════════════════════════════════════════════════════════════════════════════

import { fakeHex, seedFromHex } from "../utils/crypto.js";

const DLP_P = 4294967311n, DLP_G = 3n;

/** DLP-based OWF: f(x) = g^x mod p */
export function dlpOWF(xHex) {
  const xBig = BigInt("0x" + (xHex || "1").replace(/[^0-9a-fA-F]/g, "").padStart(1, "1")) % (DLP_P - 1n);
  let r = 1n, b = DLP_G % DLP_P, e = xBig;
  while (e > 0n) { if (e % 2n === 1n) r = (r * b) % DLP_P; b = (b * b) % DLP_P; e >>= 1n; }
  return r.toString(16).padStart(8, "0");
}

/** AES-based OWF: f(k) = AES_k(0^128) ⊕ k (Davies-Meyer style, toy stub) */
export function aesOWF(kHex) {
  const ks = seedFromHex(kHex), ao = fakeHex(ks ^ 0xae50cafe, 8);
  return ((seedFromHex(ao) ^ ks) >>> 0).toString(16).padStart(8, "0");
}

/** Goldreich-Levin hard-core bit: b(x) = <x, r> mod 2 */
const GL_MASK = 0xb5ad4ecb;
export function hardCoreBit(xHex) {
  let v = (seedFromHex(xHex) ^ GL_MASK) >>> 0;
  v ^= v >> 16; v ^= v >> 8; v ^= v >> 4; v ^= v >> 2; v ^= v >> 1;
  return v & 1;
}

/**
 * PRG from OWF (PA#1a): G(x₀) = b(x₀) ‖ b(x₁) ‖ … where xᵢ₊₁ = f(xᵢ)
 * Returns bitString, hexOut, and first 8 steps for the UI.
 */
export function prgFromOWF(seedHex, owfType, outputBytes) {
  const outputBits = outputBytes * 8;
  const steps = [];
  let xHex = seedHex.replace(/[^0-9a-fA-F]/g, "").padEnd(8, "0").slice(0, 8);
  for (let i = 0; i < outputBits; i++) {
    const bit = hardCoreBit(xHex), nextX = owfType === "DLP" ? dlpOWF(xHex) : aesOWF(xHex);
    steps.push({ i, xHex, bit, nextX }); xHex = nextX;
  }
  const bitString = steps.map(s => s.bit).join("");
  const hexOut = [];
  for (let i = 0; i < bitString.length; i += 8)
    hexOut.push(parseInt(bitString.slice(i, i + 8).padEnd(8, "0"), 2).toString(16).padStart(2, "0"));
  return { bitString, hexOut: hexOut.join(""), steps: steps.slice(0, 8) };
}

/**
 * PRG black-box interface for PA#2 — exposes seed(s) / next_bits(n).
 * PA#2 calls this without inspecting internals.
 */
export function makePRGInterface(seedHex, owfType) {
  let state = (seedHex || "deadbeef").replace(/[^0-9a-fA-F]/g, "").padEnd(8, "0").slice(0, 8);
  return {
    seed(s) { state = (s || "").replace(/[^0-9a-fA-F]/g, "").padEnd(8, "0").slice(0, 8); },
    next_bits(n) {
      const bits = [];
      for (let i = 0; i < n; i++) { bits.push(hardCoreBit(state)); state = owfType === "DLP" ? dlpOWF(state) : aesOWF(state); }
      return bits;
    },
    next_bytes_hex(byteCount) {
      const bits = this.next_bits(byteCount * 8), hex = [];
      for (let i = 0; i < bits.length; i += 8)
        hex.push(parseInt(bits.slice(i, i + 8).join(""), 2).toString(16).padStart(2, "0"));
      return hex.join("");
    },
  };
}
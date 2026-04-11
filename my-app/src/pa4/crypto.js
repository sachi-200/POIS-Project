// ═══════════════════════════════════════════════════════════════════════════════
// PA #4 — CBC, OFB, CTR modes of operation
// ═══════════════════════════════════════════════════════════════════════════════

import { fakeHex, seedFromHex, freshRandom, hexXOR, padHex, unpadHex, BLOCK_HEX_LEN } from "../utils/crypto.js";

// Toy block cipher: XOR-based stub (self-inverse, so Dec = Enc)
// Replace body with SubtleCrypto AES-ECB for real use.
function blockCipherEnc(keyHex, blockHex) {
  const pad = fakeHex((seedFromHex(keyHex) ^ 0xae50f00d) >>> 0, 8);
  return hexXOR(blockHex.padEnd(BLOCK_HEX_LEN, "0").slice(0, BLOCK_HEX_LEN), pad);
}
const blockCipherDec = blockCipherEnc; // XOR is its own inverse

function toBlocks(msgHex) {
  const padded = padHex(msgHex);
  const blocks = [];
  for (let i = 0; i < padded.length; i += BLOCK_HEX_LEN)
    blocks.push(padded.slice(i, i + BLOCK_HEX_LEN).padEnd(BLOCK_HEX_LEN, "0"));
  return blocks;
}

// ── CBC ──────────────────────────────────────────────────────────────────────
export function cbcEnc(keyHex, ivHex, msgHex) {
  const mBlocks = toBlocks(msgHex), cBlocks = [], steps = [];
  let prev = ivHex.padEnd(BLOCK_HEX_LEN, "0").slice(0, BLOCK_HEX_LEN);
  for (let i = 0; i < mBlocks.length; i++) {
    const xored = hexXOR(mBlocks[i], prev), c = blockCipherEnc(keyHex, xored);
    steps.push({ i, mBlock: mBlocks[i], prev, xored, cBlock: c });
    cBlocks.push(c); prev = c;
  }
  return { iv: ivHex, cipherBlocks: cBlocks, ciphertext: ivHex + ":" + cBlocks.join(""), steps };
}

export function cbcDec(keyHex, ivHex, cipherBlocks) {
  const mBlocks = [], steps = [];
  let prev = ivHex.padEnd(BLOCK_HEX_LEN, "0").slice(0, BLOCK_HEX_LEN);
  for (let i = 0; i < cipherBlocks.length; i++) {
    const decrypted = blockCipherDec(keyHex, cipherBlocks[i]), m = hexXOR(decrypted, prev);
    steps.push({ i, cBlock: cipherBlocks[i], prev, decrypted, mBlock: m });
    mBlocks.push(m); prev = cipherBlocks[i];
  }
  return { plainBlocks: mBlocks, plaintext: unpadHex(mBlocks.join("")), steps };
}

// ── OFB ──────────────────────────────────────────────────────────────────────
export function ofbEnc(keyHex, ivHex, msgHex) {
  const mBlocks = toBlocks(msgHex), cBlocks = [], keystreamBlocks = [], steps = [];
  let state = ivHex.padEnd(BLOCK_HEX_LEN, "0").slice(0, BLOCK_HEX_LEN);
  for (let i = 0; i < mBlocks.length; i++) {
    const ks = blockCipherEnc(keyHex, state), c = hexXOR(mBlocks[i], ks);
    steps.push({ i, state, ks, mBlock: mBlocks[i], cBlock: c });
    keystreamBlocks.push(ks); cBlocks.push(c); state = ks;
  }
  return { iv: ivHex, cipherBlocks: cBlocks, keystreamBlocks, ciphertext: ivHex + ":" + cBlocks.join(""), steps };
}

export function ofbDec(keyHex, ivHex, cipherBlocks) {
  const mBlocks = [], steps = [];
  let state = ivHex.padEnd(BLOCK_HEX_LEN, "0").slice(0, BLOCK_HEX_LEN);
  for (let i = 0; i < cipherBlocks.length; i++) {
    const ks = blockCipherEnc(keyHex, state), m = hexXOR(cipherBlocks[i], ks);
    steps.push({ i, state, ks, cBlock: cipherBlocks[i], mBlock: m });
    mBlocks.push(m); state = ks;
  }
  return { plainBlocks: mBlocks, plaintext: unpadHex(mBlocks.join("")), steps };
}

// ── CTR ──────────────────────────────────────────────────────────────────────
export function ctrEnc(keyHex, msgHex) {
  const r = freshRandom(), mBlocks = toBlocks(msgHex), cBlocks = [], steps = [];
  const rInt = seedFromHex(r);
  for (let i = 0; i < mBlocks.length; i++) {
    const ctrHex = ((rInt + i) >>> 0).toString(16).padStart(BLOCK_HEX_LEN, "0").slice(0, BLOCK_HEX_LEN);
    const ks = blockCipherEnc(keyHex, ctrHex), c = hexXOR(mBlocks[i], ks);
    steps.push({ i, r, ctrHex, ks, mBlock: mBlocks[i], cBlock: c });
    cBlocks.push(c);
  }
  return { r, cipherBlocks: cBlocks, ciphertext: r + ":" + cBlocks.join(""), steps };
}

export function ctrDec(keyHex, rHex, cipherBlocks) {
  const mBlocks = [], steps = [];
  const rInt = seedFromHex(rHex);
  for (let i = 0; i < cipherBlocks.length; i++) {
    const ctrHex = ((rInt + i) >>> 0).toString(16).padStart(BLOCK_HEX_LEN, "0").slice(0, BLOCK_HEX_LEN);
    const ks = blockCipherEnc(keyHex, ctrHex), m = hexXOR(cipherBlocks[i], ks);
    steps.push({ i, rHex, ctrHex, ks, cBlock: cipherBlocks[i], mBlock: m });
    mBlocks.push(m);
  }
  return { plainBlocks: mBlocks, plaintext: unpadHex(mBlocks.join("")), steps };
}

// ── Unified API (Encrypt / Decrypt) ─────────────────────────────────────────
export function Encrypt(mode, keyHex, msgHex) {
  if (mode === "CBC") return cbcEnc(keyHex, freshRandom().padEnd(BLOCK_HEX_LEN, "0").slice(0, BLOCK_HEX_LEN), msgHex);
  if (mode === "OFB") return ofbEnc(keyHex, freshRandom().padEnd(BLOCK_HEX_LEN, "0").slice(0, BLOCK_HEX_LEN), msgHex);
  if (mode === "CTR") return ctrEnc(keyHex, msgHex);
  throw new Error("Unknown mode: " + mode);
}

export function Decrypt(mode, keyHex, obj) {
  if (mode === "CBC") return cbcDec(keyHex, obj.iv, obj.cipherBlocks);
  if (mode === "OFB") return ofbDec(keyHex, obj.iv, obj.cipherBlocks);
  if (mode === "CTR") return ctrDec(keyHex, obj.r, obj.cipherBlocks);
  throw new Error("Unknown mode: " + mode);
}

// ── Attack demos ─────────────────────────────────────────────────────────────
export function cbcIVReuseAttack(keyHex, ivHex, msg1Hex, msg2Hex) {
  const enc1 = cbcEnc(keyHex, ivHex, msg1Hex), enc2 = cbcEnc(keyHex, ivHex, msg2Hex);
  const leaks = enc1.cipherBlocks.map((b, i) => enc2.cipherBlocks[i] === b ? i : -1).filter(i => i >= 0);
  return { enc1, enc2, leaks };
}

export function ofbKeystreamReuseAttack(keyHex, ivHex, msg1Hex, msg2Hex) {
  const enc1 = ofbEnc(keyHex, ivHex, msg1Hex), enc2 = ofbEnc(keyHex, ivHex, msg2Hex);
  return {
    enc1, enc2,
    xorBlocks: enc1.cipherBlocks.map((c, i) => i < enc2.cipherBlocks.length ? hexXOR(c, enc2.cipherBlocks[i]) : c),
    xorPlain:  enc1.steps.map((s, i) => i < enc2.steps.length ? hexXOR(s.mBlock, enc2.steps[i].mBlock) : s.mBlock),
  };
}

// ── Correctness tests ────────────────────────────────────────────────────────
export function runCorrectnessTests(keyHex) {
  const msgs = [
    { label: "Short (<1 block)", hex: "aabb" },
    { label: "Exactly 1 block",  hex: "deadbeef04040404" },
    { label: "Multi-block (3)",  hex: "deadbeef11223344aabbccdd00112233" },
  ];
  const results = [];
  for (const mode of ["CBC", "OFB", "CTR"]) {
    for (const msg of msgs) {
      const enc = Encrypt(mode, keyHex, msg.hex);
      const dec = Decrypt(mode, keyHex, enc);
      results.push({ mode, label: msg.label, original: msg.hex, recovered: dec.plaintext, pass: dec.plaintext === msg.hex });
    }
  }
  return results;
}
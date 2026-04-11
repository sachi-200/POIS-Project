// ═══════════════════════════════════════════════════════════════════════════════
// PA #2 — GGM PRF, AES PRF, PRG-from-PRF, distinguishing game
// ═══════════════════════════════════════════════════════════════════════════════

import { fakeHex, seedFromHex } from "../utils/crypto.js";

export function G0(sHex) { return fakeHex(seedFromHex(sHex) ^ 0x474d4d30, 8); }
export function G1(sHex) { return fakeHex(seedFromHex(sHex) ^ 0x474d4d31, 8); }

/** GGM PRF: F_k(b₁b₂…bₙ) — follows root-to-leaf path */
export function ggmPRF(keyHex, bitString) {
  let s = keyHex.replace(/[^0-9a-fA-F]/g, "").padEnd(8, "0").slice(0, 8);
  const path = [];
  for (const bit of bitString) {
    const left = G0(s), right = G1(s);
    path.push({ bit, nodeVal: s, left, right });
    s = bit === "0" ? left : right;
  }
  return { value: s, path };
}

/** AES plug-in PRF: F_k(x) = AES_k(x) (toy stub) */
export function aesPRF(keyHex, inputHex) {
  const k = seedFromHex(keyHex), x = seedFromHex(inputHex);
  return fakeHex((k ^ x ^ 0xae50f00d) >>> 0, 8);
}

/** PRG from PRF (PA#2b): G(s) = F_s(0ⁿ) ‖ F_s(1ⁿ) — length-doubling PRG */
export function prgFromPRF(seedHex, prfType, outputBytes) {
  const outputBits = outputBytes * 8, bits = [];
  let counter = 0;
  while (bits.length < outputBits) {
    const cHex = counter.toString(16).padStart(8, "0");
    const out = prfType === "AES" ? aesPRF(seedHex, cHex) : ggmPRF(seedHex, "00000000").value;
    for (let b = 0; b < out.length; b += 2) {
      const byte = parseInt(out.slice(b, b + 2), 16);
      for (let bit = 7; bit >= 0; bit--) bits.push((byte >> bit) & 1);
      if (bits.length >= outputBits) break;
    }
    counter++;
  }
  const bitString = bits.slice(0, outputBits).join(""), hexOut = [];
  for (let i = 0; i < bitString.length; i += 8)
    hexOut.push(parseInt(bitString.slice(i, i + 8), 2).toString(16).padStart(2, "0"));
  return { bitString, hexOut: hexOut.join("") };
}

/** Build full GGM tree up to depth n for the visualiser */
export function buildGGMTree(keyHex, bitString, maxDepth) {
  const depth = Math.min(bitString.length, maxDepth, 8);
  const nodes = { "": { val: keyHex.slice(0, 8).padEnd(8, "0"), depth: 0 } };
  for (let d = 0; d < depth; d++)
    for (const id of Object.keys(nodes).filter(id => id.length === d)) {
      const p = nodes[id];
      nodes[id + "0"] = { val: G0(p.val), depth: d + 1 };
      nodes[id + "1"] = { val: G1(p.val), depth: d + 1 };
    }
  const levels = [];
  for (let d = 0; d <= depth; d++)
    levels.push(Object.entries(nodes).filter(([id]) => id.length === d).sort(([a], [b]) => a.localeCompare(b))
      .map(([id, n]) => ({ id, val: n.val, active: bitString.startsWith(id), isLeaf: d === depth })));
  return { levels, depth, leafVal: nodes[bitString.slice(0, depth)]?.val || "" };
}

/** Distinguishing game: PRF vs truly random, q queries */
export function runDistinguishingGame(keyHex, prfType, q = 100) {
  const queries = [];
  for (let i = 0; i < q; i++) {
    const x = i.toString(16).padStart(8, "0"), bits = (i % 8).toString(2).padStart(4, "0");
    const prfOut = prfType === "AES" ? aesPRF(keyHex, x) : ggmPRF(keyHex, bits).value;
    const randOut = fakeHex((seedFromHex(x) ^ 0xdeadcafe ^ i * 0x1234) >>> 0, 8);
    queries.push({ x, prfOut, randOut, same: prfOut === randOut });
  }
  const collisions = queries.filter(q => q.same).length;
  const prfMean = queries.map(q => seedFromHex(q.prfOut) & 0xff).reduce((a, b) => a + b, 0) / q;
  const randMean = queries.map(q => seedFromHex(q.randOut) & 0xff).reduce((a, b) => a + b, 0) / q;
  return { queries: queries.slice(0, 10), collisions, collisionRate: (collisions / q * 100).toFixed(2), prfMean: prfMean.toFixed(1), randMean: randMean.toFixed(1), diff: Math.abs(prfMean - randMean).toFixed(2), totalQ: q };
}

/**
 * F(k, x) black-box interface — exported for PA#3, PA#4, PA#5.
 * Callers only see F(x); they cannot inspect internals.
 */
export function makePRFInterface(keyHex, prfType = "GGM") {
  return {
    F(x) {
      if (prfType === "AES") return aesPRF(keyHex, x);
      return ggmPRF(keyHex, x.replace(/[^01]/g, "").padEnd(8, "0").slice(0, 8)).value;
    },
    prfType, keyHex,
  };
}
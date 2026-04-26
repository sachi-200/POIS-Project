// import { useState, useMemo, useCallback } from "react";

// // ═══════════════════════════════════════════════════════════════════════════════
// // Shared toy-crypto utilities
// // ═══════════════════════════════════════════════════════════════════════════════

// function lcg(seed) { return ((seed * 1664525 + 1013904223) & 0xffffffff) >>> 0; }

// function fakeHex(seed, bytes = 8) {
//   let s = seed >>> 0, out = "";
//   for (let i = 0; i < bytes; i++) { s = lcg(s); out += ((s >>> 24) & 0xff).toString(16).padStart(2, "0"); }
//   return out;
// }

// function seedFromHex(hex) {
//   const clean = (hex || "").replace(/[^0-9a-fA-F]/g, "").padEnd(8, "0");
//   return parseInt(clean.slice(0, 8), 16) || 0xdeadbeef;
// }

// function freshRandom() {
//   try { const a = new Uint32Array(1); crypto.getRandomValues(a); return a[0].toString(16).padStart(8, "0"); }
//   catch { return fakeHex((Date.now() ^ (Math.random() * 0xffffffff)) >>> 0, 8); }
// }

// function hexXOR(a, b) {
//   const len = Math.max(a.length, b.length);
//   const pa = a.padEnd(len, "0"), pb = b.padEnd(len, "0");
//   let out = "";
//   for (let i = 0; i < len; i += 2) out += ((parseInt(pa.slice(i, i + 2), 16) || 0) ^ (parseInt(pb.slice(i, i + 2), 16) || 0)).toString(16).padStart(2, "0");
//   return out;
// }

// // ── FIX: padding / unpadding ──────────────────────────────────────────────────
// // PKCS#7-style: always add a full pad block if message already aligns exactly.
// // padLen is in bytes; stored as a hex byte repeated padLen times.
// const BLOCK_HEX_LEN = 16; // 8 bytes

// function padHex(msgHex, blockHexLen = BLOCK_HEX_LEN) {
//   // Normalise to even number of hex chars
//   const h = msgHex.length % 2 === 0 ? msgHex : msgHex + "0";
//   const msgBytes = h.length / 2;
//   const blockBytes = blockHexLen / 2;
//   // Always add 1..blockBytes bytes of padding (never 0)
//   const padLen = blockBytes - (msgBytes % blockBytes);
//   const padByte = padLen.toString(16).padStart(2, "0");
//   return h + padByte.repeat(padLen);
// }

// function unpadHex(paddedHex) {
//   if (!paddedHex || paddedHex.length < 2) return paddedHex;
//   const padLen = parseInt(paddedHex.slice(-2), 16);
//   if (padLen < 1 || padLen * 2 > paddedHex.length) return paddedHex;
//   // Verify all padding bytes are correct (basic PKCS#7 validation)
//   const padByte = paddedHex.slice(-2);
//   for (let i = 0; i < padLen; i++) {
//     if (paddedHex.slice(paddedHex.length - 2 - i * 2, paddedHex.length - i * 2) !== padByte) return paddedHex;
//   }
//   return paddedHex.slice(0, paddedHex.length - padLen * 2);
// }

// // ═══════════════════════════════════════════════════════════════════════════════
// // PA #1
// // ═══════════════════════════════════════════════════════════════════════════════

// const DLP_P = 4294967311n, DLP_G = 3n;

// function dlpOWF(xHex) {
//   const xBig = BigInt("0x" + (xHex || "1").replace(/[^0-9a-fA-F]/g, "").padStart(1, "1")) % (DLP_P - 1n);
//   let r = 1n, b = DLP_G % DLP_P, e = xBig;
//   while (e > 0n) { if (e % 2n === 1n) r = (r * b) % DLP_P; b = (b * b) % DLP_P; e >>= 1n; }
//   return r.toString(16).padStart(8, "0");
// }

// function aesOWF(kHex) {
//   const ks = seedFromHex(kHex), ao = fakeHex(ks ^ 0xae50cafe, 8);
//   return ((seedFromHex(ao) ^ ks) >>> 0).toString(16).padStart(8, "0");
// }

// const GL_MASK = 0xb5ad4ecb;
// function hardCoreBit(xHex) {
//   let v = (seedFromHex(xHex) ^ GL_MASK) >>> 0;
//   v ^= v >> 16; v ^= v >> 8; v ^= v >> 4; v ^= v >> 2; v ^= v >> 1;
//   return v & 1;
// }

// function prgFromOWF(seedHex, owfType, outputBytes) {
//   const outputBits = outputBytes * 8;
//   const steps = [];
//   let xHex = seedHex.replace(/[^0-9a-fA-F]/g, "").padEnd(8, "0").slice(0, 8);
//   for (let i = 0; i < outputBits; i++) {
//     const bit = hardCoreBit(xHex), nextX = owfType === "DLP" ? dlpOWF(xHex) : aesOWF(xHex);
//     steps.push({ i, xHex, bit, nextX }); xHex = nextX;
//   }
//   const bitString = steps.map(s => s.bit).join("");
//   const hexOut = [];
//   for (let i = 0; i < bitString.length; i += 8)
//     hexOut.push(parseInt(bitString.slice(i, i + 8).padEnd(8, "0"), 2).toString(16).padStart(2, "0"));
//   return { bitString, hexOut: hexOut.join(""), steps: steps.slice(0, 8) };
// }

// export function makePRGInterface(seedHex, owfType) {
//   let state = (seedHex || "deadbeef").replace(/[^0-9a-fA-F]/g, "").padEnd(8, "0").slice(0, 8);
//   return {
//     seed(s) { state = (s || "").replace(/[^0-9a-fA-F]/g, "").padEnd(8, "0").slice(0, 8); },
//     next_bits(n) {
//       const bits = [];
//       for (let i = 0; i < n; i++) { bits.push(hardCoreBit(state)); state = owfType === "DLP" ? dlpOWF(state) : aesOWF(state); }
//       return bits;
//     },
//     next_bytes_hex(byteCount) {
//       const bits = this.next_bits(byteCount * 8), hex = [];
//       for (let i = 0; i < bits.length; i += 8)
//         hex.push(parseInt(bits.slice(i, i + 8).join(""), 2).toString(16).padStart(2, "0"));
//       return hex.join("");
//     },
//   };
// }

// // ═══════════════════════════════════════════════════════════════════════════════
// // NIST tests
// // ═══════════════════════════════════════════════════════════════════════════════

// function erfcApprox(x) {
//   if (x < 0) return 2 - erfcApprox(-x);
//   const t = 1 / (1 + 0.3275911 * x);
//   return t * (0.254829592 + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429)))) * Math.exp(-x * x);
// }
// function chi2pval(chi2, df) {
//   if (chi2 <= 0) return 1;
//   const z = (Math.pow(chi2 / df, 1 / 3) - (1 - 2 / (9 * df))) / Math.sqrt(2 / (9 * df));
//   return erfcApprox(z / Math.sqrt(2)) / 2;
// }
// function frequencyTest(bs) {
//   const n = bs.length, ones = bs.split("").filter(b => b === "1").length;
//   const sObs = Math.abs(ones - (n - ones)) / Math.sqrt(n), pVal = erfcApprox(sObs / Math.sqrt(2));
//   return { name: "Frequency (monobit)", ones, zeros: n - ones, ratio: ((ones / n) * 100).toFixed(1), sObs: sObs.toFixed(4), pVal: pVal.toFixed(4), pass: pVal >= 0.01 };
// }
// function runsTest(bs) {
//   const n = bs.length, pi = bs.split("").filter(b => b === "1").length / n;
//   let runs = 1;
//   for (let i = 1; i < bs.length; i++) if (bs[i] !== bs[i - 1]) runs++;
//   const vObs = Math.abs(runs - 2 * n * pi * (1 - pi)) / (2 * Math.sqrt(2 * n) * pi * (1 - pi) || 1), pVal = erfcApprox(vObs);
//   return { name: "Runs", runs, expected: (2 * n * pi * (1 - pi)).toFixed(1), vObs: vObs.toFixed(4), pVal: pVal.toFixed(4), pass: pVal >= 0.01 };
// }
// function serialTest(bs) {
//   const counts = { "00": 0, "01": 0, "10": 0, "11": 0 };
//   for (let i = 0; i < bs.length - 1; i++) { const k = bs[i] + bs[i + 1]; if (counts[k] !== undefined) counts[k]++; }
//   const n = bs.length - 1, expected = n / 4;
//   const chi2 = Object.values(counts).reduce((s, c) => s + (c - expected) ** 2 / (expected || 1), 0), pVal = chi2pval(chi2, 3);
//   return { name: "Serial (digrams)", counts, chi2: chi2.toFixed(4), pVal: pVal.toFixed(4), pass: pVal >= 0.01 };
// }

// // ═══════════════════════════════════════════════════════════════════════════════
// // PA #2
// // ═══════════════════════════════════════════════════════════════════════════════

// function G0(sHex) { return fakeHex(seedFromHex(sHex) ^ 0x474d4d30, 8); }
// function G1(sHex) { return fakeHex(seedFromHex(sHex) ^ 0x474d4d31, 8); }

// function ggmPRF(keyHex, bitString) {
//   let s = keyHex.replace(/[^0-9a-fA-F]/g, "").padEnd(8, "0").slice(0, 8);
//   const path = [];
//   for (const bit of bitString) {
//     const left = G0(s), right = G1(s);
//     path.push({ bit, nodeVal: s, left, right });
//     s = bit === "0" ? left : right;
//   }
//   return { value: s, path };
// }

// function aesPRF(keyHex, inputHex) {
//   const k = seedFromHex(keyHex), x = seedFromHex(inputHex);
//   return fakeHex((k ^ x ^ 0xae50f00d) >>> 0, 8);
// }

// function prgFromPRF(seedHex, prfType, outputBytes) {
//   const outputBits = outputBytes * 8, bits = [];
//   let counter = 0;
//   while (bits.length < outputBits) {
//     const cHex = counter.toString(16).padStart(8, "0");
//     const out = prfType === "AES" ? aesPRF(seedHex, cHex) : ggmPRF(seedHex, "00000000").value;
//     for (let b = 0; b < out.length; b += 2) {
//       const byte = parseInt(out.slice(b, b + 2), 16);
//       for (let bit = 7; bit >= 0; bit--) bits.push((byte >> bit) & 1);
//       if (bits.length >= outputBits) break;
//     }
//     counter++;
//   }
//   const bitString = bits.slice(0, outputBits).join(""), hexOut = [];
//   for (let i = 0; i < bitString.length; i += 8)
//     hexOut.push(parseInt(bitString.slice(i, i + 8), 2).toString(16).padStart(2, "0"));
//   return { bitString, hexOut: hexOut.join("") };
// }

// function buildGGMTree(keyHex, bitString, maxDepth) {
//   const depth = Math.min(bitString.length, maxDepth, 8);
//   const nodes = { "": { val: keyHex.slice(0, 8).padEnd(8, "0"), depth: 0 } };
//   for (let d = 0; d < depth; d++)
//     for (const id of Object.keys(nodes).filter(id => id.length === d)) {
//       const p = nodes[id];
//       nodes[id + "0"] = { val: G0(p.val), depth: d + 1 };
//       nodes[id + "1"] = { val: G1(p.val), depth: d + 1 };
//     }
//   const levels = [];
//   for (let d = 0; d <= depth; d++)
//     levels.push(Object.entries(nodes).filter(([id]) => id.length === d).sort(([a], [b]) => a.localeCompare(b))
//       .map(([id, n]) => ({ id, val: n.val, active: bitString.startsWith(id), isLeaf: d === depth })));
//   return { levels, depth, leafVal: nodes[bitString.slice(0, depth)]?.val || "" };
// }

// function runDistinguishingGame(keyHex, prfType, q = 100) {
//   const queries = [];
//   for (let i = 0; i < q; i++) {
//     const x = i.toString(16).padStart(8, "0"), bits = (i % 8).toString(2).padStart(4, "0");
//     const prfOut = prfType === "AES" ? aesPRF(keyHex, x) : ggmPRF(keyHex, bits).value;
//     const randOut = fakeHex((seedFromHex(x) ^ 0xdeadcafe ^ i * 0x1234) >>> 0, 8);
//     queries.push({ x, prfOut, randOut, same: prfOut === randOut });
//   }
//   const collisions = queries.filter(q => q.same).length;
//   const prfMean = queries.map(q => seedFromHex(q.prfOut) & 0xff).reduce((a, b) => a + b, 0) / q;
//   const randMean = queries.map(q => seedFromHex(q.randOut) & 0xff).reduce((a, b) => a + b, 0) / q;
//   return { queries: queries.slice(0, 10), collisions, collisionRate: (collisions / q * 100).toFixed(2), prfMean: prfMean.toFixed(1), randMean: randMean.toFixed(1), diff: Math.abs(prfMean - randMean).toFixed(2), totalQ: q };
// }

// export function makePRFInterface(keyHex, prfType = "GGM") {
//   return {
//     F(x) {
//       if (prfType === "AES") return aesPRF(keyHex, x);
//       return ggmPRF(keyHex, x.replace(/[^01]/g, "").padEnd(8, "0").slice(0, 8)).value;
//     },
//     prfType, keyHex,
//   };
// }

// // ═══════════════════════════════════════════════════════════════════════════════
// // PA #3 — CPA encryption
// // ═══════════════════════════════════════════════════════════════════════════════

// function prfBlock(keyHex, rHex, counter, prfType) {
//   const cHex = ((seedFromHex(rHex) + counter) >>> 0).toString(16).padStart(8, "0");
//   if (prfType === "AES") return aesPRF(keyHex, cHex);
//   return ggmPRF(keyHex, (counter % 256).toString(2).padStart(8, "0")).value;
// }

// export function encCPA(keyHex, msgHex, prfType = "GGM", reuseNonce = false) {
//   const r = reuseNonce ? prfBlock(keyHex, "00000000", 0, prfType) : freshRandom();
//   const padded = padHex(msgHex);
//   const blocks = [];
//   let cipherHex = "";
//   for (let i = 0; i < padded.length; i += BLOCK_HEX_LEN) {
//     const mBlock = padded.slice(i, i + BLOCK_HEX_LEN).padEnd(BLOCK_HEX_LEN, "0");
//     const keyStream = prfBlock(keyHex, r, i / BLOCK_HEX_LEN, prfType);
//     const cBlock = hexXOR(mBlock, keyStream);
//     blocks.push({ counter: i / BLOCK_HEX_LEN, r, mBlock, keyStream, cBlock });
//     cipherHex += cBlock;
//   }
//   return { r, c: cipherHex, blocks, ciphertext: `${r}:${cipherHex}` };
// }

// export function decCPA(keyHex, rHex, cipherHex, prfType = "GGM") {
//   const blocks = [];
//   let plainHex = "";
//   for (let i = 0; i < cipherHex.length; i += BLOCK_HEX_LEN) {
//     const cBlock = cipherHex.slice(i, i + BLOCK_HEX_LEN).padEnd(BLOCK_HEX_LEN, "0");
//     const keyStream = prfBlock(keyHex, rHex, i / BLOCK_HEX_LEN, prfType);
//     const mBlock = hexXOR(cBlock, keyStream);
//     blocks.push({ counter: i / BLOCK_HEX_LEN, cBlock, keyStream, mBlock });
//     plainHex += mBlock;
//   }
//   return { msgHex: unpadHex(plainHex), blocks };
// }

// function playCPAGameRound(keyHex, m0hex, m1hex, prfType, reuseNonce) {
//   if (m0hex.length !== m1hex.length) return { error: "m₀ and m₁ must be the same length" };
//   const b = Math.random() < 0.5 ? 0 : 1;
//   const enc = encCPA(keyHex, b === 0 ? m0hex : m1hex, prfType, reuseNonce);
//   return { b, r: enc.r, c: enc.c, ciphertext: enc.ciphertext, blocks: enc.blocks };
// }

// function runCPASimulation(keyHex, prfType, reuseNonce, rounds = 50) {
//   let correct = 0;
//   const log = [];
//   for (let i = 0; i < rounds; i++) {
//     const m0 = fakeHex(i * 0x1111, 8), m1 = fakeHex(i * 0x2222, 8);
//     const round = playCPAGameRound(keyHex, m0, m1, prfType, reuseNonce);
//     let guess;
//     if (reuseNonce) { const testEnc = encCPA(keyHex, m0, prfType, true); guess = testEnc.c === round.c ? 0 : 1; }
//     else guess = Math.random() < 0.5 ? 0 : 1;
//     if (guess === round.b) correct++;
//     if (i < 5) log.push({ i, m0, m1, b: round.b, guess, win: guess === round.b, c: round.ciphertext.slice(0, 20) + "…" });
//   }
//   return { rounds, correct, advantage: (Math.abs((correct / rounds) - 0.5) * 2).toFixed(3), log };
// }

// function demonstrateNonceReuseAttack(keyHex, prfType) {
//   const m = fakeHex(0xdeadbeef, 8);
//   const enc1 = encCPA(keyHex, m, prfType, true), enc2 = encCPA(keyHex, m, prfType, true);
//   return { m, ct1: enc1.ciphertext, ct2: enc2.ciphertext, detected: enc1.ciphertext === enc2.ciphertext };
// }

// // ═══════════════════════════════════════════════════════════════════════════════
// // PA #4 — CBC, OFB, CTR
// // ═══════════════════════════════════════════════════════════════════════════════

// // Toy block cipher: XOR-based (self-inverse so Dec = Enc)
// function blockCipherEnc(keyHex, blockHex) {
//   const pad = fakeHex((seedFromHex(keyHex) ^ 0xae50f00d) >>> 0, 8);
//   return hexXOR(blockHex.padEnd(BLOCK_HEX_LEN, "0").slice(0, BLOCK_HEX_LEN), pad);
// }
// const blockCipherDec = blockCipherEnc; // XOR is its own inverse

// function toBlocks(msgHex) {
//   const padded = padHex(msgHex);
//   const blocks = [];
//   for (let i = 0; i < padded.length; i += BLOCK_HEX_LEN)
//     blocks.push(padded.slice(i, i + BLOCK_HEX_LEN).padEnd(BLOCK_HEX_LEN, "0"));
//   return blocks;
// }

// // ── CBC ──────────────────────────────────────────────────────────────────────
// export function cbcEnc(keyHex, ivHex, msgHex) {
//   const mBlocks = toBlocks(msgHex), cBlocks = [], steps = [];
//   let prev = ivHex.padEnd(BLOCK_HEX_LEN, "0").slice(0, BLOCK_HEX_LEN);
//   for (let i = 0; i < mBlocks.length; i++) {
//     const xored = hexXOR(mBlocks[i], prev), c = blockCipherEnc(keyHex, xored);
//     steps.push({ i, mBlock: mBlocks[i], prev, xored, cBlock: c });
//     cBlocks.push(c); prev = c;
//   }
//   return { iv: ivHex, cipherBlocks: cBlocks, ciphertext: ivHex + ":" + cBlocks.join(""), steps };
// }

// export function cbcDec(keyHex, ivHex, cipherBlocks) {
//   const mBlocks = [], steps = [];
//   let prev = ivHex.padEnd(BLOCK_HEX_LEN, "0").slice(0, BLOCK_HEX_LEN);
//   for (let i = 0; i < cipherBlocks.length; i++) {
//     const decrypted = blockCipherDec(keyHex, cipherBlocks[i]), m = hexXOR(decrypted, prev);
//     steps.push({ i, cBlock: cipherBlocks[i], prev, decrypted, mBlock: m });
//     mBlocks.push(m); prev = cipherBlocks[i];
//   }
//   return { plainBlocks: mBlocks, plaintext: unpadHex(mBlocks.join("")), steps };
// }

// // ── OFB ──────────────────────────────────────────────────────────────────────
// export function ofbEnc(keyHex, ivHex, msgHex) {
//   const mBlocks = toBlocks(msgHex), cBlocks = [], keystreamBlocks = [], steps = [];
//   let state = ivHex.padEnd(BLOCK_HEX_LEN, "0").slice(0, BLOCK_HEX_LEN);
//   for (let i = 0; i < mBlocks.length; i++) {
//     const ks = blockCipherEnc(keyHex, state), c = hexXOR(mBlocks[i], ks);
//     steps.push({ i, state, ks, mBlock: mBlocks[i], cBlock: c });
//     keystreamBlocks.push(ks); cBlocks.push(c); state = ks;
//   }
//   return { iv: ivHex, cipherBlocks: cBlocks, keystreamBlocks, ciphertext: ivHex + ":" + cBlocks.join(""), steps };
// }

// export function ofbDec(keyHex, ivHex, cipherBlocks) {
//   const mBlocks = [], steps = [];
//   let state = ivHex.padEnd(BLOCK_HEX_LEN, "0").slice(0, BLOCK_HEX_LEN);
//   for (let i = 0; i < cipherBlocks.length; i++) {
//     const ks = blockCipherEnc(keyHex, state), m = hexXOR(cipherBlocks[i], ks);
//     steps.push({ i, state, ks, cBlock: cipherBlocks[i], mBlock: m });
//     mBlocks.push(m); state = ks;
//   }
//   return { plainBlocks: mBlocks, plaintext: unpadHex(mBlocks.join("")), steps };
// }

// // ── CTR ──────────────────────────────────────────────────────────────────────
// export function ctrEnc(keyHex, msgHex) {
//   const r = freshRandom(), mBlocks = toBlocks(msgHex), cBlocks = [], steps = [];
//   const rInt = seedFromHex(r);
//   for (let i = 0; i < mBlocks.length; i++) {
//     const ctrHex = ((rInt + i) >>> 0).toString(16).padStart(BLOCK_HEX_LEN, "0").slice(0, BLOCK_HEX_LEN);
//     const ks = blockCipherEnc(keyHex, ctrHex), c = hexXOR(mBlocks[i], ks);
//     steps.push({ i, r, ctrHex, ks, mBlock: mBlocks[i], cBlock: c });
//     cBlocks.push(c);
//   }
//   return { r, cipherBlocks: cBlocks, ciphertext: r + ":" + cBlocks.join(""), steps };
// }

// export function ctrDec(keyHex, rHex, cipherBlocks) {
//   const mBlocks = [], steps = [];
//   const rInt = seedFromHex(rHex);
//   for (let i = 0; i < cipherBlocks.length; i++) {
//     const ctrHex = ((rInt + i) >>> 0).toString(16).padStart(BLOCK_HEX_LEN, "0").slice(0, BLOCK_HEX_LEN);
//     const ks = blockCipherEnc(keyHex, ctrHex), m = hexXOR(cipherBlocks[i], ks);
//     steps.push({ i, rHex, ctrHex, ks, cBlock: cipherBlocks[i], mBlock: m });
//     mBlocks.push(m);
//   }
//   return { plainBlocks: mBlocks, plaintext: unpadHex(mBlocks.join("")), steps };
// }

// // ── Unified API ──────────────────────────────────────────────────────────────
// export function Encrypt(mode, keyHex, msgHex) {
//   if (mode === "CBC") return cbcEnc(keyHex, freshRandom().padEnd(BLOCK_HEX_LEN, "0").slice(0, BLOCK_HEX_LEN), msgHex);
//   if (mode === "OFB") return ofbEnc(keyHex, freshRandom().padEnd(BLOCK_HEX_LEN, "0").slice(0, BLOCK_HEX_LEN), msgHex);
//   if (mode === "CTR") return ctrEnc(keyHex, msgHex);
//   throw new Error("Unknown mode: " + mode);
// }
// export function Decrypt(mode, keyHex, obj) {
//   if (mode === "CBC") return cbcDec(keyHex, obj.iv, obj.cipherBlocks);
//   if (mode === "OFB") return ofbDec(keyHex, obj.iv, obj.cipherBlocks);
//   if (mode === "CTR") return ctrDec(keyHex, obj.r, obj.cipherBlocks);
//   throw new Error("Unknown mode: " + mode);
// }

// // ── Attack demos ─────────────────────────────────────────────────────────────
// function cbcIVReuseAttack(keyHex, ivHex, msg1Hex, msg2Hex) {
//   const enc1 = cbcEnc(keyHex, ivHex, msg1Hex), enc2 = cbcEnc(keyHex, ivHex, msg2Hex);
//   const leaks = enc1.cipherBlocks.map((b, i) => enc2.cipherBlocks[i] === b ? i : -1).filter(i => i >= 0);
//   return { enc1, enc2, leaks };
// }

// function ofbKeystreamReuseAttack(keyHex, ivHex, msg1Hex, msg2Hex) {
//   const enc1 = ofbEnc(keyHex, ivHex, msg1Hex), enc2 = ofbEnc(keyHex, ivHex, msg2Hex);
//   return {
//     enc1, enc2,
//     xorBlocks: enc1.cipherBlocks.map((c, i) => i < enc2.cipherBlocks.length ? hexXOR(c, enc2.cipherBlocks[i]) : c),
//     xorPlain:  enc1.steps.map((s, i) => i < enc2.steps.length ? hexXOR(s.mBlock, enc2.steps[i].mBlock) : s.mBlock),
//   };
// }

// // ── Correctness tests ────────────────────────────────────────────────────────
// function runCorrectnessTests(keyHex) {
//   const msgs = [
//     { label: "Short (<1 block)", hex: "aabb" },
//     { label: "Exactly 1 block",  hex: "deadbeef04040404" },  // 8 bytes = 1 block exactly
//     { label: "Multi-block (3)",  hex: "deadbeef11223344aabbccdd00112233" },
//   ];
//   const results = [];
//   for (const mode of ["CBC", "OFB", "CTR"]) {
//     for (const msg of msgs) {
//       const enc = Encrypt(mode, keyHex, msg.hex);
//       const dec = Decrypt(mode, keyHex, enc);
//       results.push({ mode, label: msg.label, original: msg.hex, recovered: dec.plaintext, pass: dec.plaintext === msg.hex });
//     }
//   }
//   return results;
// }

// // ═══════════════════════════════════════════════════════════════════════════════
// // PA #0 routing table
// // ═══════════════════════════════════════════════════════════════════════════════

// const REDUCTIONS = {
//   "OWF→PRG":   { name: "HILL / hard-core-bit iteration",        pa: "PA#3",  security: "PRG-security from OWF hardness (HILL thm.)" },
//   "OWF→OWP":   { name: "DLP: f(x) = gˣ mod p is a OWP on ℤ_q", pa: "PA#1",  security: "OWP hardness = DLP hardness" },
//   "PRG→PRF":   { name: "GGM tree construction",                  pa: "PA#3",  security: "PRF-adv ≤ O(n)·PRG-adv (GGM thm.)" },
//   "PRF→PRP":   { name: "Luby-Rackoff 3-round Feistel",           pa: "PA#2",  security: "PRP-adv ≤ PRF-adv + q²/2ⁿ (LR thm.)" },
//   "PRF→MAC":   { name: "MAC_k(m) = F_k(m)",                      pa: "PA#5",  security: "MAC-forgery ⟹ PRF-distinguisher" },
//   "PRP→MAC":   { name: "PRP/PRF switching lemma, then MAC",       pa: "PA#5",  security: "PRP-adv ≈ PRF-adv (switching lemma)" },
//   "CRHF→HMAC": { name: "HMAC construction (PA#10)",               pa: "PA#10", security: "HMAC secure if compression fn is PRF" },
//   "HMAC→MAC":  { name: "HMAC is a secure EUF-CMA MAC",            pa: "PA#10", security: "Forgery breaks inner-hash PRF" },
//   "OWP→PRG":   { name: "OWP + hard-core predicate → PRG",        pa: "PA#3",  security: "G(x) = (f(x), b(x)) expands by 1 bit" },
//   "PRG→OWF":   { name: "Any PRG G is a OWF; f(s) = G(s)",        pa: "PA#3",  security: "Inversion of f recovers seed ⟹ breaks PRG" },
//   "PRF→PRG":   { name: "G(s) = F_s(0) ‖ F_s(1)",                 pa: "PA#3",  security: "PRG-dist ⟹ PRF-dist (contrapositive)" },
//   "PRP→PRF":   { name: "PRP/PRF switching lemma",                 pa: "PA#2",  security: "PRP over large domain ≈ PRF" },
//   "MAC→PRF":   { name: "EUF-CMA MAC on uniform msgs is PRF",      pa: "PA#5",  security: "Unforgeability ⟹ pseudorandomness" },
//   "MAC→CRHF":  { name: "Merkle-Damgård from MAC compression fn",  pa: "PA#7",  security: "Collision ⟹ MAC forgery" },
//   "MAC→HMAC":  { name: "Cast MAC as HMAC inner compression step",  pa: "PA#10", security: "HMAC is the natural PRF-based MAC structure" },
//   "HMAC→CRHF": { name: "Fix key k; H'(m) = HMAC_k(m) is CR",     pa: "PA#9",  security: "Collision = MAC forgery" },
// };
// const MULTI_STEP_PATHS = {
//   "OWF→PRF":  ["OWF→PRG","PRG→PRF"], "OWF→PRP":  ["OWF→PRG","PRG→PRF","PRF→PRP"],
//   "OWF→MAC":  ["OWF→PRG","PRG→PRF","PRF→MAC"], "OWF→HMAC": ["OWF→PRG","PRG→PRF","PRF→MAC","MAC→HMAC"],
//   "OWF→CRHF": ["OWF→PRG","PRG→PRF","PRF→MAC","MAC→CRHF"], "PRG→PRP":  ["PRG→PRF","PRF→PRP"],
//   "PRG→MAC":  ["PRG→PRF","PRF→MAC"], "PRG→HMAC": ["PRG→PRF","PRF→MAC","MAC→HMAC"],
//   "PRG→CRHF": ["PRG→PRF","PRF→MAC","MAC→CRHF"], "PRF→HMAC": ["PRF→MAC","MAC→HMAC"],
//   "PRF→CRHF": ["PRF→MAC","MAC→CRHF"], "PRP→HMAC": ["PRP→MAC","MAC→HMAC"],
//   "PRP→CRHF": ["PRP→MAC","MAC→CRHF"], "CRHF→MAC": ["CRHF→HMAC","HMAC→MAC"],
//   "OWP→PRF":  ["OWP→PRG","PRG→PRF"], "OWP→PRP":  ["OWP→PRG","PRG→PRF","PRF→PRP"],
//   "OWP→MAC":  ["OWP→PRG","PRG→PRF","PRF→MAC"], "OWP→HMAC": ["OWP→PRG","PRG→PRF","PRF→MAC","MAC→HMAC"],
//   "OWP→CRHF": ["OWP→PRG","PRG→PRF","PRF→MAC","MAC→CRHF"],
// };
// function getRoute(src, tgt) {
//   if (src === tgt) return null;
//   const d = `${src}→${tgt}`;
//   if (REDUCTIONS[d] !== undefined) return [d];
//   if (MULTI_STEP_PATHS[d]) return MULTI_STEP_PATHS[d];
//   return null;
// }
// const PA_COLORS = {
//   "PA#1": { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" }, "PA#2": { bg: "#EEEDFE", border: "#7F77DD", color: "#3C3489" },
//   "PA#3": { bg: "#E1F5EE", border: "#1D9E75", color: "#0F6E56" }, "PA#4": { bg: "#FEF3E2", border: "#E8A820", color: "#7A5200" },
//   "PA#5": { bg: "#FBEAF0", border: "#D4537E", color: "#72243E" }, "PA#7": { bg: "#FAEEDA", border: "#BA7517", color: "#854F0B" },
//   "PA#9": { bg: "#EAF3DE", border: "#639922", color: "#3B6D11" }, "PA#10": { bg: "#FAECE7", border: "#D85A30", color: "#993C1D" },
// };
// const COL1_TAG_COLORS = {
//   "AES-128": { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" }, "DLP": { bg: "#EEEDFE", border: "#7F77DD", color: "#3C3489" },
//   "PRG": { bg: "#E1F5EE", border: "#1D9E75", color: "#0F6E56" }, "GGM": { bg: "#FAEEDA", border: "#BA7517", color: "#854F0B" },
//   "L-R": { bg: "#FBEAF0", border: "#D4537E", color: "#72243E" }, "MAC": { bg: "#FAECE7", border: "#D85A30", color: "#993C1D" },
//   "M-D": { bg: "#EAF3DE", border: "#639922", color: "#3B6D11" }, "HMAC": { bg: "#EAF3DE", border: "#639922", color: "#3B6D11" },
//   "PRG→PRF": { bg: "#FAEEDA", border: "#BA7517", color: "#854F0B" },
// };
// function makeAESFoundation(keyHex) { const seed = seedFromHex(keyHex) ^ 0xaabb; return { name: "AES-128 (PRP)", paTag: "AES-128", paNum: "PA#2", rawOut: fakeHex(seed, 8) }; }
// function makeDLPFoundation(keyHex) { const seed = seedFromHex(keyHex) ^ 0x1337; return { name: "DLP (gˣ mod p)", paTag: "DLP", paNum: "PA#1", rawOut: fakeHex(seed, 8) }; }
// function buildCol1Steps(src, foundation) {
//   const { paTag, paNum, rawOut } = foundation, v0 = seedFromHex(rawOut);
//   const steps = [{ tag: paTag, fn: paTag === "AES-128" ? "AES₁₂₈(key)" : "g^key mod p", inputHex: "key", outputHex: rawOut, pa: paNum, implemented: false }];
//   if (src === "OWF" || src === "OWP") return steps;
//   if (src === "PRG") { steps.push({ tag: "PRG", fn: "G(s) = F_s(0)‖F_s(1)", inputHex: rawOut, outputHex: fakeHex(v0^0x2222,16), pa: "PA#3", implemented: false }); }
//   else if (src === "PRF") { const prg=fakeHex(v0^0x2222,16); steps.push({tag:"PRG",fn:"G(s)=F_s(0)‖F_s(1)",inputHex:rawOut,outputHex:prg,pa:"PA#3",implemented:false}); steps.push({tag:"GGM",fn:"GGM tree: F_k(b₁⋯bₙ)",inputHex:prg,outputHex:fakeHex(v0^0x3333,8),pa:"PA#3",implemented:false}); }
//   else if (src === "PRP") { const prg=fakeHex(v0^0x2222,16),prf=fakeHex(v0^0x3333,8); steps.push({tag:"PRG",fn:"G(s)=F_s(0)‖F_s(1)",inputHex:rawOut,outputHex:prg,pa:"PA#3",implemented:false}); steps.push({tag:"GGM",fn:"GGM tree→PRF",inputHex:prg,outputHex:prf,pa:"PA#3",implemented:false}); steps.push({tag:"L-R",fn:"Luby-Rackoff 3-round Feistel→PRP",inputHex:prf,outputHex:fakeHex(v0^0x4444,8),pa:"PA#2",implemented:false}); }
//   else if (src === "MAC") { const prg=fakeHex(v0^0x2222,16),prf=fakeHex(v0^0x3333,8); steps.push({tag:"PRG",fn:"G(s)=F_s(0)‖F_s(1)",inputHex:rawOut,outputHex:prg,pa:"PA#3",implemented:false}); steps.push({tag:"GGM",fn:"GGM tree→PRF",inputHex:prg,outputHex:prf,pa:"PA#3",implemented:false}); steps.push({tag:"MAC",fn:"MAC_k(m)=F_k(m)",inputHex:prf,outputHex:fakeHex(v0^0x5555,8),pa:"PA#5",implemented:false}); }
//   else if (src === "CRHF") { const prf=fakeHex(v0^0x3333,8); steps.push({tag:"PRG→PRF",fn:"GGM tree(PRG→PRF)",inputHex:rawOut,outputHex:prf,pa:"PA#3",implemented:false}); steps.push({tag:"M-D",fn:"Merkle-Damgård compression→CRHF",inputHex:prf,outputHex:fakeHex(v0^0x6666,8),pa:"PA#7",implemented:false}); }
//   else if (src === "HMAC") { const prf=fakeHex(v0^0x3333,8); steps.push({tag:"PRG→PRF",fn:"GGM tree(PRG→PRF)",inputHex:rawOut,outputHex:prf,pa:"PA#3",implemented:false}); steps.push({tag:"HMAC",fn:"HMAC_k(m)=H((k⊕opad)‖H((k⊕ipad)‖m))",inputHex:prf,outputHex:fakeHex(v0^0x7777,8),pa:"PA#10",implemented:false}); }
//   return steps;
// }
// function buildCol2Steps(chain, oracleA, msgHex) {
//   if (!chain) return null;
//   return chain.map((edge, i) => {
//     const r = REDUCTIONS[edge]; if (!r) return { tag:"?",fn:edge,inputHex:null,outputHex:null,pa:null,security:null,implemented:false };
//     const qr = oracleA(msgHex + i.toString(16).padStart(2,"0"));
//     return { tag:r.pa, fn:`${edge.replace("→"," → ")}: ${r.name}`, inputHex:qr, outputHex:fakeHex(seedFromHex(qr)^(i*0x9abc),8), pa:r.pa, security:r.security, implemented:false };
//   });
// }
// const PRIMITIVES = ["OWF","OWP","PRG","PRF","PRP","MAC","CRHF","HMAC"];

// // ═══════════════════════════════════════════════════════════════════════════════
// // Shared UI
// // ═══════════════════════════════════════════════════════════════════════════════

// function Tag({label,colorMap}) { const c=colorMap[label]||{bg:"var(--color-background-secondary)",border:"var(--color-border-secondary)",color:"var(--color-text-secondary)"}; return <span style={{fontSize:10,padding:"3px 8px",borderRadius:4,whiteSpace:"nowrap",fontWeight:500,fontFamily:"var(--font-mono)",flexShrink:0,background:c.bg,border:`0.5px solid ${c.border}`,color:c.color}}>{label}</span>; }
// function StepRow({tag,fn,inputHex,outputHex,pa,implemented,tagColorMap}) { return (<div style={{display:"flex",alignItems:"flex-start",gap:10,padding:"9px 0",borderBottom:"0.5px solid var(--color-border-tertiary)"}}><Tag label={tag} colorMap={tagColorMap}/><div style={{flex:1,minWidth:0}}><div style={{fontSize:11,color:"var(--color-text-secondary)",marginBottom:4,fontFamily:"var(--font-mono)"}}>{fn}</div>{inputHex&&<div style={{display:"flex",alignItems:"baseline",gap:6,marginBottom:3}}><span style={{fontSize:10,color:"var(--color-text-secondary)",minWidth:28,flexShrink:0}}>in:</span><span style={{fontFamily:"var(--font-mono)",fontSize:11,color:"var(--color-text-secondary)",wordBreak:"break-all"}}>{inputHex==="key"?"<user key input>":`0x${inputHex}`}</span></div>}<div style={{display:"flex",alignItems:"baseline",gap:6}}><span style={{fontSize:10,color:"var(--color-text-secondary)",minWidth:28,flexShrink:0}}>out:</span>{!implemented?<span style={{fontSize:11,color:"var(--color-text-secondary)",fontStyle:"italic"}}>Not implemented yet (due: {pa||"PA#?"})</span>:<span style={{fontFamily:"var(--font-mono)",fontSize:12,color:"var(--color-text-primary)",wordBreak:"break-all"}}>0x{outputHex}</span>}</div></div></div>); }
// function ColCard({headerLabel,headerStyle,children}) { return (<div style={{background:"var(--color-background-primary)",border:"0.5px solid var(--color-border-tertiary)",borderRadius:"var(--border-radius-lg)",overflow:"hidden",display:"flex",flexDirection:"column"}}><div style={{padding:"10px 16px",fontSize:10,fontWeight:500,letterSpacing:"0.07em",textTransform:"uppercase",...headerStyle}}>{headerLabel}</div><div style={{padding:"16px",flex:1}}>{children}</div></div>); }
// function FieldLabel({children}) { return <div style={{fontSize:10,color:"var(--color-text-secondary)",textTransform:"uppercase",letterSpacing:"0.07em",fontWeight:500,marginBottom:5}}>{children}</div>; }
// function StyledSelect({value,onChange,options,exclude}) { return <select value={value} onChange={e=>onChange(e.target.value)} style={{width:"100%",padding:"8px 12px",fontSize:13,border:"0.5px solid var(--color-border-secondary)",borderRadius:"var(--border-radius-md)",background:"var(--color-background-primary)",color:"var(--color-text-primary)",fontFamily:"var(--font-mono)",outline:"none"}}>{options.filter(o=>o!==exclude).map(o=><option key={o} value={o}>{o}</option>)}</select>; }
// function TextInput({value,onChange,placeholder}) { return <input type="text" value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder} style={{width:"100%",padding:"8px 12px",fontSize:13,border:"0.5px solid var(--color-border-secondary)",borderRadius:"var(--border-radius-md)",background:"var(--color-background-primary)",color:"var(--color-text-primary)",fontFamily:"var(--font-mono)",outline:"none"}}/>; }
// function ToggleBar({value,onChange,options}) { return (<div style={{display:"flex",gap:4,background:"var(--color-background-secondary)",border:"0.5px solid var(--color-border-tertiary)",borderRadius:"var(--border-radius-md)",padding:3}}>{options.map(opt=>{const active=value===opt.value,ac=opt.activeStyle||{};return<button key={opt.value} onClick={()=>onChange(opt.value)} style={{flex:1,padding:"7px 14px",fontSize:12,fontWeight:active?500:400,border:active?`0.5px solid ${ac.border||"var(--color-border-info)"}`:"0.5px solid transparent",borderRadius:"var(--border-radius-md)",background:active?(ac.bg||"var(--color-background-info)"):"transparent",color:active?(ac.color||"var(--color-text-info)"):"var(--color-text-secondary)",cursor:"pointer",transition:"all 0.15s",fontFamily:"var(--font-sans)"}}>{opt.label}</button>;})}</div>); }
// function SectionHeading({children}) { return <div style={{fontSize:10,color:"var(--color-text-secondary)",textTransform:"uppercase",letterSpacing:"0.07em",fontWeight:500,marginBottom:8,marginTop:4}}>{children}</div>; }
// function WarnBox({children}) { return <div style={{padding:"10px 14px",fontSize:12,borderRadius:"var(--border-radius-md)",background:"#FAEEDA",color:"#854F0B",border:"0.5px solid #BA7517"}}>{children}</div>; }
// function Divider({label}) { return (<div style={{display:"flex",alignItems:"center",gap:12,margin:"28px 0 20px"}}><div style={{flex:1,height:"0.5px",background:"var(--color-border-tertiary)"}}/><span style={{fontSize:11,color:"var(--color-text-secondary)",fontWeight:500,letterSpacing:"0.07em",textTransform:"uppercase",whiteSpace:"nowrap"}}>{label}</span><div style={{flex:1,height:"0.5px",background:"var(--color-border-tertiary)"}}/></div>); }
// function TestBadge({pass}) { return <span style={{fontSize:10,padding:"2px 8px",borderRadius:4,fontWeight:500,background:pass?"#E1F5EE":"#FCEBEB",border:`0.5px solid ${pass?"#1D9E75":"#E24B4A"}`,color:pass?"#0F6E56":"#A32D2D"}}>{pass?"PASS":"FAIL"}</span>; }
// function MonoBox({children,maxH=64}) { return <div style={{padding:"10px 12px",background:"var(--color-background-secondary)",borderRadius:"var(--border-radius-md)",fontFamily:"var(--font-mono)",fontSize:11,wordBreak:"break-all",color:"var(--color-text-primary)",maxHeight:maxH,overflowY:"auto"}}>{children}</div>; }

// // ═══════════════════════════════════════════════════════════════════════════════
// // PA #4 visual sub-components
// // ═══════════════════════════════════════════════════════════════════════════════

// const BLOCK_PALETTE = [
//   {bg:"#E6F1FB",border:"#378ADD",text:"#185FA5"},{bg:"#E1F5EE",border:"#1D9E75",text:"#0F6E56"},
//   {bg:"#EEEDFE",border:"#7F77DD",text:"#3C3489"},{bg:"#FEF3E2",border:"#E8A820",text:"#7A5200"},
// ];

// function Arrow({vertical,label}) {
//   if(vertical) return <div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:1,margin:"2px 0"}}>{label&&<span style={{fontSize:9,color:"var(--color-text-secondary)"}}>{label}</span>}<span style={{color:"var(--color-text-secondary)",fontSize:14}}>↓</span></div>;
//   return <div style={{margin:"0 4px"}}><span style={{color:"var(--color-text-secondary)",fontSize:14}}>→</span></div>;
// }
// function XorSymbol() { return <div style={{width:22,height:22,borderRadius:"50%",border:"1.5px solid #BA7517",display:"flex",alignItems:"center",justifyContent:"center",fontSize:13,color:"#BA7517",fontWeight:700,background:"#FAEEDA",flexShrink:0}}>⊕</div>; }
// function EkBox({label}) { return <div style={{padding:"4px 10px",borderRadius:6,background:"#FEF3E2",border:"1px solid #E8A820",fontFamily:"var(--font-mono)",fontSize:11,color:"#7A5200",fontWeight:600,whiteSpace:"nowrap"}}>{label||"E_k"}</div>; }

// function CBCAnimator({steps,iv,flippedBlock}) {
//   return (<div style={{overflowX:"auto",paddingBottom:8}}><div style={{display:"flex",alignItems:"flex-end",gap:0,minWidth:"fit-content"}}>
//     <div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:4,marginRight:8}}><div style={{padding:"5px 10px",borderRadius:6,background:"#EAF3DE",border:"1px solid #639922",fontFamily:"var(--font-mono)",fontSize:10,color:"#3B6D11",fontWeight:600}}>IV</div><span style={{fontSize:9,color:"#639922",fontFamily:"var(--font-mono)"}}>0x{iv?.slice(0,6)}…</span></div>
//     {(steps||[]).map((step,i)=>{const pc=BLOCK_PALETTE[i%BLOCK_PALETTE.length],isF=flippedBlock===i,cs=isF?{bg:"#FCEBEB",border:"#E24B4A",text:"#A32D2D"}:pc; return (<div key={i} style={{display:"flex",alignItems:"center"}}><Arrow/><div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:3}}><div style={{padding:"4px 8px",borderRadius:5,background:pc.bg,border:`1px solid ${pc.border}`,fontFamily:"var(--font-mono)",fontSize:9,color:pc.text}}>M{i}: 0x{step.mBlock?.slice(0,8)}…</div><Arrow vertical/><XorSymbol/><Arrow vertical/><EkBox/><Arrow vertical/><div style={{padding:"4px 8px",borderRadius:5,background:cs.bg,border:`1px solid ${cs.border}`,fontFamily:"var(--font-mono)",fontSize:9,color:cs.text,fontWeight:isF?700:500}}>C{i}: 0x{step.cBlock?.slice(0,8)}…{isF?" ⚡":""}</div></div></div>);})}
//   </div></div>);
// }
// function OFBAnimator({steps,iv,flippedBlock}) {
//   return (<div style={{overflowX:"auto",paddingBottom:8}}><div style={{display:"flex",alignItems:"flex-end",gap:0,minWidth:"fit-content"}}>
//     <div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:4,marginRight:4}}><div style={{padding:"5px 10px",borderRadius:6,background:"#EAF3DE",border:"1px solid #639922",fontFamily:"var(--font-mono)",fontSize:10,color:"#3B6D11",fontWeight:600}}>IV</div><span style={{fontSize:9,color:"#639922",fontFamily:"var(--font-mono)"}}>0x{iv?.slice(0,6)}…</span></div>
//     {(steps||[]).map((step,i)=>{const pc=BLOCK_PALETTE[i%BLOCK_PALETTE.length],isF=flippedBlock===i,cs=isF?{bg:"#FCEBEB",border:"#E24B4A",text:"#A32D2D"}:pc; return (<div key={i} style={{display:"flex",alignItems:"center"}}><Arrow/><div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:3}}><EkBox/><Arrow vertical label="ks"/><div style={{padding:"3px 7px",borderRadius:4,background:"#FEF3E2",border:"1px solid #E8A820",fontFamily:"var(--font-mono)",fontSize:9,color:"#7A5200"}}>KS{i}: 0x{step.ks?.slice(0,6)}…</div><span style={{fontSize:9,color:"var(--color-text-secondary)"}}>⊕ M{i}</span><Arrow vertical/><div style={{padding:"4px 8px",borderRadius:5,background:cs.bg,border:`1px solid ${cs.border}`,fontFamily:"var(--font-mono)",fontSize:9,color:cs.text,fontWeight:isF?700:500}}>C{i}: 0x{step.cBlock?.slice(0,8)}…{isF?" ⚡":""}</div></div></div>);})}
//   </div></div>);
// }
// function CTRAnimator({steps,r,flippedBlock}) {
//   return (<div style={{overflowX:"auto",paddingBottom:8}}><div style={{display:"flex",alignItems:"flex-end",gap:0,minWidth:"fit-content"}}>
//     <div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:4,marginRight:4}}><div style={{padding:"5px 10px",borderRadius:6,background:"#EEEDFE",border:"1px solid #7F77DD",fontFamily:"var(--font-mono)",fontSize:10,color:"#3C3489",fontWeight:600}}>r</div><span style={{fontSize:9,color:"#3C3489",fontFamily:"var(--font-mono)"}}>0x{r?.slice(0,6)}…</span></div>
//     {(steps||[]).map((step,i)=>{const pc=BLOCK_PALETTE[i%BLOCK_PALETTE.length],isF=flippedBlock===i,cs=isF?{bg:"#FCEBEB",border:"#E24B4A",text:"#A32D2D"}:pc; return (<div key={i} style={{display:"flex",alignItems:"center"}}><Arrow/><div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:3}}><div style={{padding:"3px 7px",borderRadius:4,background:"#EEEDFE",border:"1px solid #7F77DD",fontFamily:"var(--font-mono)",fontSize:9,color:"#3C3489"}}>r+{i}</div><Arrow vertical/><EkBox label={`F_k(r+${i})`}/><Arrow vertical label="ks"/><span style={{fontSize:9,color:"var(--color-text-secondary)"}}>⊕ M{i}</span><Arrow vertical/><div style={{padding:"4px 8px",borderRadius:5,background:cs.bg,border:`1px solid ${cs.border}`,fontFamily:"var(--font-mono)",fontSize:9,color:cs.text,fontWeight:isF?700:500}}>C{i}: 0x{step.cBlock?.slice(0,8)}…{isF?" ⚡":""}</div></div></div>);})}
//   </div><div style={{marginTop:6,fontSize:10,color:"var(--color-text-secondary)",fontStyle:"italic"}}>All blocks computed in parallel — CTR is fully parallelizable ✓</div></div>);
// }
// function ErrorPropBox({mode,flippedBlock,numBlocks}) {
//   if(flippedBlock===null)return null;
//   const affected=mode==="CBC"?[flippedBlock,flippedBlock+1].filter(b=>b<numBlocks):[flippedBlock];
//   return (<div style={{padding:"10px 14px",borderRadius:"var(--border-radius-md)",background:"#FCEBEB",border:"0.5px solid #E24B4A",fontSize:12,color:"#A32D2D",marginTop:10}}><strong>Error propagation ({mode}):</strong> Flipping a bit in C{flippedBlock} corrupts {affected.map(b=>`M${b}`).join(", ")}. {mode==="CBC"&&"CBC propagates to the next block too (2-block error propagation)."}{mode==="OFB"&&"OFB: no error propagation beyond the same block."}{mode==="CTR"&&"CTR: no error propagation beyond the same block."}</div>);
// }

// // ═══════════════════════════════════════════════════════════════════════════════
// // PA #4 Panel — all fixes applied
// // ═══════════════════════════════════════════════════════════════════════════════

// function PA4Panel() {
//   const [mode, setMode] = useState("CBC");
//   const [keyHex, setKeyHex] = useState("c0ffee11");
//   const [msgHex, setMsgHex] = useState("deadbeef11223344aabbccdd");
//   const [ivHex, setIvHex] = useState("0011223344556677");
//   const [encResult, setEncResult] = useState(null);
//   const [decResult, setDecResult] = useState(null);
//   const [flippedBlock, setFlippedBlock] = useState(null);
//   const [flipDecResult, setFlipDecResult] = useState(null);

//   // FIX: Reuse IV state — always visible for CBC, not gated on encResult
//   // Default msg2 shares first 16 hex chars (= 8 bytes = 1 block) with msgHex
//   const [reuseIVMsg2, setReuseIVMsg2] = useState("deadbeef11223344bbbbbbbb");
//   const [reuseIVResult, setReuseIVResult] = useState(null);

//   const [reuseMsg1, setReuseMsg1] = useState("deadbeef11223344");
//   const [reuseMsg2, setReuseMsg2] = useState("deadbeef99887766");
//   const [reuseResult, setReuseResult] = useState(null);
//   const [ofbMsg1, setOfbMsg1] = useState("aabbccdd11223344");
//   const [ofbMsg2, setOfbMsg2] = useState("11223344aabbccdd");
//   const [ofbReuseResult, setOfbReuseResult] = useState(null);
//   const [corrResults, setCorrResults] = useState(null);

//   function doEncrypt() {
//     let res;
//     if (mode === "CBC") res = cbcEnc(keyHex, ivHex, msgHex);
//     else if (mode === "OFB") res = ofbEnc(keyHex, ivHex, msgHex);
//     else res = ctrEnc(keyHex, msgHex);
//     setEncResult(res); setDecResult(null); setFlippedBlock(null); setFlipDecResult(null); setReuseIVResult(null);
//   }

//   function doDecrypt() {
//     if (!encResult) return;
//     let res;
//     if (mode === "CBC") res = cbcDec(keyHex, encResult.iv, encResult.cipherBlocks);
//     else if (mode === "OFB") res = ofbDec(keyHex, encResult.iv, encResult.cipherBlocks);
//     else res = ctrDec(keyHex, encResult.r, encResult.cipherBlocks);
//     setDecResult(res);
//   }

//   function doFlipBlock(blockIdx) {
//     if (!encResult) return;
//     setFlippedBlock(blockIdx);
//     const flipped = encResult.cipherBlocks.map((b,i) => i===blockIdx ? hexXOR(b,"0100000000000000") : b);
//     let res;
//     if (mode === "CBC") res = cbcDec(keyHex, encResult.iv, flipped);
//     else if (mode === "OFB") res = ofbDec(keyHex, encResult.iv, flipped);
//     else res = ctrDec(keyHex, encResult.r, flipped);
//     setFlipDecResult(res);
//   }

//   // FIX: Reuse IV — use the SAME IV from the current encrypt result if available,
//   // otherwise fall back to the manually entered ivHex.
//   function doReuseIV() {
//     const useIV = encResult ? encResult.iv : ivHex;
//     const enc2 = cbcEnc(keyHex, useIV, reuseIVMsg2);
//     const origBlocks = encResult ? encResult.cipherBlocks : cbcEnc(keyHex, useIV, msgHex).cipherBlocks;
//     const leaks = origBlocks.map((b,i) => enc2.cipherBlocks[i] === b ? i : -1).filter(i => i >= 0);
//     setReuseIVResult({ enc2, leaks, usedIV: useIV, origBlocks });
//   }

//   function doCBCReuseAttack() { setReuseResult(cbcIVReuseAttack(keyHex, ivHex, reuseMsg1, reuseMsg2)); }
//   function doOFBReuseAttack() { setOfbReuseResult(ofbKeystreamReuseAttack(keyHex, ivHex, ofbMsg1, ofbMsg2)); }
//   function doCorrectnessTests() { setCorrResults(runCorrectnessTests(keyHex)); }

//   const modeInfo = {
//     CBC: { label:"CBC — Cipher Block Chaining", color:"#185FA5", bg:"#E6F1FB", border:"#378ADD", desc:"Cᵢ = E_k(Cᵢ₋₁ ⊕ Mᵢ). Sequential enc, parallel dec. 2-block error propagation." },
//     OFB: { label:"OFB — Output Feedback", color:"#0F6E56", bg:"#E1F5EE", border:"#1D9E75", desc:"Sᵢ = E_k(Sᵢ₋₁); Cᵢ = Mᵢ ⊕ Sᵢ. Keystream independent of plaintext. No error propagation." },
//     CTR: { label:"CTR — Randomized Counter", color:"#3C3489", bg:"#EEEDFE", border:"#7F77DD", desc:"Cᵢ = Mᵢ ⊕ F_k(r+i). Fully parallelizable. r sampled fresh each encryption." },
//   };
//   const mi = modeInfo[mode];
//   const numBlocks = encResult?.cipherBlocks?.length || 0;

//   return (
//     <div style={{border:"0.5px solid var(--color-border-tertiary)",borderRadius:"var(--border-radius-lg)",overflow:"hidden"}}>
//       {/* Header */}
//       <div style={{padding:"10px 16px",background:"#FEF3E2",borderBottom:"0.5px solid #E8A820",display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:10}}>
//         <div style={{fontSize:10,fontWeight:500,letterSpacing:"0.07em",textTransform:"uppercase",color:"#7A5200"}}>PA #4 — Modes of Operation: CBC · OFB · CTR</div>
//         <ToggleBar value={mode} onChange={v=>{setMode(v);setEncResult(null);setDecResult(null);setFlippedBlock(null);setFlipDecResult(null);setReuseResult(null);setOfbReuseResult(null);setReuseIVResult(null);}} options={[
//           {value:"CBC",label:"CBC",activeStyle:{bg:"#E6F1FB",border:"#378ADD",color:"#185FA5"}},
//           {value:"OFB",label:"OFB",activeStyle:{bg:"#E1F5EE",border:"#1D9E75",color:"#0F6E56"}},
//           {value:"CTR",label:"CTR",activeStyle:{bg:"#EEEDFE",border:"#7F77DD",color:"#3C3489"}},
//         ]}/>
//       </div>

//       <div style={{padding:"16px"}}>
//         {/* Mode banner */}
//         <div style={{padding:"10px 14px",borderRadius:"var(--border-radius-md)",background:mi.bg,border:`0.5px solid ${mi.border}`,color:mi.color,fontSize:12,marginBottom:16}}>
//           <strong>{mi.label}</strong> — {mi.desc}
//         </div>

//         {/* Inputs */}
//         <div style={{display:"grid",gridTemplateColumns:"minmax(0,1fr) minmax(0,1fr) minmax(0,1fr)",gap:12,marginBottom:14}}>
//           <div><FieldLabel>Key k (hex)</FieldLabel><TextInput value={keyHex} onChange={setKeyHex} placeholder="e.g. c0ffee11"/></div>
//           <div><FieldLabel>Message m (hex — try 3+ blocks)</FieldLabel><TextInput value={msgHex} onChange={setMsgHex} placeholder="e.g. deadbeef11223344aabbccdd"/></div>
//           {mode !== "CTR"
//             ? <div><FieldLabel>IV (hex)</FieldLabel><TextInput value={ivHex} onChange={setIvHex} placeholder="e.g. 0011223344556677"/></div>
//             : <div style={{display:"flex",flexDirection:"column",justifyContent:"flex-end"}}><div style={{padding:"8px 12px",background:"var(--color-background-secondary)",borderRadius:"var(--border-radius-md)",fontSize:11,color:"var(--color-text-secondary)"}}>CTR: nonce r sampled fresh per call (no IV needed)</div></div>
//           }
//         </div>

//         <div style={{display:"flex",gap:10,marginBottom:14}}>
//           <button onClick={doEncrypt} style={{padding:"8px 20px",fontSize:12,fontWeight:500,border:`0.5px solid ${mi.border}`,borderRadius:"var(--border-radius-md)",background:mi.bg,color:mi.color,cursor:"pointer",fontFamily:"var(--font-sans)"}}>Encrypt ({mode}_Enc)</button>
//           <button onClick={doDecrypt} disabled={!encResult} style={{padding:"8px 20px",fontSize:12,fontWeight:500,border:"0.5px solid var(--color-border-secondary)",borderRadius:"var(--border-radius-md)",background:encResult?"var(--color-background-secondary)":"var(--color-background-tertiary)",color:encResult?"var(--color-text-primary)":"var(--color-text-secondary)",cursor:encResult?"pointer":"not-allowed",fontFamily:"var(--font-sans)"}}>Decrypt ({mode}_Dec)</button>
//         </div>

//         {/* FIX: Reuse IV section — ALWAYS visible for CBC, no longer gated on encResult */}
//         {mode === "CBC" && (
//           <div style={{marginBottom:16,padding:"12px 14px",borderRadius:"var(--border-radius-md)",background:"#E6F1FB",border:"0.5px solid #378ADD"}}>
//             <div style={{fontSize:12,fontWeight:500,color:"#185FA5",marginBottom:8}}>
//               Reuse IV attack — encrypt a second message with the same IV{encResult ? ` (0x${encResult.iv?.slice(0,12)}…)` : ` (0x${ivHex.slice(0,12)}…)`}
//             </div>
//             <div style={{fontSize:11,color:"#185FA5",marginBottom:10,opacity:0.8}}>
//               The first 16 hex chars of m and m' are the same block. If E_k(IV ⊕ M₀) = E_k(IV ⊕ M'₀) they will match (i.e. M₀ = M'₀ is revealed). Click Encrypt first, then re-encrypt below.
//             </div>
//             <div style={{marginBottom:8}}>
//               <FieldLabel>Second message m' — shares first block with m above (first 16 hex chars identical)</FieldLabel>
//               <TextInput value={reuseIVMsg2} onChange={setReuseIVMsg2} placeholder="e.g. deadbeef11223344bbbbbbbb"/>
//             </div>
//             <button onClick={doReuseIV} style={{width:"100%",padding:"7px",fontSize:12,fontWeight:500,border:"0.5px solid #E24B4A",borderRadius:"var(--border-radius-md)",background:"#FCEBEB",color:"#A32D2D",cursor:"pointer",fontFamily:"var(--font-sans)",marginBottom:reuseIVResult?10:0}}>
//               Re-encrypt m' with same IV
//             </button>
//             {reuseIVResult && (
//               <div>
//                 <div style={{fontSize:10,color:"var(--color-text-secondary)",textTransform:"uppercase",marginBottom:6}}>Original C vs C' — 🔴 = matching cipher blocks (Mᵢ = M'ᵢ revealed)</div>
//                 <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:8}}>
//                   {reuseIVResult.origBlocks.map((b,i)=>{
//                     const b2=reuseIVResult.enc2.cipherBlocks[i], match=reuseIVResult.leaks.includes(i);
//                     return (<div key={i} style={{display:"flex",flexDirection:"column",gap:2}}>
//                       <span style={{fontFamily:"var(--font-mono)",fontSize:9,padding:"2px 6px",borderRadius:3,background:"#E6F1FB",color:"#185FA5",border:"0.5px solid #378ADD"}}>C{i}: 0x{b.slice(0,8)}…</span>
//                       <span style={{fontFamily:"var(--font-mono)",fontSize:9,padding:"2px 6px",borderRadius:3,background:match?"#FCEBEB":"#E1F5EE",color:match?"#A32D2D":"#0F6E56",border:`0.5px solid ${match?"#E24B4A":"#1D9E75"}`}}>C'{i}: 0x{b2?.slice(0,8)}… {match?"🔴":"✓"}</span>
//                     </div>);
//                   })}
//                 </div>
//                 {reuseIVResult.leaks.length > 0
//                   ? <div style={{padding:"8px 12px",borderRadius:"var(--border-radius-md)",background:"#FCEBEB",border:"0.5px solid #E24B4A",color:"#A32D2D",fontSize:11}}>Matching cipher blocks at {reuseIVResult.leaks.map(i=>`C${i}`).join(", ")} — adversary learns Mᵢ = M'ᵢ for those positions!</div>
//                   : <div style={{padding:"8px 12px",borderRadius:"var(--border-radius-md)",background:"#FAEEDA",border:"0.5px solid #BA7517",color:"#854F0B",fontSize:11}}>No matching blocks yet — click Encrypt first, then try re-encrypting. Make sure the first 16 hex chars of both messages are identical (e.g. "deadbeef11223344").</div>
//                 }
//               </div>
//             )}
//           </div>
//         )}

//         {/* Animator + step table */}
//         {encResult && (
//           <div style={{marginBottom:16}}>
//             <SectionHeading>Block-by-block animation — {encResult.steps?.length} block(s)</SectionHeading>
//             <div style={{padding:"14px",background:"var(--color-background-secondary)",borderRadius:"var(--border-radius-md)",marginBottom:10,overflowX:"auto"}}>
//               {mode==="CBC"&&<CBCAnimator steps={encResult.steps} iv={encResult.iv} flippedBlock={flippedBlock}/>}
//               {mode==="OFB"&&<OFBAnimator steps={encResult.steps} iv={encResult.iv} flippedBlock={flippedBlock}/>}
//               {mode==="CTR"&&<CTRAnimator steps={encResult.steps} r={encResult.r} flippedBlock={flippedBlock}/>}
//             </div>

//             {/* Step table */}
//             <div style={{border:"0.5px solid var(--color-border-tertiary)",borderRadius:"var(--border-radius-md)",overflow:"hidden",marginBottom:10}}>
//               <div style={{display:"grid",gridTemplateColumns:"40px 1fr 1fr 1fr 1fr",background:"var(--color-background-secondary)",borderBottom:"0.5px solid var(--color-border-tertiary)"}}>
//                 {(mode==="CBC"?["Blk","Prev (IV/Cᵢ₋₁)","Mᵢ","Mᵢ⊕Prev","Cᵢ=E_k(xor)"]:mode==="OFB"?["Blk","State","KSᵢ","Mᵢ","Cᵢ=Mᵢ⊕KS"]:["Blk","Counter r+i","F_k(r+i)","Mᵢ","Cᵢ=Mᵢ⊕F_k"]).map((h,i)=><div key={i} style={{padding:"6px 10px",fontSize:10,fontWeight:500,color:"var(--color-text-secondary)",textTransform:"uppercase"}}>{h}</div>)}
//               </div>
//               {encResult.steps?.map((step,i)=>{const pc=BLOCK_PALETTE[i%BLOCK_PALETTE.length]; return (<div key={i} style={{display:"grid",gridTemplateColumns:"40px 1fr 1fr 1fr 1fr",borderBottom:"0.5px solid var(--color-border-tertiary)",background:flippedBlock===i?"#FFF5F5":"transparent"}}>
//                 <div style={{padding:"6px 10px",fontFamily:"var(--font-mono)",fontSize:11,color:pc.text,background:pc.bg,display:"flex",alignItems:"center"}}>{i}</div>
//                 {mode==="CBC"&&<><div style={{padding:"6px 10px",fontFamily:"var(--font-mono)",fontSize:10,color:"var(--color-text-secondary)"}}>0x{step.prev?.slice(0,12)}…</div><div style={{padding:"6px 10px",fontFamily:"var(--font-mono)",fontSize:10,color:"var(--color-text-secondary)"}}>0x{step.mBlock?.slice(0,12)}…</div><div style={{padding:"6px 10px",fontFamily:"var(--font-mono)",fontSize:10,color:"#854F0B"}}>0x{step.xored?.slice(0,12)}…</div><div style={{padding:"6px 10px",fontFamily:"var(--font-mono)",fontSize:10,color:pc.text,fontWeight:500}}>0x{step.cBlock?.slice(0,12)}…</div></>}
//                 {mode==="OFB"&&<><div style={{padding:"6px 10px",fontFamily:"var(--font-mono)",fontSize:10,color:"var(--color-text-secondary)"}}>0x{step.state?.slice(0,12)}…</div><div style={{padding:"6px 10px",fontFamily:"var(--font-mono)",fontSize:10,color:"#7A5200"}}>0x{step.ks?.slice(0,12)}…</div><div style={{padding:"6px 10px",fontFamily:"var(--font-mono)",fontSize:10,color:"var(--color-text-secondary)"}}>0x{step.mBlock?.slice(0,12)}…</div><div style={{padding:"6px 10px",fontFamily:"var(--font-mono)",fontSize:10,color:pc.text,fontWeight:500}}>0x{step.cBlock?.slice(0,12)}…</div></>}
//                 {mode==="CTR"&&<><div style={{padding:"6px 10px",fontFamily:"var(--font-mono)",fontSize:10,color:"#3C3489"}}>0x{step.ctrHex?.slice(0,12)}…</div><div style={{padding:"6px 10px",fontFamily:"var(--font-mono)",fontSize:10,color:"#7A5200"}}>0x{step.ks?.slice(0,12)}…</div><div style={{padding:"6px 10px",fontFamily:"var(--font-mono)",fontSize:10,color:"var(--color-text-secondary)"}}>0x{step.mBlock?.slice(0,12)}…</div><div style={{padding:"6px 10px",fontFamily:"var(--font-mono)",fontSize:10,color:pc.text,fontWeight:500}}>0x{step.cBlock?.slice(0,12)}…</div></>}
//               </div>);})}
//             </div>

//             {decResult && (
//               <div style={{padding:"10px 14px",borderRadius:"var(--border-radius-md)",background:"#E1F5EE",border:"0.5px solid #1D9E75",fontSize:12,color:"#0F6E56",marginBottom:10}}>
//                 Dec({mode}) → <span style={{fontFamily:"var(--font-mono)",fontWeight:500}}>0x{decResult.plaintext}</span>
//                 {decResult.plaintext===msgHex&&" — matches original ✓"}
//               </div>
//             )}

//             {/* Flip bit */}
//             <div style={{borderTop:"0.5px solid var(--color-border-tertiary)",paddingTop:14}}>
//               <SectionHeading>Flip bit — click a ciphertext block to flip one bit and re-decrypt</SectionHeading>
//               <div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:10}}>
//                 {encResult.cipherBlocks?.map((_,i)=>(
//                   <button key={i} onClick={()=>doFlipBlock(i)} style={{padding:"6px 14px",fontSize:12,fontWeight:500,border:`0.5px solid ${flippedBlock===i?"#E24B4A":BLOCK_PALETTE[i%BLOCK_PALETTE.length].border}`,borderRadius:"var(--border-radius-md)",background:flippedBlock===i?"#FCEBEB":BLOCK_PALETTE[i%BLOCK_PALETTE.length].bg,color:flippedBlock===i?"#A32D2D":BLOCK_PALETTE[i%BLOCK_PALETTE.length].text,cursor:"pointer",fontFamily:"var(--font-sans)"}}>Flip C{i} {flippedBlock===i?"⚡":""}</button>
//                 ))}
//                 {flippedBlock!==null&&<button onClick={()=>{setFlippedBlock(null);setFlipDecResult(null);}} style={{padding:"6px 14px",fontSize:12,border:"0.5px solid var(--color-border-secondary)",borderRadius:"var(--border-radius-md)",background:"var(--color-background-secondary)",color:"var(--color-text-secondary)",cursor:"pointer",fontFamily:"var(--font-sans)"}}>Reset</button>}
//               </div>
//               {flipDecResult&&flippedBlock!==null&&(
//                 <div>
//                   <SectionHeading>Decrypted blocks after flip (corrupted blocks highlighted)</SectionHeading>
//                   <div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:8}}>
//                     {flipDecResult.plainBlocks?.map((b,i)=>{const orig=encResult.steps[i]?.mBlock,corr=b!==orig,pc=BLOCK_PALETTE[i%BLOCK_PALETTE.length]; return <div key={i} style={{padding:"6px 10px",borderRadius:6,background:corr?"#FCEBEB":pc.bg,border:`1px solid ${corr?"#E24B4A":pc.border}`,fontFamily:"var(--font-mono)",fontSize:10,color:corr?"#A32D2D":pc.text}}>M{i}: 0x{b?.slice(0,8)}… {corr?"💥":"✓"}</div>;})}
//                   </div>
//                   <ErrorPropBox mode={mode} flippedBlock={flippedBlock} numBlocks={numBlocks}/>
//                 </div>
//               )}
//             </div>
//           </div>
//         )}

//         {/* Mode comparison table */}
//         <div style={{borderTop:"0.5px solid var(--color-border-tertiary)",paddingTop:14,marginBottom:16}}>
//           <SectionHeading>Mode comparison</SectionHeading>
//           <div style={{border:"0.5px solid var(--color-border-tertiary)",borderRadius:"var(--border-radius-md)",overflow:"hidden"}}>
//             <div style={{display:"grid",gridTemplateColumns:"80px 1fr 1fr 1fr 1fr 1fr",background:"var(--color-background-secondary)",borderBottom:"0.5px solid var(--color-border-tertiary)"}}>
//               {["Mode","Parallel Enc","Parallel Dec","Random Access","Error Prop.","IV Reuse"].map((h,i)=><div key={i} style={{padding:"6px 10px",fontSize:10,fontWeight:500,color:"var(--color-text-secondary)",textTransform:"uppercase"}}>{h}</div>)}
//             </div>
//             {[
//               {mode:"CBC",enc:"✗",dec:"✓",rand:"✗",err:"2 blocks",iv:"Fatal",c:{bg:"#E6F1FB",text:"#185FA5"}},
//               {mode:"OFB",enc:"✗",dec:"✗",rand:"✗",err:"None",iv:"Fatal",c:{bg:"#E1F5EE",text:"#0F6E56"}},
//               {mode:"CTR",enc:"✓",dec:"✓",rand:"✓",err:"None",iv:"Fatal",c:{bg:"#EEEDFE",text:"#3C3489"}},
//             ].map((row,i)=>(
//               <div key={i} style={{display:"grid",gridTemplateColumns:"80px 1fr 1fr 1fr 1fr 1fr",borderBottom:i<2?"0.5px solid var(--color-border-tertiary)":"none",background:row.mode===mode?row.c.bg:"transparent"}}>
//                 <div style={{padding:"7px 10px",fontFamily:"var(--font-mono)",fontSize:12,fontWeight:600,color:row.c.text}}>{row.mode}</div>
//                 {[row.enc,row.dec,row.rand,row.err,row.iv].map((v,j)=><div key={j} style={{padding:"7px 10px",fontSize:12,color:v==="✓"?"#0F6E56":v==="✗"||v==="Fatal"?"#A32D2D":"var(--color-text-secondary)"}}>{v}</div>)}
//               </div>
//             ))}
//           </div>
//         </div>

//         {/* Attack demos */}
//         <div style={{borderTop:"0.5px solid var(--color-border-tertiary)",paddingTop:14,marginBottom:16}}>
//           <SectionHeading>Attack demos</SectionHeading>
//           <div style={{display:"grid",gridTemplateColumns:"minmax(0,1fr) minmax(0,1fr)",gap:16}}>
//             {/* CBC IV-reuse */}
//             <div style={{border:"0.5px solid #378ADD",borderRadius:"var(--border-radius-md)",overflow:"hidden"}}>
//               <div style={{padding:"8px 12px",background:"#E6F1FB",borderBottom:"0.5px solid #B5D4F4",fontSize:10,fontWeight:500,color:"#185FA5",textTransform:"uppercase",letterSpacing:"0.07em"}}>CBC IV-Reuse Attack</div>
//               <div style={{padding:"12px"}}>
//                 <div style={{fontSize:11,color:"var(--color-text-secondary)",marginBottom:10}}>Encrypt two messages with the same IV. If Mᵢ = M'ᵢ then Cᵢ = C'ᵢ — leaking block equality. Make the first 16 hex chars identical to see a leak.</div>
//                 <div style={{marginBottom:8}}><FieldLabel>Message 1 (hex)</FieldLabel><TextInput value={reuseMsg1} onChange={setReuseMsg1} placeholder="deadbeef11223344"/></div>
//                 <div style={{marginBottom:10}}><FieldLabel>Message 2 (hex — share first 16 hex chars with msg1)</FieldLabel><TextInput value={reuseMsg2} onChange={setReuseMsg2} placeholder="deadbeef99887766"/></div>
//                 <button onClick={doCBCReuseAttack} style={{width:"100%",padding:"7px",fontSize:12,fontWeight:500,border:"0.5px solid #E24B4A",borderRadius:"var(--border-radius-md)",background:"#FCEBEB",color:"#A32D2D",cursor:"pointer",fontFamily:"var(--font-sans)"}}>Run CBC IV-reuse attack</button>
//                 {reuseResult&&(
//                   <div style={{marginTop:10}}>
//                     {["enc1","enc2"].map((k,ri)=>(
//                       <div key={k} style={{marginBottom:6}}>
//                         <div style={{fontSize:10,color:"var(--color-text-secondary)",textTransform:"uppercase",marginBottom:3}}>Enc{ri+1} cipher blocks</div>
//                         <div style={{display:"flex",gap:4,flexWrap:"wrap"}}>
//                           {reuseResult[k].cipherBlocks.map((b,i)=>{const other=ri===0?reuseResult.enc2:reuseResult.enc1,match=other.cipherBlocks[i]===b; return <span key={i} style={{fontFamily:"var(--font-mono)",fontSize:9,padding:"2px 6px",borderRadius:3,background:match?"#FCEBEB":ri===0?"#E6F1FB":"#E1F5EE",color:match?"#A32D2D":ri===0?"#185FA5":"#0F6E56",border:`0.5px solid ${match?"#E24B4A":ri===0?"#378ADD":"#1D9E75"}`}}>C{ri===1?"'":""}{i}: 0x{b.slice(0,8)}… {match?"🔴":""}</span>;})}
//                         </div>
//                       </div>
//                     ))}
//                     {reuseResult.leaks.length>0
//                       ?<div style={{padding:"7px 10px",borderRadius:"var(--border-radius-md)",background:"#FCEBEB",border:"0.5px solid #E24B4A",color:"#A32D2D",fontSize:11}}>Matching at {reuseResult.leaks.map(i=>`C${i}`).join(", ")} — Mᵢ = M'ᵢ revealed!</div>
//                       :<div style={{padding:"7px 10px",borderRadius:"var(--border-radius-md)",background:"#E1F5EE",border:"0.5px solid #1D9E75",color:"#0F6E56",fontSize:11}}>No matching blocks — make the first 16 hex chars of both messages identical.</div>
//                     }
//                   </div>
//                 )}
//               </div>
//             </div>
//             {/* OFB keystream-reuse */}
//             <div style={{border:"0.5px solid #1D9E75",borderRadius:"var(--border-radius-md)",overflow:"hidden"}}>
//               <div style={{padding:"8px 12px",background:"#E1F5EE",borderBottom:"0.5px solid #9FE1CB",fontSize:10,fontWeight:500,color:"#0F6E56",textTransform:"uppercase",letterSpacing:"0.07em"}}>OFB Keystream-Reuse Attack</div>
//               <div style={{padding:"12px"}}>
//                 <div style={{fontSize:11,color:"var(--color-text-secondary)",marginBottom:10}}>Same IV in OFB → same keystream. XORing ciphertexts gives C₁⊕C₂ = M₁⊕M₂ — keystream cancels, leaking plaintext XOR.</div>
//                 <div style={{marginBottom:8}}><FieldLabel>OFB message 1</FieldLabel><TextInput value={ofbMsg1} onChange={setOfbMsg1} placeholder="aabbccdd11223344"/></div>
//                 <div style={{marginBottom:10}}><FieldLabel>OFB message 2</FieldLabel><TextInput value={ofbMsg2} onChange={setOfbMsg2} placeholder="11223344aabbccdd"/></div>
//                 <button onClick={doOFBReuseAttack} style={{width:"100%",padding:"7px",fontSize:12,fontWeight:500,border:"0.5px solid #E24B4A",borderRadius:"var(--border-radius-md)",background:"#FCEBEB",color:"#A32D2D",cursor:"pointer",fontFamily:"var(--font-sans)"}}>Run OFB keystream-reuse attack</button>
//                 {ofbReuseResult&&(
//                   <div style={{marginTop:10}}>
//                     {[{label:"C₁ ⊕ C₂ (from ciphertexts)",vals:ofbReuseResult.xorBlocks},{label:"M₁ ⊕ M₂ (from plaintexts)",vals:ofbReuseResult.xorPlain}].map((row,ri)=>(
//                       <div key={ri} style={{marginBottom:6}}>
//                         <div style={{fontSize:10,color:"var(--color-text-secondary)",textTransform:"uppercase",marginBottom:3}}>{row.label}</div>
//                         <div style={{display:"flex",gap:4,flexWrap:"wrap"}}>{row.vals.map((b,i)=><span key={i} style={{fontFamily:"var(--font-mono)",fontSize:9,padding:"2px 6px",borderRadius:3,background:"#FEF3E2",color:"#7A5200",border:"0.5px solid #E8A820"}}>blk{i}: 0x{b.slice(0,8)}…</span>)}</div>
//                       </div>
//                     ))}
//                     <div style={{padding:"7px 10px",borderRadius:"var(--border-radius-md)",background:"#FCEBEB",border:"0.5px solid #E24B4A",color:"#A32D2D",fontSize:11}}>C₁⊕C₂ = M₁⊕M₂ — keystream cancels! Adversary recovers plaintext XOR from ciphertexts alone.</div>
//                   </div>
//                 )}
//               </div>
//             </div>
//           </div>
//         </div>

//         {/* Correctness tests */}
//         <div style={{borderTop:"0.5px solid var(--color-border-tertiary)",paddingTop:14}}>
//           <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:12}}>
//             <SectionHeading>Correctness tests — Dec(k, Enc(k, M)) = M for all 3 modes × 3 message lengths</SectionHeading>
//             <button onClick={doCorrectnessTests} style={{padding:"6px 14px",fontSize:11,fontWeight:500,border:"0.5px solid #E8A820",borderRadius:"var(--border-radius-md)",background:"#FEF3E2",color:"#7A5200",cursor:"pointer",fontFamily:"var(--font-sans)",whiteSpace:"nowrap"}}>Run tests</button>
//           </div>
//           {corrResults&&(
//             <div style={{border:"0.5px solid var(--color-border-tertiary)",borderRadius:"var(--border-radius-md)",overflow:"hidden"}}>
//               <div style={{display:"grid",gridTemplateColumns:"80px 1fr 1fr 1fr 80px",background:"var(--color-background-secondary)",borderBottom:"0.5px solid var(--color-border-tertiary)"}}>
//                 {["Mode","Length","Original","Recovered","Result"].map((h,i)=><div key={i} style={{padding:"6px 10px",fontSize:10,fontWeight:500,color:"var(--color-text-secondary)",textTransform:"uppercase"}}>{h}</div>)}
//               </div>
//               {corrResults.map((r,i)=>{const mc={CBC:{bg:"#E6F1FB",text:"#185FA5"},OFB:{bg:"#E1F5EE",text:"#0F6E56"},CTR:{bg:"#EEEDFE",text:"#3C3489"}}[r.mode]||{}; return (
//                 <div key={i} style={{display:"grid",gridTemplateColumns:"80px 1fr 1fr 1fr 80px",borderBottom:i<corrResults.length-1?"0.5px solid var(--color-border-tertiary)":"none"}}>
//                   <div style={{padding:"6px 10px",fontFamily:"var(--font-mono)",fontSize:11,fontWeight:600,color:mc.text,background:mc.bg}}>{r.mode}</div>
//                   <div style={{padding:"6px 10px",fontSize:11,color:"var(--color-text-secondary)"}}>{r.label}</div>
//                   <div style={{padding:"6px 10px",fontFamily:"var(--font-mono)",fontSize:10,color:"var(--color-text-secondary)"}}>0x{r.original}</div>
//                   <div style={{padding:"6px 10px",fontFamily:"var(--font-mono)",fontSize:10,color:r.pass?"#0F6E56":"#A32D2D"}}>0x{r.recovered}</div>
//                   <div style={{padding:"6px 10px"}}><TestBadge pass={r.pass}/></div>
//                 </div>
//               );})}
//             </div>
//           )}
//         </div>
//       </div>
//     </div>
//   );
// }

// // ═══════════════════════════════════════════════════════════════════════════════
// // PA #0 Panel
// // ═══════════════════════════════════════════════════════════════════════════════

// function ProofPanel({effSrc,effTgt,chain,fdLabel,direction}) {
//   const [open,setOpen]=useState(false);
//   return (<div><button onClick={()=>setOpen(o=>!o)} style={{width:"100%",display:"flex",justifyContent:"space-between",alignItems:"center",padding:"10px 16px",fontSize:13,fontWeight:500,border:"0.5px solid var(--color-border-tertiary)",borderRadius:open?"var(--border-radius-md) var(--border-radius-md) 0 0":"var(--border-radius-md)",background:"var(--color-background-secondary)",color:"var(--color-text-primary)",cursor:"pointer",fontFamily:"var(--font-sans)"}}><span>Reduction chain summary — click to {open?"collapse":"expand"}</span><span style={{fontSize:11}}>{open?"▾":"▸"}</span></button>{open&&(<div style={{border:"0.5px solid var(--color-border-tertiary)",borderTop:"none",borderRadius:"0 0 var(--border-radius-md) var(--border-radius-md)",padding:"16px",background:"var(--color-background-primary)"}}><div style={{marginBottom:10,fontSize:13}}><span style={{fontWeight:500}}>Full chain: </span><span style={{fontFamily:"var(--font-mono)",fontSize:12,marginLeft:6}}>{fdLabel} → {effSrc} → {effTgt}</span></div><div style={{marginBottom:14,fontSize:13}}><span style={{fontWeight:500}}>Direction: </span><span style={{marginLeft:6}}>{direction==="forward"?`Forward (${effSrc} → ${effTgt})`:`Backward (${effSrc} → ${effTgt})`}</span></div>{chain?chain.map((edge,i)=>{const r=REDUCTIONS[edge];if(!r)return null;const[,a,b]=edge.match(/(\w+)→(\w+)/);const c=PA_COLORS[r.pa]||{};return(<div key={i} style={{padding:"8px 0",borderBottom:"0.5px solid var(--color-border-tertiary)"}}><div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4,flexWrap:"wrap"}}><span style={{fontSize:10,padding:"3px 8px",borderRadius:4,fontFamily:"var(--font-mono)",fontWeight:500,background:c.bg,border:`0.5px solid ${c.border}`,color:c.color}}>{r.pa}</span><span style={{fontWeight:500,fontSize:13}}>{a} → {b}</span><span style={{color:"var(--color-text-secondary)",fontSize:12}}>— {r.name}</span></div><div style={{fontSize:11,color:"var(--color-text-secondary)",paddingLeft:4,marginBottom:2}}>Security: {r.security}</div><div style={{fontSize:11,color:"var(--color-text-secondary)",paddingLeft:4,fontStyle:"italic"}}>If adversary breaks {b} with ε, it breaks {a} with ε′≥ε/q — {r.pa}</div></div>);}):(<WarnBox>No direct reduction path from {effSrc} → {effTgt}. Try an adjacent pair or bidirectional mode.</WarnBox>)}<div style={{marginTop:14,fontSize:11,color:"var(--color-text-secondary)",fontStyle:"italic"}}>All intermediate values are toy stubs. Real values will flow from PA#1–PA#2 WASM.</div></div>)}</div>);
// }

// function PA0Panel({foundationType}) {
//   const [direction,setDirection]=useState("forward");
//   const [src,setSrc]=useState("PRG");
//   const [tgt,setTgt]=useState("PRF");
//   const [keyHex,setKeyHex]=useState("a3f2c1b8d5e09471");
//   const [msgHex,setMsgHex]=useState("deadbeef");
//   const foundation=useMemo(()=>foundationType==="AES"?makeAESFoundation(keyHex):makeDLPFoundation(keyHex),[foundationType,keyHex]);
//   const effSrc=direction==="forward"?src:tgt, effTgt=direction==="forward"?tgt:src;
//   const col1Steps=useMemo(()=>buildCol1Steps(effSrc,foundation),[effSrc,foundation]);
//   const chain=getRoute(effSrc,effTgt);
//   const oracleA=useMemo(()=>{const s=seedFromHex(col1Steps[col1Steps.length-1].outputHex);return(i)=>fakeHex(s^seedFromHex(i),8);},[col1Steps]);
//   const col2Steps=useMemo(()=>buildCol2Steps(chain,oracleA,msgHex),[chain,oracleA,msgHex]);
//   function handleSrcChange(v){setSrc(v);if(v===tgt)setTgt(PRIMITIVES.find(p=>p!==v));}
//   function handleTgtChange(v){setTgt(v);if(v===src)setSrc(PRIMITIVES.find(p=>p!==v));}
//   return (<div><div style={{display:"flex",alignItems:"center",gap:10,marginBottom:20}}><span style={{fontSize:12,color:"var(--color-text-secondary)",whiteSpace:"nowrap"}}>Mode:</span><ToggleBar value={direction} onChange={setDirection} options={[{value:"forward",label:"Forward (A → B)",activeStyle:{bg:"#E6F1FB",border:"#378ADD",color:"#185FA5"}},{value:"backward",label:"Backward (B → A)",activeStyle:{bg:"#FAEEDA",border:"#BA7517",color:"#854F0B"}}]}/></div><div style={{display:"grid",gridTemplateColumns:"minmax(0,1fr) minmax(0,1fr)",gap:16,marginBottom:20}}><ColCard headerLabel="Column 1 — Build: foundation → source primitive A" headerStyle={{background:"#E6F1FB",color:"#185FA5",borderBottom:"0.5px solid #B5D4F4"}}><div style={{marginBottom:14}}><FieldLabel>Source primitive A</FieldLabel><StyledSelect value={src} onChange={handleSrcChange} options={PRIMITIVES} exclude={tgt}/></div><div style={{marginBottom:14}}><FieldLabel>Input key / seed (hex)</FieldLabel><TextInput value={keyHex} onChange={setKeyHex} placeholder="e.g. a3f2c1b8..."/></div><SectionHeading>{foundation.name} → {effSrc}: step-through</SectionHeading>{col1Steps.map((s,i)=><StepRow key={i} tag={s.tag} fn={s.fn} inputHex={s.inputHex} outputHex={s.outputHex} pa={s.pa} implemented={s.implemented} tagColorMap={COL1_TAG_COLORS}/>)}</ColCard><ColCard headerLabel="Column 2 — Reduce: source A → target primitive B" headerStyle={{background:"#FAEEDA",color:"#854F0B",borderBottom:"0.5px solid #FAC775"}}><div style={{marginBottom:14}}><FieldLabel>Target primitive B</FieldLabel><StyledSelect value={tgt} onChange={handleTgtChange} options={PRIMITIVES} exclude={src}/></div><div style={{marginBottom:14}}><FieldLabel>Query / message</FieldLabel><TextInput value={msgHex} onChange={setMsgHex} placeholder="e.g. deadbeef..."/></div><SectionHeading>{effSrc} → {effTgt}: step-through</SectionHeading>{col2Steps?col2Steps.map((s,i)=><StepRow key={i} tag={s.tag} fn={s.fn} inputHex={s.inputHex} outputHex={s.outputHex} pa={s.pa} implemented={s.implemented} tagColorMap={PA_COLORS}/>):<WarnBox>No direct reduction path from {effSrc} → {effTgt}.<br/>Try an adjacent pair or bidirectional mode.</WarnBox>}</ColCard></div><ProofPanel effSrc={effSrc} effTgt={effTgt} chain={chain} fdLabel={foundation.name} direction={direction}/></div>);
// }

// // ═══════════════════════════════════════════════════════════════════════════════
// // PA #1 Panel
// // ═══════════════════════════════════════════════════════════════════════════════

// function ArgumentBox() {
//   const [open,setOpen]=useState(false);
//   return (<div style={{marginTop:8}}><button onClick={()=>setOpen(o=>!o)} style={{width:"100%",display:"flex",justifyContent:"space-between",alignItems:"center",padding:"7px 12px",fontSize:11,fontWeight:500,border:"0.5px solid var(--color-border-tertiary)",borderRadius:open?"var(--border-radius-md) var(--border-radius-md) 0 0":"var(--border-radius-md)",background:"var(--color-background-secondary)",color:"var(--color-text-secondary)",cursor:"pointer",fontFamily:"var(--font-sans)"}}><span>PA#1b written argument — click to {open?"collapse":"expand"}</span><span>{open?"▾":"▸"}</span></button>{open&&(<div style={{padding:"12px 14px",border:"0.5px solid var(--color-border-tertiary)",borderTop:"none",borderRadius:"0 0 var(--border-radius-md) var(--border-radius-md)",background:"var(--color-background-primary)",fontSize:11,lineHeight:1.7,color:"var(--color-text-secondary)"}}><div style={{fontWeight:500,color:"var(--color-text-primary)",marginBottom:6}}>Claim: f(s) = G(s) is a one-way function.</div><div style={{marginBottom:6}}><span style={{fontWeight:500}}>Proof (contrapositive).</span> Suppose adversary A inverts f with non-negligible probability:</div><div style={{fontFamily:"var(--font-mono)",fontSize:11,background:"var(--color-background-secondary)",padding:"6px 10px",borderRadius:"var(--border-radius-md)",marginBottom:8}}>Pr[ A(G(s)) = s' s.t. G(s') = G(s) ] ≥ 1/poly(n)</div><div style={{marginBottom:6}}>Construct distinguisher D against G:</div><div style={{fontFamily:"var(--font-mono)",fontSize:11,background:"var(--color-background-secondary)",padding:"8px 10px",borderRadius:"var(--border-radius-md)",marginBottom:8,lineHeight:1.9}}>D(y):<br/>&nbsp;&nbsp;1. Run A(y) → s'<br/>&nbsp;&nbsp;2. If G(s') = y, output 1<br/>&nbsp;&nbsp;3. Else output 0</div><div style={{marginBottom:4}}>If y = G(s): A succeeds w.p. ≥ 1/poly(n) ⟹ D outputs 1 w.h.p.</div><div style={{marginBottom:8}}>If y ← U_(n+ℓ): G(s') = y with prob ≤ 2⁻ˡ (negligible).</div><div style={{borderTop:"0.5px solid var(--color-border-tertiary)",paddingTop:8,fontStyle:"italic"}}>⟹ D wins with advantage ≥ 1/poly(n) − negl(n), contradicting PRG security. □</div></div>)}</div>);
// }

// function PA1Panel() {
//   const [owfType,setOwfType]=useState("DLP");
//   const [seedHex,setSeedHex]=useState("deadbeef");
//   const [outputLen,setOutputLen]=useState(16);
//   const [showTests,setShowTests]=useState(false);
//   const [testResults,setTestResults]=useState(null);
//   const owfOut=useMemo(()=>owfType==="DLP"?dlpOWF(seedHex):aesOWF(seedHex),[owfType,seedHex]);
//   const prgAsOwfDemo=useMemo(()=>{const{hexOut}=prgFromOWF(seedHex,owfType,8);return{prgOut:hexOut,invertAttempt:fakeHex(seedFromHex(hexOut)^0xdead,8)};},[owfType,seedHex]);
//   const prgResult=useMemo(()=>prgFromOWF(seedHex,owfType,outputLen),[seedHex,owfType,outputLen]);
//   const prgInterfaceDemo=useMemo(()=>{const prg=makePRGInterface(seedHex,owfType);const b8=prg.next_bytes_hex(4);prg.seed(owfOut);return{firstCall:b8,afterReseed:prg.next_bytes_hex(4)};},[seedHex,owfType,owfOut]);
//   const ones=prgResult.bitString.split("").filter(b=>b==="1").length;
//   const ratio=prgResult.bitString.length>0?ones/prgResult.bitString.length:0.5;
//   const runTests=useCallback(()=>{setTestResults({freq:frequencyTest(prgResult.bitString),runs:runsTest(prgResult.bitString),serial:serialTest(prgResult.bitString)});setShowTests(true);},[prgResult.bitString]);
//   return (<div style={{border:"0.5px solid var(--color-border-tertiary)",borderRadius:"var(--border-radius-lg)",overflow:"hidden"}}><div style={{padding:"10px 16px",background:"#E6F1FB",borderBottom:"0.5px solid #B5D4F4",display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:10}}><div style={{fontSize:10,fontWeight:500,letterSpacing:"0.07em",textTransform:"uppercase",color:"#185FA5"}}>PA #1 — Live PRG output viewer</div><ToggleBar value={owfType} onChange={setOwfType} options={[{value:"DLP",label:"DLP (gˣ mod p)",activeStyle:{bg:"#EEEDFE",border:"#7F77DD",color:"#3C3489"}},{value:"AES",label:"AES Davies-Meyer",activeStyle:{bg:"#E6F1FB",border:"#378ADD",color:"#185FA5"}}]}/></div><div style={{padding:"16px"}}><div style={{display:"grid",gridTemplateColumns:"minmax(0,1fr) minmax(0,1fr)",gap:16}}><div><SectionHeading>OWF — evaluate(x)</SectionHeading><div style={{marginBottom:12}}><FieldLabel>Seed / input x (hex)</FieldLabel><TextInput value={seedHex} onChange={setSeedHex} placeholder="e.g. deadbeef"/></div><div style={{padding:"10px 12px",background:"var(--color-background-secondary)",borderRadius:"var(--border-radius-md)",marginBottom:14}}><div style={{fontSize:10,color:"var(--color-text-secondary)",textTransform:"uppercase",letterSpacing:"0.07em",marginBottom:6}}>f(x) = {owfType==="DLP"?"g^x mod p":"AES_k(0¹²⁸) ⊕ k"}</div><div style={{display:"flex",gap:8,alignItems:"center"}}><span style={{fontSize:10,color:"var(--color-text-secondary)",minWidth:22}}>in:</span><span style={{fontFamily:"var(--font-mono)",fontSize:12,color:"var(--color-text-secondary)"}}>0x{seedHex.slice(0,8).padEnd(8,"0")}</span></div><div style={{display:"flex",gap:8,alignItems:"center",marginTop:4}}><span style={{fontSize:10,color:"var(--color-text-secondary)",minWidth:22}}>out:</span><span style={{fontFamily:"var(--font-mono)",fontSize:13,color:"var(--color-text-primary)",fontWeight:500}}>0x{owfOut}</span></div></div><SectionHeading>verify_hardness() — OWF from PRG (PA#1b)</SectionHeading><div style={{padding:"10px 12px",background:"var(--color-background-secondary)",borderRadius:"var(--border-radius-md)",fontSize:12,marginBottom:4}}><div style={{marginBottom:6,color:"var(--color-text-secondary)"}}>Claim: f(s)=G(s) is a OWF. Given G(s), adversary cannot recover s.</div><div style={{display:"flex",gap:8,alignItems:"center",marginBottom:4}}><span style={{fontSize:10,color:"var(--color-text-secondary)",minWidth:60}}>G(seed):</span><span style={{fontFamily:"var(--font-mono)",fontSize:11,color:"var(--color-text-primary)",wordBreak:"break-all"}}>0x{prgAsOwfDemo.prgOut}</span></div><div style={{display:"flex",gap:8,alignItems:"center",marginBottom:4}}><span style={{fontSize:10,color:"var(--color-text-secondary)",minWidth:60}}>Adv. guess:</span><span style={{fontFamily:"var(--font-mono)",fontSize:11,color:"var(--color-text-secondary)"}}>0x{prgAsOwfDemo.invertAttempt}</span></div><div style={{display:"flex",gap:8,alignItems:"center"}}><span style={{fontSize:10,color:"var(--color-text-secondary)",minWidth:60}}>Recovered:</span><TestBadge pass={false}/><span style={{fontSize:11,color:"var(--color-text-secondary)",fontStyle:"italic"}}>inversion fails ✓</span></div></div><ArgumentBox/><div style={{marginTop:14}}><SectionHeading>PRG interface — seed(s) / next_bits(n) for PA#2</SectionHeading><div style={{padding:"10px 12px",background:"var(--color-background-secondary)",borderRadius:"var(--border-radius-md)",fontSize:11}}><div style={{display:"flex",gap:8,marginBottom:4}}><span style={{fontFamily:"var(--font-mono)",color:"#185FA5",minWidth:110}}>prg.seed(s)</span><span style={{color:"var(--color-text-secondary)"}}>→ resets state</span></div><div style={{display:"flex",gap:8,marginBottom:8}}><span style={{fontFamily:"var(--font-mono)",color:"#185FA5",minWidth:110}}>next_bits(32)</span><span style={{fontFamily:"var(--font-mono)",color:"var(--color-text-primary)"}}>0x{prgInterfaceDemo.firstCall}</span></div><div style={{display:"flex",gap:8,marginBottom:4}}><span style={{fontFamily:"var(--font-mono)",color:"#0F6E56",minWidth:110}}>prg.seed(owf)</span><span style={{color:"var(--color-text-secondary)"}}>→ re-seeded with f(x)</span></div><div style={{display:"flex",gap:8}}><span style={{fontFamily:"var(--font-mono)",color:"#0F6E56",minWidth:110}}>next_bits(32)</span><span style={{fontFamily:"var(--font-mono)",color:"var(--color-text-primary)"}}>0x{prgInterfaceDemo.afterReseed}</span></div></div></div></div><div><SectionHeading>PRG from OWF — G(s) iterative construction (PA#1a)</SectionHeading><div style={{marginBottom:12}}><FieldLabel>Output length ℓ — {outputLen} bytes ({outputLen*8} bits)</FieldLabel><input type="range" min={8} max={256} step={8} value={outputLen} onChange={e=>setOutputLen(Number(e.target.value))} style={{width:"100%"}}/><div style={{display:"flex",justifyContent:"space-between",fontSize:10,color:"var(--color-text-secondary)",marginTop:2}}><span>8 B</span><span>256 B</span></div></div><SectionHeading>First 8 iterations: xᵢ → f(xᵢ) → b(xᵢ)</SectionHeading><div style={{marginBottom:12}}>{prgResult.steps.map((s,i)=>(<div key={i} style={{display:"flex",alignItems:"center",gap:6,padding:"4px 0",borderBottom:"0.5px solid var(--color-border-tertiary)",fontSize:11}}><span style={{fontFamily:"var(--font-mono)",color:"var(--color-text-secondary)",minWidth:18}}>x{i}:</span><span style={{fontFamily:"var(--font-mono)",color:"var(--color-text-secondary)",fontSize:10,flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>0x{s.xHex}</span><span style={{fontSize:10,padding:"1px 6px",borderRadius:3,fontWeight:500,background:s.bit?"#E1F5EE":"#EEEDFE",color:s.bit?"#0F6E56":"#3C3489",border:`0.5px solid ${s.bit?"#1D9E75":"#7F77DD"}`}}>b={s.bit}</span></div>))}</div><SectionHeading>G(s) output — {outputLen*8} pseudorandom bits</SectionHeading><MonoBox maxH={80}>0x{prgResult.hexOut}</MonoBox><div style={{margin:"10px 0 12px"}}><div style={{display:"flex",justifyContent:"space-between",fontSize:11,color:"var(--color-text-secondary)",marginBottom:4}}><span>Bit ratio</span><span style={{fontFamily:"var(--font-mono)"}}>{(ratio*100).toFixed(1)}% ones</span></div><div style={{height:8,borderRadius:4,background:"var(--color-background-secondary)",overflow:"hidden",border:"0.5px solid var(--color-border-tertiary)"}}><div style={{height:"100%",width:`${ratio*100}%`,background:Math.abs(ratio-0.5)<0.05?"#1D9E75":"#D85A30",transition:"width 0.3s"}}/></div><div style={{display:"flex",justifyContent:"space-between",fontSize:10,color:"var(--color-text-secondary)",marginTop:2}}><span>0%</span><span style={{color:"#1D9E75"}}>50%</span><span>100%</span></div></div><button onClick={runTests} style={{width:"100%",padding:"8px 14px",fontSize:12,fontWeight:500,border:"0.5px solid var(--color-border-secondary)",borderRadius:"var(--border-radius-md)",background:"var(--color-background-secondary)",color:"var(--color-text-primary)",cursor:"pointer",fontFamily:"var(--font-sans)"}}>Run randomness tests</button></div></div>{showTests&&testResults&&(<div style={{marginTop:16,border:"0.5px solid var(--color-border-tertiary)",borderRadius:"var(--border-radius-md)",overflow:"hidden"}}><div style={{padding:"8px 14px",background:"var(--color-background-secondary)",borderBottom:"0.5px solid var(--color-border-tertiary)",fontSize:10,fontWeight:500,letterSpacing:"0.07em",textTransform:"uppercase",color:"var(--color-text-secondary)"}}>NIST SP 800-22 — threshold p ≥ 0.01</div><div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr"}}>{[{label:testResults.freq.name,pass:testResults.freq.pass,lines:[`ones=${testResults.freq.ones} zeros=${testResults.freq.zeros}`,`ratio=${testResults.freq.ratio}% S_obs=${testResults.freq.sObs}`,`p-value = ${testResults.freq.pVal}`]},{label:testResults.runs.name,pass:testResults.runs.pass,lines:[`runs=${testResults.runs.runs} exp≈${testResults.runs.expected}`,`V_obs=${testResults.runs.vObs}`,`p-value = ${testResults.runs.pVal}`]},{label:testResults.serial.name,pass:testResults.serial.pass,lines:[`00=${testResults.serial.counts["00"]} 01=${testResults.serial.counts["01"]} 10=${testResults.serial.counts["10"]} 11=${testResults.serial.counts["11"]}`,`χ²=${testResults.serial.chi2} (df=3)`,`p-value = ${testResults.serial.pVal}`]}].map((t,i)=>(<div key={i} style={{padding:"12px 14px",borderRight:i<2?"0.5px solid var(--color-border-tertiary)":"none"}}><div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}><TestBadge pass={t.pass}/><span style={{fontSize:12,fontWeight:500}}>{t.label}</span></div>{t.lines.map((line,j)=><div key={j} style={{fontSize:11,color:j===2?(t.pass?"#0F6E56":"#A32D2D"):"var(--color-text-secondary)",fontFamily:"var(--font-mono)",marginBottom:2,fontWeight:j===2?500:400}}>{line}</div>)}</div>))}</div></div>)}</div></div>);
// }

// // ═══════════════════════════════════════════════════════════════════════════════
// // PA #2 Panel
// // ═══════════════════════════════════════════════════════════════════════════════

// function GGMTreeViz({levels,bitString}) {
//   if(!levels||levels.length===0)return null;
//   const depth=levels.length-1,nodeW=64,nodeH=28,vGap=48;
//   const svgW=Math.max(500,Math.pow(2,depth)*(nodeW+16)+16),svgH=(depth+1)*(nodeH+vGap)+16;
//   function nodeX(id){const d=id.length,total=Math.pow(2,d),idx=parseInt(id||"0",2)||0,step=svgW/total;return step*idx+step/2-nodeW/2;}
//   function nodeY(d){return 8+d*(nodeH+vGap);}
//   const allNodes=levels.flatMap(l=>l);
//   return (<svg width="100%" viewBox={`0 0 ${svgW} ${svgH}`} style={{display:"block",fontFamily:"var(--font-mono)"}}>{allNodes.map(n=>{if(n.id.length>=depth)return null;const px=nodeX(n.id)+nodeW/2,py=nodeY(n.id.length)+nodeH,l0=n.id+"0",l1=n.id+"1",lx0=nodeX(l0)+nodeW/2,lx1=nodeX(l1)+nodeW/2,cy=nodeY(n.id.length+1),pa0=bitString.startsWith(l0),pa1=bitString.startsWith(l1);return(<g key={`e-${n.id}`}><line x1={px} y1={py} x2={lx0} y2={cy} stroke={pa0?"#378ADD":"#D3D1C7"} strokeWidth={pa0?2:1}/><text x={(px+lx0)/2-6} y={(py+cy)/2} fontSize={10} fill={pa0?"#185FA5":"#888780"}>0</text><line x1={px} y1={py} x2={lx1} y2={cy} stroke={pa1?"#378ADD":"#D3D1C7"} strokeWidth={pa1?2:1}/><text x={(px+lx1)/2+2} y={(py+cy)/2} fontSize={10} fill={pa1?"#185FA5":"#888780"}>1</text></g>);})}{allNodes.map(n=>{const x=nodeX(n.id),y=nodeY(n.id.length),fill=n.isLeaf&&n.active?"#E1F5EE":n.active?"#E6F1FB":"var(--color-background-secondary)",stroke=n.isLeaf&&n.active?"#1D9E75":n.active?"#378ADD":"#D3D1C7",textC=n.isLeaf&&n.active?"#0F6E56":n.active?"#185FA5":"#888780";return(<g key={`n-${n.id}`}><rect x={x} y={y} width={nodeW} height={nodeH} rx={n.isLeaf?4:14} fill={fill} stroke={stroke} strokeWidth={n.active?1.5:0.5}/><text x={x+nodeW/2} y={y+nodeH/2+4} textAnchor="middle" fontSize={9} fill={textC}>{n.id===""?"k":`0x${n.val.slice(0,6)}`}</text></g>);})}</svg>);
// }

// function PA2Panel() {
//   const [prfType,setPrfType]=useState("GGM");
//   const [keyHex,setKeyHex]=useState("a3f2c1b8");
//   const [queryBits,setQueryBits]=useState("1010");
//   const [prgSeed,setPrgSeed]=useState("deadbeef");
//   const [prgLen,setPrgLen]=useState(16);
//   const [distResult,setDistResult]=useState(null);
//   const [showDist,setShowDist]=useState(false);
//   const cleanBits=queryBits.replace(/[^01]/g,"").slice(0,8);
//   const prfResult=useMemo(()=>prfType==="AES"?{value:aesPRF(keyHex,cleanBits.padEnd(8,"0")),path:[]}:ggmPRF(keyHex,cleanBits),[prfType,keyHex,cleanBits]);
//   const treeData=useMemo(()=>buildGGMTree(keyHex,cleanBits,8),[keyHex,cleanBits]);
//   const prgResult2=useMemo(()=>prgFromPRF(prgSeed,prfType,prgLen),[prgSeed,prfType,prgLen]);
//   const prgRatio2=prgResult2.bitString.length>0?prgResult2.bitString.split("").filter(b=>b==="1").length/prgResult2.bitString.length:0.5;
//   const prgTests2=useMemo(()=>({freq:frequencyTest(prgResult2.bitString),runs:runsTest(prgResult2.bitString),serial:serialTest(prgResult2.bitString)}),[prgResult2.bitString]);
//   return (<div style={{border:"0.5px solid var(--color-border-tertiary)",borderRadius:"var(--border-radius-lg)",overflow:"hidden"}}><div style={{padding:"10px 16px",background:"#EEEDFE",borderBottom:"0.5px solid #AFA9EC",display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:10}}><div style={{fontSize:10,fontWeight:500,letterSpacing:"0.07em",textTransform:"uppercase",color:"#3C3489"}}>PA #2 — GGM tree visualiser & PRF demo</div><ToggleBar value={prfType} onChange={setPrfType} options={[{value:"GGM",label:"GGM (PRG-based)",activeStyle:{bg:"#EEEDFE",border:"#7F77DD",color:"#3C3489"}},{value:"AES",label:"AES plug-in",activeStyle:{bg:"#E6F1FB",border:"#378ADD",color:"#185FA5"}}]}/></div><div style={{padding:"16px"}}><div style={{display:"grid",gridTemplateColumns:"260px minmax(0,1fr)",gap:16,marginBottom:20}}><div><SectionHeading>PRF inputs — F(k, x)</SectionHeading><div style={{marginBottom:10}}><FieldLabel>Key k (hex)</FieldLabel><TextInput value={keyHex} onChange={setKeyHex} placeholder="e.g. a3f2c1b8"/></div><div style={{marginBottom:14}}><FieldLabel>Query x — bit string (≤ 8 bits)</FieldLabel><TextInput value={queryBits} onChange={v=>setQueryBits(v.replace(/[^01]/g,"").slice(0,8))} placeholder="e.g. 1010"/><div style={{fontSize:10,color:"var(--color-text-secondary)",marginTop:3}}>depth={cleanBits.length}, path: {cleanBits.split("").join(" → ")||"root"}</div></div><div style={{padding:"12px",background:"var(--color-background-secondary)",borderRadius:"var(--border-radius-md)",marginBottom:10}}><div style={{fontSize:10,color:"var(--color-text-secondary)",textTransform:"uppercase",letterSpacing:"0.07em",marginBottom:8}}>F_k(x) = {prfType==="AES"?"AES_k(x)":"GGM leaf"}</div>{prfType==="GGM"&&prfResult.path.map((step,i)=>(<div key={i} style={{display:"flex",alignItems:"center",gap:6,marginBottom:4,fontSize:11}}><span style={{fontSize:10,padding:"1px 6px",borderRadius:3,fontWeight:500,background:step.bit==="0"?"#E6F1FB":"#E1F5EE",color:step.bit==="0"?"#185FA5":"#0F6E56",border:`0.5px solid ${step.bit==="0"?"#378ADD":"#1D9E75"}`}}>G{step.bit}</span><span style={{fontFamily:"var(--font-mono)",fontSize:10,color:"var(--color-text-secondary)"}}>0x{step.nodeVal.slice(0,6)}</span><span style={{fontSize:10,color:"var(--color-text-secondary)"}}>→</span><span style={{fontFamily:"var(--font-mono)",fontSize:10,color:"var(--color-text-primary)"}}>0x{(step.bit==="0"?step.left:step.right).slice(0,6)}</span></div>))}<div style={{marginTop:8,paddingTop:8,borderTop:"0.5px solid var(--color-border-tertiary)",display:"flex",gap:8}}><span style={{fontSize:10,color:"var(--color-text-secondary)"}}>F_k(x) =</span><span style={{fontFamily:"var(--font-mono)",fontSize:14,color:"#3C3489",fontWeight:500}}>0x{prfResult.value}</span></div></div><div style={{padding:"10px 12px",background:"var(--color-background-secondary)",borderRadius:"var(--border-radius-md)",fontSize:11}}><div style={{fontSize:10,color:"var(--color-text-secondary)",textTransform:"uppercase",letterSpacing:"0.07em",marginBottom:6}}>F(k, x) interface for PA#3–5</div><div style={{fontFamily:"var(--font-mono)",color:"#3C3489",marginBottom:2}}>makePRFInterface(k, "{prfType}")</div><div style={{fontFamily:"var(--font-mono)",color:"var(--color-text-secondary)",marginBottom:2}}>prf.F("{cleanBits||"0000"}")</div><div style={{fontFamily:"var(--font-mono)",color:"var(--color-text-primary)"}}>→ 0x{prfResult.value}</div></div></div><div><SectionHeading>GGM binary tree — depth {cleanBits.length} — active path in blue</SectionHeading><div style={{padding:"10px",background:"var(--color-background-secondary)",borderRadius:"var(--border-radius-md)",overflowX:"auto"}}>{prfType==="GGM"?<GGMTreeViz levels={treeData.levels} bitString={cleanBits}/>:<div style={{padding:"20px",textAlign:"center",fontSize:12,color:"var(--color-text-secondary)",fontStyle:"italic"}}>AES mode: F_k(x) = AES_k(x) directly — no tree. Switch to GGM to see the visualiser.</div>}</div>{prfType==="GGM"&&<div style={{marginTop:8,padding:"8px 12px",borderRadius:"var(--border-radius-md)",background:"#E6F1FB",border:"0.5px solid #B5D4F4",fontSize:11,color:"#185FA5"}}>Leaf F_k({cleanBits||"ε"}) = <span style={{fontFamily:"var(--font-mono)",fontWeight:500}}>0x{treeData.leafVal}</span> ✓</div>}</div></div><div style={{borderTop:"0.5px solid var(--color-border-tertiary)",paddingTop:16,marginBottom:20}}><SectionHeading>PRG from PRF — G(s) = F_s(0ⁿ) ‖ F_s(1ⁿ) (PA#2b)</SectionHeading><div style={{display:"grid",gridTemplateColumns:"minmax(0,1fr) minmax(0,1fr)",gap:16}}><div><div style={{marginBottom:10}}><FieldLabel>PRG seed</FieldLabel><TextInput value={prgSeed} onChange={setPrgSeed} placeholder="e.g. deadbeef"/></div><div style={{marginBottom:10}}><FieldLabel>Output — {prgLen} bytes</FieldLabel><input type="range" min={8} max={128} step={8} value={prgLen} onChange={e=>setPrgLen(Number(e.target.value))} style={{width:"100%"}}/></div><MonoBox>0x{prgResult2.hexOut}</MonoBox></div><div><SectionHeading>Statistical tests</SectionHeading><div style={{marginBottom:8}}><div style={{display:"flex",justifyContent:"space-between",fontSize:11,color:"var(--color-text-secondary)",marginBottom:4}}><span>Bit ratio</span><span style={{fontFamily:"var(--font-mono)"}}>{(prgRatio2*100).toFixed(1)}%</span></div><div style={{height:6,borderRadius:3,background:"var(--color-background-secondary)",border:"0.5px solid var(--color-border-tertiary)",overflow:"hidden"}}><div style={{height:"100%",width:`${prgRatio2*100}%`,background:Math.abs(prgRatio2-0.5)<0.05?"#1D9E75":"#D85A30"}}/></div></div>{[prgTests2.freq,prgTests2.runs,prgTests2.serial].map((t,i)=>(<div key={i} style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"5px 0",borderBottom:"0.5px solid var(--color-border-tertiary)",fontSize:11}}><span style={{color:"var(--color-text-secondary)"}}>{t.name}</span><span style={{display:"flex",alignItems:"center",gap:8}}><span style={{fontFamily:"var(--font-mono)",color:"var(--color-text-secondary)",fontSize:10}}>p={t.pVal}</span><span style={{fontSize:10,padding:"1px 7px",borderRadius:3,fontWeight:500,background:t.pass?"#E1F5EE":"#FCEBEB",border:`0.5px solid ${t.pass?"#1D9E75":"#E24B4A"}`,color:t.pass?"#0F6E56":"#A32D2D"}}>{t.pass?"PASS":"FAIL"}</span></span></div>))}</div></div></div><div style={{borderTop:"0.5px solid var(--color-border-tertiary)",paddingTop:16}}><div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:12}}><SectionHeading>Distinguishing game — PRF vs truly random (q = 100)</SectionHeading><button onClick={()=>{setDistResult(runDistinguishingGame(keyHex,prfType,100));setShowDist(true);}} style={{padding:"7px 14px",fontSize:12,fontWeight:500,border:"0.5px solid #7F77DD",borderRadius:"var(--border-radius-md)",background:"#EEEDFE",color:"#3C3489",cursor:"pointer",fontFamily:"var(--font-sans)",whiteSpace:"nowrap"}}>Run game</button></div>{showDist&&distResult&&(<div><div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr 1fr",gap:10,marginBottom:14}}>{[{label:"Total queries",val:distResult.totalQ},{label:"Collisions",val:`${distResult.collisions} (${distResult.collisionRate}%)`},{label:"PRF mean byte",val:distResult.prfMean},{label:"Random mean byte",val:distResult.randMean}].map((s,i)=>(<div key={i} style={{padding:"10px 12px",background:"var(--color-background-secondary)",borderRadius:"var(--border-radius-md)"}}><div style={{fontSize:10,color:"var(--color-text-secondary)",textTransform:"uppercase",letterSpacing:"0.06em",marginBottom:4}}>{s.label}</div><div style={{fontFamily:"var(--font-mono)",fontSize:14,fontWeight:500,color:"var(--color-text-primary)"}}>{s.val}</div></div>))}</div><div style={{padding:"10px 14px",borderRadius:"var(--border-radius-md)",background:parseFloat(distResult.diff)<20?"#E1F5EE":"#FAEEDA",border:`0.5px solid ${parseFloat(distResult.diff)<20?"#1D9E75":"#BA7517"}`,color:parseFloat(distResult.diff)<20?"#0F6E56":"#854F0B",fontSize:12,marginBottom:12}}>Mean byte difference = {distResult.diff} — {parseFloat(distResult.diff)<20?"statistically indistinguishable from random ✓":"outputs differ — check PRF implementation"}</div><div style={{border:"0.5px solid var(--color-border-tertiary)",borderRadius:"var(--border-radius-md)",overflow:"hidden"}}><div style={{display:"grid",gridTemplateColumns:"80px 1fr 1fr 60px",background:"var(--color-background-secondary)",borderBottom:"0.5px solid var(--color-border-tertiary)"}}>{["x","F_k(x)","random(x)","match?"].map((h,i)=><div key={i} style={{padding:"6px 10px",fontSize:10,fontWeight:500,color:"var(--color-text-secondary)",textTransform:"uppercase"}}>{h}</div>)}</div>{distResult.queries.map((q,i)=>(<div key={i} style={{display:"grid",gridTemplateColumns:"80px 1fr 1fr 60px",borderBottom:"0.5px solid var(--color-border-tertiary)"}}><div style={{padding:"6px 10px",fontFamily:"var(--font-mono)",fontSize:11,color:"var(--color-text-secondary)"}}>0x{q.x}</div><div style={{padding:"6px 10px",fontFamily:"var(--font-mono)",fontSize:11,color:"#3C3489"}}>0x{q.prfOut}</div><div style={{padding:"6px 10px",fontFamily:"var(--font-mono)",fontSize:11,color:"var(--color-text-secondary)"}}>0x{q.randOut}</div><div style={{padding:"6px 10px",fontSize:11,color:q.same?"#A32D2D":"#0F6E56"}}>{q.same?"yes !":"no ✓"}</div></div>))}</div></div>)}</div></div></div>);
// }

// // ═══════════════════════════════════════════════════════════════════════════════
// // PA #3 Panel
// // ═══════════════════════════════════════════════════════════════════════════════

// function PA3Panel() {
//   const [prfType,setPrfType]=useState("GGM");
//   const [keyHex,setKeyHex]=useState("c0ffee11");
//   const [reuseNonce,setReuseNonce]=useState(false);
//   const [msgHex,setMsgHex]=useState("deadbeef");
//   const [encResult,setEncResult]=useState(null);
//   const [decResult,setDecResult]=useState(null);
//   const [decInput,setDecInput]=useState("");
//   const [m0,setM0]=useState("aabbccdd");
//   const [m1,setM1]=useState("11223344");
//   const [gameRound,setGameRound]=useState(null);
//   const [guess,setGuess]=useState(null);
//   const [history,setHistory]=useState([]);
//   const [showResult,setShowResult]=useState(false);
//   const [simResult,setSimResult]=useState(null);
//   const [attackResult,setAttackResult]=useState(null);
//   const rounds=history.length,correct=history.filter(h=>h.correct).length;
//   const advantage=rounds>0?Math.abs((correct/rounds)-0.5)*2:0;
//   function doEnc(){const r=encCPA(keyHex,msgHex,prfType,reuseNonce);setEncResult(r);setDecResult(null);setDecInput(r.ciphertext);}
//   function doDec(){const parts=decInput.split(":");if(parts.length!==2){setDecResult({error:"Format must be r:c"});return;}setDecResult(decCPA(keyHex,parts[0],parts[1],prfType));}
//   function doEncryptChallenge(){if(m0.length!==m1.length)return;const round=playCPAGameRound(keyHex,m0,m1,prfType,reuseNonce);setGameRound(round);setGuess(null);setShowResult(false);}
//   function doGuess(g){if(!gameRound||showResult)return;setGuess(g);setShowResult(true);setHistory(h=>[...h,{b:gameRound.b,guess:g,correct:g===gameRound.b}]);}
//   function resetGame(){setHistory([]);setGameRound(null);setGuess(null);setShowResult(false);}
//   const mismatch=m0.length!==m1.length;
//   const mc=reuseNonce?{bg:"#FCEBEB",border:"#E24B4A",text:"#A32D2D"}:{bg:"#E1F5EE",border:"#1D9E75",text:"#0F6E56"};
//   return (<div style={{border:"0.5px solid var(--color-border-tertiary)",borderRadius:"var(--border-radius-lg)",overflow:"hidden"}}><div style={{padding:"10px 16px",background:"#E1F5EE",borderBottom:"0.5px solid #9FE1CB",display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:10}}><div style={{fontSize:10,fontWeight:500,letterSpacing:"0.07em",textTransform:"uppercase",color:"#0F6E56"}}>PA #3 — CPA-secure encryption & IND-CPA game</div><div style={{display:"flex",gap:10,flexWrap:"wrap"}}><ToggleBar value={prfType} onChange={setPrfType} options={[{value:"GGM",label:"GGM PRF",activeStyle:{bg:"#EEEDFE",border:"#7F77DD",color:"#3C3489"}},{value:"AES",label:"AES PRF",activeStyle:{bg:"#E6F1FB",border:"#378ADD",color:"#185FA5"}}]}/><ToggleBar value={reuseNonce?"broken":"secure"} onChange={v=>{setReuseNonce(v==="broken");resetGame();setSimResult(null);setAttackResult(null);}} options={[{value:"secure",label:"Secure (fresh r)",activeStyle:{bg:"#E1F5EE",border:"#1D9E75",color:"#0F6E56"}},{value:"broken",label:"Broken (reuse r)",activeStyle:{bg:"#FCEBEB",border:"#E24B4A",color:"#A32D2D"}}]}/></div></div><div style={{padding:"16px"}}><div style={{padding:"8px 14px",borderRadius:"var(--border-radius-md)",background:mc.bg,border:`0.5px solid ${mc.border}`,color:mc.text,fontSize:12,marginBottom:16}}>{reuseNonce?"Broken mode: r is always F_k(0) — same plaintext always produces the same ciphertext.":"Secure mode: r ← {0,1}ⁿ freshly each encryption. Advantage should converge to ≈ 0."}</div><div style={{display:"grid",gridTemplateColumns:"minmax(0,1fr) minmax(0,1fr)",gap:16,marginBottom:20}}><div><SectionHeading>Enc(k, m)</SectionHeading><div style={{marginBottom:10}}><FieldLabel>Key k (hex)</FieldLabel><TextInput value={keyHex} onChange={setKeyHex} placeholder="e.g. c0ffee11"/></div><div style={{marginBottom:10}}><FieldLabel>Message m (hex)</FieldLabel><TextInput value={msgHex} onChange={setMsgHex} placeholder="e.g. deadbeef"/></div><button onClick={doEnc} style={{width:"100%",padding:"8px 14px",fontSize:12,fontWeight:500,border:"0.5px solid #1D9E75",borderRadius:"var(--border-radius-md)",background:"#E1F5EE",color:"#0F6E56",cursor:"pointer",fontFamily:"var(--font-sans)",marginBottom:12}}>Encrypt</button>{encResult&&(<div><div style={{padding:"10px 12px",background:"var(--color-background-secondary)",borderRadius:"var(--border-radius-md)",marginBottom:8}}><div style={{fontSize:10,color:"var(--color-text-secondary)",textTransform:"uppercase",letterSpacing:"0.07em",marginBottom:6}}>C = r : c</div><div style={{display:"flex",gap:8,marginBottom:4}}><span style={{fontSize:10,color:"var(--color-text-secondary)",minWidth:12}}>r:</span><span style={{fontFamily:"var(--font-mono)",fontSize:11,color:"#185FA5",wordBreak:"break-all"}}>0x{encResult.r}</span></div><div style={{display:"flex",gap:8}}><span style={{fontSize:10,color:"var(--color-text-secondary)",minWidth:12}}>c:</span><span style={{fontFamily:"var(--font-mono)",fontSize:11,color:"var(--color-text-primary)",wordBreak:"break-all"}}>0x{encResult.c}</span></div></div>{encResult.blocks.length>0&&(<div><SectionHeading>Block-by-block detail</SectionHeading>{encResult.blocks.map((blk,i)=>(<div key={i} style={{padding:"6px 10px",background:"var(--color-background-secondary)",borderRadius:"var(--border-radius-md)",marginBottom:6,fontSize:11}}><div style={{display:"flex",gap:6,flexWrap:"wrap"}}><span style={{fontSize:10,padding:"1px 6px",borderRadius:3,background:"#EEEDFE",color:"#3C3489",border:"0.5px solid #7F77DD",fontFamily:"var(--font-mono)"}}>blk {i}</span><span style={{fontFamily:"var(--font-mono)",color:"var(--color-text-secondary)"}}>m: 0x{blk.mBlock}</span><span style={{color:"var(--color-text-secondary)"}}>⊕</span><span style={{fontFamily:"var(--font-mono)",color:"#185FA5"}}>F_k(r+{i}): 0x{blk.keyStream}</span><span style={{color:"var(--color-text-secondary)"}}>=</span><span style={{fontFamily:"var(--font-mono)",color:"var(--color-text-primary)",fontWeight:500}}>0x{blk.cBlock}</span></div></div>))}</div>)}</div>)}</div><div><SectionHeading>Dec(k, r, c)</SectionHeading><div style={{marginBottom:10}}><FieldLabel>Ciphertext (r:c)</FieldLabel><TextInput value={decInput} onChange={setDecInput} placeholder="paste r:c from Enc output"/></div><button onClick={doDec} style={{width:"100%",padding:"8px 14px",fontSize:12,fontWeight:500,border:"0.5px solid #378ADD",borderRadius:"var(--border-radius-md)",background:"#E6F1FB",color:"#185FA5",cursor:"pointer",fontFamily:"var(--font-sans)",marginBottom:12}}>Decrypt</button>{decResult&&(<div style={{padding:"10px 12px",background:"var(--color-background-secondary)",borderRadius:"var(--border-radius-md)"}}>{decResult.error?<div style={{fontSize:12,color:"#A32D2D"}}>{decResult.error}</div>:<><div style={{fontSize:10,color:"var(--color-text-secondary)",textTransform:"uppercase",letterSpacing:"0.07em",marginBottom:6}}>Recovered plaintext</div><div style={{fontFamily:"var(--font-mono)",fontSize:14,color:"var(--color-text-primary)",fontWeight:500,wordBreak:"break-all"}}>0x{decResult.msgHex}</div>{decResult.msgHex===msgHex&&<div style={{fontSize:11,color:"#0F6E56",marginTop:6}}>Matches original ✓</div>}</>}</div>)}</div></div><div style={{borderTop:"0.5px solid var(--color-border-tertiary)",paddingTop:16,marginBottom:20}}><div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:12,flexWrap:"wrap",gap:8}}><SectionHeading>IND-CPA game</SectionHeading>{rounds>0&&<button onClick={resetGame} style={{fontSize:11,padding:"4px 12px",border:"0.5px solid var(--color-border-secondary)",borderRadius:"var(--border-radius-md)",background:"var(--color-background-secondary)",color:"var(--color-text-secondary)",cursor:"pointer",fontFamily:"var(--font-sans)"}}>Reset</button>}</div><div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr 1fr",gap:10,marginBottom:14}}>{[{label:"Rounds",val:rounds},{label:"Correct",val:correct},{label:"Advantage",val:advantage.toFixed(3)},{label:"Target",val:reuseNonce?"≈ 1.0":"≤ 0.1"}].map((s,i)=>(<div key={i} style={{padding:"10px 12px",background:"var(--color-background-secondary)",borderRadius:"var(--border-radius-md)"}}><div style={{fontSize:10,color:"var(--color-text-secondary)",textTransform:"uppercase",letterSpacing:"0.06em",marginBottom:4}}>{s.label}</div><div style={{fontFamily:"var(--font-mono)",fontSize:16,fontWeight:500,color:i===2?(reuseNonce?(advantage>0.8?"#0F6E56":"#A32D2D"):(advantage<=0.1?"#0F6E56":"#854F0B")):"var(--color-text-primary)"}}>{s.val}</div></div>))}</div><div style={{height:8,borderRadius:4,background:"var(--color-background-secondary)",overflow:"hidden",border:"0.5px solid var(--color-border-tertiary)",marginBottom:14}}><div style={{height:"100%",width:`${Math.min(advantage,1)*100}%`,background:reuseNonce?"#E24B4A":advantage<=0.1?"#1D9E75":advantage<=0.3?"#BA7517":"#E24B4A",transition:"width 0.4s"}}/></div><div style={{display:"grid",gridTemplateColumns:"minmax(0,1fr) minmax(0,1fr)",gap:16}}><div><div style={{fontSize:12,fontWeight:500,marginBottom:8}}>Step 1 — enter two equal-length messages</div><div style={{marginBottom:8}}><FieldLabel>m₀</FieldLabel><TextInput value={m0} onChange={setM0} placeholder="e.g. aabbccdd"/></div><div style={{marginBottom:10}}><FieldLabel>m₁</FieldLabel><TextInput value={m1} onChange={setM1} placeholder="e.g. 11223344"/></div>{mismatch&&<div style={{fontSize:11,color:"#A32D2D",marginBottom:8}}>m₀ and m₁ must be the same length</div>}<button onClick={doEncryptChallenge} disabled={mismatch} style={{width:"100%",padding:"9px 14px",fontSize:13,fontWeight:500,border:"0.5px solid #1D9E75",borderRadius:"var(--border-radius-md)",background:mismatch?"var(--color-background-secondary)":"#E1F5EE",color:mismatch?"var(--color-text-secondary)":"#0F6E56",cursor:mismatch?"not-allowed":"pointer",fontFamily:"var(--font-sans)"}}>Step 2 — Encrypt (challenger picks b)</button></div><div><div style={{fontSize:12,fontWeight:500,marginBottom:8}}>Step 3 — see C* and guess b</div>{gameRound?(<div><div style={{padding:"10px 12px",background:"var(--color-background-secondary)",borderRadius:"var(--border-radius-md)",marginBottom:10}}><div style={{fontSize:10,color:"var(--color-text-secondary)",textTransform:"uppercase",letterSpacing:"0.07em",marginBottom:6}}>Challenge ciphertext C*</div><div style={{display:"flex",gap:6,marginBottom:3}}><span style={{fontSize:10,color:"var(--color-text-secondary)",minWidth:12}}>r:</span><span style={{fontFamily:"var(--font-mono)",fontSize:11,color:"#185FA5",wordBreak:"break-all"}}>0x{gameRound.r}</span></div><div style={{display:"flex",gap:6}}><span style={{fontSize:10,color:"var(--color-text-secondary)",minWidth:12}}>c:</span><span style={{fontFamily:"var(--font-mono)",fontSize:11,wordBreak:"break-all"}}>0x{gameRound.c}</span></div></div>{!showResult?(<div style={{display:"flex",gap:8}}><button onClick={()=>doGuess(0)} style={{flex:1,padding:"9px",fontSize:13,fontWeight:500,border:"0.5px solid #378ADD",borderRadius:"var(--border-radius-md)",background:"#E6F1FB",color:"#185FA5",cursor:"pointer",fontFamily:"var(--font-sans)"}}>b=0 (m₀)</button><button onClick={()=>doGuess(1)} style={{flex:1,padding:"9px",fontSize:13,fontWeight:500,border:"0.5px solid #1D9E75",borderRadius:"var(--border-radius-md)",background:"#E1F5EE",color:"#0F6E56",cursor:"pointer",fontFamily:"var(--font-sans)"}}>b=1 (m₁)</button></div>):(<div><div style={{padding:"10px 14px",borderRadius:"var(--border-radius-md)",background:guess===gameRound.b?"#E1F5EE":"#FCEBEB",border:`0.5px solid ${guess===gameRound.b?"#1D9E75":"#E24B4A"}`,color:guess===gameRound.b?"#0F6E56":"#A32D2D",fontSize:13,fontWeight:500,marginBottom:10}}>{guess===gameRound.b?"Correct!":"Wrong!"} b={gameRound.b} (encrypted m{gameRound.b})</div><button onClick={doEncryptChallenge} style={{width:"100%",padding:"8px",fontSize:12,fontWeight:500,border:"0.5px solid var(--color-border-secondary)",borderRadius:"var(--border-radius-md)",background:"var(--color-background-secondary)",color:"var(--color-text-primary)",cursor:"pointer",fontFamily:"var(--font-sans)"}}>Next round</button></div>)}</div>):(<div style={{padding:"20px",textAlign:"center",fontSize:12,color:"var(--color-text-secondary)",background:"var(--color-background-secondary)",borderRadius:"var(--border-radius-md)"}}>Enter m₀, m₁ and click Encrypt.</div>)}</div></div>{history.length>0&&(<div style={{marginTop:14}}><SectionHeading>Recent rounds</SectionHeading><div style={{display:"flex",gap:6,flexWrap:"wrap"}}>{history.slice(-20).map((h,i)=><span key={i} style={{fontSize:10,padding:"2px 7px",borderRadius:3,fontWeight:500,background:h.correct?"#E1F5EE":"#FCEBEB",border:`0.5px solid ${h.correct?"#1D9E75":"#E24B4A"}`,color:h.correct?"#0F6E56":"#A32D2D"}}>{h.correct?"✓":"✗"}</span>)}</div></div>)}</div><div style={{borderTop:"0.5px solid var(--color-border-tertiary)",paddingTop:16}}><div style={{display:"grid",gridTemplateColumns:"minmax(0,1fr) minmax(0,1fr)",gap:16}}><div><div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:10}}><SectionHeading>CPA simulation — 50 rounds</SectionHeading><button onClick={()=>setSimResult(runCPASimulation(keyHex,prfType,reuseNonce,50))} style={{padding:"6px 12px",fontSize:11,fontWeight:500,border:"0.5px solid #7F77DD",borderRadius:"var(--border-radius-md)",background:"#EEEDFE",color:"#3C3489",cursor:"pointer",fontFamily:"var(--font-sans)",whiteSpace:"nowrap"}}>Run sim</button></div>{simResult&&(<div><div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:8,marginBottom:10}}>{[{label:"Rounds",val:simResult.rounds},{label:"Correct",val:simResult.correct},{label:"Advantage",val:simResult.advantage}].map((s,i)=>(<div key={i} style={{padding:"8px 10px",background:"var(--color-background-secondary)",borderRadius:"var(--border-radius-md)"}}><div style={{fontSize:10,color:"var(--color-text-secondary)",textTransform:"uppercase",letterSpacing:"0.06em",marginBottom:2}}>{s.label}</div><div style={{fontFamily:"var(--font-mono)",fontSize:14,fontWeight:500}}>{s.val}</div></div>))}</div><div style={{padding:"8px 12px",borderRadius:"var(--border-radius-md)",background:parseFloat(simResult.advantage)<=0.15&&!reuseNonce?"#E1F5EE":reuseNonce&&parseFloat(simResult.advantage)>0.8?"#FCEBEB":"#FAEEDA",border:`0.5px solid ${parseFloat(simResult.advantage)<=0.15&&!reuseNonce?"#1D9E75":reuseNonce?"#E24B4A":"#BA7517"}`,fontSize:12,color:parseFloat(simResult.advantage)<=0.15&&!reuseNonce?"#0F6E56":reuseNonce?"#A32D2D":"#854F0B"}}>{reuseNonce?"broken mode: adversary wins trivially!":parseFloat(simResult.advantage)<=0.15?"secure mode: advantage ≈ 0 ✓":"advantage non-trivial"}</div></div>)}</div><div><div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:10}}><SectionHeading>Nonce reuse attack demo</SectionHeading><button onClick={()=>setAttackResult(demonstrateNonceReuseAttack(keyHex,prfType))} style={{padding:"6px 12px",fontSize:11,fontWeight:500,border:"0.5px solid #D85A30",borderRadius:"var(--border-radius-md)",background:"#FAECE7",color:"#993C1D",cursor:"pointer",fontFamily:"var(--font-sans)",whiteSpace:"nowrap"}}>Run attack</button></div><div style={{fontSize:12,color:"var(--color-text-secondary)",marginBottom:10}}>Enc(m) twice with reuse-r produces identical ciphertexts — trivially breaking IND-CPA.</div>{attackResult&&(<div><div style={{padding:"10px 12px",background:"var(--color-background-secondary)",borderRadius:"var(--border-radius-md)",marginBottom:8}}><div style={{display:"flex",gap:8,marginBottom:4}}><span style={{fontSize:10,color:"var(--color-text-secondary)",minWidth:24}}>m:</span><span style={{fontFamily:"var(--font-mono)",fontSize:11}}>0x{attackResult.m}</span></div><div style={{display:"flex",gap:8,marginBottom:4}}><span style={{fontSize:10,color:"var(--color-text-secondary)",minWidth:24}}>C₁:</span><span style={{fontFamily:"var(--font-mono)",fontSize:11,wordBreak:"break-all"}}>{attackResult.ct1}</span></div><div style={{display:"flex",gap:8,marginBottom:8}}><span style={{fontSize:10,color:"var(--color-text-secondary)",minWidth:24}}>C₂:</span><span style={{fontFamily:"var(--font-mono)",fontSize:11,wordBreak:"break-all"}}>{attackResult.ct2}</span></div><div style={{display:"flex",gap:8}}><span style={{fontSize:10,color:"var(--color-text-secondary)",minWidth:24}}>C₁=C₂:</span><span style={{fontSize:12,fontWeight:500,color:attackResult.detected?"#A32D2D":"#0F6E56"}}>{attackResult.detected?"YES — nonce reuse detected!":"No match (secure)"}</span></div></div>{attackResult.detected&&<div style={{padding:"10px 14px",borderRadius:"var(--border-radius-md)",background:"#FCEBEB",border:"0.5px solid #E24B4A",color:"#A32D2D",fontSize:12}}>Adversary queries Enc(m) twice and sees C₁ = C₂. IND-CPA is broken.</div>}</div>)}</div></div></div></div></div>);
// }

// // ═══════════════════════════════════════════════════════════════════════════════
// // Root
// // ═══════════════════════════════════════════════════════════════════════════════

// export default function MinicryptExplorer() {
//   const [foundationType,setFoundationType]=useState("AES");
//   return (<div style={{padding:"1rem 0",fontFamily:"var(--font-sans)",fontSize:14}}><div style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",flexWrap:"wrap",gap:12,marginBottom:20,paddingBottom:16,borderBottom:"0.5px solid var(--color-border-tertiary)"}}><div><div style={{fontSize:16,fontWeight:500,color:"var(--color-text-primary)"}}>CS8.401 Minicrypt Clique Explorer</div><div style={{fontSize:12,color:"var(--color-text-secondary)",marginTop:2}}>PA#0 scaffold · PA#1 OWF & PRG · PA#2 GGM PRF · PA#3 CPA encryption · PA#4 Modes of Operation</div></div><div style={{display:"flex",alignItems:"center",gap:10}}><span style={{fontSize:12,color:"var(--color-text-secondary)"}}>Foundation:</span><ToggleBar value={foundationType} onChange={setFoundationType} options={[{value:"AES",label:"AES-128 (PRP)",activeStyle:{bg:"#E6F1FB",border:"#378ADD",color:"#185FA5"}},{value:"DLP",label:"DLP (gˣ mod p)",activeStyle:{bg:"#E1F5EE",border:"#1D9E75",color:"#0F6E56"}}]}/></div></div><Divider label="PA #0 — Clique explorer scaffold"/><PA0Panel foundationType={foundationType}/><Divider label="PA #1 — OWF & PRG demo"/><PA1Panel/><Divider label="PA #2 — GGM PRF demo"/><PA2Panel/><Divider label="PA #3 — CPA-secure encryption & IND-CPA game"/><PA3Panel/><Divider label="PA #4 — Modes of Operation: CBC · OFB · CTR"/><PA4Panel/></div>);
// }

// ═══════════════════════════════════════════════════════════════════════════════
// App.jsx — root assembler
// Each PA lives in its own folder; this file only wires them together.
// ═══════════════════════════════════════════════════════════════════════════════

import { useState } from "react";
import { ToggleBar, Divider } from "./shared/ui.jsx";

// Lazy-import each panel so code is split per PA
import PA0Panel from "./pa0/PA0Panel.jsx";
import PA1Panel from "./pa1/PA1Panel.jsx";
import PA2Panel from "./pa2/PA2Panel.jsx";
import PA3Panel from "./pa3/PA3Panel.jsx";
import PA4Panel from "./pa4/PA4Panel.jsx";
import PA5Panel from "./pa5/PA5Panel.jsx";
import PA6Panel from "./pa6/PA6Panel.jsx";
import PA7Panel from "./pa7/PA7Panel.jsx";
import PA8Panel from "./pa8/PA8Panel.jsx";
import PA9Panel from "./pa9/PA9Panel.jsx";
import PA13Panel from "./pa13/PA13Panel.jsx";

export default function App() {
  const [foundationType, setFoundationType] = useState("AES");

  return (
    <div style={{ padding: "1rem 0", fontFamily: "var(--font-sans)", fontSize: 14 }}>
      {/* ── Global header ── */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", flexWrap: "wrap", gap: 12, marginBottom: 20, paddingBottom: 16, borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
        <div>
          <div style={{ fontSize: 16, fontWeight: 500, color: "var(--color-text-primary)" }}>CS8.401 Minicrypt Clique Explorer</div>
          <div style={{ fontSize: 12, color: "var(--color-text-secondary)", marginTop: 2 }}>
            PA#0 scaffold · PA#1 OWF & PRG · PA#2 GGM PRF · PA#3 CPA encryption · PA#4 Modes of Operation · PA#5-PA#9 · PA#13
          </div>
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

      <Divider label="PA #4 — Modes of Operation: CBC · OFB · CTR" />
      <PA4Panel />

      <Divider label="PA #5 — Message Authentication Codes" />
      <PA5Panel />

      <Divider label="PA #6 — CCA-Secure Symmetric Encryption" />
      <PA6Panel />

      <Divider label="PA #7 — Merkle-Damgård chain viewer" />
      <PA7Panel />

      <Divider label="PA #8 — DLP-based Collision-Resistant Hash" />
      <PA8Panel />

      <Divider label="PA #9 — Birthday Attack (Collision Finding)" />
      <PA9Panel />

      <Divider label="PA #13 — Miller-Rabin Primality Testing" />
      <PA13Panel />
    </div>
  );
}
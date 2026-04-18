// ═══════════════════════════════════════════════════════════════════════════════
// PA #5 — Message Authentication Codes (MACs)
// PRF-MAC · CBC-MAC · HMAC stub · EUF-CMA game · Length-extension demo
// ═══════════════════════════════════════════════════════════════════════════════

import { makePRFInterface } from "../pa2/crypto.js";

// ── helpers ───────────────────────────────────────────────────────────────────

/** XOR two equal-length binary strings → binary string */
function xorBin(a, b) {
  const len = Math.max(a.length, b.length);
  const pa = a.padStart(len, "0"), pb = b.padStart(len, "0");
  let out = "";
  for (let i = 0; i < len; i++) out += (parseInt(pa[i]) ^ parseInt(pb[i])).toString();
  return out;
}

/** XOR two equal-length hex strings → hex string (used by length-extension demo) */
function xorHex(a, b) {
  const len = Math.max(a.length, b.length);
  const pa = a.padStart(len, "0"), pb = b.padStart(len, "0");
  let out = "";
  for (let i = 0; i < len; i += 2) {
    const byte = (parseInt(pa.slice(i, i + 2), 16) ^ parseInt(pb.slice(i, i + 2), 16));
    out += byte.toString(16).padStart(2, "0");
  }
  return out;
}

/**
 * Convert a hex string to a binary string.
 * e.g. "deadbeef" → "11011110101011011011111011101111"
 */
export function hexToBin(hex) {
  return hex.replace(/\s/g, "").split("").map(h =>
    parseInt(h, 16).toString(2).padStart(4, "0")
  ).join("");
}

/**
 * Convert a binary string to hex.
 * Pads to multiple of 8 bits first.
 */
export function binToHex(bin) {
  const padded = bin.padEnd(Math.ceil(bin.length / 8) * 8, "0");
  let out = "";
  for (let i = 0; i < padded.length; i += 8)
    out += parseInt(padded.slice(i, i + 8), 2).toString(16).padStart(2, "0");
  return out;
}

/**
 * Pad and chunk a BINARY string into fixed-size n-bit blocks.
 * Always appends "1" then zeros — if msg is already block-aligned,
 * this forces a new padding block, making padding unambiguous.
 * blockBits = 8 (matching the GGM PRF's 8-bit input domain {0,1}^8)
 */
export function padAndChunkBin(msgBin, blockBits = 8) {
  let m = msgBin + "1";
  while (m.length % blockBits !== 0) m += "0";
  const chunks = [];
  for (let i = 0; i < m.length; i += blockBits)
    chunks.push(m.slice(i, i + blockBits));
  return chunks;
}

/** Hex-based pad+chunk — used only by naiveHash / length-extension demo */
function padAndChunkHex(msgHex, blockHexLen = 8) {
  let m = msgHex.replace(/\s/g, "");
  if (m.length % 2 !== 0) m += "0";
  m += "80";
  while ((m.length % blockHexLen) !== 0) m += "00";
  const chunks = [];
  for (let i = 0; i < m.length; i += blockHexLen) chunks.push(m.slice(i, i + blockHexLen));
  return chunks;
}

/** Simple deterministic "hash" for the length-extension demo (not cryptographic). */
// function naiveHash(keyHex, msgHex) {
//   const blocks = padAndChunkHex((keyHex + msgHex).replace(/\s/g, ""), 8);
//   let state = "cafebabe";
//   for (const blk of blocks) {
//     const a = parseInt(state, 16), b = parseInt(blk, 16);
//     state = (((a ^ b) * 0x9e3779b9) >>> 0 ^ ((a >>> 5) | (a << 27)) >>> 0)
//       .toString(16).padStart(8, "0");
//   }
//   return state.slice(0, 8);
// }

function mdCompress(stateHex, blockHex) {
  const a = parseInt(stateHex, 16), b = parseInt(blockHex, 16);
  return (((a ^ b) * 0x9e3779b9) >>> 0 ^ ((a >>> 5) | (a << 27)) >>> 0)
    .toString(16).padStart(8, "0");
}
 
/**
 * Merkle-Damgård hash over raw hex data.
 * IV = "cafebabe". Pad+chunk into 8-hex-char blocks, compress sequentially.
 * Callers prepend k themselves: naiveHash(k, m) = mdHash(k ‖ m).
 */
function mdHash(dataHex) {
  const blocks = padAndChunkHex(dataHex.replace(/\s/g, ""), 8);
  let state = "cafebabe";
  for (const blk of blocks) state = mdCompress(state, blk);
  return state.slice(0, 8);
}
 
/**
 * Naive single-hash MAC: t = H(k ‖ m).
 * Vulnerable to length-extension: attacker resumes mdHash from state t.
 */
function naiveHash(keyHex, msgHex) {
  return mdHash((keyHex + msgHex).replace(/\s/g, ""));
}

// ── PRF call helper ───────────────────────────────────────────────────────────

/**
 * Call prf.F(x) correctly regardless of prfType.
 *
 * GGM  → F expects an 8-bit BINARY string  e.g. "10110010"
 * AES  → F expects a HEX string             e.g. "b2"  (aesPRF calls seedFromHex)
 *
 * All internal callers pass an 8-bit binary string; this function converts to
 * hex automatically when prfType === "AES".
 */
function callF(prf, binInput8, prfType) {
  if (prfType === "AES") return prf.F(binToHex(binInput8));
  return prf.F(binInput8);   // GGM: pass binary directly
}

// ── Construction 1: PRF-MAC (fixed-length) ────────────────────────────────────

/**
 * Mac_k(m) = F_k(m)
 * m is an 8-bit binary string ∈ {0,1}^8.
 *
 * @param {string} keyHex
 * @param {string} msgBin  — binary string e.g. "10110010"
 * @param {"GGM"|"AES"} prfType
 */
export function prfMacSign(keyHex, msgBin, prfType = "GGM") {
  const prf = makePRFInterface(keyHex, prfType);
  const m   = msgBin.replace(/[^01]/g, "").padEnd(8, "0").slice(0, 8);
  const tag = callF(prf, m, prfType);
  return { tag, m, keyHex, prfType };
}

/** Vrfy_k(m, t) → boolean */
export function prfMacVerify(keyHex, msgBin, tag, prfType = "GGM") {
  const { tag: expected } = prfMacSign(keyHex, msgBin, prfType);
  return expected === tag;
}

// ── Construction 2: CBC-MAC (variable-length) ─────────────────────────────────

/**
 * CBC-MAC over a binary message string.
 *
 * State is kept as an 8-bit binary string — the same domain as the PRF input {0,1}^8.
 * Each step:
 *   xoredBin = stateBin XOR block          (8-bit binary)
 *   nextHex  = F_k(xoredBin)               (8-hex-char output from PRF)
 *   nextBin  = low 8 bits of nextHex       (fed as state into next round)
 * Tag = the full hex output of the LAST F_k call (not the truncated state).
 *
 * This avoids the width-mismatch bug where XOR-ing an 8-bit block into a
 * 32-bit hex state placed the block in the wrong (high) bit-position.
 *
 * @param {string} keyHex
 * @param {string} msgBin  — binary string of any length e.g. "1011001011001010"
 * @param {"GGM"|"AES"} prfType
 * @returns {{ tag: string, blocks: string[], steps: object[] }}
 */
export function cbcMacSign(keyHex, msgBin, prfType = "GGM") {
  const prf    = makePRFInterface(keyHex, prfType);
  const blocks = padAndChunkBin(msgBin, 8);   // array of 8-bit binary strings
  const steps  = [];
  let stateBin = "00000000";                   // IV = 0^8 binary

  for (let i = 0; i < blocks.length; i++) {
    const xoredBin = xorBin(stateBin, blocks[i]);          // 8-bit XOR
    const nextHex  = callF(prf, xoredBin, prfType);        // full PRF output (8 hex chars)
    const nextBin  = hexToBin(nextHex).slice(-8);          // low 8 bits → next state

    steps.push({
      block:   blocks[i],   // 8-bit binary input block (for display)
      state:   stateBin,    // 8-bit binary state going IN
      xored:   xoredBin,    // 8-bit binary after XOR
      next:    nextHex,     // full hex output of F_k (for display)
      nextBin,              // 8-bit binary state going OUT
    });
    stateBin = nextBin;
  }

  // Tag = full PRF output of the last step (not the truncated 8-bit state)
  const tag = steps.length > 0 ? steps[steps.length - 1].next : "00000000";
  return { tag, blocks, steps };
}

/** Vrfy for CBC-MAC. */
export function cbcMacVerify(keyHex, msgBin, tag, prfType = "GGM") {
  const { tag: expected } = cbcMacSign(keyHex, msgBin, prfType);
  return expected === tag;
}

// ── Construction 3: HMAC stub ─────────────────────────────────────────────────

/**
 * HMAC_k(m) = H( (k ⊕ opad) ‖ H( (k ⊕ ipad) ‖ m ) )
 * Full implementation deferred to PA#10 — raises NotImplementedError.
 */
export function hmac(_keyHex, _msgBin) {
  throw new Error("NotImplemented — HMAC full implementation belongs in PA#10.");
}

// ── MAC ⇒ PRF distinguishing test ─────────────────────────────────────────────

/**
 * Run q queries: compare PRF-MAC output against a "truly random" oracle.
 * Mirrors runDistinguishingGame from PA#2 but uses prfMacSign.
 * x ∈ {0,1}^8 — the full PRF input domain.
 */
export function runMacPRFDistTest(keyHex, prfType = "GGM", q = 100) {
  function seedFromHex(h) { return parseInt(h.slice(0, 8), 16) || 0; }
  function fakeHex(seed, bytes) {
    let s = (seed ^ 0x5a5a5a5a) >>> 0;
    let out = "";
    for (let i = 0; i < bytes; i++) {
      s = (s * 1664525 + 1013904223) >>> 0;
      out += (s & 0xff).toString(16).padStart(2, "0");
    }
    return out;
  }

  const queries = [];
  for (let i = 0; i < q; i++) {
    // x is 8-bit binary (PRF input domain {0,1}^8)
    const x      = (i & 0xff).toString(2).padStart(8, "0");
    const xHex   = binToHex(x);
    const macOut = prfMacSign(keyHex, x, prfType).tag;
    const rndOut = fakeHex((seedFromHex(xHex) ^ 0xdeadcafe ^ i * 0x1234) >>> 0, 4);
    queries.push({ x, macOut, rndOut, same: macOut === rndOut });
  }

  const collisions = queries.filter(q => q.same).length;
  const seed_    = h => parseInt(h.slice(0, 2), 16);
  const macMean  = queries.map(q => seed_(q.macOut)).reduce((a, b) => a + b, 0) / q;
  const randMean = queries.map(q => seed_(q.rndOut)).reduce((a, b) => a + b, 0) / q;
  return {
    queries: queries.slice(0, 10),
    collisions,
    collisionRate: (collisions / q * 100).toFixed(2),
    macMean:  macMean.toFixed(1),
    randMean: randMean.toFixed(1),
    diff:     Math.abs(macMean - randMean).toFixed(2),
    totalQ:   q,
  };
}

// ── EUF-CMA game ──────────────────────────────────────────────────────────────

/**
 * Generate q (m_i, t_i) pairs signed under keyHex.
 * Messages are distinct 8-bit binary strings (capped at 256 unique values).
 */
export function generateSignedPairs(keyHex, prfType = "GGM", q = 50) {
  const pairs = [];
  for (let i = 0; i < Math.min(q, 256); i++) {
    const m = ((i * 0x1b + 0x37) & 0xff).toString(2).padStart(8, "0");
    const { tag } = prfMacSign(keyHex, m, prfType);
    pairs.push({ m, tag });
  }
  return pairs;
}

/**
 * Attempt a forgery: submit (m*, t*) where m* must NOT be in the signed set.
 * forgeryMsg should be an 8-bit binary string.
 * Returns { accepted: boolean, reason: string }
 */
export function attemptForgery(keyHex, forgeryMsg, forgeryTag, signedPairs, prfType = "GGM") {
  const m = forgeryMsg.replace(/[^01]/g, "").padEnd(8, "0").slice(0, 8);
  const alreadySeen = signedPairs.some(p => p.m === m);
  if (alreadySeen) return { accepted: false, reason: "Message already in signed set — not a new message" };
  const valid = prfMacVerify(keyHex, m, forgeryTag, prfType);
  return {
    accepted: valid,
    reason: valid ? "Forgery accepted ✓ (unexpected!)" : "Forgery rejected — tag invalid",
  };
}

// ── Length-extension attack demo ──────────────────────────────────────────────

/**
 * Naive single-hash MAC vulnerability: t = H(k ‖ m).
 * An attacker who knows t and |k| can forge a valid tag on m ‖ pad ‖ m′
 * WITHOUT knowing k, by continuing the hash from state t.
 *
 * All inputs/outputs are HEX (the naive hash operates over bytes).
 *
 * @param {string} keyHex
 * @param {string} origMsgHex
 * @param {string} suffixHex   — attacker-chosen suffix m′
 * @returns {{ origTag, extMsg, extTag, extTagTrue, attackSucceeded, padHex }}
 */
export function lengthExtensionDemo(keyHex, origMsgHex, suffixHex) {
  const origTag = naiveHash(keyHex, origMsgHex);

  // Padding appended inside H when it processed (k ‖ m)
  const inner  = (keyHex + origMsgHex).replace(/\s/g, "");
  const padded = padAndChunkHex(inner, 8).join("");
  const padHex = padded.slice(inner.length);

  // Extended message m_ext = m ‖ pad ‖ m′  (attacker builds this without k)
  const extMsg = origMsgHex + padHex + suffixHex;

  // Attacker continues hashing from state = origTag, feeding only suffix blocks
  const suffixBlocks = padAndChunkHex(suffixHex, 8);
  // let state = origTag;
  // for (const blk of suffixBlocks) {
  //   const a = parseInt(state, 16), b = parseInt(blk, 16);
  //   state = (((a ^ b) * 0x9e3779b9) >>> 0 ^ ((a >>> 5) | (a << 27)) >>> 0)
  //     .toString(16).padStart(8, "0");
  // }
  let attackState = origTag;   // resume from t — no k!
  for (const blk of suffixBlocks)
    attackState = mdCompress(attackState, blk);
  const extTagForged = attackState.slice(0, 8);
  // const extTagFromState = state.slice(0, 8);

  // Ground truth: what H(k ‖ m_ext) actually produces
  const extTagTrue = naiveHash(keyHex, extMsg);

  return {
    origTag,
    extMsg,
    extTag: extTagForged,
    extTagTrue,
    attackSucceeded: extTagForged === extTagTrue,
    padHex,
  };
}

// ── re-exports ────────────────────────────────────────────────────────────────
export { xorBin, xorHex, naiveHash, padAndChunkHex };

// Forged message: 1011001011111011
// You never asked the oracle to sign 1011001011111011. You only ever queried:

// Mac(10110010) → t₁
// Mac(11001010) → t₂


// FOR AES
//  KEY K = a3f2c1b8
// Message m1 = 10110010
// Message m2 = 11001010

// T1 - d53cf30bebe5f272 
// T2 - 6df44b83031dca6a

//  M' = 1011001010101001
// SAME T2 WILL VERIFY THIS

// Step 2 XOR = t₁_low8 ⊕ m₂′
//            = t₁_low8 ⊕ (m₂ ⊕ t₁_low8)
//            = m₂          ← t₁_low8 cancels out


// // // ═══════════════════════════════════════════════════════════════════════════════
// // // PA #5 — Message Authentication Codes (MACs)
// // // PRF-MAC · CBC-MAC · HMAC stub · EUF-CMA game · Length-extension demo
// // // ═══════════════════════════════════════════════════════════════════════════════

// // import { makePRFInterface } from "../pa2/crypto.js";

// // // ── helpers ───────────────────────────────────────────────────────────────────

// // /** XOR two equal-length hex strings → hex string */
// // function xorHex(a, b) {
// //   const len = Math.max(a.length, b.length);
// //   const pa  = a.padStart(len, "0"), pb = b.padStart(len, "0");
// //   let out = "";
// //   for (let i = 0; i < len; i += 2) {
// //     const byte = (parseInt(pa.slice(i, i + 2), 16) ^ parseInt(pb.slice(i, i + 2), 16));
// //     out += byte.toString(16).padStart(2, "0");
// //   }
// //   return out;
// // }

// // /** Pad / chunk a hex message into fixed-size 8-hex-char (4-byte) blocks.
// //  *  Padding: append 0x80 byte then 0x00… until block-aligned. */
// // function padAndChunk(msgHex, blockHexLen = 8) {
// //   let m = msgHex.replace(/\s/g, "");
// //   if (m.length % 2 !== 0) m += "0";          // make even nibbles
// //   m += "80";                                   // padding byte
// //   while ((m.length % blockHexLen) !== 0) m += "00";
// //   const chunks = [];
// //   for (let i = 0; i < m.length; i += blockHexLen) chunks.push(m.slice(i, i + blockHexLen));
// //   return chunks;
// // }

// // /** Simple deterministic "hash" for the length-extension demo (not cryptographic). */
// // function naiveHash(keyHex, msgHex) {
// //   // H(k ‖ m): feed k ‖ m block by block through a Davies–Meyer-like compression
// //   const blocks = padAndChunk((keyHex + msgHex).replace(/\s/g, ""), 8);
// //   let state = "cafebabe";
// //   for (const blk of blocks) {
// //     const a = parseInt(state, 16), b = parseInt(blk, 16);
// //     state = (((a ^ b) * 0x9e3779b9) >>> 0 ^ ((a >>> 5) | (a << 27)) >>> 0).toString(16).padStart(8, "0");
// //   }
// //   return state.slice(0, 8);
// // }

// // // ── Construction 1: PRF-MAC (fixed-length) ────────────────────────────────────

// // /**
// //  * Mac_k(m) = F_k(m)  — message must be exactly one PRF-input block (8 hex chars).
// //  * @param {string} keyHex
// //  * @param {string} msgHex  — 8 hex chars (4 bytes), i.e. ∈ {0,1}ⁿ
// //  * @param {"GGM"|"AES"} prfType
// //  */
// // export function prfMacSign(keyHex, msgHex, prfType = "GGM") {
// //   const prf = makePRFInterface(keyHex, prfType);
// //   const m   = msgHex.padEnd(8, "0").slice(0, 8);
// //   const tag = prf.F(m);
// //   return { tag, m, keyHex, prfType };
// // }

// // /**
// //  * Vrfy_k(m, t) → boolean
// //  */
// // export function prfMacVerify(keyHex, msgHex, tag, prfType = "GGM") {
// //   const { tag: expected } = prfMacSign(keyHex, msgHex, prfType);
// //   return expected === tag;
// // }

// // // ── Construction 2: CBC-MAC (variable-length) ─────────────────────────────────

// // /**
// //  * CBC-MAC: chain F_k over padded message blocks, return final state as tag.
// //  * @param {string} keyHex
// //  * @param {string} msgHex  — arbitrary hex string
// //  * @param {"GGM"|"AES"} prfType
// //  * @returns {{ tag, steps }}  steps for visualisation
// //  */
// // export function cbcMacSign(keyHex, msgHex, prfType = "GGM") {
// //   const prf    = makePRFInterface(keyHex, prfType);
// //   const blocks = padAndChunk(msgHex, 8);
// //   const steps  = [];
// //   let state    = "00000000";                    // IV = 0ⁿ

// //   for (let i = 0; i < blocks.length; i++) {
// //     const xored = xorHex(state, blocks[i]);
// //     const next  = prf.F(xored);
// //     steps.push({ block: blocks[i], state, xored, next });
// //     state = next;
// //   }
// //   return { tag: state, blocks, steps };
// // }

// // /**
// //  * Vrfy for CBC-MAC.
// //  */
// // export function cbcMacVerify(keyHex, msgHex, tag, prfType = "GGM") {
// //   const { tag: expected } = cbcMacSign(keyHex, msgHex, prfType);
// //   return expected === tag;
// // }

// // // ── Construction 3: HMAC stub ─────────────────────────────────────────────────

// // /**
// //  * HMAC_k(m) = H( (k ⊕ opad) ‖ H( (k ⊕ ipad) ‖ m ) )
// //  * Full implementation deferred to PA#10 — raises NotImplementedError.
// //  */
// // export function hmac(_keyHex, _msgHex) {
// //   throw new Error("NotImplemented — HMAC full implementation belongs in PA#10.");
// // }

// // // ── MAC ⇒ PRF distinguishing test ─────────────────────────────────────────────

// // /**
// //  * Run q queries: compare PRF-MAC output against a "truly random" oracle.
// //  * Mirrors runDistinguishingGame from PA#2 but uses prfMacSign.
// //  */
// // export function runMacPRFDistTest(keyHex, prfType = "GGM", q = 100) {
// //   const { fakeHex, seedFromHex } = (() => {
// //     // Inline minimal versions so this file stays self-contained for tests
// //     function seedFromHex(h) { return parseInt(h.slice(0, 8), 16) || 0; }
// //     function fakeHex(seed, bytes) {
// //       let s = (seed ^ 0x5a5a5a5a) >>> 0;
// //       let out = "";
// //       for (let i = 0; i < bytes; i++) {
// //         s = (s * 1664525 + 1013904223) >>> 0;
// //         out += (s & 0xff).toString(16).padStart(2, "0");
// //       }
// //       return out;
// //     }
// //     return { fakeHex, seedFromHex };
// //   })();

// //   const queries = [];
// //   for (let i = 0; i < q; i++) {
// //     const x      = i.toString(16).padStart(8, "0");
// //     const macOut = prfMacSign(keyHex, x, prfType).tag;
// //     const rndOut = fakeHex((seedFromHex(x) ^ 0xdeadcafe ^ i * 0x1234) >>> 0, 4);
// //     queries.push({ x, macOut, rndOut, same: macOut === rndOut });
// //   }
// //   const collisions = queries.filter(q => q.same).length;
// //   const seed_ = h => parseInt(h.slice(0, 2), 16);
// //   const macMean  = queries.map(q => seed_(q.macOut)).reduce((a, b) => a + b, 0) / q;
// //   const randMean = queries.map(q => seed_(q.rndOut)).reduce((a, b) => a + b, 0) / q;
// //   return {
// //     queries: queries.slice(0, 10),
// //     collisions,
// //     collisionRate: (collisions / q * 100).toFixed(2),
// //     macMean:  macMean.toFixed(1),
// //     randMean: randMean.toFixed(1),
// //     diff:     Math.abs(macMean - randMean).toFixed(2),
// //     totalQ: q,
// //   };
// // }

// // // ── EUF-CMA game ──────────────────────────────────────────────────────────────

// // /** Generate q (m_i, t_i) pairs signed under keyHex. */
// // export function generateSignedPairs(keyHex, prfType = "GGM", q = 50) {
// //   const pairs = [];
// //   for (let i = 0; i < q; i++) {
// //     const m = (i * 0x12345678 + 0xabcd0000 + i * 0x1111).toString(16).padStart(8, "0").slice(0, 8);
// //     const { tag } = prfMacSign(keyHex, m, prfType);
// //     pairs.push({ m, tag });
// //   }
// //   return pairs;
// // }

// // /**
// //  * Try to forge: submit (m*, t*) where m* is not in the signed pairs.
// //  * Returns { accepted, reason }
// //  */
// // export function attemptForgery(keyHex, forgeryMsg, forgeryTag, signedPairs, prfType = "GGM") {
// //   const alreadySeen = signedPairs.some(p => p.m === forgeryMsg);
// //   if (alreadySeen) return { accepted: false, reason: "Message already in signed set — not a new message" };
// //   const valid = prfMacVerify(keyHex, forgeryMsg, forgeryTag, prfType);
// //   return { accepted: valid, reason: valid ? "Forgery accepted ✓ (unexpected!)" : "Forgery rejected — tag invalid" };
// // }

// // // ── Length-extension attack demo ──────────────────────────────────────────────

// // /**
// //  * Naive single-hash MAC: t = H(k ‖ m).
// //  * An attacker who knows t = H(k ‖ m) and |k| can compute H(k ‖ m ‖ pad ‖ m')
// //  * WITHOUT knowing k, just by continuing from state t.
// //  *
// //  * @param {string} keyHex
// //  * @param {string} origMsgHex  — original message (hex)
// //  * @param {string} suffixHex   — attacker-chosen suffix m′
// //  * @returns {{ origTag, extMsg, extTag, attackSucceeded }}
// //  */
// // export function lengthExtensionDemo(keyHex, origMsgHex, suffixHex) {
// //   // Legitimate tag t = H(k ‖ m)
// //   const origTag = naiveHash(keyHex, origMsgHex);

// //   // Padding that would have been appended inside H(k ‖ m)
// //   const inner   = (keyHex + origMsgHex).replace(/\s/g, "");
// //   const padded  = padAndChunk(inner, 8).join("");          // k ‖ m ‖ pad
// //   const padHex  = padded.slice(inner.length);              // just the padding bytes

// //   // Extended message m_ext = m ‖ pad ‖ m′  (no key needed!)
// //   const extMsg  = origMsgHex + padHex + suffixHex;

// //   // Attacker continues hashing from state = origTag, feeding only suffix blocks
// //   const suffixBlocks = padAndChunk(suffixHex, 8);
// //   let state = origTag;
// //   for (const blk of suffixBlocks) {
// //     const a = parseInt(state, 16), b = parseInt(blk, 16);
// //     state = (((a ^ b) * 0x9e3779b9) >>> 0 ^ ((a >>> 5) | (a << 27)) >>> 0).toString(16).padStart(8, "0");
// //   }
// //   const extTagFromState = state.slice(0, 8);

// //   // Ground truth: what H(k ‖ m_ext) actually produces
// //   const extTagTrue = naiveHash(keyHex, extMsg);

// //   const attackSucceeded = extTagFromState === extTagTrue;
// //   return { origTag, extMsg, extTag: extTagFromState, extTagTrue, attackSucceeded, padHex };
// // }

// // // ── CBC-MAC step-by-step trace (for visualiser) ───────────────────────────────

// // export { padAndChunk, xorHex, naiveHash };

// // ═══════════════════════════════════════════════════════════════════════════════
// // PA #5 — Message Authentication Codes (MACs)
// // PRF-MAC · CBC-MAC · HMAC stub · EUF-CMA game · Length-extension demo
// // ═══════════════════════════════════════════════════════════════════════════════

// import { makePRFInterface } from "../pa2/crypto.js";

// // ── helpers ───────────────────────────────────────────────────────────────────

// /** XOR two equal-length binary strings → binary string */
// function xorBin(a, b) {
//   const len = Math.max(a.length, b.length);
//   const pa = a.padStart(len, "0"), pb = b.padStart(len, "0");
//   let out = "";
//   for (let i = 0; i < len; i++) out += (parseInt(pa[i]) ^ parseInt(pb[i])).toString();
//   return out;
// }

// /** XOR two equal-length hex strings → hex string (kept for length-extension demo) */
// function xorHex(a, b) {
//   const len = Math.max(a.length, b.length);
//   const pa = a.padStart(len, "0"), pb = b.padStart(len, "0");
//   let out = "";
//   for (let i = 0; i < len; i += 2) {
//     const byte = (parseInt(pa.slice(i, i + 2), 16) ^ parseInt(pb.slice(i, i + 2), 16));
//     out += byte.toString(16).padStart(2, "0");
//   }
//   return out;
// }

// /**
//  * Convert a hex string to a binary string.
//  * e.g. "deadbeef" → "11011110101011011011111011101111"
//  */
// function hexToBin(hex) {
//   return hex.replace(/\s/g, "").split("").map(h =>
//     parseInt(h, 16).toString(2).padStart(4, "0")
//   ).join("");
// }

// /**
//  * Convert a binary string to hex.
//  * Pads to multiple of 8 bits first.
//  */
// function binToHex(bin) {
//   const padded = bin.padEnd(Math.ceil(bin.length / 8) * 8, "0");
//   let out = "";
//   for (let i = 0; i < padded.length; i += 8)
//     out += parseInt(padded.slice(i, i + 8), 2).toString(16).padStart(2, "0");
//   return out;
// }

// /**
//  * Pad and chunk a BINARY string into fixed-size n-bit blocks.
//  * Padding: append 1 bit, then 0s until block-aligned.
//  * blockBits = 8 (matching the GGM PRF's 8-bit input domain {0,1}^8)
//  */
// // function padAndChunkBin(msgBin, blockBits = 8) {
// //   let m = msgBin + "1";                          // append 1-bit
// //   while (m.length % blockBits !== 0) m += "0";  // pad with 0s
// //   const chunks = [];
// //   for (let i = 0; i < m.length; i += blockBits) chunks.push(m.slice(i, i + blockBits));
// //   return chunks;
// // }
// // function padAndChunkBin(msgBin, blockBits = 8) {
// //   // Step 1: ALWAYS append the '1' bit (the separator)
// //   let m = msgBin + "1"; 
  
// //   // Step 2: Pad with '0's until the string is a multiple of blockBits
// //   // Because we added '1', if the original was 8 bits, this will 
// //   // correctly push us into a second block (16 bits total).
// //   while (m.length % blockBits !== 0) {
// //     m += "0";
// //   }
  
// //   const chunks = [];
// //   for (let i = 0; i < m.length; i += blockBits) {
// //     chunks.push(m.slice(i, i + blockBits));
// //   }
// //   return chunks;
// // }

// function padAndChunkBin(msgBin, blockBits = 8) {
//   // Always append "1" then zeros — if msg is already block-aligned,
//   // this forces a new padding block, making padding unambiguous
//   let m = msgBin + "1";
//   while (m.length % blockBits !== 0) m += "0";
//   const chunks = [];
//   for (let i = 0; i < m.length; i += blockBits) 
//     chunks.push(m.slice(i, i + blockBits));
//   return chunks;
// }

// /** Simple deterministic "hash" for the length-extension demo (not cryptographic). */
// function naiveHash(keyHex, msgHex) {
//   const blocks = padAndChunkHex((keyHex + msgHex).replace(/\s/g, ""), 8);
//   let state = "cafebabe";
//   for (const blk of blocks) {
//     const a = parseInt(state, 16), b = parseInt(blk, 16);
//     state = (((a ^ b) * 0x9e3779b9) >>> 0 ^ ((a >>> 5) | (a << 27)) >>> 0).toString(16).padStart(8, "0");
//   }
//   return state.slice(0, 8);
// }

// /** Hex-based pad+chunk kept only for naiveHash (length-extension demo) */
// function padAndChunkHex(msgHex, blockHexLen = 8) {
//   let m = msgHex.replace(/\s/g, "");
//   if (m.length % 2 !== 0) m += "0";
//   m += "80";
//   while ((m.length % blockHexLen) !== 0) m += "00";
//   const chunks = [];
//   for (let i = 0; i < m.length; i += blockHexLen) chunks.push(m.slice(i, i + blockHexLen));
//   return chunks;
// }

// // ── Construction 1: PRF-MAC (fixed-length) ────────────────────────────────────

// /**
//  * Mac_k(m) = F_k(m)
//  * m must be a binary string of exactly n bits (n=8 for our GGM/AES stub).
//  * @param {string} keyHex
//  * @param {string} msgBin  — binary string e.g. "10110010" ∈ {0,1}^8
//  * @param {"GGM"|"AES"} prfType
//  */
// export function prfMacSign(keyHex, msgBin, prfType = "GGM") {
//   const prf = makePRFInterface(keyHex, prfType);
//   // Normalise: keep only 0/1 chars, pad/truncate to 8 bits
//   const m = msgBin.replace(/[^01]/g, "").padEnd(8, "0").slice(0, 8);
//   const tag = prf.F(m);
//   return { tag, m, keyHex, prfType };
// }

// /**
//  * Vrfy_k(m, t) → boolean
//  */
// export function prfMacVerify(keyHex, msgBin, tag, prfType = "GGM") {
//   const { tag: expected } = prfMacSign(keyHex, msgBin, prfType);
//   return expected === tag;
// }

// // ── Construction 2: CBC-MAC (variable-length) ─────────────────────────────────

// /**
//  * CBC-MAC over binary message string.
//  * Splits msgBin into 8-bit blocks (with padding), XORs each with current state
//  * (also 8-bit binary), applies F_k, chains the result.
//  *
//  * @param {string} keyHex
//  * @param {string} msgBin  — binary string of any length e.g. "1011001011001010"
//  * @param {"GGM"|"AES"} prfType
//  * @returns {{ tag, blocks, steps }}
//  */
// // export function cbcMacSign(keyHex, msgBin, prfType = "GGM") {
// //   const prf = makePRFInterface(keyHex, prfType);
// //   const blocks = padAndChunkBin(msgBin, 8);
  
// //   // Start the state with the length of the original message
// //   // This ensures that '1010' and '101010' result in totally different chains
// //   let state = hexToBin(prf.F(msgBin.length.toString(2).padStart(8, "0"))).slice(0, 8);

// //   for (const block of blocks) {
// //     state = hexToBin(prf.F(xorBin(state, block))).slice(0, 8);
// //   }
// //   return binToHex(state);
// // }
// // export function cbcMacSign(keyHex, msgBin, prfType = "GGM") {
// //   const prf    = makePRFInterface(keyHex, prfType);
// //   const blocks = padAndChunkBin(msgBin, 8);        // each block: 8-bit binary string
// //   const steps  = [];
// //   let state    = "00000000";                        // IV = 0^8 in binary

// //   for (let i = 0; i < blocks.length; i++) {
// //     const xored = xorBin(state, blocks[i]);         // 8-bit binary XOR
// //     const next  = prf.F(xored);                     // prf.F takes {0,1}^8, returns hex
// //     // Convert hex output back to 8-bit binary for next state
// //     const nextBin = hexToBin(next).slice(0, 8);
// //     steps.push({ block: blocks[i], state, xored, next, nextBin });
// //     state = nextBin;
// //   }

// //   // Final tag as hex (more readable)
// //   const tagHex = binToHex(state);
// //   return { tag: tagHex, tagBin: state, blocks, steps };
// // }

// /**
//  * CBC-MAC — state is HEX (8 chars = 32 bits, matching PRF output width).
//  * Message blocks are 8-bit binary (matching PRF *input* domain {0,1}^8).
//  * To XOR: zero-extend the 8-bit block to 32 bits, then XOR with hex state.
//  */
// export function cbcMacSign(keyHex, msgBin, prfType = "GGM") {
//   const prf    = makePRFInterface(keyHex, prfType);
//   const blocks = padAndChunkBin(msgBin, 8);   // each block: 8-bit binary string
//   const steps  = [];
//   let stateHex = "00000000";                   // IV = 0^32 as 8-hex-char string

//   for (let i = 0; i < blocks.length; i++) {
//     // Convert 8-bit binary block → hex, zero-pad to 8 hex chars (32 bits)
//     const blockHex = binToHex(blocks[i]).padStart(8, "0");
//     // XOR state (32-bit hex) with block (32-bit hex, block in low bits)
//     const xoredHex = xorHex(stateHex, blockHex);
//     // Feed XOR result's low 8 bits as binary to PRF (PRF input domain = {0,1}^8)
//     const xoredLowBin = hexToBin(xoredHex).slice(-8);  // take LAST 8 bits
//     const nextHex  = prf.F(xoredLowBin);               // returns 8-hex-char string
//     steps.push({
//       block:    blocks[i],          // 8-bit binary
//       blockHex,                     // for display
//       state:    stateHex,           // hex
//       xored:    xoredHex,           // hex
//       xoredBin: xoredLowBin,        // what actually went into F_k
//       next:     nextHex,            // hex output of F_k
//     });
//     stateHex = nextHex;
//   }
//   return { tag: stateHex, blocks, steps };
// }

// /**
//  * Vrfy for CBC-MAC.
//  */
// export function cbcMacVerify(keyHex, msgBin, tag, prfType = "GGM") {
//   const { tag: expected } = cbcMacSign(keyHex, msgBin, prfType);
//   return expected === tag;
// }

// // ── Construction 3: HMAC stub ─────────────────────────────────────────────────

// export function hmac(_keyHex, _msgBin) {
//   throw new Error("NotImplemented — HMAC full implementation belongs in PA#10.");
// }

// // ── MAC ⇒ PRF distinguishing test ─────────────────────────────────────────────

// export function runMacPRFDistTest(keyHex, prfType = "GGM", q = 100) {
//   const { fakeHex, seedFromHex } = (() => {
//     function seedFromHex(h) { return parseInt(h.slice(0, 8), 16) || 0; }
//     function fakeHex(seed, bytes) {
//       let s = (seed ^ 0x5a5a5a5a) >>> 0;
//       let out = "";
//       for (let i = 0; i < bytes; i++) {
//         s = (s * 1664525 + 1013904223) >>> 0;
//         out += (s & 0xff).toString(16).padStart(2, "0");
//       }
//       return out;
//     }
//     return { fakeHex, seedFromHex };
//   })();

//   const queries = [];
//   for (let i = 0; i < q; i++) {
//     // x is an 8-bit binary string (domain {0,1}^8)
//     const x      = i.toString(2).padStart(8, "0").slice(0, 8);
//     const xHex   = binToHex(x);
//     const macOut = prfMacSign(keyHex, x, prfType).tag;
//     const rndOut = fakeHex((seedFromHex(xHex) ^ 0xdeadcafe ^ i * 0x1234) >>> 0, 4);
//     queries.push({ x, macOut, rndOut, same: macOut === rndOut });
//   }
//   const collisions = queries.filter(q => q.same).length;
//   const seed_ = h => parseInt(h.slice(0, 2), 16);
//   const macMean  = queries.map(q => seed_(q.macOut)).reduce((a, b) => a + b, 0) / q;
//   const randMean = queries.map(q => seed_(q.rndOut)).reduce((a, b) => a + b, 0) / q;
//   return {
//     queries: queries.slice(0, 10),
//     collisions,
//     collisionRate: (collisions / q * 100).toFixed(2),
//     macMean:  macMean.toFixed(1),
//     randMean: randMean.toFixed(1),
//     diff:     Math.abs(macMean - randMean).toFixed(2),
//     totalQ: q,
//   };
// }

// // ── EUF-CMA game ──────────────────────────────────────────────────────────────

// /** Generate q (m_i, t_i) pairs — messages are 8-bit binary strings */
// export function generateSignedPairs(keyHex, prfType = "GGM", q = 50) {
//   const pairs = [];
//   for (let i = 0; i < q; i++) {
//     // Generate distinct 8-bit binary messages
//     const m = ((i * 0x1b + 0x37) & 0xff).toString(2).padStart(8, "0");
//     const { tag } = prfMacSign(keyHex, m, prfType);
//     pairs.push({ m, tag });
//   }
//   return pairs;
// }

// export function attemptForgery(keyHex, forgeryMsg, forgeryTag, signedPairs, prfType = "GGM") {
//   // Normalise forgeryMsg to 8-bit binary
//   const m = forgeryMsg.replace(/[^01]/g, "").padEnd(8, "0").slice(0, 8);
//   const alreadySeen = signedPairs.some(p => p.m === m);
//   if (alreadySeen) return { accepted: false, reason: "Message already in signed set — not a new message" };
//   const valid = prfMacVerify(keyHex, m, forgeryTag, prfType);
//   return { accepted: valid, reason: valid ? "Forgery accepted ✓ (unexpected!)" : "Forgery rejected — tag invalid" };
// }

// // ── Length-extension attack demo ──────────────────────────────────────────────

// export function lengthExtensionDemo(keyHex, origMsgHex, suffixHex) {
//   const origTag = naiveHash(keyHex, origMsgHex);
//   const inner   = (keyHex + origMsgHex).replace(/\s/g, "");
//   const padded  = padAndChunkHex(inner, 8).join("");
//   const padHex  = padded.slice(inner.length);
//   const extMsg  = origMsgHex + padHex + suffixHex;

//   const suffixBlocks = padAndChunkHex(suffixHex, 8);
//   let state = origTag;
//   for (const blk of suffixBlocks) {
//     const a = parseInt(state, 16), b = parseInt(blk, 16);
//     state = (((a ^ b) * 0x9e3779b9) >>> 0 ^ ((a >>> 5) | (a << 27)) >>> 0).toString(16).padStart(8, "0");
//   }
//   const extTagFromState = state.slice(0, 8);
//   const extTagTrue = naiveHash(keyHex, extMsg);
//   const attackSucceeded = extTagFromState === extTagTrue;
//   return { origTag, extMsg, extTag: extTagFromState, extTagTrue, attackSucceeded, padHex };
// }

// export { padAndChunkBin as padAndChunk, xorBin as xorHex, naiveHash, hexToBin, binToHex };
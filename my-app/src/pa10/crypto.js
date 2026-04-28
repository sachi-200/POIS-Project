// ═══════════════════════════════════════════════════════════════════════════════
// PA #10 — HMAC and HMAC-Based CCA Encryption
//
// Implements:
//   1. HMAC over PA#8 DLP_Hash
//   2. Constant-time tag verification
//   3. CRHF ⇒ MAC demo via EUF-CMA HMAC game
//   4. MAC ⇒ CRHF demo by using HMAC as a Merkle-Damgård compression function
//   5. Length-extension attack on naive H(k || m) and HMAC resistance
//   6. Encrypt-then-HMAC CCA-secure encryption built on PA#3 CPA encryption
//
// No external crypto libraries are used. The hash layer is PA#8 DLP_Hash and
// the encryption layer is PA#3 CPA encryption.
// ═══════════════════════════════════════════════════════════════════════════════

import { encCPA, decCPA } from "../pa3/crypto.js";
import { mdPad, parseBlocks, IV } from "../pa7/crypto.js";
import { setupGroup, makeDLPCompressFn, dlpHash, DEMO_P, DEMO_Q } from "../pa8/crypto.js";

// PA#8 setupGroup chooses alpha randomly. Keep one stable PA#10 parameter set for
// the whole app session, so HMAC signing and verification use the same hash.
export const HMAC_HASH_PARAMS = setupGroup(DEMO_P, DEMO_Q);
export const HMAC_BLOCK_BYTES = 8;     // PA#7 block size
export const HMAC_DIGEST_BYTES = 4;    // PA#8/PA#7 digest is 8 hex chars = 4 bytes

// ── Byte/hex/text helpers ────────────────────────────────────────────────────

export function cleanHex(hex) {
  return String(hex || "").replace(/[^0-9a-fA-F]/g, "").toLowerCase();
}

export function hexToBytes(hex) {
  const h0 = cleanHex(hex);
  const h = h0.length % 2 === 0 ? h0 : `0${h0}`;
  const out = [];
  for (let i = 0; i < h.length; i += 2) out.push(Number.parseInt(h.slice(i, i + 2), 16) || 0);
  return out;
}

export function bytesToHexLocal(bytes) {
  return Array.from(bytes).map(b => (b & 0xff).toString(16).padStart(2, "0")).join("");
}

export function textToBytes(text) {
  return Array.from(new TextEncoder().encode(String(text ?? "")));
}

export function bytesToText(bytes) {
  try { return new TextDecoder().decode(new Uint8Array(bytes)); }
  catch { return ""; }
}

export function normalizeMessageToBytes(message, mode = "text") {
  if (Array.isArray(message)) return message.map(b => b & 0xff);
  if (mode === "hex") return hexToBytes(message);
  return textToBytes(message);
}

function randomByte() {
  try {
    const b = new Uint8Array(1);
    crypto.getRandomValues(b);
    return b[0];
  } catch {
    return Math.floor(Math.random() * 256) & 0xff;
  }
}

export function randomHex(bytes = 8) {
  const out = [];
  for (let i = 0; i < bytes; i++) out.push(randomByte());
  return bytesToHexLocal(out);
}

function xorByteArrays(a, b) {
  const len = Math.max(a.length, b.length);
  const out = [];
  for (let i = 0; i < len; i++) out.push((a[i] || 0) ^ (b[i] || 0));
  return out;
}

function truncateMiddle(s, keep = 24) {
  s = String(s ?? "");
  if (s.length <= keep * 2 + 1) return s;
  return `${s.slice(0, keep)}…${s.slice(-keep)}`;
}
export { truncateMiddle };

// ── PA#8 hash wrappers ──────────────────────────────────────────────────────

/** DLP_Hash(bytes) -> digest hex using PA#8's DLP compression plugged into PA#7. */
export function dlpHashBytes(bytes, params = HMAC_HASH_PARAMS) {
  return dlpHash(bytes.map(b => b & 0xff), params).padStart(HMAC_DIGEST_BYTES * 2, "0").slice(-HMAC_DIGEST_BYTES * 2);
}

/** Hash a long key down to HMAC block length using PA#8 DLP_Hash. */
export function normalizeHmacKey(keyHex, blockBytes = HMAC_BLOCK_BYTES, params = HMAC_HASH_PARAMS) {
  let keyBytes = hexToBytes(keyHex);
  const originalLength = keyBytes.length;
  let wasHashed = false;

  if (keyBytes.length > blockBytes) {
    keyBytes = hexToBytes(dlpHashBytes(keyBytes, params));
    wasHashed = true;
  }
  while (keyBytes.length < blockBytes) keyBytes.push(0x00);
  keyBytes = keyBytes.slice(0, blockBytes);

  return {
    keyBytes,
    keyHex: bytesToHexLocal(keyBytes),
    originalLength,
    wasHashed,
  };
}

// ── HMAC construction ───────────────────────────────────────────────────────

/**
 * HMAC_k(m) = H((k ⊕ opad) || H((k ⊕ ipad) || m)).
 * H is PA#8 DLP_Hash. keyHex is hex; message is text by default.
 */
export function hmacDlp(keyHex, message, mode = "text", params = HMAC_HASH_PARAMS) {
  const msgBytes = normalizeMessageToBytes(message, mode);
  const keyInfo = normalizeHmacKey(keyHex, HMAC_BLOCK_BYTES, params);
  const ipad = Array(HMAC_BLOCK_BYTES).fill(0x36);
  const opad = Array(HMAC_BLOCK_BYTES).fill(0x5c);

  const innerKey = xorByteArrays(keyInfo.keyBytes, ipad);
  const outerKey = xorByteArrays(keyInfo.keyBytes, opad);

  const innerInput = [...innerKey, ...msgBytes];
  const innerHash = dlpHashBytes(innerInput, params);
  const innerHashBytes = hexToBytes(innerHash);

  const outerInput = [...outerKey, ...innerHashBytes];
  const tag = dlpHashBytes(outerInput, params);

  return {
    tag,
    keyHex: keyInfo.keyHex,
    keyWasHashed: keyInfo.wasHashed,
    normalizedKeyBytes: keyInfo.keyBytes,
    ipadHex: bytesToHexLocal(ipad),
    opadHex: bytesToHexLocal(opad),
    innerKeyHex: bytesToHexLocal(innerKey),
    outerKeyHex: bytesToHexLocal(outerKey),
    innerInputHex: bytesToHexLocal(innerInput),
    innerHash,
    outerInputHex: bytesToHexLocal(outerInput),
    messageHex: bytesToHexLocal(msgBytes),
  };
}

/** Constant-time comparison for hex tags. Length mismatch is folded into diff. */
export function constantTimeEqualHex(aHex, bHex) {
  const a = hexToBytes(aHex);
  const b = hexToBytes(bHex);
  const maxLen = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < maxLen; i++) diff |= (a[i] || 0) ^ (b[i] || 0);
  return diff === 0;
}

/** Deliberately leaky comparison for the timing demo. */
export function naiveEqualHex(aHex, bHex) {
  const a = cleanHex(aHex);
  const b = cleanHex(bHex);
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function hmacVerify(keyHex, message, tagHex, mode = "text", params = HMAC_HASH_PARAMS) {
  const expected = hmacDlp(keyHex, message, mode, params);
  return {
    valid: constantTimeEqualHex(expected.tag, tagHex),
    expectedTag: expected.tag,
    suppliedTag: cleanHex(tagHex),
    details: expected,
  };
}

// ── 1. CRHF ⇒ MAC: EUF-CMA HMAC demo ────────────────────────────────────────

export function generateHmacSignedPairs(keyHex, count = 20, params = HMAC_HASH_PARAMS) {
  const pairs = [];
  const n = Math.max(1, Math.min(Number.parseInt(count, 10) || 20, 100));
  for (let i = 0; i < n; i++) {
    const msg = `oracle-msg-${i}-${randomHex(2)}`;
    const tag = hmacDlp(keyHex, msg, "text", params).tag;
    pairs.push({ msg, tag });
  }
  return pairs;
}

export function attemptHmacForgery(keyHex, pairs, forgedMsg, forgedTag, params = HMAC_HASH_PARAMS) {
  const seen = new Set((pairs || []).map(p => p.msg));
  const verify = hmacVerify(keyHex, forgedMsg, forgedTag, "text", params);
  const isNewMessage = !seen.has(forgedMsg);
  return {
    accepted: verify.valid && isNewMessage,
    tagValid: verify.valid,
    isNewMessage,
    expectedTag: verify.expectedTag,
    reason: verify.valid
      ? (isNewMessage ? "Forgery accepted: new message with valid tag." : "Replay only: tag is valid but message was already signed.")
      : "Forgery rejected: constant-time HMAC verification failed.",
  };
}

export function runHmacEufCmaGame(keyHex, queryCount = 50, attempts = 20, params = HMAC_HASH_PARAMS) {
  const pairs = generateHmacSignedPairs(keyHex, queryCount, params);
  let successes = 0;
  const logs = [];
  const signed = new Set(pairs.map(p => p.msg));

  for (let i = 0; i < attempts; i++) {
    const msg = `forgery-target-${i}-${randomHex(2)}`;
    // A naive adversary guesses a fresh 32-bit tag.
    let guessedTag = randomHex(HMAC_DIGEST_BYTES);
    if (signed.has(msg)) guessedTag = pairs[0].tag;
    const res = attemptHmacForgery(keyHex, pairs, msg, guessedTag, params);
    if (res.accepted) successes++;
    if (i < 6) logs.push({ i, msg, guessedTag, expectedTag: res.expectedTag, accepted: res.accepted });
  }

  return {
    queryCount: pairs.length,
    attempts,
    successes,
    successRate: attempts ? successes / attempts : 0,
    samplePairs: pairs.slice(0, 6),
    logs,
  };
}

// ── 2. MAC ⇒ CRHF: use HMAC as an MD compression function ───────────────────

/**
 * Fixed-key HMAC compression function: Compress(z, M_i) = HMAC_k(z || M_i)
 * truncated to 32 bits, so it matches the PA#7 chaining-value width.
 */
export function makeHmacCompressionFn(keyHex, params = HMAC_HASH_PARAMS) {
  return function hmacCompress(zHex, blockBytes) {
    const inputBytes = [...hexToBytes(zHex.padStart(8, "0").slice(-8)), ...blockBytes.map(b => b & 0xff)];
    return hmacDlp(keyHex, inputBytes, "bytes", params).tag.slice(-8).padStart(8, "0");
  };
}

export function hmacMdHash(message, keyHex, mode = "text", params = HMAC_HASH_PARAMS) {
  const bytes = normalizeMessageToBytes(message, mode);
  const padded = mdPad(bytes);
  const blocks = parseBlocks(padded);
  const compress = makeHmacCompressionFn(keyHex, params);
  const chain = [IV];
  let z = IV;
  const steps = [];
  for (let i = 0; i < blocks.length; i++) {
    const input = `${z}${bytesToHexLocal(blocks[i])}`;
    const out = compress(z, blocks[i]);
    steps.push({ i, zIn: z, blockHex: bytesToHexLocal(blocks[i]), compressionInputHex: input, zOut: out });
    z = out;
    chain.push(z);
  }
  return {
    digest: z,
    blocks: blocks.map(bytesToHexLocal),
    chain,
    steps,
    paddedHex: bytesToHexLocal(padded),
  };
}

export function macToCrhfDemo(keyHex, msgA, msgB, params = HMAC_HASH_PARAMS) {
  const hA = hmacMdHash(msgA, keyHex, "text", params);
  const hB = hmacMdHash(msgB, keyHex, "text", params);
  return {
    msgA,
    msgB,
    digestA: hA.digest,
    digestB: hB.digest,
    distinct: hA.digest !== hB.digest,
    chainA: hA.chain,
    chainB: hB.chain,
    stepsA: hA.steps,
    explanation: "Fixing k and using HMAC_k as the compression function gives a Merkle-Damgård-style hash. A collision in this derived hash would give a collision/forgery against the fixed-key MAC compression step.",
  };
}

// ── 3. Length-extension attack demo ─────────────────────────────────────────

function gluePaddingForLength(byteLen) {
  const pad = [0x80];
  while (((byteLen + pad.length + 8) % HMAC_BLOCK_BYTES) !== 0) pad.push(0x00);

  const bitLen = byteLen * 8;
  const hi = Math.floor(bitLen / 0x100000000);
  const lo = bitLen >>> 0;
  pad.push(
    (hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff,
    (lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff,
  );
  return pad;
}

function dlpMdHashFromState(stateHex, bytesToProcess, priorBytesProcessed, params = HMAC_HASH_PARAMS) {
  // The attacker resumes from the public state and must append padding based on
  // the total length of the hidden-prefix message after appending the suffix.
  const finalPad = gluePaddingForLength(priorBytesProcessed + bytesToProcess.length);
  const stream = [...bytesToProcess, ...finalPad];
  const blocks = parseBlocks(stream);
  const bridge = makeDLPCompressFn(params);
  let z = stateHex.padStart(8, "0").slice(-8);
  const chain = [z];
  const steps = [];
  for (let i = 0; i < blocks.length; i++) {
    const out = bridge(z, blocks[i]);
    steps.push({ i, zIn: z, blockHex: bytesToHexLocal(blocks[i]), zOut: out });
    z = out;
    chain.push(z);
  }
  return { digest: z, finalPad, blocks: blocks.map(bytesToHexLocal), chain, steps };
}

export function naivePrefixMac(keyHex, msg, params = HMAC_HASH_PARAMS) {
  const keyBytes = hexToBytes(keyHex);
  const msgBytes = normalizeMessageToBytes(msg, "text");
  return dlpHashBytes([...keyBytes, ...msgBytes], params);
}

export function lengthExtensionAttackDemo(keyHex, message, suffix, guessedKeyBytes = null, params = HMAC_HASH_PARAMS) {
  const keyBytes = hexToBytes(keyHex);
  const msgBytes = normalizeMessageToBytes(message, "text");
  const suffixBytes = normalizeMessageToBytes(suffix, "text");
  const keyLenGuess = guessedKeyBytes === null || guessedKeyBytes === undefined
    ? keyBytes.length
    : Math.max(0, Number.parseInt(guessedKeyBytes, 10) || 0);

  // Victim's vulnerable tag: H(k || m). Attacker sees only this digest.
  const originalNaiveTag = naivePrefixMac(keyHex, message, params);

  // Attacker computes glue padding for guessed hidden-prefix length |k| + |m|.
  const guessedOriginalLen = keyLenGuess + msgBytes.length;
  const gluePad = gluePaddingForLength(guessedOriginalLen);
  const forgedPublicMsgBytes = [...msgBytes, ...gluePad, ...suffixBytes];

  // Resume DLP-MD from state originalNaiveTag over suffix || final_pad.
  const priorProcessed = guessedOriginalLen + gluePad.length;
  const extension = dlpMdHashFromState(originalNaiveTag, suffixBytes, priorProcessed, params);
  const attackerForgedTag = extension.digest;

  // Server checks H(k || forgedPublicMsg). This should match if key length guessed.
  const serverNaiveTag = dlpHashBytes([...keyBytes, ...forgedPublicMsgBytes], params);
  const naiveAttackWorks = constantTimeEqualHex(attackerForgedTag, serverNaiveTag);

  // HMAC cannot be resumed this way: the visible tag is an outer hash output, not
  // the inner chaining state under k ⊕ ipad.
  const originalHmac = hmacDlp(keyHex, message, "text", params).tag;
  const attackerHmacAttempt = dlpMdHashFromState(originalHmac, suffixBytes, priorProcessed, params).digest;
  const realHmacOnForgedMsg = hmacDlp(keyHex, forgedPublicMsgBytes, "bytes", params).tag;
  const hmacAttackWorks = constantTimeEqualHex(attackerHmacAttempt, realHmacOnForgedMsg);

  return {
    keyLenActual: keyBytes.length,
    keyLenGuess,
    message,
    suffix,
    originalNaiveTag,
    gluePadHex: bytesToHexLocal(gluePad),
    forgedPublicMessageHex: bytesToHexLocal(forgedPublicMsgBytes),
    forgedPublicMessagePreview: `${message} || pad || ${suffix}`,
    attackerForgedTag,
    serverNaiveTag,
    naiveAttackWorks,
    originalHmac,
    attackerHmacAttempt,
    realHmacOnForgedMsg,
    hmacAttackWorks,
    extensionSteps: extension.steps,
  };
}

// ── 4. Encrypt-then-HMAC CCA-secure encryption ──────────────────────────────

function ceToBytes(CE) {
  return textToBytes(String(CE));
}

export function hmacCcaEnc(kEHex, kMHex, msgHex, prfType = "GGM", params = HMAC_HASH_PARAMS) {
  const enc = encCPA(kEHex, cleanHex(msgHex), prfType, false);
  const CE = enc.ciphertext; // PA#3 format: r:c
  const tag = hmacDlp(kMHex, ceToBytes(CE), "bytes", params).tag;
  return {
    CE,
    tag,
    r: enc.r,
    c: enc.c,
    blocks: enc.blocks,
    macInputHex: bytesToHexLocal(ceToBytes(CE)),
  };
}

export function hmacCcaDec(kEHex, kMHex, CE, tagHex, prfType = "GGM", params = HMAC_HASH_PARAMS) {
  const expected = hmacDlp(kMHex, ceToBytes(CE), "bytes", params).tag;
  const valid = constantTimeEqualHex(expected, tagHex);
  if (!valid) {
    return {
      accepted: false,
      plaintext: null,
      expectedTag: expected,
      suppliedTag: cleanHex(tagHex),
      reason: "⊥ — constant-time HMAC verification failed; reject before decrypting.",
    };
  }

  const parts = String(CE).split(":");
  if (parts.length !== 2) {
    return { accepted: false, plaintext: null, expectedTag: expected, suppliedTag: cleanHex(tagHex), reason: "⊥ — malformed ciphertext; expected r:c." };
  }

  const dec = decCPA(kEHex, parts[0], parts[1], prfType);
  return {
    accepted: true,
    plaintext: dec.msgHex,
    expectedTag: expected,
    suppliedTag: cleanHex(tagHex),
    reason: "✓ HMAC tag valid; decrypted after authentication.",
    blocks: dec.blocks,
  };
}

export function tamperCiphertextHex(cHex, bitIndex = 0) {
  const h = cleanHex(cHex);
  if (!h.length) return h;
  const idx = Math.max(0, Math.min(Math.floor(bitIndex / 4), h.length - 1));
  const bitWithin = 3 - (Math.max(0, bitIndex) % 4);
  const chars = h.split("");
  const nibble = Number.parseInt(chars[idx], 16) || 0;
  chars[idx] = ((nibble ^ (1 << bitWithin)) & 0xf).toString(16);
  return chars.join("");
}

export function hmacMalleabilityDemo(kEHex, kMHex, msgHex, bitToFlip = 0, prfType = "GGM", params = HMAC_HASH_PARAMS) {
  const enc = hmacCcaEnc(kEHex, kMHex, msgHex, prfType, params);
  const tamperedC = tamperCiphertextHex(enc.c, bitToFlip);
  const tamperedCE = `${enc.r}:${tamperedC}`;

  // CPA-only path: decrypts blindly and therefore accepts bit flipping.
  const cpaDec = decCPA(kEHex, enc.r, tamperedC, prfType);

  // CCA path: HMAC verification rejects the same tampering before decryption.
  const hmacDec = hmacCcaDec(kEHex, kMHex, tamperedCE, enc.tag, prfType, params);

  return {
    originalMsgHex: cleanHex(msgHex),
    CE: enc.CE,
    tag: enc.tag,
    r: enc.r,
    c: enc.c,
    tamperedC,
    tamperedCE,
    cpaPlaintext: cpaDec.msgHex,
    cpaAccepted: true,
    hmacAccepted: hmacDec.accepted,
    hmacReason: hmacDec.reason,
  };
}

export function runHmacCca2Game(kEHex, kMHex, m0Hex, m1Hex, rounds = 50, prfType = "GGM", params = HMAC_HASH_PARAMS) {
  const m0 = cleanHex(m0Hex);
  const m1 = cleanHex(m1Hex);
  if (m0.length !== m1.length) return { error: "m₀ and m₁ must have equal hex length" };

  const n = Math.max(1, Math.min(Number.parseInt(rounds, 10) || 50, 200));
  let correct = 0;
  const log = [];

  for (let i = 0; i < n; i++) {
    const b = Math.random() < 0.5 ? 0 : 1;
    const challenge = hmacCcaEnc(kEHex, kMHex, b === 0 ? m0 : m1, prfType, params);

    // Adversary tests decryption oracle on a tampered challenge; HMAC rejects.
    const tamperedC = tamperCiphertextHex(challenge.c, i % Math.max(1, challenge.c.length * 4));
    const tamperedCE = `${challenge.r}:${tamperedC}`;
    const tamperedDec = hmacCcaDec(kEHex, kMHex, tamperedCE, challenge.tag, prfType, params);

    // No useful oracle information remains, so the dummy adversary guesses randomly.
    const guess = Math.random() < 0.5 ? 0 : 1;
    if (guess === b) correct++;
    if (i < 6) log.push({ i, b, guess, win: guess === b, challengeCE: challenge.CE, tag: challenge.tag, tamperedAccepted: tamperedDec.accepted });
  }

  return {
    rounds: n,
    correct,
    advantage: Math.abs(correct / n - 0.5) * 2,
    log,
  };
}

// ── 5. Constant-time comparison demonstration ───────────────────────────────

export function comparisonTimingDemo(tagHex) {
  const tag = cleanHex(tagHex).padEnd(8, "0").slice(0, 8);
  const candidates = [
    { label: "0 matching hex chars", candidate: `f${tag.slice(1)}` },
    { label: "2 matching hex chars", candidate: `${tag.slice(0, 2)}f${tag.slice(3)}` },
    { label: "4 matching hex chars", candidate: `${tag.slice(0, 4)}f${tag.slice(5)}` },
    { label: "full tag", candidate: tag },
  ];

  return candidates.map(row => {
    let naiveChecks = 0;
    const a = tag;
    const b = row.candidate;
    if (a.length !== b.length) naiveChecks = 0;
    else {
      for (let i = 0; i < a.length; i++) {
        naiveChecks++;
        if (a[i] !== b[i]) break;
      }
    }
    const ctByteChecks = Math.max(hexToBytes(a).length, hexToBytes(b).length);
    return {
      ...row,
      naiveEqual: naiveEqualHex(a, b),
      constantTimeEqual: constantTimeEqualHex(a, b),
      naiveChecks,
      constantTimeChecks: ctByteChecks,
    };
  });
}

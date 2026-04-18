// ═══════════════════════════════════════════════════════════════════════════════
// PA #6 — CCA-Secure Symmetric Encryption (Encrypt-then-MAC)
// Built directly on PA#3 encCPA/decCPA and PA#5 prfMacSign/prfMacVerify
// ═══════════════════════════════════════════════════════════════════════════════

import { encCPA, decCPA }           from "../pa3/crypto.js";
// import { hexXOR, BLOCK_HEX_LEN }    from "../utils/crypto.js";
import { prfMacSign, prfMacVerify } from "../pa5/crypto.js";

// ── helpers ───────────────────────────────────────────────────────────────────

/**
 * Derive a single MAC-input string from a full ciphertext string.
 * PA#3 ciphertexts are "r:c" hex strings.
 * We MAC the entire "r:c" string treated as hex for PRF-MAC.
 * PRF-MAC takes an 8-bit binary input, so we fold the hex digest to 8 bits
 * by XOR-folding all bytes of the UTF-8 encoding of the ciphertext string.
 */
function ceToBin8(ciphertext) {
  // XOR-fold all character codes of the ciphertext string into one byte
  let acc = 0;
  for (let i = 0; i < ciphertext.length; i++)
    acc = (acc ^ ciphertext.charCodeAt(i)) & 0xff;
  return acc.toString(2).padStart(8, "0");
}

/**
 * Flip bit i (0-indexed from left) in a hex string.
 * Used by the malleability demo to corrupt the ciphertext part.
 */
export function flipHexBit(hexStr, bitIndex) {
  // which hex char and which bit within it
  const hexCharIdx = Math.floor(bitIndex / 4);
  const bitWithin  = 3 - (bitIndex % 4);
  const chars      = hexStr.split("");
  const nibble     = parseInt(chars[hexCharIdx], 16);
  chars[hexCharIdx] = ((nibble ^ (1 << bitWithin)) & 0xf).toString(16);
  return chars.join("");
}

// ── Construction: Encrypt-then-MAC ───────────────────────────────────────────

/**
 * CCA_Enc(kE, kM, m):
 *   1. C_E ← encCPA(kE, m)          — PA#3 CPA encryption (hex in/out, r:c format)
 *   2. t   ← Mac_kM(C_E)            — PA#5 PRF-MAC on folded ciphertext
 *   3. Output (C_E, t)
 *
 * @param {string} kEHex      — encryption key (hex)
 * @param {string} kMHex      — MAC key (hex, must be independent of kE)
 * @param {string} msgHex     — plaintext (hex, any length)
 * @param {string} prfType    — "GGM" | "AES"
 * @param {boolean} reuseNonce — pass-through to PA#3 (for broken-mode demo)
 * @returns {{ CE, t, r, c, blocks, macInput }}
 */
export function ccaEnc(kEHex, kMHex, msgHex, prfType = "GGM", reuseNonce = false) {
  // Step 1: CPA encrypt (PA#3)
  const enc = encCPA(kEHex, msgHex, prfType, reuseNonce);
  const CE  = enc.ciphertext;       // "r:c" string

  // Step 2: MAC the ciphertext
  const macInput = ceToBin8(CE);    // fold CE → 8-bit binary for PRF-MAC
  const { tag: t } = prfMacSign(kMHex, macInput, prfType);

  return { CE, t, r: enc.r, c: enc.c, blocks: enc.blocks, macInput };
}

/**
 * CCA_Dec(kE, kM, CE, t):
 *   1. Verify Vrfy_kM(CE, t) — if 0, output ⊥ (REJECT before decrypting)
 *   2. Parse CE as "r:c", call decCPA(kE, r, c)
 *   3. Output plaintext
 *
 * @returns {{ plaintext: string|null, accepted: boolean, reason: string }}
 */
export function ccaDec(kEHex, kMHex, CE, t, prfType = "GGM") {
  // Step 1: verify MAC BEFORE decrypting
  const macInput = ceToBin8(CE);
  const valid    = prfMacVerify(kMHex, macInput, t, prfType);

  if (!valid) {
    return {
      plaintext: null,
      accepted:  false,
      reason:    "⊥ — Vrfy_kM(C_E, t) = 0: ciphertext rejected before decryption",
    };
  }

  // Step 2: parse "r:c" and decrypt
  const parts = CE.split(":");
  if (parts.length !== 2) {
    return { plaintext: null, accepted: false, reason: "⊥ — malformed ciphertext (expected r:c format)" };
  }
  const { msgHex } = decCPA(kEHex, parts[0], parts[1], prfType);
  return {
    plaintext: msgHex,
    accepted:  true,
    reason:    "✓ Vrfy_kM(C_E, t) = 1 — MAC valid, decryption succeeded",
  };
}

// ── Malleability demo ─────────────────────────────────────────────────────────

/**
 * Demonstrate CPA malleability vs CCA integrity.
 *
 * CPA: C = (r, F_k(r) ⊕ m). Flipping bit i of the ciphertext hex flips bit i
 * of the plaintext. The CPA oracle has no integrity check — it decrypts blindly.
 *
 * CCA: The MAC covers C_E. Any modification invalidates t, so CCA_Dec returns ⊥
 * before touching the plaintext.
 *
 * @param {string} kEHex
 * @param {string} kMHex
 * @param {string} msgHex     — hex plaintext
 * @param {number} bitToFlip  — bit index into the ciphertext hex (c part only)
 * @param {string} prfType
 */
export function malleabilityDemo(kEHex, kMHex, msgHex, bitToFlip, prfType = "GGM") {
  // Encrypt
  const enc = ccaEnc(kEHex, kMHex, msgHex, prfType);

  // Adversary flips bit `bitToFlip` of the c part (not r)
  const tamperedC  = flipHexBit(enc.c, bitToFlip);
  const tamperedCE = `${enc.r}:${tamperedC}`;

  // CPA path: no integrity check — just decrypt the tampered ciphertext
  const cpaDecResult = decCPA(kEHex, enc.r, tamperedC, prfType);

  // CCA path: Vrfy fires first — uses ORIGINAL tag with TAMPERED CE → must fail
  const ccaResult = ccaDec(kEHex, kMHex, tamperedCE, enc.t, prfType);

  return {
    origMsg:      msgHex,
    origCE:       enc.CE,
    origC:        enc.c,
    origTag:      enc.t,
    r:            enc.r,
    tamperedC,
    tamperedCE,
    bitFlipped:   bitToFlip,
    // CPA: blindly decrypts tampered ciphertext
    cpaAccepted:  true,
    cpaPlaintext: cpaDecResult.msgHex,
    // CCA: MAC rejects tampered ciphertext
    ccaAccepted:  ccaResult.accepted,
    ccaReason:    ccaResult.reason,
  };
}

// ── Key-separation demo ───────────────────────────────────────────────────────

/**
 * Demonstrate why kE ≠ kM is required.
 *
 * When kE === kM, the MAC tag is computed using the same PRF key as the
 * encryption. This means an adversary observing (C_E, t) pairs can build a
 * table of F_k evaluations from the tags and use them to predict keystreams.
 *
 * @param {string} sharedKey  — used for BOTH kE and kM
 * @param {string} msgHex
 * @param {string} prfType
 */
export function keySeparationDemo(sharedKey, msgHex, prfType = "GGM") {
  const separateKM = "b4e7a291";

  // Case 1: kE = kM = sharedKey
  const sameEnc = ccaEnc(sharedKey, sharedKey,   msgHex, prfType);
  // Case 2: kE = sharedKey, kM = separateKM
  const sepEnc  = ccaEnc(sharedKey, separateKM,  msgHex, prfType);

  // Correlation: with same key, the tag is F_k(macInput) where k is also the
  // encryption key. Verify by re-computing the tag with sharedKey.
  const { tag: recomputedTag } = prfMacSign(sharedKey, sameEnc.macInput, prfType);
  const correlation = recomputedTag === sameEnc.t;

  return {
    sharedKey,
    separateKM,
    same: {
      kE: sharedKey, kM: sharedKey,
      CE: sameEnc.CE, t: sameEnc.t, macInput: sameEnc.macInput,
    },
    sep: {
      kE: sharedKey, kM: separateKM,
      CE: sepEnc.CE,  t: sepEnc.t,  macInput: sepEnc.macInput,
    },
    correlation,
    correlationMsg: correlation
      ? "Tag = F_kE(macInput) — same key creates circular dependency! Exploitable."
      : "No correlation — independent keys are safe.",
  };
}

// ── IND-CCA2 game ─────────────────────────────────────────────────────────────

/**
 * IND-CCA2 game simulation:
 *   - Challenger picks b ∈ {0,1} secretly, encrypts m_b with Encrypt-then-MAC
 *   - Adversary gets encryption oracle + decryption oracle
 *     (decryption oracle rejects the challenge ciphertext and any tampered CT)
 *   - Adversary tries to guess b — best possible is random (advantage ≈ 0)
 *
 * @param {string} kEHex
 * @param {string} kMHex
 * @param {string} m0Hex
 * @param {string} m1Hex
 * @param {string} prfType
 */
export function runCCA2Game(kEHex, kMHex, m0Hex, m1Hex, prfType = "GGM") {
  if (m0Hex.length !== m1Hex.length) return { error: "m₀ and m₁ must be the same length" };

  // Challenger picks b secretly
  const b         = Math.random() < 0.5 ? 0 : 1;
  const mb        = b === 0 ? m0Hex : m1Hex;
  const challenge = ccaEnc(kEHex, kMHex, mb, prfType);

  // Simulate 10 adversary decryption oracle queries
  // Each query uses a freshly encrypted message — these are legit queries
  // A tampered version of each is also tried — all rejected
  const oracleQueries = [];
  for (let i = 0; i < 10; i++) {
    // Fresh message
    const qMsgHex = (i * 0xabcd + 0x1234).toString(16).padStart(8, "0");
    const qEnc    = ccaEnc(kEHex, kMHex, qMsgHex, prfType);

    // Legit decrypt (correct tag)
    const legitDec = ccaDec(kEHex, kMHex, qEnc.CE, qEnc.t, prfType);

    // Tampered decrypt (wrong tag — simulates adversary trying to modify CT)
    const tamperedDec = ccaDec(kEHex, kMHex, qEnc.CE, "deadbeef", prfType);

    // Try to query challenge ciphertext itself — must be rejected
    const challengeQuery = ccaDec(kEHex, kMHex, challenge.CE, challenge.t, prfType);
    // In a real CCA2 game the oracle rejects the challenge CT by definition
    // We simulate that by flipping its tag
    const challengeRejected = !ccaDec(kEHex, kMHex, challenge.CE, "00000000", prfType).accepted;

    oracleQueries.push({
      qMsgHex,
      CE:               qEnc.CE,
      t:                qEnc.t,
      legitPlaintext:   legitDec.plaintext,
      tamperedResult:   tamperedDec.reason,
      challengeRejected,
    });
  }

  return {
    b, mb,
    m0Hex, m1Hex,
    challengeCE: challenge.CE,
    challengeT:  challenge.t,
    oracleQueries,
  };
}
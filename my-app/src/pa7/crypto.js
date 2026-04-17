// ═══════════════════════════════════════════════════════════════════════════════
// PA #7 — Merkle-Damgård crypto helpers
// Block size: 8 bytes  |  IV: 0x00000000  |  Compression: XOR-fold toy
// ═══════════════════════════════════════════════════════════════════════════════

const BLOCK = 8;
export const IV = "00000000";

// ── Encoding helpers ──────────────────────────────────────────────────────────

/** Convert a string or "0x…" hex literal to a Uint8 byte array */
export function strToBytes(s) {
  if (s.startsWith("0x") || s.startsWith("0X")) {
    const h = s.slice(2).replace(/[^0-9a-fA-F]/g, "");
    return Array.from({ length: Math.ceil(h.length / 2) }, (_, i) =>
      parseInt(h.slice(i * 2, i * 2 + 2) || "00", 16)
    );
  }
  return Array.from(new TextEncoder().encode(s));
}

/** Byte array → lowercase hex string */
export function bytesToHex(arr) {
  return arr.map(b => b.toString(16).padStart(2, "0")).join("");
}

// ── MD-strengthening padding ──────────────────────────────────────────────────

/**
 * Append 0x80, then zero-pad so that (length + 8) ≡ 0 (mod BLOCK),
 * then append original bit-length as 8-byte big-endian integer.
 * Matches the spec: block size 8 bytes, 64-bit length field.
 */
export function mdPad(bytes) {
  const msg = [...bytes];
  const origBitLen = msg.length * 8;

  msg.push(0x80);
  while ((msg.length + 8) % BLOCK !== 0) msg.push(0x00);

  // 64-bit big-endian length (JS safe up to 2^53 bits)
  const hi = Math.floor(origBitLen / 0x100000000);
  const lo = origBitLen >>> 0;
  msg.push(
    (hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff,
    (lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff,
  );
  return msg;
}

// ── Block parsing ─────────────────────────────────────────────────────────────

/** Split a padded byte array into BLOCK-sized chunks */
export function parseBlocks(padded) {
  const blocks = [];
  for (let i = 0; i < padded.length; i += BLOCK) blocks.push(padded.slice(i, i + BLOCK));
  return blocks;
}

// ── Toy compression function ──────────────────────────────────────────────────

/**
 * h(z, M): XOR-fold the 8-byte block into two 32-bit words, XOR with
 * current chaining value, then mix with a fixed constant.
 * Output: 8-char hex string (32-bit value, zero-padded).
 */
export function compress(zHex, blockBytes) {
  const z = (parseInt(zHex, 16) || 0) >>> 0;
  // Fold block into two 32-bit words and XOR them together
  const w0 = (((blockBytes[0] || 0) << 24) | ((blockBytes[1] || 0) << 16) |
               ((blockBytes[2] || 0) << 8)  |  (blockBytes[3] || 0)) >>> 0;
  const w1 = (((blockBytes[4] || 0) << 24) | ((blockBytes[5] || 0) << 16) |
               ((blockBytes[6] || 0) << 8)  |  (blockBytes[7] || 0)) >>> 0;
  return (((z ^ w0 ^ w1 ^ 0xDEAD1234) >>> 0)).toString(16).padStart(8, "0");
}

// ── Chain builder ─────────────────────────────────────────────────────────────

/**
 * Compute full MD chain: [z₀=IV, z₁, …, zₗ=H(M)]
 * Returns an array of hex strings, length = blocks.length + 1.
 */
export function buildChain(blocks) {
  const zs = [IV];
  for (const b of blocks) zs.push(compress(zs[zs.length - 1], b));
  return zs;
}

// ── Public hash interface (for PA#8 plug-in) ──────────────────────────────────

/**
 * hash(message, compression_fn) → digest hex string
 *
 * `message` may be a string, "0x…" hex literal, or byte array.
 * `compression_fn` defaults to the toy XOR compress above; PA#8 passes its DLP
 * compression function here directly.
 *
 * PA#8 interface contract:
 *   compression_fn(zHex: string, blockBytes: number[]) → string (8-char hex)
 */
export function hash(message, compression_fn = compress) {
  const bytes  = Array.isArray(message) ? message : strToBytes(message);
  const padded = mdPad(bytes);
  const blocks = parseBlocks(padded);
  let z = IV;
  for (const b of blocks) z = compression_fn(z, b);
  return z;
}
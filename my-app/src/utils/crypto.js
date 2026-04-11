// ═══════════════════════════════════════════════════════════════════════════════
// Shared toy-crypto utilities — used by all PAs
// ═══════════════════════════════════════════════════════════════════════════════

export function lcg(seed) { return ((seed * 1664525 + 1013904223) & 0xffffffff) >>> 0; }

export function fakeHex(seed, bytes = 8) {
  let s = seed >>> 0, out = "";
  for (let i = 0; i < bytes; i++) { s = lcg(s); out += ((s >>> 24) & 0xff).toString(16).padStart(2, "0"); }
  return out;
}

export function seedFromHex(hex) {
  const clean = (hex || "").replace(/[^0-9a-fA-F]/g, "").padEnd(8, "0");
  return parseInt(clean.slice(0, 8), 16) || 0xdeadbeef;
}

export function freshRandom() {
  try { const a = new Uint32Array(1); crypto.getRandomValues(a); return a[0].toString(16).padStart(8, "0"); }
  catch { return fakeHex((Date.now() ^ (Math.random() * 0xffffffff)) >>> 0, 8); }
}

export function hexXOR(a, b) {
  const len = Math.max(a.length, b.length);
  const pa = a.padEnd(len, "0"), pb = b.padEnd(len, "0");
  let out = "";
  for (let i = 0; i < len; i += 2)
    out += ((parseInt(pa.slice(i, i + 2), 16) || 0) ^ (parseInt(pb.slice(i, i + 2), 16) || 0)).toString(16).padStart(2, "0");
  return out;
}

export const BLOCK_HEX_LEN = 16; // 8 bytes per block

export function padHex(msgHex, blockHexLen = BLOCK_HEX_LEN) {
  const h = msgHex.length % 2 === 0 ? msgHex : msgHex + "0";
  const msgBytes = h.length / 2, blockBytes = blockHexLen / 2;
  const padLen = blockBytes - (msgBytes % blockBytes);
  const padByte = padLen.toString(16).padStart(2, "0");
  return h + padByte.repeat(padLen);
}

export function unpadHex(paddedHex) {
  if (!paddedHex || paddedHex.length < 2) return paddedHex;
  const padLen = parseInt(paddedHex.slice(-2), 16);
  if (padLen < 1 || padLen * 2 > paddedHex.length) return paddedHex;
  const padByte = paddedHex.slice(-2);
  for (let i = 0; i < padLen; i++) {
    if (paddedHex.slice(paddedHex.length - 2 - i * 2, paddedHex.length - i * 2) !== padByte) return paddedHex;
  }
  return paddedHex.slice(0, paddedHex.length - padLen * 2);
}
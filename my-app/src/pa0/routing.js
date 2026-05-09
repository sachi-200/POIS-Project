// ═══════════════════════════════════════════════════════════════════════════════
// PA #0 — Routing table, foundations, column step builders
// ═══════════════════════════════════════════════════════════════════════════════

import { fakeHex, seedFromHex } from "../utils/crypto.js";

// export const REDUCTIONS = {
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

// export const MULTI_STEP_PATHS = {
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

export const REDUCTIONS = {
  // ── Foundational upward reductions ──────────────────────────────────────────
  "OWF→PRG":   { name: "HILL / hard-core-bit iteration",         pa: "PA#3",  security: "PRG-security from OWF hardness (HILL thm.)" },
  "OWF→OWP":   { name: "DLP: f(x) = gˣ mod p is a OWP on ℤ_q", pa: "PA#1",  security: "OWP hardness = DLP hardness" },
  "OWP→PRG":   { name: "OWP + hard-core predicate → PRG",        pa: "PA#3",  security: "G(x) = (f(x), b(x)) expands by 1 bit" },
  "PRG→PRF":   { name: "GGM tree construction",                  pa: "PA#3",  security: "PRF-adv ≤ O(n)·PRG-adv (GGM thm.)" },
  "PRF→PRP":   { name: "Luby-Rackoff 3-round Feistel",           pa: "PA#2",  security: "PRP-adv ≤ PRF-adv + q²/2ⁿ (LR thm.)" },
  "PRF→MAC":   { name: "MAC_k(m) = F_k(m)",                      pa: "PA#5",  security: "MAC-forgery ⟹ PRF-distinguisher" },
  "PRP→MAC":   { name: "PRP/PRF switching lemma, then MAC",       pa: "PA#5",  security: "PRP-adv ≈ PRF-adv (switching lemma)" },
  "CRHF→HMAC": { name: "HMAC construction (PA#10)",               pa: "PA#10", security: "HMAC secure if compression fn is PRF" },
  "HMAC→MAC":  { name: "HMAC is a secure EUF-CMA MAC",            pa: "PA#10", security: "Forgery breaks inner-hash PRF" },

  // ── Downward / reverse reductions ───────────────────────────────────────────
  "PRG→OWF":   { name: "Any PRG G is a OWF; f(s) = G(s)",        pa: "PA#3",  security: "Inversion of f recovers seed ⟹ breaks PRG" },
  "PRF→PRG":   { name: "G(s) = F_s(0) ‖ F_s(1)",                 pa: "PA#3",  security: "PRG-dist ⟹ PRF-dist (contrapositive)" },
  "PRP→PRF":   { name: "PRP/PRF switching lemma",                 pa: "PA#2",  security: "PRP over large domain ≈ PRF" },
  "MAC→PRF":   { name: "EUF-CMA MAC on uniform msgs is PRF",      pa: "PA#5",  security: "Unforgeability ⟹ pseudorandomness" },
  "MAC→CRHF":  { name: "Merkle-Damgård from MAC compression fn",  pa: "PA#7",  security: "Collision ⟹ MAC forgery" },
  "MAC→HMAC":  { name: "Cast MAC as HMAC inner compression step",  pa: "PA#10", security: "HMAC is the natural PRF-based MAC structure" },
  "HMAC→CRHF": { name: "Fix key k; H'(m) = HMAC_k(m) is CR",     pa: "PA#9",  security: "Collision = MAC forgery" },

  // ── NEW: missing edges ───────────────────────────────────────────────────────
  "OWP→OWF":   { name: "Any OWP is a OWF (permutation ⊆ function)", pa: "PA#1",  security: "OWP inversion ⟹ OWF inversion" },
  "PRF→OWF":   { name: "f(k) = F_k(0) is a OWF",                    pa: "PA#3",  security: "PRF inversion recovers key ⟹ PRF-distinguisher" },
  "PRP→OWF":   { name: "f(k) = E_k(0) is a OWF",                    pa: "PA#2",  security: "PRP inversion recovers key ⟹ PRP-distinguisher" },
  "HMAC→PRF":  { name: "HMAC with fixed key is a PRF",               pa: "PA#10", security: "HMAC pseudorandomness ⟹ PRF indistinguishability" },
  "MAC→OWF":   { name: "MAC→PRF→OWF; f(k) = MAC_k(0) is a OWF",    pa: "PA#5",  security: "MAC inversion recovers key ⟹ MAC forgery" },
};

export const MULTI_STEP_PATHS = {
  // ── OWF as source ───────────────────────────────────────────────────────────
  "OWF→PRF":  ["OWF→PRG", "PRG→PRF"],
  "OWF→PRP":  ["OWF→PRG", "PRG→PRF", "PRF→PRP"],
  "OWF→MAC":  ["OWF→PRG", "PRG→PRF", "PRF→MAC"],
  "OWF→HMAC": ["OWF→PRG", "PRG→PRF", "PRF→MAC", "MAC→HMAC"],
  "OWF→CRHF": ["OWF→PRG", "PRG→PRF", "PRF→MAC", "MAC→CRHF"],

  // ── OWP as source ───────────────────────────────────────────────────────────
  "OWP→PRF":  ["OWP→PRG", "PRG→PRF"],
  "OWP→PRP":  ["OWP→PRG", "PRG→PRF", "PRF→PRP"],
  "OWP→MAC":  ["OWP→PRG", "PRG→PRF", "PRF→MAC"],
  "OWP→HMAC": ["OWP→PRG", "PRG→PRF", "PRF→MAC", "MAC→HMAC"],
  "OWP→CRHF": ["OWP→PRG", "PRG→PRF", "PRF→MAC", "MAC→CRHF"],

  // ── PRG as source ───────────────────────────────────────────────────────────
  "PRG→PRP":  ["PRG→PRF", "PRF→PRP"],
  "PRG→MAC":  ["PRG→PRF", "PRF→MAC"],
  "PRG→HMAC": ["PRG→PRF", "PRF→MAC", "MAC→HMAC"],
  "PRG→CRHF": ["PRG→PRF", "PRF→MAC", "MAC→CRHF"],
  // "PRG→OWF":  // direct — already in REDUCTIONS

  // ── PRF as source ───────────────────────────────────────────────────────────
  "PRF→HMAC": ["PRF→MAC", "MAC→HMAC"],
  "PRF→CRHF": ["PRF→MAC", "MAC→CRHF"],
  // PRF→PRG and PRF→OWF are direct — already in REDUCTIONS

  // ── PRP as source ───────────────────────────────────────────────────────────
  "PRP→HMAC": ["PRP→MAC", "MAC→HMAC"],
  "PRP→CRHF": ["PRP→MAC", "MAC→CRHF"],
  "PRP→PRG":  ["PRP→PRF", "PRF→PRG"],
  // "PRP→OWF":  // direct — already in REDUCTIONS

  // ── MAC as source ───────────────────────────────────────────────────────────
  "MAC→PRG":  ["MAC→PRF", "PRF→PRG"],
  "MAC→PRP":  ["MAC→PRF", "PRF→PRP"],
  // "MAC→OWF":  // direct — already in REDUCTIONS

  // ── CRHF as source ──────────────────────────────────────────────────────────
  "CRHF→MAC": ["CRHF→HMAC", "HMAC→MAC"],
  "CRHF→PRF": ["CRHF→HMAC", "HMAC→PRF"],
  "CRHF→PRG": ["CRHF→HMAC", "HMAC→PRF", "PRF→PRG"],
  "CRHF→OWF": ["CRHF→HMAC", "HMAC→PRF", "PRF→OWF"],

  // ── HMAC as source ──────────────────────────────────────────────────────────
  "HMAC→PRG": ["HMAC→PRF", "PRF→PRG"],
  "HMAC→OWF": ["HMAC→PRF", "PRF→OWF"],
  "HMAC→PRP": ["HMAC→PRF", "PRF→PRP"],
  // HMAC→MAC, HMAC→CRHF, HMAC→PRF are direct — already in REDUCTIONS
};

export function getRoute(src, tgt) {
  if (src === tgt) return null;
  const d = `${src}→${tgt}`;
  if (REDUCTIONS[d] !== undefined) return [d];
  if (MULTI_STEP_PATHS[d]) return MULTI_STEP_PATHS[d];
  return null;
}

export const PA_COLORS = {
  "PA#1":  { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" },
  "PA#2":  { bg: "#EEEDFE", border: "#7F77DD", color: "#3C3489" },
  "PA#3":  { bg: "#E1F5EE", border: "#1D9E75", color: "#0F6E56" },
  "PA#4":  { bg: "#FEF3E2", border: "#E8A820", color: "#7A5200" },
  "PA#5":  { bg: "#FBEAF0", border: "#D4537E", color: "#72243E" },
  "PA#7":  { bg: "#FAEEDA", border: "#BA7517", color: "#854F0B" },
  "PA#9":  { bg: "#EAF3DE", border: "#639922", color: "#3B6D11" },
  "PA#10": { bg: "#FAECE7", border: "#D85A30", color: "#993C1D" },
};

export const COL1_TAG_COLORS = {
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

export const PRIMITIVES = ["OWF","OWP","PRG","PRF","PRP","MAC","CRHF","HMAC"];

export function makeAESFoundation(keyHex) {
  return { name: "AES-128 (PRP)", paTag: "AES-128", paNum: "PA#2", rawOut: fakeHex(seedFromHex(keyHex) ^ 0xaabb, 8) };
}
export function makeDLPFoundation(keyHex) {
  return { name: "DLP (gˣ mod p)", paTag: "DLP", paNum: "PA#1", rawOut: fakeHex(seedFromHex(keyHex) ^ 0x1337, 8) };
}

export function buildCol1Steps(src, foundation) {
  const { paTag, paNum, rawOut } = foundation, v0 = seedFromHex(rawOut);
  const steps = [{ tag: paTag, fn: paTag === "AES-128" ? "AES₁₂₈(key)" : "g^key mod p", inputHex: "key", outputHex: rawOut, pa: paNum, implemented: false }];
  if (src === "OWF" || src === "OWP") return steps;
  if (src === "PRG") { steps.push({ tag: "PRG", fn: "G(s) = F_s(0)‖F_s(1)", inputHex: rawOut, outputHex: fakeHex(v0^0x2222,16), pa: "PA#3", implemented: false }); }
  else if (src === "PRF") { const prg=fakeHex(v0^0x2222,16); steps.push({tag:"PRG",fn:"G(s)=F_s(0)‖F_s(1)",inputHex:rawOut,outputHex:prg,pa:"PA#3",implemented:false}); steps.push({tag:"GGM",fn:"GGM tree: F_k(b₁⋯bₙ)",inputHex:prg,outputHex:fakeHex(v0^0x3333,8),pa:"PA#3",implemented:false}); }
  else if (src === "PRP") { const prg=fakeHex(v0^0x2222,16),prf=fakeHex(v0^0x3333,8); steps.push({tag:"PRG",fn:"G(s)=F_s(0)‖F_s(1)",inputHex:rawOut,outputHex:prg,pa:"PA#3",implemented:false}); steps.push({tag:"GGM",fn:"GGM tree→PRF",inputHex:prg,outputHex:prf,pa:"PA#3",implemented:false}); steps.push({tag:"L-R",fn:"Luby-Rackoff 3-round Feistel→PRP",inputHex:prf,outputHex:fakeHex(v0^0x4444,8),pa:"PA#2",implemented:false}); }
  else if (src === "MAC") { const prg=fakeHex(v0^0x2222,16),prf=fakeHex(v0^0x3333,8); steps.push({tag:"PRG",fn:"G(s)=F_s(0)‖F_s(1)",inputHex:rawOut,outputHex:prg,pa:"PA#3",implemented:false}); steps.push({tag:"GGM",fn:"GGM tree→PRF",inputHex:prg,outputHex:prf,pa:"PA#3",implemented:false}); steps.push({tag:"MAC",fn:"MAC_k(m)=F_k(m)",inputHex:prf,outputHex:fakeHex(v0^0x5555,8),pa:"PA#5",implemented:false}); }
  else if (src === "CRHF") { const prf=fakeHex(v0^0x3333,8); steps.push({tag:"PRG→PRF",fn:"GGM tree(PRG→PRF)",inputHex:rawOut,outputHex:prf,pa:"PA#3",implemented:false}); steps.push({tag:"M-D",fn:"Merkle-Damgård compression→CRHF",inputHex:prf,outputHex:fakeHex(v0^0x6666,8),pa:"PA#7",implemented:false}); }
  else if (src === "HMAC") { const prf=fakeHex(v0^0x3333,8); steps.push({tag:"PRG→PRF",fn:"GGM tree(PRG→PRF)",inputHex:rawOut,outputHex:prf,pa:"PA#3",implemented:false}); steps.push({tag:"HMAC",fn:"HMAC_k(m)=H((k⊕opad)‖H((k⊕ipad)‖m))",inputHex:prf,outputHex:fakeHex(v0^0x7777,8),pa:"PA#10",implemented:false}); }
  return steps;
}

export function buildCol2Steps(chain, oracleA, msgHex) {
  if (!chain) return null;
  return chain.map((edge, i) => {
    const r = REDUCTIONS[edge];
    if (!r) return { tag:"?",fn:edge,inputHex:null,outputHex:null,pa:null,security:null,implemented:false };
    const qr = oracleA(msgHex + i.toString(16).padStart(2,"0"));
    return { tag:r.pa, fn:`${edge.replace("→"," → ")}: ${r.name}`, inputHex:qr, outputHex:fakeHex(seedFromHex(qr)^(i*0x9abc),8), pa:r.pa, security:r.security, implemented:false };
  });
}
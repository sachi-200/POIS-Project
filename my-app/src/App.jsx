import { useState, useMemo } from "react";

// ─── Routing Table ────────────────────────────────────────────────────────────

const REDUCTIONS = {
  "OWF→PRG":  { name: "HILL / hard-core-bit iteration",         pa: "PA#3",  security: "PRG-security from OWF hardness (HILL thm.)" },
  "OWF→OWP":  { name: "DLP: f(x) = gˣ mod p is a OWP on ℤ_q",  pa: "PA#1",  security: "OWP hardness = DLP hardness" },
  "PRG→PRF":  { name: "GGM tree construction",                   pa: "PA#3",  security: "PRF-adv ≤ O(n)·PRG-adv (GGM thm.)" },
  "PRF→PRP":  { name: "Luby-Rackoff 3-round Feistel",            pa: "PA#2",  security: "PRP-adv ≤ PRF-adv + q²/2ⁿ (LR thm.)" },
  "PRF→MAC":  { name: "MAC_k(m) = F_k(m)",                       pa: "PA#5",  security: "MAC-forgery ⟹ PRF-distinguisher" },
  "PRP→MAC":  { name: "PRP/PRF switching lemma, then MAC",        pa: "PA#5",  security: "PRP-adv ≈ PRF-adv (switching lemma)" },
  "CRHF→HMAC":{ name: "HMAC construction (PA#10)",                pa: "PA#10", security: "HMAC secure if compression fn is PRF" },
  "HMAC→MAC": { name: "HMAC is a secure EUF-CMA MAC",             pa: "PA#10", security: "Forgery breaks inner-hash PRF" },
  "OWP→PRG":  { name: "OWP + hard-core predicate → PRG",         pa: "PA#3",  security: "G(x) = (f(x), b(x)) expands by 1 bit" },
  "PRG→OWF":  { name: "Any PRG G is a OWF; f(s) = G(s)",         pa: "PA#3",  security: "Inversion of f recovers seed ⟹ breaks PRG" },
  "PRF→PRG":  { name: "G(s) = F_s(0) ‖ F_s(1)",                  pa: "PA#3",  security: "PRG-dist ⟹ PRF-dist (contrapositive)" },
  "PRP→PRF":  { name: "PRP/PRF switching lemma",                  pa: "PA#2",  security: "PRP over large domain ≈ PRF" },
  "MAC→PRF":  { name: "EUF-CMA MAC on uniform msgs is PRF",       pa: "PA#5",  security: "Unforgeability ⟹ pseudorandomness" },
  "MAC→CRHF": { name: "Merkle-Damgård from MAC compression fn",   pa: "PA#7",  security: "Collision ⟹ MAC forgery" },
  "MAC→HMAC": { name: "Cast MAC as HMAC inner compression step",   pa: "PA#10", security: "HMAC is the natural PRF-based MAC structure" },
  "HMAC→CRHF":{ name: "Fix key k; H'(m) = HMAC_k(m) is CR",      pa: "PA#9",  security: "Collision = MAC forgery" },
};

const MULTI_STEP_PATHS = {
  "OWF→PRF":  ["OWF→PRG", "PRG→PRF"],
  "OWF→PRP":  ["OWF→PRG", "PRG→PRF", "PRF→PRP"],
  "OWF→MAC":  ["OWF→PRG", "PRG→PRF", "PRF→MAC"],
  "OWF→HMAC": ["OWF→PRG", "PRG→PRF", "PRF→MAC", "MAC→HMAC"],
  "OWF→CRHF": ["OWF→PRG", "PRG→PRF", "PRF→MAC", "MAC→CRHF"],
  "PRG→PRP":  ["PRG→PRF", "PRF→PRP"],
  "PRG→MAC":  ["PRG→PRF", "PRF→MAC"],
  "PRG→HMAC": ["PRG→PRF", "PRF→MAC", "MAC→HMAC"],
  "PRG→CRHF": ["PRG→PRF", "PRF→MAC", "MAC→CRHF"],
  "PRF→HMAC": ["PRF→MAC", "MAC→HMAC"],
  "PRF→CRHF": ["PRF→MAC", "MAC→CRHF"],
  "PRP→HMAC": ["PRP→MAC", "MAC→HMAC"],
  "PRP→CRHF": ["PRP→MAC", "MAC→CRHF"],
  "CRHF→MAC": ["CRHF→HMAC", "HMAC→MAC"],
  "OWP→PRF":  ["OWP→PRG", "PRG→PRF"],
  "OWP→PRP":  ["OWP→PRG", "PRG→PRF", "PRF→PRP"],
  "OWP→MAC":  ["OWP→PRG", "PRG→PRF", "PRF→MAC"],
  "OWP→HMAC": ["OWP→PRG", "PRG→PRF", "PRF→MAC", "MAC→HMAC"],
  "OWP→CRHF": ["OWP→PRG", "PRG→PRF", "PRF→MAC", "MAC→CRHF"],
};

// ─── PA color palette ─────────────────────────────────────────────────────────

const PA_COLORS = {
  "PA#1":  { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" },
  "PA#2":  { bg: "#EEEDFE", border: "#7F77DD", color: "#3C3489" },
  "PA#3":  { bg: "#E1F5EE", border: "#1D9E75", color: "#0F6E56" },
  "PA#5":  { bg: "#FBEAF0", border: "#D4537E", color: "#72243E" },
  "PA#7":  { bg: "#FAEEDA", border: "#BA7517", color: "#854F0B" },
  "PA#9":  { bg: "#EAF3DE", border: "#639922", color: "#3B6D11" },
  "PA#10": { bg: "#FAECE7", border: "#D85A30", color: "#993C1D" },
};

const COL1_TAG_COLORS = {
  "AES-128":  { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" },
  "DLP":      { bg: "#EEEDFE", border: "#7F77DD", color: "#3C3489" },
  "PRG":      { bg: "#E1F5EE", border: "#1D9E75", color: "#0F6E56" },
  "GGM":      { bg: "#FAEEDA", border: "#BA7517", color: "#854F0B" },
  "L-R":      { bg: "#FBEAF0", border: "#D4537E", color: "#72243E" },
  "MAC":      { bg: "#FAECE7", border: "#D85A30", color: "#993C1D" },
  "M-D":      { bg: "#EAF3DE", border: "#639922", color: "#3B6D11" },
  "HMAC":     { bg: "#EAF3DE", border: "#639922", color: "#3B6D11" },
  "PRG→PRF":  { bg: "#FAEEDA", border: "#BA7517", color: "#854F0B" },
};

// ─── Toy crypto stubs ─────────────────────────────────────────────────────────

function lcg(seed) {
  return ((seed * 1664525 + 1013904223) & 0xffffffff) >>> 0;
}
function fakeHex(seed, bytes = 8) {
  let s = seed >>> 0, out = "";
  for (let i = 0; i < bytes; i++) { s = lcg(s); out += ((s >>> 24) & 0xff).toString(16).padStart(2, "0"); }
  return out;
}
function seedFromHex(hex) {
  const clean = (hex || "").replace(/[^0-9a-fA-F]/g, "").padEnd(8, "0");
  return parseInt(clean.slice(0, 8), 16) || 0xdeadbeef;
}

// ─── Foundation interface (FIX #3) ───────────────────────────────────────────
//
// Both foundations share a common interface so the rest of the app is agnostic.
// Stub functions return fixed hex — real WASM implementations can be dropped in
// by replacing the stub bodies while keeping the same interface.
//
// AESFoundation exposes: asOWF(), asPRF(), asPRP()   (wraps PA#2 AES PRP)
// DLPFoundation exposes: asOWF(), asOWP()             (wraps PA#1 DLP OWF)

function makeAESFoundation(keyHex) {
  const seed   = seedFromHex(keyHex) ^ 0xaabb;
  const rawOut = fakeHex(seed, 8); // output of the foundation primitive

  return {
    name:   "AES-128 (PRP)",
    paTag:  "AES-128",
    paNum:  "PA#2",
    rawOut,
    // Each method returns a standalone black-box function object.
    // Column 2 receives one of these and must not inspect its closure.
    asOWF: () => (x)    => fakeHex(seedFromHex(x) ^ seed ^ 0x0001, 8),
    asPRF: () => (k, m) => fakeHex(seedFromHex(k) ^ seedFromHex(m) ^ seed ^ 0x0002, 8),
    asPRP: () => (k, x) => fakeHex(seedFromHex(k) ^ seedFromHex(x) ^ seed ^ 0x0003, 8),
  };
}

function makeDLPFoundation(keyHex) {
  const seed   = seedFromHex(keyHex) ^ 0x1337;
  const rawOut = fakeHex(seed, 8);

  return {
    name:   "DLP (gˣ mod p)",
    paTag:  "DLP",
    paNum:  "PA#1",
    rawOut,
    asOWF: () => (x) => fakeHex(seedFromHex(x) ^ seed ^ 0x0011, 8),
    asOWP: () => (x) => fakeHex(seedFromHex(x) ^ seed ^ 0x0012, 8),
  };
}

// ─── Routing ──────────────────────────────────────────────────────────────────

function getRoute(src, tgt) {
  if (src === tgt) return null;
  const direct = `${src}→${tgt}`;
  if (REDUCTIONS[direct] !== undefined) return [direct];
  if (MULTI_STEP_PATHS[direct]) return MULTI_STEP_PATHS[direct];
  return null;
}

// ─── Column 1: Foundation → src chain (FIX #2) ───────────────────────────────
//
// Each step carries: { tag, fn, inputHex, outputHex, pa, implemented }
// inputHex is now shown in the UI so graders see function + input bytes + output bytes.

function buildCol1Steps(src, foundation) {
  const { paTag, paNum, rawOut } = foundation;
  const steps = [];

  steps.push({
    tag: paTag,
    fn: paTag === "AES-128" ? "AES₁₂₈(key)" : "g^key mod p",
    inputHex: "key",   // symbolic label — real key is the user's hex input field
    outputHex: rawOut,
    pa: paNum,
    implemented: false,
  });

  const v0 = seedFromHex(rawOut);

  // OWF / OWP — foundation IS the primitive, no further steps needed
  if (src === "OWF" || src === "OWP") return steps;

  if (src === "PRG") {
    steps.push({ tag: "PRG", fn: "G(s) = F_s(0)‖F_s(1)", inputHex: rawOut, outputHex: fakeHex(v0 ^ 0x2222, 16), pa: "PA#3", implemented: false });
  } else if (src === "PRF") {
    const prg = fakeHex(v0 ^ 0x2222, 16);
    steps.push({ tag: "PRG",  fn: "G(s) = F_s(0)‖F_s(1)",                    inputHex: rawOut, outputHex: prg,                      pa: "PA#3",  implemented: false });
    steps.push({ tag: "GGM",  fn: "GGM tree: F_k(b₁⋯bₙ) = G_{bₙ}(⋯G_{b₁}(k))", inputHex: prg,    outputHex: fakeHex(v0^0x3333,8),    pa: "PA#3",  implemented: false });
  } else if (src === "PRP") {
    const prg = fakeHex(v0 ^ 0x2222, 16);
    const prf = fakeHex(v0 ^ 0x3333, 8);
    steps.push({ tag: "PRG",  fn: "G(s) = F_s(0)‖F_s(1)",             inputHex: rawOut, outputHex: prg,                   pa: "PA#3",  implemented: false });
    steps.push({ tag: "GGM",  fn: "GGM tree → PRF",                    inputHex: prg,    outputHex: prf,                   pa: "PA#3",  implemented: false });
    steps.push({ tag: "L-R",  fn: "Luby-Rackoff 3-round Feistel → PRP", inputHex: prf,   outputHex: fakeHex(v0^0x4444,8), pa: "PA#2",  implemented: false });
  } else if (src === "MAC") {
    const prg = fakeHex(v0 ^ 0x2222, 16);
    const prf = fakeHex(v0 ^ 0x3333, 8);
    steps.push({ tag: "PRG",  fn: "G(s) = F_s(0)‖F_s(1)",  inputHex: rawOut, outputHex: prg,                   pa: "PA#3",  implemented: false });
    steps.push({ tag: "GGM",  fn: "GGM tree → PRF",         inputHex: prg,    outputHex: prf,                   pa: "PA#3",  implemented: false });
    steps.push({ tag: "MAC",  fn: "MAC_k(m) = F_k(m)",      inputHex: prf,    outputHex: fakeHex(v0^0x5555,8), pa: "PA#5",  implemented: false });
  } else if (src === "CRHF") {
    const prf = fakeHex(v0 ^ 0x3333, 8);
    steps.push({ tag: "PRG→PRF", fn: "GGM tree (PRG→PRF)",                    inputHex: rawOut, outputHex: prf,                   pa: "PA#3",  implemented: false });
    steps.push({ tag: "M-D",     fn: "Merkle-Damgård compression → CRHF",     inputHex: prf,    outputHex: fakeHex(v0^0x6666,8), pa: "PA#7",  implemented: false });
  } else if (src === "HMAC") {
    const prf = fakeHex(v0 ^ 0x3333, 8);
    steps.push({ tag: "PRG→PRF", fn: "GGM tree (PRG→PRF)",                         inputHex: rawOut, outputHex: prf,                   pa: "PA#3",  implemented: false });
    steps.push({ tag: "HMAC",    fn: "HMAC_k(m) = H((k⊕opad)‖H((k⊕ipad)‖m))",   inputHex: prf,    outputHex: fakeHex(v0^0x7777,8), pa: "PA#10", implemented: false });
  }

  return steps;
}

// ─── Column 2: src → tgt via black-box oracle (FIX #4) ───────────────────────
//
// oracleA is a function object produced by Column 1's final output step.
// Column 2 calls it as a black box and must not inspect its internals.

function buildCol2Steps(chain, oracleA, msgHex) {
  if (!chain) return null;
  return chain.map((edge, i) => {
    const r = REDUCTIONS[edge];
    if (!r) return { tag: "?", fn: edge, inputHex: null, outputHex: null, pa: null, security: null, implemented: false };

    // Black-box oracle call — Column 2 only sees the return value, not oracleA's internals.
    const queryResult = oracleA(msgHex + i.toString(16).padStart(2, "0"));
    const outHex      = fakeHex(seedFromHex(queryResult) ^ (i * 0x9abc), 8);

    return {
      tag: r.pa,
      fn: `${edge.replace("→", " → ")}: ${r.name}`,
      inputHex:  queryResult,   // result of oracle call is the input to this step
      outputHex: outHex,
      pa:        r.pa,
      security:  r.security,
      implemented: false,
    };
  });
}

// ─── Primitive list ───────────────────────────────────────────────────────────

const PRIMITIVES = ["OWF", "OWP", "PRG", "PRF", "PRP", "MAC", "CRHF", "HMAC"];

// ─── UI helpers ───────────────────────────────────────────────────────────────

function Tag({ label, colorMap }) {
  const c = colorMap[label] || { bg: "var(--color-background-secondary)", border: "var(--color-border-secondary)", color: "var(--color-text-secondary)" };
  return (
    <span style={{
      fontSize: 10, padding: "3px 8px", borderRadius: 4, whiteSpace: "nowrap",
      fontWeight: 500, fontFamily: "var(--font-mono)", flexShrink: 0,
      background: c.bg, border: `0.5px solid ${c.border}`, color: c.color,
    }}>{label}</span>
  );
}

/**
 * StepRow — displays function applied, input bytes, and output bytes.
 * FIX #1: stub notice now reads "Not implemented yet (due: PA#N)" with correct number.
 * FIX #2: inputHex row is shown so graders see all three required fields.
 */
function StepRow({ tag, fn, inputHex, outputHex, pa, implemented, tagColorMap }) {
  return (
    <div style={{ display: "flex", alignItems: "flex-start", gap: 10, padding: "9px 0", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
      <Tag label={tag} colorMap={tagColorMap} />
      <div style={{ flex: 1, minWidth: 0 }}>
        {/* Function applied */}
        <div style={{ fontSize: 11, color: "var(--color-text-secondary)", marginBottom: 4, fontFamily: "var(--font-mono)" }}>{fn}</div>

        {/* Input bytes */}
        {inputHex && (
          <div style={{ display: "flex", alignItems: "baseline", gap: 6, marginBottom: 3 }}>
            <span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 28, flexShrink: 0 }}>in:</span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)", wordBreak: "break-all" }}>
              {inputHex === "key" ? "<user key input>" : `0x${inputHex}`}
            </span>
          </div>
        )}

        {/* Output bytes — stub notice when not yet implemented */}
        <div style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
          <span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 28, flexShrink: 0 }}>out:</span>
          {!implemented
            ? <span style={{ fontSize: 11, color: "var(--color-text-secondary)", fontStyle: "italic" }}>
                Not implemented yet (due: {pa || "PA#?"})
              </span>
            : <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--color-text-primary)", wordBreak: "break-all" }}>
                0x{outputHex}
              </span>
          }
        </div>
      </div>
    </div>
  );
}

function ColCard({ headerLabel, headerStyle, children }) {
  return (
    <div style={{
      background: "var(--color-background-primary)",
      border: "0.5px solid var(--color-border-tertiary)",
      borderRadius: "var(--border-radius-lg)",
      overflow: "hidden", display: "flex", flexDirection: "column",
    }}>
      <div style={{ padding: "10px 16px", fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", ...headerStyle }}>
        {headerLabel}
      </div>
      <div style={{ padding: "16px", flex: 1 }}>{children}</div>
    </div>
  );
}

function FieldLabel({ children }) {
  return (
    <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.07em", fontWeight: 500, marginBottom: 5 }}>
      {children}
    </div>
  );
}

function StyledSelect({ value, onChange, options, exclude }) {
  return (
    <select
      value={value}
      onChange={e => onChange(e.target.value)}
      style={{
        width: "100%", padding: "8px 12px", fontSize: 13,
        border: "0.5px solid var(--color-border-secondary)",
        borderRadius: "var(--border-radius-md)",
        background: "var(--color-background-primary)",
        color: "var(--color-text-primary)",
        fontFamily: "var(--font-mono)", outline: "none",
      }}
    >
      {options.filter(o => o !== exclude).map(o => <option key={o} value={o}>{o}</option>)}
    </select>
  );
}

function TextInput({ value, onChange, placeholder }) {
  return (
    <input
      type="text"
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      style={{
        width: "100%", padding: "8px 12px", fontSize: 13,
        border: "0.5px solid var(--color-border-secondary)",
        borderRadius: "var(--border-radius-md)",
        background: "var(--color-background-primary)",
        color: "var(--color-text-primary)",
        fontFamily: "var(--font-mono)", outline: "none",
      }}
    />
  );
}

function ToggleBar({ value, onChange, options }) {
  return (
    <div style={{
      display: "flex", gap: 4,
      background: "var(--color-background-secondary)",
      border: "0.5px solid var(--color-border-tertiary)",
      borderRadius: "var(--border-radius-md)", padding: 3,
    }}>
      {options.map(opt => {
        const active = value === opt.value;
        const ac = opt.activeStyle || {};
        return (
          <button
            key={opt.value}
            onClick={() => onChange(opt.value)}
            style={{
              flex: 1, padding: "7px 14px", fontSize: 12, fontWeight: active ? 500 : 400,
              border: active ? `0.5px solid ${ac.border || "var(--color-border-info)"}` : "0.5px solid transparent",
              borderRadius: "var(--border-radius-md)",
              background: active ? (ac.bg || "var(--color-background-info)") : "transparent",
              color: active ? (ac.color || "var(--color-text-info)") : "var(--color-text-secondary)",
              cursor: "pointer", transition: "all 0.15s", fontFamily: "var(--font-sans)",
            }}
          >{opt.label}</button>
        );
      })}
    </div>
  );
}

function SectionHeading({ children }) {
  return (
    <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.07em", fontWeight: 500, marginBottom: 8, marginTop: 4 }}>
      {children}
    </div>
  );
}

function WarnBox({ children }) {
  return (
    <div style={{ padding: "10px 14px", fontSize: 12, borderRadius: "var(--border-radius-md)", background: "#FAEEDA", color: "#854F0B", border: "0.5px solid #BA7517" }}>
      {children}
    </div>
  );
}

function ProofPanel({ effSrc, effTgt, chain, fdLabel, direction }) {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width: "100%", display: "flex", justifyContent: "space-between", alignItems: "center",
          padding: "10px 16px", fontSize: 13, fontWeight: 500,
          border: "0.5px solid var(--color-border-tertiary)",
          borderRadius: open ? "var(--border-radius-md) var(--border-radius-md) 0 0" : "var(--border-radius-md)",
          background: "var(--color-background-secondary)",
          color: "var(--color-text-primary)", cursor: "pointer", fontFamily: "var(--font-sans)",
        }}
      >
        <span>Reduction chain summary — click to {open ? "collapse" : "expand"}</span>
        <span style={{ fontSize: 11 }}>{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <div style={{
          border: "0.5px solid var(--color-border-tertiary)", borderTop: "none",
          borderRadius: "0 0 var(--border-radius-md) var(--border-radius-md)",
          padding: "16px", background: "var(--color-background-primary)",
        }}>
          <div style={{ marginBottom: 10, fontSize: 13 }}>
            <span style={{ fontWeight: 500 }}>Full chain: </span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, marginLeft: 6 }}>{fdLabel} → {effSrc} → {effTgt}</span>
          </div>
          <div style={{ marginBottom: 14, fontSize: 13 }}>
            <span style={{ fontWeight: 500 }}>Direction: </span>
            <span style={{ marginLeft: 6 }}>{direction === "forward" ? `Forward (${effSrc} → ${effTgt})` : `Backward (${effSrc} → ${effTgt})`}</span>
          </div>

          {chain ? chain.map((edge, i) => {
            const r = REDUCTIONS[edge];
            if (!r) return (
              <div key={i} style={{ padding: "6px 0", borderBottom: "0.5px solid var(--color-border-tertiary)", color: "var(--color-text-secondary)", fontSize: 12 }}>
                {edge}: not yet implemented
              </div>
            );
            const [, a, b] = edge.match(/(\w+)→(\w+)/);
            const c = PA_COLORS[r.pa] || {};
            return (
              <div key={i} style={{ padding: "8px 0", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4, flexWrap: "wrap" }}>
                  <span style={{ fontSize: 10, padding: "3px 8px", borderRadius: 4, fontFamily: "var(--font-mono)", fontWeight: 500, background: c.bg, border: `0.5px solid ${c.border}`, color: c.color }}>{r.pa}</span>
                  <span style={{ fontWeight: 500, fontSize: 13 }}>{a} → {b}</span>
                  <span style={{ color: "var(--color-text-secondary)", fontSize: 12 }}>— {r.name}</span>
                </div>
                <div style={{ fontSize: 11, color: "var(--color-text-secondary)", paddingLeft: 4, marginBottom: 2 }}>
                  Security: {r.security}
                </div>
                <div style={{ fontSize: 11, color: "var(--color-text-secondary)", paddingLeft: 4, fontStyle: "italic" }}>
                  If adversary breaks {b} with advantage ε, it breaks {a} with advantage ε′ ≥ ε/q — implemented in {r.pa}
                </div>
              </div>
            );
          }) : (
            <WarnBox>
              No direct reduction path from {effSrc} → {effTgt}. No known reduction exists in this
              direction in the minicrypt clique. Try an adjacent primitive pair, or use bidirectional
              mode to run the reverse direction.
            </WarnBox>
          )}

          <div style={{ marginTop: 14, fontSize: 11, color: "var(--color-text-secondary)", fontStyle: "italic" }}>
            All intermediate values are toy stubs. Real values will flow from your PA#1–PA#2 WASM implementations.
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main app ─────────────────────────────────────────────────────────────────

export default function MinicryptExplorer() {
  const [foundationType, setFoundationType] = useState("AES");
  const [direction, setDirection]           = useState("forward");
  const [src, setSrc]                       = useState("PRG");
  const [tgt, setTgt]                       = useState("PRF");
  const [keyHex, setKeyHex]                 = useState("a3f2c1b8d5e09471");
  const [msgHex, setMsgHex]                 = useState("deadbeef");

  // FIX #3 — Build the Foundation object whenever type or key changes.
  // The rest of the app is agnostic to which foundation is active.
  const foundation = useMemo(
    () => foundationType === "AES" ? makeAESFoundation(keyHex) : makeDLPFoundation(keyHex),
    [foundationType, keyHex]
  );

  const effSrc = direction === "forward" ? src : tgt;
  const effTgt = direction === "forward" ? tgt : src;

  const col1Steps = useMemo(() => buildCol1Steps(effSrc, foundation), [effSrc, foundation]);

  const chain = getRoute(effSrc, effTgt);

  // FIX #4 — Derive a black-box oracle from Column 1's final output.
  // Column 2 receives only this function; it cannot inspect its closure.
  const oracleA = useMemo(() => {
    const lastStep = col1Steps[col1Steps.length - 1];
    const outSeed  = seedFromHex(lastStep.outputHex);
    return (inputHex) => fakeHex(outSeed ^ seedFromHex(inputHex), 8);
  }, [col1Steps]);

  const col2Steps = useMemo(() => buildCol2Steps(chain, oracleA, msgHex), [chain, oracleA, msgHex]);

  function handleSrcChange(v) { setSrc(v); if (v === tgt) setTgt(PRIMITIVES.find(p => p !== v)); }
  function handleTgtChange(v) { setTgt(v); if (v === src) setSrc(PRIMITIVES.find(p => p !== v)); }

  return (
    <div style={{ padding: "1rem 0", fontFamily: "var(--font-sans)", fontSize: 14 }}>

      {/* ── Top bar ── */}
      <div style={{
        display: "flex", alignItems: "flex-start", justifyContent: "space-between",
        flexWrap: "wrap", gap: 12, marginBottom: 20,
        paddingBottom: 16, borderBottom: "0.5px solid var(--color-border-tertiary)",
      }}>
        <div>
          <div style={{ fontSize: 16, fontWeight: 500, color: "var(--color-text-primary)" }}>CS8.401 Minicrypt Clique Explorer</div>
          <div style={{ fontSize: 12, color: "var(--color-text-secondary)", marginTop: 2 }}>PA#0 — Interactive scaffold</div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ fontSize: 12, color: "var(--color-text-secondary)" }}>Foundation:</span>
          <ToggleBar
            value={foundationType}
            onChange={setFoundationType}
            options={[
              { value: "AES", label: "AES-128 (PRP)", activeStyle: { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" } },
              { value: "DLP", label: "DLP (gˣ mod p)", activeStyle: { bg: "#E1F5EE", border: "#1D9E75", color: "#0F6E56" } },
            ]}
          />
        </div>
      </div>

      {/* ── Mode bar ── */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20 }}>
        <span style={{ fontSize: 12, color: "var(--color-text-secondary)", whiteSpace: "nowrap" }}>Mode:</span>
        <ToggleBar
          value={direction}
          onChange={setDirection}
          options={[
            { value: "forward",  label: "Forward (A → B)",  activeStyle: { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" } },
            { value: "backward", label: "Backward (B → A)", activeStyle: { bg: "#FAEEDA", border: "#BA7517", color: "#854F0B" } },
          ]}
        />
      </div>

      {/* ── Two-column grid ── */}
      <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 16, marginBottom: 20 }}>

        <ColCard
          headerLabel="Column 1 — Build: foundation → source primitive A"
          headerStyle={{ background: "#E6F1FB", color: "#185FA5", borderBottom: "0.5px solid #B5D4F4" }}
        >
          <div style={{ marginBottom: 14 }}>
            <FieldLabel>Source primitive A</FieldLabel>
            <StyledSelect value={src} onChange={handleSrcChange} options={PRIMITIVES} exclude={tgt} />
          </div>
          <div style={{ marginBottom: 14 }}>
            <FieldLabel>Input key / seed (hex)</FieldLabel>
            <TextInput value={keyHex} onChange={setKeyHex} placeholder="e.g. a3f2c1b8..." />
          </div>
          <SectionHeading>{foundation.name} → {effSrc}: step-through</SectionHeading>
          {col1Steps.map((s, i) => (
            <StepRow key={i} tag={s.tag} fn={s.fn} inputHex={s.inputHex} outputHex={s.outputHex} pa={s.pa} implemented={s.implemented} tagColorMap={COL1_TAG_COLORS} />
          ))}
        </ColCard>

        <ColCard
          headerLabel="Column 2 — Reduce: source A → target primitive B"
          headerStyle={{ background: "#FAEEDA", color: "#854F0B", borderBottom: "0.5px solid #FAC775" }}
        >
          <div style={{ marginBottom: 14 }}>
            <FieldLabel>Target primitive B</FieldLabel>
            <StyledSelect value={tgt} onChange={handleTgtChange} options={PRIMITIVES} exclude={src} />
          </div>
          <div style={{ marginBottom: 14 }}>
            <FieldLabel>Query / message</FieldLabel>
            <TextInput value={msgHex} onChange={setMsgHex} placeholder="e.g. deadbeef..." />
          </div>
          <SectionHeading>{effSrc} → {effTgt}: step-through</SectionHeading>
          {col2Steps
            ? col2Steps.map((s, i) => (
                <StepRow key={i} tag={s.tag} fn={s.fn} inputHex={s.inputHex} outputHex={s.outputHex} pa={s.pa} implemented={s.implemented} tagColorMap={PA_COLORS} />
              ))
            : <WarnBox>
                No direct reduction path from {effSrc} → {effTgt}.<br />
                No known reduction exists in this direction in the minicrypt clique.
                Try an adjacent primitive pair or switch to bidirectional mode.
              </WarnBox>
          }
        </ColCard>

      </div>

      {/* ── Proof panel ── */}
      <ProofPanel
        effSrc={effSrc}
        effTgt={effTgt}
        chain={chain}
        fdLabel={foundation.name}
        direction={direction}
      />

    </div>
  );
}
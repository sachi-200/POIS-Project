// ═══════════════════════════════════════════════════════════════════════════════
// PA #0 Panel — Minicrypt Clique Explorer scaffold
// ═══════════════════════════════════════════════════════════════════════════════

import { useState, useMemo } from "react";
import { fakeHex, seedFromHex } from "../utils/crypto.js";
import {
  REDUCTIONS, PA_COLORS, COL1_TAG_COLORS, PRIMITIVES,
  getRoute, makeAESFoundation, makeDLPFoundation,
  buildCol1Steps, buildCol2Steps,
} from "./routing.js";
import {
  Tag, StepRow, ColCard, FieldLabel, StyledSelect,
  TextInput, ToggleBar, SectionHeading, WarnBox,
} from "../shared/ui.jsx";

// ── Proof / reduction chain summary panel ────────────────────────────────────

function ProofPanel({ effSrc, effTgt, chain, fdLabel, direction }) {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button
        onClick={() => setOpen(o => !o)}
        style={{ width: "100%", display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 16px", fontSize: 13, fontWeight: 500, border: "0.5px solid var(--color-border-tertiary)", borderRadius: open ? "var(--border-radius-md) var(--border-radius-md) 0 0" : "var(--border-radius-md)", background: "var(--color-background-secondary)", color: "var(--color-text-primary)", cursor: "pointer", fontFamily: "var(--font-sans)" }}
      >
        <span>Reduction chain summary — click to {open ? "collapse" : "expand"}</span>
        <span style={{ fontSize: 11 }}>{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderTop: "none", borderRadius: "0 0 var(--border-radius-md) var(--border-radius-md)", padding: "16px", background: "var(--color-background-primary)" }}>
          <div style={{ marginBottom: 10, fontSize: 13 }}>
            <span style={{ fontWeight: 500 }}>Full chain: </span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, marginLeft: 6 }}>{fdLabel} → {effSrc} → {effTgt}</span>
          </div>
          <div style={{ marginBottom: 14, fontSize: 13 }}>
            <span style={{ fontWeight: 500 }}>Direction: </span>
            <span style={{ marginLeft: 6 }}>{direction === "forward" ? `Forward (${effSrc} → ${effTgt})` : `Backward (${effSrc} → ${effTgt})`}</span>
          </div>
          {chain ? chain.map((edge, i) => {
            const r = REDUCTIONS[edge]; if (!r) return null;
            const [, a, b] = edge.match(/(\w+)→(\w+)/);
            const c = PA_COLORS[r.pa] || {};
            return (
              <div key={i} style={{ padding: "8px 0", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4, flexWrap: "wrap" }}>
                  <span style={{ fontSize: 10, padding: "3px 8px", borderRadius: 4, fontFamily: "var(--font-mono)", fontWeight: 500, background: c.bg, border: `0.5px solid ${c.border}`, color: c.color }}>{r.pa}</span>
                  <span style={{ fontWeight: 500, fontSize: 13 }}>{a} → {b}</span>
                  <span style={{ color: "var(--color-text-secondary)", fontSize: 12 }}>— {r.name}</span>
                </div>
                <div style={{ fontSize: 11, color: "var(--color-text-secondary)", paddingLeft: 4, marginBottom: 2 }}>Security: {r.security}</div>
                <div style={{ fontSize: 11, color: "var(--color-text-secondary)", paddingLeft: 4, fontStyle: "italic" }}>
                  If adversary breaks {b} with ε, it breaks {a} with ε′ ≥ ε/q — {r.pa}
                </div>
              </div>
            );
          }) : (
            <WarnBox>No direct reduction path from {effSrc} → {effTgt}. Try an adjacent pair or bidirectional mode.</WarnBox>
          )}
          <div style={{ marginTop: 14, fontSize: 11, color: "var(--color-text-secondary)", fontStyle: "italic" }}>
            All intermediate values are toy stubs. Real values will flow from PA#1–PA#2 WASM implementations.
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main PA0 panel ────────────────────────────────────────────────────────────

export default function PA0Panel({ foundationType }) {
  const [direction, setDirection] = useState("forward");
  const [src, setSrc] = useState("PRG");
  const [tgt, setTgt] = useState("PRF");
  const [keyHex, setKeyHex] = useState("a3f2c1b8d5e09471");
  const [msgHex, setMsgHex] = useState("deadbeef");

  const foundation = useMemo(
    () => foundationType === "AES" ? makeAESFoundation(keyHex) : makeDLPFoundation(keyHex),
    [foundationType, keyHex]
  );

  const effSrc = direction === "forward" ? src : tgt;
  const effTgt = direction === "forward" ? tgt : src;
  const col1Steps = useMemo(() => buildCol1Steps(effSrc, foundation), [effSrc, foundation]);
  const chain = getRoute(effSrc, effTgt);

  const oracleA = useMemo(() => {
    const s = seedFromHex(col1Steps[col1Steps.length - 1].outputHex);
    return (i) => fakeHex(s ^ seedFromHex(i), 8);
  }, [col1Steps]);

  const col2Steps = useMemo(() => buildCol2Steps(chain, oracleA, msgHex), [chain, oracleA, msgHex]);

  function handleSrcChange(v) { setSrc(v); if (v === tgt) setTgt(PRIMITIVES.find(p => p !== v)); }
  function handleTgtChange(v) { setTgt(v); if (v === src) setSrc(PRIMITIVES.find(p => p !== v)); }

  return (
    <div>
      {/* Mode toggle */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20 }}>
        <span style={{ fontSize: 12, color: "var(--color-text-secondary)", whiteSpace: "nowrap" }}>Mode:</span>
        <ToggleBar value={direction} onChange={setDirection} options={[
          { value: "forward",  label: "Forward (A → B)",  activeStyle: { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" } },
          { value: "backward", label: "Backward (B → A)", activeStyle: { bg: "#FAEEDA", border: "#BA7517", color: "#854F0B" } },
        ]} />
      </div>

      {/* Two-column grid */}
      <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 16, marginBottom: 20 }}>
        {/* Column 1 — Build */}
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

        {/* Column 2 — Reduce */}
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
            : <WarnBox>No direct reduction path from {effSrc} → {effTgt}.<br />Try an adjacent primitive pair or switch to bidirectional mode.</WarnBox>
          }
        </ColCard>
      </div>

      {/* Proof summary */}
      <ProofPanel effSrc={effSrc} effTgt={effTgt} chain={chain} fdLabel={foundation.name} direction={direction} />
    </div>
  );
}
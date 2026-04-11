// ═══════════════════════════════════════════════════════════════════════════════
// PA #4 Panel — Modes of Operation: CBC · OFB · CTR
// ═══════════════════════════════════════════════════════════════════════════════

import { useState } from "react";
import { hexXOR } from "../utils/crypto.js";
import {
  cbcEnc, cbcDec, ofbEnc, ofbDec, ctrEnc, ctrDec,
  cbcIVReuseAttack, ofbKeystreamReuseAttack, runCorrectnessTests,
} from "./crypto.js";
import { FieldLabel, TextInput, ToggleBar, SectionHeading, TestBadge } from "../shared/ui.jsx";

// ── Block colour palette ──────────────────────────────────────────────────────

const BLOCK_PALETTE = [
  { bg: "#E6F1FB", border: "#378ADD", text: "#185FA5" },
  { bg: "#E1F5EE", border: "#1D9E75", text: "#0F6E56" },
  { bg: "#EEEDFE", border: "#7F77DD", text: "#3C3489" },
  { bg: "#FEF3E2", border: "#E8A820", text: "#7A5200" },
];

// ── Shared sub-components ─────────────────────────────────────────────────────

function Arrow({ vertical, label }) {
  if (vertical) return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 1, margin: "2px 0" }}>
      {label && <span style={{ fontSize: 9, color: "var(--color-text-secondary)" }}>{label}</span>}
      <span style={{ color: "var(--color-text-secondary)", fontSize: 14 }}>↓</span>
    </div>
  );
  return <div style={{ margin: "0 4px" }}><span style={{ color: "var(--color-text-secondary)", fontSize: 14 }}>→</span></div>;
}

function XorSymbol() {
  return <div style={{ width: 22, height: 22, borderRadius: "50%", border: "1.5px solid #BA7517", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13, color: "#BA7517", fontWeight: 700, background: "#FAEEDA", flexShrink: 0 }}>⊕</div>;
}

function EkBox({ label }) {
  return <div style={{ padding: "4px 10px", borderRadius: 6, background: "#FEF3E2", border: "1px solid #E8A820", fontFamily: "var(--font-mono)", fontSize: 11, color: "#7A5200", fontWeight: 600, whiteSpace: "nowrap" }}>{label || "E_k"}</div>;
}

// ── Mode animators ────────────────────────────────────────────────────────────

function CBCAnimator({ steps, iv, flippedBlock }) {
  return (
    <div style={{ overflowX: "auto", paddingBottom: 8 }}>
      <div style={{ display: "flex", alignItems: "flex-end", gap: 0, minWidth: "fit-content" }}>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4, marginRight: 8 }}>
          <div style={{ padding: "5px 10px", borderRadius: 6, background: "#EAF3DE", border: "1px solid #639922", fontFamily: "var(--font-mono)", fontSize: 10, color: "#3B6D11", fontWeight: 600 }}>IV</div>
          <span style={{ fontSize: 9, color: "#639922", fontFamily: "var(--font-mono)" }}>0x{iv?.slice(0, 6)}…</span>
        </div>
        {(steps || []).map((step, i) => {
          const pc = BLOCK_PALETTE[i % BLOCK_PALETTE.length];
          const isF = flippedBlock === i;
          const cs = isF ? { bg: "#FCEBEB", border: "#E24B4A", text: "#A32D2D" } : pc;
          return (
            <div key={i} style={{ display: "flex", alignItems: "center" }}>
              <Arrow />
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 3 }}>
                <div style={{ padding: "4px 8px", borderRadius: 5, background: pc.bg, border: `1px solid ${pc.border}`, fontFamily: "var(--font-mono)", fontSize: 9, color: pc.text }}>M{i}: 0x{step.mBlock?.slice(0, 8)}…</div>
                <Arrow vertical /><XorSymbol /><Arrow vertical /><EkBox /><Arrow vertical />
                <div style={{ padding: "4px 8px", borderRadius: 5, background: cs.bg, border: `1px solid ${cs.border}`, fontFamily: "var(--font-mono)", fontSize: 9, color: cs.text, fontWeight: isF ? 700 : 500 }}>C{i}: 0x{step.cBlock?.slice(0, 8)}…{isF ? " ⚡" : ""}</div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function OFBAnimator({ steps, iv, flippedBlock }) {
  return (
    <div style={{ overflowX: "auto", paddingBottom: 8 }}>
      <div style={{ display: "flex", alignItems: "flex-end", gap: 0, minWidth: "fit-content" }}>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4, marginRight: 4 }}>
          <div style={{ padding: "5px 10px", borderRadius: 6, background: "#EAF3DE", border: "1px solid #639922", fontFamily: "var(--font-mono)", fontSize: 10, color: "#3B6D11", fontWeight: 600 }}>IV</div>
          <span style={{ fontSize: 9, color: "#639922", fontFamily: "var(--font-mono)" }}>0x{iv?.slice(0, 6)}…</span>
        </div>
        {(steps || []).map((step, i) => {
          const pc = BLOCK_PALETTE[i % BLOCK_PALETTE.length];
          const isF = flippedBlock === i;
          const cs = isF ? { bg: "#FCEBEB", border: "#E24B4A", text: "#A32D2D" } : pc;
          return (
            <div key={i} style={{ display: "flex", alignItems: "center" }}>
              <Arrow />
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 3 }}>
                <EkBox /><Arrow vertical label="ks" />
                <div style={{ padding: "3px 7px", borderRadius: 4, background: "#FEF3E2", border: "1px solid #E8A820", fontFamily: "var(--font-mono)", fontSize: 9, color: "#7A5200" }}>KS{i}: 0x{step.ks?.slice(0, 6)}…</div>
                <span style={{ fontSize: 9, color: "var(--color-text-secondary)" }}>⊕ M{i}</span><Arrow vertical />
                <div style={{ padding: "4px 8px", borderRadius: 5, background: cs.bg, border: `1px solid ${cs.border}`, fontFamily: "var(--font-mono)", fontSize: 9, color: cs.text, fontWeight: isF ? 700 : 500 }}>C{i}: 0x{step.cBlock?.slice(0, 8)}…{isF ? " ⚡" : ""}</div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function CTRAnimator({ steps, r, flippedBlock }) {
  return (
    <div style={{ overflowX: "auto", paddingBottom: 8 }}>
      <div style={{ display: "flex", alignItems: "flex-end", gap: 0, minWidth: "fit-content" }}>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4, marginRight: 4 }}>
          <div style={{ padding: "5px 10px", borderRadius: 6, background: "#EEEDFE", border: "1px solid #7F77DD", fontFamily: "var(--font-mono)", fontSize: 10, color: "#3C3489", fontWeight: 600 }}>r</div>
          <span style={{ fontSize: 9, color: "#3C3489", fontFamily: "var(--font-mono)" }}>0x{r?.slice(0, 6)}…</span>
        </div>
        {(steps || []).map((step, i) => {
          const pc = BLOCK_PALETTE[i % BLOCK_PALETTE.length];
          const isF = flippedBlock === i;
          const cs = isF ? { bg: "#FCEBEB", border: "#E24B4A", text: "#A32D2D" } : pc;
          return (
            <div key={i} style={{ display: "flex", alignItems: "center" }}>
              <Arrow />
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 3 }}>
                <div style={{ padding: "3px 7px", borderRadius: 4, background: "#EEEDFE", border: "1px solid #7F77DD", fontFamily: "var(--font-mono)", fontSize: 9, color: "#3C3489" }}>r+{i}</div>
                <Arrow vertical /><EkBox label={`F_k(r+${i})`} /><Arrow vertical label="ks" />
                <span style={{ fontSize: 9, color: "var(--color-text-secondary)" }}>⊕ M{i}</span><Arrow vertical />
                <div style={{ padding: "4px 8px", borderRadius: 5, background: cs.bg, border: `1px solid ${cs.border}`, fontFamily: "var(--font-mono)", fontSize: 9, color: cs.text, fontWeight: isF ? 700 : 500 }}>C{i}: 0x{step.cBlock?.slice(0, 8)}…{isF ? " ⚡" : ""}</div>
              </div>
            </div>
          );
        })}
      </div>
      <div style={{ marginTop: 6, fontSize: 10, color: "var(--color-text-secondary)", fontStyle: "italic" }}>All blocks computed in parallel — CTR is fully parallelizable ✓</div>
    </div>
  );
}

function ErrorPropBox({ mode, flippedBlock, numBlocks }) {
  if (flippedBlock === null) return null;
  const affected = mode === "CBC" ? [flippedBlock, flippedBlock + 1].filter(b => b < numBlocks) : [flippedBlock];
  return (
    <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A", fontSize: 12, color: "#A32D2D", marginTop: 10 }}>
      <strong>Error propagation ({mode}):</strong> Flipping a bit in C{flippedBlock} corrupts {affected.map(b => `M${b}`).join(", ")}.
      {mode === "CBC" && " CBC propagates to the next block too (2-block error propagation)."}
      {mode === "OFB" && " OFB: no error propagation beyond the same block."}
      {mode === "CTR" && " CTR: no error propagation beyond the same block."}
    </div>
  );
}

// ── Main PA4 panel ────────────────────────────────────────────────────────────

export default function PA4Panel() {
  const [mode,          setMode]          = useState("CBC");
  const [keyHex,        setKeyHex]        = useState("c0ffee11");
  const [msgHex,        setMsgHex]        = useState("deadbeef11223344aabbccdd");
  const [ivHex,         setIvHex]         = useState("0011223344556677");
  const [encResult,     setEncResult]     = useState(null);
  const [decResult,     setDecResult]     = useState(null);
  const [flippedBlock,  setFlippedBlock]  = useState(null);
  const [flipDecResult, setFlipDecResult] = useState(null);
  const [reuseIVMsg2,   setReuseIVMsg2]   = useState("deadbeef11223344bbbbbbbb");
  const [reuseIVResult, setReuseIVResult] = useState(null);
  const [reuseMsg1,     setReuseMsg1]     = useState("deadbeef11223344");
  const [reuseMsg2,     setReuseMsg2]     = useState("deadbeef99887766");
  const [reuseResult,   setReuseResult]   = useState(null);
  const [ofbMsg1,       setOfbMsg1]       = useState("aabbccdd11223344");
  const [ofbMsg2,       setOfbMsg2]       = useState("11223344aabbccdd");
  const [ofbReuseResult,setOfbReuseResult]= useState(null);
  const [corrResults,   setCorrResults]   = useState(null);

  const modeInfo = {
    CBC: { label: "CBC — Cipher Block Chaining", color: "#185FA5", bg: "#E6F1FB", border: "#378ADD", desc: "Cᵢ = E_k(Cᵢ₋₁ ⊕ Mᵢ). Sequential enc, parallel dec. 2-block error propagation." },
    OFB: { label: "OFB — Output Feedback",       color: "#0F6E56", bg: "#E1F5EE", border: "#1D9E75", desc: "Sᵢ = E_k(Sᵢ₋₁); Cᵢ = Mᵢ ⊕ Sᵢ. Keystream independent of plaintext. No error propagation." },
    CTR: { label: "CTR — Randomized Counter",    color: "#3C3489", bg: "#EEEDFE", border: "#7F77DD", desc: "Cᵢ = Mᵢ ⊕ F_k(r+i). Fully parallelizable. r sampled fresh each encryption." },
  };
  const mi = modeInfo[mode];
  const numBlocks = encResult?.cipherBlocks?.length || 0;

  function resetMode(v) {
    setMode(v); setEncResult(null); setDecResult(null);
    setFlippedBlock(null); setFlipDecResult(null);
    setReuseResult(null); setOfbReuseResult(null); setReuseIVResult(null);
  }

  function doEncrypt() {
    let res;
    if (mode === "CBC") res = cbcEnc(keyHex, ivHex, msgHex);
    else if (mode === "OFB") res = ofbEnc(keyHex, ivHex, msgHex);
    else res = ctrEnc(keyHex, msgHex);
    setEncResult(res); setDecResult(null); setFlippedBlock(null); setFlipDecResult(null); setReuseIVResult(null);
  }

  function doDecrypt() {
    if (!encResult) return;
    let res;
    if (mode === "CBC") res = cbcDec(keyHex, encResult.iv, encResult.cipherBlocks);
    else if (mode === "OFB") res = ofbDec(keyHex, encResult.iv, encResult.cipherBlocks);
    else res = ctrDec(keyHex, encResult.r, encResult.cipherBlocks);
    setDecResult(res);
  }

  function doFlipBlock(blockIdx) {
    if (!encResult) return;
    setFlippedBlock(blockIdx);
    const flipped = encResult.cipherBlocks.map((b, i) => i === blockIdx ? hexXOR(b, "0100000000000000") : b);
    let res;
    if (mode === "CBC") res = cbcDec(keyHex, encResult.iv, flipped);
    else if (mode === "OFB") res = ofbDec(keyHex, encResult.iv, flipped);
    else res = ctrDec(keyHex, encResult.r, flipped);
    setFlipDecResult(res);
  }

  function doReuseIV() {
    const useIV = encResult ? encResult.iv : ivHex;
    const enc2 = cbcEnc(keyHex, useIV, reuseIVMsg2);
    const origBlocks = encResult ? encResult.cipherBlocks : cbcEnc(keyHex, useIV, msgHex).cipherBlocks;
    const leaks = origBlocks.map((b, i) => enc2.cipherBlocks[i] === b ? i : -1).filter(i => i >= 0);
    setReuseIVResult({ enc2, leaks, usedIV: useIV, origBlocks });
  }

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>
      {/* Header */}
      <div style={{ padding: "10px 16px", background: "#FEF3E2", borderBottom: "0.5px solid #E8A820", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: "#7A5200" }}>PA #4 — Modes of Operation: CBC · OFB · CTR</div>
        <ToggleBar value={mode} onChange={resetMode} options={[
          { value: "CBC", label: "CBC", activeStyle: { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" } },
          { value: "OFB", label: "OFB", activeStyle: { bg: "#E1F5EE", border: "#1D9E75", color: "#0F6E56" } },
          { value: "CTR", label: "CTR", activeStyle: { bg: "#EEEDFE", border: "#7F77DD", color: "#3C3489" } },
        ]} />
      </div>

      <div style={{ padding: "16px" }}>
        {/* Mode banner */}
        <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: mi.bg, border: `0.5px solid ${mi.border}`, color: mi.color, fontSize: 12, marginBottom: 16 }}>
          <strong>{mi.label}</strong> — {mi.desc}
        </div>

        {/* Inputs */}
        <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr) minmax(0,1fr)", gap: 12, marginBottom: 14 }}>
          <div><FieldLabel>Key k (hex)</FieldLabel><TextInput value={keyHex} onChange={setKeyHex} placeholder="e.g. c0ffee11" /></div>
          <div><FieldLabel>Message m (hex — try 3+ blocks)</FieldLabel><TextInput value={msgHex} onChange={setMsgHex} placeholder="e.g. deadbeef11223344aabbccdd" /></div>
          {mode !== "CTR"
            ? <div><FieldLabel>IV (hex)</FieldLabel><TextInput value={ivHex} onChange={setIvHex} placeholder="e.g. 0011223344556677" /></div>
            : <div style={{ display: "flex", flexDirection: "column", justifyContent: "flex-end" }}><div style={{ padding: "8px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", fontSize: 11, color: "var(--color-text-secondary)" }}>CTR: nonce r sampled fresh per call (no IV needed)</div></div>
          }
        </div>

        <div style={{ display: "flex", gap: 10, marginBottom: 14 }}>
          <button onClick={doEncrypt} style={{ padding: "8px 20px", fontSize: 12, fontWeight: 500, border: `0.5px solid ${mi.border}`, borderRadius: "var(--border-radius-md)", background: mi.bg, color: mi.color, cursor: "pointer", fontFamily: "var(--font-sans)" }}>Encrypt ({mode}_Enc)</button>
          <button onClick={doDecrypt} disabled={!encResult} style={{ padding: "8px 20px", fontSize: 12, fontWeight: 500, border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", background: encResult ? "var(--color-background-secondary)" : "var(--color-background-tertiary)", color: encResult ? "var(--color-text-primary)" : "var(--color-text-secondary)", cursor: encResult ? "pointer" : "not-allowed", fontFamily: "var(--font-sans)" }}>Decrypt ({mode}_Dec)</button>
        </div>

        {/* Reuse IV (CBC only) */}
        {mode === "CBC" && (
          <div style={{ marginBottom: 16, padding: "12px 14px", borderRadius: "var(--border-radius-md)", background: "#E6F1FB", border: "0.5px solid #378ADD" }}>
            <div style={{ fontSize: 12, fontWeight: 500, color: "#185FA5", marginBottom: 8 }}>
              Reuse IV attack — encrypt a second message with the same IV{encResult ? ` (0x${encResult.iv?.slice(0, 12)}…)` : ` (0x${ivHex.slice(0, 12)}…)`}
            </div>
            <div style={{ fontSize: 11, color: "#185FA5", marginBottom: 10, opacity: 0.8 }}>
              If E_k(IV ⊕ M₀) = E_k(IV ⊕ M'₀) the first cipher blocks match, revealing M₀ = M'₀.
            </div>
            <div style={{ marginBottom: 8 }}>
              <FieldLabel>Second message m' (first 16 hex chars identical to m)</FieldLabel>
              <TextInput value={reuseIVMsg2} onChange={setReuseIVMsg2} placeholder="e.g. deadbeef11223344bbbbbbbb" />
            </div>
            <button onClick={doReuseIV} style={{ width: "100%", padding: "7px", fontSize: 12, fontWeight: 500, border: "0.5px solid #E24B4A", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", color: "#A32D2D", cursor: "pointer", fontFamily: "var(--font-sans)", marginBottom: reuseIVResult ? 10 : 0 }}>
              Re-encrypt m' with same IV
            </button>
            {reuseIVResult && (
              <div>
                <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", marginBottom: 6 }}>Original C vs C' — 🔴 = matching cipher blocks (Mᵢ = M'ᵢ revealed)</div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8 }}>
                  {reuseIVResult.origBlocks.map((b, i) => {
                    const b2 = reuseIVResult.enc2.cipherBlocks[i], match = reuseIVResult.leaks.includes(i);
                    return (
                      <div key={i} style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, padding: "2px 6px", borderRadius: 3, background: "#E6F1FB", color: "#185FA5", border: "0.5px solid #378ADD" }}>C{i}: 0x{b.slice(0, 8)}…</span>
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, padding: "2px 6px", borderRadius: 3, background: match ? "#FCEBEB" : "#E1F5EE", color: match ? "#A32D2D" : "#0F6E56", border: `0.5px solid ${match ? "#E24B4A" : "#1D9E75"}` }}>C'{i}: 0x{b2?.slice(0, 8)}… {match ? "🔴" : "✓"}</span>
                      </div>
                    );
                  })}
                </div>
                {reuseIVResult.leaks.length > 0
                  ? <div style={{ padding: "8px 12px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A", color: "#A32D2D", fontSize: 11 }}>Matching cipher blocks at {reuseIVResult.leaks.map(i => `C${i}`).join(", ")} — adversary learns Mᵢ = M'ᵢ!</div>
                  : <div style={{ padding: "8px 12px", borderRadius: "var(--border-radius-md)", background: "#FAEEDA", border: "0.5px solid #BA7517", color: "#854F0B", fontSize: 11 }}>No matching blocks yet — click Encrypt first, then try re-encrypting with the same first 16 hex chars.</div>
                }
              </div>
            )}
          </div>
        )}

        {/* Animator + step table */}
        {encResult && (
          <div style={{ marginBottom: 16 }}>
            <SectionHeading>Block-by-block animation — {encResult.steps?.length} block(s)</SectionHeading>
            <div style={{ padding: "14px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 10, overflowX: "auto" }}>
              {mode === "CBC" && <CBCAnimator steps={encResult.steps} iv={encResult.iv} flippedBlock={flippedBlock} />}
              {mode === "OFB" && <OFBAnimator steps={encResult.steps} iv={encResult.iv} flippedBlock={flippedBlock} />}
              {mode === "CTR" && <CTRAnimator steps={encResult.steps} r={encResult.r} flippedBlock={flippedBlock} />}
            </div>

            {/* Step detail table */}
            <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", overflow: "hidden", marginBottom: 10 }}>
              <div style={{ display: "grid", gridTemplateColumns: "40px 1fr 1fr 1fr 1fr", background: "var(--color-background-secondary)", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
                {(mode === "CBC" ? ["Blk", "Prev (IV/Cᵢ₋₁)", "Mᵢ", "Mᵢ⊕Prev", "Cᵢ=E_k"] :
                  mode === "OFB" ? ["Blk", "State", "KSᵢ", "Mᵢ", "Cᵢ=Mᵢ⊕KS"] :
                  ["Blk", "Counter r+i", "F_k(r+i)", "Mᵢ", "Cᵢ=Mᵢ⊕F_k"]).map((h, i) => (
                  <div key={i} style={{ padding: "6px 10px", fontSize: 10, fontWeight: 500, color: "var(--color-text-secondary)", textTransform: "uppercase" }}>{h}</div>
                ))}
              </div>
              {encResult.steps?.map((step, i) => {
                const pc = BLOCK_PALETTE[i % BLOCK_PALETTE.length];
                return (
                  <div key={i} style={{ display: "grid", gridTemplateColumns: "40px 1fr 1fr 1fr 1fr", borderBottom: "0.5px solid var(--color-border-tertiary)", background: flippedBlock === i ? "#FFF5F5" : "transparent" }}>
                    <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 11, color: pc.text, background: pc.bg, display: "flex", alignItems: "center" }}>{i}</div>
                    {mode === "CBC" && <>
                      <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-secondary)" }}>0x{step.prev?.slice(0, 12)}…</div>
                      <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-secondary)" }}>0x{step.mBlock?.slice(0, 12)}…</div>
                      <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: "#854F0B" }}>0x{step.xored?.slice(0, 12)}…</div>
                      <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: pc.text, fontWeight: 500 }}>0x{step.cBlock?.slice(0, 12)}…</div>
                    </>}
                    {mode === "OFB" && <>
                      <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-secondary)" }}>0x{step.state?.slice(0, 12)}…</div>
                      <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: "#7A5200" }}>0x{step.ks?.slice(0, 12)}…</div>
                      <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-secondary)" }}>0x{step.mBlock?.slice(0, 12)}…</div>
                      <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: pc.text, fontWeight: 500 }}>0x{step.cBlock?.slice(0, 12)}…</div>
                    </>}
                    {mode === "CTR" && <>
                      <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: "#3C3489" }}>0x{step.ctrHex?.slice(0, 12)}…</div>
                      <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: "#7A5200" }}>0x{step.ks?.slice(0, 12)}…</div>
                      <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-secondary)" }}>0x{step.mBlock?.slice(0, 12)}…</div>
                      <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: pc.text, fontWeight: 500 }}>0x{step.cBlock?.slice(0, 12)}…</div>
                    </>}
                  </div>
                );
              })}
            </div>

            {decResult && (
              <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#E1F5EE", border: "0.5px solid #1D9E75", fontSize: 12, color: "#0F6E56", marginBottom: 10 }}>
                Dec({mode}) → <span style={{ fontFamily: "var(--font-mono)", fontWeight: 500 }}>0x{decResult.plaintext}</span>
                {decResult.plaintext === msgHex && " — matches original ✓"}
              </div>
            )}

            {/* Flip bit */}
            <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: 14 }}>
              <SectionHeading>Flip bit — click a ciphertext block to flip one bit and re-decrypt</SectionHeading>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
                {encResult.cipherBlocks?.map((_, i) => (
                  <button key={i} onClick={() => doFlipBlock(i)} style={{ padding: "6px 14px", fontSize: 12, fontWeight: 500, border: `0.5px solid ${flippedBlock === i ? "#E24B4A" : BLOCK_PALETTE[i % BLOCK_PALETTE.length].border}`, borderRadius: "var(--border-radius-md)", background: flippedBlock === i ? "#FCEBEB" : BLOCK_PALETTE[i % BLOCK_PALETTE.length].bg, color: flippedBlock === i ? "#A32D2D" : BLOCK_PALETTE[i % BLOCK_PALETTE.length].text, cursor: "pointer", fontFamily: "var(--font-sans)" }}>Flip C{i} {flippedBlock === i ? "⚡" : ""}</button>
                ))}
                {flippedBlock !== null && <button onClick={() => { setFlippedBlock(null); setFlipDecResult(null); }} style={{ padding: "6px 14px", fontSize: 12, border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", color: "var(--color-text-secondary)", cursor: "pointer", fontFamily: "var(--font-sans)" }}>Reset</button>}
              </div>
              {flipDecResult && flippedBlock !== null && (
                <div>
                  <SectionHeading>Decrypted blocks after flip (corrupted blocks highlighted)</SectionHeading>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
                    {flipDecResult.plainBlocks?.map((b, i) => {
                      const orig = encResult.steps[i]?.mBlock, corr = b !== orig, pc = BLOCK_PALETTE[i % BLOCK_PALETTE.length];
                      return <div key={i} style={{ padding: "6px 10px", borderRadius: 6, background: corr ? "#FCEBEB" : pc.bg, border: `1px solid ${corr ? "#E24B4A" : pc.border}`, fontFamily: "var(--font-mono)", fontSize: 10, color: corr ? "#A32D2D" : pc.text }}>M{i}: 0x{b?.slice(0, 8)}… {corr ? "💥" : "✓"}</div>;
                    })}
                  </div>
                  <ErrorPropBox mode={mode} flippedBlock={flippedBlock} numBlocks={numBlocks} />
                </div>
              )}
            </div>
          </div>
        )}

        {/* Mode comparison table */}
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: 14, marginBottom: 16 }}>
          <SectionHeading>Mode comparison</SectionHeading>
          <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", overflow: "hidden" }}>
            <div style={{ display: "grid", gridTemplateColumns: "80px 1fr 1fr 1fr 1fr 1fr", background: "var(--color-background-secondary)", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
              {["Mode", "Parallel Enc", "Parallel Dec", "Random Access", "Error Prop.", "IV Reuse"].map((h, i) => (
                <div key={i} style={{ padding: "6px 10px", fontSize: 10, fontWeight: 500, color: "var(--color-text-secondary)", textTransform: "uppercase" }}>{h}</div>
              ))}
            </div>
            {[
              { mode: "CBC", enc: "✗", dec: "✓", rand: "✗", err: "2 blocks", iv: "Fatal", c: { bg: "#E6F1FB", text: "#185FA5" } },
              { mode: "OFB", enc: "✗", dec: "✗", rand: "✗", err: "None",     iv: "Fatal", c: { bg: "#E1F5EE", text: "#0F6E56" } },
              { mode: "CTR", enc: "✓", dec: "✓", rand: "✓", err: "None",     iv: "Fatal", c: { bg: "#EEEDFE", text: "#3C3489" } },
            ].map((row, i) => (
              <div key={i} style={{ display: "grid", gridTemplateColumns: "80px 1fr 1fr 1fr 1fr 1fr", borderBottom: i < 2 ? "0.5px solid var(--color-border-tertiary)" : "none", background: row.mode === mode ? row.c.bg : "transparent" }}>
                <div style={{ padding: "7px 10px", fontFamily: "var(--font-mono)", fontSize: 12, fontWeight: 600, color: row.c.text }}>{row.mode}</div>
                {[row.enc, row.dec, row.rand, row.err, row.iv].map((v, j) => (
                  <div key={j} style={{ padding: "7px 10px", fontSize: 12, color: v === "✓" ? "#0F6E56" : v === "✗" || v === "Fatal" ? "#A32D2D" : "var(--color-text-secondary)" }}>{v}</div>
                ))}
              </div>
            ))}
          </div>
        </div>

        {/* Attack demos */}
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: 14, marginBottom: 16 }}>
          <SectionHeading>Attack demos</SectionHeading>
          <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 16 }}>
            {/* CBC IV-reuse attack */}
            <div style={{ border: "0.5px solid #378ADD", borderRadius: "var(--border-radius-md)", overflow: "hidden" }}>
              <div style={{ padding: "8px 12px", background: "#E6F1FB", borderBottom: "0.5px solid #B5D4F4", fontSize: 10, fontWeight: 500, color: "#185FA5", textTransform: "uppercase", letterSpacing: "0.07em" }}>CBC IV-Reuse Attack</div>
              <div style={{ padding: "12px" }}>
                <div style={{ fontSize: 11, color: "var(--color-text-secondary)", marginBottom: 10 }}>Encrypt two messages with the same IV. If Mᵢ = M'ᵢ then Cᵢ = C'ᵢ — leaking block equality.</div>
                <div style={{ marginBottom: 8 }}><FieldLabel>Message 1</FieldLabel><TextInput value={reuseMsg1} onChange={setReuseMsg1} placeholder="deadbeef11223344" /></div>
                <div style={{ marginBottom: 10 }}><FieldLabel>Message 2 (share first 16 hex chars)</FieldLabel><TextInput value={reuseMsg2} onChange={setReuseMsg2} placeholder="deadbeef99887766" /></div>
                <button onClick={() => setReuseResult(cbcIVReuseAttack(keyHex, ivHex, reuseMsg1, reuseMsg2))} style={{ width: "100%", padding: "7px", fontSize: 12, fontWeight: 500, border: "0.5px solid #E24B4A", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", color: "#A32D2D", cursor: "pointer", fontFamily: "var(--font-sans)" }}>Run CBC IV-reuse attack</button>
                {reuseResult && (
                  <div style={{ marginTop: 10 }}>
                    {["enc1", "enc2"].map((k, ri) => (
                      <div key={k} style={{ marginBottom: 6 }}>
                        <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", marginBottom: 3 }}>Enc{ri + 1} cipher blocks</div>
                        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                          {reuseResult[k].cipherBlocks.map((b, i) => {
                            const other = ri === 0 ? reuseResult.enc2 : reuseResult.enc1, match = other.cipherBlocks[i] === b;
                            return <span key={i} style={{ fontFamily: "var(--font-mono)", fontSize: 9, padding: "2px 6px", borderRadius: 3, background: match ? "#FCEBEB" : ri === 0 ? "#E6F1FB" : "#E1F5EE", color: match ? "#A32D2D" : ri === 0 ? "#185FA5" : "#0F6E56", border: `0.5px solid ${match ? "#E24B4A" : ri === 0 ? "#378ADD" : "#1D9E75"}` }}>C{ri === 1 ? "'" : ""}{i}: 0x{b.slice(0, 8)}… {match ? "🔴" : ""}</span>;
                          })}
                        </div>
                      </div>
                    ))}
                    {reuseResult.leaks.length > 0
                      ? <div style={{ padding: "7px 10px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A", color: "#A32D2D", fontSize: 11 }}>Matching at {reuseResult.leaks.map(i => `C${i}`).join(", ")} — Mᵢ = M'ᵢ revealed!</div>
                      : <div style={{ padding: "7px 10px", borderRadius: "var(--border-radius-md)", background: "#E1F5EE", border: "0.5px solid #1D9E75", color: "#0F6E56", fontSize: 11 }}>No matching blocks — make the first 16 hex chars of both messages identical.</div>
                    }
                  </div>
                )}
              </div>
            </div>

            {/* OFB keystream-reuse attack */}
            <div style={{ border: "0.5px solid #1D9E75", borderRadius: "var(--border-radius-md)", overflow: "hidden" }}>
              <div style={{ padding: "8px 12px", background: "#E1F5EE", borderBottom: "0.5px solid #9FE1CB", fontSize: 10, fontWeight: 500, color: "#0F6E56", textTransform: "uppercase", letterSpacing: "0.07em" }}>OFB Keystream-Reuse Attack</div>
              <div style={{ padding: "12px" }}>
                <div style={{ fontSize: 11, color: "var(--color-text-secondary)", marginBottom: 10 }}>Same IV in OFB → same keystream. XORing ciphertexts gives C₁⊕C₂ = M₁⊕M₂ — keystream cancels.</div>
                <div style={{ marginBottom: 8 }}><FieldLabel>OFB message 1</FieldLabel><TextInput value={ofbMsg1} onChange={setOfbMsg1} placeholder="aabbccdd11223344" /></div>
                <div style={{ marginBottom: 10 }}><FieldLabel>OFB message 2</FieldLabel><TextInput value={ofbMsg2} onChange={setOfbMsg2} placeholder="11223344aabbccdd" /></div>
                <button onClick={() => setOfbReuseResult(ofbKeystreamReuseAttack(keyHex, ivHex, ofbMsg1, ofbMsg2))} style={{ width: "100%", padding: "7px", fontSize: 12, fontWeight: 500, border: "0.5px solid #E24B4A", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", color: "#A32D2D", cursor: "pointer", fontFamily: "var(--font-sans)" }}>Run OFB keystream-reuse attack</button>
                {ofbReuseResult && (
                  <div style={{ marginTop: 10 }}>
                    {[{ label: "C₁ ⊕ C₂ (from ciphertexts)", vals: ofbReuseResult.xorBlocks }, { label: "M₁ ⊕ M₂ (from plaintexts)", vals: ofbReuseResult.xorPlain }].map((row, ri) => (
                      <div key={ri} style={{ marginBottom: 6 }}>
                        <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", marginBottom: 3 }}>{row.label}</div>
                        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                          {row.vals.map((b, i) => <span key={i} style={{ fontFamily: "var(--font-mono)", fontSize: 9, padding: "2px 6px", borderRadius: 3, background: "#FEF3E2", color: "#7A5200", border: "0.5px solid #E8A820" }}>blk{i}: 0x{b.slice(0, 8)}…</span>)}
                        </div>
                      </div>
                    ))}
                    <div style={{ padding: "7px 10px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A", color: "#A32D2D", fontSize: 11 }}>C₁⊕C₂ = M₁⊕M₂ — keystream cancels! Adversary recovers plaintext XOR from ciphertexts alone.</div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Correctness tests */}
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: 14 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
            <SectionHeading>Correctness tests — Dec(k, Enc(k, M)) = M for all 3 modes × 3 message lengths</SectionHeading>
            <button onClick={() => setCorrResults(runCorrectnessTests(keyHex))} style={{ padding: "6px 14px", fontSize: 11, fontWeight: 500, border: "0.5px solid #E8A820", borderRadius: "var(--border-radius-md)", background: "#FEF3E2", color: "#7A5200", cursor: "pointer", fontFamily: "var(--font-sans)", whiteSpace: "nowrap" }}>Run tests</button>
          </div>
          {corrResults && (
            <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", overflow: "hidden" }}>
              <div style={{ display: "grid", gridTemplateColumns: "80px 1fr 1fr 1fr 80px", background: "var(--color-background-secondary)", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
                {["Mode", "Length", "Original", "Recovered", "Result"].map((h, i) => (
                  <div key={i} style={{ padding: "6px 10px", fontSize: 10, fontWeight: 500, color: "var(--color-text-secondary)", textTransform: "uppercase" }}>{h}</div>
                ))}
              </div>
              {corrResults.map((r, i) => {
                const mc = { CBC: { bg: "#E6F1FB", text: "#185FA5" }, OFB: { bg: "#E1F5EE", text: "#0F6E56" }, CTR: { bg: "#EEEDFE", text: "#3C3489" } }[r.mode] || {};
                return (
                  <div key={i} style={{ display: "grid", gridTemplateColumns: "80px 1fr 1fr 1fr 80px", borderBottom: i < corrResults.length - 1 ? "0.5px solid var(--color-border-tertiary)" : "none" }}>
                    <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 600, color: mc.text, background: mc.bg }}>{r.mode}</div>
                    <div style={{ padding: "6px 10px", fontSize: 11, color: "var(--color-text-secondary)" }}>{r.label}</div>
                    <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-secondary)" }}>0x{r.original}</div>
                    <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: r.pass ? "#0F6E56" : "#A32D2D" }}>0x{r.recovered}</div>
                    <div style={{ padding: "6px 10px" }}><TestBadge pass={r.pass} /></div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
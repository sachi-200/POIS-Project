// ═══════════════════════════════════════════════════════════════════════════════
// PA #20 — Secure Multi-Party Computation (Interactive Demo)
// ═══════════════════════════════════════════════════════════════════════════════

import { useState } from "react";
import {
  createMillionaireCircuit,
  createEqualityCircuit,
  createAdditionCircuit,
  Secure_Eval,
} from "./crypto.js";
import {
  FieldLabel,
  SectionHeading,
} from "../shared/ui.jsx";

function ActionButton({ children, onClick, disabled, tone = "teal" }) {
  const palette = tone === "red"
    ? { bg: "#FCEBEB", border: "#E24B4A", text: "#A32D2D" }
    : tone === "orange"
      ? { bg: "#FEF3E2", border: "#E8A820", text: "#7A5200" }
      : tone === "purple"
        ? { bg: "#EEEDFE", border: "#7F77DD", text: "#3C3489" }
        : { bg: "#E1F5EE", border: "#1D9E75", text: "#0F6E56" };

  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        padding: "8px 14px",
        fontSize: 12,
        fontWeight: 500,
        border: `0.5px solid ${palette.border}`,
        borderRadius: "var(--border-radius-md)",
        background: palette.bg,
        color: palette.text,
        cursor: disabled ? "not-allowed" : "pointer",
        fontFamily: "var(--font-sans)",
      }}
    >
      {children}
    </button>
  );
}

function PA20Panel() {
  const [x, setX] = useState(7);
  const [y, setY] = useState(12);
  const [result, setResult] = useState(null);

  function runMillionaire() {
    const circuit = createMillionaireCircuit(4);
    const xBits = toBits(x, 4);
    const yBits = toBits(y, 4);
    const res = Secure_Eval(circuit, xBits, yBits);
    setResult({ type: 'millionaire', x, y, result: res[0] ? 'Alice richer' : 'Bob richer' });
  }

  function toBits(num, n) {
    const bits = [];
    for (let i = 0; i < n; i++) {
      bits.push((num >> i) & 1);
    }
    return bits;
  }

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>
      {/* Header */}
      <div style={{ padding: "10px 16px", background: "#FAECE7", borderBottom: "0.5px solid #D85A30", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: "#993C1D" }}>PA #20 — Secure Multi-Party Computation (Yao/GMW)</div>
      </div>

      <div style={{ padding: "16px" }}>
        {/* Millionaire */}
        <div style={{ marginBottom: 16 }}>
          <SectionHeading>Millionaire's Problem</SectionHeading>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
            <div>
              <FieldLabel>Alice's wealth x</FieldLabel>
              <input type="range" min={0} max={15} value={x} onChange={e => setX(Number(e.target.value))} style={{ width: "100%" }} />
              <div style={{ textAlign: "center", fontSize: 12 }}>{x}</div>
            </div>
            <div>
              <FieldLabel>Bob's wealth y</FieldLabel>
              <input type="range" min={0} max={15} value={y} onChange={e => setY(Number(e.target.value))} style={{ width: "100%" }} />
              <div style={{ textAlign: "center", fontSize: 12 }}>{y}</div>
            </div>
          </div>
          <ActionButton onClick={runMillionaire}>Who is richer?</ActionButton>
          {result && result.type === 'millionaire' && (
            <div style={{ marginTop: 8, padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#E1F5EE", border: "0.5px solid #1D9E75", color: "#0F6E56" }}>
              {result.result}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default PA20Panel;
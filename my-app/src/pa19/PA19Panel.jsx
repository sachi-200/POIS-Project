// ═══════════════════════════════════════════════════════════════════════════════
// PA #19 — Secure AND Gate (Interactive Demo)
// ═══════════════════════════════════════════════════════════════════════════════

import { useState } from "react";
import {
  Secure_AND,
  Secure_XOR,
  Secure_NOT,
  testANDTruthTable,
  testXORTruthTable,
} from "./crypto.js";
import {
  FieldLabel,
  SectionHeading,
  TestBadge,
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

function PA19Panel() {
  const [a, setA] = useState(0);
  const [b, setB] = useState(0);
  const [andResult, setAndResult] = useState(null);
  const [xorResult, setXorResult] = useState(null);
  const [andTest, setAndTest] = useState(null);
  const [xorTest, setXorTest] = useState(null);

  function computeAND() {
    const result = Secure_AND(a, b);
    setAndResult(result);
  }

  function computeXOR() {
    const result = Secure_XOR(a, b);
    setXorResult(result);
  }

  function runANDTest() {
    const result = testANDTruthTable(50);
    setAndTest(result);
  }

  function runXORTest() {
    const result = testXORTruthTable(50);
    setXorTest(result);
  }

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>
      {/* Header */}
      <div style={{ padding: "10px 16px", background: "#E1F5EE", borderBottom: "0.5px solid #1D9E75", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: "#0F6E56" }}>PA #19 — Secure AND & XOR Gates</div>
      </div>

      <div style={{ padding: "16px" }}>
        {/* Inputs */}
        <div style={{ marginBottom: 16 }}>
          <SectionHeading>Inputs</SectionHeading>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div>
              <FieldLabel>Alice's bit a</FieldLabel>
              <select value={a} onChange={e => setA(Number(e.target.value))} style={{ width: "100%", padding: "8px 12px", border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)" }}>
                <option value={0}>0</option>
                <option value={1}>1</option>
              </select>
            </div>
            <div>
              <FieldLabel>Bob's bit b</FieldLabel>
              <select value={b} onChange={e => setB(Number(e.target.value))} style={{ width: "100%", padding: "8px 12px", border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)" }}>
                <option value={0}>0</option>
                <option value={1}>1</option>
              </select>
            </div>
          </div>
        </div>

        {/* Compute */}
        <div style={{ marginBottom: 16 }}>
          <SectionHeading>Compute Secure Gates</SectionHeading>
          <div style={{ display: "flex", gap: 10, marginBottom: 12 }}>
            <ActionButton onClick={computeAND}>Compute AND</ActionButton>
            <ActionButton onClick={computeXOR}>Compute XOR</ActionButton>
          </div>
          {andResult !== null && (
            <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#E1F5EE", border: "0.5px solid #1D9E75", color: "#0F6E56", marginBottom: 8 }}>
              AND(a={a}, b={b}) = {andResult}
            </div>
          )}
          {xorResult !== null && (
            <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#EEEDFE", border: "0.5px solid #7F77DD", color: "#3C3489" }}>
              XOR(a={a}, b={b}) = {xorResult}
            </div>
          )}
        </div>

        {/* Tests */}
        <div style={{ marginBottom: 16 }}>
          <SectionHeading>Truth Table Tests</SectionHeading>
          <div style={{ display: "flex", gap: 10, marginBottom: 12 }}>
            <ActionButton onClick={runANDTest}>Test AND (200 trials)</ActionButton>
            <ActionButton onClick={runXORTest}>Test XOR (200 trials)</ActionButton>
          </div>
          {andTest && (
            <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#E1F5EE", border: "0.5px solid #1D9E75", color: "#0F6E56", marginBottom: 8 }}>
              AND accuracy: {andTest.accuracy}%
            </div>
          )}
          {xorTest && (
            <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#EEEDFE", border: "0.5px solid #7F77DD", color: "#3C3489" }}>
              XOR accuracy: {xorTest.accuracy}%
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default PA19Panel;
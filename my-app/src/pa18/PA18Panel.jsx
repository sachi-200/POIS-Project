// ═══════════════════════════════════════════════════════════════════════════════
// PA #18 — Oblivious Transfer (Interactive Demo)
// ═══════════════════════════════════════════════════════════════════════════════

import { useState } from "react";
import {
  OT_Receiver_Step1,
  OT_Sender_Step,
  OT_Receiver_Step2,
  otDemo,
  otCorrectnessTrials,
  receiverPrivacyDemo,
  senderPrivacyDemo,
  parseMessageRepresentative,
} from "./crypto.js";
import {
  FieldLabel,
  SectionHeading,
  TextInput,
  MonoBox,
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

function PA18Panel() {
  const [b, setB] = useState(0);
  const [m0, setM0] = useState("secret0");
  const [m1, setM1] = useState("secret1");
  const [otResult, setOtResult] = useState(null);
  const [trialsResult, setTrialsResult] = useState(null);

  function runOT() {
    const result = otDemo(b, m0, m1);
    setOtResult(result);
  }

  function runTrials() {
    const result = otCorrectnessTrials(100);
    setTrialsResult(result);
  }

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>
      {/* Header */}
      <div style={{ padding: "10px 16px", background: "#EEEDFE", borderBottom: "0.5px solid #7F77DD", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: "#3C3489" }}>PA #18 — Oblivious Transfer (OT)</div>
      </div>

      <div style={{ padding: "16px" }}>
        {/* Inputs */}
        <div style={{ marginBottom: 16 }}>
          <SectionHeading>OT Setup</SectionHeading>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 12 }}>
            <div>
              <FieldLabel>Choice b</FieldLabel>
              <select value={b} onChange={e => setB(Number(e.target.value))} style={{ width: "100%", padding: "8px 12px", border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)" }}>
                <option value={0}>0</option>
                <option value={1}>1</option>
              </select>
            </div>
            <div>
              <FieldLabel>Message m₀</FieldLabel>
              <TextInput value={m0} onChange={setM0} placeholder="secret0" />
            </div>
            <div>
              <FieldLabel>Message m₁</FieldLabel>
              <TextInput value={m1} onChange={setM1} placeholder="secret1" />
            </div>
          </div>
          <ActionButton onClick={runOT}>Run OT Protocol</ActionButton>
        </div>

        {/* Result */}
        {otResult && (
          <div style={{ marginBottom: 16 }}>
            <SectionHeading>OT Result</SectionHeading>
            <div style={{ padding: "12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 8 }}>
              <div>Receiver chose b = {otResult.b}</div>
              <div>Received m_b = 0x{otResult.result.toString(16)}</div>
              <TestBadge pass={otResult.correct} />
            </div>
            <div style={{ fontSize: 11, color: "var(--color-text-secondary)" }}>
              Sender's messages hidden: m_{1-b} = ??
            </div>
          </div>
        )}

        {/* Correctness */}
        <div style={{ marginBottom: 16 }}>
          <SectionHeading>Correctness Trials</SectionHeading>
          <ActionButton onClick={runTrials}>Run 100 Trials</ActionButton>
          {trialsResult && (
            <div style={{ marginTop: 8 }}>
              <div>Success rate: {trialsResult.successRate}%</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default PA18Panel;
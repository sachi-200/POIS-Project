// ═══════════════════════════════════════════════════════════════════════════════
// PA #17 — CCA-Secure PKC (Interactive Demo)
// ═══════════════════════════════════════════════════════════════════════════════

import { useState } from "react";
import {
  ccaKeygen,
  CCA_PKC_Enc,
  CCA_PKC_Dec,
  ccaEncryptDecryptDemo,
  tamperCiphertext,
  malleabilityAttackDemo,
  runIndCca2Game,
  truncMiddle,
} from "./crypto.js";
import {
  FieldLabel,
  SectionHeading,
  TextInput,
  MonoBox,
  TestBadge,
} from "../shared/ui.jsx";

function StatCard({ label, value, accent }) {
  return (
    <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
      <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>{label}</div>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, fontWeight: 500, color: accent || "var(--color-text-primary)", wordBreak: "break-all" }}>{value}</div>
    </div>
  );
}

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

function PA17Panel() {
  const [keys, setKeys] = useState(null);
  const [message, setMessage] = useState("hello world");
  const [encResult, setEncResult] = useState(null);
  const [tamperedResult, setTamperedResult] = useState(null);
  const [ccaGameResult, setCcaGameResult] = useState(null);

  function generateKeys() {
    setKeys(ccaKeygen());
    setEncResult(null);
    setTamperedResult(null);
  }

  function doEncrypt() {
    if (!keys) return;
    const result = ccaEncryptDecryptDemo(keys, message);
    setEncResult(result);
    setTamperedResult(null);
  }

  function doTamper() {
    if (!encResult) return;
    const tamperedC_E = tamperCiphertext(encResult.ciphertext);
    const dec = CCA_PKC_Dec(keys.sk_enc, keys.vk_sign, tamperedC_E, encResult.signature);
    setTamperedResult({ tamperedC_E, dec });
  }

  function runCcaGame() {
    if (!keys) return;
    const result = runIndCca2Game(keys, "message0", "message1", 50);
    setCcaGameResult(result);
  }

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>
      {/* Header */}
      <div style={{ padding: "10px 16px", background: "#FAECE7", borderBottom: "0.5px solid #D85A30", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: "#993C1D" }}>PA #17 — CCA-Secure PKC (Sign-then-Encrypt)</div>
        <ActionButton onClick={generateKeys} tone="purple">Generate Keys</ActionButton>
      </div>

      <div style={{ padding: "16px" }}>
        {/* Keys */}
        {keys && (
          <div style={{ marginBottom: 16 }}>
            <SectionHeading>Keys Generated</SectionHeading>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              <StatCard label="ElGamal pk (h)" value={truncMiddle(keys.pk_enc.h)} />
              <StatCard label="RSA vk (N,e)" value={truncMiddle(keys.vk_sign.N)} />
            </div>
          </div>
        )}

        {/* Encrypt */}
        <div style={{ marginBottom: 16 }}>
          <SectionHeading>Encrypt-then-Sign</SectionHeading>
          <div style={{ marginBottom: 12 }}>
            <FieldLabel>Message m</FieldLabel>
            <TextInput value={message} onChange={setMessage} placeholder="e.g. hello world" />
          </div>
          <ActionButton onClick={doEncrypt} disabled={!keys}>Encrypt & Sign</ActionButton>
        </div>

        {/* Result */}
        {encResult && (
          <div style={{ marginBottom: 16 }}>
            <SectionHeading>Ciphertext & Signature</SectionHeading>
            <div style={{ padding: "12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 8 }}>
              <div style={{ fontSize: 11, color: "var(--color-text-secondary)", marginBottom: 4 }}>C_E = (c1, c2)</div>
              <MonoBox>c1: 0x{encResult.ciphertext.c1.toString(16)}</MonoBox>
              <MonoBox>c2: 0x{encResult.ciphertext.c2.toString(16)}</MonoBox>
              <div style={{ fontSize: 11, color: "var(--color-text-secondary)", marginTop: 8, marginBottom: 4 }}>σ (signature)</div>
              <MonoBox>0x{encResult.signature.sigmaHex}</MonoBox>
            </div>
            <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: encResult.pass ? "#E1F5EE" : "#FCEBEB", border: `0.5px solid ${encResult.pass ? "#1D9E75" : "#E24B4A"}`, color: encResult.pass ? "#0F6E56" : "#A32D2D" }}>
              Decrypt: {encResult.pass ? `Success — ${encResult.maybeText || "0x" + encResult.decrypted.toString(16)}` : "Failed"}
            </div>
          </div>
        )}

        {/* Tamper */}
        {encResult && (
          <div style={{ marginBottom: 16 }}>
            <SectionHeading>Tamper with Ciphertext</SectionHeading>
            <ActionButton onClick={doTamper} tone="red">Tamper & Try Decrypt</ActionButton>
            {tamperedResult && (
              <div style={{ marginTop: 8, padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A", color: "#A32D2D" }}>
                Signature invalid, decryption aborted, output ⊥
              </div>
            )}
          </div>
        )}

        {/* CCA Game */}
        <div style={{ marginBottom: 16 }}>
          <SectionHeading>IND-CCA2 Game</SectionHeading>
          <ActionButton onClick={runCcaGame} disabled={!keys}>Run CCA2 Simulation</ActionButton>
          {ccaGameResult && (
            <div style={{ marginTop: 8 }}>
              <StatCard label="Advantage" value={ccaGameResult.advantage} accent="#993C1D" />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default PA17Panel;
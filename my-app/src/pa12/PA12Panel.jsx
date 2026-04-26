// ═══════════════════════════════════════════════════════════════════════════════
// PA #12 — Textbook RSA (Interactive Demo)
//
// Demo: Textbook RSA determinism attack.
//   • Student types a short message (e.g., "yes" or "no", simulating a vote).
//   • Click "Encrypt twice." Both ciphertexts shown — identical. Red banner.
//   • Switch to PKCS#1 v1.5 mode: click "Encrypt twice" again. Ciphertexts differ.
//   • "Padding bytes" panel shows the random PS bytes that differ.
//   • Toy parameters: 512-bit N for fast in-browser computation.
// ═══════════════════════════════════════════════════════════════════════════════

import { useState } from "react";
import {
  rsaKeygen,
  rsaEnc,
  rsaDec,
  pkcs15Enc,
  pkcs15Dec,
  determinismAttack,
  bleichenbacherDemo,
} from "./crypto.js";
import {
  FieldLabel,
  SectionHeading,
  TextInput,
  MonoBox,
  ToggleBar,
} from "../shared/ui.jsx";

// ── Helpers ──────────────────────────────────────────────────────────────────

function StatCard({ label, value, accent }) {
  return (
    <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
      <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>{label}</div>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, fontWeight: 500, color: accent || "var(--color-text-primary)", wordBreak: "break-all" }}>{value}</div>
    </div>
  );
}

function truncHex(n, len = 32) {
  if (n === null || n === undefined) return "—";
  const s = typeof n === "bigint" ? n.toString(16) : String(n);
  return s.length > len ? `${s.slice(0, len)}…` : s;
}

// ── Main Panel ───────────────────────────────────────────────────────────────

export default function PA12Panel() {
  // ── Key state ─────────────────────────────────────────────────────────────
  const [keys, setKeys] = useState(null);
  const [keyBits, setKeyBits] = useState("512");
  const [generating, setGenerating] = useState(false);

  // ── Determinism attack state ──────────────────────────────────────────────
  const [message, setMessage] = useState("yes");
  const [attackResult, setAttackResult] = useState(null);
  const [encrypting, setEncrypting] = useState(false);

  // ── Manual enc/dec state ──────────────────────────────────────────────────
  const [encMode, setEncMode] = useState("textbook");
  const [encInput, setEncInput] = useState("hello");
  const [encResult, setEncResult] = useState(null);
  const [decInput, setDecInput] = useState("");
  const [decResult, setDecResult] = useState(null);

  // ── Bleichenbacher state ──────────────────────────────────────────────────
  const [bleichResult, setBleichResult] = useState(null);
  const [bleichRunning, setBleichRunning] = useState(false);

  // ── Handlers ──────────────────────────────────────────────────────────────

  function generateKeys() {
    setGenerating(true);
    setAttackResult(null);
    setEncResult(null);
    setDecResult(null);
    setBleichResult(null);
    setTimeout(() => {
      try {
        const bits = Number.parseInt(keyBits, 10) || 512;
        const k = rsaKeygen(bits);
        setKeys(k);
      } catch (e) {
        setKeys({ error: e.message });
      }
      setGenerating(false);
    }, 10);
  }

  function runDeterminismAttack() {
    if (!keys || keys.error) return;
    setEncrypting(true);
    setTimeout(() => {
      try {
        const pk = { N: keys.N, e: keys.e };
        const result = determinismAttack(pk, message);
        setAttackResult(result);
      } catch (e) {
        setAttackResult({ error: e.message });
      }
      setEncrypting(false);
    }, 10);
  }

  function doEncrypt() {
    if (!keys || keys.error) return;
    try {
      const pk = { N: keys.N, e: keys.e };
      if (encMode === "textbook") {
        const res = rsaEnc(pk, encInput);
        setEncResult({ C: res.C, mode: "textbook" });
        setDecInput(res.C.toString(16));
      } else {
        const res = pkcs15Enc(pk, encInput);
        setEncResult({ C: res.C, psHex: res.psHex, emHex: res.emHex, mode: "pkcs15" });
        setDecInput(res.C.toString(16));
      }
    } catch (e) {
      setEncResult({ error: e.message });
    }
  }

  function doDecrypt() {
    if (!keys || keys.error || !decInput.trim()) return;
    try {
      const sk = { N: keys.N, d: keys.d };
      const c = BigInt("0x" + decInput.trim());
      if (encMode === "textbook") {
        const res = rsaDec(sk, c);
        setDecResult({ M: res.M, mHex: res.mHex, mStr: res.mStr, mode: "textbook" });
      } else {
        const res = pkcs15Dec(sk, c);
        setDecResult({ valid: res.valid, mStr: res.mStr, mHex: res.mHex, psHex: res.psHex, emHex: res.emHex, mode: "pkcs15" });
      }
    } catch (e) {
      setDecResult({ error: e.message });
    }
  }

  function runBleichenbacher() {
    if (!keys || keys.error || bleichRunning) return;
    setBleichRunning(true);
    setBleichResult(null);
    setTimeout(() => {
      try {
        const pk = { N: keys.N, e: keys.e };
        const sk = { N: keys.N, d: keys.d };
        const enc = pkcs15Enc(pk, "secret");
        const result = bleichenbacherDemo(pk, sk, enc.C, 200);
        setBleichResult(result);
      } catch (e) {
        setBleichResult({ error: e.message });
      }
      setBleichRunning(false);
    }, 10);
  }

  // ── Render ────────────────────────────────────────────────────────────────

  const hdr = { bg: "#FEF3E2", border: "#E8A820", text: "#7A5200" };

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>

      {/* ── Header ── */}
      <div style={{ padding: "10px 16px", background: hdr.bg, borderBottom: `0.5px solid ${hdr.border}`, display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: hdr.text }}>
          PA #12 — Textbook RSA
        </div>
        <div style={{ fontSize: 10, color: "#7A5200", fontFamily: "var(--font-mono)" }}>
          C = M<sup>e</sup> mod N
        </div>
      </div>

      <div style={{ padding: "16px" }}>

        {/* ── Description ── */}
        <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", marginBottom: 14, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
          Textbook RSA is <strong>deterministic</strong> — encrypting the same plaintext always produces the same ciphertext.
          This breaks CPA security. PKCS#1 v1.5 padding injects random bytes to prevent this.
          Never use raw RSA in practice; always apply padding.
        </div>

        {/* ═══ Section 1: Key Generation ═══ */}
        <SectionHeading>RSA key generation (using PA#13 Miller-Rabin)</SectionHeading>

        <div style={{ display: "flex", gap: 10, alignItems: "end", marginBottom: 14, flexWrap: "wrap" }}>
          <div style={{ width: 140 }}>
            <FieldLabel>Key size (bits)</FieldLabel>
            <TextInput value={keyBits} onChange={setKeyBits} placeholder="512" />
          </div>
          <button
            onClick={generateKeys}
            disabled={generating}
            style={{
              padding: "8px 20px", fontSize: 12, fontWeight: 500,
              border: `0.5px solid ${hdr.border}`, borderRadius: "var(--border-radius-md)",
              background: generating ? "#D3D1C7" : hdr.bg,
              color: generating ? "#888780" : hdr.text,
              cursor: generating ? "default" : "pointer", fontFamily: "var(--font-sans)",
            }}
          >
            {generating ? "Generating…" : "Generate RSA keys"}
          </button>
        </div>

        {keys && !keys.error && (
          <div style={{ marginBottom: 14 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))", gap: 8, marginBottom: 8 }}>
              <StatCard label="Key bits" value={keys.bits} />
              <StatCard label="e" value="65537" />
              <StatCard label="Time" value={`${keys.timeMs.toFixed(1)} ms`} />
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              <MonoBox maxH={40}>N = 0x{truncHex(keys.N, 64)}</MonoBox>
              <MonoBox maxH={40}>p = 0x{truncHex(keys.p, 64)}</MonoBox>
              <MonoBox maxH={40}>q = 0x{truncHex(keys.q, 64)}</MonoBox>
              <MonoBox maxH={40}>d = 0x{truncHex(keys.d, 64)}</MonoBox>
            </div>
          </div>
        )}
        {keys && keys.error && (
          <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A", color: "#A32D2D", fontSize: 11, marginBottom: 14 }}>
            Error: {keys.error}
          </div>
        )}

        {/* ═══ Section 2: Determinism Attack Demo ═══ */}
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", marginTop: 16, paddingTop: 14 }}>
          <SectionHeading>Determinism attack — encrypt the same message twice</SectionHeading>
          <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", marginBottom: 10, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
            Type a short message (e.g., "yes" or "no", simulating a vote). Click "Encrypt twice" to see that textbook RSA produces
            identical ciphertexts, leaking information. Then compare with PKCS#1 v1.5 which randomizes each encryption.
          </div>

          <div style={{ display: "flex", gap: 10, alignItems: "end", marginBottom: 10, flexWrap: "wrap" }}>
            <div style={{ width: 200 }}>
              <FieldLabel>Message (short string)</FieldLabel>
              <TextInput value={message} onChange={setMessage} placeholder="yes" />
            </div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              <button onClick={() => setMessage("yes")} style={presetBtn("#E1F5EE", "#1D9E75", "#0F6E56")}>yes</button>
              <button onClick={() => setMessage("no")} style={presetBtn("#FCEBEB", "#E24B4A", "#A32D2D")}>no</button>
              <button onClick={() => setMessage("approve")} style={presetBtn("#E6F1FB", "#378ADD", "#185FA5")}>approve</button>
              <button onClick={() => setMessage("reject")} style={presetBtn("#FAEEDA", "#BA7517", "#854F0B")}>reject</button>
            </div>
          </div>

          <button
            onClick={runDeterminismAttack}
            disabled={encrypting || !keys || !!keys?.error}
            style={{
              padding: "8px 20px", fontSize: 12, fontWeight: 500,
              border: "0.5px solid #E24B4A", borderRadius: "var(--border-radius-md)",
              background: encrypting ? "#D3D1C7" : "#FCEBEB",
              color: encrypting ? "#888780" : "#A32D2D",
              cursor: (encrypting || !keys) ? "default" : "pointer", fontFamily: "var(--font-sans)",
              marginBottom: 14,
            }}
          >
            {encrypting ? "Encrypting…" : "Encrypt twice"}
          </button>

          {attackResult && !attackResult.error && (
            <div>
              {/* Textbook RSA result */}
              <SectionHeading>Textbook RSA — two encryptions</SectionHeading>
              <div style={{ display: "flex", flexDirection: "column", gap: 4, marginBottom: 8 }}>
                <MonoBox maxH={40}>C₁ = 0x{truncHex(attackResult.textbook.c1, 64)}</MonoBox>
                <MonoBox maxH={40}>C₂ = 0x{truncHex(attackResult.textbook.c2, 64)}</MonoBox>
              </div>
              <div style={{
                padding: "10px 14px", borderRadius: "var(--border-radius-md)",
                background: attackResult.textbook.identical ? "#FCEBEB" : "#E1F5EE",
                border: `0.5px solid ${attackResult.textbook.identical ? "#E24B4A" : "#1D9E75"}`,
                color: attackResult.textbook.identical ? "#A32D2D" : "#0F6E56",
                fontSize: 12, fontWeight: 500, marginBottom: 14,
              }}>
                {attackResult.textbook.identical
                  ? "✗ Identical ciphertexts: plaintext leaked!"
                  : "✓ Ciphertexts differ (unexpected for textbook RSA)"}
              </div>

              {/* PKCS#1 v1.5 result */}
              <SectionHeading>PKCS#1 v1.5 — two encryptions</SectionHeading>
              <div style={{ display: "flex", flexDirection: "column", gap: 4, marginBottom: 8 }}>
                <MonoBox maxH={40}>C₁ = 0x{truncHex(attackResult.pkcs15.c1, 64)}</MonoBox>
                <MonoBox maxH={40}>C₂ = 0x{truncHex(attackResult.pkcs15.c2, 64)}</MonoBox>
              </div>
              <div style={{
                padding: "10px 14px", borderRadius: "var(--border-radius-md)",
                background: attackResult.pkcs15.identical ? "#FCEBEB" : "#E1F5EE",
                border: `0.5px solid ${attackResult.pkcs15.identical ? "#E24B4A" : "#1D9E75"}`,
                color: attackResult.pkcs15.identical ? "#A32D2D" : "#0F6E56",
                fontSize: 12, fontWeight: 500, marginBottom: 10,
              }}>
                {attackResult.pkcs15.identical
                  ? "✗ Identical ciphertexts (unexpected for PKCS#1 v1.5)"
                  : "✓ Ciphertexts differ each time — random PS prevents determinism!"}
              </div>

              {/* Padding bytes panel */}
              <SectionHeading>Padding bytes (PS) — random nonzero bytes that differ</SectionHeading>
              <div style={{ display: "flex", flexDirection: "column", gap: 4, marginBottom: 14 }}>
                <MonoBox maxH={40}>PS₁ = {attackResult.pkcs15.ps1Hex}</MonoBox>
                <MonoBox maxH={40}>PS₂ = {attackResult.pkcs15.ps2Hex}</MonoBox>
              </div>
            </div>
          )}
          {attackResult && attackResult.error && (
            <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A", color: "#A32D2D", fontSize: 11, marginBottom: 14 }}>
              Error: {attackResult.error}
            </div>
          )}
        </div>

        {/* ═══ Section 3: Manual Enc/Dec ═══ */}
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", marginTop: 16, paddingTop: 14 }}>
          <SectionHeading>Encrypt / Decrypt — Textbook vs PKCS#1 v1.5</SectionHeading>

          <div style={{ marginBottom: 10, maxWidth: 300 }}>
            <ToggleBar value={encMode} onChange={v => { setEncMode(v); setEncResult(null); setDecResult(null); }} options={[
              { value: "textbook", label: "Textbook", activeStyle: { bg: "#FEF3E2", border: "#E8A820", color: "#7A5200" } },
              { value: "pkcs15", label: "PKCS#1 v1.5", activeStyle: { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" } },
            ]} />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 10 }}>
            <div>
              <FieldLabel>Plaintext (string)</FieldLabel>
              <TextInput value={encInput} onChange={setEncInput} placeholder="hello" />
              <button onClick={doEncrypt} disabled={!keys || !!keys?.error} style={{ marginTop: 8, padding: "7px 14px", fontSize: 12, fontWeight: 500, border: `0.5px solid ${hdr.border}`, borderRadius: "var(--border-radius-md)", background: hdr.bg, color: hdr.text, cursor: keys ? "pointer" : "default", fontFamily: "var(--font-sans)" }}>
                Encrypt ({encMode === "textbook" ? "M^e mod N" : "PKCS#1 v1.5"})
              </button>
            </div>
            <div>
              <FieldLabel>Ciphertext (hex)</FieldLabel>
              <TextInput value={decInput} onChange={setDecInput} placeholder="paste hex ciphertext" />
              <button onClick={doDecrypt} disabled={!keys || !!keys?.error} style={{ marginTop: 8, padding: "7px 14px", fontSize: 12, fontWeight: 500, border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", color: "var(--color-text-primary)", cursor: keys ? "pointer" : "default", fontFamily: "var(--font-sans)" }}>
                Decrypt ({encMode === "textbook" ? "C^d mod N" : "PKCS#1 v1.5"})
              </button>
            </div>
          </div>

          {encResult && !encResult.error && (
            <div style={{ marginBottom: 8 }}>
              <MonoBox maxH={60}>C = 0x{truncHex(encResult.C, 80)}</MonoBox>
              {encResult.psHex && <div style={{ marginTop: 4 }}><MonoBox maxH={40}>PS = {encResult.psHex}</MonoBox></div>}
            </div>
          )}
          {encResult && encResult.error && (
            <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A", color: "#A32D2D", fontSize: 11, marginBottom: 8 }}>Error: {encResult.error}</div>
          )}
          {decResult && !decResult.error && (
            <div style={{ marginBottom: 8 }}>
              {decResult.mode === "textbook" ? (
                <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#E1F5EE", border: "0.5px solid #1D9E75", color: "#0F6E56", fontSize: 12 }}>
                  Decrypted: <strong style={{ fontFamily: "var(--font-mono)" }}>{decResult.mStr || `0x${decResult.mHex}`}</strong>
                </div>
              ) : (
                <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: decResult.valid ? "#E1F5EE" : "#FCEBEB", border: `0.5px solid ${decResult.valid ? "#1D9E75" : "#E24B4A"}`, color: decResult.valid ? "#0F6E56" : "#A32D2D", fontSize: 12 }}>
                  {decResult.valid
                    ? <>Decrypted: <strong style={{ fontFamily: "var(--font-mono)" }}>{decResult.mStr || `0x${decResult.mHex}`}</strong></>
                    : "⊥ Malformed padding — decryption failed"}
                </div>
              )}
            </div>
          )}
          {decResult && decResult.error && (
            <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A", color: "#A32D2D", fontSize: 11, marginBottom: 8 }}>Error: {decResult.error}</div>
          )}
        </div>

        {/* ═══ Section 4: Bleichenbacher Demo ═══ */}
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", marginTop: 16, paddingTop: 14 }}>
          <SectionHeading>Bleichenbacher padding oracle attack (simplified demo)</SectionHeading>
          <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", marginBottom: 10, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
            In 1998, Bleichenbacher showed that a padding oracle — a service revealing whether a ciphertext decrypts to valid PKCS#1 v1.5 format —
            can be exploited to decrypt any RSA ciphertext with ≈2²⁰ adaptive queries. This demo shows the blinding phase on a toy 512-bit key.
          </div>

          <button
            onClick={runBleichenbacher}
            disabled={bleichRunning || !keys || !!keys?.error}
            style={{
              padding: "7px 14px", fontSize: 12, fontWeight: 500,
              border: "0.5px solid #E24B4A", borderRadius: "var(--border-radius-md)",
              background: bleichRunning ? "#D3D1C7" : "#FCEBEB",
              color: bleichRunning ? "#888780" : "#A32D2D",
              cursor: (bleichRunning || !keys) ? "default" : "pointer", fontFamily: "var(--font-sans)",
              marginBottom: 14,
            }}
          >
            {bleichRunning ? "Running…" : "Run Bleichenbacher demo"}
          </button>

          {bleichResult && !bleichResult.error && (
            <div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))", gap: 8, marginBottom: 10 }}>
                <StatCard label="Oracle calls" value={bleichResult.oracleCallCount} />
                <StatCard label="Valid padding" value={bleichResult.validCount} />
                <StatCard label="First s₁" value={bleichResult.s1 || "—"} />
                <StatCard label="k (bytes)" value={bleichResult.k} />
              </div>
              <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A", color: "#A32D2D", fontSize: 11, lineHeight: 1.7, marginBottom: 10 }}>
                {bleichResult.explanation}
              </div>
              {bleichResult.queries.length > 0 && (
                <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", overflow: "hidden", maxHeight: 200, overflowY: "auto" }}>
                  <div style={{ display: "grid", gridTemplateColumns: "60px 1fr 80px 120px", background: "var(--color-background-secondary)", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
                    {["s", "c' (truncated)", "Valid?", "Phase"].map((h, i) => (
                      <div key={i} style={{ padding: "6px 10px", fontSize: 10, fontWeight: 500, color: "var(--color-text-secondary)", textTransform: "uppercase" }}>{h}</div>
                    ))}
                  </div>
                  {bleichResult.queries.slice(0, 20).map((q, i) => (
                    <div key={i} style={{ display: "grid", gridTemplateColumns: "60px 1fr 80px 120px", borderBottom: "0.5px solid var(--color-border-tertiary)", background: q.valid ? "#E1F5EE" : "transparent" }}>
                      <div style={{ padding: "5px 10px", fontFamily: "var(--font-mono)", fontSize: 11 }}>{q.s}</div>
                      <div style={{ padding: "5px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-secondary)" }}>{q.cPrimeHex}</div>
                      <div style={{ padding: "5px 10px", fontSize: 11, fontWeight: 500, color: q.valid ? "#0F6E56" : "#A32D2D" }}>{q.valid ? "YES ✓" : "NO"}</div>
                      <div style={{ padding: "5px 10px", fontSize: 10, color: "var(--color-text-secondary)" }}>{q.phase}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
          {bleichResult && bleichResult.error && (
            <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A", color: "#A32D2D", fontSize: 11 }}>Error: {bleichResult.error}</div>
          )}
        </div>

      </div>
    </div>
  );
}

// ── Preset button style helper ───────────────────────────────────────────────

function presetBtn(bg, border, color) {
  return {
    padding: "5px 10px", fontSize: 11, fontWeight: 500,
    border: `0.5px solid ${border}`, borderRadius: "var(--border-radius-md)",
    background: bg, color: color, cursor: "pointer",
    fontFamily: "var(--font-sans)", whiteSpace: "nowrap",
  };
}

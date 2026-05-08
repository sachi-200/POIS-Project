// ═══════════════════════════════════════════════════════════════════════════════
// PA #14 — CRT & Breaking Textbook RSA (Interactive Demo)
// ═══════════════════════════════════════════════════════════════════════════════

import { useState } from "react";
import {
  crt,
  verifyCrtSolution,
  rsaKeygen,
  decryptCompare,
  testCrtRsaCorrectness,
  benchmarkRsaCrt,
  runHastadDemo,
  runPkcsPaddingContrast,
  truncMiddle,
} from "./crypto.js";
import {
  FieldLabel,
  SectionHeading,
  TextInput,
  MonoBox,
} from "../shared/ui.jsx";

function StatCard({ label, value, accent }) {
  return (
    <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
      <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>{label}</div>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, fontWeight: 500, color: accent || "var(--color-text-primary)", wordBreak: "break-all" }}>{value}</div>
    </div>
  );
}

function ActionButton({ children, onClick, disabled, tone = "blue" }) {
  const palette = tone === "orange"
    ? { bg: "#FEF3E2", border: "#E8A820", text: "#7A5200" }
    : tone === "green"
      ? { bg: "#E1F5EE", border: "#1D9E75", text: "#0F6E56" }
      : { bg: "#E6F1FB", border: "#378ADD", text: "#185FA5" };

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
        background: disabled ? "#E5E2D8" : palette.bg,
        color: disabled ? "#85827A" : palette.text,
        cursor: disabled ? "default" : "pointer",
        fontFamily: "var(--font-sans)",
      }}
    >
      {children}
    </button>
  );
}

function parseBigIntList(input) {
  return input
    .split(/[,.\s]+/)
    .map(s => s.trim())
    .filter(Boolean)
    .map(s => BigInt(s));
}

function HexLine({ label, value }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "130px 1fr", gap: 8, fontSize: 11, marginBottom: 4 }}>
      <span style={{ color: "var(--color-text-secondary)" }}>{label}</span>
      <span style={{ fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>{value}</span>
    </div>
  );
}

export default function PA14Panel() {
  const hdr = { bg: "#EAF4FF", border: "#4C9CEB", text: "#185FA5" };

  // ── CRT solver state ─────────────────────────────────────────────────────
  const [residues, setResidues] = useState("2, 3, 2");
  const [moduli, setModuli] = useState("3, 5, 7");
  const [crtResult, setCrtResult] = useState(null);

  // ── CRT RSA state ────────────────────────────────────────────────────────
  const [keyBits, setKeyBits] = useState("512");
  const [keys, setKeys] = useState(null);
  const [generating, setGenerating] = useState(false);
  const [message, setMessage] = useState("hello");
  const [decryptResult, setDecryptResult] = useState(null);
  const [correctness, setCorrectness] = useState(null);
  const [benchTrials, setBenchTrials] = useState("100");
  const [benchmark, setBenchmark] = useState(null);
  const [running, setRunning] = useState(false);

  // ── Håstad state ─────────────────────────────────────────────────────────
  const [hastadMsg, setHastadMsg] = useState("attack");
  const [hastadBits, setHastadBits] = useState("192");
  const [hastadResult, setHastadResult] = useState(null);
  const [paddingContrast, setPaddingContrast] = useState(null);
  const [hastadRunning, setHastadRunning] = useState(false);

  function runCrt() {
    try {
      const a = parseBigIntList(residues);
      const n = parseBigIntList(moduli);
      const result = crt(a, n);
      setCrtResult({ ...result, checks: verifyCrtSolution(result.x, a, n) });
    } catch (e) {
      setCrtResult({ error: e.message });
    }
  }

  function generateKeys() {
    setGenerating(true);
    setDecryptResult(null);
    setCorrectness(null);
    setBenchmark(null);
    setTimeout(() => {
      try {
        const bits = Number.parseInt(keyBits, 10) || 512;
        setKeys(rsaKeygen(bits));
      } catch (e) {
        setKeys({ error: e.message });
      }
      setGenerating(false);
    }, 10);
  }

  function runDecryptCompare() {
    if (!keys || keys.error) return;
    setRunning(true);
    setTimeout(() => {
      try {
        setDecryptResult(decryptCompare(keys, message));
      } catch (e) {
        setDecryptResult({ error: e.message });
      }
      setRunning(false);
    }, 10);
  }

  function runCorrectness() {
    if (!keys || keys.error) return;
    setRunning(true);
    setTimeout(() => {
      try {
        setCorrectness(testCrtRsaCorrectness(keys, 100));
      } catch (e) {
        setCorrectness({ error: e.message });
      }
      setRunning(false);
    }, 10);
  }

  function runBenchmark() {
    if (!keys || keys.error) return;
    setRunning(true);
    setTimeout(() => {
      try {
        const trials = Number.parseInt(benchTrials, 10) || 100;
        setBenchmark(benchmarkRsaCrt(keys, trials));
      } catch (e) {
        setBenchmark({ error: e.message });
      }
      setRunning(false);
    }, 10);
  }

  function runHastad() {
    setHastadRunning(true);
    setHastadResult(null);
    setPaddingContrast(null);
    setTimeout(() => {
      try {
        const bits = Number.parseInt(hastadBits, 10) || 192;
        setHastadResult(runHastadDemo(hastadMsg, bits, 3n));
      } catch (e) {
        setHastadResult({ error: e.message });
      }
      setHastadRunning(false);
    }, 10);
  }

  function runPaddingContrast() {
    setHastadRunning(true);
    setPaddingContrast(null);
    setTimeout(() => {
      try {
        const bits = Number.parseInt(hastadBits, 10) || 192;
        setPaddingContrast(runPkcsPaddingContrast(hastadMsg, bits, 3n));
      } catch (e) {
        setPaddingContrast({ error: e.message });
      }
      setHastadRunning(false);
    }, 10);
  }

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>
      <div style={{ padding: "10px 16px", background: hdr.bg, borderBottom: `0.5px solid ${hdr.border}`, display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: hdr.text }}>
          PA #14 — CRT & Breaking Textbook RSA
        </div>
        <div style={{ fontSize: 10, color: hdr.text, fontFamily: "var(--font-mono)" }}>
          x ≡ ai mod ni · Garner CRT · Håstad e=3
        </div>
      </div>

      <div style={{ padding: 16 }}>
        <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", marginBottom: 14, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
          CRT is used in two opposite ways: the legitimate receiver uses it to speed up RSA decryption, while an attacker uses it to break textbook RSA when the same short message is broadcast with a small exponent.
        </div>

        {/* Section 1: CRT Solver */}
        <SectionHeading>1. Constructive Chinese Remainder Theorem solver</SectionHeading>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr auto", gap: 10, alignItems: "end", marginBottom: 12 }}>
          <div>
            <FieldLabel>Residues ai</FieldLabel>
            <TextInput value={residues} onChange={setResidues} placeholder="2, 3, 2" />
          </div>
          <div>
            <FieldLabel>Pairwise-coprime moduli ni</FieldLabel>
            <TextInput value={moduli} onChange={setModuli} placeholder="3, 5, 7" />
          </div>
          <ActionButton onClick={runCrt}>Solve CRT</ActionButton>
        </div>

        {crtResult?.error && <MonoBox>{crtResult.error}</MonoBox>}
        {crtResult && !crtResult.error && (
          <div style={{ marginBottom: 18 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10, marginBottom: 10 }}>
              <StatCard label="Solution x" value={crtResult.x.toString()} accent="#185FA5" />
              <StatCard label="Unique modulo N" value={crtResult.modulus.toString()} />
              <StatCard label="Expected example" value="x = 23 mod 105" accent={crtResult.x === 23n ? "#0F6E56" : "#A32D2D"} />
            </div>
            <div style={{ fontSize: 11, color: "var(--color-text-secondary)", marginBottom: 6 }}>Verification:</div>
            <MonoBox>
              {crtResult.checks.map((c) => `x mod ${c.modulus} = ${c.observed} ${c.pass ? "✓" : "✗"} (target ${c.residue})`).join("\n")}
            </MonoBox>
          </div>
        )}

        {/* Section 2: CRT RSA */}
        <SectionHeading>2. CRT-based RSA decryption using PA#12 keys</SectionHeading>
        <div style={{ display: "flex", gap: 10, alignItems: "end", flexWrap: "wrap", marginBottom: 12 }}>
          <div style={{ width: 140 }}>
            <FieldLabel>RSA key size</FieldLabel>
            <TextInput value={keyBits} onChange={setKeyBits} placeholder="512" />
          </div>
          <ActionButton onClick={generateKeys} disabled={generating} tone="green">
            {generating ? "Generating…" : "Generate RSA key"}
          </ActionButton>
          <div style={{ flex: 1, minWidth: 220 }}>
            <FieldLabel>Message</FieldLabel>
            <TextInput value={message} onChange={setMessage} placeholder="hello" />
          </div>
          <ActionButton onClick={runDecryptCompare} disabled={!keys || keys.error || running}>Encrypt + decrypt</ActionButton>
        </div>

        {keys?.error && <MonoBox>{keys.error}</MonoBox>}
        {keys && !keys.error && (
          <div style={{ marginBottom: 12 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10, marginBottom: 10 }}>
              <StatCard label="N bits" value={keys.N.toString(2).length} />
              <StatCard label="e" value={keys.e.toString()} />
              <StatCard label="dp = d mod (p−1)" value={truncMiddle(keys.dp.toString(16), 12)} />
              <StatCard label="dq = d mod (q−1)" value={truncMiddle(keys.dq.toString(16), 12)} />
            </div>
            <MonoBox>{`qInv = q⁻¹ mod p = ${truncMiddle(keys.qInv.toString(16), 28)}\nN    = ${truncMiddle(keys.N.toString(16), 28)}`}</MonoBox>
          </div>
        )}

        {decryptResult?.error && <MonoBox>{decryptResult.error}</MonoBox>}
        {decryptResult && !decryptResult.error && (
          <div style={{ marginBottom: 14 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10, marginBottom: 10 }}>
              <StatCard label="Standard == CRT?" value={decryptResult.equal ? "YES ✓" : "NO ✗"} accent={decryptResult.equal ? "#0F6E56" : "#A32D2D"} />
              <StatCard label="Standard dec time" value={`${decryptResult.standardMs.toFixed(4)} ms`} />
              <StatCard label="CRT dec time" value={`${decryptResult.crtMs.toFixed(4)} ms`} />
              <StatCard label="Single-op speedup" value={`${decryptResult.speedup.toFixed(2)}×`} accent="#185FA5" />
            </div>
            <MonoBox>{`Ciphertext C = ${truncMiddle(decryptResult.ciphertext.toString(16), 36)}\nmp = C^dp mod p = ${truncMiddle(decryptResult.crt.mp.toString(16), 28)}\nmq = C^dq mod q = ${truncMiddle(decryptResult.crt.mq.toString(16), 28)}\nh  = qInv(mp - mq) mod p = ${truncMiddle(decryptResult.crt.h.toString(16), 28)}\nRecovered text = ${decryptResult.crt.mStr ?? "(not UTF-8)"}`}</MonoBox>
          </div>
        )}

        <div style={{ display: "flex", gap: 10, alignItems: "end", flexWrap: "wrap", marginBottom: 12 }}>
          <ActionButton onClick={runCorrectness} disabled={!keys || keys.error || running} tone="green">Run 100-message correctness test</ActionButton>
          <div style={{ width: 140 }}>
            <FieldLabel>Benchmark trials</FieldLabel>
            <TextInput value={benchTrials} onChange={setBenchTrials} placeholder="100" />
          </div>
          <ActionButton onClick={runBenchmark} disabled={!keys || keys.error || running} tone="orange">Benchmark standard vs CRT</ActionButton>
        </div>

        {correctness?.error && <MonoBox>{correctness.error}</MonoBox>}
        {correctness && !correctness.error && (
          <div style={{ marginBottom: 12 }}>
            <StatCard label="Correctness result" value={`${correctness.count - correctness.failureCount}/${correctness.count} passed ${correctness.passed ? "✓" : "✗"}`} accent={correctness.passed ? "#0F6E56" : "#A32D2D"} />
          </div>
        )}

        {benchmark?.error && <MonoBox>{benchmark.error}</MonoBox>}
        {benchmark && !benchmark.error && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10, marginBottom: 18 }}>
            <StatCard label="Trials" value={benchmark.trials} />
            <StatCard label="Standard total" value={`${benchmark.standardMs.toFixed(2)} ms`} />
            <StatCard label="CRT total" value={`${benchmark.crtMs.toFixed(2)} ms`} />
            <StatCard label="Speedup" value={`${benchmark.speedup.toFixed(2)}×`} accent="#185FA5" />
          </div>
        )}

        {/* Section 3: Håstad */}
        <SectionHeading>3. Håstad broadcast attack on textbook RSA</SectionHeading>
        <div style={{ display: "flex", gap: 10, alignItems: "end", flexWrap: "wrap", marginBottom: 12 }}>
          <div style={{ flex: 1, minWidth: 220 }}>
            <FieldLabel>Short broadcast message</FieldLabel>
            <TextInput value={hastadMsg} onChange={setHastadMsg} placeholder="attack" />
          </div>
          <div style={{ width: 140 }}>
            <FieldLabel>Recipient key bits</FieldLabel>
            <TextInput value={hastadBits} onChange={setHastadBits} placeholder="192" />
          </div>
          <ActionButton onClick={runHastad} disabled={hastadRunning} tone="orange">
            {hastadRunning ? "Running…" : "Run Håstad attack"}
          </ActionButton>
          <ActionButton onClick={runPaddingContrast} disabled={hastadRunning} tone="green">Use PKCS#1 padding</ActionButton>
        </div>

        {hastadResult?.error && <MonoBox>{hastadResult.error}</MonoBox>}
        {hastadResult && !hastadResult.error && (
          <div style={{ marginBottom: 14 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10, marginBottom: 10 }}>
              <StatCard label="Attack success" value={hastadResult.success ? "Recovered m ✓" : "Failed ✗"} accent={hastadResult.success ? "#0F6E56" : "#A32D2D"} />
              <StatCard label="e" value="3" />
              <StatCard label="Recovered text" value={hastadResult.attack.recoveredText ?? "(not UTF-8)"} accent="#185FA5" />
              <StatCard label="Exact cube root?" value={hastadResult.attack.exact ? "YES" : "NO"} />
            </div>
            <div style={{ marginBottom: 8 }}>
              {hastadResult.recipients.map((r) => (
                <div key={r.index} style={{ padding: "8px 10px", border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", marginBottom: 6 }}>
                  <HexLine label={`Recipient ${r.index} N`} value={truncMiddle(r.pk.N.toString(16), 30)} />
                  <HexLine label={`c${r.index} = m³ mod N`} value={truncMiddle(r.ciphertext.toString(16), 30)} />
                </div>
              ))}
            </div>
            <MonoBox>{`CRT reconstructs x = m³ = ${truncMiddle(hastadResult.attack.crtValue.toString(16), 42)}\n∛x = ${hastadResult.attack.recovered}\nRecovered message = ${hastadResult.attack.recoveredText}`}</MonoBox>
          </div>
        )}

        {paddingContrast?.error && <MonoBox>{paddingContrast.error}</MonoBox>}
        {paddingContrast && !paddingContrast.error && (
          <div style={{ marginBottom: 4 }}>
            <SectionHeading>4. PKCS#1 v1.5 padding defeats Håstad</SectionHeading>
            <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#E1F5EE", border: "0.5px solid #1D9E75", marginBottom: 10, fontSize: 11, color: "#0F6E56", lineHeight: 1.7 }}>
              Here we call PA#12's actual PKCS#1 v1.5 encryption. Each recipient can decrypt correctly, but the attacker cannot use CRT + cube root because the padded plaintext integers EM₁, EM₂, EM₃ are different.
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10, marginBottom: 10 }}>
              <StatCard label="Legitimate decryptions" value={paddingContrast.allLegitimateDecryptionsOk ? "ALL VALID ✓" : "ERROR ✗"} accent={paddingContrast.allLegitimateDecryptionsOk ? "#0F6E56" : "#A32D2D"} />
              <StatCard label="PKCS padded EM values differ?" value={paddingContrast.paddedValuesDiffer ? "YES ✓" : "NO ✗"} accent={paddingContrast.paddedValuesDiffer ? "#0F6E56" : "#A32D2D"} />
              <StatCard label="Attacker recovered m?" value={paddingContrast.originalRecovered ? "YES ✗" : "NO ✓"} accent={paddingContrast.originalRecovered ? "#A32D2D" : "#0F6E56"} />
              <StatCard label="Exact cube root?" value={paddingContrast.exactRoot ? "YES" : "NO ✓"} accent={paddingContrast.exactRoot ? "#A32D2D" : "#0F6E56"} />
            </div>
            <div style={{ marginBottom: 8 }}>
              {paddingContrast.recipients.map((r) => (
                <div key={r.index} style={{ padding: "8px 10px", border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", marginBottom: 6 }}>
                  <HexLine label={`Recipient ${r.index} PS`} value={truncMiddle(r.psHex, 30)} />
                  <HexLine label={`Recipient ${r.index} EM`} value={truncMiddle(r.emHex, 30)} />
                  <HexLine label={`Decrypts to`} value={r.decryptedText ?? "(invalid)"} />
                </div>
              ))}
            </div>
            <MonoBox>{`${paddingContrast.explanation}

CRT output x = ${truncMiddle(paddingContrast.attack.crtValue.toString(16), 42)}
integer cube root floor(∛x) = ${paddingContrast.attack.recovered}
Recovered text attempt = ${paddingContrast.attack.recoveredText ?? "(not valid UTF-8)"}`}</MonoBox>
          </div>
        )}
      </div>
    </div>
  );
}

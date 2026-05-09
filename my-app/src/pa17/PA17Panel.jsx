// ═══════════════════════════════════════════════════════════════════════════════
// PA #17 — Encrypt-then-Sign (CCA2-secure signcrypt) (Interactive Demo)
// ═══════════════════════════════════════════════════════════════════════════════

import { useState } from "react";
import {
  generatePA17Keys,
  CCA_PKC_Enc,
  CCA_PKC_Dec,
  runIndCca2Game,
  malleabilityAttackPA16,
  malleabilityAttackPA17,
  truncMiddle,
  ciphertextToHex,
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

function HexLine({ label, value }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "150px 1fr", gap: 8, fontSize: 11, marginBottom: 4 }}>
      <span style={{ color: "var(--color-text-secondary)" }}>{label}</span>
      <span style={{ fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>{value}</span>
    </div>
  );
}

function BigLine({ label, value }) {
  return <HexLine label={label} value={typeof value === "bigint" ? value.toString() : value} />;
}

export default function PA17Panel() {
  const hdr = { bg: "#F0E8F8", border: "#8B6FBB", text: "#5A4A7F" };

  // ── State: Keys ───────────────────────────────────────────────────────────────
  const [keys, setKeys] = useState(null);
  const [rsaBits, setRsaBits] = useState("512");
  const [generating, setGenerating] = useState(false);

  // ── State: Encrypt-then-Sign ──────────────────────────────────────────────────
  const [message, setMessage] = useState("12345");
  const [encryptResult, setEncryptResult] = useState(null);
  const [decryptResult, setDecryptResult] = useState(null);
  const [tamperTest, setTamperTest] = useState(null);
  const [running, setRunning] = useState(false);

  // ── State: IND-CCA2 ───────────────────────────────────────────────────────────
  const [m0Cca, setM0Cca] = useState("11111");
  const [m1Cca, setM1Cca] = useState("22222");
  const [ccaRounds, setCcaRounds] = useState("50");
  const [ccaResult, setCcaResult] = useState(null);

  // ── State: Malleability comparison ─────────────────────────────────────────────
  const [mallMsg, setMallMsg] = useState("99999");
  const [mallPA16, setMallPA16] = useState(null);
  const [mallPA17, setMallPA17] = useState(null);

  // ── Handlers ──────────────────────────────────────────────────────────────────

  const generateKeys = async () => {
    setGenerating(true);
    try {
      const bits = Number.parseInt(rsaBits, 10) || 512;
      const result = generatePA17Keys(bits);
      if (result.success) {
        setKeys(result);
        setEncryptResult(null);
        setDecryptResult(null);
        setTamperTest(null);
        setCcaResult(null);
        setMallPA16(null);
        setMallPA17(null);
      } else {
        setKeys({ error: result.error });
      }
    } catch (err) {
      setKeys({ error: err.message });
    } finally {
      setGenerating(false);
    }
  };

  const runEncryptThenSign = async () => {
    if (!keys || keys.error) return;
    setRunning(true);
    try {
      const enc = CCA_PKC_Enc(
        keys.elgamalKeys.pk,
        { N: keys.rsaKeys.N, d: keys.rsaKeys.d },
        message
      );
      setEncryptResult(enc);
      setDecryptResult(null);
    } catch (err) {
      setEncryptResult({ success: false, error: err.message });
    } finally {
      setRunning(false);
    }
  };

  const runDecrypt = async () => {
    if (!keys || keys.error || !encryptResult || !encryptResult.success) return;
    setRunning(true);
    try {
      const dec = CCA_PKC_Dec(
        keys.elgamalKeys.sk,
        { N: keys.rsaKeys.N, e: keys.rsaKeys.e },
        encryptResult.ciphertext,
        encryptResult.signature
      );
      setDecryptResult(dec);
    } catch (err) {
      setDecryptResult({ success: false, error: err.message });
    } finally {
      setRunning(false);
    }
  };

  const runTamperAndDecrypt = async () => {
    if (!keys || keys.error || !encryptResult || !encryptResult.success) return;
    setRunning(true);
    try {
      const p = keys.elgamalKeys.pk.p;
      // Attacker tampers: modify c2 by multiplying by 2
      const tampered = {
        c1: encryptResult.ciphertext.c1,
        c2: (BigInt(2) * BigInt(encryptResult.ciphertext.c2)) % p,
      };

      // Attacker tries to decrypt the tampered ciphertext
      const dec = CCA_PKC_Dec(
        keys.elgamalKeys.sk,
        { N: keys.rsaKeys.N, e: keys.rsaKeys.e },
        tampered,
        encryptResult.signature  // Using original signature (now invalid for tampered ciphertext)
      );

      setTamperTest({
        success: true,
        originalC2: encryptResult.ciphertext.c2,
        tamperedC2: tampered.c2,
        decResult: dec,
        blocked: !dec.success,
        insight: dec.success
          ? "ERROR: Tampered ciphertext was decrypted! (should not happen)"
          : "✓ Signature verification FAILED on tampered ciphertext. Decryption oracle returned ⊥.",
      });
    } catch (err) {
      setTamperTest({ success: false, error: err.message });
    } finally {
      setRunning(false);
    }
  };

  const runCca2Game = async () => {
    if (!keys || keys.error) return;
    setRunning(true);
    try {
      const result = runIndCca2Game(
        keys.elgamalKeys,
        keys.rsaKeys,
        m0Cca,
        m1Cca,
        ccaRounds
      );
      setCcaResult(result);
    } catch (err) {
      setCcaResult({ success: false, error: err.message });
    } finally {
      setRunning(false);
    }
  };

  const runMalleabilityComparison = async () => {
    if (!keys || keys.error) return;
    setRunning(true);
    try {
      const pa16Attack = malleabilityAttackPA16(keys.elgamalKeys, mallMsg);
      const pa17Attack = malleabilityAttackPA17(keys.elgamalKeys, keys.rsaKeys, mallMsg);
      setMallPA16(pa16Attack);
      setMallPA17(pa17Attack);
    } catch (err) {
      setMallPA16({ success: false, error: err.message });
    } finally {
      setRunning(false);
    }
  };

  // ── Render ────────────────────────────────────────────────────────────────────

  return (
    <div style={{ padding: "16px" }}>
      <div
        style={{
          border: `0.5px solid ${hdr.border}`,
          background: hdr.bg,
          borderRadius: "var(--border-radius-md)",
          padding: 12,
          marginBottom: 16,
        }}
      >
        <div style={{ fontSize: 11, color: hdr.text, lineHeight: 1.6 }}>
          <strong>PA#17 — Encrypt-then-Sign (CCA2-secure signcrypt)</strong>
          <br />
          Implements Signcrypt and Verify-then-Decrypt. Demonstrates that adding signatures to
          ElGamal defeats malleability: modified ciphertexts fail signature verification before decryption,
          making the CCA decryption oracle useless to the adversary. Full dependency chain: PA#17 → PA#16 (ElGamal) + PA#15 (RSA signatures), which call PA#12 (RSA), PA#11 (safe primes), PA#13 (modular inverse).
        </div>
      </div>

      {/* ═══════════════════════════════════════════════════════════════════════ */}
      {/* Key Generation */}
      {/* ═══════════════════════════════════════════════════════════════════════ */}

      <SectionHeading>Generate PA17 keys</SectionHeading>
      <div style={{ display: "flex", gap: 10, alignItems: "end", flexWrap: "wrap", marginBottom: 14 }}>
        <div style={{ width: 160 }}>
          <FieldLabel>RSA key size (bits)</FieldLabel>
          <TextInput value={rsaBits} onChange={setRsaBits} placeholder="512" />
        </div>
        <ActionButton onClick={generateKeys} disabled={generating}>
          {generating ? "Generating…" : "Generate keys"}
        </ActionButton>
      </div>

      {keys?.error && <div style={{ color: "#A32D2D", fontSize: 12, marginBottom: 12 }}>{keys.error}</div>}
      {keys && !keys.error && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(200px,1fr))", gap: 10, marginBottom: 18 }}>
          <StatCard label="ElGamal p" value={truncMiddle(keys.elgamalKeys.pk.p)} />
          <StatCard label="ElGamal pk h" value={truncMiddle(keys.elgamalKeys.pk.h)} />
          <StatCard label="RSA N" value={truncMiddle(keys.rsaKeys.N)} />
          <StatCard label="RSA e" value={keys.rsaKeys.e.toString()} />
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════════ */}
      {/* Encrypt-then-Sign */}
      {/* ═══════════════════════════════════════════════════════════════════════ */}

      <SectionHeading>Encrypt-then-Sign</SectionHeading>
      <div style={{ display: "flex", gap: 10, alignItems: "end", flexWrap: "wrap", marginBottom: 12 }}>
        <div style={{ width: 220 }}>
          <FieldLabel>Message</FieldLabel>
          <TextInput value={message} onChange={setMessage} placeholder="e.g., 12345 or text" />
        </div>
        <ActionButton onClick={runEncryptThenSign} disabled={!keys || keys.error || running}>
          Encrypt & Sign
        </ActionButton>
      </div>

      {encryptResult?.error && <div style={{ color: "#A32D2D", fontSize: 12, marginBottom: 12 }}>{encryptResult.error}</div>}
      {encryptResult && encryptResult.success && (
        <>
          <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", padding: 12, marginBottom: 12 }}>
            <div style={{ fontSize: 11, fontWeight: 600, marginBottom: 8 }}>Ciphertext (C_E, σ)</div>
            <BigLine label="m" value={encryptResult.message} />
            <BigLine label="c1 = g^r" value={truncMiddle(encryptResult.ciphertext.c1)} />
            <BigLine label="c2 = m·h^r" value={truncMiddle(encryptResult.ciphertext.c2)} />
            <BigLine label="σ = Sign(C_E)" value={truncMiddle(encryptResult.sigma)} />
          </div>

          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 12 }}>
            <ActionButton onClick={runDecrypt} disabled={!encryptResult || running}>
              Decrypt (untampered)
            </ActionButton>
            <ActionButton onClick={runTamperAndDecrypt} disabled={!encryptResult || running} tone="orange">
              Tamper with c₂, then decrypt
            </ActionButton>
          </div>

          {decryptResult && decryptResult.success && (
            <div style={{ border: "0.5px solid #1D9E75", borderRadius: "var(--border-radius-md)", padding: 12, background: "#F7FFFC", marginBottom: 12 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                <TestBadge pass={true} />
                <span style={{ fontSize: 12 }}>Decryption successful (signature valid)</span>
              </div>
              <BigLine label="Verified" value={decryptResult.verifyResult.valid ? "Yes ✓" : "No ✗"} />
              <BigLine label="Decrypted m" value={decryptResult.message} />
            </div>
          )}

          {decryptResult && !decryptResult.success && (
            <div style={{ border: "0.5px solid #E24B4A", borderRadius: "var(--border-radius-md)", padding: 12, background: "#FFFAFA", marginBottom: 12 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                <TestBadge pass={false} />
                <span style={{ fontSize: 12 }}>Decryption failed: {decryptResult.reason}</span>
              </div>
              <BigLine label="Result" value={decryptResult.reason} />
            </div>
          )}

          {tamperTest && tamperTest.success && (
            <div style={{ border: tamperTest.blocked ? "0.5px solid #1D9E75" : "0.5px solid #E24B4A", borderRadius: "var(--border-radius-md)", padding: 12, background: tamperTest.blocked ? "#F7FFFC" : "#FFFAFA", marginBottom: 12 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                <TestBadge pass={tamperTest.blocked} />
                <span style={{ fontSize: 12 }}>{tamperTest.insight}</span>
              </div>
              <BigLine label="Original c₂" value={truncMiddle(tamperTest.originalC2)} />
              <BigLine label="Tampered c₂ (×2)" value={truncMiddle(tamperTest.tamperedC2)} />
              {tamperTest.decResult.verifyResult && (
                <>
                  <BigLine label="Signature still valid?" value={tamperTest.decResult.verifyResult.valid ? "Yes (ERROR!)" : "No ✓ (correct)"} />
                  <BigLine label="Result" value={tamperTest.decResult.success ? "ERROR" : "⊥ (rejected)"} />
                </>
              )}
            </div>
          )}
        </>
      )}

      {/* ═══════════════════════════════════════════════════════════════════════ */}
      {/* IND-CCA2 Game */}
      {/* ═══════════════════════════════════════════════════════════════════════ */}

      <SectionHeading>IND-CCA2 simulation (with decryption oracle)</SectionHeading>
      <div style={{ display: "flex", gap: 10, alignItems: "end", flexWrap: "wrap", marginBottom: 12 }}>
        <div style={{ width: 120 }}>
          <FieldLabel>m₀</FieldLabel>
          <TextInput value={m0Cca} onChange={setM0Cca} placeholder="11111" />
        </div>
        <div style={{ width: 120 }}>
          <FieldLabel>m₁</FieldLabel>
          <TextInput value={m1Cca} onChange={setM1Cca} placeholder="22222" />
        </div>
        <div style={{ width: 100 }}>
          <FieldLabel>Rounds</FieldLabel>
          <TextInput value={ccaRounds} onChange={setCcaRounds} placeholder="50" />
        </div>
        <ActionButton onClick={runCca2Game} disabled={!keys || keys.error || running} tone="purple">
          Run CCA2 game
        </ActionButton>
      </div>

      {ccaResult?.error && <div style={{ color: "#A32D2D", fontSize: 12, marginBottom: 12 }}>{ccaResult.error}</div>}
      {ccaResult && ccaResult.success && (
        <>
          <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", padding: 12, marginBottom: 12 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))", gap: 10, marginBottom: 10 }}>
              <StatCard label="rounds" value={ccaResult.rounds} />
              <StatCard label="correct" value={ccaResult.correct} />
              <StatCard label="success rate" value={`${(ccaResult.successRate * 100).toFixed(1)}%`} />
              <StatCard label="advantage" value={ccaResult.advantage.toFixed(3)} accent={ccaResult.advantage <= 0.25 ? "#0F6E56" : "#A32D2D"} />
            </div>
            <div style={{ fontSize: 10, color: "var(--color-text-secondary)", lineHeight: 1.5 }}>{ccaResult.insight}</div>
          </div>
          <MonoBox maxH={100}>
            {ccaResult.log.map(row => `Round ${row.round}: b=${row.b}, guess=${row.guess}, ${row.win ? "✓ win" : "✗ lose"}`).join("\n")}
          </MonoBox>
        </>
      )}

      {/* ═══════════════════════════════════════════════════════════════════════ */}
      {/* Malleability Attack Contrast */}
      {/* ═══════════════════════════════════════════════════════════════════════ */}

      <SectionHeading>Malleability attack: PA#16 vs PA#17</SectionHeading>
      <div style={{ display: "flex", gap: 10, alignItems: "end", flexWrap: "wrap", marginBottom: 12 }}>
        <div style={{ width: 220 }}>
          <FieldLabel>Message for attack</FieldLabel>
          <TextInput value={mallMsg} onChange={setMallMsg} placeholder="e.g., 99999" />
        </div>
        <ActionButton onClick={runMalleabilityComparison} disabled={!keys || keys.error || running} tone="orange">
          Run comparison
        </ActionButton>
      </div>

      {mallPA16 && mallPA16.success && (
        <div style={{ border: "0.5px solid #E8A820", borderRadius: "var(--border-radius-md)", padding: 12, background: "#FFFBF2", marginBottom: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
            <TestBadge pass={!mallPA16.attackWorks} />
            <span style={{ fontSize: 12, fontWeight: 600 }}>PA#16 (plain ElGamal) — Malleability attack {mallPA16.attackWorks ? "WORKS ✗" : "fails"}</span>
          </div>
          <BigLine label="m" value={mallPA16.message} />
          <BigLine label="Original Dec(c1,c2)" value={mallPA16.originalDec} />
          <BigLine label="Modified Dec(c1, 2c₂)" value={mallPA16.modifiedDec} />
          <BigLine label="Expected 2m" value={mallPA16.expected} />
          {mallPA16.attackWorks && <div style={{ fontSize: 10, color: "#7A5200", marginTop: 8 }}>⚠️ {mallPA16.insight}</div>}
        </div>
      )}

      {mallPA17 && mallPA17.success && (
        <div style={{ border: "0.5px solid #1D9E75", borderRadius: "var(--border-radius-md)", padding: 12, background: "#F7FFFC", marginBottom: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
            <TestBadge pass={mallPA17.attackBlocked} />
            <span style={{ fontSize: 12, fontWeight: 600 }}>PA#17 (Encrypt-then-Sign) — Attack {mallPA17.attackBlocked ? "BLOCKED ✓" : "NOT blocked"}</span>
          </div>
          <BigLine label="m" value={mallPA17.message} />
          <BigLine label="Original ciphertext" value={`(${truncMiddle(mallPA17.original.c1)}, ${truncMiddle(mallPA17.original.c2)})`} />
          <BigLine label="Original signature" value={truncMiddle(mallPA17.originalSig)} />
          <BigLine label="Tampered c₂ (×2)" value={truncMiddle(mallPA17.modified.c2)} />
          <BigLine label="Decryption oracle result" value={mallPA17.decAttempt.success ? "ERROR (should fail)" : "⊥ (rejected)"} />
          {mallPA17.verificationFailed && <div style={{ fontSize: 10, color: "#0F6E56", marginTop: 8 }}>✓ {mallPA17.insight}</div>}
        </div>
      )}
    </div>
  );
}

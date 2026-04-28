// ═══════════════════════════════════════════════════════════════════════════════
// PA #15 — Digital Signatures (Interactive Demo)
// ═══════════════════════════════════════════════════════════════════════════════

import { useState } from "react";
import {
  keygen,
  publicKey,
  privateKey,
  Sign,
  Verify,
  verifyTampered,
  rawMultiplicativeForgeryDemo,
  hashThenSignForgeryContrast,
  runEufCmaGame,
  SIGNATURE_HASH_PARAMS,
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

function ActionButton({ children, onClick, disabled, tone = "purple" }) {
  const palette = tone === "red"
    ? { bg: "#FCEBEB", border: "#E24B4A", text: "#A32D2D" }
    : tone === "green"
      ? { bg: "#E1F5EE", border: "#1D9E75", text: "#0F6E56" }
      : tone === "orange"
        ? { bg: "#FEF3E2", border: "#E8A820", text: "#7A5200" }
        : { bg: "#EEEDFE", border: "#7F77DD", text: "#3C3489" };

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
    <div style={{ display: "grid", gridTemplateColumns: "145px 1fr", gap: 8, fontSize: 11, marginBottom: 4 }}>
      <span style={{ color: "var(--color-text-secondary)" }}>{label}</span>
      <span style={{ fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>{value}</span>
    </div>
  );
}

function parseBigIntInput(value, fallback) {
  const clean = String(value || "").trim();
  if (!clean) return BigInt(fallback);
  if (/^0x[0-9a-fA-F]+$/.test(clean)) return BigInt(clean);
  return BigInt(clean);
}

export default function PA15Panel() {
  const hdr = { bg: "#F1EAFE", border: "#9B72E7", text: "#56359E" };

  // ── Key state ─────────────────────────────────────────────────────────────
  const [keyBits, setKeyBits] = useState("512");
  const [keys, setKeys] = useState(null);
  const [generating, setGenerating] = useState(false);

  // ── Sign/verify state ─────────────────────────────────────────────────────
  const [message, setMessage] = useState("Sign this POIS message");
  const [signature, setSignature] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [tamperResult, setTamperResult] = useState(null);
  const [running, setRunning] = useState(false);

  // ── Raw forgery state ─────────────────────────────────────────────────────
  const [m1, setM1] = useState("7");
  const [m2, setM2] = useState("12");
  const [rawForgery, setRawForgery] = useState(null);
  const [hashContrast, setHashContrast] = useState(null);

  // ── EUF-CMA state ─────────────────────────────────────────────────────────
  const [queryCount, setQueryCount] = useState("50");
  const [eufResult, setEufResult] = useState(null);

  function generateKeys() {
    setGenerating(true);
    setSignature(null);
    setVerifyResult(null);
    setTamperResult(null);
    setRawForgery(null);
    setHashContrast(null);
    setEufResult(null);
    setTimeout(() => {
      try {
        const bits = Number.parseInt(keyBits, 10) || 512;
        setKeys(keygen(bits));
      } catch (e) {
        setKeys({ error: e.message });
      }
      setGenerating(false);
    }, 10);
  }

  function signMessage() {
    if (!keys || keys.error) return;
    setRunning(true);
    setTimeout(() => {
      try {
        const sig = Sign(privateKey(keys), message, SIGNATURE_HASH_PARAMS);
        const vr = Verify(publicKey(keys), message, sig.sigma, SIGNATURE_HASH_PARAMS);
        setSignature(sig);
        setVerifyResult(vr);
        setTamperResult(null);
      } catch (e) {
        setSignature({ error: e.message });
        setVerifyResult(null);
      }
      setRunning(false);
    }, 10);
  }

  function verifyCurrent() {
    if (!keys || keys.error || !signature || signature.error) return;
    try {
      setVerifyResult(Verify(publicKey(keys), message, signature.sigma, SIGNATURE_HASH_PARAMS));
    } catch (e) {
      setVerifyResult({ error: e.message });
    }
  }

  function tamperAndVerify() {
    if (!keys || keys.error || !signature || signature.error) return;
    try {
      setTamperResult(verifyTampered(keys, message, signature.sigma, SIGNATURE_HASH_PARAMS));
    } catch (e) {
      setTamperResult({ error: e.message });
    }
  }

  function runForgeryDemo() {
    if (!keys || keys.error) return;
    setRunning(true);
    setTimeout(() => {
      try {
        const a = parseBigIntInput(m1, 7n);
        const b = parseBigIntInput(m2, 12n);
        setRawForgery(rawMultiplicativeForgeryDemo(keys, a, b));
        setHashContrast(hashThenSignForgeryContrast(keys, a, b, SIGNATURE_HASH_PARAMS));
      } catch (e) {
        setRawForgery({ error: e.message });
        setHashContrast(null);
      }
      setRunning(false);
    }, 10);
  }

  function runGame() {
    if (!keys || keys.error) return;
    setRunning(true);
    setTimeout(() => {
      try {
        setEufResult(runEufCmaGame(keys, queryCount, SIGNATURE_HASH_PARAMS));
      } catch (e) {
        setEufResult({ error: e.message });
      }
      setRunning(false);
    }, 10);
  }

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>
      <div style={{ padding: "10px 16px", background: hdr.bg, borderBottom: `0.5px solid ${hdr.border}`, display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: hdr.text }}>
          PA #15 — Digital Signatures
        </div>
        <div style={{ fontSize: 10, color: hdr.text, fontFamily: "var(--font-mono)" }}>
          σ = H(m)^d mod N · verify σ^e ?= H(m)
        </div>
      </div>

      <div style={{ padding: 16 }}>
        <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", marginBottom: 14, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
          This panel implements RSA hash-then-sign using PA#12 RSA and PA#8 DLP_Hash. Raw RSA signatures are shown only as a broken construction because the multiplicative property lets an attacker forge signatures.
        </div>

        {/* ═══ Key generation ═══ */}
        <SectionHeading>Key generation and PA#8 hash parameters</SectionHeading>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))", gap: 10, marginBottom: 12 }}>
          <div>
            <FieldLabel>RSA key size</FieldLabel>
            <TextInput value={keyBits} onChange={setKeyBits} placeholder="512" />
          </div>
          <div style={{ display: "flex", alignItems: "end" }}>
            <ActionButton onClick={generateKeys} disabled={generating}>
              {generating ? "Generating…" : "Generate RSA keys"}
            </ActionButton>
          </div>
        </div>

        {keys?.error && <MonoBox>{keys.error}</MonoBox>}
        {keys && !keys.error && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))", gap: 8, marginBottom: 16 }}>
            <StatCard label="N bits" value={keys.N.toString(2).length.toString()} />
            <StatCard label="e" value={keys.e.toString()} />
            <StatCard label="N hex" value={truncMiddle(keys.N)} />
            <StatCard label="hash p/q" value={`${SIGNATURE_HASH_PARAMS.p}/${SIGNATURE_HASH_PARAMS.q}`} />
          </div>
        )}

        {/* ═══ Sign and verify ═══ */}
        <SectionHeading>Live sign and verify</SectionHeading>
        <div style={{ display: "grid", gridTemplateColumns: "1fr auto auto auto", gap: 10, alignItems: "end", marginBottom: 12 }}>
          <div>
            <FieldLabel>Message</FieldLabel>
            <TextInput value={message} onChange={setMessage} placeholder="Message to sign" />
          </div>
          <ActionButton onClick={signMessage} disabled={!keys || keys.error || running} tone="green">Sign</ActionButton>
          <ActionButton onClick={verifyCurrent} disabled={!signature || signature.error || !keys || keys.error}>Verify</ActionButton>
          <ActionButton onClick={tamperAndVerify} disabled={!signature || signature.error || !keys || keys.error} tone="red">Tamper</ActionButton>
        </div>

        {signature?.error && <MonoBox>{signature.error}</MonoBox>}
        {signature && !signature.error && (
          <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", padding: 12, marginBottom: 14 }}>
            <HexLine label="DLP_Hash(m)" value={`0x${signature.hash.digestHex}`} />
            <HexLine label="H(m) mod N" value={`0x${signature.hash.hInt.toString(16)}`} />
            <HexLine label="Signature σ" value={`0x${signature.sigmaHex}`} />
            {verifyResult && !verifyResult.error && (
              <>
                <HexLine label="σ^e mod N" value={`0x${verifyResult.lhsHex}`} />
                <HexLine label="Expected H(m)" value={`0x${verifyResult.rhsHex}`} />
                <div style={{ marginTop: 8, display: "flex", alignItems: "center", gap: 8 }}>
                  <TestBadge pass={verifyResult.valid} />
                  <span style={{ fontSize: 12, color: verifyResult.valid ? "#0F6E56" : "#A32D2D" }}>
                    {verifyResult.valid ? "Valid signature" : "Invalid signature"}
                  </span>
                </div>
              </>
            )}
          </div>
        )}

        {tamperResult && !tamperResult.error && (
          <div style={{ padding: "10px 12px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A", marginBottom: 16 }}>
            <div style={{ fontSize: 11, color: "#A32D2D", marginBottom: 6 }}>
              Tampered message after one-bit flip: <span style={{ fontFamily: "var(--font-mono)" }}>{JSON.stringify(tamperResult.tamperedMessage)}</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <TestBadge pass={!tamperResult.verification.valid} />
              <span style={{ fontSize: 12, color: "#A32D2D" }}>
                Verification fails after tampering, as required.
              </span>
            </div>
          </div>
        )}

        {/* ═══ Raw RSA forgery ═══ */}
        <SectionHeading>Raw RSA multiplicative forgery</SectionHeading>
        <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#FAEEDA", border: "0.5px solid #BA7517", marginBottom: 12, fontSize: 11, color: "#633806", lineHeight: 1.7 }}>
          Raw RSA signing is broken: from signatures on m₁ and m₂, an attacker computes σ* = σ₁·σ₂ mod N, which verifies as a signature on m₁·m₂ mod N without using the private key.
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "160px 160px auto", gap: 10, alignItems: "end", marginBottom: 12 }}>
          <div>
            <FieldLabel>m₁ integer</FieldLabel>
            <TextInput value={m1} onChange={setM1} placeholder="7" />
          </div>
          <div>
            <FieldLabel>m₂ integer</FieldLabel>
            <TextInput value={m2} onChange={setM2} placeholder="12" />
          </div>
          <ActionButton onClick={runForgeryDemo} disabled={!keys || keys.error || running} tone="orange">Run forgery demo</ActionButton>
        </div>

        {rawForgery?.error && <MonoBox>{rawForgery.error}</MonoBox>}
        {rawForgery && !rawForgery.error && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(260px,1fr))", gap: 10, marginBottom: 16 }}>
            <div style={{ border: "0.5px solid #E8A820", borderRadius: "var(--border-radius-md)", padding: 12, background: "#FEF3E2" }}>
              <div style={{ fontSize: 10, color: "#7A5200", textTransform: "uppercase", letterSpacing: ".07em", marginBottom: 8 }}>Broken raw RSA</div>
              <HexLine label="m* = m₁m₂ mod N" value={rawForgery.forgedMessage.toString()} />
              <HexLine label="σ* = σ₁σ₂ mod N" value={`0x${truncMiddle(rawForgery.forgedSigma)}`} />
              <div style={{ marginTop: 8, display: "flex", alignItems: "center", gap: 8 }}>
                <TestBadge pass={rawForgery.attackSuccess} />
                <span style={{ fontSize: 12, color: rawForgery.attackSuccess ? "#0F6E56" : "#A32D2D" }}>
                  Forgery accepted by raw verification.
                </span>
              </div>
            </div>

            {hashContrast && (
              <div style={{ border: "0.5px solid #1D9E75", borderRadius: "var(--border-radius-md)", padding: 12, background: "#E1F5EE" }}>
                <div style={{ fontSize: 10, color: "#0F6E56", textTransform: "uppercase", letterSpacing: ".07em", marginBottom: 8 }}>Hash-then-sign contrast</div>
                <HexLine label="target message" value={hashContrast.targetMessage} />
                <HexLine label="forged σ" value={`0x${truncMiddle(hashContrast.forgedSigma)}`} />
                <HexLine label="σ^e mod N" value={`0x${hashContrast.verification.lhsHex}`} />
                <HexLine label="H(target)" value={`0x${hashContrast.verification.rhsHex}`} />
                <div style={{ marginTop: 8, display: "flex", alignItems: "center", gap: 8 }}>
                  <TestBadge pass={!hashContrast.attackSuccess} />
                  <span style={{ fontSize: 12, color: hashContrast.attackSuccess ? "#A32D2D" : "#0F6E56" }}>
                    {hashContrast.attackSuccess ? "Unexpected toy collision: try different m₁/m₂." : "Forgery rejected after hashing."}
                  </span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ═══ EUF-CMA game ═══ */}
        <SectionHeading>EUF-CMA signing-oracle game</SectionHeading>
        <div style={{ display: "grid", gridTemplateColumns: "180px auto", gap: 10, alignItems: "end", marginBottom: 12 }}>
          <div>
            <FieldLabel>Oracle queries ≤ 50</FieldLabel>
            <TextInput value={queryCount} onChange={setQueryCount} placeholder="50" />
          </div>
          <ActionButton onClick={runGame} disabled={!keys || keys.error || running}>Run EUF-CMA game</ActionButton>
        </div>

        {eufResult?.error && <MonoBox>{eufResult.error}</MonoBox>}
        {eufResult && !eufResult.error && (
          <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", padding: 12 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))", gap: 8, marginBottom: 10 }}>
              <StatCard label="signed messages seen" value={eufResult.totalTranscriptSize.toString()} />
              <StatCard label="new forged message" value={eufResult.forgedMessage} />
              <StatCard label="random σ* accepted?" value={eufResult.acceptedAsNewForgery ? "YES" : "NO"} accent={eufResult.acceptedAsNewForgery ? "#A32D2D" : "#0F6E56"} />
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
              <TestBadge pass={!eufResult.acceptedAsNewForgery} />
              <span style={{ fontSize: 12, color: eufResult.acceptedAsNewForgery ? "#A32D2D" : "#0F6E56" }}>
                {eufResult.acceptedAsNewForgery ? "A new forgery was accepted." : "No valid signature on a new message was produced."}
              </span>
            </div>
            <MonoBox maxH={130}>
              {eufResult.transcript.map(row => `#${row.index} ${row.message}\n  H=${row.digestHex}\n  σ=${truncMiddle(row.sigmaHex, 24)}`).join("\n")}
            </MonoBox>
            <div style={{ marginTop: 8, fontSize: 11, color: "var(--color-text-secondary)" }}>
              Replay check: a previously signed message verifies, but it does not count as a EUF-CMA forgery because the message was already queried.
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// PA #15 — Digital Signatures (Interactive Demo)
// Updated: explicit Verify button + Raw RSA / Hash-then-sign toggle
// ═══════════════════════════════════════════════════════════════════════════════

import { useState } from "react";
import {
  keygen,
  publicKey,
  privateKey,
  Sign,
  Verify,
  rawRsaSign,
  rawRsaVerify,
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
  ToggleBar,
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
        whiteSpace: "nowrap",
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

function parseBigIntInput(value, fallback = 0n) {
  const clean = String(value || "").trim();
  if (!clean) return BigInt(fallback);
  if (/^0x[0-9a-fA-F]+$/.test(clean)) return BigInt(clean);
  if (/^[0-9]+$/.test(clean)) return BigInt(clean);
  throw new Error("Raw RSA mode expects the message to be an integer, e.g. 42 or 0x2a.");
}

function parseSignatureHex(value) {
  const clean = String(value || "").trim().replace(/^0x/i, "").replace(/\s+/g, "");
  if (!clean) throw new Error("Enter a signature first, or click Sign to populate it.");
  if (!/^[0-9a-fA-F]+$/.test(clean)) throw new Error("Signature must be hex.");
  return BigInt("0x" + clean);
}

function ModeBanner({ mode }) {
  const raw = mode === "raw";
  return (
    <div style={{
      padding: "10px 14px",
      borderRadius: "var(--border-radius-md)",
      background: raw ? "#FEF3E2" : "#E1F5EE",
      border: `0.5px solid ${raw ? "#E8A820" : "#1D9E75"}`,
      color: raw ? "#7A5200" : "#0F6E56",
      fontSize: 11,
      lineHeight: 1.7,
      marginBottom: 12,
    }}>
      {raw ? (
        <>
          <strong>Raw RSA signing mode.</strong> This signs the message integer directly: σ = m<sup>d</sup> mod N. It is intentionally broken and is shown only to demonstrate multiplicative forgery.
        </>
      ) : (
        <>
          <strong>Secure hash-then-sign mode.</strong> This signs the PA#8 DLP hash of the message: σ = H(m)<sup>d</sup> mod N.
        </>
      )}
    </div>
  );
}

export default function PA15Panel() {
  const hdr = { bg: "#F1EAFE", border: "#9B72E7", text: "#56359E" };

  // ── Key state ─────────────────────────────────────────────────────────────
  const [keyBits, setKeyBits] = useState("512");
  const [keys, setKeys] = useState(null);
  const [generating, setGenerating] = useState(false);

  // ── Live sign/verify state ───────────────────────────────────────────────
  const [signMode, setSignMode] = useState("hash");
  const [message, setMessage] = useState("Sign this POIS message");
  const [signatureHex, setSignatureHex] = useState("");
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

  function resetLiveOutputs() {
    setSignature(null);
    setSignatureHex("");
    setVerifyResult(null);
    setTamperResult(null);
  }

  function switchMode(mode) {
    setSignMode(mode);
    resetLiveOutputs();
    if (mode === "raw") setMessage("42");
    else setMessage("Sign this POIS message");
  }

  function generateKeys() {
    setGenerating(true);
    resetLiveOutputs();
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
        if (signMode === "raw") {
          const m = parseBigIntInput(message, 42n);
          const sig = rawRsaSign(privateKey(keys), m);
          const vr = rawRsaVerify(publicKey(keys), m, sig.sigma);
          setSignature({ mode: "raw", ...sig });
          setSignatureHex(sig.sigmaHex);
          setVerifyResult({ mode: "raw", ...vr });
        } else {
          const sig = Sign(privateKey(keys), message, SIGNATURE_HASH_PARAMS);
          const vr = Verify(publicKey(keys), message, sig.sigma, SIGNATURE_HASH_PARAMS);
          setSignature({ mode: "hash", ...sig });
          setSignatureHex(sig.sigmaHex);
          setVerifyResult({ mode: "hash", ...vr });
        }
        setTamperResult(null);
      } catch (e) {
        setSignature({ error: e.message });
        setVerifyResult(null);
        setTamperResult(null);
      }
      setRunning(false);
    }, 10);
  }

  function verifyCurrent() {
    if (!keys || keys.error) return;
    try {
      const sigma = parseSignatureHex(signatureHex);
      if (signMode === "raw") {
        const m = parseBigIntInput(message, 42n);
        setVerifyResult({ mode: "raw", ...rawRsaVerify(publicKey(keys), m, sigma) });
      } else {
        setVerifyResult({ mode: "hash", ...Verify(publicKey(keys), message, sigma, SIGNATURE_HASH_PARAMS) });
      }
    } catch (e) {
      setVerifyResult({ error: e.message });
    }
  }

  function tamperAndVerify() {
    if (!keys || keys.error) return;
    try {
      const sigma = parseSignatureHex(signatureHex);
      if (signMode === "raw") {
        const original = parseBigIntInput(message, 42n);
        const tamperedMessage = (original + 1n) % keys.N;
        const verification = rawRsaVerify(publicKey(keys), tamperedMessage, sigma);
        setTamperResult({ mode: "raw", tamperedMessage: tamperedMessage.toString(), verification });
      } else {
        // Inline the tamper operation so the Verify button and Tamper button use the same manual signature field.
        const bytes = new TextEncoder().encode(String(message));
        const out = bytes.length ? new Uint8Array(bytes) : new Uint8Array([0]);
        out[0] = out[0] ^ 0x01;
        const tamperedMessage = new TextDecoder().decode(out);
        const verification = Verify(publicKey(keys), tamperedMessage, sigma, SIGNATURE_HASH_PARAMS);
        setTamperResult({ mode: "hash", tamperedMessage, verification });
      }
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

  const liveValid = verifyResult && !verifyResult.error ? verifyResult.valid : false;
  const tamperInvalid = tamperResult && !tamperResult.error ? !tamperResult.verification.valid : false;

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>
      <div style={{ padding: "10px 16px", background: hdr.bg, borderBottom: `0.5px solid ${hdr.border}`, display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: hdr.text }}>
          PA #15 — Digital Signatures
        </div>
        <div style={{ fontSize: 10, color: hdr.text, fontFamily: "var(--font-mono)" }}>
          secure: σ = H(m)^d · raw: σ = m^d
        </div>
      </div>

      <div style={{ padding: 16 }}>
        <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", marginBottom: 14, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
          This panel now has an explicit <strong>Verify</strong> workflow and a <strong>Raw RSA sign toggle</strong>. Use hash-then-sign for the secure construction, and switch to raw RSA to see why signing without hashing is broken.
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
        <SectionHeading>Live sign and explicit verify</SectionHeading>
        <div style={{ marginBottom: 12 }}>
          <FieldLabel>Signature mode</FieldLabel>
          <ToggleBar value={signMode} onChange={switchMode} options={[
            { value: "hash", label: "Hash-then-sign (secure)", activeStyle: { bg: "#E1F5EE", border: "#1D9E75", color: "#0F6E56" } },
            { value: "raw", label: "Raw RSA sign (broken)", activeStyle: { bg: "#FEF3E2", border: "#E8A820", color: "#7A5200" } },
          ]} />
        </div>

        <ModeBanner mode={signMode} />

        <div style={{ display: "grid", gridTemplateColumns: "minmax(220px,1fr) minmax(220px,1fr)", gap: 12, marginBottom: 12 }}>
          <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", padding: 12 }}>
            <div style={{ fontSize: 10, color: signMode === "raw" ? "#7A5200" : "#0F6E56", textTransform: "uppercase", letterSpacing: ".07em", marginBottom: 10 }}>
              1. Sign
            </div>
            <div style={{ marginBottom: 10 }}>
              <FieldLabel>{signMode === "raw" ? "Message integer m" : "Message m"}</FieldLabel>
              <TextInput value={message} onChange={(v) => { setMessage(v); setVerifyResult(null); setTamperResult(null); }} placeholder={signMode === "raw" ? "42" : "Message to sign"} />
            </div>
            <ActionButton onClick={signMessage} disabled={!keys || keys.error || running} tone="green">
              {signMode === "raw" ? "Raw RSA Sign" : "Hash-then-Sign"}
            </ActionButton>
          </div>

          <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", padding: 12 }}>
            <div style={{ fontSize: 10, color: "#3C3489", textTransform: "uppercase", letterSpacing: ".07em", marginBottom: 10 }}>
              2. Verify manually
            </div>
            <div style={{ marginBottom: 10 }}>
              <FieldLabel>Signature σ / hex</FieldLabel>
              <TextInput value={signatureHex} onChange={(v) => { setSignatureHex(v); setVerifyResult(null); setTamperResult(null); }} placeholder="Click Sign or paste a signature hex" />
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <ActionButton onClick={verifyCurrent} disabled={!keys || keys.error || running}>Verify</ActionButton>
              <ActionButton onClick={tamperAndVerify} disabled={!keys || keys.error || running} tone="red">Tamper + Verify</ActionButton>
            </div>
          </div>
        </div>

        {signature?.error && <MonoBox>{signature.error}</MonoBox>}
        {verifyResult?.error && <MonoBox>{verifyResult.error}</MonoBox>}

        {signature && !signature.error && (
          <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", padding: 12, marginBottom: 14 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
              <span style={{ fontSize: 10, padding: "2px 8px", borderRadius: 4, fontWeight: 500, background: signMode === "raw" ? "#FEF3E2" : "#E1F5EE", border: `0.5px solid ${signMode === "raw" ? "#E8A820" : "#1D9E75"}`, color: signMode === "raw" ? "#7A5200" : "#0F6E56" }}>
                {signMode === "raw" ? "RAW RSA" : "HASH-THEN-SIGN"}
              </span>
              {verifyResult && !verifyResult.error && <TestBadge pass={liveValid} />}
              {verifyResult && !verifyResult.error && (
                <span style={{ fontSize: 12, color: liveValid ? "#0F6E56" : "#A32D2D" }}>
                  {liveValid ? "Verify accepted the signature." : "Verify rejected the signature."}
                </span>
              )}
            </div>

            {signature.mode === "hash" ? (
              <>
                <HexLine label="DLP_Hash(m)" value={`0x${signature.hash.digestHex}`} />
                <HexLine label="H(m) mod N" value={`0x${signature.hash.hInt.toString(16)}`} />
                <HexLine label="Signature σ" value={`0x${signature.sigmaHex}`} />
                {verifyResult && !verifyResult.error && verifyResult.mode === "hash" && (
                  <>
                    <HexLine label="σ^e mod N" value={`0x${verifyResult.lhsHex}`} />
                    <HexLine label="Expected H(m)" value={`0x${verifyResult.rhsHex}`} />
                  </>
                )}
              </>
            ) : (
              <>
                <HexLine label="Raw message m" value={signature.m.toString()} />
                <HexLine label="Signature σ" value={`0x${signature.sigmaHex}`} />
                {verifyResult && !verifyResult.error && verifyResult.mode === "raw" && (
                  <>
                    <HexLine label="σ^e mod N" value={verifyResult.recovered.toString()} />
                    <HexLine label="Expected m" value={verifyResult.expected.toString()} />
                  </>
                )}
              </>
            )}
          </div>
        )}

        {tamperResult?.error && <MonoBox>{tamperResult.error}</MonoBox>}
        {tamperResult && !tamperResult.error && (
          <div style={{ padding: "10px 12px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A", marginBottom: 16 }}>
            <div style={{ fontSize: 11, color: "#A32D2D", marginBottom: 6 }}>
              Tampered message: <span style={{ fontFamily: "var(--font-mono)" }}>{JSON.stringify(tamperResult.tamperedMessage)}</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <TestBadge pass={tamperInvalid} />
              <span style={{ fontSize: 12, color: tamperInvalid ? "#0F6E56" : "#A32D2D" }}>
                {tamperInvalid ? "The old signature fails on the tampered message." : "Unexpectedly accepted after tampering."}
              </span>
            </div>
          </div>
        )}

        {/* ═══ Raw RSA forgery ═══ */}
        <SectionHeading>Raw RSA multiplicative forgery</SectionHeading>
        <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#FAEEDA", border: "0.5px solid #BA7517", marginBottom: 12, fontSize: 11, color: "#633806", lineHeight: 1.7 }}>
          Raw RSA signing is broken: from signatures on m₁ and m₂, an attacker computes σ* = σ₁·σ₂ mod N, which verifies as a signature on m₁·m₂ mod N without using the private key. The green panel shows why hash-then-sign blocks the same trick.
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

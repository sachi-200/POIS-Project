// ═══════════════════════════════════════════════════════════════════════════════
// PA #11 — Diffie-Hellman Key Exchange (Interactive Demo)
//
// Demo features:
//   • Two panels: Alice (left) and Bob (right) with private exponent inputs
//   • Click "Exchange" → animate g^a and g^b, compute shared secret K = g^ab
//   • "Enable Eve" checkbox inserts MITM: Eve intercepts and substitutes values
//   • CDH hardness demo: brute-force search for small parameters
//   • Safe prime generation using PA#13 Miller-Rabin
// ═══════════════════════════════════════════════════════════════════════════════

import { useState, useRef } from "react";
import {
  dhExchange,
  mitmAttack,
  cdhBruteForceAsync,
  genSafePrimeAsync,
  findGenerator,
  TOY_P, TOY_Q, TOY_G,
  SMALL_P, SMALL_Q, SMALL_G,
  modPow,
} from "./crypto.js";
import {
  FieldLabel,
  SectionHeading,
  TextInput,
  MonoBox,
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

function truncHex(n, len = 16) {
  if (n === null || n === undefined) return "—";
  const s = n.toString(16);
  return s.length > len ? `${s.slice(0, len)}…` : s;
}

function PartyCard({ name, color, privLabel, privVal, pubLabel, pubVal, secretLabel, secretVal, secretColor }) {
  return (
    <div style={{ padding: "12px 14px", borderRadius: "var(--border-radius-md)", background: color.bg, border: `0.5px solid ${color.border}` }}>
      <div style={{ fontSize: 11, fontWeight: 600, color: color.text, marginBottom: 8 }}>{name}</div>
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        <div style={{ display: "flex", gap: 6, fontSize: 10 }}>
          <span style={{ color: "var(--color-text-secondary)", minWidth: 70 }}>{privLabel}:</span>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-primary)", wordBreak: "break-all" }}>{privVal}</span>
        </div>
        <div style={{ display: "flex", gap: 6, fontSize: 10 }}>
          <span style={{ color: "var(--color-text-secondary)", minWidth: 70 }}>{pubLabel}:</span>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: color.text, wordBreak: "break-all" }}>{pubVal}</span>
        </div>
        {secretVal !== undefined && (
          <div style={{ display: "flex", gap: 6, fontSize: 10, marginTop: 4, paddingTop: 4, borderTop: `0.5px solid ${color.border}` }}>
            <span style={{ color: "var(--color-text-secondary)", minWidth: 70 }}>{secretLabel}:</span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, fontWeight: 600, color: secretColor || "#0F6E56", wordBreak: "break-all" }}>{secretVal}</span>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main Panel ───────────────────────────────────────────────────────────────

export default function PA11Panel() {
  // ── DH exchange state ─────────────────────────────────────────────────────
  const [aliceA, setAliceA] = useState("");
  const [bobB, setBobB] = useState("");
  const [exchangeResult, setExchangeResult] = useState(null);
  const [eveEnabled, setEveEnabled] = useState(false);
  const [exchanging, setExchanging] = useState(false);

  // ── CDH state ─────────────────────────────────────────────────────────────
  const [cdhResult, setCdhResult] = useState(null);
  const [cdhRunning, setCdhRunning] = useState(false);
  const [cdhProgress, setCdhProgress] = useState(0);

  // ── Safe prime gen state ──────────────────────────────────────────────────
  const [genBits, setGenBits] = useState("32");
  const [genResult, setGenResult] = useState(null);
  const [genRunning, setGenRunning] = useState(false);
  const [genProgress, setGenProgress] = useState(0);

  const cancelRef = useRef(false);

  // ── Handlers ──────────────────────────────────────────────────────────────

  function runExchange() {
    setExchanging(true);
    setTimeout(() => {
      try {
        const aOvr = aliceA.trim() ? aliceA.trim() : null;
        const bOvr = bobB.trim() ? bobB.trim() : null;
        if (eveEnabled) {
          const result = mitmAttack(TOY_P, TOY_G, TOY_Q, aOvr, bOvr);
          setExchangeResult({ ...result, mitm: true });
        } else {
          const result = dhExchange(TOY_P, TOY_G, TOY_Q, aOvr, bOvr);
          setExchangeResult({ ...result, mitm: false });
        }
      } catch (e) {
        setExchangeResult({ error: e.message });
      }
      setExchanging(false);
    }, 10);
  }

  function randomise(setter) {
    const arr = new Uint32Array(1);
    crypto.getRandomValues(arr);
    const val = (BigInt(arr[0]) % (TOY_Q - 3n)) + 2n;
    setter(val.toString());
  }

  async function runCDH() {
    if (cdhRunning) return;
    setCdhRunning(true);
    setCdhResult(null);
    setCdhProgress(0);
    cancelRef.current = false;

    try {
      // Generate a small DH exchange on SMALL params
      const a = 2n + BigInt(Math.floor(Math.random() * 100000));
      const b = 2n + BigInt(Math.floor(Math.random() * 100000));
      const ga = modPow(SMALL_G, a, SMALL_P);
      const gb = modPow(SMALL_G, b, SMALL_P);
      const realK = modPow(SMALL_G, a * b % SMALL_Q, SMALL_P);
      const realK2 = modPow(gb, a, SMALL_P);

      const result = await cdhBruteForceAsync(
        SMALL_P, SMALL_G, SMALL_Q, ga, gb,
        (n) => setCdhProgress(n),
        1_100_000
      );
      setCdhResult({ ...result, ga, gb, realK: realK2, a_actual: a, b_actual: b });
    } catch (e) {
      setCdhResult({ error: e.message });
    }
    setCdhRunning(false);
  }

  async function runGenSafePrime() {
    if (genRunning) return;
    const bits = Number.parseInt(genBits, 10) || 32;
    if (bits < 16 || bits > 64) { setGenResult({ error: "Bits must be 16–64 for browser demo" }); return; }
    setGenRunning(true);
    setGenResult(null);
    setGenProgress(0);
    cancelRef.current = false;

    try {
      const result = await genSafePrimeAsync(bits, (c) => setGenProgress(c));
      const g = findGenerator(result.p, result.q);
      setGenResult({ ...result, g });
    } catch (e) {
      setGenResult({ error: e.message });
    }
    setGenRunning(false);
  }

  // ── Render ────────────────────────────────────────────────────────────────

  const hdr = { bg: "#E6F1FB", border: "#378ADD", text: "#185FA5" };
  const aliceC = { bg: "#E6F1FB", border: "#378ADD", text: "#185FA5" };
  const bobC = { bg: "#E1F5EE", border: "#1D9E75", text: "#0F6E56" };
  const eveC = { bg: "#FCEBEB", border: "#E24B4A", text: "#A32D2D" };

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>

      {/* ── Header ── */}
      <div style={{ padding: "10px 16px", background: hdr.bg, borderBottom: `0.5px solid ${hdr.border}`, display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: hdr.text }}>
          PA #11 — Diffie-Hellman Key Exchange
        </div>
        <div style={{ fontSize: 10, color: "#185FA5", fontFamily: "var(--font-mono)" }}>
          K = g<sup>ab</sup> mod p
        </div>
      </div>

      <div style={{ padding: "16px" }}>

        {/* ── Description ── */}
        <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", marginBottom: 14, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
          Diffie-Hellman allows two parties to establish a shared secret K = g<sup>ab</sup> over a public channel.
          Security relies on the CDH assumption: given g<sup>a</sup> and g<sup>b</sup>, computing g<sup>ab</sup> is hard.
          Basic DH is not authenticated — it is vulnerable to Man-in-the-Middle (MITM) attacks.
        </div>

        {/* ── Public parameters ── */}
        <SectionHeading>Public parameters (toy ~32-bit safe prime)</SectionHeading>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))", gap: 8, marginBottom: 14 }}>
          <StatCard label="p (safe prime)" value={`0x${TOY_P.toString(16)}`} />
          <StatCard label="q = (p−1)/2" value={`0x${TOY_Q.toString(16)}`} />
          <StatCard label="g (generator)" value={TOY_G.toString()} />
          <StatCard label="Bits" value="~32" />
        </div>

        {/* ═══ Section 1: DH Exchange ═══ */}
        <SectionHeading>Live Diffie-Hellman exchange</SectionHeading>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 14 }}>
          {/* Alice */}
          <div>
            <FieldLabel>Alice — private exponent a (or leave blank for random)</FieldLabel>
            <div style={{ display: "flex", gap: 6 }}>
              <TextInput value={aliceA} onChange={setAliceA} placeholder="random" />
              <button onClick={() => randomise(setAliceA)} style={smallBtn(aliceC)}>🎲</button>
            </div>
          </div>
          {/* Bob */}
          <div>
            <FieldLabel>Bob — private exponent b (or leave blank for random)</FieldLabel>
            <div style={{ display: "flex", gap: 6 }}>
              <TextInput value={bobB} onChange={setBobB} placeholder="random" />
              <button onClick={() => randomise(setBobB)} style={smallBtn(bobC)}>🎲</button>
            </div>
          </div>
        </div>

        {/* Eve toggle + Exchange button */}
        <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 14, flexWrap: "wrap" }}>
          <button
            onClick={runExchange}
            disabled={exchanging}
            style={{
              padding: "8px 20px", fontSize: 12, fontWeight: 500,
              border: `0.5px solid ${hdr.border}`, borderRadius: "var(--border-radius-md)",
              background: exchanging ? "#D3D1C7" : hdr.bg,
              color: exchanging ? "#888780" : hdr.text,
              cursor: exchanging ? "default" : "pointer", fontFamily: "var(--font-sans)",
            }}
          >
            {exchanging ? "Exchanging…" : "Exchange"}
          </button>
          <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: eveC.text, cursor: "pointer", userSelect: "none" }}>
            <input type="checkbox" checked={eveEnabled} onChange={(e) => { setEveEnabled(e.target.checked); setExchangeResult(null); }} />
            Enable Eve (MITM)
          </label>
        </div>

        {/* Exchange result */}
        {exchangeResult && !exchangeResult.error && (
          <div style={{ marginBottom: 14 }}>
            {/* Arrow animation row */}
            <div style={{ display: "grid", gridTemplateColumns: eveEnabled ? "1fr auto 1fr auto 1fr" : "1fr auto 1fr", gap: 8, alignItems: "start", marginBottom: 12 }}>
              {/* Alice card */}
              <PartyCard
                name="Alice" color={aliceC}
                privLabel="a (secret)" privVal={truncHex(exchangeResult.alice.a, 12)}
                pubLabel="A = gᵃ mod p" pubVal={`0x${truncHex(exchangeResult.alice.A)}`}
                secretLabel="K (computed)" secretVal={`0x${truncHex(exchangeResult.alice.K)}`}
                secretColor={exchangeResult.mitm ? eveC.text : "#0F6E56"}
              />

              {/* Arrow Alice → (Eve →) Bob */}
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4, paddingTop: 20 }}>
                <span style={{ fontSize: 9, color: "var(--color-text-secondary)" }}>A = g<sup>a</sup></span>
                <span style={{ fontSize: 18, color: "var(--color-text-secondary)" }}>→</span>
                <span style={{ fontSize: 18, color: "var(--color-text-secondary)" }}>←</span>
                <span style={{ fontSize: 9, color: "var(--color-text-secondary)" }}>B = g<sup>b</sup></span>
              </div>

              {eveEnabled && exchangeResult.eve && (
                <>
                  {/* Eve card */}
                  <PartyCard
                    name="Eve (MITM)" color={eveC}
                    privLabel="e (secret)" privVal={truncHex(exchangeResult.eve.e, 12)}
                    pubLabel="E = gᵉ mod p" pubVal={`0x${truncHex(exchangeResult.eve.E)}`}
                    secretLabel="K_AE / K_BE"
                    secretVal={`0x${truncHex(exchangeResult.eve.K_AE, 10)} / 0x${truncHex(exchangeResult.eve.K_BE, 10)}`}
                    secretColor={eveC.text}
                  />
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4, paddingTop: 20 }}>
                    <span style={{ fontSize: 9, color: eveC.text }}>E (fake A)</span>
                    <span style={{ fontSize: 18, color: eveC.text }}>→</span>
                    <span style={{ fontSize: 18, color: eveC.text }}>←</span>
                    <span style={{ fontSize: 9, color: eveC.text }}>E (fake B)</span>
                  </div>
                </>
              )}

              {/* Bob card */}
              <PartyCard
                name="Bob" color={bobC}
                privLabel="b (secret)" privVal={truncHex(exchangeResult.bob.b, 12)}
                pubLabel="B = gᵇ mod p" pubVal={`0x${truncHex(exchangeResult.bob.B)}`}
                secretLabel="K (computed)" secretVal={`0x${truncHex(exchangeResult.bob.K)}`}
                secretColor={exchangeResult.mitm ? eveC.text : "#0F6E56"}
              />
            </div>

            {/* Match/mismatch banner */}
            {!exchangeResult.mitm ? (
              <div style={{
                padding: "10px 14px", borderRadius: "var(--border-radius-md)",
                background: exchangeResult.match ? "#E1F5EE" : "#FCEBEB",
                border: `0.5px solid ${exchangeResult.match ? "#1D9E75" : "#E24B4A"}`,
                color: exchangeResult.match ? "#0F6E56" : "#A32D2D",
                fontSize: 12, fontWeight: 500,
              }}>
                {exchangeResult.match
                  ? "✓ Shared secrets match! K_A = K_B = g^(ab) mod p"
                  : "✗ Secrets do NOT match (unexpected error)"}
              </div>
            ) : (
              <div>
                <div style={{
                  padding: "10px 14px", borderRadius: "var(--border-radius-md)",
                  background: "#FCEBEB", border: "0.5px solid #E24B4A",
                  color: "#A32D2D", fontSize: 12, fontWeight: 500, marginBottom: 8,
                }}>
                  ✗ Alice and Bob do NOT share the same secret! K_A ≠ K_B
                </div>
                <div style={{
                  padding: "10px 14px", borderRadius: "var(--border-radius-md)",
                  background: "#FCEBEB", border: "0.5px solid #E24B4A",
                  color: "#A32D2D", fontSize: 11, lineHeight: 1.7,
                }}>
                  <strong>MITM attack succeeded:</strong> Eve holds K_AE (shared with Alice) and K_BE (shared with Bob).
                  Eve can decrypt all traffic from Alice, re-encrypt it for Bob, and vice versa.
                  Neither Alice nor Bob detects the attack — they need authentication (e.g. digital signatures, PA#15).
                  <br />
                  Eve K_AE matches Alice K? <strong>{exchangeResult.eve.matchAlice ? "YES ✓" : "NO ✗"}</strong>
                  {" · "}
                  Eve K_BE matches Bob K? <strong>{exchangeResult.eve.matchBob ? "YES ✓" : "NO ✗"}</strong>
                </div>
              </div>
            )}
          </div>
        )}
        {exchangeResult && exchangeResult.error && (
          <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A", color: "#A32D2D", fontSize: 11, marginBottom: 14 }}>
            Error: {exchangeResult.error}
          </div>
        )}

        {/* ═══ Section 2: CDH Hardness ═══ */}
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", marginTop: 16, paddingTop: 14 }}>
          <SectionHeading>CDH hardness demo — brute-force on small parameters (q ≈ 2²⁰)</SectionHeading>
          <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", marginBottom: 10, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
            Given g<sup>a</sup> and g<sup>b</sup>, we brute-force all x to find x such that g<sup>x</sup> = g<sup>a</sup>,
            then compute g<sup>ab</sup> = (g<sup>b</sup>)<sup>x</sup>. With q ≈ 2²⁰ this is feasible; with q ≈ 2²⁵⁶ it is not.
          </div>

          <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 14, flexWrap: "wrap" }}>
            <button
              onClick={runCDH}
              disabled={cdhRunning}
              style={{
                padding: "7px 14px", fontSize: 12, fontWeight: 500,
                border: "0.5px solid #BA7517", borderRadius: "var(--border-radius-md)",
                background: cdhRunning ? "#D3D1C7" : "#FAEEDA",
                color: cdhRunning ? "#888780" : "#854F0B",
                cursor: cdhRunning ? "default" : "pointer", fontFamily: "var(--font-sans)",
              }}
            >
              {cdhRunning ? "Searching…" : "Run CDH brute-force"}
            </button>
            {cdhRunning && (
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)" }}>
                attempts: {cdhProgress.toLocaleString()}
              </span>
            )}
          </div>

          {cdhResult && !cdhResult.error && (
            <div style={{ marginBottom: 10 }}>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))", gap: 8, marginBottom: 8 }}>
                <StatCard label="Found?" value={cdhResult.found ? "YES ✓" : "NO (max reached)"} accent={cdhResult.found ? "#0F6E56" : "#A32D2D"} />
                <StatCard label="Attempts" value={cdhResult.attempts.toLocaleString()} />
                <StatCard label="Time" value={`${cdhResult.timeMs.toFixed(1)} ms`} />
                <StatCard label="Recovered a" value={cdhResult.found ? cdhResult.a.toString() : "—"} />
              </div>
              {cdhResult.found && (
                <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#E1F5EE", border: "0.5px solid #1D9E75", color: "#0F6E56", fontSize: 11, lineHeight: 1.7 }}>
                  Brute-force recovered a = {cdhResult.a.toString()} after {cdhResult.attempts.toLocaleString()} attempts ({cdhResult.timeMs.toFixed(1)} ms).
                  <br />Computed g<sup>ab</sup> = 0x{truncHex(cdhResult.gab, 16)}
                  {" · "}Actual K = 0x{truncHex(cdhResult.realK, 16)}
                  {" · "}Match: <strong>{cdhResult.gab === cdhResult.realK ? "YES ✓" : "NO ✗"}</strong>
                </div>
              )}
            </div>
          )}
        </div>

        {/* ═══ Section 3: Safe Prime Generation ═══ */}
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", marginTop: 16, paddingTop: 14 }}>
          <SectionHeading>Safe prime generation — p = 2q + 1 (using PA#13 Miller-Rabin)</SectionHeading>

          <div style={{ display: "grid", gridTemplateColumns: "200px auto", gap: 10, alignItems: "end", marginBottom: 10 }}>
            <div>
              <FieldLabel>Bit length (16–64)</FieldLabel>
              <TextInput value={genBits} onChange={setGenBits} placeholder="32" />
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <button
                onClick={runGenSafePrime}
                disabled={genRunning}
                style={{
                  padding: "7px 14px", fontSize: 12, fontWeight: 500,
                  border: `0.5px solid ${hdr.border}`, borderRadius: "var(--border-radius-md)",
                  background: genRunning ? "#D3D1C7" : hdr.bg,
                  color: genRunning ? "#888780" : hdr.text,
                  cursor: genRunning ? "default" : "pointer", fontFamily: "var(--font-sans)",
                }}
              >
                {genRunning ? "Generating…" : "Generate safe prime"}
              </button>
              {genRunning && (
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)" }}>
                  candidates tested: {genProgress}
                </span>
              )}
            </div>
          </div>

          {genResult && !genResult.error && (
            <div style={{ marginBottom: 10 }}>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))", gap: 8, marginBottom: 8 }}>
                <StatCard label="Candidates" value={genResult.candidates} />
                <StatCard label="Time" value={`${genResult.timeMs.toFixed(1)} ms`} />
              </div>
              <SectionHeading>Generated parameters</SectionHeading>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                <MonoBox maxH={40}>p = {genResult.p.toString()}</MonoBox>
                <MonoBox maxH={40}>q = {genResult.q.toString()}</MonoBox>
                <MonoBox maxH={40}>g = {genResult.g.toString()}</MonoBox>
              </div>
            </div>
          )}
          {genResult && genResult.error && (
            <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A", color: "#A32D2D", fontSize: 11 }}>
              Error: {genResult.error}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Small button style helper ────────────────────────────────────────────────

function smallBtn(c) {
  return {
    padding: "7px 10px", fontSize: 12, border: `0.5px solid ${c.border}`,
    borderRadius: "var(--border-radius-md)", background: c.bg, color: c.text,
    cursor: "pointer", fontFamily: "var(--font-sans)", flexShrink: 0,
  };
}

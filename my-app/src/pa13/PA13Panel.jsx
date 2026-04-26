// ═══════════════════════════════════════════════════════════════════════════════
// PA #13 — Miller-Rabin Primality Testing  (Interactive Demo)
//
// Demo features:
//   • Number input field (up to 20 digits)
//   • Rounds slider (k = 1–40)
//   • Click "Test" → PRIME or COMPOSITE with witness log
//   • Pre-loaded examples: 561, known 512-bit prime, known composite
//   • Carmichael demo (Fermat vs Miller-Rabin)
//   • Prime generation with benchmarking
// ═══════════════════════════════════════════════════════════════════════════════

import { useRef, useState } from "react";
import {
  millerRabin,
  fermatTest,
  carmichaelDemo,
  genPrimeAsync,
  benchmarkPrimeGen,
  KNOWN_512_PRIME,
  KNOWN_COMPOSITE,
  CARMICHAEL_NUMBERS,
} from "./crypto.js";
import {
  FieldLabel,
  SectionHeading,
  TextInput,
  TestBadge,
  MonoBox,
} from "../shared/ui.jsx";

// ── Stat card (same pattern as PA9) ──────────────────────────────────────────

function StatCard({ label, value, accent }) {
  return (
    <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
      <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>{label}</div>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, fontWeight: 500, color: accent || "var(--color-text-primary)", wordBreak: "break-all" }}>{value}</div>
    </div>
  );
}

// ── Witness log row ──────────────────────────────────────────────────────────

function WitnessRow({ info, index }) {
  const isComposite = info.composite;
  return (
    <div style={{
      padding: "8px 12px",
      borderRadius: "var(--border-radius-md)",
      background: isComposite ? "#FCEBEB" : "#E1F5EE",
      border: `0.5px solid ${isComposite ? "#E24B4A" : "#1D9E75"}`,
      marginBottom: 6,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
        <span style={{ fontSize: 10, padding: "2px 8px", borderRadius: 4, fontWeight: 500, background: isComposite ? "#FCEBEB" : "#E1F5EE", border: `0.5px solid ${isComposite ? "#E24B4A" : "#1D9E75"}`, color: isComposite ? "#A32D2D" : "#0F6E56" }}>
          Round {index + 1}
        </span>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)" }}>
          a = {info.witness.toString().length > 30 ? `${info.witness.toString().slice(0, 30)}…` : info.witness.toString()}
        </span>
        <span style={{ fontSize: 10, fontWeight: 500, color: isComposite ? "#A32D2D" : "#0F6E56" }}>
          {isComposite ? "COMPOSITE witness found" : "passed"}
        </span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
        {info.values.map((v, i) => (
          <div key={i} style={{ display: "flex", alignItems: "baseline", gap: 6, fontSize: 10 }}>
            <span style={{ color: "var(--color-text-secondary)", minWidth: 100 }}>{v.label}:</span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-primary)", wordBreak: "break-all" }}>
              {v.value.toString().length > 60 ? `${v.value.toString().slice(0, 60)}…` : v.value.toString()}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Main panel ───────────────────────────────────────────────────────────────

export default function PA13Panel() {
  // ── Primality test state ───────────────────────────────────────────────────
  const [inputN, setInputN] = useState("561");
  const [rounds, setRounds] = useState(10);
  const [testResult, setTestResult] = useState(null);
  const [testTime, setTestTime] = useState(null);
  const [testing, setTesting] = useState(false);

  // ── Carmichael demo state ──────────────────────────────────────────────────
  const [carDemo, setCarDemo] = useState(null);
  const [carN, setCarN] = useState("561");

  // ── Prime generation state ─────────────────────────────────────────────────
  const [genBits, setGenBits] = useState("64");
  const [genResult, setGenResult] = useState(null);
  const [genRunning, setGenRunning] = useState(false);
  const [genProgress, setGenProgress] = useState(0);

  // ── Benchmark state ────────────────────────────────────────────────────────
  const [benchResults, setBenchResults] = useState([]);
  const [benchRunning, setBenchRunning] = useState(false);
  const [benchProgress, setBenchProgress] = useState("");

  const cancelRef = useRef(false);

  // ── Handlers ───────────────────────────────────────────────────────────────

  function runTest() {
    setTesting(true);
    // defer to let UI update
    setTimeout(() => {
      try {
        const n = BigInt(inputN.trim());
        const t0 = performance.now();
        const result = millerRabin(n, rounds);
        const elapsed = performance.now() - t0;
        setTestResult(result);
        setTestTime(elapsed);
      } catch (e) {
        setTestResult({ prime: false, rounds: [], reason: `Error: ${e.message}` });
        setTestTime(0);
      }
      setTesting(false);
    }, 10);
  }

  function loadExample(val) {
    setInputN(val);
    setTestResult(null);
    setTestTime(null);
  }

  function runCarmichaelDemo() {
    try {
      const n = BigInt(carN.trim());
      setCarDemo(carmichaelDemo(n));
    } catch (e) {
      setCarDemo(null);
    }
  }

  async function runGenPrime() {
    if (genRunning) return;
    const bits = Number.parseInt(genBits, 10) || 64;
    setGenRunning(true);
    setGenProgress(0);
    setGenResult(null);
    cancelRef.current = false;

    try {
      const result = await genPrimeAsync(bits, (c) => setGenProgress(c));
      setGenResult(result);
    } catch (e) {
      setGenResult({ error: e.message });
    }
    setGenRunning(false);
  }

  async function runBenchmark() {
    if (benchRunning) return;
    setBenchRunning(true);
    setBenchResults([]);
    cancelRef.current = false;

    // Only benchmark sensible sizes — 512 and 1024; skip 2048 in demo (too slow for browser BigInt)
    const sizes = [64, 128, 256, 512];
    const results = [];

    for (const bits of sizes) {
      if (cancelRef.current) break;
      setBenchProgress(`Generating ${bits}-bit prime…`);
      try {
        const res = await benchmarkPrimeGen(bits, () => {});
        results.push(res);
        setBenchResults([...results]);
      } catch (e) {
        results.push({ bits, error: e.message });
        setBenchResults([...results]);
      }
    }
    setBenchProgress("");
    setBenchRunning(false);
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  const headerColor = { bg: "#EEEDFE", border: "#AFA9EC", text: "#3C3489" };

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>

      {/* ── Header ── */}
      <div style={{ padding: "10px 16px", background: headerColor.bg, borderBottom: `0.5px solid ${headerColor.border}`, display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: headerColor.text }}>
          PA #13 — Miller-Rabin Primality Testing
        </div>
        <div style={{ fontSize: 10, color: "#6B62B5", fontFamily: "var(--font-mono)" }}>
          error ≤ 4⁻ᵏ per k rounds
        </div>
      </div>

      <div style={{ padding: "16px" }}>

        {/* ── Description ── */}
        <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", marginBottom: 14, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
          Miller-Rabin is a probabilistic primality test: if it says "composite," it is definitely correct; if it says "prime," there is at most a 4⁻ᵏ probability of error after k rounds.
          Write n−1 = 2ˢ·d (d odd), then for each random witness a, compute a^d mod n and square repeatedly.
        </div>

        {/* ═══ Section 1: Interactive Primality Tester ═══ */}
        <SectionHeading>Interactive primality tester</SectionHeading>

        <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 16, marginBottom: 14 }}>
          <div>
            <FieldLabel>Number n (integer, up to 20 digits or any BigInt)</FieldLabel>
            <TextInput value={inputN} onChange={setInputN} placeholder="e.g. 561" />
          </div>
          <div>
            <FieldLabel>Rounds k ({rounds})</FieldLabel>
            <input
              type="range"
              min={1}
              max={40}
              step={1}
              value={rounds}
              onChange={(e) => setRounds(Number(e.target.value))}
              style={{ width: "100%" }}
            />
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--color-text-secondary)", marginTop: 2 }}>
              <span>1</span>
              <span>error ≤ 4⁻{rounds} ≈ {(Math.pow(4, -rounds)).toExponential(1)}</span>
              <span>40</span>
            </div>
          </div>
        </div>

        {/* Pre-loaded examples */}
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 14 }}>
          <span style={{ fontSize: 10, color: "var(--color-text-secondary)", alignSelf: "center" }}>Pre-loaded:</span>
          <button onClick={() => loadExample("561")} style={presetBtnStyle("#FAEEDA", "#BA7517", "#854F0B")}>561 (Carmichael)</button>
          <button onClick={() => loadExample(KNOWN_512_PRIME.toString())} style={presetBtnStyle("#E1F5EE", "#1D9E75", "#0F6E56")}>512-bit prime</button>
          <button onClick={() => loadExample(KNOWN_COMPOSITE.toString())} style={presetBtnStyle("#FCEBEB", "#E24B4A", "#A32D2D")}>Known composite</button>
          <button onClick={() => loadExample("104729")} style={presetBtnStyle("#E6F1FB", "#378ADD", "#185FA5")}>104729 (prime)</button>
          <button onClick={() => loadExample("1729")} style={presetBtnStyle("#FAEEDA", "#BA7517", "#854F0B")}>1729 (Carmichael)</button>
        </div>

        {/* Test button */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
          <button
            onClick={runTest}
            disabled={testing}
            style={{
              padding: "8px 20px",
              fontSize: 12,
              fontWeight: 500,
              border: `0.5px solid ${headerColor.border}`,
              borderRadius: "var(--border-radius-md)",
              background: testing ? "#D3D1C7" : headerColor.bg,
              color: testing ? "#888780" : headerColor.text,
              cursor: testing ? "default" : "pointer",
              fontFamily: "var(--font-sans)",
            }}
          >
            {testing ? "Testing…" : "Test"}
          </button>
          {testTime !== null && (
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)" }}>
              {testTime.toFixed(2)} ms
            </span>
          )}
        </div>

        {/* Test result */}
        {testResult && (
          <div style={{ marginBottom: 14 }}>
            <div style={{
              padding: "10px 14px",
              borderRadius: "var(--border-radius-md)",
              background: testResult.prime ? "#E1F5EE" : "#FCEBEB",
              border: `0.5px solid ${testResult.prime ? "#1D9E75" : "#E24B4A"}`,
              color: testResult.prime ? "#0F6E56" : "#A32D2D",
              fontSize: 13,
              fontWeight: 500,
              marginBottom: 8,
            }}>
              {testResult.prime ? "PROBABLY PRIME" : "COMPOSITE"}
              {testResult.reason && <span style={{ fontWeight: 400, marginLeft: 8 }}>({testResult.reason})</span>}
              {testResult.s !== undefined && (
                <span style={{ fontWeight: 400, fontFamily: "var(--font-mono)", fontSize: 11, marginLeft: 12, color: "var(--color-text-secondary)" }}>
                  n−1 = 2^{testResult.s.toString()} · {testResult.d.toString().length > 40 ? `${testResult.d.toString().slice(0, 40)}…` : testResult.d.toString()}
                </span>
              )}
            </div>

            {/* Stat cards */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))", gap: 8, marginBottom: 10 }}>
              <StatCard label="Rounds run" value={testResult.rounds.length} />
              <StatCard label="Result" value={testResult.prime ? "PRIME" : "COMPOSITE"} accent={testResult.prime ? "#0F6E56" : "#A32D2D"} />
              <StatCard label="Error bound" value={`≤ 4⁻${testResult.rounds.length}`} />
              <StatCard label="n digits" value={inputN.length} />
            </div>

            {/* Witness log */}
            {testResult.rounds.length > 0 && (
              <div>
                <SectionHeading>Witness log ({testResult.rounds.length} rounds)</SectionHeading>
                <div style={{ maxHeight: 300, overflowY: "auto" }}>
                  {testResult.rounds.map((info, i) => (
                    <WitnessRow key={i} info={info} index={i} />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ═══ Section 2: Carmichael Demo ═══ */}
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", marginTop: 16, paddingTop: 14 }}>
          <SectionHeading>Carmichael number demo — Fermat vs Miller-Rabin</SectionHeading>
          <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", marginBottom: 10, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
            Carmichael numbers (e.g. 561) pass the naïve Fermat test (a^(n−1) ≡ 1 mod n for all a coprime to n)
            but are correctly identified as composite by Miller-Rabin.
          </div>

          <div style={{ display: "flex", gap: 10, alignItems: "end", marginBottom: 10, flexWrap: "wrap" }}>
            <div style={{ width: 160 }}>
              <FieldLabel>Carmichael number</FieldLabel>
              <TextInput value={carN} onChange={setCarN} placeholder="561" />
            </div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {CARMICHAEL_NUMBERS.map(c => (
                <button key={c.toString()} onClick={() => setCarN(c.toString())} style={presetBtnStyle("#FAEEDA", "#BA7517", "#854F0B")}>
                  {c.toString()}
                </button>
              ))}
            </div>
            <button
              onClick={runCarmichaelDemo}
              style={{
                padding: "7px 14px",
                fontSize: 12,
                fontWeight: 500,
                border: "0.5px solid #BA7517",
                borderRadius: "var(--border-radius-md)",
                background: "#FAEEDA",
                color: "#854F0B",
                cursor: "pointer",
                fontFamily: "var(--font-sans)",
              }}
            >
              Run demo
            </button>
          </div>

          {carDemo && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              {/* Fermat result */}
              <div style={{
                padding: "10px 14px",
                borderRadius: "var(--border-radius-md)",
                background: carDemo.fermatSaysPrime ? "#FCEBEB" : "#E1F5EE",
                border: `0.5px solid ${carDemo.fermatSaysPrime ? "#E24B4A" : "#1D9E75"}`,
              }}>
                <div style={{ fontSize: 11, fontWeight: 500, color: carDemo.fermatSaysPrime ? "#A32D2D" : "#0F6E56", marginBottom: 4 }}>
                  Fermat test says: {carDemo.fermatSaysPrime ? "PRIME ✗ (WRONG!)" : "COMPOSITE ✓"}
                </div>
                <div style={{ fontSize: 10, color: "var(--color-text-secondary)" }}>
                  {carDemo.fermat.rounds.length} rounds — all a^(n−1) ≡ 1 (mod n)
                  {carDemo.fermatSaysPrime && " — Carmichael number fools Fermat!"}
                </div>
              </div>
              {/* Miller-Rabin result */}
              <div style={{
                padding: "10px 14px",
                borderRadius: "var(--border-radius-md)",
                background: carDemo.mrSaysPrime ? "#FCEBEB" : "#E1F5EE",
                border: `0.5px solid ${carDemo.mrSaysPrime ? "#E24B4A" : "#1D9E75"}`,
              }}>
                <div style={{ fontSize: 11, fontWeight: 500, color: carDemo.mrSaysPrime ? "#A32D2D" : "#0F6E56", marginBottom: 4 }}>
                  Miller-Rabin says: {carDemo.mrSaysPrime ? "PRIME ✗" : "COMPOSITE ✓"}
                </div>
                <div style={{ fontSize: 10, color: "var(--color-text-secondary)" }}>
                  {carDemo.millerRabin.rounds.length} round(s) to detect composite
                  {!carDemo.mrSaysPrime && " — correctly rejected!"}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* ═══ Section 3: Prime Generation ═══ */}
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", marginTop: 16, paddingTop: 14 }}>
          <SectionHeading>Prime generation — gen_prime(bits)</SectionHeading>

          <div style={{ display: "grid", gridTemplateColumns: "200px auto", gap: 10, alignItems: "end", marginBottom: 10 }}>
            <div>
              <FieldLabel>Bit length (8–512)</FieldLabel>
              <TextInput value={genBits} onChange={setGenBits} placeholder="64" />
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <button
                onClick={runGenPrime}
                disabled={genRunning}
                style={{
                  padding: "7px 14px",
                  fontSize: 12,
                  fontWeight: 500,
                  border: `0.5px solid ${headerColor.border}`,
                  borderRadius: "var(--border-radius-md)",
                  background: genRunning ? "#D3D1C7" : headerColor.bg,
                  color: genRunning ? "#888780" : headerColor.text,
                  cursor: genRunning ? "default" : "pointer",
                  fontFamily: "var(--font-sans)",
                }}
              >
                {genRunning ? "Generating…" : "Generate prime"}
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
                <StatCard label="Bits" value={genResult.bits} />
                <StatCard label="Candidates tested" value={genResult.candidates} />
                <StatCard label="Time" value={`${genResult.timeMs.toFixed(1)} ms`} />
                <StatCard label="Sanity (100 rounds)" value={genResult.sanityPass ? "PASS ✓" : "FAIL ✗"} accent={genResult.sanityPass ? "#0F6E56" : "#A32D2D"} />
              </div>
              <SectionHeading>Generated prime</SectionHeading>
              <MonoBox maxH={80}>{genResult.prime.toString()}</MonoBox>
            </div>
          )}
          {genResult && genResult.error && (
            <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A", color: "#A32D2D", fontSize: 11 }}>
              Error: {genResult.error}
            </div>
          )}
        </div>

        {/* ═══ Section 4: Performance Benchmark ═══ */}
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", marginTop: 16, paddingTop: 14 }}>
          <SectionHeading>Performance benchmark — candidates vs Prime Number Theorem</SectionHeading>
          <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", marginBottom: 10, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
            The Prime Number Theorem predicts ~ln(2^b) ≈ b·ln(2) candidates before finding a b-bit prime.
            This benchmark compares actual candidates sampled to the theoretical prediction.
          </div>

          <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 14, flexWrap: "wrap" }}>
            <button
              onClick={runBenchmark}
              disabled={benchRunning}
              style={{
                padding: "7px 14px",
                fontSize: 12,
                fontWeight: 500,
                border: "0.5px solid #378ADD",
                borderRadius: "var(--border-radius-md)",
                background: benchRunning ? "#D3D1C7" : "#E6F1FB",
                color: benchRunning ? "#888780" : "#185FA5",
                cursor: benchRunning ? "default" : "pointer",
                fontFamily: "var(--font-sans)",
              }}
            >
              {benchRunning ? "Running…" : "Run benchmark (64, 128, 256, 512 bit)"}
            </button>
            {benchRunning && (
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)" }}>
                {benchProgress}
              </span>
            )}
            {benchRunning && (
              <button
                onClick={() => { cancelRef.current = true; }}
                style={{
                  padding: "7px 14px",
                  fontSize: 12,
                  border: "0.5px solid var(--color-border-secondary)",
                  borderRadius: "var(--border-radius-md)",
                  background: "var(--color-background-secondary)",
                  color: "var(--color-text-secondary)",
                  cursor: "pointer",
                  fontFamily: "var(--font-sans)",
                }}
              >
                Stop
              </button>
            )}
          </div>

          {benchResults.length > 0 && (
            <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", overflow: "hidden" }}>
              <div style={{ display: "grid", gridTemplateColumns: "80px 1fr 1fr 1fr 1fr", background: "var(--color-background-secondary)", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
                {["Bits", "Candidates", "Theoretical", "Ratio", "Time (ms)"].map((h, i) => (
                  <div key={i} style={{ padding: "6px 10px", fontSize: 10, fontWeight: 500, color: "var(--color-text-secondary)", textTransform: "uppercase" }}>{h}</div>
                ))}
              </div>
              {benchResults.map((r, i) => (
                <div key={i} style={{ display: "grid", gridTemplateColumns: "80px 1fr 1fr 1fr 1fr", borderBottom: i < benchResults.length - 1 ? "0.5px solid var(--color-border-tertiary)" : "none" }}>
                  <div style={{ padding: "7px 10px", fontFamily: "var(--font-mono)", fontSize: 12, color: "#3C3489", fontWeight: 500 }}>{r.bits}</div>
                  <div style={{ padding: "7px 10px", fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--color-text-primary)" }}>{r.error ? "Error" : r.candidates}</div>
                  <div style={{ padding: "7px 10px", fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--color-text-secondary)" }}>{r.theoreticalCandidates || "-"}</div>
                  <div style={{ padding: "7px 10px", fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--color-text-primary)" }}>{r.ratio || "-"}×</div>
                  <div style={{ padding: "7px 10px", fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--color-text-secondary)" }}>{r.timeMs ? r.timeMs.toFixed(1) : "-"}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Preset button style helper ───────────────────────────────────────────────

function presetBtnStyle(bg, border, color) {
  return {
    padding: "5px 10px",
    fontSize: 11,
    fontWeight: 500,
    border: `0.5px solid ${border}`,
    borderRadius: "var(--border-radius-md)",
    background: bg,
    color: color,
    cursor: "pointer",
    fontFamily: "var(--font-sans)",
    whiteSpace: "nowrap",
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// PA #1 Panel — Live PRG output viewer
// ═══════════════════════════════════════════════════════════════════════════════

import { useState, useMemo, useCallback } from "react";
import { fakeHex, seedFromHex } from "../utils/crypto.js";
import { frequencyTest, runsTest, serialTest } from "../utils/nist.js";
import { dlpOWF, aesOWF, prgFromOWF, makePRGInterface } from "./crypto.js";
import { FieldLabel, TextInput, ToggleBar, SectionHeading, TestBadge, MonoBox } from "../shared/ui.jsx";

function ArgumentBox() {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ marginTop: 8 }}>
      <button onClick={() => setOpen(o => !o)} style={{ width: "100%", display: "flex", justifyContent: "space-between", alignItems: "center", padding: "7px 12px", fontSize: 11, fontWeight: 500, border: "0.5px solid var(--color-border-tertiary)", borderRadius: open ? "var(--border-radius-md) var(--border-radius-md) 0 0" : "var(--border-radius-md)", background: "var(--color-background-secondary)", color: "var(--color-text-secondary)", cursor: "pointer", fontFamily: "var(--font-sans)" }}>
        <span>PA#1b written argument — click to {open ? "collapse" : "expand"}</span><span>{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <div style={{ padding: "12px 14px", border: "0.5px solid var(--color-border-tertiary)", borderTop: "none", borderRadius: "0 0 var(--border-radius-md) var(--border-radius-md)", background: "var(--color-background-primary)", fontSize: 11, lineHeight: 1.7, color: "var(--color-text-secondary)" }}>
          <div style={{ fontWeight: 500, color: "var(--color-text-primary)", marginBottom: 6 }}>Claim: f(s) = G(s) is a one-way function.</div>
          <div style={{ marginBottom: 6 }}><span style={{ fontWeight: 500 }}>Proof (contrapositive).</span> Suppose adversary A inverts f with non-negligible probability:</div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, background: "var(--color-background-secondary)", padding: "6px 10px", borderRadius: "var(--border-radius-md)", marginBottom: 8 }}>Pr[ A(G(s)) = s' s.t. G(s') = G(s) ] ≥ 1/poly(n)</div>
          <div style={{ marginBottom: 6 }}>Construct distinguisher D against G:</div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, background: "var(--color-background-secondary)", padding: "8px 10px", borderRadius: "var(--border-radius-md)", marginBottom: 8, lineHeight: 1.9 }}>
            D(y):<br />&nbsp;&nbsp;1. Run A(y) → s'<br />&nbsp;&nbsp;2. If G(s') = y, output 1<br />&nbsp;&nbsp;3. Else output 0
          </div>
          <div style={{ marginBottom: 4 }}>If y = G(s): A succeeds w.p. ≥ 1/poly(n) ⟹ D outputs 1 w.h.p.</div>
          <div style={{ marginBottom: 8 }}>If y ← U_(n+ℓ): G(s') = y with prob ≤ 2⁻ˡ (negligible).</div>
          <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: 8, fontStyle: "italic" }}>⟹ D wins with advantage ≥ 1/poly(n) − negl(n), contradicting PRG security. □</div>
        </div>
      )}
    </div>
  );
}

export default function PA1Panel() {
  const [owfType, setOwfType] = useState("DLP");
  const [seedHex, setSeedHex] = useState("deadbeef");
  const [outputLen, setOutputLen] = useState(16);
  const [showTests, setShowTests] = useState(false);
  const [testResults, setTestResults] = useState(null);

  const owfOut = useMemo(() => owfType === "DLP" ? dlpOWF(seedHex) : aesOWF(seedHex), [owfType, seedHex]);
  const prgAsOwfDemo = useMemo(() => {
    const { hexOut } = prgFromOWF(seedHex, owfType, 8);
    return { prgOut: hexOut, invertAttempt: fakeHex(seedFromHex(hexOut) ^ 0xdead, 8) };
  }, [owfType, seedHex]);
  const prgResult = useMemo(() => prgFromOWF(seedHex, owfType, outputLen), [seedHex, owfType, outputLen]);
  const prgInterfaceDemo = useMemo(() => {
    const prg = makePRGInterface(seedHex, owfType);
    const b8 = prg.next_bytes_hex(4);
    prg.seed(owfOut);
    return { firstCall: b8, afterReseed: prg.next_bytes_hex(4) };
  }, [seedHex, owfType, owfOut]);

  const ones = prgResult.bitString.split("").filter(b => b === "1").length;
  const ratio = prgResult.bitString.length > 0 ? ones / prgResult.bitString.length : 0.5;
  const runTests = useCallback(() => {
    setTestResults({ freq: frequencyTest(prgResult.bitString), runs: runsTest(prgResult.bitString), serial: serialTest(prgResult.bitString) });
    setShowTests(true);
  }, [prgResult.bitString]);

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>
      <div style={{ padding: "10px 16px", background: "#E6F1FB", borderBottom: "0.5px solid #B5D4F4", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: "#185FA5" }}>PA #1 — Live PRG output viewer</div>
        <ToggleBar value={owfType} onChange={setOwfType} options={[
          { value: "DLP", label: "DLP (gˣ mod p)", activeStyle: { bg: "#EEEDFE", border: "#7F77DD", color: "#3C3489" } },
          { value: "AES", label: "AES Davies-Meyer", activeStyle: { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" } },
        ]} />
      </div>
      <div style={{ padding: "16px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 16 }}>
          {/* Left: OWF + hardness demo */}
          <div>
            <SectionHeading>OWF — evaluate(x)</SectionHeading>
            <div style={{ marginBottom: 12 }}><FieldLabel>Seed / input x (hex)</FieldLabel><TextInput value={seedHex} onChange={setSeedHex} placeholder="e.g. deadbeef" /></div>
            <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 14 }}>
              <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 6 }}>f(x) = {owfType === "DLP" ? "g^x mod p" : "AES_k(0¹²⁸) ⊕ k"}</div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}><span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 22 }}>in:</span><span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--color-text-secondary)" }}>0x{seedHex.slice(0, 8).padEnd(8, "0")}</span></div>
              <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 4 }}><span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 22 }}>out:</span><span style={{ fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--color-text-primary)", fontWeight: 500 }}>0x{owfOut}</span></div>
            </div>
            <SectionHeading>verify_hardness() — OWF from PRG (PA#1b)</SectionHeading>
            <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", fontSize: 12, marginBottom: 4 }}>
              <div style={{ marginBottom: 6, color: "var(--color-text-secondary)" }}>Claim: f(s)=G(s) is a OWF. Given G(s), adversary cannot recover s.</div>
              <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4 }}><span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 60 }}>G(seed):</span><span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-primary)", wordBreak: "break-all" }}>0x{prgAsOwfDemo.prgOut}</span></div>
              <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4 }}><span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 60 }}>Adv. guess:</span><span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)" }}>0x{prgAsOwfDemo.invertAttempt}</span></div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}><span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 60 }}>Recovered:</span><TestBadge pass={false} /><span style={{ fontSize: 11, color: "var(--color-text-secondary)", fontStyle: "italic" }}>inversion fails ✓</span></div>
            </div>
            <ArgumentBox />
            <div style={{ marginTop: 14 }}>
              <SectionHeading>PRG interface — seed(s) / next_bits(n) for PA#2</SectionHeading>
              <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", fontSize: 11 }}>
                <div style={{ display: "flex", gap: 8, marginBottom: 4 }}><span style={{ fontFamily: "var(--font-mono)", color: "#185FA5", minWidth: 110 }}>prg.seed(s)</span><span style={{ color: "var(--color-text-secondary)" }}>→ resets state</span></div>
                <div style={{ display: "flex", gap: 8, marginBottom: 8 }}><span style={{ fontFamily: "var(--font-mono)", color: "#185FA5", minWidth: 110 }}>next_bits(32)</span><span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-primary)" }}>0x{prgInterfaceDemo.firstCall}</span></div>
                <div style={{ display: "flex", gap: 8, marginBottom: 4 }}><span style={{ fontFamily: "var(--font-mono)", color: "#0F6E56", minWidth: 110 }}>prg.seed(owf)</span><span style={{ color: "var(--color-text-secondary)" }}>→ re-seeded with f(x)</span></div>
                <div style={{ display: "flex", gap: 8 }}><span style={{ fontFamily: "var(--font-mono)", color: "#0F6E56", minWidth: 110 }}>next_bits(32)</span><span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-primary)" }}>0x{prgInterfaceDemo.afterReseed}</span></div>
              </div>
            </div>
          </div>
          {/* Right: PRG construction */}
          <div>
            <SectionHeading>PRG from OWF — G(s) iterative construction (PA#1a)</SectionHeading>
            <div style={{ marginBottom: 12 }}>
              <FieldLabel>Output length ℓ — {outputLen} bytes ({outputLen * 8} bits)</FieldLabel>
              <input type="range" min={8} max={256} step={8} value={outputLen} onChange={e => setOutputLen(Number(e.target.value))} style={{ width: "100%" }} />
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--color-text-secondary)", marginTop: 2 }}><span>8 B</span><span>256 B</span></div>
            </div>
            <SectionHeading>First 8 iterations: xᵢ → f(xᵢ) → b(xᵢ)</SectionHeading>
            <div style={{ marginBottom: 12 }}>
              {prgResult.steps.map((s, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 0", borderBottom: "0.5px solid var(--color-border-tertiary)", fontSize: 11 }}>
                  <span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-secondary)", minWidth: 18 }}>x{i}:</span>
                  <span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-secondary)", fontSize: 10, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>0x{s.xHex}</span>
                  <span style={{ fontSize: 10, padding: "1px 6px", borderRadius: 3, fontWeight: 500, background: s.bit ? "#E1F5EE" : "#EEEDFE", color: s.bit ? "#0F6E56" : "#3C3489", border: `0.5px solid ${s.bit ? "#1D9E75" : "#7F77DD"}` }}>b={s.bit}</span>
                </div>
              ))}
            </div>
            <SectionHeading>G(s) output — {outputLen * 8} pseudorandom bits</SectionHeading>
            <MonoBox maxH={80}>0x{prgResult.hexOut}</MonoBox>
            <div style={{ margin: "10px 0 12px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--color-text-secondary)", marginBottom: 4 }}><span>Bit ratio</span><span style={{ fontFamily: "var(--font-mono)" }}>{(ratio * 100).toFixed(1)}% ones</span></div>
              <div style={{ height: 8, borderRadius: 4, background: "var(--color-background-secondary)", overflow: "hidden", border: "0.5px solid var(--color-border-tertiary)" }}>
                <div style={{ height: "100%", width: `${ratio * 100}%`, background: Math.abs(ratio - 0.5) < 0.05 ? "#1D9E75" : "#D85A30", transition: "width 0.3s" }} />
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--color-text-secondary)", marginTop: 2 }}><span>0%</span><span style={{ color: "#1D9E75" }}>50%</span><span>100%</span></div>
            </div>
            <button onClick={runTests} style={{ width: "100%", padding: "8px 14px", fontSize: 12, fontWeight: 500, border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", color: "var(--color-text-primary)", cursor: "pointer", fontFamily: "var(--font-sans)" }}>
              Run randomness tests (frequency + runs + serial)
            </button>
          </div>
        </div>
        {showTests && testResults && (
          <div style={{ marginTop: 16, border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", overflow: "hidden" }}>
            <div style={{ padding: "8px 14px", background: "var(--color-background-secondary)", borderBottom: "0.5px solid var(--color-border-tertiary)", fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: "var(--color-text-secondary)" }}>NIST SP 800-22 — threshold p ≥ 0.01</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr" }}>
              {[
                { label: testResults.freq.name, pass: testResults.freq.pass, lines: [`ones=${testResults.freq.ones} zeros=${testResults.freq.zeros}`, `ratio=${testResults.freq.ratio}% S_obs=${testResults.freq.sObs}`, `p-value = ${testResults.freq.pVal}`] },
                { label: testResults.runs.name, pass: testResults.runs.pass, lines: [`runs=${testResults.runs.runs} exp≈${testResults.runs.expected}`, `V_obs=${testResults.runs.vObs}`, `p-value = ${testResults.runs.pVal}`] },
                { label: testResults.serial.name, pass: testResults.serial.pass, lines: [`00=${testResults.serial.counts["00"]} 01=${testResults.serial.counts["01"]} 10=${testResults.serial.counts["10"]} 11=${testResults.serial.counts["11"]}`, `χ²=${testResults.serial.chi2} (df=3)`, `p-value = ${testResults.serial.pVal}`] },
              ].map((t, i) => (
                <div key={i} style={{ padding: "12px 14px", borderRight: i < 2 ? "0.5px solid var(--color-border-tertiary)" : "none" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}><TestBadge pass={t.pass} /><span style={{ fontSize: 12, fontWeight: 500 }}>{t.label}</span></div>
                  {t.lines.map((line, j) => <div key={j} style={{ fontSize: 11, color: j === 2 ? (t.pass ? "#0F6E56" : "#A32D2D") : "var(--color-text-secondary)", fontFamily: "var(--font-mono)", marginBottom: 2, fontWeight: j === 2 ? 500 : 400 }}>{line}</div>)}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
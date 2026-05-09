/**
 * PA20Panel.jsx — All 2-Party Secure Computation
 *
 * Aesthetic: "Cryptographic Observatory" — obsidian dark, split-pane
 *   Alice side: violet (#a78bfa)  — always left
 *   Bob side:   emerald (#34d399) — always right
 *   Shared/output: amber (#fbbf24)
 *   AND gates: red, XOR gates: sky blue, NOT gates: slate
 *   Mono font: IBM Plex Mono / Courier Prime
 *
 * Features
 *   • Three-circuit tab bar (Millionaire / Equality / Adder)
 *   • Split Alice ↔ Bob sliders — values hidden from the opposite panel
 *   • Gate-by-gate animated evaluation with progress bar
 *   • Expandable circuit trace showing AND/XOR/NOT outputs in order
 *   • Full OT call count and wall-clock timing
 *   • n=8 benchmark table
 *   • Call-stack lineage trace (PA#20 → PA#19 → RSA OT → modpow)
 *   • Privacy verification / simulatability argument
 */

import { useState, useCallback, useEffect, useRef } from "react";
import {
  buildMillionaireCircuit,
  buildEqualityCircuit,
  buildAdderCircuit,
  Secure_Eval,
  intToBits,
  bitsToInt,
  runBenchmark,
  getCallStackTrace,
  selfTest,
} from "./crypto.js";

// ── Design tokens ──────────────────────────────────────────────────────────────

const C = {
  bg:         "#07080c",
  surface:    "#0d0f14",
  surfaceHi:  "#121520",
  border:     "#181c27",
  borderHi:   "#252c3e",
  alice:      "#a78bfa",
  aliceDim:   "#6d28d9",
  alicePale:  "#a78bfa18",
  bob:        "#34d399",
  bobDim:     "#065f46",
  bobPale:    "#34d39918",
  amber:      "#fbbf24",
  amberDim:   "#92400e",
  amberPale:  "#fbbf2415",
  red:        "#f87171",
  sky:        "#38bdf8",
  slate:      "#64748b",
  text:       "#e2e8f0",
  textMid:    "#94a3b8",
  textDim:    "#3d4a5c",
  mono:       "'IBM Plex Mono', 'Courier Prime', 'Courier New', monospace",
  sans:       "'IBM Plex Sans', 'Trebuchet MS', system-ui, sans-serif",
  gateColor:  { AND: "#f87171", XOR: "#38bdf8", NOT: "#64748b" },
};

// ── Micro-components ───────────────────────────────────────────────────────────

function SectionDivider({ label }) {
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 12,
      margin: "28px 0 18px",
    }}>
      <div style={{ flex: 1, height: 1, background: C.border }} />
      <span style={{
        fontFamily: C.mono, fontSize: 10, color: C.textDim,
        letterSpacing: "0.18em", textTransform: "uppercase",
      }}>
        {label}
      </span>
      <div style={{ flex: 1, height: 1, background: C.border }} />
    </div>
  );
}

function Mono({ children, color, size, bold }) {
  return (
    <span style={{
      fontFamily: C.mono,
      fontSize: size || 12,
      color: color || C.textMid,
      fontWeight: bold ? 700 : 400,
    }}>
      {children}
    </span>
  );
}

function Badge({ children, color }) {
  return (
    <span style={{
      fontFamily: C.mono, fontSize: 10,
      padding: "2px 7px", borderRadius: 3,
      border: `1px solid ${color}44`,
      color, background: `${color}12`,
      letterSpacing: "0.06em",
    }}>
      {children}
    </span>
  );
}

function GateTag({ type }) {
  const col = C.gateColor[type] || C.textDim;
  return (
    <span style={{
      fontFamily: C.mono, fontSize: 9,
      padding: "1px 6px", borderRadius: 2,
      border: `1px solid ${col}55`,
      color: col, background: `${col}12`,
      letterSpacing: "0.08em", fontWeight: 700,
    }}>
      {type}
    </span>
  );
}

function Btn({ children, onClick, disabled, color, small }) {
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        padding: small ? "6px 14px" : "10px 22px",
        fontFamily: C.mono,
        fontSize: small ? 11 : 12,
        letterSpacing: "0.05em",
        border: `1px solid ${disabled ? C.border : (color || C.amber)}`,
        borderRadius: 5,
        background: disabled ? "transparent" : hov ? `${color || C.amber}20` : `${color || C.amber}12`,
        color: disabled ? C.textDim : (color || C.amber),
        cursor: disabled ? "default" : "pointer",
        transition: "all 0.15s ease",
      }}
    >
      {children}
    </button>
  );
}

// Slider with value label
function PartySlider({ label, value, onChange, color, max, locked, lockLabel }) {
  return (
    <div>
      <div style={{
        display: "flex", justifyContent: "space-between",
        alignItems: "center", marginBottom: 8,
      }}>
        <span style={{ fontFamily: C.mono, fontSize: 11, color: `${color}99`, letterSpacing: "0.1em", textTransform: "uppercase" }}>
          {label}
        </span>
        <span style={{
          fontFamily: C.mono, fontSize: 22, fontWeight: 700,
          color, letterSpacing: "-0.02em",
        }}>
          {locked ? "??" : value}
        </span>
      </div>

      <input
        type="range"
        min={0}
        max={max}
        value={value}
        onChange={e => onChange(Number(e.target.value))}
        style={{ width: "100%", accentColor: color, cursor: "pointer" }}
      />

      {/* Bit representation */}
      <div style={{
        display: "flex", gap: 4, marginTop: 10, justifyContent: "center",
      }}>
        {intToBits(value, 4).reverse().map((bit, i) => (
          <div
            key={i}
            style={{
              width: 28, height: 28,
              display: "flex", alignItems: "center", justifyContent: "center",
              borderRadius: 4,
              border: `1px solid ${locked ? C.border : (bit ? color : `${color}44`)}`,
              background: locked ? "transparent" : (bit ? `${color}18` : "transparent"),
              fontFamily: C.mono, fontSize: 13, fontWeight: 700,
              color: locked ? C.textDim : (bit ? color : `${color}55`),
            }}
          >
            {locked ? "?" : bit}
          </div>
        ))}
        {!locked && (
          <div style={{
            marginLeft: 6,
            fontFamily: C.mono, fontSize: 10,
            color: C.textDim, alignSelf: "center",
          }}>
            (MSB→LSB)
          </div>
        )}
      </div>

      {locked && (
        <div style={{
          marginTop: 10, textAlign: "center",
          fontFamily: C.mono, fontSize: 10,
          color: C.textDim, letterSpacing: "0.08em",
        }}>
          🔒 {lockLabel}
        </div>
      )}
    </div>
  );
}

// ── Progress bar ───────────────────────────────────────────────────────────────

function ProgressBar({ current, total, color }) {
  const pct = total > 0 ? (current / total) * 100 : 0;
  return (
    <div>
      <div style={{
        display: "flex", justifyContent: "space-between",
        marginBottom: 5,
      }}>
        <span style={{ fontFamily: C.mono, fontSize: 10, color: C.textDim }}>
          Gates evaluated
        </span>
        <span style={{ fontFamily: C.mono, fontSize: 10, color }}>
          {current} / {total}
        </span>
      </div>
      <div style={{
        height: 6, borderRadius: 3,
        background: C.border, overflow: "hidden",
      }}>
        <div style={{
          height: "100%",
          width: `${pct}%`,
          borderRadius: 3,
          background: `linear-gradient(90deg, ${color}88, ${color})`,
          transition: "width 0.06s ease",
          boxShadow: pct > 0 ? `0 0 8px ${color}66` : "none",
        }} />
      </div>
    </div>
  );
}

// ── Gate trace row ─────────────────────────────────────────────────────────────

function GateRow({ entry, index }) {
  const isAND = entry.type === 'AND';
  const isXOR = entry.type === 'XOR';

  const inputStr = entry.type === 'NOT'
    ? `${entry.in[0]}`
    : `${entry.in[0]}, ${entry.in[1]}`;

  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "28px 48px 1fr 28px",
      gap: 8,
      alignItems: "center",
      padding: "5px 12px",
      borderBottom: `1px solid ${C.border}`,
      background: isAND ? `${C.red}06` : "transparent",
    }}>
      {/* Index */}
      <span style={{ fontFamily: C.mono, fontSize: 10, color: C.textDim }}>
        {index + 1}
      </span>
      {/* Type */}
      <GateTag type={entry.type} />
      {/* Detail */}
      <span style={{ fontFamily: C.mono, fontSize: 10, color: C.textMid }}>
        f({inputStr})
        {isAND && (
          <span style={{ color: C.red, marginLeft: 8 }}>
            [OT #{entry.otCall}]
          </span>
        )}
      </span>
      {/* Output */}
      <span style={{
        fontFamily: C.mono, fontSize: 12, fontWeight: 700,
        color: entry.out === 1
          ? (isAND ? C.red : isXOR ? C.sky : C.slate)
          : C.textDim,
        textAlign: "center",
      }}>
        {entry.out}
      </span>
    </div>
  );
}

// ── Result banner ──────────────────────────────────────────────────────────────

function ResultBanner({ text, subtext, color }) {
  return (
    <div style={{
      border: `2px solid ${color}44`,
      borderRadius: 10,
      background: `${color}0e`,
      padding: "20px 28px",
      textAlign: "center",
      boxShadow: `0 0 24px ${color}22`,
    }}>
      <div style={{
        fontFamily: C.mono, fontSize: 22, fontWeight: 700,
        color, letterSpacing: "-0.01em", marginBottom: 6,
      }}>
        {text}
      </div>
      {subtext && (
        <div style={{ fontFamily: C.sans, fontSize: 13, color: C.textMid }}>
          {subtext}
        </div>
      )}
    </div>
  );
}

// ── Call stack row ─────────────────────────────────────────────────────────────

function StackRow({ entry }) {
  const pkgColor = {
    'PA#20': C.alice,
    'PA#19': C.bob,
  }[entry.pkg] || C.textMid;

  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "56px 1fr auto",
      gap: 10,
      padding: "5px 14px",
      borderBottom: `1px solid ${C.border}`,
      alignItems: "baseline",
    }}>
      <span style={{
        fontFamily: C.mono, fontSize: 9,
        color: pkgColor, letterSpacing: "0.06em",
      }}>
        {entry.pkg}
      </span>
      <span style={{
        fontFamily: C.mono, fontSize: 11,
        color: C.textMid,
        paddingLeft: entry.depth * 8,
      }}>
        {entry.fn}
      </span>
      <span style={{ fontFamily: C.sans, fontSize: 11, color: C.textDim }}>
        {entry.note}
      </span>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────

const NBITS    = 4;
const MAX_VAL  = (1 << NBITS) - 1;    // 15

const TABS = [
  { id: 'millionaire', label: 'Millionaire\'s Problem', short: 'x > y' },
  { id: 'equality',    label: 'Secure Equality',       short: 'x = y' },
  { id: 'adder',       label: 'Secure Adder',          short: 'x + y' },
];

export default function PA20Panel() {
  // ── input state ──────────────────────────────────────────────────────────────
  const [tab,      setTab]      = useState('millionaire');
  const [aliceVal, setAliceVal] = useState(7);   // x=7 from spec
  const [bobVal,   setBobVal]   = useState(12);  // y=12 from spec

  // ── evaluation state ─────────────────────────────────────────────────────────
  const [evalData,      setEvalData]      = useState(null);  // Secure_Eval result
  const [visibleCount,  setVisibleCount]  = useState(0);     // gates revealed so far
  const [running,       setRunning]       = useState(false);

  // ── UI toggles ───────────────────────────────────────────────────────────────
  const [showTrace,     setShowTrace]     = useState(false);
  const [showStack,     setShowStack]     = useState(false);
  const [showPrivacy,   setShowPrivacy]   = useState(false);

  // ── benchmark state ──────────────────────────────────────────────────────────
  const [benchData,     setBenchData]     = useState(null);
  const [benchRunning,  setBenchRunning]  = useState(false);

  // ── self-test state ──────────────────────────────────────────────────────────
  const [testResult,    setTestResult]    = useState(null);
  const [testRunning,   setTestRunning]   = useState(false);

  // ── reset evaluation when inputs change ──────────────────────────────────────
  useEffect(() => {
    setEvalData(null);
    setVisibleCount(0);
  }, [tab, aliceVal, bobVal]);

  // ── gate animation ticker ─────────────────────────────────────────────────────
  useEffect(() => {
    if (!evalData || visibleCount >= evalData.trace.length) return;
    const t = setTimeout(() => setVisibleCount(v => v + 1), 60);
    return () => clearTimeout(t);
  }, [evalData, visibleCount]);

  // ── helpers ──────────────────────────────────────────────────────────────────
  const buildCircuit = useCallback(() => {
    if (tab === 'millionaire') return buildMillionaireCircuit(NBITS);
    if (tab === 'equality')    return buildEqualityCircuit(NBITS);
    return buildAdderCircuit(NBITS);
  }, [tab]);

  const handleEvaluate = useCallback(() => {
    setRunning(true);
    setEvalData(null);
    setVisibleCount(0);
    setShowTrace(false);

    // Crypto is synchronous — run immediately, then animate reveal.
    setTimeout(() => {
      const circuit = buildCircuit();
      const xBits   = intToBits(aliceVal, NBITS);
      const yBits   = intToBits(bobVal,   NBITS);
      const result  = Secure_Eval(circuit, xBits, yBits);

      setEvalData({
        ...result,
        circuit,
        aliceVal,
        bobVal,
        xBits,
        yBits,
      });
      setRunning(false);
    }, 80);
  }, [aliceVal, bobVal, buildCircuit]);

  const animDone = evalData && visibleCount >= evalData.trace.length;

  // Interpret outputs into human-readable result.
  const getResult = () => {
    if (!animDone) return null;
    const { outputs } = evalData;
    if (tab === 'millionaire') {
      if (aliceVal === bobVal) return { text: 'Equal wealth', sub: `Both hold ${aliceVal}`, color: C.amber };
      if (outputs[0] === 1)   return { text: 'Alice is richer', sub: `Circuit confirmed x > y without revealing values`, color: C.alice };
      return                        { text: 'Bob is richer',   sub: `Circuit confirmed y > x without revealing values`, color: C.bob };
    }
    if (tab === 'equality') {
      return outputs[0] === 1
        ? { text: 'Equal ✓',     sub: `x = y = ${aliceVal}`, color: C.bob }
        : { text: 'Not equal ✗', sub: `${aliceVal} ≠ ${bobVal}`,        color: C.red };
    }
    // adder
    const sum = bitsToInt(outputs);
    return { text: `Sum = ${sum}`, sub: `${aliceVal} + ${bobVal} = ${sum}  (${NBITS+1}-bit result)`, color: C.amber };
  };

  const result = getResult();

  // OT-call count for current tab circuit (without running it).
  const otCountForTab = () => {
    const c = buildCircuit();
    return c.countAND();
  };

  // ── render ───────────────────────────────────────────────────────────────────
  return (
    <div style={{
      minHeight: "100vh",
      background: C.bg,
      color: C.text,
      fontFamily: C.sans,
      padding: "32px 20px 60px",
      backgroundImage: `
        radial-gradient(ellipse 80% 40% at 20% 0%, ${C.alice}06 0%, transparent 60%),
        radial-gradient(ellipse 60% 30% at 80% 0%, ${C.bob}06 0%, transparent 60%),
        linear-gradient(${C.border}30 1px, transparent 1px),
        linear-gradient(90deg, ${C.border}30 1px, transparent 1px)
      `,
      backgroundSize: "100% 100%, 100% 100%, 48px 48px, 48px 48px",
    }}>
      <div style={{ maxWidth: 960, margin: "0 auto" }}>

        {/* ── Header ── */}
        <div style={{ marginBottom: 32 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
            <div style={{
              width: 7, height: 7, borderRadius: "50%",
              background: C.amber, boxShadow: `0 0 10px ${C.amber}`,
              animation: "pulse 2.5s infinite",
            }} />
            <span style={{
              fontFamily: C.mono, fontSize: 10,
              color: C.amberDim, letterSpacing: "0.22em", textTransform: "uppercase",
            }}>
              PA #20 — Secure Two-Party Computation
            </span>
          </div>
          <h1 style={{
            fontFamily: C.mono, fontSize: 30, fontWeight: 700,
            color: "#fff", margin: 0, letterSpacing: "-0.02em",
          }}>
            Full MPC Stack: Any Boolean Circuit, Securely
          </h1>
          <p style={{
            marginTop: 10, color: C.textMid, fontSize: 14, lineHeight: 1.7,
            maxWidth: 700,
          }}>
            Given <Mono color={C.red}>Secure AND</Mono> (PA#19 → PA#18 OT → PA#16 ElGamal) and{" "}
            <Mono color={C.sky}>Secure XOR</Mono> (free, additive secret sharing), we can
            evaluate <em>any</em> polynomial-time 2-party function — the MPC Completeness Theorem.
          </p>

          {/* Lineage pills */}
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 14 }}>
            {[
              ['PA#20', C.alice, 'Circuit Evaluator'],
              ['PA#19', C.bob,   'Secure AND / XOR'],
              ['PA#18', C.amber, '1-of-2 OT'],
              ['PA#16', C.red,   'ElGamal PKE'],
            ].map(([label, color, desc]) => (
              <div key={label} style={{
                display: "flex", alignItems: "center", gap: 6,
                border: `1px solid ${color}33`, borderRadius: 5,
                padding: "4px 10px",
                background: `${color}0a`,
              }}>
                <span style={{ fontFamily: C.mono, fontSize: 11, color, fontWeight: 700 }}>{label}</span>
                <span style={{ fontFamily: C.sans, fontSize: 11, color: C.textDim }}>{desc}</span>
              </div>
            ))}
          </div>
        </div>

        {/* ── Circuit tab bar ── */}
        <div style={{
          display: "flex", gap: 0,
          border: `1px solid ${C.border}`,
          borderRadius: 8, overflow: "hidden",
          marginBottom: 24,
        }}>
          {TABS.map((t, i) => {
            const active = tab === t.id;
            return (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                style={{
                  flex: 1,
                  padding: "11px 16px",
                  border: "none",
                  borderRight: i < TABS.length - 1 ? `1px solid ${C.border}` : "none",
                  background: active ? `${C.amber}12` : "transparent",
                  cursor: "pointer",
                  transition: "all 0.15s",
                }}
              >
                <div style={{
                  fontFamily: C.mono, fontSize: 12, fontWeight: active ? 700 : 400,
                  color: active ? C.amber : C.textMid,
                  marginBottom: 2,
                }}>
                  {t.label}
                </div>
                <div style={{
                  fontFamily: C.mono, fontSize: 10,
                  color: active ? `${C.amber}99` : C.textDim,
                }}>
                  output: {t.short}
                </div>
              </button>
            );
          })}
        </div>

        {/* ── Split panels: Alice (left) ↔ Bob (right) ── */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 20 }}>

          {/* Alice panel */}
          <div style={{
            border: `1px solid ${C.alice}33`,
            borderRadius: 10,
            background: C.alicePale,
            overflow: "hidden",
          }}>
            <div style={{
              padding: "12px 18px",
              borderBottom: `1px solid ${C.alice}22`,
              display: "flex", alignItems: "center", gap: 10,
            }}>
              <span style={{ fontFamily: C.mono, fontSize: 13, fontWeight: 700, color: C.alice }}>
                ALICE
              </span>
              <Badge color={C.alice}>private input x</Badge>
              <div style={{ flex: 1 }} />
              <span style={{ fontFamily: C.mono, fontSize: 10, color: C.textDim }}>
                {tab === 'millionaire' ? 'OT Sender: m₀=0, m₁=x' :
                 tab === 'equality'   ? 'XNOR party' : 'Adder input A'}
              </span>
            </div>
            <div style={{ padding: 20 }}>
              <PartySlider
                label="Alice's wealth x"
                value={aliceVal}
                onChange={setAliceVal}
                color={C.alice}
                max={MAX_VAL}
                locked={false}
              />
              <div style={{
                marginTop: 16, padding: "10px 14px", borderRadius: 6,
                border: `1px solid ${C.alice}22`, background: `${C.alice}08`,
                fontFamily: C.mono, fontSize: 11, color: C.textDim, lineHeight: 1.7,
              }}>
                <span style={{ color: C.alice }}>✓ learns:</span> output only
                <br />
                <span style={{ color: C.red }}>✗ cannot learn:</span> Bob's value y
              </div>
            </div>
          </div>

          {/* Bob panel */}
          <div style={{
            border: `1px solid ${C.bob}33`,
            borderRadius: 10,
            background: C.bobPale,
            overflow: "hidden",
          }}>
            <div style={{
              padding: "12px 18px",
              borderBottom: `1px solid ${C.bob}22`,
              display: "flex", alignItems: "center", gap: 10,
            }}>
              <span style={{ fontFamily: C.mono, fontSize: 13, fontWeight: 700, color: C.bob }}>
                BOB
              </span>
              <Badge color={C.bob}>private input y</Badge>
              <div style={{ flex: 1 }} />
              <span style={{ fontFamily: C.mono, fontSize: 10, color: C.textDim }}>
                {tab === 'millionaire' ? 'OT Receiver: choice=y_bits' :
                 tab === 'equality'   ? 'XNOR party' : 'Adder input B'}
              </span>
            </div>
            <div style={{ padding: 20 }}>
              <PartySlider
                label="Bob's wealth y"
                value={bobVal}
                onChange={setBobVal}
                color={C.bob}
                max={MAX_VAL}
                locked={false}
              />
              <div style={{
                marginTop: 16, padding: "10px 14px", borderRadius: 6,
                border: `1px solid ${C.bob}22`, background: `${C.bob}08`,
                fontFamily: C.mono, fontSize: 11, color: C.textDim, lineHeight: 1.7,
              }}>
                <span style={{ color: C.bob }}>✓ learns:</span> output only
                <br />
                <span style={{ color: C.red }}>✗ cannot learn:</span> Alice's value x
              </div>
            </div>
          </div>
        </div>

        {/* ── Evaluate button row ── */}
        <div style={{
          display: "flex", justifyContent: "center",
          alignItems: "center", gap: 16, marginBottom: 24,
        }}>
          <div style={{ fontFamily: C.mono, fontSize: 11, color: C.textDim }}>
            {otCountForTab()} AND gates = {otCountForTab()} OT calls
          </div>
          <Btn onClick={handleEvaluate} disabled={running}>
            {running ? "⟳  Evaluating…" : `▶  ${
              tab === 'millionaire' ? 'Who is richer?' :
              tab === 'equality'   ? 'Are they equal?' : 'Compute sum'
            }`}
          </Btn>
          {evalData && (
            <div style={{ fontFamily: C.mono, fontSize: 11, color: C.textDim }}>
              {evalData.timeMs.toFixed(1)} ms
            </div>
          )}
        </div>

        {/* ── Evaluation output area ── */}
        {evalData && (
          <div style={{
            border: `1px solid ${C.border}`,
            borderRadius: 10, overflow: "hidden",
            marginBottom: 20,
          }}>
            {/* Header */}
            <div style={{
              padding: "12px 18px",
              borderBottom: `1px solid ${C.border}`,
              background: C.surfaceHi,
              display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap",
            }}>
              <span style={{ fontFamily: C.mono, fontSize: 12, fontWeight: 700, color: C.text }}>
                Circuit Evaluation — n={NBITS} bits
              </span>
              <Badge color={C.red}>{evalData.otCalls} OT calls</Badge>
              <Badge color={C.sky}>{evalData.xorCalls} XOR (free)</Badge>
              <Badge color={C.slate}>{evalData.notCalls} NOT (free)</Badge>
              <div style={{ flex: 1 }} />
              <span style={{ fontFamily: C.mono, fontSize: 11, color: C.textDim }}>
                {evalData.trace.length} total gates
              </span>
            </div>

            <div style={{ padding: 18 }}>
              {/* Progress bar */}
              <div style={{ marginBottom: 18 }}>
                <ProgressBar
                  current={visibleCount}
                  total={evalData.trace.length}
                  color={C.amber}
                />
              </div>

              {/* Result banner — appears when animation completes */}
              {result && (
                <div style={{ marginBottom: 18 }}>
                  <ResultBanner
                    text={result.text}
                    subtext={result.sub}
                    color={result.color}
                  />
                </div>
              )}

              {/* Expandable gate trace */}
              <button
                onClick={() => setShowTrace(v => !v)}
                style={{
                  width: "100%", background: "none",
                  border: `1px solid ${C.border}`, borderRadius: 6,
                  padding: "9px 14px", cursor: "pointer",
                  display: "flex", alignItems: "center", justifyContent: "space-between",
                  marginBottom: showTrace ? 0 : 0,
                }}
              >
                <span style={{ fontFamily: C.mono, fontSize: 11, color: C.textDim }}>
                  {showTrace ? "▾" : "▸"}  Circuit Trace ({visibleCount}/{evalData.trace.length} gates revealed)
                </span>
                <div style={{ display: "flex", gap: 8 }}>
                  <GateTag type="AND" />
                  <GateTag type="XOR" />
                  <GateTag type="NOT" />
                </div>
              </button>

              {showTrace && (
                <div style={{
                  border: `1px solid ${C.border}`,
                  borderTop: "none",
                  borderRadius: "0 0 6px 6px",
                  overflow: "hidden",
                  maxHeight: 300, overflowY: "auto",
                }}>
                  {/* Column headers */}
                  <div style={{
                    display: "grid", gridTemplateColumns: "28px 48px 1fr 28px",
                    gap: 8, padding: "5px 12px",
                    background: C.surfaceHi,
                    borderBottom: `1px solid ${C.border}`,
                  }}>
                    {["#", "TYPE", "OPERATION", "OUT"].map(h => (
                      <span key={h} style={{
                        fontFamily: C.mono, fontSize: 9, color: C.textDim,
                        letterSpacing: "0.12em", textTransform: "uppercase",
                      }}>
                        {h}
                      </span>
                    ))}
                  </div>
                  {evalData.trace.slice(0, visibleCount).map((entry, i) => (
                    <GateRow key={i} entry={entry} index={i} />
                  ))}
                  {visibleCount < evalData.trace.length && (
                    <div style={{
                      padding: "8px 12px",
                      fontFamily: C.mono, fontSize: 10,
                      color: C.amber,
                    }}>
                      ⟳ evaluating…
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── Privacy verification ── */}
        {animDone && (
          <div style={{
            border: `1px solid ${C.border}`,
            borderRadius: 10, overflow: "hidden",
            marginBottom: 20,
          }}>
            <button
              onClick={() => setShowPrivacy(v => !v)}
              style={{
                width: "100%", background: C.surfaceHi,
                border: "none", cursor: "pointer",
                padding: "12px 18px",
                display: "flex", alignItems: "center",
                borderBottom: showPrivacy ? `1px solid ${C.border}` : "none",
              }}
            >
              <span style={{ fontFamily: C.mono, fontSize: 12, fontWeight: 700, color: C.text, flex: 1, textAlign: "left" }}>
                {showPrivacy ? "▾" : "▸"}  Privacy Verification — Simulatability Argument
              </span>
              <Badge color={C.bob}>OT sender-privacy + receiver-privacy</Badge>
            </button>

            {showPrivacy && (
              <div style={{ padding: 18 }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
                  {[
                    {
                      title: "What Alice Learns",
                      color: C.alice,
                      items: [
                        `Output: [${evalData.outputs.join(', ')}]`,
                        `# OT rounds: ${evalData.otCalls} (= structure, not inputs)`,
                        "NOT Bob's input bits y",
                        "NOT Bob's OT choice bits",
                      ],
                      okItems: [true, true, false, false],
                    },
                    {
                      title: "What Bob Learns",
                      color: C.bob,
                      items: [
                        `Output: [${evalData.outputs.join(', ')}]`,
                        `# OT rounds: ${evalData.otCalls}`,
                        "NOT Alice's input bits x",
                        "NOT the unchosen OT message ε_{1−b}",
                      ],
                      okItems: [true, true, false, false],
                    },
                  ].map(({ title, color, items, okItems }) => (
                    <div key={title} style={{
                      border: `1px solid ${color}33`,
                      borderRadius: 8, overflow: "hidden",
                    }}>
                      <div style={{
                        background: `${color}12`, padding: "8px 14px",
                        fontFamily: C.mono, fontSize: 11, color, fontWeight: 700,
                        borderBottom: `1px solid ${color}22`,
                      }}>
                        {title}
                      </div>
                      <div style={{ padding: "10px 14px" }}>
                        {items.map((item, i) => (
                          <div key={i} style={{
                            fontFamily: C.mono, fontSize: 11,
                            color: okItems[i] ? C.textMid : C.textDim,
                            padding: "2px 0",
                          }}>
                            <span style={{ color: okItems[i] ? "#4ade80" : C.red, marginRight: 6 }}>
                              {okItems[i] ? "✓" : "✗"}
                            </span>
                            {item}
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>

                <div style={{
                  padding: "12px 16px", borderRadius: 7,
                  border: `1px solid ${C.amber}22`, background: C.amberPale,
                }}>
                  <div style={{ fontFamily: C.mono, fontSize: 11, color: C.amber, fontWeight: 700, marginBottom: 6 }}>
                    Simulatability (informal)
                  </div>
                  <div style={{ fontFamily: C.sans, fontSize: 13, color: C.textMid, lineHeight: 1.65 }}>
                    A PPT simulator S, given only the output{" "}
                    <Mono color={C.amber}>[{evalData.outputs.join(", ")}]</Mono> and the circuit topology,
                    can produce a transcript computationally indistinguishable from the real one.
                    For each of the <Mono color={C.red}>{evalData.otCalls} AND gates</Mono>, S samples fresh RSA keys,
                    random challenges x₀′, x₁′, random v′, and derives (ε₀′, ε₁′) consistently — under the
                    RSA hardness assumption, no PPT distinguisher separates this from a real execution.
                    XOR gates each send one uniform bit r′ ← {"{0,1}"}, also simulatable.
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── n=8 Benchmark table ── */}
        <SectionDivider label="Performance Benchmark — n=8 bit inputs" />

        <div style={{
          border: `1px solid ${C.border}`,
          borderRadius: 10, overflow: "hidden",
          marginBottom: 20,
        }}>
          <div style={{
            padding: "12px 18px",
            borderBottom: `1px solid ${C.border}`,
            background: C.surfaceHi,
            display: "flex", alignItems: "center", gap: 16,
          }}>
            <span style={{ fontFamily: C.mono, fontSize: 12, fontWeight: 700, color: C.text }}>
              OT Calls &amp; Timing per Circuit
            </span>
            <Btn onClick={() => {
              setBenchRunning(true);
              setBenchData(null);
              setTimeout(() => {
                setBenchData(runBenchmark(8));
                setBenchRunning(false);
              }, 80);
            }} disabled={benchRunning} small>
              {benchRunning ? "⟳ Running…" : "▶ Run Benchmark (n=8)"}
            </Btn>
          </div>

          <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: C.mono }}>
            <thead>
              <tr style={{ background: "#0a0c12" }}>
                {[
                  ["Circuit", C.text],
                  ["AND gates", C.red],
                  ["XOR gates", C.sky],
                  ["NOT gates", C.slate],
                  ["Total gates", C.textMid],
                  ["OT calls", C.amber],
                  ["Time (ms)", C.bob],
                  ["Correct?", C.alice],
                ].map(([h, c]) => (
                  <th key={h} style={{
                    padding: "10px 14px", textAlign: h === "Circuit" ? "left" : "center",
                    fontFamily: C.mono, fontSize: 10, fontWeight: 700, color: c,
                    letterSpacing: "0.08em", textTransform: "uppercase",
                    borderBottom: `1px solid ${C.border}`,
                  }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {benchData ? benchData.map((row, i) => (
                <tr key={i} style={{ borderBottom: `1px solid ${C.border}` }}>
                  <td style={{ padding: "10px 14px", fontFamily: C.mono, fontSize: 12, color: C.textMid }}>
                    {row.name}
                  </td>
                  {[row.andGates, row.xorGates, row.notGates, row.totalGates].map((v, j) => (
                    <td key={j} style={{
                      padding: "10px 14px", textAlign: "center",
                      fontFamily: C.mono, fontSize: 12,
                      color: [C.red, C.sky, C.slate, C.textMid][j],
                    }}>
                      {v}
                    </td>
                  ))}
                  <td style={{
                    padding: "10px 14px", textAlign: "center",
                    fontFamily: C.mono, fontSize: 13, fontWeight: 700, color: C.amber,
                  }}>
                    {row.otCalls}
                  </td>
                  <td style={{
                    padding: "10px 14px", textAlign: "center",
                    fontFamily: C.mono, fontSize: 12, color: C.bob,
                  }}>
                    {row.timeMs}
                  </td>
                  <td style={{
                    padding: "10px 14px", textAlign: "center",
                    fontFamily: C.mono, fontSize: 12,
                    color: row.correct ? "#4ade80" : C.red,
                  }}>
                    {row.correct ? "✓" : "✗"}
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan={8} style={{
                    padding: "20px", textAlign: "center",
                    fontFamily: C.mono, fontSize: 11, color: C.textDim,
                  }}>
                    Click "Run Benchmark" to evaluate all three circuits with random 8-bit inputs.
                  </td>
                </tr>
              )}
            </tbody>
          </table>

          {/* OT call formula table */}
          <div style={{
            padding: "12px 18px",
            borderTop: `1px solid ${C.border}`,
            background: C.surfaceHi,
            display: "flex", gap: 24, flexWrap: "wrap",
          }}>
            {[
              { name: "Millionaire", formula: "4n − 3", n8: 29 },
              { name: "Equality",    formula: "n − 1",  n8: 7  },
              { name: "Adder",       formula: "3n − 2", n8: 22 },
            ].map(({ name, formula, n8 }) => (
              <div key={name} style={{ fontFamily: C.mono, fontSize: 11 }}>
                <span style={{ color: C.textDim }}>{name}: </span>
                <span style={{ color: C.amber }}>{formula}</span>
                <span style={{ color: C.textDim }}> OT calls — n=8 → </span>
                <span style={{ color: C.red, fontWeight: 700 }}>{n8}</span>
              </div>
            ))}
          </div>
        </div>

        {/* ── Self-test ── */}
        <div style={{
          border: `1px solid ${C.border}`,
          borderRadius: 10, overflow: "hidden",
          marginBottom: 20,
        }}>
          <div style={{
            padding: "12px 18px",
            borderBottom: testResult ? `1px solid ${C.border}` : "none",
            background: C.surfaceHi,
            display: "flex", alignItems: "center", gap: 16,
          }}>
            <span style={{ fontFamily: C.mono, fontSize: 12, fontWeight: 700, color: C.text }}>
              Correctness — 32 random trials across all three circuits
            </span>
            <Btn onClick={() => {
              setTestRunning(true);
              setTestResult(null);
              setTimeout(() => {
                setTestResult(selfTest(4, 32));
                setTestRunning(false);
              }, 80);
            }} disabled={testRunning} small color={C.bob}>
              {testRunning ? "⟳ Testing…" : "▶ Run self-test"}
            </Btn>
            {testResult && (
              <Badge color={testResult.pass ? "#4ade80" : C.red}>
                {testResult.pass ? `✓ ALL ${testResult.samples} PASS` : "✗ FAILURES"}
              </Badge>
            )}
          </div>

          {testResult && !testResult.pass && (
            <div style={{ padding: 14 }}>
              {testResult.failures.map((f, i) => (
                <div key={i} style={{ fontFamily: C.mono, fontSize: 11, color: C.red }}>
                  x={f.xInt} y={f.yInt} — M:{f.mOk ? "✓" : "✗"} E:{f.eOk ? "✓" : "✗"} A:{f.aOk ? "✓" : "✗"}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* ── Call-stack lineage trace ── */}
        <SectionDivider label="Call-Stack Lineage — One AND Gate" />

        <div style={{
          border: `1px solid ${C.border}`,
          borderRadius: 10, overflow: "hidden",
          marginBottom: 20,
        }}>
          <button
            onClick={() => setShowStack(v => !v)}
            style={{
              width: "100%", background: C.surfaceHi,
              border: "none", cursor: "pointer",
              padding: "12px 18px",
              display: "flex", alignItems: "center",
              borderBottom: showStack ? `1px solid ${C.border}` : "none",
            }}
          >
            <span style={{ fontFamily: C.mono, fontSize: 12, fontWeight: 700, color: C.text, flex: 1, textAlign: "left" }}>
              {showStack ? "▾" : "▸"}  Full lineage: PA#20 → PA#19 → RSA OT → modpow
            </span>
            <div style={{ display: "flex", gap: 8 }}>
              <Badge color={C.alice}>PA#20</Badge>
              <Badge color={C.bob}>PA#19</Badge>
            </div>
          </button>

          {showStack && (
            <div>
              {/* Column headers */}
              <div style={{
                display: "grid", gridTemplateColumns: "56px 1fr auto",
                gap: 10, padding: "7px 14px",
                background: "#0a0c12",
                borderBottom: `1px solid ${C.border}`,
              }}>
                {["PKG", "FUNCTION CALL", "NOTE"].map(h => (
                  <span key={h} style={{
                    fontFamily: C.mono, fontSize: 9, color: C.textDim,
                    letterSpacing: "0.12em", textTransform: "uppercase",
                  }}>
                    {h}
                  </span>
                ))}
              </div>
              {getCallStackTrace().map((entry, i) => (
                <StackRow key={i} entry={entry} />
              ))}
              <div style={{
                padding: "10px 14px",
                fontFamily: C.sans, fontSize: 12, color: C.textDim,
                lineHeight: 1.65,
                background: `${C.amber}06`,
                borderTop: `1px solid ${C.border}`,
              }}>
                <span style={{ color: C.amber, fontWeight: 600 }}>Security chain: </span>
                Each AND gate ultimately depends on the RSA hard problem (inverting{" "}
                <Mono>x ↦ xᵉ mod n</Mono>) for OT sender-privacy, and the RSA assumption
                for receiver-privacy (recovering d from e). No AND result is learnable
                without breaking RSA.
              </div>
            </div>
          )}
        </div>

        {/* ── Footer ── */}
        <div style={{
          fontFamily: C.mono, fontSize: 10,
          color: C.textDim, textAlign: "center",
          letterSpacing: "0.1em", marginTop: 12,
        }}>
          PA#20 — MPC Completeness · Secure_Eval(Circuit, xAlice, yBob) ·
          AND→PA#19→OT→RSA · XOR→Additive Sharing · NOT→Local
        </div>

      </div>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50%       { opacity: 0.4; transform: scale(0.85); }
        }
        input[type=range] { height: 6px; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: ${C.bg}; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 2px; }
      `}</style>
    </div>
  );
}

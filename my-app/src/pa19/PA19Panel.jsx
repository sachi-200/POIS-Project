/**
 * PA19Panel.jsx — Secure AND Gate: Interactive Demo
 *
 * Aesthetic: cryptographic-terminal noir
 *   • Near-black background with a subtle grid texture
 *   • Alice side: neon green (#00ff88)  — OT sender
 *   • Bob side:   electric cyan (#00d4ff) — OT receiver
 *   • Amber (#ffb800) for shared output / transcript
 *   • Monospaced type (IBM Plex Mono / Courier Prime / fallback)
 */

import { useState, useCallback, useRef, useEffect } from "react";
import { secureAND, secureXOR, runTruthTableTests } from "./crypto.js";

// ─────────────────────────────────────────────
// Tiny design tokens (inline; no Tailwind needed)
// ─────────────────────────────────────────────
const C = {
  bg:       "#0a0c0f",
  surface:  "#111418",
  border:   "#1e2530",
  alice:    "#00ff88",
  aliceDim: "#00994d",
  bob:      "#00d4ff",
  bobDim:   "#007a99",
  amber:    "#ffb800",
  amberDim: "#997000",
  red:      "#ff4466",
  text:     "#c8d6e0",
  textDim:  "#5a6a7a",
  mono:     "'IBM Plex Mono', 'Courier New', monospace",
  sans:     "'IBM Plex Sans', system-ui, sans-serif",
};

// ─────────────────────────────────────────────
// Small reusable UI atoms
// ─────────────────────────────────────────────

function Badge({ color, children }) {
  return (
    <span style={{
      fontFamily: C.mono,
      fontSize: 11,
      padding: "2px 8px",
      borderRadius: 3,
      border: `1px solid ${color}44`,
      color,
      background: `${color}11`,
      letterSpacing: "0.05em",
    }}>
      {children}
    </span>
  );
}

function BitButton({ value, active, color, onClick }) {
  return (
    <button
      onClick={onClick}
      style={{
        width: 52,
        height: 52,
        borderRadius: 6,
        border: `2px solid ${active ? color : C.border}`,
        background: active ? `${color}18` : "transparent",
        color: active ? color : C.textDim,
        fontFamily: C.mono,
        fontSize: 24,
        fontWeight: 700,
        cursor: "pointer",
        transition: "all 0.15s ease",
        outline: "none",
      }}
    >
      {value}
    </button>
  );
}

function Panel({ color, title, badge, children }) {
  return (
    <div style={{
      flex: 1,
      minWidth: 0,
      border: `1px solid ${color}33`,
      borderRadius: 10,
      background: `${color}05`,
      overflow: "hidden",
    }}>
      <div style={{
        padding: "12px 18px",
        borderBottom: `1px solid ${color}22`,
        display: "flex",
        alignItems: "center",
        gap: 10,
      }}>
        <span style={{ color, fontFamily: C.mono, fontWeight: 700, fontSize: 13 }}>
          {title}
        </span>
        {badge && <Badge color={color}>{badge}</Badge>}
      </div>
      <div style={{ padding: "18px" }}>{children}</div>
    </div>
  );
}

function Label({ children, color }) {
  return (
    <div style={{
      fontFamily: C.mono,
      fontSize: 11,
      color: color || C.textDim,
      marginBottom: 6,
      letterSpacing: "0.08em",
      textTransform: "uppercase",
    }}>
      {children}
    </div>
  );
}

function StepEntry({ step, index, visible }) {
  return (
    <div style={{
      opacity: visible ? 1 : 0,
      transform: visible ? "translateY(0)" : "translateY(8px)",
      transition: `opacity 0.3s ease ${index * 0.12}s, transform 0.3s ease ${index * 0.12}s`,
      marginBottom: 14,
      borderLeft: `2px solid ${C.amber}44`,
      paddingLeft: 14,
    }}>
      <div style={{
        fontFamily: C.mono,
        fontSize: 12,
        color: C.amber,
        fontWeight: 700,
        marginBottom: 4,
      }}>
        {step.label}
      </div>
      <div style={{
        fontFamily: C.sans,
        fontSize: 13,
        color: C.text,
        marginBottom: 6,
      }}>
        {step.desc}
      </div>
      <pre style={{
        fontFamily: C.mono,
        fontSize: 11,
        color: C.textDim,
        background: "#0d1117",
        border: `1px solid ${C.border}`,
        borderRadius: 5,
        padding: "8px 12px",
        margin: 0,
        overflowX: "auto",
        lineHeight: 1.7,
        whiteSpace: "pre-wrap",
        wordBreak: "break-all",
      }}>
        {step.detail}
      </pre>
    </div>
  );
}

function TranscriptRow({ label, value, color }) {
  return (
    <div style={{
      display: "flex",
      gap: 12,
      marginBottom: 8,
      alignItems: "flex-start",
    }}>
      <span style={{
        fontFamily: C.mono,
        fontSize: 11,
        color,
        minWidth: 160,
        paddingTop: 2,
      }}>
        {label}
      </span>
      <span style={{
        fontFamily: C.mono,
        fontSize: 11,
        color: C.textDim,
        wordBreak: "break-all",
        lineHeight: 1.6,
      }}>
        {value}
      </span>
    </div>
  );
}

function KnowledgeCard({ title, color, knows, doesNot }) {
  return (
    <div style={{
      border: `1px solid ${color}33`,
      borderRadius: 8,
      overflow: "hidden",
      flex: 1,
      minWidth: 0,
    }}>
      <div style={{
        background: `${color}12`,
        padding: "10px 14px",
        fontFamily: C.mono,
        fontSize: 12,
        color,
        fontWeight: 700,
        borderBottom: `1px solid ${color}22`,
      }}>
        {title}
      </div>
      <div style={{ padding: "12px 14px" }}>
        <div style={{ marginBottom: 10 }}>
          <div style={{
            fontFamily: C.mono, fontSize: 10,
            color: "#00ff88", marginBottom: 5, letterSpacing: "0.1em",
          }}>
            ✓ LEARNS
          </div>
          {knows.map((k, i) => (
            <div key={i} style={{
              fontFamily: C.mono, fontSize: 11,
              color: C.text, padding: "2px 0",
            }}>
              {k}
            </div>
          ))}
        </div>
        <div>
          <div style={{
            fontFamily: C.mono, fontSize: 10,
            color: C.red, marginBottom: 5, letterSpacing: "0.1em",
          }}>
            ✗ CANNOT LEARN
          </div>
          {doesNot.map((d, i) => (
            <div key={i} style={{
              fontFamily: C.mono, fontSize: 11,
              color: C.textDim, padding: "2px 0",
            }}>
              {d}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// Truth-table mini-table
// ─────────────────────────────────────────────
function TruthRow({ row }) {
  const ok = row.andOk && row.xorOk;
  return (
    <tr>
      {[row.a, row.b, row.expectedAND, row.expectedXOR].map((v, i) => (
        <td key={i} style={{
          fontFamily: C.mono,
          fontSize: 13,
          padding: "8px 14px",
          textAlign: "center",
          color: i < 2 ? C.textDim : (i === 2 ? C.alice : C.bob),
          borderBottom: `1px solid ${C.border}`,
        }}>
          {v}
        </td>
      ))}
      <td style={{
        fontFamily: C.mono,
        fontSize: 12,
        padding: "8px 14px",
        textAlign: "center",
        color: ok ? "#00ff88" : C.red,
        borderBottom: `1px solid ${C.border}`,
      }}>
        {ok ? `✓ ${row.andPasses + row.xorPasses}/${(row.andPasses + row.xorPasses)} passes` : "✗ FAIL"}
      </td>
    </tr>
  );
}

// ─────────────────────────────────────────────
// Main Component
// ─────────────────────────────────────────────
export default function PA19Panel() {
  const [a, setA] = useState(null);          // Alice's bit
  const [b, setB] = useState(null);          // Bob's bit
  const [mode, setMode] = useState("and");   // "and" | "xor"

  const [result, setResult]       = useState(null);
  const [steps, setSteps]         = useState([]);
  const [transcript, setTranscript] = useState(null);
  const [aliceView, setAliceView] = useState(null);
  const [bobView, setBobView]     = useState(null);
  const [stepsVisible, setStepsVisible] = useState(false);
  const [running, setRunning]     = useState(false);

  const [allResults, setAllResults] = useState(null);
  const [testRunning, setTestRunning] = useState(false);

  const logRef = useRef(null);

  const reset = () => {
    setResult(null);
    setSteps([]);
    setTranscript(null);
    setAliceView(null);
    setBobView(null);
    setStepsVisible(false);
  };

  useEffect(() => { reset(); }, [a, b, mode]);

  const compute = useCallback(() => {
    if (a === null || b === null) return;
    setRunning(true);
    reset();

    // Small artificial delay so the animation feels intentional
    setTimeout(() => {
      if (mode === "and") {
        const out = secureAND(a, b);
        setResult(out.result);
        setSteps(out.otDetail.steps);
        setTranscript(out.otDetail.transcript);
        setAliceView(out.otDetail.aliceView);
        setBobView(out.otDetail.bobView);
      } else {
        const out = secureXOR(a, b);
        setResult(out.result);
        setSteps(out.steps.map(s => ({ label: s.label, desc: "", detail: s.detail })));
        setTranscript({ "Alice → Bob (r)": { r_sent_to_bob: out.r.toString() } });
        setAliceView(out.aliceView);
        setBobView(out.bobView);
      }
      setStepsVisible(true);
      setRunning(false);
      setTimeout(() => logRef.current?.scrollIntoView({ behavior: "smooth" }), 100);
    }, 180);
  }, [a, b, mode]);

  const runAll = useCallback(() => {
    setTestRunning(true);
    setAllResults(null);
    setTimeout(() => {
      const res = runTruthTableTests(50);
      setAllResults(res);
      setTestRunning(false);
    }, 200);
  }, []);

  const opLabel = mode === "and" ? "AND" : "XOR";
  const opColor = mode === "and" ? C.alice : C.bob;
  const expectedResult = (a !== null && b !== null)
    ? (mode === "and" ? (a & b) : (a ^ b))
    : null;

  // ── render ──────────────────────────────────
  return (
    <div style={{
      minHeight: "100vh",
      background: C.bg,
      color: C.text,
      fontFamily: C.sans,
      padding: "32px 24px",
      backgroundImage: `
        linear-gradient(${C.border}33 1px, transparent 1px),
        linear-gradient(90deg, ${C.border}33 1px, transparent 1px)
      `,
      backgroundSize: "40px 40px",
    }}>
      <div style={{ maxWidth: 900, margin: "0 auto" }}>

        {/* ── Header ── */}
        <div style={{ marginBottom: 36 }}>
          <div style={{
            display: "flex",
            alignItems: "center",
            gap: 14,
            marginBottom: 8,
          }}>
            <div style={{
              width: 8, height: 8, borderRadius: "50%",
              background: C.alice, boxShadow: `0 0 8px ${C.alice}`,
              animation: "pulse 2s infinite",
            }} />
            <span style={{
              fontFamily: C.mono,
              fontSize: 11,
              color: C.aliceDim,
              letterSpacing: "0.2em",
              textTransform: "uppercase",
            }}>
              PA #19 — Secure Two-Party Computation
            </span>
          </div>
          <h1 style={{
            fontFamily: C.mono,
            fontSize: 28,
            fontWeight: 700,
            color: "#fff",
            margin: 0,
            letterSpacing: "-0.02em",
          }}>
            Secure AND Gate via Oblivious Transfer
          </h1>
          <p style={{
            marginTop: 10,
            color: C.textDim,
            fontSize: 14,
            lineHeight: 1.6,
            maxWidth: 600,
          }}>
            Alice holds <code style={{ color: C.alice }}>a ∈ {"{0,1}"}</code> and Bob holds{" "}
            <code style={{ color: C.bob }}>b ∈ {"{0,1}"}</code>. Using 1-of-2 OT,
            both parties compute <code style={{ color: C.amber }}>a ∧ b</code> — neither learns
            the other's private input.
          </p>
        </div>

        {/* ── Mode toggle ── */}
        <div style={{ display: "flex", gap: 8, marginBottom: 28 }}>
          {[["and", "⊙  Secure AND (via OT)"], ["xor", "⊕  Secure XOR (free)"]].map(([m, label]) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              style={{
                padding: "8px 18px",
                borderRadius: 6,
                border: `1px solid ${mode === m ? (m === "and" ? C.alice : C.bob) : C.border}`,
                background: mode === m ? `${m === "and" ? C.alice : C.bob}15` : "transparent",
                color: mode === m ? (m === "and" ? C.alice : C.bob) : C.textDim,
                fontFamily: C.mono,
                fontSize: 12,
                cursor: "pointer",
                transition: "all 0.15s ease",
              }}
            >
              {label}
            </button>
          ))}
        </div>

        {/* ── Alice & Bob input panels ── */}
        <div style={{ display: "flex", gap: 16, marginBottom: 24, flexWrap: "wrap" }}>

          {/* Alice */}
          <Panel color={C.alice} title="Alice — OT Sender" badge="m₀=0, m₁=a">
            <Label color={C.aliceDim}>Alice's private bit a</Label>
            <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
              <BitButton value={0} active={a === 0} color={C.alice} onClick={() => setA(0)} />
              <BitButton value={1} active={a === 1} color={C.alice} onClick={() => setA(1)} />
            </div>
            {a !== null && (
              <div style={{
                fontFamily: C.mono, fontSize: 12,
                color: C.aliceDim, lineHeight: 1.7,
              }}>
                OT messages:<br />
                <span style={{ color: C.alice }}>m₀ = 0,  m₁ = {a}</span>
              </div>
            )}
            {mode === "and" && (
              <div style={{
                marginTop: 14,
                fontFamily: C.mono, fontSize: 11,
                color: C.textDim, lineHeight: 1.7,
                borderTop: `1px solid ${C.border}`,
                paddingTop: 12,
              }}>
                <span style={{ color: C.red }}>✗ will not learn</span> Bob's bit b<br />
                <span style={{ color: "#00ff88" }}>✓ will output</span> a ∧ b locally
              </div>
            )}
          </Panel>

          {/* Bob */}
          <Panel color={C.bob} title="Bob — OT Receiver" badge="choice=b">
            <Label color={C.bobDim}>Bob's private bit b</Label>
            <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
              <BitButton value={0} active={b === 0} color={C.bob} onClick={() => setB(0)} />
              <BitButton value={1} active={b === 1} color={C.bob} onClick={() => setB(1)} />
            </div>
            {b !== null && (
              <div style={{
                fontFamily: C.mono, fontSize: 12,
                color: C.bobDim, lineHeight: 1.7,
              }}>
                OT choice bit:<br />
                <span style={{ color: C.bob }}>b = {b}  →  will receive m_{b}</span>
              </div>
            )}
            {mode === "and" && (
              <div style={{
                marginTop: 14,
                fontFamily: C.mono, fontSize: 11,
                color: C.textDim, lineHeight: 1.7,
                borderTop: `1px solid ${C.border}`,
                paddingTop: 12,
              }}>
                <span style={{ color: C.red }}>✗ will not learn</span> m_{"{1−b}"} (other message)<br />
                <span style={{ color: "#00ff88" }}>✓ will receive</span> m_b = a ∧ b
              </div>
            )}
          </Panel>

          {/* Expected output card */}
          <div style={{
            minWidth: 160,
            border: `1px solid ${C.amber}33`,
            borderRadius: 10,
            background: `${C.amber}05`,
            overflow: "hidden",
          }}>
            <div style={{
              padding: "12px 18px",
              borderBottom: `1px solid ${C.amber}22`,
              fontFamily: C.mono,
              fontSize: 13,
              fontWeight: 700,
              color: C.amber,
            }}>
              Output
            </div>
            <div style={{ padding: 18, textAlign: "center" }}>
              <div style={{
                fontFamily: C.mono,
                fontSize: 48,
                fontWeight: 700,
                color: result !== null ? C.amber : C.border,
                lineHeight: 1,
                marginBottom: 8,
                textShadow: result !== null ? `0 0 20px ${C.amber}66` : "none",
                transition: "all 0.3s ease",
              }}>
                {result !== null ? result : "?"}
              </div>
              <div style={{
                fontFamily: C.mono,
                fontSize: 11,
                color: C.amberDim,
              }}>
                {a !== null && b !== null
                  ? `${a} ${opLabel} ${b} = ${expectedResult}`
                  : "select a and b"}
              </div>
              {result !== null && (
                <div style={{
                  marginTop: 8,
                  fontFamily: C.mono,
                  fontSize: 11,
                  color: result === expectedResult ? "#00ff88" : C.red,
                }}>
                  {result === expectedResult ? "✓ CORRECT" : "✗ ERROR"}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* ── Compute button ── */}
        <div style={{ display: "flex", gap: 12, marginBottom: 32, alignItems: "center" }}>
          <button
            onClick={compute}
            disabled={a === null || b === null || running}
            style={{
              padding: "12px 28px",
              borderRadius: 7,
              border: `1px solid ${opColor}`,
              background: (a === null || b === null || running) ? "transparent" : `${opColor}18`,
              color: (a === null || b === null || running) ? C.textDim : opColor,
              fontFamily: C.mono,
              fontSize: 14,
              fontWeight: 700,
              cursor: (a === null || b === null || running) ? "not-allowed" : "pointer",
              transition: "all 0.15s ease",
              letterSpacing: "0.05em",
            }}
          >
            {running ? "⟳  Computing…" : `▶  Compute ${opLabel}`}
          </button>
          {(a === null || b === null) && (
            <span style={{ fontFamily: C.mono, fontSize: 12, color: C.textDim }}>
              ← select both bits first
            </span>
          )}
        </div>

        {/* ── Step log ── */}
        {steps.length > 0 && (
          <div ref={logRef} style={{ marginBottom: 28 }}>
            <div style={{
              fontFamily: C.mono,
              fontSize: 12,
              color: C.amber,
              letterSpacing: "0.15em",
              textTransform: "uppercase",
              marginBottom: 16,
              display: "flex",
              alignItems: "center",
              gap: 10,
            }}>
              <span>Protocol Execution Log</span>
              <div style={{ flex: 1, height: 1, background: C.border }} />
            </div>
            {steps.map((step, i) => (
              <StepEntry key={i} step={step} index={i} visible={stepsVisible} />
            ))}
          </div>
        )}

        {/* ── Transcript ── */}
        {transcript && (
          <div style={{
            marginBottom: 28,
            border: `1px solid ${C.border}`,
            borderRadius: 10,
            overflow: "hidden",
          }}>
            <div style={{
              padding: "12px 18px",
              borderBottom: `1px solid ${C.border}`,
              fontFamily: C.mono,
              fontSize: 12,
              color: C.amber,
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}>
              <span>Wire Transcript</span>
              <Badge color={C.textDim}>eavesdropper view</Badge>
            </div>
            <div style={{ padding: 18, background: "#0a0e13" }}>
              {mode === "and" ? (
                <>
                  <div style={{
                    fontFamily: C.mono, fontSize: 11,
                    color: C.textDim, marginBottom: 12,
                    fontStyle: "italic",
                  }}>
                    An eavesdropper sees all three OT messages — but cannot determine a or b.
                  </div>
                  <TranscriptRow
                    label="Alice → Bob [Step 1]"
                    color={C.alice}
                    value={`n=${transcript.step1_AliceToBob?.n}, e=${transcript.step1_AliceToBob?.e}, x₀=${transcript.step1_AliceToBob?.x0}, x₁=${transcript.step1_AliceToBob?.x1}`}
                  />
                  <TranscriptRow
                    label="Bob → Alice [Step 2]"
                    color={C.bob}
                    value={`v = ${transcript.step2_BobToAlice?.v}`}
                  />
                  <TranscriptRow
                    label="Alice → Bob [Step 3]"
                    color={C.alice}
                    value={`ε₀=${transcript.step3_AliceToBob?.e0}, ε₁=${transcript.step3_AliceToBob?.e1}`}
                  />
                  <div style={{
                    marginTop: 14,
                    padding: "10px 14px",
                    borderRadius: 6,
                    background: `${C.red}0a`,
                    border: `1px solid ${C.red}22`,
                    fontFamily: C.mono,
                    fontSize: 11,
                    color: C.textDim,
                    lineHeight: 1.7,
                  }}>
                    <span style={{ color: C.red }}>Security note: </span>
                    The transcript (n, e, x₀, x₁, v, ε₀, ε₁) reveals nothing about a or b.
                    Recovering b from v requires inverting RSA (finding k from v and xᵢ).
                    Recovering a from ε₀, ε₁ requires knowing d (the private key).
                  </div>
                </>
              ) : (
                <>
                  <TranscriptRow
                    label="Alice → Bob"
                    color={C.alice}
                    value={`r = ${transcript["Alice → Bob (r)"]?.r_sent_to_bob ?? Object.values(transcript)[0]?.r_sent_to_bob ?? "?"}`}
                  />
                  <div style={{
                    marginTop: 14,
                    padding: "10px 14px",
                    borderRadius: 6,
                    background: `${C.red}0a`,
                    border: `1px solid ${C.red}22`,
                    fontFamily: C.mono,
                    fontSize: 11,
                    color: C.textDim,
                    lineHeight: 1.7,
                  }}>
                    <span style={{ color: C.red }}>Security note: </span>
                    Only r is transmitted. r is uniformly random, so it reveals nothing
                    about a or b. Shares (a⊕r) and (b⊕r) are local.
                  </div>
                </>
              )}
            </div>
          </div>
        )}

        {/* ── Knowledge cards ── */}
        {aliceView && bobView && (
          <div style={{ marginBottom: 32 }}>
            <div style={{
              fontFamily: C.mono,
              fontSize: 12,
              color: C.textDim,
              letterSpacing: "0.15em",
              textTransform: "uppercase",
              marginBottom: 14,
              display: "flex",
              alignItems: "center",
              gap: 10,
            }}>
              <span>Party Knowledge After Protocol</span>
              <div style={{ flex: 1, height: 1, background: C.border }} />
            </div>
            <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
              <KnowledgeCard
                title="What Alice Learns"
                color={C.alice}
                knows={aliceView.knows}
                doesNot={aliceView.doesNot}
              />
              <KnowledgeCard
                title="What Bob Learns"
                color={C.bob}
                knows={bobView.knows}
                doesNot={bobView.doesNot}
              />
            </div>
          </div>
        )}

        {/* ── Run All / Truth Table ── */}
        <div style={{
          border: `1px solid ${C.border}`,
          borderRadius: 10,
          overflow: "hidden",
          marginBottom: 32,
        }}>
          <div style={{
            padding: "14px 18px",
            borderBottom: `1px solid ${C.border}`,
            display: "flex",
            alignItems: "center",
            gap: 14,
            flexWrap: "wrap",
          }}>
            <span style={{
              fontFamily: C.mono,
              fontSize: 13,
              fontWeight: 700,
              color: C.text,
            }}>
              Truth Table Verification — 50 runs per combination
            </span>
            <button
              onClick={runAll}
              disabled={testRunning}
              style={{
                padding: "7px 18px",
                borderRadius: 6,
                border: `1px solid ${C.amber}`,
                background: testRunning ? "transparent" : `${C.amber}15`,
                color: testRunning ? C.amberDim : C.amber,
                fontFamily: C.mono,
                fontSize: 12,
                cursor: testRunning ? "not-allowed" : "pointer",
                transition: "all 0.15s ease",
              }}
            >
              {testRunning ? "⟳  Running…" : "▶  Run All 4 Combinations"}
            </button>
            {allResults && (
              <Badge color={
                allResults.every(r => r.andOk && r.xorOk) ? "#00ff88" : C.red
              }>
                {allResults.every(r => r.andOk && r.xorOk)
                  ? "ALL PASS — 200/200"
                  : "FAILURES DETECTED"}
              </Badge>
            )}
          </div>

          <table style={{
            width: "100%",
            borderCollapse: "collapse",
            fontFamily: C.mono,
          }}>
            <thead>
              <tr style={{ background: "#0d1117" }}>
                {[
                  ["a", C.alice],
                  ["b", C.bob],
                  ["a AND b", C.alice],
                  ["a XOR b", C.bob],
                  ["50-run result", C.amber],
                ].map(([h, c]) => (
                  <th key={h} style={{
                    padding: "10px 14px",
                    textAlign: "center",
                    fontFamily: C.mono,
                    fontSize: 11,
                    fontWeight: 700,
                    color: c,
                    letterSpacing: "0.08em",
                    textTransform: "uppercase",
                    borderBottom: `1px solid ${C.border}`,
                  }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {allResults ? (
                allResults.map((row, i) => <TruthRow key={i} row={row} />)
              ) : (
                [[0, 0], [0, 1], [1, 0], [1, 1]].map(([av, bv]) => (
                  <tr key={`${av}${bv}`}>
                    {[av, bv, av & bv, av ^ bv].map((v, i) => (
                      <td key={i} style={{
                        fontFamily: C.mono,
                        fontSize: 13,
                        padding: "8px 14px",
                        textAlign: "center",
                        color: i < 2 ? C.textDim : C.border,
                        borderBottom: `1px solid ${C.border}`,
                      }}>
                        {v}
                      </td>
                    ))}
                    <td style={{
                      padding: "8px 14px",
                      textAlign: "center",
                      color: C.border,
                      fontFamily: C.mono,
                      fontSize: 12,
                      borderBottom: `1px solid ${C.border}`,
                    }}>
                      —
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* ── Privacy proof summary ── */}
        <div style={{
          border: `1px solid ${C.border}`,
          borderRadius: 10,
          overflow: "hidden",
          marginBottom: 24,
        }}>
          <div style={{
            padding: "12px 18px",
            borderBottom: `1px solid ${C.border}`,
            fontFamily: C.mono,
            fontSize: 12,
            color: C.textDim,
            letterSpacing: "0.1em",
            textTransform: "uppercase",
          }}>
            Informal Privacy Proof
          </div>
          <div style={{ padding: 18, display: "flex", flexDirection: "column", gap: 12 }}>
            {[
              {
                label: "(a) Bob learns only a∧b",
                color: C.bob,
                text: "Bob receives m_b via OT. When b=0 he gets m₀=0 regardless of a — no information about a. When b=1 he gets m₁=a, but a∧b=a in this case, so he learns only the correct output. He cannot compute m_{1-b} without Alice's private key d (RSA assumption).",
              },
              {
                label: "(b) Alice learns nothing about b",
                color: C.alice,
                text: "Alice receives only Bob's blinded value v = (x_b + k^e) mod n. Distinguishing whether Bob chose x₀ or x₁ from v requires recovering k from k^e mod n — equivalent to breaking RSA. The OT sender-privacy guarantee is therefore computational under the RSA hardness assumption.",
              },
              {
                label: "(c) Secure XOR privacy",
                color: C.amber,
                text: "Only the uniform random bit r is transmitted. Alice's share a⊕r is statistically independent of a (r masks it perfectly). Bob's share b⊕r leaks nothing to Alice beyond what she already knows. The XOR of shares reconstructs a⊕b with no additional leakage.",
              },
            ].map(({ label, color, text }) => (
              <div key={label} style={{
                padding: "12px 16px",
                borderRadius: 7,
                border: `1px solid ${color}22`,
                background: `${color}07`,
              }}>
                <div style={{
                  fontFamily: C.mono,
                  fontSize: 11,
                  color,
                  fontWeight: 700,
                  marginBottom: 6,
                }}>
                  {label}
                </div>
                <div style={{
                  fontFamily: C.sans,
                  fontSize: 13,
                  color: C.textDim,
                  lineHeight: 1.65,
                }}>
                  {text}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* ── Footer ── */}
        <div style={{
          fontFamily: C.mono,
          fontSize: 11,
          color: C.border,
          textAlign: "center",
          letterSpacing: "0.1em",
        }}>
          PA#19 — Secure AND Gate · OT-based MPC · Exports AND / XOR / NOT for PA#20 composition
        </div>

      </div>

      {/* Global keyframe for the pulsing dot */}
      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50%       { opacity: 0.4; transform: scale(0.8); }
        }
      `}</style>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// PA #18 — Oblivious Transfer Interactive Demo
//
// Layout:
//   Left panel  — Alice (Sender):  holds m₀ and m₁, hidden behind lock icons.
//   Right panel — Bob (Receiver):  student clicks "Choose 0" or "Choose 1",
//                 watches the three-step OT protocol execute, then sees m_b.
//   Log panel   — step-by-step protocol trace with hex values.
//   Cheat panel — attempt to decrypt C_{1-b} and brute-force DLP.
//
// Aesthetic: dark "terminal-green" cryptography lab feel.  Monospaced data,
// amber highlights for warnings, cyan for chosen values, red for failures.
// ═══════════════════════════════════════════════════════════════════════════════

import { useState, useRef } from "react";
import {
  OT_Receiver_Step1,
  OT_Sender_Step,
  OT_Receiver_Step2,
  runCorrectnessTest,
  receiverPrivacyDemo,
  senderPrivacyDemo,
  truncMiddle,
  bigintToHex,
} from "./crypto.js";

// ─── Design tokens ────────────────────────────────────────────────────────────

const C = {
  bg:       "#0B0F0B",
  bgCard:   "#111711",
  bgPanel:  "#141C14",
  bgHover:  "#1A251A",
  border:   "#1F2F1F",
  borderHi: "#2B4B2B",
  green:    "#3EBF6A",
  greenDim: "#1D6637",
  cyan:     "#4DD9C0",
  amber:    "#F0B840",
  red:      "#E0503A",
  muted:    "#4A6B4A",
  text:     "#C8DCC8",
  textDim:  "#6B8A6B",
  mono:     "'Courier New', 'Lucida Console', monospace",
  sans:     "'Trebuchet MS', 'Segoe UI', sans-serif",
};

// ─── Micro components ─────────────────────────────────────────────────────────

function Label({ children, color }) {
  return (
    <div style={{
      fontSize: 9,
      fontFamily: C.mono,
      letterSpacing: "0.12em",
      textTransform: "uppercase",
      color: color || C.textDim,
      marginBottom: 4,
    }}>
      {children}
    </div>
  );
}

function MonoVal({ children, color, size }) {
  return (
    <span style={{
      fontFamily: C.mono,
      fontSize: size || 11,
      color: color || C.text,
      wordBreak: "break-all",
    }}>
      {children}
    </span>
  );
}

function Row({ label, value, color }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "130px 1fr", gap: 6, marginBottom: 3 }}>
      <span style={{ fontFamily: C.mono, fontSize: 10, color: C.textDim }}>{label}</span>
      <MonoVal color={color}>{typeof value === "bigint" ? truncMiddle(value) : String(value)}</MonoVal>
    </div>
  );
}

function Pill({ children, tone = "green" }) {
  const colors = {
    green:  { bg: "#0E2B18", border: "#1D6637", text: C.green },
    cyan:   { bg: "#082820", border: "#1A5048", text: C.cyan },
    amber:  { bg: "#2A1E02", border: "#6B4A0A", text: C.amber },
    red:    { bg: "#2B0E0B", border: "#6B2518", text: C.red },
    muted:  { bg: "#131D13", border: C.border, text: C.textDim },
  };
  const p = colors[tone] || colors.green;
  return (
    <span style={{
      display: "inline-block",
      padding: "2px 8px",
      borderRadius: 3,
      border: `1px solid ${p.border}`,
      background: p.bg,
      color: p.text,
      fontFamily: C.mono,
      fontSize: 9,
      letterSpacing: "0.08em",
    }}>
      {children}
    </span>
  );
}

function Btn({ children, onClick, disabled, tone = "green", wide }) {
  const colors = {
    green: { bg: "#0A2214", border: C.greenDim, hover: "#0F3020", text: C.green },
    cyan:  { bg: "#071F1C", border: "#1A5048",  hover: "#0C2E29", text: C.cyan  },
    amber: { bg: "#1E1400", border: "#6B4A0A",  hover: "#2A1C00", text: C.amber },
    red:   { bg: "#1E0A08", border: "#6B2518",  hover: "#2A0E0C", text: C.red   },
  };
  const col = colors[tone] || colors.green;
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        padding: "9px 18px",
        fontFamily: C.mono,
        fontSize: 11,
        letterSpacing: "0.06em",
        border: `1px solid ${disabled ? "#1A2A1A" : col.border}`,
        borderRadius: 4,
        background: disabled ? "#0D150D" : hov ? col.hover : col.bg,
        color: disabled ? "#2A3F2A" : col.text,
        cursor: disabled ? "default" : "pointer",
        transition: "all 0.15s",
        width: wide ? "100%" : "auto",
      }}
    >
      {children}
    </button>
  );
}

function Card({ children, glow, style: extra }) {
  return (
    <div style={{
      background: C.bgCard,
      border: `1px solid ${glow ? C.borderHi : C.border}`,
      borderRadius: 6,
      padding: "16px 18px",
      boxShadow: glow ? `0 0 18px #1D6637` : "none",
      ...extra,
    }}>
      {children}
    </div>
  );
}

function SectionTitle({ children, color }) {
  return (
    <div style={{
      fontFamily: C.mono,
      fontSize: 10,
      letterSpacing: "0.18em",
      color: color || C.greenDim,
      textTransform: "uppercase",
      borderBottom: `1px solid ${C.border}`,
      paddingBottom: 6,
      marginBottom: 14,
    }}>
      ▸ {children}
    </div>
  );
}

function LogEntry({ step, text, color }) {
  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "18px 1fr",
      gap: 8,
      marginBottom: 6,
      fontSize: 10,
      fontFamily: C.mono,
    }}>
      <span style={{ color: C.greenDim }}>{step}.</span>
      <span style={{ color: color || C.text, wordBreak: "break-word" }}>{text}</span>
    </div>
  );
}

// ─── Lock icon (Alice's hidden messages) ─────────────────────────────────────

function Lock({ size = 18, open }) {
  return (
    <svg viewBox="0 0 24 24" width={size} height={size} fill="none" stroke={open ? C.cyan : C.muted} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
      {open
        ? <path d="M7 11V7a5 5 0 0 1 9.9-1" />
        : <path d="M7 11V7a5 5 0 0 1 10 0v4" />
      }
    </svg>
  );
}

// ─── Main panel ───────────────────────────────────────────────────────────────

export default function PA18Panel() {
  // Alice's secret messages (editable before the run starts).
  const [aliceM0, setAliceM0] = useState("12345");
  const [aliceM1, setAliceM1] = useState("99999");

  // Protocol state.
  const [phase, setPhase]       = useState("idle"); // idle | step1 | step2 | step3 | done
  const [chosenB, setChosenB]   = useState(null);
  const [otData, setOtData]     = useState(null);
  const [log, setLog]           = useState([]);
  const [cheatResult, setCheat] = useState(null);
  const [cheatRunning, setCheatRunning] = useState(false);

  // Auxiliary section results.
  const [correctness, setCorrectness] = useState(null);
  const [privacyDemo, setPrivacyDemo] = useState(null);
  const [runningAux, setRunningAux]   = useState(false);

  const logRef = useRef();

  function pushLog(step, text, color) {
    setLog(prev => [...prev, { step, text, color }]);
    setTimeout(() => logRef.current?.scrollTo({ top: 9999, behavior: "smooth" }), 50);
  }

  function reset() {
    setPhase("idle");
    setChosenB(null);
    setOtData(null);
    setLog([]);
    setCheat(null);
  }

  // ── OT protocol execution (async so we can animate steps) ────────────────

  async function startOT(b) {
    reset();
    setChosenB(b);
    setPhase("step1");

    // Validate Alice's messages first.
    let m0Val = aliceM0.trim() || "12345";
    let m1Val = aliceM1.trim() || "99999";

    // Small artificial delays make the step-by-step feel real.
    await delay(300);

    // ── Step 1: Receiver (Bob) ────────────────────────────────────────────
    let step1;
    try {
      step1 = OT_Receiver_Step1(b);
    } catch (e) {
      pushLog(1, `ERROR in Receiver Step 1: ${e.message}`, C.red);
      setPhase("idle");
      return;
    }

    const { pk0, pk1, state } = step1;
    pushLog(1, `Bob: choice bit b = ${b}`, C.cyan);
    pushLog(2, `Bob: generated honest key-pair for pk_${b}`, C.text);
    pushLog(3, `Bob: pk_${b}.h = ${truncMiddle(b === 0 ? pk0.h : pk1.h)}`, C.cyan);
    pushLog(4, `Bob: sampled random group element for pk_${1 - b} (no secret key)`, C.textDim);
    pushLog(5, `Bob: pk_${1 - b}.h = ${truncMiddle(b === 0 ? pk1.h : pk0.h)}`, C.textDim);
    pushLog(6, `Bob → Alice: sends (pk_0, pk_1)`, C.amber);

    await delay(600);
    setPhase("step2");

    // ── Step 2: Sender (Alice) ────────────────────────────────────────────
    let step2;
    try {
      step2 = OT_Sender_Step(pk0, pk1, m0Val, m1Val);
    } catch (e) {
      pushLog(7, `ERROR in Sender Step 2: ${e.message}`, C.red);
      setPhase("idle");
      return;
    }

    const { C0, C1, m0Rep, m1Rep } = step2;
    pushLog(7, `Alice: encrypts m_0 under pk_0 → C_0 = (${truncMiddle(C0.c1)}, ${truncMiddle(C0.c2)})`, C.text);
    pushLog(8, `Alice: encrypts m_1 under pk_1 → C_1 = (${truncMiddle(C1.c1)}, ${truncMiddle(C1.c2)})`, C.text);
    pushLog(9, `Alice → Bob: sends (C_0, C_1)`, C.amber);

    await delay(600);
    setPhase("step3");

    // ── Step 3: Receiver (Bob) decrypts ──────────────────────────────────
    let step3;
    try {
      step3 = OT_Receiver_Step2(state, C0, C1);
    } catch (e) {
      pushLog(10, `ERROR in Receiver Step 3: ${e.message}`, C.red);
      setPhase("idle");
      return;
    }

    pushLog(10, `Bob: decrypts C_${b} using sk_${b}`, C.cyan);
    pushLog(11, `Bob: recovered m_${b} = ${step3.mb}${step3.mbText ? ` ("${step3.mbText}")` : ""}`, C.green);
    pushLog(12, `Bob: C_${1 - b} is inaccessible — no sk_${1 - b} exists`, C.textDim);

    setOtData({ pk0, pk1, state, C0, C1, m0Rep, m1Rep, result: step3 });
    setPhase("done");
  }

  // ── Cheat attempt: try to decrypt C_{1-b} ─────────────────────────────────

  function runCheat() {
    if (!otData) return;
    setCheatRunning(true);
    setCheat(null);
    setTimeout(() => {
      try {
        const { state } = otData;
        const b = state.b;
        const res = senderPrivacyDemo(b, aliceM0 || "12345", aliceM1 || "99999");
        setCheat(res);
      } catch (e) {
        setCheat({ error: e.message });
      }
      setCheatRunning(false);
    }, 50);
  }

  // ── Aux tests ─────────────────────────────────────────────────────────────

  function runCorrectness() {
    setRunningAux(true);
    setCorrectness(null);
    setTimeout(() => {
      try { setCorrectness(runCorrectnessTest()); }
      catch (e) { setCorrectness({ error: e.message }); }
      setRunningAux(false);
    }, 20);
  }

  function runPrivacy() {
    setRunningAux(true);
    setPrivacyDemo(null);
    setTimeout(() => {
      try { setPrivacyDemo(receiverPrivacyDemo(10)); }
      catch (e) { setPrivacyDemo({ error: e.message }); }
      setRunningAux(false);
    }, 20);
  }

  // ─────────────────────────────────────────────────────────────────────────

  const isDone   = phase === "done";
  const isRunning = ["step1","step2","step3"].includes(phase);
  const b        = chosenB;
  const other    = b === null ? null : 1 - b;

  return (
    <div style={{
      background: C.bg,
      minHeight: "100vh",
      color: C.text,
      fontFamily: C.sans,
      padding: "28px 24px",
    }}>
      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div style={{ marginBottom: 28 }}>
        <div style={{
          fontFamily: C.mono,
          fontSize: 10,
          letterSpacing: "0.22em",
          color: C.greenDim,
          textTransform: "uppercase",
          marginBottom: 6,
        }}>
          PA #18 — Cryptography Lab
        </div>
        <div style={{
          fontFamily: C.mono,
          fontSize: 20,
          color: C.green,
          letterSpacing: "0.04em",
          marginBottom: 4,
        }}>
          1-out-of-2 Oblivious Transfer
        </div>
        <div style={{ fontSize: 12, color: C.textDim, maxWidth: 620, lineHeight: 1.6 }}>
          Bellare–Micali OT built on <span style={{ color: C.cyan }}>PA #16 ElGamal</span>.
          Bob learns exactly one of Alice's two secrets.
          Alice never learns which one. Bob cannot recover the other.
        </div>
      </div>

      {/* ── Main two-column: Alice (left) + Bob (right) ─────────────────── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 20 }}>

        {/* ── ALICE panel ──────────────────────────────────────────────── */}
        <Card style={{ opacity: isRunning ? 0.7 : 1, transition: "opacity 0.3s" }}>
          <SectionTitle color={C.textDim}>Alice — Sender</SectionTitle>

          <div style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            marginBottom: 18,
            padding: "8px 10px",
            background: "#0D150D",
            borderRadius: 4,
            border: `1px solid ${C.border}`,
          }}>
            <span style={{ fontSize: 10, color: C.textDim, fontFamily: C.mono }}>
              Alice has two secret messages. She will encrypt both and send the ciphertexts to Bob. She never learns which one Bob decrypts.
            </span>
          </div>

          {/* m_0 */}
          <div style={{ marginBottom: 14 }}>
            <Label>Message m₀</Label>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Lock size={14} open={isDone && b === 0} />
              {isDone && b === 0 ? (
                <MonoVal color={C.cyan}>{aliceM0 || "12345"}</MonoVal>
              ) : (
                <>
                  {isRunning || isDone ? (
                    <MonoVal color={C.muted}>{"•".repeat(8)}</MonoVal>
                  ) : (
                    <input
                      value={aliceM0}
                      onChange={e => setAliceM0(e.target.value)}
                      placeholder="12345"
                      style={{
                        background: "#0D150D",
                        border: `1px solid ${C.border}`,
                        borderRadius: 3,
                        color: C.text,
                        fontFamily: C.mono,
                        fontSize: 11,
                        padding: "5px 8px",
                        width: 120,
                      }}
                    />
                  )}
                </>
              )}
            </div>
          </div>

          {/* m_1 */}
          <div style={{ marginBottom: 18 }}>
            <Label>Message m₁</Label>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Lock size={14} open={isDone && b === 1} />
              {isDone && b === 1 ? (
                <MonoVal color={C.cyan}>{aliceM1 || "99999"}</MonoVal>
              ) : (
                <>
                  {isRunning || isDone ? (
                    <MonoVal color={C.muted}>{"•".repeat(8)}</MonoVal>
                  ) : (
                    <input
                      value={aliceM1}
                      onChange={e => setAliceM1(e.target.value)}
                      placeholder="99999"
                      style={{
                        background: "#0D150D",
                        border: `1px solid ${C.border}`,
                        borderRadius: 3,
                        color: C.text,
                        fontFamily: C.mono,
                        fontSize: 11,
                        padding: "5px 8px",
                        width: 120,
                      }}
                    />
                  )}
                </>
              )}
            </div>
          </div>

          {/* Ciphertexts (shown after step 2) */}
          {otData && (
            <>
              <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 12, marginTop: 4 }}>
                <Label color={C.amber}>Ciphertexts sent to Bob</Label>
                <Row label="C₀.c1" value={truncMiddle(otData.C0.c1)} />
                <Row label="C₀.c2" value={truncMiddle(otData.C0.c2)} />
                <Row label="C₁.c1" value={truncMiddle(otData.C1.c1)} />
                <Row label="C₁.c2" value={truncMiddle(otData.C1.c2)} />
              </div>
            </>
          )}
        </Card>

        {/* ── BOB panel ────────────────────────────────────────────────── */}
        <Card glow={isDone}>
          <SectionTitle color={C.green}>Bob — Receiver</SectionTitle>

          {phase === "idle" && (
            <>
              <div style={{
                fontSize: 11,
                color: C.textDim,
                lineHeight: 1.6,
                marginBottom: 20,
              }}>
                You are Bob. Choose which of Alice's messages you want to receive.
                Alice will never know your choice.
              </div>
              <div style={{ display: "flex", gap: 10 }}>
                <Btn onClick={() => startOT(0)} tone="cyan">Choose m₀</Btn>
                <Btn onClick={() => startOT(1)} tone="green">Choose m₁</Btn>
              </div>
            </>
          )}

          {isRunning && (
            <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "20px 0" }}>
              <div style={{
                width: 10, height: 10, borderRadius: "50%",
                background: C.green,
                animation: "pulse 1s infinite",
              }} />
              <MonoVal color={C.green}>
                {phase === "step1" && "Generating key pairs…"}
                {phase === "step2" && "Alice encrypting…"}
                {phase === "step3" && "Decrypting C_b…"}
              </MonoVal>
            </div>
          )}

          {isDone && otData && (
            <>
              {/* Chosen result */}
              <div style={{
                background: "#071A0F",
                border: `1px solid ${C.greenDim}`,
                borderRadius: 4,
                padding: "14px 16px",
                marginBottom: 16,
              }}>
                <Label color={C.green}>Received (choice b = {b})</Label>
                <div style={{ fontFamily: C.mono, fontSize: 22, color: C.green, marginBottom: 4 }}>
                  m_{b} = {otData.result.mb.toString()}
                </div>
                {otData.result.mbText && (
                  <div style={{ fontFamily: C.mono, fontSize: 13, color: C.cyan }}>
                    "{otData.result.mbText}"
                  </div>
                )}
              </div>

              {/* Other message - hidden */}
              <div style={{
                background: "#120E0D",
                border: `1px solid #2A1A18`,
                borderRadius: 4,
                padding: "14px 16px",
                marginBottom: 16,
              }}>
                <Label color={C.textDim}>m_{other} (inaccessible — no sk_{other})</Label>
                <div style={{ fontFamily: C.mono, fontSize: 22, color: C.muted }}>
                  ??  ??  ??  ??
                </div>
              </div>

              {/* Keys shown */}
              <div style={{ marginBottom: 14 }}>
                <Label>Public keys sent to Alice</Label>
                <Row
                  label={`pk_${b}.h (real)`}
                  value={truncMiddle(b === 0 ? otData.pk0.h : otData.pk1.h)}
                  color={C.cyan}
                />
                <Row
                  label={`pk_${other}.h (trap-free)`}
                  value={truncMiddle(b === 0 ? otData.pk1.h : otData.pk0.h)}
                  color={C.textDim}
                />
              </div>

              <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                <Btn onClick={reset} tone="amber">↺ Reset</Btn>
                <Btn
                  onClick={runCheat}
                  disabled={cheatRunning}
                  tone="red"
                >
                  {cheatRunning ? "Attempting…" : `⚡ Cheat: decrypt C_${other}`}
                </Btn>
              </div>
            </>
          )}
        </Card>
      </div>

      {/* ── Step-by-step protocol log ────────────────────────────────────── */}
      {log.length > 0 && (
        <Card style={{ marginBottom: 20 }}>
          <SectionTitle>Protocol log</SectionTitle>
          <div
            ref={logRef}
            style={{
              maxHeight: 200,
              overflowY: "auto",
              background: "#080E08",
              border: `1px solid ${C.border}`,
              borderRadius: 4,
              padding: "10px 12px",
            }}
          >
            {log.map((entry, i) => (
              <LogEntry key={i} step={entry.step} text={entry.text} color={entry.color} />
            ))}
            {isRunning && (
              <div style={{ fontFamily: C.mono, fontSize: 10, color: C.greenDim }}>
                _ <span style={{ animation: "blink 1s step-end infinite" }}>▌</span>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* ── Cheat attempt result ─────────────────────────────────────────── */}
      {cheatResult && (
        <Card style={{ marginBottom: 20, borderColor: "#3A1A14" }}>
          <SectionTitle color={C.red}>Cheat Attempt — Decrypt C_{cheatResult.b === 0 ? 1 : 0}</SectionTitle>

          {cheatResult.error ? (
            <MonoVal color={C.red}>{cheatResult.error}</MonoVal>
          ) : (
            <>
              <div style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit,minmax(240px,1fr))",
                gap: 14,
                marginBottom: 14,
              }}>
                <div>
                  <Label color={C.green}>Correct decryption (C_{cheatResult.b})</Label>
                  <Row label="m_b recovered" value={cheatResult.correctMb.toString()} color={C.green} />
                </div>
                <div>
                  <Label color={C.red}>Wrong-key attempt on C_{cheatResult.b === 0 ? 1 : 0}</Label>
                  <Row label="result using sk_b" value={truncMiddle(cheatResult.wrongDecResult)} color={C.muted} />
                  <Row
                    label="matches m_{1-b}?"
                    value={cheatResult.wrongMatchesTarget ? "YES (lucky)" : "NO — random garbage"}
                    color={cheatResult.wrongMatchesTarget ? C.red : C.textDim}
                  />
                </div>
              </div>

              <div style={{
                background: "#180A08",
                border: `1px solid #3A1A14`,
                borderRadius: 4,
                padding: "10px 14px",
              }}>
                <Label color={C.amber}>DLP brute-force on trapdoor-free pk_{cheatResult.b === 0 ? 1 : 0}.h</Label>
                <Row label="budget (steps)" value={cheatResult.dlpBudget.toString()} />
                <Row label="iterations run" value={cheatResult.dlpIters.toString()} />
                <Row
                  label="DLP found?"
                  value={cheatResult.dlpFound ? `YES — log = ${cheatResult.dlpLog}` : "NO"}
                  color={cheatResult.dlpFound ? C.amber : C.textDim}
                />
                <div style={{
                  marginTop: 8,
                  fontFamily: C.mono,
                  fontSize: 10,
                  color: C.amber,
                  lineHeight: 1.6,
                }}>
                  {cheatResult.message}
                </div>
              </div>

              <div style={{
                marginTop: 12,
                padding: "8px 12px",
                background: "#0A1A0A",
                borderRadius: 4,
                border: `1px solid ${C.borderHi}`,
                fontFamily: C.mono,
                fontSize: 10,
                color: C.textDim,
                lineHeight: 1.7,
              }}>
                <span style={{ color: C.green }}>Security conclusion:</span>{" "}
                Decrypting C_{cheatResult.b === 0 ? 1 : 0} without sk_{cheatResult.b === 0 ? 1 : 0} requires solving
                the Discrete Logarithm Problem in the PA#11 subgroup. The trapdoor-free key was
                sampled as a random group element; recovering its discrete log is as hard as breaking ElGamal.
                Under DDH the sender cannot distinguish pk_b (real) from pk_{"1-b"} (trapdoor-free).
              </div>
            </>
          )}
        </Card>
      )}

      {/* ── Correctness + Privacy sections ──────────────────────────────── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 20 }}>

        {/* Correctness */}
        <Card>
          <SectionTitle>Correctness — 100 random trials</SectionTitle>
          <div style={{ fontSize: 11, color: C.textDim, marginBottom: 12, lineHeight: 1.6 }}>
            Runs OT 100 times with random b and random (m₀, m₁).
            Verifies that the receiver always recovers m_b.
          </div>
          <Btn onClick={runCorrectness} disabled={runningAux} tone="green">
            {runningAux ? "Running…" : "Run 100 trials"}
          </Btn>

          {correctness && (
            <div style={{ marginTop: 14 }}>
              {correctness.error ? (
                <MonoVal color={C.red}>{correctness.error}</MonoVal>
              ) : (
                <>
                  <div style={{
                    display: "grid",
                    gridTemplateColumns: "1fr 1fr 1fr",
                    gap: 10,
                    marginBottom: 10,
                  }}>
                    {[
                      { label: "TRIALS", val: correctness.trials },
                      { label: "PASS", val: correctness.pass, color: C.green },
                      { label: "FAIL", val: correctness.fail, color: correctness.fail ? C.red : C.textDim },
                    ].map(({ label, val, color }) => (
                      <div key={label} style={{
                        background: "#0D150D",
                        border: `1px solid ${C.border}`,
                        borderRadius: 4,
                        padding: "8px 10px",
                        textAlign: "center",
                      }}>
                        <div style={{ fontFamily: C.mono, fontSize: 18, color: color || C.text }}>{val}</div>
                        <div style={{ fontFamily: C.mono, fontSize: 8, color: C.textDim, letterSpacing: "0.12em" }}>{label}</div>
                      </div>
                    ))}
                  </div>
                  <div style={{ textAlign: "center" }}>
                    <Pill tone={correctness.fail === 0 ? "green" : "red"}>
                      {correctness.fail === 0 ? "✓ ALL CORRECT" : `${correctness.fail} FAILURES`}
                    </Pill>
                  </div>
                  {correctness.failures.length > 0 && (
                    <div style={{ marginTop: 10 }}>
                      {correctness.failures.map((f, i) => (
                        <div key={i} style={{ fontFamily: C.mono, fontSize: 9, color: C.red, marginBottom: 3 }}>
                          trial {f.trial}: b={f.b} expected={f.expected} got={f.got || f.error}
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </Card>

        {/* Receiver privacy */}
        <Card>
          <SectionTitle>Receiver Privacy — DDH indistinguishability</SectionTitle>
          <div style={{ fontSize: 11, color: C.textDim, marginBottom: 12, lineHeight: 1.6 }}>
            Samples OT Step 1 for alternating b=0 and b=1. Shows that Alice
            sees (pk₀, pk₁) where both h values look like random group elements.
          </div>
          <Btn onClick={runPrivacy} disabled={runningAux} tone="cyan">
            {runningAux ? "Sampling…" : "Sample 10 pairs"}
          </Btn>

          {privacyDemo && (
            <div style={{ marginTop: 14 }}>
              {privacyDemo.error ? (
                <MonoVal color={C.red}>{privacyDemo.error}</MonoVal>
              ) : (
                <div style={{
                  background: "#080E08",
                  border: `1px solid ${C.border}`,
                  borderRadius: 4,
                  padding: "8px 10px",
                  maxHeight: 180,
                  overflowY: "auto",
                }}>
                  {privacyDemo.samples.map((s, i) => (
                    <div key={i} style={{
                      fontFamily: C.mono,
                      fontSize: 9,
                      color: C.textDim,
                      marginBottom: 6,
                      borderBottom: i < privacyDemo.samples.length - 1 ? `1px solid #0F1C0F` : "none",
                      paddingBottom: 5,
                    }}>
                      <span style={{ color: C.cyan }}>b={s.b}</span>
                      {"  "}h₀={truncMiddle(s.h0, 10)}
                      {"  "}h₁={truncMiddle(s.h1, 10)}
                      {"  "}
                      <span style={{ color: C.textDim }}>← which is "real"? Alice can't tell.</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </Card>
      </div>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.3; }
        }
        @keyframes blink {
          0%, 100% { opacity: 1; }
          50% { opacity: 0; }
        }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: #0B0F0B; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 2px; }
      `}</style>
    </div>
  );
}

function delay(ms) {
  return new Promise(r => setTimeout(r, ms));
}

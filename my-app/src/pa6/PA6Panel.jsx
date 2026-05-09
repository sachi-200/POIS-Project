// ═══════════════════════════════════════════════════════════════════════════════
// PA #6 Panel — CCA-Secure Symmetric Encryption (Encrypt-then-MAC)
// Enc-then-MAC · Malleability attack · Key separation · IND-CCA2 game
// ═══════════════════════════════════════════════════════════════════════════════

import {
  ccaEnc, ccaDec,
  malleabilityDemo,
  keySeparationDemo,
  runCCA2Game,
  flipHexBit,
} from "./crypto.js";
import {
  FieldLabel, TextInput, ToggleBar, SectionHeading,
} from "../shared/ui.jsx";
import { useState, useEffect } from "react";

// ── shared tiny components ────────────────────────────────────────────────────

function StatCard({ label, value, accent }) {
  return (
    <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
      <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>{label}</div>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 13, fontWeight: 500, color: accent || "var(--color-text-primary)", wordBreak: "break-all" }}>{value}</div>
    </div>
  );
}

function TestBadge({ pass, passLabel = "PASS", failLabel = "FAIL" }) {
  return (
    <span style={{
      fontSize: 10, padding: "2px 8px", borderRadius: 4, fontWeight: 500,
      background: pass ? "#E1F5EE" : "#FCEBEB",
      border: `0.5px solid ${pass ? "#1D9E75" : "#E24B4A"}`,
      color: pass ? "#0F6E56" : "#A32D2D",
    }}>{pass ? passLabel : failLabel}</span>
  );
}

function btnStyle(bg, border, color, extra = {}) {
  return {
    padding: "7px 14px", fontSize: 12, fontWeight: 500,
    border: `0.5px solid ${border}`, borderRadius: "var(--border-radius-md)",
    background: bg, color, cursor: "pointer",
    fontFamily: "var(--font-sans)", whiteSpace: "nowrap", ...extra,
  };
}

// ── Encrypt-then-MAC flow diagram ─────────────────────────────────────────────

function EtMFlow({ r, c, t, macInput }) {
  const BOX_H = 30, MID = 44;
  return (
    <svg width="100%" viewBox="0 0 580 90" style={{ display: "block", fontFamily: "var(--font-mono)", overflow: "visible" }}>
      {/* m */}
      <rect x={0} y={MID - BOX_H/2} width={52} height={BOX_H} rx={4} fill="#E1F5EE" stroke="#1D9E75" strokeWidth={0.8}/>
      <text x={26} y={MID+5} textAnchor="middle" fontSize={9} fill="#0F6E56">m (hex)</text>

      <line x1={52} y1={MID} x2={82} y2={MID} stroke="#B5B1A8" strokeWidth={1}/>

      {/* Enc_kE */}
      <rect x={82} y={MID - BOX_H/2} width={88} height={BOX_H} rx={4} fill="#E6F1FB" stroke="#378ADD" strokeWidth={1}/>
      <text x={126} y={MID-3} textAnchor="middle" fontSize={8} fill="#185FA5">Enc_kE(m)</text>
      <text x={126} y={MID+10} textAnchor="middle" fontSize={7} fill="#185FA5">PA#3 CTR</text>

      <line x1={170} y1={MID} x2={200} y2={MID} stroke="#B5B1A8" strokeWidth={1}/>

      {/* C_E */}
      <rect x={200} y={MID - BOX_H/2} width={76} height={BOX_H} rx={4} fill="#FEF3E2" stroke="#E8B96A" strokeWidth={1}/>
      <text x={238} y={MID-3} textAnchor="middle" fontSize={8} fill="#7A4A00">C_E = r:c</text>
      <text x={238} y={MID+10} textAnchor="middle" fontSize={7} fill="#7A4A00">{r ? `${r.slice(0,6)}…` : "—"}</text>

      <line x1={276} y1={MID} x2={306} y2={MID} stroke="#B5B1A8" strokeWidth={1}/>

      {/* Mac_kM */}
      <rect x={306} y={MID - BOX_H/2} width={96} height={BOX_H} rx={4} fill="#EEEDFE" stroke="#7F77DD" strokeWidth={1}/>
      <text x={354} y={MID-3} textAnchor="middle" fontSize={8} fill="#3C3489">Mac_kM(C_E)</text>
      <text x={354} y={MID+10} textAnchor="middle" fontSize={7} fill="#3C3489">PA#5 PRF-MAC</text>

      <line x1={402} y1={MID} x2={432} y2={MID} stroke="#B5B1A8" strokeWidth={1}/>

      {/* Output */}
      <rect x={432} y={MID - BOX_H/2} width={90} height={BOX_H} rx={4} fill="#1a1a2e" stroke="#7F77DD" strokeWidth={1}/>
      <text x={477} y={MID-3} textAnchor="middle" fontSize={8} fill="#c8c4f8">(C_E, t)</text>
      <text x={477} y={MID+10} textAnchor="middle" fontSize={7} fill="#8b8aaa">{t ? `t=0x${t.slice(0,6)}…` : "output"}</text>
    </svg>
  );
}

// ── Decryption flow diagram ───────────────────────────────────────────────────

function DecFlow({ accepted }) {
  const BOX_H = 30, MID = 44;
  return (
    <svg width="100%" viewBox="0 0 520 90" style={{ display: "block", fontFamily: "var(--font-mono)", overflow: "visible" }}>
      {/* (C_E, t) */}
      <rect x={0} y={MID - BOX_H/2} width={72} height={BOX_H} rx={4} fill="#FEF3E2" stroke="#E8B96A" strokeWidth={0.8}/>
      <text x={36} y={MID-3} textAnchor="middle" fontSize={8} fill="#7A4A00">(C_E, t)</text>
      <text x={36} y={MID+10} textAnchor="middle" fontSize={7} fill="#7A4A00">input</text>

      <line x1={72} y1={MID} x2={102} y2={MID} stroke="#B5B1A8" strokeWidth={1}/>

      {/* Vrfy */}
      <rect x={102} y={MID - BOX_H/2} width={88} height={BOX_H} rx={4}
        fill={accepted === null ? "#EEEDFE" : accepted ? "#E1F5EE" : "#FCEBEB"}
        stroke={accepted === null ? "#7F77DD" : accepted ? "#1D9E75" : "#E24B4A"} strokeWidth={1}/>
      <text x={146} y={MID-3} textAnchor="middle" fontSize={8}
        fill={accepted === null ? "#3C3489" : accepted ? "#0F6E56" : "#A32D2D"}>
        Vrfy_kM(C_E, t)
      </text>
      <text x={146} y={MID+10} textAnchor="middle" fontSize={7}
        fill={accepted === null ? "#3C3489" : accepted ? "#0F6E56" : "#A32D2D"}>
        {accepted === null ? "check first!" : accepted ? "= 1 ✓" : "= 0 → ⊥"}
      </text>

      <line x1={190} y1={MID} x2={220} y2={MID} stroke="#B5B1A8" strokeWidth={1}/>

      {/* Dec or reject */}
      <rect x={220} y={MID - BOX_H/2} width={88} height={BOX_H} rx={4}
        fill={accepted === false ? "#FCEBEB" : "#E6F1FB"}
        stroke={accepted === false ? "#E24B4A" : "#378ADD"} strokeWidth={1}/>
      <text x={264} y={MID-3} textAnchor="middle" fontSize={8}
        fill={accepted === false ? "#A32D2D" : "#185FA5"}>
        {accepted === false ? "REJECT" : "Dec_kE(C_E)"}
      </text>
      <text x={264} y={MID+10} textAnchor="middle" fontSize={7}
        fill={accepted === false ? "#A32D2D" : "#185FA5"}>
        {accepted === false ? "output ⊥" : "PA#3 CTR"}
      </text>

      <line x1={308} y1={MID} x2={338} y2={MID} stroke="#B5B1A8" strokeWidth={1}/>

      {/* output */}
      <rect x={338} y={MID - BOX_H/2} width={72} height={BOX_H} rx={4}
        fill={accepted === false ? "#FCEBEB" : "#E1F5EE"}
        stroke={accepted === false ? "#E24B4A" : "#1D9E75"} strokeWidth={1}/>
      <text x={374} y={MID+5} textAnchor="middle" fontSize={9}
        fill={accepted === false ? "#A32D2D" : "#0F6E56"}>
        {accepted === false ? "⊥" : "m (hex)"}
      </text>
    </svg>
  );
}

// ── Main PA6 panel ────────────────────────────────────────────────────────────

export default function PA6Panel() {
  const [prfType,   setPrfType]   = useState("GGM");
  const [activeTab, setActiveTab] = useState("etm");

  // ── Tab 1: Encrypt-then-MAC ──
  const [kE,        setKE]        = useState("a3f2c1b8");
  const [kM,        setKM]        = useState("b4e7a291");
  const [encMsg,    setEncMsg]    = useState("deadbeef");
  const [encResult, setEncResult] = useState(null);
  const [decCE,     setDecCE]     = useState("");
  const [decT,      setDecT]      = useState("");
  const [decResult, setDecResult] = useState(null);

  // ── Tab 2: Malleability ──
  const [malKE,     setMalKE]     = useState("a3f2c1b8");
  const [malKM,     setMalKM]     = useState("b4e7a291");
  const [malMsg,    setMalMsg]    = useState("deadbeef");
  const [malBit,    setMalBit]    = useState(3);
  const [malResult, setMalResult] = useState(null);

  // ── Tab 3: Key separation ──
  const [sepKey,    setSepKey]    = useState("a3f2c1b8");
  const [sepMsg,    setSepMsg]    = useState("deadbeef");
  const [sepResult, setSepResult] = useState(null);

  // ── Tab 4: IND-CCA2 game ──
  const [ccaKE,     setCcaKE]     = useState("a3f2c1b8");
  const [ccaKM,     setCcaKM]     = useState("b4e7a291");
  const [ccaM0,     setCcaM0]     = useState("aabbccdd");
  const [ccaM1,     setCcaM1]     = useState("11223344");
  const [ccaResult, setCcaResult] = useState(null);
  const [ccaGuess,  setCcaGuess]  = useState(null);
  const [ccaScore,  setCcaScore]  = useState({ attempts: 0, correct: 0 });
  const [showCcaB,  setShowCcaB]  = useState(false);

  // ── actions ───────────────────────────────────────────────────────────────
  function doEnc() {
    const r = ccaEnc(kE, kM, encMsg, prfType);
    setEncResult(r); setDecCE(r.CE); setDecT(r.t); setDecResult(null);
  }
  function doDec() {
    setDecResult(ccaDec(kE, kM, decCE, decT, prfType));
  }
  function doTamperTest() {
    if (!encResult) return;
    // Flip bit 0 of the c part — keep original tag → MAC must reject
    const parts     = encResult.CE.split(":");
    const tamperedC = flipHexBit(parts[1], 0);
    setDecCE(`${parts[0]}:${tamperedC}`);
    setDecResult(null);
  }
  function doMal()  { setMalResult(malleabilityDemo(malKE, malKM, malMsg, malBit, prfType)); }
  useEffect(() => {
    if (malResult) doMal();
  }, [malKE, malKM, malMsg, malBit, prfType]);
  function doSep()  { setSepResult(keySeparationDemo(sepKey, sepMsg, prfType)); }
  function doCCA2() {
    if (ccaM0.length !== ccaM1.length) return;
    setCcaResult(runCCA2Game(ccaKE, ccaKM, ccaM0, ccaM1, prfType));
    setCcaGuess(null); setShowCcaB(false);
  }
  function submitGuess(g) {
    if (!ccaResult || ccaGuess !== null) return;
    setCcaGuess(g);
    setCcaScore(s => ({ attempts: s.attempts + 1, correct: s.correct + (g === ccaResult.b ? 1 : 0) }));
  }

  const ccaMismatch = ccaM0.length !== ccaM1.length;
  const ccaAdvantage = ccaScore.attempts > 0
    ? (Math.abs(ccaScore.correct / ccaScore.attempts - 0.5) * 2).toFixed(3)
    : "—";

  const TABS = [
    { id: "etm",  label: "Encrypt-then-MAC" },
    { id: "mal",  label: "Malleability attack" },
    { id: "sep",  label: "Key separation" },
    { id: "cca2", label: "IND-CCA2 game" },
  ];

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>

      {/* ── Header ── */}
      <div style={{ padding: "10px 16px", background: "#EAF4FB", borderBottom: "0.5px solid #7BBDE8", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: "#0D4F7C" }}>
          PA #6 — CCA-Secure Symmetric Encryption (Encrypt-then-MAC)
        </div>
        <ToggleBar value={prfType} onChange={setPrfType} options={[
          { value: "GGM", label: "GGM PRF",  activeStyle: { bg: "#EEEDFE", border: "#7F77DD", color: "#3C3489" } },
          { value: "AES", label: "AES PRF",  activeStyle: { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" } },
        ]} />
      </div>

      {/* ── Tab bar ── */}
      <div style={{ display: "flex", borderBottom: "0.5px solid var(--color-border-tertiary)", background: "var(--color-background-secondary)", overflowX: "auto" }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)} style={{
            padding: "8px 16px", fontSize: 12,
            fontWeight: activeTab === t.id ? 500 : 400,
            border: "none",
            borderBottom: activeTab === t.id ? "2px solid #1A7FC1" : "2px solid transparent",
            background: "transparent", cursor: "pointer",
            color: activeTab === t.id ? "#0D4F7C" : "var(--color-text-secondary)",
            fontFamily: "var(--font-sans)", whiteSpace: "nowrap",
          }}>{t.label}</button>
        ))}
      </div>

      <div style={{ padding: 16 }}>

        {/* ════════════════════════════════════════════════════
            TAB 1 — Encrypt-then-MAC
        ════════════════════════════════════════════════════ */}
        {activeTab === "etm" && (
          <div>
            <SectionHeading>Encrypt-then-MAC: CCA_Enc(kE, kM, m) and CCA_Dec(kE, kM, C_E, t)</SectionHeading>

            {/* Flow diagrams */}
            <div style={{ padding: 10, background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 16, overflowX: "auto" }}>
              <div style={{ fontSize: 10, color: "var(--color-text-secondary)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.07em" }}>Encryption flow</div>
              <EtMFlow r={encResult?.r} c={encResult?.c} t={encResult?.t} macInput={encResult?.macInput} />
            </div>
            <div style={{ padding: 10, background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 16, overflowX: "auto" }}>
              <div style={{ fontSize: 10, color: "var(--color-text-secondary)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.07em" }}>Decryption flow — Vrfy fires BEFORE Dec</div>
              <DecFlow accepted={decResult ? decResult.accepted : null} />
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 16 }}>

              {/* Encrypt */}
              <div>
                <SectionHeading>CCA_Enc(kE, kM, m)</SectionHeading>
                <div style={{ marginBottom: 8 }}><FieldLabel>Encryption key kE (hex)</FieldLabel><TextInput value={kE} onChange={setKE} placeholder="a3f2c1b8" /></div>
                <div style={{ marginBottom: 8 }}><FieldLabel>MAC key kM (hex) — must differ from kE</FieldLabel><TextInput value={kM} onChange={setKM} placeholder="b4e7a291" /></div>
                <div style={{ marginBottom: 12 }}><FieldLabel>Message m (hex)</FieldLabel><TextInput value={encMsg} onChange={setEncMsg} placeholder="deadbeef" /></div>
                <button onClick={doEnc} style={{ ...btnStyle("#EAF4FB", "#7BBDE8", "#0D4F7C"), width: "100%", marginBottom: 12 }}>Encrypt</button>

                {encResult && (
                  <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
                    <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>Output (C_E, t)</div>
                    <div style={{ marginBottom: 4 }}>
                      <span style={{ fontSize: 10, color: "var(--color-text-secondary)" }}>r: </span>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "#185FA5" }}>0x{encResult.r}</span>
                    </div>
                    <div style={{ marginBottom: 4 }}>
                      <span style={{ fontSize: 10, color: "var(--color-text-secondary)" }}>c: </span>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-primary)", wordBreak: "break-all" }}>0x{encResult.c}</span>
                    </div>
                    <div style={{ marginBottom: 4 }}>
                      <span style={{ fontSize: 10, color: "var(--color-text-secondary)" }}>C_E: </span>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "#7A4A00", wordBreak: "break-all" }}>{encResult.CE}</span>
                    </div>
                    <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: 8, marginTop: 6 }}>
                      <span style={{ fontSize: 10, color: "var(--color-text-secondary)" }}>tag t: </span>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 13, fontWeight: 600, color: "#3C3489" }}>0x{encResult.t}</span>
                    </div>
                    <div style={{ marginTop: 6, fontSize: 10, color: "var(--color-text-secondary)" }}>
                      macInput (CE folded to 8-bit): <span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-primary)" }}>{encResult.macInput}</span>
                    </div>

                    {/* Block detail */}
                    {encResult.blocks.length > 0 && (
                      <div style={{ marginTop: 8 }}>
                        <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", marginBottom: 4 }}>PA#3 block detail</div>
                        {encResult.blocks.map((blk, i) => (
                          <div key={i} style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--color-text-secondary)", marginBottom: 2 }}>
                            blk{i}: 0x{blk.mBlock} ⊕ 0x{blk.keyStream} = <span style={{ color: "var(--color-text-primary)" }}>0x{blk.cBlock}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Decrypt */}
              <div>
                <SectionHeading>CCA_Dec(kE, kM, C_E, t)</SectionHeading>
                <div style={{ padding: "8px 12px", background: "#FAEEDA", borderRadius: "var(--border-radius-md)", fontSize: 11, color: "#7A4A00", marginBottom: 10, border: "0.5px solid #E8B96A" }}>
                  Vrfy_kM(C_E, t) is called <strong>before</strong> Dec. Any modified ciphertext returns ⊥.
                </div>
                <div style={{ marginBottom: 8 }}><FieldLabel>C_E (r:c format)</FieldLabel><TextInput value={decCE} onChange={v => { setDecCE(v); setDecResult(null); }} placeholder="auto-filled after encrypt" /></div>
                <div style={{ marginBottom: 12 }}><FieldLabel>Tag t (hex)</FieldLabel><TextInput value={decT} onChange={v => { setDecT(v); setDecResult(null); }} placeholder="auto-filled after encrypt" /></div>
                <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
                  <button onClick={doDec} style={btnStyle("#EAF4FB", "#7BBDE8", "#0D4F7C")}>Decrypt</button>
                  {encResult && (
                    <button onClick={() => { setDecCE(encResult.CE); setDecT(encResult.t); setDecResult(null); }}
                      style={btnStyle("#E6F1FB", "#B5D4F4", "#185FA5")}>Copy from encrypt</button>
                  )}
                </div>

                {decResult && (
                  <div style={{ padding: "10px 12px", borderRadius: "var(--border-radius-md)", marginBottom: 10,
                    background: decResult.accepted ? "#E1F5EE" : "#FCEBEB",
                    border: `0.5px solid ${decResult.accepted ? "#1D9E75" : "#E24B4A"}`,
                    color: decResult.accepted ? "#0F6E56" : "#A32D2D", fontSize: 12, fontWeight: 500 }}>
                    {decResult.reason}
                    {decResult.accepted && (
                      <div style={{ marginTop: 4, fontFamily: "var(--font-mono)", fontSize: 14 }}>
                        m = 0x{decResult.plaintext}
                      </div>
                    )}
                  </div>
                )}

                {/* Tamper test */}
                <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginTop: 8 }}>
                  <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>
                    Tamper test — modify C_E, keep original tag t
                  </div>
                  <div style={{ fontSize: 11, color: "var(--color-text-secondary)", marginBottom: 8 }}>
                    Flip bit 0 of c (auto), keep same t, then click Decrypt. MAC rejects → ⊥.
                  </div>
                  {encResult && (
                    <button onClick={doTamperTest} style={btnStyle("#FCEBEB", "#E24B4A", "#A32D2D")}>
                      Auto-flip bit 0 of c
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ════════════════════════════════════════════════════
            TAB 2 — Malleability attack
        ════════════════════════════════════════════════════ */}
        {activeTab === "mal" && (
          <div>
            <SectionHeading>Malleability attack — CPA is malleable, CCA rejects tampered ciphertexts</SectionHeading>
            <div style={{ padding: "8px 14px", borderRadius: "var(--border-radius-md)", background: "#FAEEDA", border: "0.5px solid #E8B96A", color: "#7A4A00", fontSize: 12, marginBottom: 16, lineHeight: 1.6 }}>
              <strong>CPA (PA#3):</strong> C = (r, F_k(r) ⊕ m). Flipping bit i of c flips bit i of plaintext — adversary controls output without knowing k.<br/>
              <strong>CCA (PA#6):</strong> MAC tag covers C_E. Any modification fails Vrfy → ⊥ returned, plaintext never touched.
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "260px minmax(0,1fr)", gap: 16 }}>
              <div>
                <div style={{ marginBottom: 8 }}><FieldLabel>Encryption key kE (hex)</FieldLabel><TextInput value={malKE} onChange={setMalKE} placeholder="a3f2c1b8" /></div>
                <div style={{ marginBottom: 8 }}><FieldLabel>MAC key kM (hex)</FieldLabel><TextInput value={malKM} onChange={setMalKM} placeholder="b4e7a291" /></div>
                <div style={{ marginBottom: 8 }}><FieldLabel>Message m (hex)</FieldLabel><TextInput value={malMsg} onChange={setMalMsg} placeholder="deadbeef" /></div>
                <div style={{ marginBottom: 12 }}>
                  <FieldLabel>Bit to flip in ciphertext c (0–{malResult ? malResult.origC.length * 4 - 1 : 31})</FieldLabel>
                  <input type="range" min={0} max={31} value={malBit} onChange={e => setMalBit(Number(e.target.value))} style={{ width: "100%" }} />
                  <div style={{ fontSize: 11, color: "var(--color-text-secondary)", marginTop: 2 }}>Bit index: {malBit}</div>
                </div>
                <button onClick={doMal} style={btnStyle("#EAF4FB", "#7BBDE8", "#0D4F7C", { width: "100%" })}>
                  Run malleability demo
                </button>
              </div>

              {malResult && (
                <div>
                  {/* Ciphertext display */}
                  <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 12 }}>
                    <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", marginBottom: 6 }}>Ciphertext c (hex)</div>
                    <div style={{ marginBottom: 4 }}>
                      <span style={{ fontSize: 10, color: "var(--color-text-secondary)" }}>Original c: </span>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "#185FA5" }}>0x{malResult.origC}</span>
                    </div>
                    <div>
                      <span style={{ fontSize: 10, color: "var(--color-text-secondary)" }}>Tampered c: </span>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "#A32D2D" }}>0x{malResult.tamperedC}</span>
                    </div>
                    <div style={{ marginTop: 4, fontSize: 10, color: "var(--color-text-secondary)" }}>
                      Bit {malResult.bitFlipped} flipped
                    </div>
                  </div>

                  {/* Side-by-side comparison */}
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>

                    {/* CPA — accepts */}
                    <div style={{ padding: "12px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A" }}>
                      <div style={{ fontSize: 11, fontWeight: 500, color: "#A32D2D", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.06em" }}>
                        CPA-only — malleable ✗
                      </div>
                      <div style={{ fontSize: 11, color: "var(--color-text-secondary)", marginBottom: 8 }}>No integrity check. Decrypts tampered CT blindly.</div>
                      <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, marginBottom: 3 }}>
                        orig m: <span style={{ color: "#185FA5" }}>0x{malResult.origMsg}</span>
                      </div>
                      <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, marginBottom: 3 }}>
                        dec of tampered: <span style={{ color: "#A32D2D", fontWeight: 600 }}>0x{malResult.cpaPlaintext}</span>
                      </div>
                      <div style={{ marginTop: 8, fontSize: 11, color: "#A32D2D" }}>
                        Adversary controlled plaintext bit {malResult.bitFlipped} without knowing k!
                      </div>
                    </div>

                    {/* CCA — rejects */}
                    <div style={{ padding: "12px", borderRadius: "var(--border-radius-md)", background: "#E1F5EE", border: "0.5px solid #1D9E75" }}>
                      <div style={{ fontSize: 11, fontWeight: 500, color: "#0F6E56", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.06em" }}>
                        CCA / Encrypt-then-MAC ✓
                      </div>
                      <div style={{ fontSize: 11, color: "var(--color-text-secondary)", marginBottom: 8 }}>Vrfy_kM fires before Dec.</div>
                      <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, marginBottom: 3 }}>
                        MAC check: <span style={{ color: "#A32D2D", fontWeight: 600 }}>FAIL</span>
                      </div>
                      <div style={{ fontFamily: "var(--font-mono)", fontSize: 13, fontWeight: 600, color: "#0F6E56" }}>
                        Output: ⊥
                      </div>
                      <div style={{ marginTop: 8, fontSize: 11, color: "#0F6E56" }}>
                        {malResult.ccaReason}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ════════════════════════════════════════════════════
            TAB 3 — Key separation
        ════════════════════════════════════════════════════ */}
        {activeTab === "sep" && (
          <div>
            <SectionHeading>Key separation — kE and kM must be independently sampled</SectionHeading>
            <div style={{ padding: "8px 14px", borderRadius: "var(--border-radius-md)", background: "#FAEEDA", border: "0.5px solid #E8B96A", color: "#7A4A00", fontSize: 12, marginBottom: 16, lineHeight: 1.6 }}>
              Reusing a single key for both encryption and MAC creates exploitable correlations. The MAC tag leaks evaluations of F_k, which is the same key used for the keystream — an adversary can build a lookup table of F_k values from observed tags.
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "260px minmax(0,1fr)", gap: 16 }}>
              <div>
                <div style={{ marginBottom: 8 }}><FieldLabel>Shared key (used for BOTH kE and kM)</FieldLabel><TextInput value={sepKey} onChange={setSepKey} placeholder="a3f2c1b8" /></div>
                <div style={{ marginBottom: 12 }}><FieldLabel>Message m (hex)</FieldLabel><TextInput value={sepMsg} onChange={setSepMsg} placeholder="deadbeef" /></div>
                <button onClick={doSep} style={btnStyle("#EAF4FB", "#7BBDE8", "#0D4F7C", { width: "100%" })}>
                  Run key-separation demo
                </button>
              </div>

              {sepResult && (
                <div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>

                    {/* Same key */}
                    <div style={{ padding: "12px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A" }}>
                      <div style={{ fontSize: 11, fontWeight: 500, color: "#A32D2D", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.06em" }}>kE = kM ✗</div>
                      {[
                        ["kE", sepResult.same.kE],
                        ["kM", sepResult.same.kM],
                        ["C_E", sepResult.same.CE.slice(0, 20) + "…"],
                        ["tag t", `0x${sepResult.same.t}`],
                        ["macInput", sepResult.same.macInput],
                      ].map(([l, v], i) => (
                        <div key={i} style={{ marginBottom: 4, fontSize: 11 }}>
                          <span style={{ color: "var(--color-text-secondary)", display: "inline-block", minWidth: 64 }}>{l}:</span>
                          <span style={{ fontFamily: "var(--font-mono)", color: "#A32D2D" }}>{v}</span>
                        </div>
                      ))}
                      <div style={{ marginTop: 8, padding: "6px 8px", background: "#fff0f0", borderRadius: 4, fontSize: 11, color: "#A32D2D", fontWeight: 500 }}>
                        {sepResult.correlationMsg}
                      </div>
                    </div>

                    {/* Independent keys */}
                    <div style={{ padding: "12px", borderRadius: "var(--border-radius-md)", background: "#E1F5EE", border: "0.5px solid #1D9E75" }}>
                      <div style={{ fontSize: 11, fontWeight: 500, color: "#0F6E56", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.06em" }}>kE ≠ kM ✓</div>
                      {[
                        ["kE", sepResult.sep.kE],
                        ["kM", sepResult.sep.kM],
                        ["C_E", sepResult.sep.CE.slice(0, 20) + "…"],
                        ["tag t", `0x${sepResult.sep.t}`],
                        ["macInput", sepResult.sep.macInput],
                      ].map(([l, v], i) => (
                        <div key={i} style={{ marginBottom: 4, fontSize: 11 }}>
                          <span style={{ color: "var(--color-text-secondary)", display: "inline-block", minWidth: 64 }}>{l}:</span>
                          <span style={{ fontFamily: "var(--font-mono)", color: "#0F6E56" }}>{v}</span>
                        </div>
                      ))}
                      <div style={{ marginTop: 8, padding: "6px 8px", background: "#f0fff8", borderRadius: 4, fontSize: 11, color: "#0F6E56", fontWeight: 500 }}>
                        No correlation — independent keys are safe.
                      </div>
                    </div>
                  </div>

                  <div style={{ padding: "10px 14px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
                    <strong style={{ color: "var(--color-text-primary)" }}>Correlation detail:</strong> When kE = kM, tag t = F_k(macInput) uses the same k as the encryption keystream F_k(r). An adversary collecting (C_E, t) pairs builds a partial F_k table from the tags, then uses it to predict or recover keystreams. Independent keys eliminate this overlap entirely.
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ════════════════════════════════════════════════════
            TAB 4 — IND-CCA2 game
        ════════════════════════════════════════════════════ */}
        {activeTab === "cca2" && (
          <div>
            <SectionHeading>IND-CCA2 game — adversary advantage ≈ 0 against Encrypt-then-MAC</SectionHeading>

            <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 16 }}>

              {/* Left: game controls */}
              <div>
                <div style={{ padding: "10px 12px", background: "#EAF4FB", borderRadius: "var(--border-radius-md)", fontSize: 11, color: "#0D4F7C", marginBottom: 12, border: "0.5px solid #7BBDE8", lineHeight: 1.6 }}>
                  Challenger secretly picks b ∈ &#x7B;0,1&#x7D;, encrypts m_b. You see (C_E, t) and have a decryption oracle that rejects modified ciphertexts. Guess which message was encrypted.
                </div>

                <div style={{ marginBottom: 8 }}><FieldLabel>Encryption key kE (hex)</FieldLabel><TextInput value={ccaKE} onChange={setCcaKE} placeholder="a3f2c1b8" /></div>
                <div style={{ marginBottom: 8 }}><FieldLabel>MAC key kM (hex)</FieldLabel><TextInput value={ccaKM} onChange={setCcaKM} placeholder="b4e7a291" /></div>
                <div style={{ marginBottom: 8 }}><FieldLabel>m₀ (hex)</FieldLabel><TextInput value={ccaM0} onChange={setCcaM0} placeholder="aabbccdd" /></div>
                <div style={{ marginBottom: 4 }}><FieldLabel>m₁ (hex — same length as m₀)</FieldLabel><TextInput value={ccaM1} onChange={setCcaM1} placeholder="11223344" /></div>
                {ccaMismatch && <div style={{ fontSize: 11, color: "#A32D2D", marginBottom: 6 }}>m₀ and m₁ must be the same length</div>}

                <button onClick={doCCA2} disabled={ccaMismatch}
                  style={{ ...btnStyle(ccaMismatch ? "var(--color-background-secondary)" : "#EAF4FB", "#7BBDE8", ccaMismatch ? "var(--color-text-secondary)" : "#0D4F7C"), width: "100%", marginTop: 8, marginBottom: 12 }}>
                  Get challenge ciphertext
                </button>

                {/* Score */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginBottom: 10 }}>
                  {[
                    { label: "Attempts",  val: ccaScore.attempts },
                    { label: "Correct",   val: ccaScore.correct },
                    { label: "Advantage", val: ccaAdvantage },
                  ].map((s, i) => (
                    <div key={i} style={{ padding: "8px 10px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
                      <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 2 }}>{s.label}</div>
                      <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, fontWeight: 500 }}>{s.val}</div>
                    </div>
                  ))}
                </div>
                {ccaScore.attempts >= 5 && (
                  <div style={{ padding: "8px 12px", borderRadius: "var(--border-radius-md)", fontSize: 12,
                    background: parseFloat(ccaAdvantage) <= 0.15 ? "#E1F5EE" : "#FAEEDA",
                    border: `0.5px solid ${parseFloat(ccaAdvantage) <= 0.15 ? "#1D9E75" : "#BA7517"}`,
                    color: parseFloat(ccaAdvantage) <= 0.15 ? "#0F6E56" : "#854F0B" }}>
                    {parseFloat(ccaAdvantage) <= 0.15
                      ? "Advantage ≈ 0 ✓ — scheme is CCA2-secure"
                      : "Advantage non-trivial — keep playing to see convergence"}
                  </div>
                )}
              </div>

              {/* Right: challenge + oracle queries */}
              <div>
                {ccaResult ? (
                  <>
                    {ccaResult.error ? (
                      <div style={{ color: "#A32D2D", fontSize: 12 }}>{ccaResult.error}</div>
                    ) : (
                      <>
                        <SectionHeading>Challenge ciphertext C* = (C_E, t)</SectionHeading>
                        <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 12 }}>
                          <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-primary)", marginBottom: 3, wordBreak: "break-all" }}>
                            C_E = {ccaResult.challengeCE}
                          </div>
                          <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "#7A4A00" }}>
                            t = 0x{ccaResult.challengeT}
                          </div>
                        </div>

                        {/* Guess buttons */}
                        {ccaGuess === null ? (
                          <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
                            <button onClick={() => submitGuess(0)} style={{ ...btnStyle("#E6F1FB", "#378ADD", "#185FA5"), flex: 1 }}>Guess m₀</button>
                            <button onClick={() => submitGuess(1)} style={{ ...btnStyle("#E1F5EE", "#1D9E75", "#0F6E56"), flex: 1 }}>Guess m₁</button>
                          </div>
                        ) : (
                          <div style={{ marginBottom: 12 }}>
                            <div style={{ padding: "10px 12px", borderRadius: "var(--border-radius-md)", fontWeight: 500, fontSize: 13, marginBottom: 8,
                              background: ccaGuess === ccaResult.b ? "#E1F5EE" : "#FCEBEB",
                              border: `0.5px solid ${ccaGuess === ccaResult.b ? "#1D9E75" : "#E24B4A"}`,
                              color: ccaGuess === ccaResult.b ? "#0F6E56" : "#A32D2D" }}>
                              {ccaGuess === ccaResult.b ? "Correct!" : "Wrong!"} b = {ccaResult.b} (encrypted m{ccaResult.b})
                            </div>
                            {!showCcaB && (
                              <button onClick={() => { setShowCcaB(true); doCCA2(); }}
                                style={{ ...btnStyle("var(--color-background-secondary)", "var(--color-border-secondary)", "var(--color-text-primary)"), width: "100%" }}>
                                Next round
                              </button>
                            )}
                          </div>
                        )}

                        {/* Oracle queries table */}
                        <SectionHeading>Decryption oracle — 10 simulated queries</SectionHeading>
                        <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", overflow: "hidden" }}>
                          <div style={{ display: "grid", gridTemplateColumns: "90px 1fr 80px 60px", background: "var(--color-background-secondary)", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
                            {["msg (hex)", "legit dec", "tampered", "C* rej?"].map((h, i) => (
                              <div key={i} style={{ padding: "5px 8px", fontSize: 9, fontWeight: 500, color: "var(--color-text-secondary)", textTransform: "uppercase" }}>{h}</div>
                            ))}
                          </div>
                          {ccaResult.oracleQueries.map((q, i) => (
                            <div key={i} style={{ display: "grid", gridTemplateColumns: "90px 1fr 80px 60px", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
                              <div style={{ padding: "5px 8px", fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-secondary)" }}>0x{q.qMsgHex}</div>
                              <div style={{ padding: "5px 8px", fontFamily: "var(--font-mono)", fontSize: 10, color: "#0F6E56" }}>0x{q.legitPlaintext}</div>
                              <div style={{ padding: "5px 8px", fontFamily: "var(--font-mono)", fontSize: 10, color: "#A32D2D" }}>⊥</div>
                              <div style={{ padding: "5px 8px", fontSize: 10, color: q.challengeRejected ? "#0F6E56" : "#A32D2D" }}>
                                {q.challengeRejected ? "✓" : "✗"}
                              </div>
                            </div>
                          ))}
                        </div>
                        <div style={{ marginTop: 8, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.6 }}>
                          Tampered queries always return ⊥. The challenge ciphertext is also rejected when queried with wrong tag. Without seeing the plaintext under challenge, the adversary can only guess randomly → advantage ≈ 0.
                        </div>
                      </>
                    )}
                  </>
                ) : (
                  <div style={{ padding: 24, textAlign: "center", fontSize: 12, color: "var(--color-text-secondary)", fontStyle: "italic", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
                    Enter m₀, m₁ and click "Get challenge ciphertext" to start the game.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
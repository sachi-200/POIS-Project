// ═══════════════════════════════════════════════════════════════════════════════
// PA #3 Panel — CPA-Secure Encryption & IND-CPA Game
// Fixes:
//   1. Broken (reuse r) mode: adversary exploits fixed nonce deterministically,
//      so advantage jumps to ≈ 1.0 immediately.
//   2. Nonce Reuse Attack Demo section removed.
// ═══════════════════════════════════════════════════════════════════════════════

import { useState, useCallback } from "react";
import {
  encCPA, decCPA, playCPAGameRound, runCPASimulation,
} from "./crypto.js";
import { fakeHex } from "../utils/crypto.js";
import { FieldLabel, TextInput, ToggleBar, SectionHeading } from "../shared/ui.jsx";

function TestBadge({ pass }) {
  return (
    <span style={{
      fontSize: 10, padding: "2px 8px", borderRadius: 4, fontWeight: 500,
      background: pass ? "#E1F5EE" : "#FCEBEB",
      border: `0.5px solid ${pass ? "#1D9E75" : "#E24B4A"}`,
      color: pass ? "#0F6E56" : "#A32D2D",
    }}>
      {pass ? "PASS" : "FAIL"}
    </span>
  );
}

export default function PA3Panel() {
  const [prfType,      setPrfType]      = useState("GGM");
  const [keyHex,       setKeyHex]       = useState("c0ffee11");
  const [reuseNonce,   setReuseNonce]   = useState(false);
  const [msgHex,       setMsgHex]       = useState("deadbeef");
  const [encResult,    setEncResult]    = useState(null);
  const [decResult,    setDecResult]    = useState(null);
  const [decInput,     setDecInput]     = useState("");
  const [m0,           setM0]           = useState("aabbccdd");
  const [m1,           setM1]           = useState("11223344");
  const [gameRound,    setGameRound]    = useState(null);
  const [guess,        setGuess]        = useState(null);
  const [history,      setHistory]      = useState([]);
  const [showResult,   setShowResult]   = useState(false);
  const [simResult,    setSimResult]    = useState(null);

  const rounds    = history.length;
  const correct   = history.filter(h => h.correct).length;
  const advantage = rounds > 0 ? Math.abs((correct / rounds) - 0.5) * 2 : 0;
  const mismatch  = m0.length !== m1.length;
  const mc = reuseNonce
    ? { bg: "#FCEBEB", border: "#E24B4A", text: "#A32D2D" }
    : { bg: "#E1F5EE", border: "#1D9E75", text: "#0F6E56" };

  function doEnc() {
    const r = encCPA(keyHex, msgHex, prfType, reuseNonce);
    setEncResult(r);
    setDecResult(null);
    setDecInput(r.ciphertext);
  }

  function doDec() {
    const parts = decInput.split(":");
    if (parts.length !== 2) { setDecResult({ error: "Format must be r:c" }); return; }
    setDecResult(decCPA(keyHex, parts[0], parts[1], prfType));
  }

  function doEncryptChallenge() {
    if (mismatch) return;
    const round = playCPAGameRound(keyHex, m0, m1, prfType, reuseNonce);
    setGameRound(round);
    setGuess(null);
    setShowResult(false);
  }

  // In broken mode: adversary deterministically re-encrypts m0 and compares.
  // If ciphertexts match → b=0, else → b=1. This yields advantage ≈ 1.0.
  function getExploitGuess(round) {
    if (!reuseNonce) return null;
    const testEnc = encCPA(keyHex, m0, prfType, true);
    return testEnc.c === round.c ? 0 : 1;
  }

  function doGuess(g) {
    if (!gameRound || showResult) return;
    setGuess(g);
    setShowResult(true);
    setHistory(h => [...h, { b: gameRound.b, guess: g, correct: g === gameRound.b }]);
  }

  // In broken mode, auto-submit the exploit guess immediately after challenge
  function doEncryptChallengeWithExploit() {
    if (mismatch) return;
    const round = playCPAGameRound(keyHex, m0, m1, prfType, reuseNonce);
    setGameRound(round);
    setShowResult(false);
    setGuess(null);

    if (reuseNonce) {
      // Compute deterministic exploit guess right away
      const testEnc = encCPA(keyHex, m0, prfType, true);
      const exploitGuess = testEnc.c === round.c ? 0 : 1;
      setGuess(exploitGuess);
      setShowResult(true);
      setHistory(h => [...h, { b: round.b, guess: exploitGuess, correct: exploitGuess === round.b }]);
    }
  }

  function resetGame() {
    setHistory([]);
    setGameRound(null);
    setGuess(null);
    setShowResult(false);
  }

  function handleSetNonce(val) {
    const broken = val === "broken";
    setReuseNonce(broken);
    resetGame();
    setSimResult(null);
  }

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>

      {/* ── Header ── */}
      <div style={{ padding: "10px 16px", background: "#E1F5EE", borderBottom: "0.5px solid #9FE1CB", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: "#0F6E56" }}>
          PA #3 — CPA-secure encryption & IND-CPA game
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <ToggleBar value={prfType} onChange={setPrfType} options={[
            { value: "GGM", label: "GGM PRF", activeStyle: { bg: "#EEEDFE", border: "#7F77DD", color: "#3C3489" } },
            { value: "AES", label: "AES PRF", activeStyle: { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" } },
          ]} />
          <ToggleBar
            value={reuseNonce ? "broken" : "secure"}
            onChange={handleSetNonce}
            options={[
              { value: "secure", label: "Secure (fresh r)", activeStyle: { bg: "#E1F5EE", border: "#1D9E75", color: "#0F6E56" } },
              { value: "broken", label: "Broken (reuse r)",  activeStyle: { bg: "#FCEBEB", border: "#E24B4A", color: "#A32D2D" } },
            ]}
          />
        </div>
      </div>

      <div style={{ padding: "16px" }}>

        {/* ── Mode banner ── */}
        <div style={{ padding: "8px 14px", borderRadius: "var(--border-radius-md)", background: mc.bg, border: `0.5px solid ${mc.border}`, color: mc.text, fontSize: 12, marginBottom: 16 }}>
          {reuseNonce
            ? "Broken mode: r is always F_k(0) — same plaintext always produces the same ciphertext. The adversary re-encrypts m₀ and compares with C* to win every round."
            : "Secure mode: r ← {0,1}ⁿ freshly each encryption. Advantage should converge to ≈ 0 over many rounds."}
        </div>

        {/* ── Enc / Dec ── */}
        <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 16, marginBottom: 20 }}>
          <div>
            <SectionHeading>Enc(k, m) — C = ⟨r, F_k(r) ⊕ m⟩</SectionHeading>
            <div style={{ marginBottom: 10 }}><FieldLabel>Key k (hex)</FieldLabel><TextInput value={keyHex} onChange={setKeyHex} placeholder="e.g. c0ffee11" /></div>
            <div style={{ marginBottom: 10 }}><FieldLabel>Message m (hex)</FieldLabel><TextInput value={msgHex} onChange={setMsgHex} placeholder="e.g. deadbeef" /></div>
            <button onClick={doEnc} style={{ width: "100%", padding: "8px 14px", fontSize: 12, fontWeight: 500, border: "0.5px solid #1D9E75", borderRadius: "var(--border-radius-md)", background: "#E1F5EE", color: "#0F6E56", cursor: "pointer", fontFamily: "var(--font-sans)", marginBottom: 12 }}>
              Encrypt
            </button>
            {encResult && (
              <div>
                <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 8 }}>
                  <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 6 }}>C = r : c</div>
                  <div style={{ display: "flex", gap: 8, marginBottom: 4 }}>
                    <span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 12 }}>r:</span>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "#185FA5", wordBreak: "break-all" }}>0x{encResult.r}</span>
                  </div>
                  <div style={{ display: "flex", gap: 8 }}>
                    <span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 12 }}>c:</span>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-primary)", wordBreak: "break-all" }}>0x{encResult.c}</span>
                  </div>
                </div>
                {encResult.blocks.length > 0 && (
                  <div>
                    <SectionHeading>Block-by-block detail</SectionHeading>
                    {encResult.blocks.map((blk, i) => (
                      <div key={i} style={{ padding: "6px 10px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 6, fontSize: 11 }}>
                        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                          <span style={{ fontSize: 10, padding: "1px 6px", borderRadius: 3, background: "#EEEDFE", color: "#3C3489", border: "0.5px solid #7F77DD", fontFamily: "var(--font-mono)" }}>blk {i}</span>
                          <span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-secondary)" }}>m: 0x{blk.mBlock}</span>
                          <span style={{ color: "var(--color-text-secondary)" }}>⊕</span>
                          <span style={{ fontFamily: "var(--font-mono)", color: "#185FA5" }}>F_k(r+{i}): 0x{blk.keyStream}</span>
                          <span style={{ color: "var(--color-text-secondary)" }}>=</span>
                          <span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-primary)", fontWeight: 500 }}>0x{blk.cBlock}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          <div>
            <SectionHeading>Dec(k, r, c) — m = F_k(r) ⊕ c</SectionHeading>
            <div style={{ marginBottom: 10 }}><FieldLabel>Ciphertext (r:c format)</FieldLabel><TextInput value={decInput} onChange={setDecInput} placeholder="paste r:c from Enc output" /></div>
            <button onClick={doDec} style={{ width: "100%", padding: "8px 14px", fontSize: 12, fontWeight: 500, border: "0.5px solid #378ADD", borderRadius: "var(--border-radius-md)", background: "#E6F1FB", color: "#185FA5", cursor: "pointer", fontFamily: "var(--font-sans)", marginBottom: 12 }}>
              Decrypt
            </button>
            {decResult && (
              <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
                {decResult.error
                  ? <div style={{ fontSize: 12, color: "#A32D2D" }}>{decResult.error}</div>
                  : <>
                      <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 6 }}>Recovered plaintext</div>
                      <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, color: "var(--color-text-primary)", fontWeight: 500, wordBreak: "break-all" }}>0x{decResult.msgHex}</div>
                      {decResult.msgHex === msgHex && <div style={{ fontSize: 11, color: "#0F6E56", marginTop: 6 }}>Matches original ✓</div>}
                    </>
                }
              </div>
            )}
          </div>
        </div>

        {/* ── IND-CPA game ── */}
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: 16, marginBottom: 20 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12, flexWrap: "wrap", gap: 8 }}>
            <SectionHeading>IND-CPA game — play as the adversary (20 rounds target)</SectionHeading>
            {rounds > 0 && (
              <button onClick={resetGame} style={{ fontSize: 11, padding: "4px 12px", border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", color: "var(--color-text-secondary)", cursor: "pointer", fontFamily: "var(--font-sans)" }}>
                Reset
              </button>
            )}
          </div>

          {/* Counters */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 10, marginBottom: 14 }}>
            {[
              { label: "Rounds",    val: rounds },
              { label: "Correct",   val: correct },
              { label: "Advantage", val: advantage.toFixed(3) },
              { label: "Target",    val: reuseNonce ? "≈ 1.0" : "≤ 0.1" },
            ].map((s, i) => (
              <div key={i} style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
                <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>{s.label}</div>
                <div style={{
                  fontFamily: "var(--font-mono)", fontSize: 16, fontWeight: 500,
                  color: i === 2
                    ? reuseNonce
                      ? (advantage > 0.8 ? "#0F6E56" : "#A32D2D")
                      : (advantage <= 0.1 ? "#0F6E56" : "#854F0B")
                    : "var(--color-text-primary)",
                }}>
                  {s.val}
                </div>
              </div>
            ))}
          </div>

          {/* Advantage bar */}
          <div style={{ height: 8, borderRadius: 4, background: "var(--color-background-secondary)", overflow: "hidden", border: "0.5px solid var(--color-border-tertiary)", marginBottom: 14 }}>
            <div style={{
              height: "100%",
              width: `${Math.min(advantage, 1) * 100}%`,
              background: reuseNonce ? "#E24B4A" : advantage <= 0.1 ? "#1D9E75" : "#BA7517",
              transition: "width 0.4s",
            }} />
          </div>

          {/* Broken-mode exploit explanation */}
          {reuseNonce && (
            <div style={{ padding: "8px 14px", borderRadius: "var(--border-radius-md)", background: "#FAEEDA", border: "0.5px solid #BA7517", color: "#854F0B", fontSize: 12, marginBottom: 14 }}>
              <strong>Exploit:</strong> r is fixed, so the adversary re-encrypts m₀ with the same key and compares with C*.
              If <code>Enc(m₀) = C*</code> → guess b=0; otherwise → guess b=1. This wins every round → advantage = 1.0.
            </div>
          )}

          <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 16 }}>
            <div>
              <div style={{ fontSize: 12, fontWeight: 500, marginBottom: 8 }}>Step 1 — enter two equal-length messages</div>
              <div style={{ marginBottom: 8 }}><FieldLabel>m₀</FieldLabel><TextInput value={m0} onChange={setM0} placeholder="e.g. aabbccdd" /></div>
              <div style={{ marginBottom: 10 }}><FieldLabel>m₁</FieldLabel><TextInput value={m1} onChange={setM1} placeholder="e.g. 11223344" /></div>
              {mismatch && <div style={{ fontSize: 11, color: "#A32D2D", marginBottom: 8 }}>m₀ and m₁ must be the same length</div>}
              <button
                onClick={doEncryptChallengeWithExploit}
                disabled={mismatch}
                style={{ width: "100%", padding: "9px 14px", fontSize: 13, fontWeight: 500, border: "0.5px solid #1D9E75", borderRadius: "var(--border-radius-md)", background: mismatch ? "var(--color-background-secondary)" : "#E1F5EE", color: mismatch ? "var(--color-text-secondary)" : "#0F6E56", cursor: mismatch ? "not-allowed" : "pointer", fontFamily: "var(--font-sans)" }}
              >
                Step 2 — Encrypt (challenger picks b)
              </button>
            </div>

            <div>
              <div style={{ fontSize: 12, fontWeight: 500, marginBottom: 8 }}>Step 3 — see C* and guess b</div>
              {gameRound ? (
                <div>
                  <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 10 }}>
                    <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 6 }}>Challenge ciphertext C*</div>
                    <div style={{ display: "flex", gap: 6, marginBottom: 3 }}>
                      <span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 12 }}>r:</span>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "#185FA5", wordBreak: "break-all" }}>0x{gameRound.r}</span>
                    </div>
                    <div style={{ display: "flex", gap: 6 }}>
                      <span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 12 }}>c:</span>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, wordBreak: "break-all" }}>0x{gameRound.c}</span>
                    </div>
                  </div>

                  {/* In broken mode, show the exploit result instead of buttons */}
                  {reuseNonce && showResult && guess !== null ? (
                    (() => {
                      const testEnc = encCPA(keyHex, m0, prfType, true);
                      return (
                        <div>
                          <div style={{ padding: "8px 12px", background: "#FAEEDA", border: "0.5px solid #BA7517", borderRadius: "var(--border-radius-md)", fontSize: 11, color: "#854F0B", marginBottom: 8 }}>
                            Enc(m₀).c = <span style={{ fontFamily: "var(--font-mono)" }}>0x{testEnc.c}</span><br />
                            C*.c = <span style={{ fontFamily: "var(--font-mono)" }}>0x{gameRound.c}</span><br />
                            Match: <strong>{testEnc.c === gameRound.c ? "YES → guessed b=0" : "NO → guessed b=1"}</strong>
                          </div>
                          <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: guess === gameRound.b ? "#E1F5EE" : "#FCEBEB", border: `0.5px solid ${guess === gameRound.b ? "#1D9E75" : "#E24B4A"}`, color: guess === gameRound.b ? "#0F6E56" : "#A32D2D", fontSize: 13, fontWeight: 500, marginBottom: 10 }}>
                            {guess === gameRound.b ? "Correct!" : "Wrong!"} b={gameRound.b} (encrypted m{gameRound.b})
                          </div>
                          <button onClick={doEncryptChallengeWithExploit} style={{ width: "100%", padding: "8px", fontSize: 12, fontWeight: 500, border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", color: "var(--color-text-primary)", cursor: "pointer", fontFamily: "var(--font-sans)" }}>
                            Next round
                          </button>
                        </div>
                      );
                    })()
                  ) : !showResult ? (
                    <div style={{ display: "flex", gap: 8 }}>
                      <button onClick={() => doGuess(0)} style={{ flex: 1, padding: "9px", fontSize: 13, fontWeight: 500, border: "0.5px solid #378ADD", borderRadius: "var(--border-radius-md)", background: "#E6F1FB", color: "#185FA5", cursor: "pointer", fontFamily: "var(--font-sans)" }}>b=0 (m₀)</button>
                      <button onClick={() => doGuess(1)} style={{ flex: 1, padding: "9px", fontSize: 13, fontWeight: 500, border: "0.5px solid #1D9E75", borderRadius: "var(--border-radius-md)", background: "#E1F5EE", color: "#0F6E56", cursor: "pointer", fontFamily: "var(--font-sans)" }}>b=1 (m₁)</button>
                    </div>
                  ) : (
                    <div>
                      <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: guess === gameRound.b ? "#E1F5EE" : "#FCEBEB", border: `0.5px solid ${guess === gameRound.b ? "#1D9E75" : "#E24B4A"}`, color: guess === gameRound.b ? "#0F6E56" : "#A32D2D", fontSize: 13, fontWeight: 500, marginBottom: 10 }}>
                        {guess === gameRound.b ? "Correct!" : "Wrong!"} b={gameRound.b} (encrypted m{gameRound.b})
                      </div>
                      <button onClick={doEncryptChallenge} style={{ width: "100%", padding: "8px", fontSize: 12, fontWeight: 500, border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", color: "var(--color-text-primary)", cursor: "pointer", fontFamily: "var(--font-sans)" }}>
                        Next round
                      </button>
                    </div>
                  )}
                </div>
              ) : (
                <div style={{ padding: "20px", textAlign: "center", fontSize: 12, color: "var(--color-text-secondary)", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
                  Enter m₀, m₁ and click Encrypt.
                </div>
              )}
            </div>
          </div>

          {history.length > 0 && (
            <div style={{ marginTop: 14 }}>
              <SectionHeading>Recent rounds</SectionHeading>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {history.slice(-20).map((h, i) => (
                  <span key={i} style={{ fontSize: 10, padding: "2px 7px", borderRadius: 3, fontWeight: 500, background: h.correct ? "#E1F5EE" : "#FCEBEB", border: `0.5px solid ${h.correct ? "#1D9E75" : "#E24B4A"}`, color: h.correct ? "#0F6E56" : "#A32D2D" }}>
                    {h.correct ? "✓" : "✗"}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* ── CPA simulation only (nonce reuse attack demo removed) ── */}
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: 16 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
            <SectionHeading>CPA simulation — dummy adversary, 50 rounds</SectionHeading>
            <button
              onClick={() => setSimResult(runCPASimulation(keyHex, prfType, reuseNonce, 50))}
              style={{ padding: "6px 12px", fontSize: 11, fontWeight: 500, border: "0.5px solid #7F77DD", borderRadius: "var(--border-radius-md)", background: "#EEEDFE", color: "#3C3489", cursor: "pointer", fontFamily: "var(--font-sans)", whiteSpace: "nowrap" }}
            >
              Run sim
            </button>
          </div>
          <div style={{ fontSize: 12, color: "var(--color-text-secondary)", marginBottom: 10 }}>
            {reuseNonce
              ? "In broken mode the simulated adversary uses the exploit strategy (re-encrypt m₀, compare) — advantage → 1.0."
              : "In secure mode the simulated adversary guesses randomly — advantage → 0."}
          </div>
          {simResult && (
            <div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginBottom: 10 }}>
                {[{ label: "Rounds", val: simResult.rounds }, { label: "Correct", val: simResult.correct }, { label: "Advantage", val: simResult.advantage }].map((s, i) => (
                  <div key={i} style={{ padding: "8px 10px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
                    <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 2 }}>{s.label}</div>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, fontWeight: 500 }}>{s.val}</div>
                  </div>
                ))}
              </div>
              <div style={{
                padding: "8px 12px", borderRadius: "var(--border-radius-md)", fontSize: 12,
                background: parseFloat(simResult.advantage) <= 0.15 && !reuseNonce ? "#E1F5EE" : reuseNonce && parseFloat(simResult.advantage) > 0.8 ? "#FCEBEB" : "#FAEEDA",
                border: `0.5px solid ${parseFloat(simResult.advantage) <= 0.15 && !reuseNonce ? "#1D9E75" : reuseNonce ? "#E24B4A" : "#BA7517"}`,
                color: parseFloat(simResult.advantage) <= 0.15 && !reuseNonce ? "#0F6E56" : reuseNonce ? "#A32D2D" : "#854F0B",
              }}>
                {reuseNonce
                  ? "Broken mode: adversary exploits fixed r — wins trivially!"
                  : parseFloat(simResult.advantage) <= 0.15
                    ? "Secure mode: advantage ≈ 0 ✓"
                    : "Advantage non-trivial (expected variance with small sample)"}
              </div>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
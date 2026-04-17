// ═══════════════════════════════════════════════════════════════════════════════
// PA #5 Panel — Message Authentication Codes (MACs)
// PRF-MAC · CBC-MAC · EUF-CMA game · Length-extension attack demo
// ═══════════════════════════════════════════════════════════════════════════════

import { useState, useMemo, useRef } from "react";
import {
  prfMacSign, prfMacVerify,
  cbcMacSign, cbcMacVerify,
  runMacPRFDistTest,
  generateSignedPairs, attemptForgery,
  lengthExtensionDemo,
} from "./crypto.js";
import {
  FieldLabel, TextInput, ToggleBar, SectionHeading, MonoBox,
} from "../shared/ui.jsx";

// ── tiny shared stat card ─────────────────────────────────────────────────────
function StatCard({ label, value, accent }) {
  return (
    <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
      <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>{label}</div>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, fontWeight: 500, color: accent || "var(--color-text-primary)" }}>{value}</div>
    </div>
  );
}

// ── badge ─────────────────────────────────────────────────────────────────────
function Badge({ pass, passLabel = "PASS", failLabel = "FAIL" }) {
  return (
    <span style={{
      fontSize: 10, padding: "2px 8px", borderRadius: 3, fontWeight: 500,
      background: pass ? "#E1F5EE" : "#FCEBEB",
      border: `0.5px solid ${pass ? "#1D9E75" : "#E24B4A"}`,
      color: pass ? "#0F6E56" : "#A32D2D",
    }}>{pass ? passLabel : failLabel}</span>
  );
}

// ── CBC-MAC chain visualiser ──────────────────────────────────────────────────
function CBCChainViz({ steps }) {
  if (!steps || steps.length === 0) return null;
  const BOX_W = 72, BOX_H = 32, XOR_R = 14, GAP = 52;
  const totalW = (BOX_W + GAP) * steps.length + 60;
  const MID_Y  = 50;

  return (
    <svg width="100%" viewBox={`0 0 ${totalW} 120`} style={{ display: "block", fontFamily: "var(--font-mono)", overflow: "visible" }}>
      {/* IV label */}
      <rect x={0} y={MID_Y - BOX_H / 2} width={42} height={BOX_H} rx={4}
        fill="var(--color-background-secondary)" stroke="#D3D1C7" strokeWidth={0.5} />
      <text x={21} y={MID_Y + 5} textAnchor="middle" fontSize={9} fill="#888780">0ⁿ</text>

      {steps.map((s, i) => {
        const baseX = 42 + i * (BOX_W + GAP);
        const xorX  = baseX + GAP * 0.45;
        const fkX   = baseX + GAP * 0.7;

        return (
          <g key={i}>
            {/* arrow from prev state → XOR */}
            <line x1={baseX} y1={MID_Y} x2={xorX - XOR_R} y2={MID_Y}
              stroke="#B5B1A8" strokeWidth={1} markerEnd="url(#arr)" />

            {/* message block M_i — drops in from above */}
            <rect x={xorX - 18} y={MID_Y - 52} width={36} height={22} rx={4}
              fill="#E1F5EE" stroke="#1D9E75" strokeWidth={0.8} />
            <text x={xorX} y={MID_Y - 36} textAnchor="middle" fontSize={8} fill="#0F6E56">
              {`M${i + 1}`}
            </text>
            <text x={xorX} y={MID_Y - 24} textAnchor="middle" fontSize={7} fill="#0F6E56">
              {`0x${s.block.slice(0, 6)}`}
            </text>
            <line x1={xorX} y1={MID_Y - 30} x2={xorX} y2={MID_Y - XOR_R}
              stroke="#1D9E75" strokeWidth={0.8} />

            {/* XOR circle */}
            <circle cx={xorX} cy={MID_Y} r={XOR_R}
              fill="#FFF8EC" stroke="#BA7517" strokeWidth={1} />
            <text x={xorX} y={MID_Y + 4} textAnchor="middle" fontSize={12} fill="#854F0B">⊕</text>

            {/* arrow XOR → F_k */}
            <line x1={xorX + XOR_R} y1={MID_Y} x2={fkX} y2={MID_Y}
              stroke="#B5B1A8" strokeWidth={1} />

            {/* F_k box */}
            <rect x={fkX} y={MID_Y - BOX_H / 2} width={BOX_W} height={BOX_H} rx={4}
              fill="#E6F1FB" stroke="#378ADD" strokeWidth={1} />
            <text x={fkX + BOX_W / 2} y={MID_Y - 3} textAnchor="middle" fontSize={9} fill="#185FA5">Fₖ</text>
            <text x={fkX + BOX_W / 2} y={MID_Y + 10} textAnchor="middle" fontSize={7.5} fill="#185FA5">
              {`0x${s.next.slice(0, 6)}`}
            </text>
          </g>
        );
      })}

      {/* final → tag label */}
      {steps.length > 0 && (() => {
        const lastFkX = 42 + (steps.length - 1) * (BOX_W + GAP) + GAP * 0.7;
        return (
          <g>
            <line x1={lastFkX + BOX_W} y1={MID_Y} x2={lastFkX + BOX_W + 32} y2={MID_Y}
              stroke="#B5B1A8" strokeWidth={1} />
            <rect x={lastFkX + BOX_W + 32} y={MID_Y - 14} width={44} height={28} rx={4}
              fill="#EEEDFE" stroke="#7F77DD" strokeWidth={1} />
            <text x={lastFkX + BOX_W + 54} y={MID_Y + 5} textAnchor="middle" fontSize={9} fill="#3C3489">tag t</text>
          </g>
        );
      })()}

      <defs>
        <marker id="arr" markerWidth={6} markerHeight={6} refX={5} refY={3} orient="auto">
          <path d="M0,0 L6,3 L0,6 Z" fill="#B5B1A8" />
        </marker>
      </defs>
    </svg>
  );
}

// ── Main PA5 panel ────────────────────────────────────────────────────────────
export default function PA5Panel() {
  const [prfType,     setPrfType]     = useState("GGM");
  const [activeTab,   setActiveTab]   = useState("prf-mac");

  // ── PRF-MAC tab state ──
  const [pmKey,       setPmKey]       = useState("a3f2c1b8");
//   const [pmMsg,       setPmMsg]       = useState("deadbeef");
  const [pmMsg, setPmMsg] = useState("10110010"); 
  const [pmTag,       setPmTag]       = useState("");
  const [pmVerifyTag, setPmVerifyTag] = useState("");
  const [pmVerifyRes, setPmVerifyRes] = useState(null);

  // ── CBC-MAC tab state ──
  const [cbcKey,      setCbcKey]      = useState("a3f2c1b8");
//   const [cbcMsg,      setCbcMsg]      = useState("cafebabe1234");
  const [cbcMsg, setCbcMsg] = useState("1011001011001010"); 
  const [cbcTag,      setCbcTag]      = useState("");
  const [cbcVerify,   setCbcVerify]   = useState("");
  const [cbcVerRes,   setCbcVerRes]   = useState(null);

  // ── EUF-CMA tab state ──
  const [eufKey]                      = useState(() => Math.floor(Math.random() * 0xffffffff).toString(16).padStart(8, "0"));
  const [eufPairs,    setEufPairs]    = useState(null);
  const [forgeMsg,    setForgeMsg]    = useState("");
  const [forgeTag,    setForgeTag]    = useState("");
  const [forgeResult, setForgeResult] = useState(null);
  const [forgeCounts, setForgeCounts] = useState({ attempts: 0, successes: 0 });

  // ── MAC⇒PRF tab state ──
  const [distResult,  setDistResult]  = useState(null);
  const [distKey,     setDistKey]     = useState("b4e7a2f1");

  // ── Length-extension tab state ──
  const [leKey,       setLeKey]       = useState("a3f2c1b8");
  const [leMsg,       setLeMsg]       = useState("deadbeef");
  const [leSuffix,    setLeSuffix]    = useState("cafebabe");
  const [leResult,    setLeResult]    = useState(null);

  // ── computed ──────────────────────────────────────────────────────────────
  const pmResult = useMemo(() => prfMacSign(pmKey, pmMsg, prfType), [pmKey, pmMsg, prfType]);
  const cbcResult = useMemo(() => cbcMacSign(cbcKey, cbcMsg, prfType), [cbcKey, cbcMsg, prfType]);

  // ── actions ───────────────────────────────────────────────────────────────
  function doGenPairs() { setEufPairs(generateSignedPairs(eufKey, prfType, 50)); setForgeResult(null); }
  function doForgery() {
    if (!eufPairs) return;
    const res = attemptForgery(eufKey, forgeMsg, forgeTag, eufPairs, prfType);
    setForgeResult(res);
    setForgeCounts(c => ({ attempts: c.attempts + 1, successes: c.successes + (res.accepted ? 1 : 0) }));
  }
  function doLenExt() { setLeResult(lengthExtensionDemo(leKey, leMsg, leSuffix)); }

  // ── tab config ────────────────────────────────────────────────────────────
  const TABS = [
    { id: "prf-mac",  label: "PRF-MAC" },
    { id: "cbc-mac",  label: "CBC-MAC" },
    { id: "euf-cma",  label: "EUF-CMA game" },
    { id: "mac-prf",  label: "MAC ⇒ PRF" },
    { id: "len-ext",  label: "Length-ext attack" },
  ];

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>
      {/* ── Header ── */}
      <div style={{ padding: "10px 16px", background: "#FEF3E2", borderBottom: "0.5px solid #E8B96A", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: "#7A4A00" }}>
          PA #5 — Message Authentication Codes
        </div>
        <ToggleBar value={prfType} onChange={setPrfType} options={[
          { value: "GGM", label: "GGM (PRG-based)", activeStyle: { bg: "#EEEDFE", border: "#7F77DD", color: "#3C3489" } },
          { value: "AES", label: "AES plug-in",      activeStyle: { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" } },
        ]} />
      </div>

      {/* ── Tab bar ── */}
      <div style={{ display: "flex", borderBottom: "0.5px solid var(--color-border-tertiary)", background: "var(--color-background-secondary)", overflowX: "auto" }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)} style={{
            padding: "8px 16px", fontSize: 12, fontWeight: activeTab === t.id ? 500 : 400,
            border: "none", borderBottom: activeTab === t.id ? "2px solid #BA7517" : "2px solid transparent",
            background: "transparent", cursor: "pointer", color: activeTab === t.id ? "#7A4A00" : "var(--color-text-secondary)",
            fontFamily: "var(--font-sans)", whiteSpace: "nowrap",
          }}>{t.label}</button>
        ))}
      </div>

      <div style={{ padding: 16 }}>

        {/* ════════════════════════════════════════════════════
            TAB 1 — PRF-MAC (fixed-length)
        ════════════════════════════════════════════════════ */}
        {activeTab === "prf-mac" && (
          <div>
            <SectionHeading>Construction 1 — PRF-MAC (fixed-length): Mac_k(m) = F_k(m)</SectionHeading>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>

              {/* Sign */}
              <div>
                <div style={{ fontWeight: 500, fontSize: 12, marginBottom: 10, color: "var(--color-text-primary)" }}>Sign</div>
                <div style={{ marginBottom: 8 }}><FieldLabel>Key k (hex, 8 chars)</FieldLabel><TextInput value={pmKey} onChange={setPmKey} placeholder="a3f2c1b8" /></div>
                <div style={{ marginBottom: 12 }}><FieldLabel>Message m (hex, 8 chars — one block)</FieldLabel><TextInput value={pmMsg} onChange={setPmMsg} placeholder="10110010" /></div>
                <div style={{ padding: "12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
                  <div style={{ fontSize: 10, color: "var(--color-text-secondary)", marginBottom: 6 }}>Mac_k(m) = F_k(m)</div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)", marginBottom: 4 }}>F_{"{prfType}"}(0x{pmKey.slice(0,6)}, 0x{pmResult.m})</div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ fontSize: 11, color: "var(--color-text-secondary)" }}>tag t =</span>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 16, fontWeight: 600, color: "#7A4A00" }}>0x{pmResult.tag}</span>
                  </div>
                </div>
              </div>

              {/* Verify */}
              <div>
                <div style={{ fontWeight: 500, fontSize: 12, marginBottom: 10, color: "var(--color-text-primary)" }}>Verify</div>
                <div style={{ marginBottom: 8 }}><FieldLabel>Tag to verify</FieldLabel>
                  <TextInput value={pmVerifyTag} onChange={setPmVerifyTag} placeholder="paste tag here" />
                </div>
                <button onClick={() => setPmVerifyRes(prfMacVerify(pmKey, pmMsg, pmVerifyTag, prfType))}
                  style={btnStyle("#FEF3E2", "#E8B96A", "#7A4A00")}>Verify tag</button>
                {pmVerifyRes !== null && (
                  <div style={{ marginTop: 10, padding: "10px 12px", borderRadius: "var(--border-radius-md)", background: pmVerifyRes ? "#E1F5EE" : "#FCEBEB", border: `0.5px solid ${pmVerifyRes ? "#1D9E75" : "#E24B4A"}`, color: pmVerifyRes ? "#0F6E56" : "#A32D2D", fontSize: 13, fontWeight: 500 }}>
                    {pmVerifyRes ? "✓ Tag valid — Vrfy(k, m, t) = 1" : "✗ Tag invalid — Vrfy(k, m, t) = 0"}
                  </div>
                )}
                <div style={{ marginTop: 12, padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", fontSize: 11 }}>
                  <div style={{ fontSize: 10, color: "var(--color-text-secondary)", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.07em" }}>Quick test — copy current tag</div>
                  <button onClick={() => setPmVerifyTag(pmResult.tag)} style={btnStyle("#E6F1FB", "#B5D4F4", "#185FA5")}>Copy tag → verify field</button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ════════════════════════════════════════════════════
            TAB 2 — CBC-MAC (variable-length)
        ════════════════════════════════════════════════════ */}
        {activeTab === "cbc-mac" && (
          <div>
            <SectionHeading>Construction 2 — CBC-MAC: chain F_k over message blocks, output final state</SectionHeading>
            <div style={{ display: "grid", gridTemplateColumns: "260px minmax(0,1fr)", gap: 16, marginBottom: 16 }}>
              <div>
                <div style={{ marginBottom: 8 }}><FieldLabel>Key k (hex)</FieldLabel><TextInput value={cbcKey} onChange={setCbcKey} placeholder="a3f2c1b8" /></div>
                <div style={{ marginBottom: 12 }}><FieldLabel>Message m (hex, any length)</FieldLabel><TextInput value={cbcMsg} onChange={setCbcMsg} placeholder="cafebabe1234" /></div>
                <div style={{ padding: "12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 10 }}>
                  <div style={{ fontSize: 10, color: "var(--color-text-secondary)", marginBottom: 4 }}>Blocks (after padding): {cbcResult.blocks.length}</div>
                  {cbcResult.blocks.map((b, i) => (
                    <div key={i} style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-secondary)", marginBottom: 2 }}>
                      M{i + 1} = 0x{b}
                    </div>
                  ))}
                  <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", marginTop: 8, paddingTop: 8, display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ fontSize: 11, color: "var(--color-text-secondary)" }}>tag t =</span>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 15, fontWeight: 600, color: "#7A4A00" }}>0x{cbcResult.tag}</span>
                  </div>
                </div>

                {/* Verify */}
                <div style={{ marginBottom: 6 }}><FieldLabel>Tag to verify</FieldLabel><TextInput value={cbcVerify} onChange={setCbcVerify} placeholder="paste tag" /></div>
                <div style={{ display: "flex", gap: 8 }}>
                  <button onClick={() => setCbcVerRes(cbcMacVerify(cbcKey, cbcMsg, cbcVerify, prfType))} style={btnStyle("#FEF3E2", "#E8B96A", "#7A4A00")}>Verify</button>
                  <button onClick={() => setCbcVerify(cbcResult.tag)} style={btnStyle("#E6F1FB", "#B5D4F4", "#185FA5")}>Copy tag</button>
                </div>
                {cbcVerRes !== null && (
                  <div style={{ marginTop: 10, padding: "10px 12px", borderRadius: "var(--border-radius-md)", background: cbcVerRes ? "#E1F5EE" : "#FCEBEB", border: `0.5px solid ${cbcVerRes ? "#1D9E75" : "#E24B4A"}`, color: cbcVerRes ? "#0F6E56" : "#A32D2D", fontSize: 12, fontWeight: 500 }}>
                    {cbcVerRes ? "✓ Tag valid" : "✗ Tag invalid"}
                  </div>
                )}
              </div>

              {/* Chain visualiser */}
              <div>
                <SectionHeading>CBC-MAC chain — {cbcResult.steps.length} blocks</SectionHeading>
                <div style={{ padding: 10, background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", overflowX: "auto" }}>
                  <CBCChainViz steps={cbcResult.steps} />
                </div>
                <div style={{ marginTop: 8 }}>
                  <SectionHeading>Step trace</SectionHeading>
                  <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", overflow: "hidden" }}>
                    <div style={{ display: "grid", gridTemplateColumns: "50px 1fr 1fr 1fr", background: "var(--color-background-secondary)", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
                      {["Step", "State_in", "M_i ⊕ state", "F_k(·)"].map((h, i) => (
                        <div key={i} style={{ padding: "5px 8px", fontSize: 10, fontWeight: 500, color: "var(--color-text-secondary)", textTransform: "uppercase" }}>{h}</div>
                      ))}
                    </div>
                    {cbcResult.steps.map((s, i) => (
                      <div key={i} style={{ display: "grid", gridTemplateColumns: "50px 1fr 1fr 1fr", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
                        <div style={{ padding: "5px 8px", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)" }}>{i + 1}</div>
                        <div style={{ padding: "5px 8px", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)" }}>0x{s.state}</div>
                        <div style={{ padding: "5px 8px", fontFamily: "var(--font-mono)", fontSize: 11, color: "#854F0B" }}>0x{s.xored}</div>
                        <div style={{ padding: "5px 8px", fontFamily: "var(--font-mono)", fontSize: 11, color: "#3C3489" }}>0x{s.next}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ════════════════════════════════════════════════════
            TAB 3 — EUF-CMA game
        ════════════════════════════════════════════════════ */}
        {activeTab === "euf-cma" && (
          <div>
            <SectionHeading>EUF-CMA Forgery Game — hidden key k (not shown), up to 50 signed pairs</SectionHeading>
            <div style={{ display: "grid", gridTemplateColumns: "260px minmax(0,1fr)", gap: 16 }}>
              <div>
                <div style={{ padding: "10px 12px", background: "#FEF3E2", borderRadius: "var(--border-radius-md)", fontSize: 11, color: "#7A4A00", marginBottom: 12, border: "0.5px solid #E8B96A" }}>
                  Key k is hidden. You see (m_i, t_i) pairs. Forge a valid tag on a <em>new</em> message.
                </div>
                <button onClick={doGenPairs} style={{ ...btnStyle("#FEF3E2", "#E8B96A", "#7A4A00"), width: "100%", marginBottom: 12 }}>
                  Generate 50 signed pairs
                </button>
                {eufPairs && (
                  <>
                    <div style={{ marginBottom: 8 }}><FieldLabel>Forge message m* (hex, 8 chars — not in list)</FieldLabel><TextInput value={forgeMsg} onChange={setForgeMsg} placeholder="new hex msg…" /></div>
                    <div style={{ marginBottom: 10 }}><FieldLabel>Forge tag t* (hex)</FieldLabel><TextInput value={forgeTag} onChange={setForgeTag} placeholder="your guessed tag…" /></div>
                    <button onClick={doForgery} style={{ ...btnStyle("#FCEBEB", "#E24B4A", "#A32D2D"), width: "100%", marginBottom: 12 }}>Submit forgery</button>
                    {forgeResult && (
                      <div style={{ padding: "10px 12px", borderRadius: "var(--border-radius-md)", background: forgeResult.accepted ? "#FCEBEB" : "#E1F5EE", border: `0.5px solid ${forgeResult.accepted ? "#E24B4A" : "#1D9E75"}`, color: forgeResult.accepted ? "#A32D2D" : "#0F6E56", fontSize: 12, fontWeight: 500, marginBottom: 10 }}>
                        {forgeResult.reason}
                      </div>
                    )}
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                      <StatCard label="Attempts" value={forgeCounts.attempts} />
                      <StatCard label="Successes" value={forgeCounts.successes} accent={forgeCounts.successes > 0 ? "#A32D2D" : "#0F6E56"} />
                    </div>
                    <div style={{ marginTop: 8, padding: "8px 10px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", fontSize: 11, color: "var(--color-text-secondary)" }}>
                      Graders expect <strong>0 successes</strong> in ≥ 20 attempts.
                    </div>
                  </>
                )}
              </div>

              {/* Signed pairs table */}
              <div>
                <SectionHeading>Signed pairs (m_i, t_i) — oracle output</SectionHeading>
                {eufPairs ? (
                  <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", overflow: "hidden", maxHeight: 360, overflowY: "auto" }}>
                    <div style={{ display: "grid", gridTemplateColumns: "50px 1fr 1fr", background: "var(--color-background-secondary)", borderBottom: "0.5px solid var(--color-border-tertiary)", position: "sticky", top: 0 }}>
                      {["#", "m_i", "t_i = Mac_k(m_i)"].map((h, i) => (
                        <div key={i} style={{ padding: "5px 10px", fontSize: 10, fontWeight: 500, color: "var(--color-text-secondary)", textTransform: "uppercase" }}>{h}</div>
                      ))}
                    </div>
                    {eufPairs.map((p, i) => (
                      <div key={i} style={{ display: "grid", gridTemplateColumns: "50px 1fr 1fr", borderBottom: "0.5px solid var(--color-border-tertiary)", background: p.m === forgeMsg ? "#FEF3E2" : "transparent" }}>
                        <div style={{ padding: "5px 10px", fontSize: 11, color: "var(--color-text-secondary)" }}>{i + 1}</div>
                        <div style={{ padding: "5px 10px", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-primary)" }}>0x{p.m}</div>
                        <div style={{ padding: "5px 10px", fontFamily: "var(--font-mono)", fontSize: 11, color: "#7A4A00" }}>0x{p.tag}</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ padding: 24, textAlign: "center", fontSize: 12, color: "var(--color-text-secondary)", fontStyle: "italic", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
                    Click "Generate 50 signed pairs" to begin the game.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ════════════════════════════════════════════════════
            TAB 4 — MAC ⇒ PRF distinguishing test
        ════════════════════════════════════════════════════ */}
        {activeTab === "mac-prf" && (
          <div>
            <SectionHeading>MAC ⇒ PRF — PRF-MAC on uniform random inputs passes the PA#2 distinguishing test</SectionHeading>
            <div style={{ display: "grid", gridTemplateColumns: "260px minmax(0,1fr)", gap: 16 }}>
              <div>
                <div style={{ marginBottom: 10 }}><FieldLabel>Key k (hex)</FieldLabel><TextInput value={distKey} onChange={setDistKey} placeholder="b4e7a2f1" /></div>
                <button onClick={() => setDistResult(runMacPRFDistTest(distKey, prfType, 100))}
                  style={{ ...btnStyle("#FEF3E2", "#E8B96A", "#7A4A00"), width: "100%" }}>
                  Run test (q = 100)
                </button>
                {distResult && (
                  <div style={{ marginTop: 12 }}>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 10 }}>
                      <StatCard label="Collisions" value={`${distResult.collisions} (${distResult.collisionRate}%)`} />
                      <StatCard label="Mean diff" value={distResult.diff} accent={parseFloat(distResult.diff) < 20 ? "#0F6E56" : "#A32D2D"} />
                      <StatCard label="MAC mean byte" value={distResult.macMean} />
                      <StatCard label="Rand mean byte" value={distResult.randMean} />
                    </div>
                    <div style={{ padding: "10px 12px", borderRadius: "var(--border-radius-md)", background: parseFloat(distResult.diff) < 20 ? "#E1F5EE" : "#FAEEDA", border: `0.5px solid ${parseFloat(distResult.diff) < 20 ? "#1D9E75" : "#BA7517"}`, color: parseFloat(distResult.diff) < 20 ? "#0F6E56" : "#854F0B", fontSize: 12 }}>
                      {parseFloat(distResult.diff) < 20
                        ? "Statistically indistinguishable from random ✓ — MAC ⇒ PRF confirmed"
                        : "Outputs differ — check PRF implementation"}
                    </div>
                  </div>
                )}
              </div>

              {distResult && (
                <div>
                  <SectionHeading>First 10 queries</SectionHeading>
                  <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", overflow: "hidden" }}>
                    <div style={{ display: "grid", gridTemplateColumns: "80px 1fr 1fr 60px", background: "var(--color-background-secondary)", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
                      {["x", "MAC_k(x)", "random(x)", "match?"].map((h, i) => (
                        <div key={i} style={{ padding: "6px 10px", fontSize: 10, fontWeight: 500, color: "var(--color-text-secondary)", textTransform: "uppercase" }}>{h}</div>
                      ))}
                    </div>
                    {distResult.queries.map((q, i) => (
                      <div key={i} style={{ display: "grid", gridTemplateColumns: "80px 1fr 1fr 60px", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
                        <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)" }}>0x{q.x}</div>
                        <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 11, color: "#7A4A00" }}>0x{q.macOut}</div>
                        <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)" }}>0x{q.rndOut}</div>
                        <div style={{ padding: "6px 10px", fontSize: 11, color: q.same ? "#A32D2D" : "#0F6E56" }}>{q.same ? "yes !" : "no ✓"}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ════════════════════════════════════════════════════
            TAB 5 — Length-extension attack
        ════════════════════════════════════════════════════ */}
        {activeTab === "len-ext" && (
          <div>
            <SectionHeading>Length-extension attack on naive MAC: t = H(k ‖ m)</SectionHeading>
            <div style={{ padding: "10px 12px", background: "#FAEEDA", borderRadius: "var(--border-radius-md)", fontSize: 12, color: "#7A4A00", marginBottom: 16, border: "0.5px solid #E8B96A", lineHeight: 1.6 }}>
              <strong>Vulnerability:</strong> If t = H(k ‖ m), an attacker who knows t and |k| can compute a valid tag for
              m ‖ pad ‖ m′ <em>without knowing k</em>. This motivates HMAC's double-hash structure.
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "260px minmax(0,1fr)", gap: 16 }}>
              <div>
                <div style={{ marginBottom: 8 }}><FieldLabel>Key k (hex)</FieldLabel><TextInput value={leKey} onChange={setLeKey} placeholder="a3f2c1b8" /></div>
                <div style={{ marginBottom: 8 }}><FieldLabel>Original message m (hex)</FieldLabel><TextInput value={leMsg} onChange={setLeMsg} placeholder="1011001011001010" /></div>
                <div style={{ marginBottom: 12 }}><FieldLabel>Attacker suffix m′ (hex)</FieldLabel><TextInput value={leSuffix} onChange={setLeSuffix} placeholder="cafebabe" /></div>
                <button onClick={doLenExt} style={{ ...btnStyle("#FCEBEB", "#E24B4A", "#A32D2D"), width: "100%" }}>Run length-extension</button>
              </div>

              <div>
                {leResult ? (
                  <div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 14 }}>
                      <StatCard label="Original tag H(k‖m)" value={`0x${leResult.origTag}`} accent="#185FA5" />
                      <StatCard label="Attack succeeded?" value={leResult.attackSucceeded ? "YES ✓" : "no"} accent={leResult.attackSucceeded ? "#A32D2D" : "#0F6E56"} />
                    </div>
                    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", overflow: "hidden", marginBottom: 12 }}>
                      {[
                        { label: "Padding appended inside H", val: `0x${leResult.padHex}`, c: "#854F0B" },
                        { label: "Extended msg m‖pad‖m′", val: `0x${leResult.extMsg.slice(0, 32)}…`, c: "var(--color-text-primary)" },
                        { label: "Tag from state (no key)", val: `0x${leResult.extTag}`, c: "#A32D2D" },
                        { label: "True H(k‖m_ext) tag", val: `0x${leResult.extTagTrue}`, c: "#0F6E56" },
                      ].map((row, i) => (
                        <div key={i} style={{ display: "grid", gridTemplateColumns: "180px 1fr", padding: "7px 12px", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
                          <div style={{ fontSize: 11, color: "var(--color-text-secondary)" }}>{row.label}</div>
                          <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: row.c }}>{row.val}</div>
                        </div>
                      ))}
                    </div>
                    <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: leResult.attackSucceeded ? "#FCEBEB" : "#E1F5EE", border: `0.5px solid ${leResult.attackSucceeded ? "#E24B4A" : "#1D9E75"}`, color: leResult.attackSucceeded ? "#A32D2D" : "#0F6E56", fontSize: 12, lineHeight: 1.6 }}>
                      {leResult.attackSucceeded
                        ? "Attack succeeded — forged tag matches H(k ‖ m_ext) without knowing k. HMAC prevents this."
                        : "Attack did not succeed in this configuration."}
                    </div>
                  </div>
                ) : (
                  <div style={{ padding: 24, textAlign: "center", fontSize: 12, color: "var(--color-text-secondary)", fontStyle: "italic", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
                    Set inputs and click "Run length-extension" to see the attack.
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

// ── tiny inline button style helper (avoids duplicate objects) ─────────────────
function btnStyle(bg, border, color) {
  return {
    padding: "7px 14px", fontSize: 12, fontWeight: 500,
    border: `0.5px solid ${border}`, borderRadius: "var(--border-radius-md)",
    background: bg, color, cursor: "pointer",
    fontFamily: "var(--font-sans)", whiteSpace: "nowrap",
  };
}
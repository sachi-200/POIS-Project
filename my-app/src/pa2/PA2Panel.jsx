// ═══════════════════════════════════════════════════════════════════════════════
// PA #2 Panel — GGM tree visualiser & PRF demo
// ═══════════════════════════════════════════════════════════════════════════════

import { useState, useMemo } from "react";
import { frequencyTest, runsTest, serialTest } from "../utils/nist.js";
import {
  ggmPRF, aesPRF, prgFromPRF, buildGGMTree, runDistinguishingGame,
} from "./crypto.js";
import {
  FieldLabel, TextInput, ToggleBar, SectionHeading, MonoBox,
} from "../shared/ui.jsx";

// ── GGM binary tree SVG visualiser ───────────────────────────────────────────

function GGMTreeViz({ levels, bitString }) {
  if (!levels || levels.length === 0) return null;
  const depth = levels.length - 1;
  const nodeW = 64, nodeH = 28, vGap = 48;
  const svgW = Math.max(500, Math.pow(2, depth) * (nodeW + 16) + 16);
  const svgH = (depth + 1) * (nodeH + vGap) + 16;

  function nodeX(id) {
    const d = id.length, total = Math.pow(2, d), idx = parseInt(id || "0", 2) || 0;
    return (svgW / total) * idx + svgW / total / 2 - nodeW / 2;
  }
  function nodeY(d) { return 8 + d * (nodeH + vGap); }
  const allNodes = levels.flatMap(l => l);

  return (
    <svg width="100%" viewBox={`0 0 ${svgW} ${svgH}`} style={{ display: "block", fontFamily: "var(--font-mono)" }}>
      {allNodes.map(n => {
        if (n.id.length >= depth) return null;
        const px = nodeX(n.id) + nodeW / 2, py = nodeY(n.id.length) + nodeH;
        const l0 = n.id + "0", l1 = n.id + "1";
        const lx0 = nodeX(l0) + nodeW / 2, lx1 = nodeX(l1) + nodeW / 2;
        const cy = nodeY(n.id.length + 1);
        const pa0 = bitString.startsWith(l0), pa1 = bitString.startsWith(l1);
        return (
          <g key={`e-${n.id}`}>
            <line x1={px} y1={py} x2={lx0} y2={cy} stroke={pa0 ? "#378ADD" : "#D3D1C7"} strokeWidth={pa0 ? 2 : 1} />
            <text x={(px + lx0) / 2 - 6} y={(py + cy) / 2} fontSize={10} fill={pa0 ? "#185FA5" : "#888780"}>0</text>
            <line x1={px} y1={py} x2={lx1} y2={cy} stroke={pa1 ? "#378ADD" : "#D3D1C7"} strokeWidth={pa1 ? 2 : 1} />
            <text x={(px + lx1) / 2 + 2} y={(py + cy) / 2} fontSize={10} fill={pa1 ? "#185FA5" : "#888780"}>1</text>
          </g>
        );
      })}
      {allNodes.map(n => {
        const x = nodeX(n.id), y = nodeY(n.id.length);
        const fill   = n.isLeaf && n.active ? "#E1F5EE" : n.active ? "#E6F1FB" : "var(--color-background-secondary)";
        const stroke = n.isLeaf && n.active ? "#1D9E75" : n.active ? "#378ADD" : "#D3D1C7";
        const textC  = n.isLeaf && n.active ? "#0F6E56" : n.active ? "#185FA5" : "#888780";
        return (
          <g key={`n-${n.id}`}>
            <rect x={x} y={y} width={nodeW} height={nodeH} rx={n.isLeaf ? 4 : 14} fill={fill} stroke={stroke} strokeWidth={n.active ? 1.5 : 0.5} />
            <text x={x + nodeW / 2} y={y + nodeH / 2 + 4} textAnchor="middle" fontSize={9} fill={textC}>
              {n.id === "" ? "k" : `0x${n.val.slice(0, 6)}`}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

// ── Main PA2 panel ────────────────────────────────────────────────────────────

export default function PA2Panel() {
  const [prfType,   setPrfType]   = useState("GGM");
  const [keyHex,    setKeyHex]    = useState("a3f2c1b8");
  const [queryBits, setQueryBits] = useState("1010");
  const [prgSeed,   setPrgSeed]   = useState("deadbeef");
  const [prgLen,    setPrgLen]    = useState(16);
  const [distResult,setDistResult]= useState(null);
  const [showDist,  setShowDist]  = useState(false);

  const cleanBits = queryBits.replace(/[^01]/g, "").slice(0, 8);

  const prfResult  = useMemo(() =>
    prfType === "AES"
      ? { value: aesPRF(keyHex, cleanBits.padEnd(8, "0")), path: [] }
      : ggmPRF(keyHex, cleanBits),
    [prfType, keyHex, cleanBits]
  );
  const treeData   = useMemo(() => buildGGMTree(keyHex, cleanBits, 8), [keyHex, cleanBits]);
  const prgResult2 = useMemo(() => prgFromPRF(prgSeed, prfType, prgLen), [prgSeed, prfType, prgLen]);

  const prgRatio2 = prgResult2.bitString.length > 0
    ? prgResult2.bitString.split("").filter(b => b === "1").length / prgResult2.bitString.length
    : 0.5;
  const prgTests2 = useMemo(() => ({
    freq:   frequencyTest(prgResult2.bitString),
    runs:   runsTest(prgResult2.bitString),
    serial: serialTest(prgResult2.bitString),
  }), [prgResult2.bitString]);

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>
      {/* Header */}
      <div style={{ padding: "10px 16px", background: "#EEEDFE", borderBottom: "0.5px solid #AFA9EC", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: "#3C3489" }}>PA #2 — GGM tree visualiser & PRF demo</div>
        <ToggleBar value={prfType} onChange={setPrfType} options={[
          { value: "GGM", label: "GGM (PRG-based)", activeStyle: { bg: "#EEEDFE", border: "#7F77DD", color: "#3C3489" } },
          { value: "AES", label: "AES plug-in",      activeStyle: { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" } },
        ]} />
      </div>

      <div style={{ padding: "16px" }}>
        {/* ── Row 1: PRF inputs + tree ── */}
        <div style={{ display: "grid", gridTemplateColumns: "260px minmax(0,1fr)", gap: 16, marginBottom: 20 }}>
          <div>
            <SectionHeading>PRF inputs — F(k, x)</SectionHeading>
            <div style={{ marginBottom: 10 }}><FieldLabel>Key k (hex)</FieldLabel><TextInput value={keyHex} onChange={setKeyHex} placeholder="e.g. a3f2c1b8" /></div>
            <div style={{ marginBottom: 14 }}>
              <FieldLabel>Query x — bit string (≤ 8 bits)</FieldLabel>
              <TextInput value={queryBits} onChange={v => setQueryBits(v.replace(/[^01]/g, "").slice(0, 8))} placeholder="e.g. 1010" />
              <div style={{ fontSize: 10, color: "var(--color-text-secondary)", marginTop: 3 }}>depth={cleanBits.length}, path: {cleanBits.split("").join(" → ") || "root"}</div>
            </div>

            {/* F_k(x) result */}
            <div style={{ padding: "12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 10 }}>
              <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>F_k(x) = {prfType === "AES" ? "AES_k(x)" : "GGM leaf"}</div>
              {prfType === "GGM" && prfResult.path.map((step, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4, fontSize: 11 }}>
                  <span style={{ fontSize: 10, padding: "1px 6px", borderRadius: 3, fontWeight: 500, background: step.bit === "0" ? "#E6F1FB" : "#E1F5EE", color: step.bit === "0" ? "#185FA5" : "#0F6E56", border: `0.5px solid ${step.bit === "0" ? "#378ADD" : "#1D9E75"}` }}>G{step.bit}</span>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-secondary)" }}>0x{step.nodeVal.slice(0, 6)}</span>
                  <span style={{ fontSize: 10, color: "var(--color-text-secondary)" }}>→</span>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-primary)" }}>0x{(step.bit === "0" ? step.left : step.right).slice(0, 6)}</span>
                </div>
              ))}
              <div style={{ marginTop: 8, paddingTop: 8, borderTop: "0.5px solid var(--color-border-tertiary)", display: "flex", gap: 8 }}>
                <span style={{ fontSize: 10, color: "var(--color-text-secondary)" }}>F_k(x) =</span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 14, color: "#3C3489", fontWeight: 500 }}>0x{prfResult.value}</span>
              </div>
            </div>

            {/* Interface box */}
            <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", fontSize: 11 }}>
              <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 6 }}>F(k, x) interface for PA#3–5</div>
              <div style={{ fontFamily: "var(--font-mono)", color: "#3C3489", marginBottom: 2 }}>makePRFInterface(k, "{prfType}")</div>
              <div style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-secondary)", marginBottom: 2 }}>prf.F("{cleanBits || "0000"}")</div>
              <div style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-primary)" }}>→ 0x{prfResult.value}</div>
            </div>
          </div>

          {/* Tree visualiser */}
          <div>
            <SectionHeading>GGM binary tree — depth {cleanBits.length} — active path in blue</SectionHeading>
            <div style={{ padding: "10px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", overflowX: "auto" }}>
              {prfType === "GGM"
                ? <GGMTreeViz levels={treeData.levels} bitString={cleanBits} />
                : <div style={{ padding: "20px", textAlign: "center", fontSize: 12, color: "var(--color-text-secondary)", fontStyle: "italic" }}>AES mode: F_k(x) = AES_k(x) directly — no tree. Switch to GGM to see the visualiser.</div>
              }
            </div>
            {prfType === "GGM" && (
              <div style={{ marginTop: 8, padding: "8px 12px", borderRadius: "var(--border-radius-md)", background: "#E6F1FB", border: "0.5px solid #B5D4F4", fontSize: 11, color: "#185FA5" }}>
                Leaf F_k({cleanBits || "ε"}) = <span style={{ fontFamily: "var(--font-mono)", fontWeight: 500 }}>0x{treeData.leafVal}</span> ✓
              </div>
            )}
          </div>
        </div>

        {/* ── Row 2: PRG from PRF ── */}
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: 16, marginBottom: 20 }}>
          <SectionHeading>PRG from PRF — G(s) = F_s(0ⁿ) ‖ F_s(1ⁿ) (PA#2b)</SectionHeading>
          <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 16 }}>
            <div>
              <div style={{ marginBottom: 10 }}><FieldLabel>PRG seed (hex)</FieldLabel><TextInput value={prgSeed} onChange={setPrgSeed} placeholder="e.g. deadbeef" /></div>
              <div style={{ marginBottom: 10 }}>
                <FieldLabel>Output — {prgLen} bytes ({prgLen * 8} bits)</FieldLabel>
                <input type="range" min={8} max={128} step={8} value={prgLen} onChange={e => setPrgLen(Number(e.target.value))} style={{ width: "100%" }} />
              </div>
              <MonoBox>0x{prgResult2.hexOut}</MonoBox>
            </div>
            <div>
              <SectionHeading>Statistical tests — same suite as PA#1</SectionHeading>
              <div style={{ marginBottom: 8 }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--color-text-secondary)", marginBottom: 4 }}>
                  <span>Bit ratio</span><span style={{ fontFamily: "var(--font-mono)" }}>{(prgRatio2 * 100).toFixed(1)}% ones</span>
                </div>
                <div style={{ height: 6, borderRadius: 3, background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-tertiary)", overflow: "hidden" }}>
                  <div style={{ height: "100%", width: `${prgRatio2 * 100}%`, background: Math.abs(prgRatio2 - 0.5) < 0.05 ? "#1D9E75" : "#D85A30" }} />
                </div>
              </div>
              {[prgTests2.freq, prgTests2.runs, prgTests2.serial].map((t, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "5px 0", borderBottom: "0.5px solid var(--color-border-tertiary)", fontSize: 11 }}>
                  <span style={{ color: "var(--color-text-secondary)" }}>{t.name}</span>
                  <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-secondary)", fontSize: 10 }}>p={t.pVal}</span>
                    <span style={{ fontSize: 10, padding: "1px 7px", borderRadius: 3, fontWeight: 500, background: t.pass ? "#E1F5EE" : "#FCEBEB", border: `0.5px solid ${t.pass ? "#1D9E75" : "#E24B4A"}`, color: t.pass ? "#0F6E56" : "#A32D2D" }}>{t.pass ? "PASS" : "FAIL"}</span>
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── Row 3: Distinguishing game ── */}
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: 16 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
            <SectionHeading>Distinguishing game — PRF vs truly random (q = 100 queries)</SectionHeading>
            <button
              onClick={() => { setDistResult(runDistinguishingGame(keyHex, prfType, 100)); setShowDist(true); }}
              style={{ padding: "7px 14px", fontSize: 12, fontWeight: 500, border: "0.5px solid #7F77DD", borderRadius: "var(--border-radius-md)", background: "#EEEDFE", color: "#3C3489", cursor: "pointer", fontFamily: "var(--font-sans)", whiteSpace: "nowrap" }}
            >Run game</button>
          </div>
          {showDist && distResult && (
            <div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 10, marginBottom: 14 }}>
                {[
                  { label: "Total queries",    val: distResult.totalQ },
                  { label: "Collisions",       val: `${distResult.collisions} (${distResult.collisionRate}%)` },
                  { label: "PRF mean byte",    val: distResult.prfMean },
                  { label: "Random mean byte", val: distResult.randMean },
                ].map((s, i) => (
                  <div key={i} style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
                    <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>{s.label}</div>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, fontWeight: 500, color: "var(--color-text-primary)" }}>{s.val}</div>
                  </div>
                ))}
              </div>
              <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: parseFloat(distResult.diff) < 20 ? "#E1F5EE" : "#FAEEDA", border: `0.5px solid ${parseFloat(distResult.diff) < 20 ? "#1D9E75" : "#BA7517"}`, color: parseFloat(distResult.diff) < 20 ? "#0F6E56" : "#854F0B", fontSize: 12, marginBottom: 12 }}>
                Mean byte difference = {distResult.diff} — {parseFloat(distResult.diff) < 20 ? "statistically indistinguishable from random ✓" : "outputs differ — check PRF implementation"}
              </div>
              <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", overflow: "hidden" }}>
                <div style={{ display: "grid", gridTemplateColumns: "80px 1fr 1fr 60px", background: "var(--color-background-secondary)", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
                  {["x", "F_k(x)", "random(x)", "match?"].map((h, i) => (
                    <div key={i} style={{ padding: "6px 10px", fontSize: 10, fontWeight: 500, color: "var(--color-text-secondary)", textTransform: "uppercase" }}>{h}</div>
                  ))}
                </div>
                {distResult.queries.map((q, i) => (
                  <div key={i} style={{ display: "grid", gridTemplateColumns: "80px 1fr 1fr 60px", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
                    <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)" }}>0x{q.x}</div>
                    <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 11, color: "#3C3489" }}>0x{q.prfOut}</div>
                    <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)" }}>0x{q.randOut}</div>
                    <div style={{ padding: "6px 10px", fontSize: 11, color: q.same ? "#A32D2D" : "#0F6E56" }}>{q.same ? "yes !" : "no ✓"}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
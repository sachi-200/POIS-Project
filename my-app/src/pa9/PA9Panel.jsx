// ═══════════════════════════════════════════════════════════════════════════════
// PA #9 — Birthday Attack (Collision Finding)
// ═══════════════════════════════════════════════════════════════════════════════

import { useMemo, useRef, useState } from "react";
import {
  BIT_OPTIONS,
  DEFAULT_BITS,
  createPA9Params,
  expectedBirthdayCount,
  makeTruncatedPA8Hash,
  runAttackTrials,
  runFloydBirthdayAttack,
  runNaiveSortBirthdayAttack,
  theoreticalCollisionProbability,
} from "./crypto.js";
import {
  FieldLabel,
  SectionHeading,
  TextInput,
  ToggleBar,
} from "../shared/ui.jsx";

function StatCard({ label, value, accent }) {
  return (
    <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
      <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>{label}</div>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, fontWeight: 500, color: accent || "var(--color-text-primary)", wordBreak: "break-all" }}>{value}</div>
    </div>
  );
}

function ChartLegend({ color, label, dashed }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
      <svg width="18" height="8" aria-hidden="true">
        <line x1="0" y1="4" x2="18" y2="4" stroke={color} strokeWidth="2" strokeDasharray={dashed ? "4 2" : ""} />
      </svg>
      <span style={{ fontSize: 10, color: "var(--color-text-secondary)" }}>{label}</span>
    </div>
  );
}

function CurveChart({ nBits, expected, currentCount, empiricalCounts, running, found }) {
  const W = 560;
  const H = 232;
  const padL = 46;
  const padR = 16;
  const padT = 14;
  const padB = 30;

  const maxObserved = Math.max(currentCount || 0, ...empiricalCounts, Math.ceil(expected * 2.2), 64);
  const maxX = Math.max(64, Math.ceil(maxObserved));
  const xSpan = W - padL - padR;
  const ySpan = H - padT - padB;

  const xToPx = k => padL + (Math.min(Math.max(k, 0), maxX) / maxX) * xSpan;
  const pToPy = p => H - padB - Math.min(Math.max(p, 0), 1) * ySpan;

  const sampleCount = 90;

  const toPath = (points) => points.map((pt, idx) => `${idx === 0 ? "M" : "L"}${pt[0].toFixed(2)} ${pt[1].toFixed(2)}`).join(" ");

  const theoryPath = useMemo(() => {
    const pts = [];
    for (let i = 0; i <= sampleCount; i += 1) {
      const k = (i / sampleCount) * maxX;
      const p = theoreticalCollisionProbability(k, nBits);
      pts.push([xToPx(k), pToPy(p)]);
    }
    return toPath(pts);
  }, [maxX, nBits]);

  const empiricalPath = useMemo(() => {
    if (!empiricalCounts.length) return "";
    const pts = [];
    for (let i = 0; i <= sampleCount; i += 1) {
      const k = (i / sampleCount) * maxX;
      const hitCount = empiricalCounts.filter(c => c <= k).length;
      const p = hitCount / empiricalCounts.length;
      pts.push([xToPx(k), pToPy(p)]);
    }
    return toPath(pts);
  }, [empiricalCounts, maxX]);

  const currentProb = theoreticalCollisionProbability(currentCount, nBits);
  const expectedX = xToPx(expected);
  const currentX = xToPx(currentCount);
  const currentY = pToPy(currentProb);

  const xTicks = [0, Math.round(maxX * 0.25), Math.round(maxX * 0.5), Math.round(maxX * 0.75), maxX];
  const yTicks = [0, 0.25, 0.5, 0.75, 1];

  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ display: "block", background: "var(--color-background-primary)", border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)" }}>
        {xTicks.map((k, idx) => (
          <g key={`x-${idx}`}>
            <line x1={xToPx(k)} y1={padT} x2={xToPx(k)} y2={H - padB} stroke="var(--color-border-tertiary)" strokeWidth="0.5" />
            <text x={xToPx(k)} y={H - 10} textAnchor="middle" fontSize="9" fill="var(--color-text-secondary)">{k}</text>
          </g>
        ))}

        {yTicks.map((p, idx) => (
          <g key={`y-${idx}`}>
            <line x1={padL} y1={pToPy(p)} x2={W - padR} y2={pToPy(p)} stroke="var(--color-border-tertiary)" strokeWidth="0.5" />
            <text x={padL - 8} y={pToPy(p) + 3} textAnchor="end" fontSize="9" fill="var(--color-text-secondary)">{p.toFixed(2)}</text>
          </g>
        ))}

        <line x1={padL} y1={H - padB} x2={W - padR} y2={H - padB} stroke="var(--color-text-secondary)" strokeWidth="0.8" />
        <line x1={padL} y1={padT} x2={padL} y2={H - padB} stroke="var(--color-text-secondary)" strokeWidth="0.8" />

        <path d={theoryPath} fill="none" stroke="#378ADD" strokeWidth="2" />

        {empiricalPath && (
          <path d={empiricalPath} fill="none" stroke="#1D9E75" strokeWidth="2" />
        )}

        <line x1={expectedX} y1={padT} x2={expectedX} y2={H - padB} stroke="#BA7517" strokeWidth="1.2" strokeDasharray="4 3" />
        <text x={expectedX + 3} y={padT + 10} fontSize="9" fill="#854F0B">2^(n/2)</text>

        {(running || currentCount > 0 || found) && (
          <g>
            <line x1={currentX} y1={padT} x2={currentX} y2={H - padB} stroke="#7F77DD" strokeWidth="1" strokeDasharray="3 3" />
            <circle cx={currentX} cy={currentY} r="3" fill="#7F77DD" />
          </g>
        )}

        <text x={W / 2} y={H - 2} textAnchor="middle" fontSize="10" fill="var(--color-text-secondary)">hashes computed (k)</text>
        <text x={12} y={H / 2} transform={`rotate(-90, 12, ${H / 2})`} textAnchor="middle" fontSize="10" fill="var(--color-text-secondary)">collision probability</text>
      </svg>

      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, marginTop: 8, flexWrap: "wrap" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
          <ChartLegend color="#378ADD" label="theory: 1 - exp(-k(k-1)/2^(n+1))" />
          <ChartLegend color="#1D9E75" label={`empirical CDF (${empiricalCounts.length} successful runs)`} />
          <ChartLegend color="#BA7517" label="expected point 2^(n/2)" dashed />
        </div>
        <div style={{ fontSize: 10, color: "var(--color-text-secondary)", fontFamily: "var(--font-mono)" }}>
          p_theory(k={currentCount}) = {currentProb.toFixed(4)}
        </div>
      </div>
    </div>
  );
}

function complexityLabel(variant) {
  if (variant === "floyd") {
    return {
      time: "O(2^(n/2))",
      space: "O(1)",
      text: "Floyd tortoise-hare (space efficient)",
      color: { bg: "#EEEDFE", border: "#7F77DD", text: "#3C3489" },
    };
  }
  return {
    time: "O(k log k)",
    space: "O(k)",
    text: "Naive sort-based",
    color: { bg: "#E6F1FB", border: "#378ADD", text: "#185FA5" },
  };
}

export default function PA9Panel() {
  const [params, setParams] = useState(() => createPA9Params());
  const [nBits, setNBits] = useState(DEFAULT_BITS);
  const [variant, setVariant] = useState("naive-sort");

  const [running, setRunning] = useState(false);
  const [evalCount, setEvalCount] = useState(0);
  const [result, setResult] = useState(null);

  const [trialCount, setTrialCount] = useState("20");
  const [batchRunning, setBatchRunning] = useState(false);
  const [batchProgress, setBatchProgress] = useState(0);
  const [batchSummary, setBatchSummary] = useState(null);

  const [history, setHistory] = useState([]);

  const cancelRef = useRef(false);

  const complexity = complexityLabel(variant);
  const expected = expectedBirthdayCount(nBits);
  const maxEvaluations = Math.max(512, Math.ceil(expected * 24));

  const verifyHash = useMemo(() => makeTruncatedPA8Hash(params, nBits), [params, nBits]);

  const scopedHistory = useMemo(
    () => history.filter(h => h.nBits === nBits && h.variant === variant && h.found).map(h => h.count),
    [history, nBits, variant],
  );

  const empiricalAverage = scopedHistory.length
    ? scopedHistory.reduce((sum, c) => sum + c, 0) / scopedHistory.length
    : null;

  const verification = useMemo(() => {
    if (!result || !result.found) return null;
    const a = verifyHash(result.input1).digestHex;
    const b = verifyHash(result.input2).digestHex;
    return {
      a,
      b,
      ok: a === b,
    };
  }, [result, verifyHash]);

  async function runSingleAttack() {
    if (running || batchRunning) return;

    cancelRef.current = false;
    setRunning(true);
    setResult(null);
    setBatchSummary(null);
    setEvalCount(0);

    const args = {
      nBits,
      params,
      maxEvaluations,
      onProgress: setEvalCount,
      shouldCancel: () => cancelRef.current,
    };

    const out = variant === "floyd"
      ? await runFloydBirthdayAttack(args)
      : await runNaiveSortBirthdayAttack(args);

    setResult(out);
    setEvalCount(out.count || 0);

    if (out.found) {
      setHistory(prev => [...prev, { nBits, variant, found: true, count: out.count }]);
    }

    setRunning(false);
  }

  async function runTrialBatch() {
    if (running || batchRunning) return;

    const parsed = Number.parseInt(trialCount, 10);
    const numTrials = Number.isFinite(parsed) ? Math.min(Math.max(parsed, 1), 100) : 20;

    cancelRef.current = false;
    setBatchRunning(true);
    setBatchProgress(0);
    setBatchSummary(null);

    const summary = await runAttackTrials({
      variant,
      nBits,
      numTrials,
      params,
      maxEvaluations,
      shouldCancel: () => cancelRef.current,
      onTrialComplete: (trialIdx) => setBatchProgress(trialIdx),
    });

    setBatchSummary(summary);
    if (summary.counts.length) {
      setHistory(prev => [
        ...prev,
        ...summary.counts.map(c => ({ nBits, variant, found: true, count: c })),
      ]);
    }
    setBatchRunning(false);
  }

  function stopCurrentRun() {
    cancelRef.current = true;
  }

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>

      <div style={{ padding: "10px 16px", background: "#EAF3DE", borderBottom: "0.5px solid #8CB65A", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: "#3B6D11" }}>
          PA #9 - Birthday Attack (Collision Finding)
        </div>
        <div style={{ fontSize: 10, color: "#527C2A", fontFamily: "var(--font-mono)" }}>
          target: truncated PA #8 DLP hash
        </div>
      </div>

      <div style={{ padding: "16px" }}>

        <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", marginBottom: 14, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
          Implemented variants: naive sort-based and Floyd cycle detection. The chart overlays theory and empirical behavior.
          Formula: p(k) = 1 - exp(-k(k-1)/2^(n+1)) approx 1 - exp(-k^2/2^n).
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 16, marginBottom: 14 }}>

          <div>
            <FieldLabel>Output bit-length n (allowed set)</FieldLabel>
            <input
              type="range"
              min={8}
              max={16}
              step={2}
              value={nBits}
              disabled={running || batchRunning}
              onChange={(e) => {
                const value = Number(e.target.value);
                if (BIT_OPTIONS.includes(value)) {
                  setNBits(value);
                  setResult(null);
                  setEvalCount(0);
                }
              }}
              style={{ width: "100%" }}
            />
            <div style={{ display: "flex", justifyContent: "space-between", marginTop: 4, fontSize: 10, color: "var(--color-text-secondary)" }}>
              {BIT_OPTIONS.map(v => <span key={v}>{v}</span>)}
            </div>
          </div>

          <div>
            <FieldLabel>Algorithm variant</FieldLabel>
            <ToggleBar
              value={variant}
              onChange={(v) => {
                setVariant(v);
                setResult(null);
                setEvalCount(0);
              }}
              options={[
                { value: "naive-sort", label: "Naive sort", activeStyle: { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" } },
                { value: "floyd", label: "Floyd", activeStyle: { bg: "#EEEDFE", border: "#7F77DD", color: "#3C3489" } },
              ]}
            />
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14, flexWrap: "wrap" }}>
          <button
            onClick={runSingleAttack}
            disabled={running || batchRunning}
            style={{
              padding: "7px 14px",
              fontSize: 12,
              fontWeight: 500,
              border: "0.5px solid #639922",
              borderRadius: "var(--border-radius-md)",
              background: running || batchRunning ? "#D3D1C7" : "#EAF3DE",
              color: running || batchRunning ? "#888780" : "#3B6D11",
              cursor: running || batchRunning ? "default" : "pointer",
              fontFamily: "var(--font-sans)",
            }}
          >
            {running ? "Running..." : "Run attack"}
          </button>

          {(running || batchRunning) && (
            <button
              onClick={stopCurrentRun}
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

          <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--color-text-secondary)" }}>
            {evalCount} hash evaluations (live)
          </span>

          <span style={{ fontSize: 10, padding: "2px 8px", borderRadius: 4, background: complexity.color.bg, border: `0.5px solid ${complexity.color.border}`, color: complexity.color.text, fontWeight: 500 }}>
            {complexity.text}
          </span>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))", gap: 10, marginBottom: 14 }}>
          <StatCard label="n bits" value={nBits} />
          <StatCard label="expected 2^(n/2)" value={expected.toFixed(2)} accent="#854F0B" />
          <StatCard label="time complexity" value={complexity.time} />
          <StatCard label="space complexity" value={complexity.space} />
          <StatCard label="max evaluations" value={maxEvaluations} />
          <StatCard label="empirical avg" value={empiricalAverage ? empiricalAverage.toFixed(2) : "-"} accent="#0F6E56" />
        </div>

        <SectionHeading>Live chart - hashes computed vs collision probability</SectionHeading>
        <CurveChart
          nBits={nBits}
          expected={expected}
          currentCount={evalCount}
          empiricalCounts={scopedHistory}
          running={running}
          found={Boolean(result?.found)}
        />

        {result && (
          <div style={{ marginTop: 14, padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: result.found ? "#E1F5EE" : result.cancelled ? "#FAEEDA" : "#FCEBEB", border: `0.5px solid ${result.found ? "#1D9E75" : result.cancelled ? "#BA7517" : "#E24B4A"}`, color: result.found ? "#085041" : result.cancelled ? "#633806" : "#A32D2D", fontSize: 11 }}>
            {result.found ? (
              <>
                <div style={{ fontWeight: 500, marginBottom: 6 }}>
                  Collision found using {result.algorithm} after {result.count} evaluations.
                </div>
                <div style={{ fontFamily: "var(--font-mono)", marginBottom: 2 }}>input x  = {result.input1}</div>
                <div style={{ fontFamily: "var(--font-mono)", marginBottom: 2 }}>input x' = {result.input2}</div>
                <div style={{ fontFamily: "var(--font-mono)", marginBottom: 2 }}>shared H_n(x) = H_n(x') = 0x{result.digestHex}</div>
                <div style={{ fontFamily: "var(--font-mono)", marginBottom: verification ? 2 : 0 }}>ratio count / 2^(n/2) = {(result.ratio || (result.count / expected)).toFixed(3)}</div>
                {verification && (
                  <div style={{ fontFamily: "var(--font-mono)" }}>
                    verify: H_n(x)=0x{verification.a}, H_n(x')=0x{verification.b} {verification.ok ? "(match)" : "(mismatch)"}
                  </div>
                )}
                {result.algorithm === "floyd" && (
                  <div style={{ marginTop: 4, fontFamily: "var(--font-mono)", color: "#3C3489" }}>
                    floyd stats: mu={result.mu}, lambda={result.lambda}, restarts={result.restartsUsed || 0}
                  </div>
                )}
              </>
            ) : result.cancelled ? (
              `Run cancelled at ${result.count} evaluations.`
            ) : (
              `No collision found within ${result.count} evaluations. Try run again.`
            )}
          </div>
        )}

        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", marginTop: 16, paddingTop: 14 }}>
          <SectionHeading>Empirical curve builder (num_trials)</SectionHeading>
          <div style={{ display: "grid", gridTemplateColumns: "220px auto", gap: 10, alignItems: "end" }}>
            <div>
              <FieldLabel>Number of trials (1-100)</FieldLabel>
              <TextInput value={trialCount} onChange={setTrialCount} placeholder="20" />
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <button
                onClick={runTrialBatch}
                disabled={running || batchRunning}
                style={{
                  padding: "7px 14px",
                  fontSize: 12,
                  fontWeight: 500,
                  border: "0.5px solid #378ADD",
                  borderRadius: "var(--border-radius-md)",
                  background: running || batchRunning ? "#D3D1C7" : "#E6F1FB",
                  color: running || batchRunning ? "#888780" : "#185FA5",
                  cursor: running || batchRunning ? "default" : "pointer",
                  fontFamily: "var(--font-sans)",
                }}
              >
                {batchRunning ? "Running trials..." : "Run trials"}
              </button>

              {batchRunning && (
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)" }}>
                  completed: {batchProgress}
                </span>
              )}
            </div>
          </div>

          {batchSummary && (
            <div style={{ marginTop: 10, padding: "9px 12px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
              trials: {batchSummary.completedTrials}/{batchSummary.numTrials} | success rate: {(batchSummary.successRate * 100).toFixed(1)}%
              <br />
              average count: {batchSummary.averageCount ? batchSummary.averageCount.toFixed(2) : "-"} | median count: {batchSummary.medianCount || "-"}
              <br />
              target check for n=12: expected near 2^(12/2)=64.
            </div>
          )}
        </div>

        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", marginTop: 16, paddingTop: 14 }}>
          <SectionHeading>PA #8 hash source parameters</SectionHeading>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))", gap: 8, marginBottom: 8 }}>
            <StatCard label="p" value={params.p.toString()} />
            <StatCard label="q" value={params.q.toString()} />
            <StatCard label="g" value={params.g.toString()} />
            <StatCard label="h" value={params.h.toString()} />
          </div>
          <button
            onClick={() => setParams(createPA9Params())}
            disabled={running || batchRunning}
            style={{
              padding: "6px 12px",
              fontSize: 11,
              fontWeight: 500,
              border: "0.5px solid #639922",
              borderRadius: "var(--border-radius-md)",
              background: "#EAF3DE",
              color: "#3B6D11",
              cursor: running || batchRunning ? "default" : "pointer",
              fontFamily: "var(--font-sans)",
            }}
          >
            Regenerate h parameter
          </button>
        </div>
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", marginTop: 16, paddingTop: 14 }}>
          <SectionHeading>Real-World Context: Why Output Length Matters</SectionHeading>
          <div style={{ fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.6 }}>
            <p>At a standard CPU speed of 10<sup>9</sup> hashes/second:</p>
            <ul style={{ margin: "4px 0 0 20px" }}>
              <li><strong>MD5 (128-bit):</strong> Expected 2<sup>64</sup> hashes ≈ 584 years on a single CPU. (Easily broken with modern GPU clusters).</li>
              <li><strong>SHA-1 (160-bit):</strong> Expected 2<sup>80</sup> hashes ≈ 38 million years. (Broken by Google/CWI in 2017 using massive parallelization; deprecated).</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}

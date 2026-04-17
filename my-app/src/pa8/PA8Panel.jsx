// ═══════════════════════════════════════════════════════════════════════════════
// PA #8 — DLP-based Collision-Resistant Hash Function panel
// ═══════════════════════════════════════════════════════════════════════════════

import { useState, useMemo, useRef, useEffect } from "react";
import {
  setupGroup, dlpHash, makeDLPCompressFn, dlpCompress,
  modpow, DEMO_P, DEMO_Q, birthdayAttack,
} from "./crypto.js";
import { mdPad, parseBlocks, IV } from "../pa7/crypto.js";
import {
  FieldLabel, TextInput, SectionHeading, MonoBox, ToggleBar,
} from "../shared/ui.jsx";

// ── helpers ───────────────────────────────────────────────────────────────────

function Badge({ children, color = "blue" }) {
  const styles = {
    blue:   { background: "#E6F1FB", border: "0.5px solid #378ADD", color: "#0C447C" },
    green:  { background: "#E1F5EE", border: "0.5px solid #1D9E75", color: "#085041" },
    purple: { background: "#EEEDFE", border: "0.5px solid #7F77DD", color: "#3C3489" },
    amber:  { background: "#FAEEDA", border: "0.5px solid #BA7517", color: "#633806" },
    red:    { background: "#FCEBEB", border: "0.5px solid #E24B4A", color: "#A32D2D" },
  };
  return (
    <span style={{ fontSize: 10, padding: "2px 7px", borderRadius: 3, fontWeight: 500, fontFamily: "var(--font-mono)", ...styles[color] }}>
      {children}
    </span>
  );
}

function StatCard({ label, value, mono }) {
  return (
    <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
      <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>{label}</div>
      <div style={{ fontFamily: mono ? "var(--font-mono)" : "var(--font-sans)", fontSize: 14, fontWeight: 500, color: "var(--color-text-primary)", wordBreak: "break-all" }}>{value}</div>
    </div>
  );
}

// ── Group params display ──────────────────────────────────────────────────────

function GroupSetupPanel({ params, onRegen }) {
  return (
    <div style={{ padding: "12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 14 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10, flexWrap: "wrap", gap: 8 }}>
        <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: ".07em" }}>Group parameters (safe-prime subgroup of Z*_p)</div>
        <button
          onClick={onRegen}
          style={{ padding: "5px 12px", fontSize: 11, fontWeight: 500, border: "0.5px solid #7F77DD", borderRadius: "var(--border-radius-md)", background: "#EEEDFE", color: "#3C3489", cursor: "pointer", fontFamily: "var(--font-sans)" }}
        >
          Regen α
        </button>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(140px,1fr))", gap: 8 }}>
        {[
          { label: "p (safe prime)", value: params.p.toString() },
          { label: "q (group order)", value: params.q.toString() },
          { label: "g (generator)", value: params.g.toString() },
          { label: "ĥ = g^α mod p", value: params.h.toString() },
          { label: "α (discarded)", value: "hidden ✓" },
        ].map((s, i) => <StatCard key={i} label={s.label} value={s.value} mono />)}
      </div>
      <div style={{ marginTop: 8, fontSize: 11, color: "var(--color-text-secondary)", fontStyle: "italic" }}>
        α is generated then discarded. The adversary only sees p, q, g, ĥ — computing log_g(ĥ) = α requires solving DLP.
      </div>
    </div>
  );
}

// ── DLP_Hash live demo ────────────────────────────────────────────────────────

function HashLiveDemo({ params }) {
  const [msg, setMsg] = useState("Hello World!");

  const digest = useMemo(() => dlpHash(msg, params), [msg, params]);

  const TEST_MSGS = ["Hello World!", "hello world!", "Hello World!!", "CS8.401", "Merkle-Damgård"];

  return (
    <div>
      <div style={{ marginBottom: 10 }}>
        <FieldLabel>Message</FieldLabel>
        <TextInput value={msg} onChange={setMsg} placeholder="Type any message…" />
      </div>
      <div style={{ padding: "10px 14px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", marginBottom: 14 }}>
        <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: ".07em", marginBottom: 6 }}>DLP_Hash(message) → group element (hex)</div>
        <div style={{ fontFamily: "var(--font-mono)", fontSize: 18, fontWeight: 500, color: "#3C3489", wordBreak: "break-all" }}>0x{digest}</div>
      </div>

      <SectionHeading>Integration test — 5 distinct messages → distinct digests</SectionHeading>
      <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", overflow: "hidden" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", background: "var(--color-background-secondary)", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
          {["Message", "DLP_Hash(M)"].map((h, i) => (
            <div key={i} style={{ padding: "6px 10px", fontSize: 10, fontWeight: 500, color: "var(--color-text-secondary)", textTransform: "uppercase" }}>{h}</div>
          ))}
        </div>
        {TEST_MSGS.map((m, i) => {
          const d = dlpHash(m, params);
          return (
            <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr 1fr", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
              <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)" }}>{m}</div>
              <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: 11, color: "#3C3489" }}>0x{d}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── DLP compression function explorer ────────────────────────────────────────

function CompressionExplorer({ params }) {
  const [x, setX] = useState("12345");
  const [y, setY] = useState("67890");

  const result = useMemo(() => {
    try {
      const xn = BigInt(x) % params.q;
      const yn = BigInt(y) % params.q;
      const full = dlpCompress(xn, yn, params.g, params.h, params.p);
      const simple = modpow(params.g, (xn + yn) % params.q, params.p);
      return { full: full.toString(16).padStart(8, "0"), simple: simple.toString(16).padStart(8, "0"), xn: xn.toString(), yn: yn.toString(), ok: true };
    } catch {
      return { ok: false };
    }
  }, [x, y, params]);

  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
        <div><FieldLabel>x (chaining value, Z_q)</FieldLabel><TextInput value={x} onChange={v => setX(v.replace(/\D/g,""))} placeholder="integer" /></div>
        <div><FieldLabel>y (block integer, Z_q)</FieldLabel><TextInput value={y} onChange={v => setY(v.replace(/\D/g,""))} placeholder="integer" /></div>
      </div>
      {result.ok && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          <div style={{ padding: "10px 12px", background: "#EEEDFE", border: "0.5px solid #AFA9EC", borderRadius: "var(--border-radius-md)" }}>
            <div style={{ fontSize: 10, color: "#534AB7", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 4 }}>Full: g^x · ĥ^y mod p</div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, fontWeight: 500, color: "#3C3489" }}>0x{result.full}</div>
            <div style={{ fontSize: 10, color: "#534AB7", marginTop: 4 }}>x mod q = {result.xn}, y mod q = {result.yn}</div>
          </div>
          <div style={{ padding: "10px 12px", background: "#E6F1FB", border: "0.5px solid #B5D4F4", borderRadius: "var(--border-radius-md)" }}>
            <div style={{ fontSize: 10, color: "#185FA5", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 4 }}>Simplified: g^(x+y) mod p</div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, fontWeight: 500, color: "#185FA5" }}>0x{result.simple}</div>
            <div style={{ fontSize: 10, color: "#185FA5", marginTop: 4 }}>ĥ = g (simplest case)</div>
          </div>
        </div>
      )}
      <div style={{ marginTop: 10, padding: "8px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
        Collision resistance: finding (x,y) ≠ (x′,y′) with equal outputs requires computing log_g(ĥ) mod q — the DLP. Any collision gives g^(x−x′) = ĥ^(y′−y), so log_g(ĥ) = (x−x′)/(y′−y) mod q.
      </div>
    </div>
  );
}

// ── Birthday attack demo ──────────────────────────────────────────────────────

// function BirthdayDemo({ params }) {
//   const [running,  setRunning]  = useState(false);
//   const [count,    setCount]    = useState(0);
//   const [result,   setResult]   = useState(null);
//   const cancelRef = useRef(false);
//   const TARGET = 256; // 2^(n/2) for n=16

//   function runAttack() {
//     setRunning(true);
//     setResult(null);
//     setCount(0);
//     cancelRef.current = false;

//     // Run in chunks to keep UI responsive
//     const bridge = makeDLPCompressFn(params);
//     const seen   = new Map();
//     let   i      = 0;
//     const MAX    = 4000;

//     function step() {
//       if (cancelRef.current) { setRunning(false); return; }
//       const CHUNK = 40;
//       for (let c = 0; c < CHUNK && i < MAX; c++, i++) {
//         const input = Array.from({ length: 8 }, () => Math.floor(Math.random() * 256));
//         const padded = mdPad(input);
//         const blocks = parseBlocks(padded);
//         let z = IV;
//         for (const b of blocks) z = bridge(z, b);
//         const d16 = parseInt(z.slice(-4), 16) & 0xFFFF;
//         const hex  = input.map(b => b.toString(16).padStart(2,"0")).join("");

//         if (seen.has(d16)) {
//           const prev = seen.get(d16);
//           if (prev !== hex) {
//             setCount(i + 1);
//             setResult({ found: true, count: i + 1, input1: prev, input2: hex, digest: d16.toString(16).padStart(4, "0") });
//             setRunning(false);
//             return;
//           }
//         }
//         seen.set(d16, hex);
//       }
//       setCount(i);
//       if (i < MAX) setTimeout(step, 0);
//       else { setResult({ found: false, count: MAX }); setRunning(false); }
//     }
//     setTimeout(step, 0);
//   }

function BirthdayDemo({ params }) {
  const [running,  setRunning]  = useState(false);
  const [count,    setCount]    = useState(0);
  const [result,   setResult]   = useState(null);
  const cancelRef = useRef(false);
  const TARGET = 256; // 2^(n/2) for n=16
 
  function runAttack() {
    setRunning(true);
    setResult(null);
    setCount(0);
    cancelRef.current = false;
 
    // Run in chunks to keep UI responsive
    const bridge = makeDLPCompressFn(params);
    const seen   = new Map();
    let   i      = 0;
    const MAX    = 4000;
 
    function step() {
      if (cancelRef.current) { setRunning(false); return; }
      const CHUNK = 40;
      for (let c = 0; c < CHUNK && i < MAX; c++, i++) {
        const input = Array.from({ length: 8 }, () => Math.floor(Math.random() * 256));
        const padded = mdPad(input);
        const blocks = parseBlocks(padded);
        let z = IV;
        for (const b of blocks) z = bridge(z, b);
        const d16 = parseInt(z.slice(-4), 16) & 0xFFFF;
        const hex  = input.map(b => b.toString(16).padStart(2,"0")).join("");
 
        if (seen.has(d16)) {
          const prev = seen.get(d16);
          if (prev !== hex) {
            console.log("=== Collision found! ===");
            console.log("Input A (hex):", prev);
            console.log("Input B (hex):", hex);
            console.log("Shared 16-bit digest:", d16.toString(16).padStart(4, "0"));
            console.log("Found after", i + 1, "hashes");
            setCount(i + 1);
            setResult({ found: true, count: i + 1, input1: prev, input2: hex, digest: d16.toString(16).padStart(4, "0") });
            setRunning(false);
            return;
          }
        }
        seen.set(d16, hex);
      }
      setCount(i);
      if (i < MAX) setTimeout(step, 0);
      else { setResult({ found: false, count: MAX }); setRunning(false); }
    }
    setTimeout(step, 0);
  }
  
  const progress = Math.min(count / TARGET * 100, 100);
  const barColor = result?.found ? "#1D9E75" : running ? "#378ADD" : "#D3D1C7";

  return (
    <div>
      <div style={{ fontSize: 11, color: "var(--color-text-secondary)", marginBottom: 10, lineHeight: 1.7 }}>
        Birthday attack on 16-bit truncated DLP hash. Expected collisions after O(2^(16/2)) = O(256) evaluations. Progress bar tracks hashes evaluated vs. the 2^(n/2) = 256 milestone.
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10, flexWrap: "wrap" }}>
        <button
          onClick={runAttack}
          disabled={running}
          style={{ padding: "7px 14px", fontSize: 12, fontWeight: 500, border: "0.5px solid #7F77DD", borderRadius: "var(--border-radius-md)", background: running ? "#D3D1C7" : "#EEEDFE", color: running ? "#888780" : "#3C3489", cursor: running ? "default" : "pointer", fontFamily: "var(--font-sans)" }}
        >
          {running ? "Searching…" : "Collision hunt"}
        </button>
        {running && (
          <button
            onClick={() => cancelRef.current = true}
            style={{ padding: "7px 14px", fontSize: 12, border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", color: "var(--color-text-secondary)", cursor: "pointer", fontFamily: "var(--font-sans)" }}
          >
            Stop
          </button>
        )}
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--color-text-secondary)" }}>{count} hashes evaluated</span>
      </div>

      {/* Progress bar */}
      <div style={{ marginBottom: 10 }}>
        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--color-text-secondary)", marginBottom: 3 }}>
          <span>0</span>
          <span>2^(n/2) = {TARGET} (birthday bound)</span>
          <span>2·{TARGET}</span>
        </div>
        <div style={{ height: 8, borderRadius: 4, background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-tertiary)", overflow: "hidden" }}>
          <div style={{ height: "100%", width: `${progress}%`, background: barColor, transition: "width 0.1s" }} />
        </div>
      </div>

      {result && (
        <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: result.found ? "#E1F5EE" : "#FAEEDA", border: `0.5px solid ${result.found ? "#1D9E75" : "#BA7517"}`, fontSize: 11, color: result.found ? "#085041" : "#633806" }}>
          {result.found ? (
            <>
              <div style={{ fontWeight: 500, marginBottom: 6 }}>Collision found after {result.count} hashes ✓ (O(√q) confirmed)</div>
              <div style={{ fontFamily: "var(--font-mono)", marginBottom: 2 }}>Input A: 0x{result.input1}</div>
              <div style={{ fontFamily: "var(--font-mono)", marginBottom: 2 }}>Input B: 0x{result.input2}</div>
              <div style={{ fontFamily: "var(--font-mono)" }}>Shared 16-bit digest: 0x{result.digest}</div>
            </>
          ) : (
            `Searched ${result.count} hashes — no collision found (try again; probabilistic).`
          )}
        </div>
      )}
    </div>
  );
}

// ── Main PA8 panel ────────────────────────────────────────────────────────────

export default function PA8Panel() {
  const [params, setParams] = useState(() => setupGroup(DEMO_P, DEMO_Q));
  const [tab,    setTab]    = useState("hash");

  const TABS = [
    { value: "hash",     label: "DLP_Hash live" },
    { value: "compress", label: "Compression fn" },
    { value: "birthday", label: "Birthday attack" },
  ];

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>

      {/* Header */}
      <div style={{ padding: "10px 16px", background: "#E1F5EE", borderBottom: "0.5px solid #5DCAA5", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: "#085041" }}>PA #8 — DLP-based Collision-Resistant Hash Function</div>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {TABS.map(t => (
            <button
              key={t.value}
              onClick={() => setTab(t.value)}
              style={{ padding: "5px 12px", fontSize: 11, fontWeight: 500, border: `0.5px solid ${tab === t.value ? "#1D9E75" : "var(--color-border-secondary)"}`, borderRadius: "var(--border-radius-md)", background: tab === t.value ? "#E1F5EE" : "var(--color-background-secondary)", color: tab === t.value ? "#085041" : "var(--color-text-secondary)", cursor: "pointer", fontFamily: "var(--font-sans)" }}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      <div style={{ padding: "16px" }}>

        {/* Group setup — always visible */}
        <GroupSetupPanel params={params} onRegen={() => setParams(setupGroup(DEMO_P, DEMO_Q))} />

        {/* Pipeline diagram */}
        <div style={{ padding: "8px 14px", marginBottom: 16, background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", fontSize: 11, color: "var(--color-text-secondary)", display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <span style={{ padding: "3px 8px", borderRadius: 3, background: "#E6F1FB", border: "0.5px solid #378ADD", color: "#0C447C", fontSize: 10 }}>Message M</span>
          <span>→</span>
          <span style={{ padding: "3px 8px", borderRadius: 3, background: "#EEEDFE", border: "0.5px solid #7F77DD", color: "#3C3489", fontSize: 10 }}>Merkle-Damgård (PA#7)</span>
          <span style={{ fontSize: 10, color: "var(--color-text-secondary)", fontStyle: "italic" }}>block-by-block</span>
          <span>→</span>
          <span style={{ padding: "3px 8px", borderRadius: 3, background: "#E1F5EE", border: "0.5px solid #1D9E75", color: "#085041", fontSize: 10 }}>h(x,y) = g^x · ĥ^y mod p</span>
          <span>→</span>
          <span style={{ padding: "3px 8px", borderRadius: 3, background: "#FAEEDA", border: "0.5px solid #BA7517", color: "#633806", fontSize: 10 }}>Hash digest ∈ G</span>
        </div>

        {/* Tab content */}
        {tab === "hash"     && <HashLiveDemo      params={params} />}
        {tab === "compress" && <CompressionExplorer params={params} />}
        {tab === "birthday" && <BirthdayDemo        params={params} />}

      </div>
    </div>
  );
}
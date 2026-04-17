// ═══════════════════════════════════════════════════════════════════════════════
// PA #7 — Merkle-Damgård chain viewer
// ═══════════════════════════════════════════════════════════════════════════════

import { useState, useMemo } from "react";
import {
  mdPad, parseBlocks, buildChain, bytesToHex, strToBytes,
} from "./crypto.js";
import {
  FieldLabel, TextInput, SectionHeading, MonoBox,
} from "../shared/ui.jsx";

// ── Block row ────────────────────────────────────────────────────────────────

function BlockBox({ hexStr, label, sub, type, highlight, dim }) {
  const bdr = type === "pad" ? "#BA7517" : highlight ? "#7F77DD" : "#B5D4F4";
  const bg  = type === "pad" ? "#FAEEDA" : highlight ? "#EEEDFE" : "#E6F1FB";
  const tc  = type === "pad" ? "#633806" : highlight ? "#3C3489" : "#0C447C";
  return (
    <div style={{ opacity: dim ? 0.45 : 1, minWidth: 84, border: `0.5px solid ${bdr}`, borderRadius: "var(--border-radius-md)", background: bg, padding: "6px 8px", textAlign: "center" }}>
      <div style={{ fontSize: 10, fontWeight: 500, color: tc, letterSpacing: ".05em" }}>{label}</div>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: tc, marginTop: 2, wordBreak: "break-all" }}>
        {hexStr.match(/.{1,2}/g).join(" ")}
      </div>
      <div style={{ fontSize: 9, color: tc, marginTop: 2, opacity: 0.7 }}>{sub}</div>
    </div>
  );
}

// ── Chain node ───────────────────────────────────────────────────────────────

function ChainNode({ zHex, label, isLeaf, changed }) {
  const bg  = isLeaf ? (changed ? "#FCEBEB" : "#E1F5EE") : (changed ? "#FCEBEB" : "#E6F1FB");
  const bdr = isLeaf ? (changed ? "#E24B4A" : "#1D9E75") : (changed ? "#E24B4A" : "#378ADD");
  const tc  = isLeaf ? (changed ? "#A32D2D" : "#085041") : (changed ? "#A32D2D" : "#0C447C");
  return (
    <div style={{ display: "inline-flex", flexDirection: "column", alignItems: "center" }}>
      <div style={{ border: `0.5px solid ${bdr}`, borderRadius: isLeaf ? "var(--border-radius-md)" : 50, background: bg, padding: "5px 10px", textAlign: "center", minWidth: 90 }}>
        <div style={{ fontSize: 9, color: tc, fontWeight: 500 }}>{label}</div>
        <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: tc, fontWeight: 500 }}>0x{zHex}</div>
      </div>
    </div>
  );
}

function Arrow({ label }) {
  return (
    <div style={{ display: "inline-flex", alignItems: "center", padding: "0 3px" }}>
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 1 }}>
        <span style={{ fontSize: 9, color: "var(--color-text-secondary)" }}>{label}</span>
        <span style={{ color: "var(--color-text-secondary)", fontSize: 14 }}>→</span>
      </div>
    </div>
  );
}

// ── Chain row ─────────────────────────────────────────────────────────────────

function ChainRow({ chain, editIdx, isEdit }) {
  return (
    <div style={{ overflowX: "auto", paddingBottom: 4 }}>
      <div style={{ display: "inline-flex", alignItems: "center", flexWrap: "nowrap" }}>
        <ChainNode zHex={chain[0]} label="IV = z₀" isLeaf={false} changed={false} />
        {chain.slice(1).map((z, i) => {
          const changed = isEdit && i >= editIdx;
          const isLeaf  = i === chain.length - 2;
          return (
            <span key={i} style={{ display: "inline-flex", alignItems: "center" }}>
              <Arrow label={`h(z${i},M${i + 1})`} />
              <ChainNode
                zHex={z}
                label={isLeaf ? (isEdit ? "H(M)′" : "H(M)") : `z${i + 1}${isEdit && i >= editIdx ? "′" : ""}`}
                isLeaf={isLeaf}
                changed={changed}
              />
            </span>
          );
        })}
      </div>
    </div>
  );
}

// ── Avalanche panel ───────────────────────────────────────────────────────────

function AvalanchePanel({ origBlocks, editBlocks, editIdx }) {
  const origChain = useMemo(() => buildChain(origBlocks), [origBlocks]);
  const editChain = useMemo(() => buildChain(editBlocks),  [editBlocks]);

  const origH = origChain[origChain.length - 1];
  const newH  = editChain[editChain.length - 1];
  const b1 = parseInt(origH, 16).toString(2).padStart(32, "0");
  const b2 = parseInt(newH,  16).toString(2).padStart(32, "0");
  const flipped = b1.split("").filter((c, i) => c !== b2[i]).length;
  const changed = origH !== newH;

  return (
    <div>
      <ChainRow chain={editChain} editIdx={editIdx} isEdit={true} />
      <div style={{ marginTop: 8, padding: "8px 12px", borderRadius: "var(--border-radius-md)", background: changed ? "#FCEBEB" : "#E1F5EE", border: `0.5px solid ${changed ? "#E24B4A" : "#1D9E75"}`, fontSize: 11, color: changed ? "#A32D2D" : "#085041" }}>
        Original H(M) = <span style={{ fontFamily: "var(--font-mono)" }}>0x{origH}</span>
        {"  →  "}
        New H(M)′ = <span style={{ fontFamily: "var(--font-mono)" }}>0x{newH}</span>
        {"  |  "}
        {flipped}/32 output bits flipped {
          !changed ? "— no change yet" : 
          (flipped >= 12 ? "— true avalanche confirmed ✓" : "— weak change (linear toy function) ✓")
        }
      </div>
    </div>
  );
}

// ── Collision demo ────────────────────────────────────────────────────────────

// function CollisionDemo({ rawInput }) {
//   const { chainA, chainB, origH, altH, colIdx, colZ } = useMemo(() => {
//     const bytes = strToBytes(rawInput);
//     if (!bytes.length) return { chainA: [], chainB: [], origH: "", altH: "", colIdx: -1, colZ: "" };

//     const altBytes = [...bytes];
//     altBytes[0] ^= 0xFF;

//     const blocksA = parseBlocks(mdPad(bytes));
//     const blocksB = parseBlocks(mdPad(altBytes));
//     const chainA  = buildChain(blocksA);
//     const chainB  = buildChain(blocksB);

//     let colIdx = -1, colZ = "";
//     for (let i = 0; i < Math.min(chainA.length, chainB.length); i++) {
//       if (chainA[i] === chainB[i]) { colIdx = i; colZ = chainA[i]; break; }
//     }
//     return { chainA, chainB, origH: chainA[chainA.length - 1], altH: chainB[chainB.length - 1], colIdx, colZ };
//   }, [rawInput]);

//   if (!chainA.length) return null;

//   return (
//     <div>
//       <div style={{ fontSize: 11, color: "var(--color-text-secondary)", marginBottom: 8, lineHeight: 1.7 }}>
//         Message A: <span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-primary)" }}>{rawInput.slice(0, 32)}</span>
//         {" → H(A) = "}<span style={{ fontFamily: "var(--font-mono)", color: "#3C3489" }}>0x{origH}</span>
//         <br />
//         Message B: <span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-primary)" }}>(flip first byte)</span>
//         {" → H(B) = "}<span style={{ fontFamily: "var(--font-mono)", color: "#3C3489" }}>0x{altH}</span>
//       </div>
//       {colIdx >= 0
//         ? <div style={{ padding: "8px 12px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A", fontSize: 11, color: "#A32D2D" }}>
//             Compression collision at z{colIdx} = <span style={{ fontFamily: "var(--font-mono)" }}>0x{colZ}</span> — both chains share this chaining value; any appended suffix produces a full MD collision.
//           </div>
//         : <div style={{ padding: "8px 12px", borderRadius: "var(--border-radius-md)", background: "#E1F5EE", border: "0.5px solid #1D9E75", fontSize: 11, color: "#085041" }}>
//             No intermediate collision found. A collision in any z_i would propagate through the remaining chain to H(M).
//           </div>
//       }
//     </div>
//   );
// }

// ── Collision demo ────────────────────────────────────────────────────────────

function CollisionDemo({ rawInput }) {
  // 1. Added a state so you can manually enter Message B
  const [msgB, setMsgB] = useState("0xFFFFFFFFFFFFFFFF");

  const { chainA, chainB, origH, altH, colIdx, colZ } = useMemo(() => {
    const bytesA = strToBytes(rawInput);
    const bytesB = strToBytes(msgB); // Use the new input instead of auto-flipping
    
    if (!bytesA.length || !bytesB.length) return { chainA: [], chainB: [], origH: "", altH: "", colIdx: -1, colZ: "" };

    const blocksA = parseBlocks(mdPad(bytesA));
    const blocksB = parseBlocks(mdPad(bytesB));
    const chainA  = buildChain(blocksA);
    const chainB  = buildChain(blocksB);

    let colIdx = -1, colZ = "";
    
    // 2. Start at i = 1 to skip the IV (z0)
    for (let i = 1; i < Math.min(chainA.length, chainB.length); i++) {
      
      // 3. Ensure chaining values match AND the blocks that created them were different
      const blockAStr = bytesToHex(blocksA[i - 1] || []);
      const blockBStr = bytesToHex(blocksB[i - 1] || []);
      
      if (chainA[i] === chainB[i] && blockAStr !== blockBStr) { 
        colIdx = i; 
        colZ = chainA[i]; 
        break; 
      }
    }
    return { chainA, chainB, origH: chainA[chainA.length - 1], altH: chainB[chainB.length - 1], colIdx, colZ };
  }, [rawInput, msgB]);

  if (!chainA.length) return null;

  return (
    <div>
      {/* Added an input field for Message B */}
      <div style={{ marginBottom: 12 }}>
        <FieldLabel>Message B (for collision testing)</FieldLabel>
        <TextInput value={msgB} onChange={setMsgB} placeholder="Type Message B..." />
      </div>

      <div style={{ fontSize: 11, color: "var(--color-text-secondary)", marginBottom: 8, lineHeight: 1.7 }}>
        Message A: <span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-primary)" }}>{rawInput.slice(0, 32)}</span>
        {" → H(A) = "}<span style={{ fontFamily: "var(--font-mono)", color: "#3C3489" }}>0x{origH}</span>
        <br />
        Message B: <span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-primary)" }}>{msgB.slice(0, 32)}</span>
        {" → H(B) = "}<span style={{ fontFamily: "var(--font-mono)", color: "#3C3489" }}>0x{altH}</span>
      </div>
      
      {colIdx >= 0
        ? <div style={{ padding: "8px 12px", borderRadius: "var(--border-radius-md)", background: "#FCEBEB", border: "0.5px solid #E24B4A", fontSize: 11, color: "#A32D2D" }}>
            Compression collision at z{colIdx} = <span style={{ fontFamily: "var(--font-mono)" }}>0x{colZ}</span> — both chains share this chaining value; any appended suffix produces a full MD collision.
          </div>
        : <div style={{ padding: "8px 12px", borderRadius: "var(--border-radius-md)", background: "#E1F5EE", border: "0.5px solid #1D9E75", fontSize: 11, color: "#085041" }}>
            No intermediate collision found. A collision in any z_i would propagate through the remaining chain to H(M).
          </div>
      }
    </div>
  );
}

// ── Main PA7 panel ────────────────────────────────────────────────────────────

export default function PA7Panel() {
  const [msgInput,  setMsgInput]  = useState("Hello World!");
  const [editIdx,   setEditIdx]   = useState(0);
  const [editHex,   setEditHex]   = useState("");
  const [showEdit,  setShowEdit]  = useState(false);

  const bytes   = useMemo(() => strToBytes(msgInput), [msgInput]);
  const padded  = useMemo(() => mdPad(bytes),          [bytes]);
  const blocks  = useMemo(() => parseBlocks(padded),   [padded]);
  const chain   = useMemo(() => buildChain(blocks),    [blocks]);

  function blockMeta(i) {
    if (i < blocks.length - 1) {
      const chunk = bytes.slice(i * 8, i * 8 + 8);
      const disp  = chunk.map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : "·").join("");
      return { label: `M${i + 1}`, sub: disp, type: "msg" };
    }
    return { label: `M${i + 1}`, sub: "pad", type: "pad" };
  }

  function startEdit(i) {
    setEditIdx(i);
    setEditHex(bytesToHex(blocks[i]));
    setShowEdit(true);
  }

  const editBlocks = useMemo(() => {
    if (!showEdit) return blocks;
    const copy = blocks.map(b => [...b]);
    const h = (editHex.replace(/[^0-9a-fA-F]/g, "").padEnd(16, "0")).slice(0, 16);
    copy[editIdx] = Array.from({ length: 8 }, (_, j) => parseInt(h.slice(j * 2, j * 2 + 2), 16));
    return copy;
  }, [blocks, showEdit, editIdx, editHex]);

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>

      {/* Header */}
      <div style={{ padding: "10px 16px", background: "#EEEDFE", borderBottom: "0.5px solid #AFA9EC", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: "#3C3489" }}>PA #7 — Merkle-Damgård chain viewer</div>
        <span style={{ fontSize: 10, color: "#534AB7" }}>Block size: 8 bytes · IV = 0x00000000</span>
      </div>

      <div style={{ padding: "16px" }}>

        {/* Input + stats */}
        <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) auto", gap: 16, marginBottom: 16, alignItems: "end" }}>
          <div>
            <FieldLabel>Message (text, or hex with 0x prefix)</FieldLabel>
            <TextInput value={msgInput} onChange={setMsgInput} placeholder="Type any message…" />
          </div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", paddingBottom: 2 }}>
            {[
              { label: `${bytes.length}B input`,   style: { background: "#E6F1FB", border: "0.5px solid #378ADD", color: "#0C447C" } },
              { label: `${padded.length}B padded`, style: { background: "#FAEEDA", border: "0.5px solid #BA7517", color: "#633806" } },
              { label: `${blocks.length} blocks`,  style: { background: "#E6F1FB", border: "0.5px solid #378ADD", color: "#0C447C" } },
              { label: `H(M)=0x${chain[chain.length-1]}`, style: { background: "#E1F5EE", border: "0.5px solid #1D9E75", color: "#085041", fontFamily: "var(--font-mono)" } },
            ].map((b, i) => (
              <span key={i} style={{ fontSize: 10, padding: "2px 7px", borderRadius: 3, fontWeight: 500, ...b.style }}>{b.label}</span>
            ))}
          </div>
        </div>

        {/* Block row */}
        <SectionHeading>MD-strengthening padding — padded blocks</SectionHeading>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 16 }}>
          {blocks.map((b, i) => {
            const meta = blockMeta(i);
            return (
              <span key={i} style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                <BlockBox hexStr={bytesToHex(b)} {...meta} highlight={showEdit && i === editIdx} dim={false} />
                {i < blocks.length - 1 && <span style={{ color: "var(--color-text-secondary)", fontSize: 14 }}>→</span>}
              </span>
            );
          })}
        </div>

        {/* Chain */}
        <SectionHeading>Merkle-Damgård chain — z₀ → h(z₀,M₁) → … → H(M)</SectionHeading>
        <div style={{ marginBottom: 16 }}>
          <ChainRow chain={chain} editIdx={-1} isEdit={false} />
        </div>

        {/* Edit / avalanche */}
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: 14, marginBottom: 16 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10, flexWrap: "wrap", gap: 8 }}>
            <SectionHeading>Edit a block — avalanche effect demo</SectionHeading>
            <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
              <span style={{ fontSize: 11, color: "var(--color-text-secondary)" }}>Edit block:</span>
              <select
                value={editIdx}
                onChange={e => startEdit(Number(e.target.value))}
                style={{ fontSize: 12, padding: "4px 8px", borderRadius: "var(--border-radius-md)", border: "0.5px solid var(--color-border-secondary)", background: "var(--color-background-primary)", color: "var(--color-text-primary)", fontFamily: "var(--font-sans)" }}
              >
                {blocks.map((_, i) => <option key={i} value={i}>M{i + 1}</option>)}
              </select>
              <button
                onClick={() => startEdit(editIdx)}
                style={{ padding: "5px 12px", fontSize: 11, fontWeight: 500, border: "0.5px solid #7F77DD", borderRadius: "var(--border-radius-md)", background: "#EEEDFE", color: "#3C3489", cursor: "pointer", fontFamily: "var(--font-sans)" }}
              >
                Select
              </button>
              {showEdit && (
                <button
                  onClick={() => { setShowEdit(false); }}
                  style={{ padding: "5px 12px", fontSize: 11, border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", color: "var(--color-text-secondary)", cursor: "pointer", fontFamily: "var(--font-sans)" }}
                >
                  Reset
                </button>
              )}
            </div>
          </div>

          {showEdit ? (
            <div>
              <div style={{ marginBottom: 10 }}>
                <FieldLabel>Block M{editIdx + 1} hex (8 bytes = 16 hex chars)</FieldLabel>
                <TextInput
                  value={editHex}
                  onChange={v => setEditHex(v.replace(/[^0-9a-fA-F]/g, "").slice(0, 16))}
                  placeholder="16 hex chars"
                />
              </div>
              <AvalanchePanel origBlocks={blocks} editBlocks={editBlocks} editIdx={editIdx} />
            </div>
          ) : (
            <div style={{ fontSize: 11, color: "var(--color-text-secondary)", fontStyle: "italic" }}>
              Select a block above to edit its hex and observe how the chain re-computes from that point onwards.
            </div>
          )}
        </div>

        {/* Collision demo */}
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: 14 }}>
          <SectionHeading>Collision propagation demo</SectionHeading>
          <CollisionDemo rawInput={msgInput} />
        </div>

      </div>
    </div>
  );
}
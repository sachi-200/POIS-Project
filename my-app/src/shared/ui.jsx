// ═══════════════════════════════════════════════════════════════════════════════
// Shared UI components — used by all PA panels
// ═══════════════════════════════════════════════════════════════════════════════

export function Tag({ label, colorMap }) {
  const c = colorMap[label] || { bg: "var(--color-background-secondary)", border: "var(--color-border-secondary)", color: "var(--color-text-secondary)" };
  return <span style={{ fontSize: 10, padding: "3px 8px", borderRadius: 4, whiteSpace: "nowrap", fontWeight: 500, fontFamily: "var(--font-mono)", flexShrink: 0, background: c.bg, border: `0.5px solid ${c.border}`, color: c.color }}>{label}</span>;
}

export function StepRow({ tag, fn, inputHex, outputHex, pa, implemented, tagColorMap }) {
  return (
    <div style={{ display: "flex", alignItems: "flex-start", gap: 10, padding: "9px 0", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
      <Tag label={tag} colorMap={tagColorMap} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 11, color: "var(--color-text-secondary)", marginBottom: 4, fontFamily: "var(--font-mono)" }}>{fn}</div>
        {inputHex && (
          <div style={{ display: "flex", alignItems: "baseline", gap: 6, marginBottom: 3 }}>
            <span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 28, flexShrink: 0 }}>in:</span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-text-secondary)", wordBreak: "break-all" }}>{inputHex === "key" ? "<user key input>" : `0x${inputHex}`}</span>
          </div>
        )}
        <div style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
          <span style={{ fontSize: 10, color: "var(--color-text-secondary)", minWidth: 28, flexShrink: 0 }}>out:</span>
          {!implemented
            ? <span style={{ fontSize: 11, color: "var(--color-text-secondary)", fontStyle: "italic" }}>Not implemented yet (due: {pa || "PA#?"})</span>
            : <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--color-text-primary)", wordBreak: "break-all" }}>0x{outputHex}</span>
          }
        </div>
      </div>
    </div>
  );
}

export function ColCard({ headerLabel, headerStyle, children }) {
  return (
    <div style={{ background: "var(--color-background-primary)", border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden", display: "flex", flexDirection: "column" }}>
      <div style={{ padding: "10px 16px", fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", ...headerStyle }}>{headerLabel}</div>
      <div style={{ padding: "16px", flex: 1 }}>{children}</div>
    </div>
  );
}

export function FieldLabel({ children }) {
  return <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.07em", fontWeight: 500, marginBottom: 5 }}>{children}</div>;
}

export function StyledSelect({ value, onChange, options, exclude }) {
  return (
    <select value={value} onChange={e => onChange(e.target.value)} style={{ width: "100%", padding: "8px 12px", fontSize: 13, border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", background: "var(--color-background-primary)", color: "var(--color-text-primary)", fontFamily: "var(--font-mono)", outline: "none" }}>
      {options.filter(o => o !== exclude).map(o => <option key={o} value={o}>{o}</option>)}
    </select>
  );
}

export function TextInput({ value, onChange, placeholder }) {
  return <input type="text" value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} style={{ width: "100%", padding: "8px 12px", fontSize: 13, border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", background: "var(--color-background-primary)", color: "var(--color-text-primary)", fontFamily: "var(--font-mono)", outline: "none" }} />;
}

export function ToggleBar({ value, onChange, options }) {
  return (
    <div style={{ display: "flex", gap: 4, background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", padding: 3 }}>
      {options.map(opt => {
        const active = value === opt.value, ac = opt.activeStyle || {};
        return <button key={opt.value} onClick={() => onChange(opt.value)} style={{ flex: 1, padding: "7px 14px", fontSize: 12, fontWeight: active ? 500 : 400, border: active ? `0.5px solid ${ac.border || "var(--color-border-info)"}` : "0.5px solid transparent", borderRadius: "var(--border-radius-md)", background: active ? (ac.bg || "var(--color-background-info)") : "transparent", color: active ? (ac.color || "var(--color-text-info)") : "var(--color-text-secondary)", cursor: "pointer", transition: "all 0.15s", fontFamily: "var(--font-sans)" }}>{opt.label}</button>;
      })}
    </div>
  );
}

export function SectionHeading({ children }) {
  return <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.07em", fontWeight: 500, marginBottom: 8, marginTop: 4 }}>{children}</div>;
}

export function WarnBox({ children }) {
  return <div style={{ padding: "10px 14px", fontSize: 12, borderRadius: "var(--border-radius-md)", background: "#FAEEDA", color: "#854F0B", border: "0.5px solid #BA7517" }}>{children}</div>;
}

export function Divider({ label }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 12, margin: "28px 0 20px" }}>
      <div style={{ flex: 1, height: "0.5px", background: "var(--color-border-tertiary)" }} />
      <span style={{ fontSize: 11, color: "var(--color-text-secondary)", fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", whiteSpace: "nowrap" }}>{label}</span>
      <div style={{ flex: 1, height: "0.5px", background: "var(--color-border-tertiary)" }} />
    </div>
  );
}

export function TestBadge({ pass }) {
  return <span style={{ fontSize: 10, padding: "2px 8px", borderRadius: 4, fontWeight: 500, background: pass ? "#E1F5EE" : "#FCEBEB", border: `0.5px solid ${pass ? "#1D9E75" : "#E24B4A"}`, color: pass ? "#0F6E56" : "#A32D2D" }}>{pass ? "PASS" : "FAIL"}</span>;
}

export function MonoBox({ children, maxH = 64 }) {
  return <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", fontFamily: "var(--font-mono)", fontSize: 11, wordBreak: "break-all", color: "var(--color-text-primary)", maxHeight: maxH, overflowY: "auto" }}>{children}</div>;
}
// ═══════════════════════════════════════════════════════════════════════════════
// PA #10 — HMAC and HMAC-Based CCA Encryption (Interactive Demo)
// ═══════════════════════════════════════════════════════════════════════════════

import { Fragment, useMemo, useState } from "react";
import {
  hmacDlp,
  hmacVerify,
  runHmacEufCmaGame,
  attemptHmacForgery,
  generateHmacSignedPairs,
  macToCrhfDemo,
  lengthExtensionAttackDemo,
  hmacCcaEnc,
  hmacCcaDec,
  hmacMalleabilityDemo,
  runHmacCca2Game,
  comparisonTimingDemo,
  randomHex,
  truncateMiddle,
} from "./crypto.js";
import {
  FieldLabel,
  SectionHeading,
  TextInput,
  ToggleBar,
  MonoBox,
} from "../shared/ui.jsx";

function StatCard({ label, value, accent }) {
  return (
    <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
      <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>{label}</div>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, fontWeight: 500, color: accent || "var(--color-text-primary)", wordBreak: "break-all" }}>{value}</div>
    </div>
  );
}

function ActionButton({ children, onClick, disabled, tone = "green" }) {
  const palette = tone === "red"
    ? { bg: "#FCEBEB", border: "#E24B4A", text: "#A32D2D" }
    : tone === "purple"
      ? { bg: "#EEEDFE", border: "#7F77DD", text: "#3C3489" }
      : tone === "orange"
        ? { bg: "#FEF3E2", border: "#E8A820", text: "#7A5200" }
        : { bg: "#E1F5EE", border: "#1D9E75", text: "#0F6E56" };

  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        padding: "8px 14px",
        fontSize: 12,
        fontWeight: 500,
        border: `0.5px solid ${palette.border}`,
        borderRadius: "var(--border-radius-md)",
        background: disabled ? "#E5E2D8" : palette.bg,
        color: disabled ? "#85827A" : palette.text,
        cursor: disabled ? "default" : "pointer",
        fontFamily: "var(--font-sans)",
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </button>
  );
}

function HexLine({ label, value }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "150px 1fr", gap: 8, fontSize: 11, marginBottom: 4 }}>
      <span style={{ color: "var(--color-text-secondary)" }}>{label}</span>
      <span style={{ fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>{value}</span>
    </div>
  );
}

function Banner({ ok, children }) {
  return (
    <div style={{
      padding: "10px 12px",
      borderRadius: "var(--border-radius-md)",
      background: ok ? "#E1F5EE" : "#FCEBEB",
      border: `0.5px solid ${ok ? "#1D9E75" : "#E24B4A"}`,
      color: ok ? "#0F6E56" : "#A32D2D",
      fontSize: 12,
      lineHeight: 1.5,
      marginTop: 10,
    }}>
      {children}
    </div>
  );
}

function HmacFlow({ result }) {
  if (!result || result.error) return null;
  const box = (x, y, w, label, sub, fill, stroke, color) => (
    <g>
      <rect x={x} y={y} width={w} height={34} rx={5} fill={fill} stroke={stroke} strokeWidth={0.8} />
      <text x={x + w / 2} y={y + 14} textAnchor="middle" fontSize={8.5} fill={color}>{label}</text>
      <text x={x + w / 2} y={y + 27} textAnchor="middle" fontSize={7} fill={color}>{sub}</text>
    </g>
  );
  return (
    <svg width="100%" viewBox="0 0 690 120" style={{ display: "block", fontFamily: "var(--font-mono)", marginTop: 10 }}>
      {box(0, 42, 86, "k ⊕ ipad", `0x${result.innerKeyHex.slice(0, 8)}…`, "#E6F1FB", "#378ADD", "#185FA5")}
      <line x1={86} y1={59} x2={116} y2={59} stroke="#B5B1A8" />
      {box(116, 42, 80, "message", `0x${result.messageHex.slice(0, 8)}…`, "#E1F5EE", "#1D9E75", "#0F6E56")}
      <line x1={196} y1={59} x2={226} y2={59} stroke="#B5B1A8" />
      {box(226, 42, 78, "H", "inner", "#EEEDFE", "#7F77DD", "#3C3489")}
      <line x1={304} y1={59} x2={334} y2={59} stroke="#B5B1A8" />
      {box(334, 42, 94, "inner hash", `0x${result.innerHash}`, "#FEF3E2", "#E8A820", "#7A5200")}
      <line x1={428} y1={59} x2={458} y2={59} stroke="#B5B1A8" />
      {box(458, 42, 88, "k ⊕ opad", `0x${result.outerKeyHex.slice(0, 8)}…`, "#E6F1FB", "#378ADD", "#185FA5")}
      <line x1={546} y1={59} x2={576} y2={59} stroke="#B5B1A8" />
      {box(576, 42, 48, "H", "outer", "#EEEDFE", "#7F77DD", "#3C3489")}
      <line x1={624} y1={59} x2={650} y2={59} stroke="#B5B1A8" />
      {box(650, 42, 38, "tag", `0x${result.tag}`, "#1a1a2e", "#7F77DD", "#c8c4f8")}
    </svg>
  );
}

export default function PA10Panel() {
  const hdr = { bg: "#E1F5EE", border: "#1D9E75", text: "#0F6E56" };
  const [activeTab, setActiveTab] = useState("hmac");

  // ── HMAC state ───────────────────────────────────────────────────────────
  const [hmacKey, setHmacKey] = useState("a3f2c1b8d9e0f123");
  const [hmacMsg, setHmacMsg] = useState("Authenticate this message");
  const [verifyTag, setVerifyTag] = useState("");
  const [verifyResult, setVerifyResult] = useState(null);

  // ── EUF-CMA state ────────────────────────────────────────────────────────
  const [eufKey, setEufKey] = useState("a3f2c1b8d9e0f123");
  const [pairCount, setPairCount] = useState("50");
  const [pairs, setPairs] = useState(null);
  const [forgeMsg, setForgeMsg] = useState("new forged message");
  const [forgeTag, setForgeTag] = useState("deadbeef");
  const [forgeResult, setForgeResult] = useState(null);
  const [gameResult, setGameResult] = useState(null);

  // ── MAC ⇒ CRHF state ─────────────────────────────────────────────────────
  const [crhfKey, setCrhfKey] = useState("b4e7a29199cc00ff");
  const [crhfA, setCrhfA] = useState("first integrity document");
  const [crhfB, setCrhfB] = useState("second integrity document");
  const [crhfResult, setCrhfResult] = useState(null);

  // ── Length extension state ───────────────────────────────────────────────
  const [leKey, setLeKey] = useState("a3f2c1b8");
  const [leMsg, setLeMsg] = useState("amount=100&to=bob");
  const [leSuffix, setLeSuffix] = useState("&admin=true");
  const [leGuess, setLeGuess] = useState("4");
  const [leResult, setLeResult] = useState(null);

  // ── CCA state ────────────────────────────────────────────────────────────
  const [prfType, setPrfType] = useState("GGM");
  const [kE, setKE] = useState("c0ffee11");
  const [kM, setKM] = useState("a3f2c1b8d9e0f123");
  const [plainHex, setPlainHex] = useState("deadbeefcafebabe");
  const [encResult, setEncResult] = useState(null);
  const [decResult, setDecResult] = useState(null);
  const [tamperResult, setTamperResult] = useState(null);
  const [m0, setM0] = useState("aaaaaaaa");
  const [m1, setM1] = useState("bbbbbbbb");
  const [rounds, setRounds] = useState("50");
  const [ccaGame, setCcaGame] = useState(null);

  const hmacResult = useMemo(() => {
    try { return hmacDlp(hmacKey, hmacMsg, "text"); }
    catch (e) { return { error: e.message }; }
  }, [hmacKey, hmacMsg]);

  const timingRows = useMemo(() => hmacResult?.tag ? comparisonTimingDemo(hmacResult.tag) : [], [hmacResult]);

  function copyTagToVerify() {
    if (hmacResult?.tag) setVerifyTag(hmacResult.tag);
  }

  function runVerify() {
    try { setVerifyResult(hmacVerify(hmacKey, hmacMsg, verifyTag, "text")); }
    catch (e) { setVerifyResult({ error: e.message }); }
  }

  function runGenPairs() {
    try {
      const p = generateHmacSignedPairs(eufKey, pairCount);
      setPairs(p);
      setForgeResult(null);
      setGameResult(null);
    } catch (e) {
      setPairs([{ error: e.message }]);
    }
  }

  function runAttemptForgery() {
    if (!pairs) return;
    try { setForgeResult(attemptHmacForgery(eufKey, pairs, forgeMsg, forgeTag)); }
    catch (e) { setForgeResult({ error: e.message }); }
  }

  function runEufGame() {
    try { setGameResult(runHmacEufCmaGame(eufKey, pairCount, 20)); }
    catch (e) { setGameResult({ error: e.message }); }
  }

  function runCrhfDemo() {
    try { setCrhfResult(macToCrhfDemo(crhfKey, crhfA, crhfB)); }
    catch (e) { setCrhfResult({ error: e.message }); }
  }

  function runLenExt() {
    try { setLeResult(lengthExtensionAttackDemo(leKey, leMsg, leSuffix, leGuess)); }
    catch (e) { setLeResult({ error: e.message }); }
  }

  function runEncrypt() {
    try {
      const enc = hmacCcaEnc(kE, kM, plainHex, prfType);
      const dec = hmacCcaDec(kE, kM, enc.CE, enc.tag, prfType);
      setEncResult(enc);
      setDecResult(dec);
      setTamperResult(null);
      setCcaGame(null);
    } catch (e) {
      setEncResult({ error: e.message });
      setDecResult(null);
    }
  }

  function runTamper() {
    try { setTamperResult(hmacMalleabilityDemo(kE, kM, plainHex, 0, prfType)); }
    catch (e) { setTamperResult({ error: e.message }); }
  }

  function runGame() {
    try { setCcaGame(runHmacCca2Game(kE, kM, m0, m1, rounds, prfType)); }
    catch (e) { setCcaGame({ error: e.message }); }
  }

  const TABS = [
    { value: "hmac", label: "HMAC" },
    { value: "euf", label: "CRHF ⇒ MAC" },
    { value: "crhf", label: "MAC ⇒ CRHF" },
    { value: "lenext", label: "Length extension" },
    { value: "cca", label: "Encrypt-then-HMAC" },
  ];

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>
      <div style={{ padding: "10px 16px", background: hdr.bg, borderBottom: `0.5px solid ${hdr.border}`, display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: hdr.text }}>
          PA #10 — HMAC and HMAC-Based CCA Encryption
        </div>
        <div style={{ fontSize: 10, color: hdr.text, fontFamily: "var(--font-mono)" }}>
          H((k⊕opad) || H((k⊕ipad) || m))
        </div>
      </div>

      <div style={{ padding: "10px 16px", borderBottom: "0.5px solid var(--color-border-tertiary)", background: "var(--color-background-secondary)" }}>
        <ToggleBar value={activeTab} onChange={setActiveTab} options={TABS.map(t => ({
          ...t,
          activeStyle: { bg: "#E1F5EE", border: "#1D9E75", color: "#0F6E56" },
        }))} />
      </div>

      <div style={{ padding: 16 }}>
        {activeTab === "hmac" && (
          <div>
            <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", marginBottom: 14, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
              HMAC is built over your PA#8 DLP hash. The key is normalized to the PA#7 block size, then used once with ipad and once with opad.
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
              <div>
                <FieldLabel>HMAC key k (hex)</FieldLabel>
                <TextInput value={hmacKey} onChange={setHmacKey} placeholder="a3f2c1b8" />
              </div>
              <div>
                <FieldLabel>Message m (text)</FieldLabel>
                <TextInput value={hmacMsg} onChange={setHmacMsg} placeholder="message" />
              </div>
            </div>

            {hmacResult?.error ? <Banner ok={false}>{hmacResult.error}</Banner> : (
              <>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 8, marginBottom: 12 }}>
                  <StatCard label="HMAC tag" value={`0x${hmacResult.tag}`} accent="#0F6E56" />
                  <StatCard label="Inner hash" value={`0x${hmacResult.innerHash}`} />
                  <StatCard label="Normalized key" value={`0x${hmacResult.keyHex}`} />
                </div>
                <HmacFlow result={hmacResult} />
                <SectionHeading>Step values</SectionHeading>
                <MonoBox maxH={180}>{[
                  `k ⊕ ipad = 0x${hmacResult.innerKeyHex}`,
                  `inner input = 0x${truncateMiddle(hmacResult.innerInputHex, 48)}`,
                  `H(inner) = 0x${hmacResult.innerHash}`,
                  `k ⊕ opad = 0x${hmacResult.outerKeyHex}`,
                  `outer input = 0x${truncateMiddle(hmacResult.outerInputHex, 48)}`,
                  `HMAC tag = 0x${hmacResult.tag}`,
                ].join("\n")}</MonoBox>
              </>
            )}

            <SectionHeading>Constant-time verification</SectionHeading>
            <div style={{ display: "flex", gap: 10, alignItems: "end", flexWrap: "wrap", marginBottom: 10 }}>
              <div style={{ flex: "1 1 240px" }}>
                <FieldLabel>Supplied tag</FieldLabel>
                <TextInput value={verifyTag} onChange={setVerifyTag} placeholder="paste tag" />
              </div>
              <ActionButton onClick={copyTagToVerify} tone="purple">Use correct tag</ActionButton>
              <ActionButton onClick={runVerify}>Verify tag</ActionButton>
            </div>
            {verifyResult && !verifyResult.error && <Banner ok={verifyResult.valid}>{verifyResult.valid ? "Tag accepted ✓" : `Tag rejected. Expected 0x${verifyResult.expectedTag}`}</Banner>}
            {verifyResult?.error && <Banner ok={false}>{verifyResult.error}</Banner>}

            <SectionHeading>Timing leak comparison</SectionHeading>
            <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr 1fr", border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", overflow: "hidden", fontSize: 11 }}>
              {["Candidate", "Naive early-exit checks", "Constant-time byte checks"].map(h => <div key={h} style={{ padding: "7px 10px", background: "var(--color-background-secondary)", fontWeight: 500 }}>{h}</div>)}
              {timingRows.map((r) => (
                <Fragment key={r.label}>
                  <div key={`${r.label}-a`} style={{ padding: "7px 10px", fontFamily: "var(--font-mono)", borderTop: "0.5px solid var(--color-border-tertiary)" }}>{r.label}: 0x{r.candidate}</div>
                  <div key={`${r.label}-b`} style={{ padding: "7px 10px", borderTop: "0.5px solid var(--color-border-tertiary)" }}>{r.naiveChecks}</div>
                  <div key={`${r.label}-c`} style={{ padding: "7px 10px", borderTop: "0.5px solid var(--color-border-tertiary)" }}>{r.constantTimeChecks}</div>
                </Fragment>
              ))}
            </div>
          </div>
        )}

        {activeTab === "euf" && (
          <div>
            <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", marginBottom: 14, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
              CRHF ⇒ MAC: once DLP_Hash is available, HMAC becomes a secure MAC. The EUF-CMA demo gives the adversary signed messages, then checks whether a valid tag on a new message can be produced.
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 140px", gap: 10, marginBottom: 10 }}>
              <div><FieldLabel>Hidden MAC key (hex)</FieldLabel><TextInput value={eufKey} onChange={setEufKey} placeholder="key" /></div>
              <div><FieldLabel>Oracle queries</FieldLabel><TextInput value={pairCount} onChange={setPairCount} placeholder="50" /></div>
            </div>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 12 }}>
              <ActionButton onClick={runGenPairs}>Generate signed pairs</ActionButton>
              <ActionButton onClick={runEufGame} tone="purple">Run 20 random forgery attempts</ActionButton>
              <ActionButton onClick={() => { setEufKey(randomHex(8)); setPairs(null); setGameResult(null); setForgeResult(null); }} tone="orange">Random key</ActionButton>
            </div>

            {pairs && !pairs[0]?.error && (
              <>
                <SectionHeading>Sample HMAC oracle outputs</SectionHeading>
                <MonoBox maxH={110}>{pairs.slice(0, 8).map((p, i) => `${i + 1}. ${p.msg}  →  0x${p.tag}`).join("\n")}</MonoBox>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginTop: 12 }}>
                  <div><FieldLabel>Forged message m*</FieldLabel><TextInput value={forgeMsg} onChange={setForgeMsg} placeholder="new message" /></div>
                  <div><FieldLabel>Forged tag t*</FieldLabel><TextInput value={forgeTag} onChange={setForgeTag} placeholder="deadbeef" /></div>
                </div>
                <div style={{ marginTop: 10 }}><ActionButton onClick={runAttemptForgery} tone="red">Submit forgery</ActionButton></div>
              </>
            )}
            {pairs?.[0]?.error && <Banner ok={false}>{pairs[0].error}</Banner>}
            {forgeResult && !forgeResult.error && <Banner ok={forgeResult.accepted}>{forgeResult.reason} Expected tag: 0x{forgeResult.expectedTag}</Banner>}
            {gameResult && !gameResult.error && (
              <div style={{ marginTop: 12 }}>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))", gap: 8 }}>
                  <StatCard label="Attempts" value={gameResult.attempts} />
                  <StatCard label="Successes" value={gameResult.successes} accent={gameResult.successes === 0 ? "#0F6E56" : "#A32D2D"} />
                  <StatCard label="Success rate" value={`${(gameResult.successRate * 100).toFixed(1)}%`} />
                </div>
                <MonoBox maxH={120}>{gameResult.logs.map(l => `try ${l.i}: ${l.msg} / guessed 0x${l.guessedTag} / expected 0x${l.expectedTag} / accepted=${l.accepted}`).join("\n")}</MonoBox>
              </div>
            )}
            {gameResult?.error && <Banner ok={false}>{gameResult.error}</Banner>}
          </div>
        )}

        {activeTab === "crhf" && (
          <div>
            <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", marginBottom: 14, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
              MAC ⇒ CRHF: fix a key and use HMAC as the Merkle-Damgård compression step: zᵢ = HMACₖ(zᵢ₋₁ || Mᵢ). A collision here would imply a collision/forgery against the MAC compression function.
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 10 }}>
              <div><FieldLabel>Fixed HMAC key</FieldLabel><TextInput value={crhfKey} onChange={setCrhfKey} placeholder="key" /></div>
              <div />
              <div><FieldLabel>Message A</FieldLabel><TextInput value={crhfA} onChange={setCrhfA} placeholder="message A" /></div>
              <div><FieldLabel>Message B</FieldLabel><TextInput value={crhfB} onChange={setCrhfB} placeholder="message B" /></div>
            </div>
            <ActionButton onClick={runCrhfDemo}>Build HMAC-MD hash</ActionButton>
            {crhfResult && !crhfResult.error && (
              <div style={{ marginTop: 12 }}>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 8, marginBottom: 10 }}>
                  <StatCard label="HMAC-MD(A)" value={`0x${crhfResult.digestA}`} />
                  <StatCard label="HMAC-MD(B)" value={`0x${crhfResult.digestB}`} />
                  <StatCard label="Distinct?" value={crhfResult.distinct ? "YES ✓" : "NO"} accent={crhfResult.distinct ? "#0F6E56" : "#A32D2D"} />
                </div>
                <MonoBox maxH={160}>{crhfResult.stepsA.map(s => `z${s.i}=0x${s.zIn}, M${s.i + 1}=0x${s.blockHex}  →  z${s.i + 1}=0x${s.zOut}`).join("\n")}</MonoBox>
                <Banner ok={true}>{crhfResult.explanation}</Banner>
              </div>
            )}
            {crhfResult?.error && <Banner ok={false}>{crhfResult.error}</Banner>}
          </div>
        )}

        {activeTab === "lenext" && (
          <div>
            <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", marginBottom: 14, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
              A naive MAC t = H(k || m) exposes the final Merkle-Damgård chaining value. Given a key-length guess, the attacker can resume hashing and authenticate m || pad || suffix. HMAC prevents this because the public tag is the output of a fresh outer keyed hash.
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 10 }}>
              <div><FieldLabel>Secret key k (hex)</FieldLabel><TextInput value={leKey} onChange={setLeKey} placeholder="a3f2c1b8" /></div>
              <div><FieldLabel>Guessed key length (bytes)</FieldLabel><TextInput value={leGuess} onChange={setLeGuess} placeholder="4" /></div>
              <div><FieldLabel>Known message m</FieldLabel><TextInput value={leMsg} onChange={setLeMsg} placeholder="amount=100" /></div>
              <div><FieldLabel>Attacker suffix</FieldLabel><TextInput value={leSuffix} onChange={setLeSuffix} placeholder="&admin=true" /></div>
            </div>
            <ActionButton onClick={runLenExt} tone="orange">Run length-extension attack</ActionButton>
            {leResult && !leResult.error && (
              <div style={{ marginTop: 12 }}>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))", gap: 8, marginBottom: 10 }}>
                  <StatCard label="Naive original tag" value={`0x${leResult.originalNaiveTag}`} />
                  <StatCard label="Attacker forged tag" value={`0x${leResult.attackerForgedTag}`} />
                  <StatCard label="Server recomputed tag" value={`0x${leResult.serverNaiveTag}`} />
                  <StatCard label="Naive attack works?" value={leResult.naiveAttackWorks ? "YES ✓" : "NO"} accent={leResult.naiveAttackWorks ? "#0F6E56" : "#A32D2D"} />
                  <StatCard label="HMAC attack works?" value={leResult.hmacAttackWorks ? "YES" : "NO ✓"} accent={leResult.hmacAttackWorks ? "#A32D2D" : "#0F6E56"} />
                </div>
                <HexLine label="Glue padding" value={`0x${leResult.gluePadHex}`} />
                <HexLine label="Forged public msg" value={`0x${truncateMiddle(leResult.forgedPublicMessageHex, 52)}`} />
                <HexLine label="Real HMAC forged msg" value={`0x${leResult.realHmacOnForgedMsg}`} />
                <HexLine label="Attacker HMAC attempt" value={`0x${leResult.attackerHmacAttempt}`} />
                <Banner ok={leResult.naiveAttackWorks && !leResult.hmacAttackWorks}>
                  Naive H(k||m) was extended successfully, but the same resume trick fails against HMAC.
                </Banner>
              </div>
            )}
            {leResult?.error && <Banner ok={false}>{leResult.error}</Banner>}
          </div>
        )}

        {activeTab === "cca" && (
          <div>
            <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", marginBottom: 14, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
              Encrypt-then-HMAC is the PA#10 CCA-secure scheme: C_E ← PA#3 Enc(kE,m), t ← HMAC(kM,C_E), and decryption verifies t before calling PA#3 Dec.
            </div>

            <div style={{ marginBottom: 12 }}>
              <ToggleBar value={prfType} onChange={setPrfType} options={[
                { value: "GGM", label: "GGM PRF", activeStyle: { bg: "#EEEDFE", border: "#7F77DD", color: "#3C3489" } },
                { value: "AES", label: "AES PRF", activeStyle: { bg: "#E6F1FB", border: "#378ADD", color: "#185FA5" } },
              ]} />
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 10 }}>
              <div><FieldLabel>Encryption key kE</FieldLabel><TextInput value={kE} onChange={setKE} placeholder="c0ffee11" /></div>
              <div><FieldLabel>HMAC key kM</FieldLabel><TextInput value={kM} onChange={setKM} placeholder="a3f2..." /></div>
              <div><FieldLabel>Plaintext m (hex)</FieldLabel><TextInput value={plainHex} onChange={setPlainHex} placeholder="deadbeef" /></div>
              <div style={{ display: "flex", alignItems: "end", gap: 10 }}>
                <ActionButton onClick={runEncrypt}>Encrypt + decrypt</ActionButton>
                <ActionButton onClick={runTamper} tone="red">Tamper bit</ActionButton>
              </div>
            </div>

            {encResult?.error && <Banner ok={false}>{encResult.error}</Banner>}
            {encResult && !encResult.error && (
              <div style={{ marginBottom: 12 }}>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 8, marginBottom: 10 }}>
                  <StatCard label="C_E = r:c" value={truncateMiddle(encResult.CE, 28)} />
                  <StatCard label="HMAC tag" value={`0x${encResult.tag}`} />
                  <StatCard label="Decryption" value={decResult?.accepted ? `accepted: 0x${decResult.plaintext}` : "rejected"} accent={decResult?.accepted ? "#0F6E56" : "#A32D2D"} />
                </div>
                <MonoBox maxH={120}>{[
                  `CE = ${encResult.CE}`,
                  `MAC input bytes = 0x${truncateMiddle(encResult.macInputHex, 50)}`,
                  `tag = 0x${encResult.tag}`,
                  `dec = ${decResult?.reason}`,
                ].join("\n")}</MonoBox>
              </div>
            )}

            {tamperResult && !tamperResult.error && (
              <div style={{ marginTop: 12 }}>
                <SectionHeading>Malleability blocked by HMAC</SectionHeading>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 8, marginBottom: 10 }}>
                  <StatCard label="CPA-only decrypts" value={`0x${tamperResult.cpaPlaintext}`} accent="#A32D2D" />
                  <StatCard label="HMAC-CCA accepts?" value={tamperResult.hmacAccepted ? "YES" : "NO ✓"} accent={tamperResult.hmacAccepted ? "#A32D2D" : "#0F6E56"} />
                  <StatCard label="Tampered CE" value={truncateMiddle(tamperResult.tamperedCE, 26)} />
                </div>
                <Banner ok={!tamperResult.hmacAccepted}>{tamperResult.hmacReason}</Banner>
              </div>
            )}
            {tamperResult?.error && <Banner ok={false}>{tamperResult.error}</Banner>}

            <SectionHeading>IND-CCA2 game simulation</SectionHeading>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 120px", gap: 10, marginBottom: 10 }}>
              <div><FieldLabel>m0 (hex)</FieldLabel><TextInput value={m0} onChange={setM0} placeholder="aaaaaaaa" /></div>
              <div><FieldLabel>m1 (hex)</FieldLabel><TextInput value={m1} onChange={setM1} placeholder="bbbbbbbb" /></div>
              <div><FieldLabel>Rounds</FieldLabel><TextInput value={rounds} onChange={setRounds} placeholder="50" /></div>
            </div>
            <ActionButton onClick={runGame} tone="purple">Run CCA2 game</ActionButton>
            {ccaGame && !ccaGame.error && (
              <div style={{ marginTop: 12 }}>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))", gap: 8, marginBottom: 10 }}>
                  <StatCard label="Rounds" value={ccaGame.rounds} />
                  <StatCard label="Correct guesses" value={ccaGame.correct} />
                  <StatCard label="Advantage" value={ccaGame.advantage.toFixed(3)} />
                </div>
                <MonoBox maxH={120}>{ccaGame.log.map(l => `round ${l.i}: b=${l.b}, guess=${l.guess}, win=${l.win}, tampered accepted=${l.tamperedAccepted}`).join("\n")}</MonoBox>
              </div>
            )}
            {ccaGame?.error && <Banner ok={false}>{ccaGame.error}</Banner>}
          </div>
        )}
      </div>
    </div>
  );
}

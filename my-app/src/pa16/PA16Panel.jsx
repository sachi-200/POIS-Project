// ═══════════════════════════════════════════════════════════════════════════════
// PA #16 — ElGamal Public-Key Cryptosystem (Interactive Demo)
// ═══════════════════════════════════════════════════════════════════════════════

import { useState } from "react";
import {
  DEFAULT_GROUP,
  elgamalKeygen,
  encryptDecryptDemo,
  randomizedEncryptionDemo,
  malleabilityDemo,
  malleabilityCounterDemo,
  runIndCpaSimulation,
  sampleDdhTuples,
  truncMiddle,
  bigintToHex,
} from "./crypto.js";
import {
  FieldLabel,
  SectionHeading,
  TextInput,
  MonoBox,
  TestBadge,
} from "../shared/ui.jsx";

function StatCard({ label, value, accent }) {
  return (
    <div style={{ padding: "10px 12px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)" }}>
      <div style={{ fontSize: 10, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>{label}</div>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, fontWeight: 500, color: accent || "var(--color-text-primary)", wordBreak: "break-all" }}>{value}</div>
    </div>
  );
}

function ActionButton({ children, onClick, disabled, tone = "teal" }) {
  const palette = tone === "red"
    ? { bg: "#FCEBEB", border: "#E24B4A", text: "#A32D2D" }
    : tone === "orange"
      ? { bg: "#FEF3E2", border: "#E8A820", text: "#7A5200" }
      : tone === "purple"
        ? { bg: "#EEEDFE", border: "#7F77DD", text: "#3C3489" }
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

function BigLine({ label, value }) {
  return <HexLine label={label} value={typeof value === "bigint" ? value.toString() : value} />;
}

function percent(value) {
  if (!Number.isFinite(value)) return "—";
  return `${(value * 100).toFixed(1)}%`;
}

export default function PA16Panel() {
  const hdr = { bg: "#E8F8F3", border: "#20A47B", text: "#0F6E56" };

  // ── Key state ─────────────────────────────────────────────────────────────
  const [keys, setKeys] = useState(null);
  const [secretOverride, setSecretOverride] = useState("");
  const [generating, setGenerating] = useState(false);

  // ── Encrypt/decrypt state ─────────────────────────────────────────────────
  const [message, setMessage] = useState("12345");
  const [encResult, setEncResult] = useState(null);
  const [randomization, setRandomization] = useState(null);
  const [malleability, setMalleability] = useState(null);
  const [running, setRunning] = useState(false);

  // ── Malleability success-counter state ────────────────────────────────────
  const [trickTrials, setTrickTrials] = useState("20");
  const [trickCounter, setTrickCounter] = useState({ attempts: 0, successes: 0 });
  const [trickBatch, setTrickBatch] = useState(null);

  // ── IND-CPA state ─────────────────────────────────────────────────────────
  const [m0, setM0] = useState("11111");
  const [m1, setM1] = useState("22222");
  const [rounds, setRounds] = useState("50");
  const [cpaResult, setCpaResult] = useState(null);

  // ── DDH tuple state ───────────────────────────────────────────────────────
  const [ddh, setDdh] = useState(null);

  function resetTrickCounter() {
    setTrickCounter({ attempts: 0, successes: 0 });
    setTrickBatch(null);
  }

  function generateKeys() {
    setGenerating(true);
    setEncResult(null);
    setRandomization(null);
    setMalleability(null);
    setCpaResult(null);
    setDdh(null);
    resetTrickCounter();
    setTimeout(() => {
      try {
        const x = secretOverride.trim() ? BigInt(secretOverride.trim()) : null;
        setKeys(elgamalKeygen(DEFAULT_GROUP, x));
      } catch (e) {
        setKeys({ error: e.message });
      }
      setGenerating(false);
    }, 10);
  }

  function runEncryptDecrypt() {
    if (!keys || keys.error) return;
    setRunning(true);
    setTimeout(() => {
      try {
        setEncResult(encryptDecryptDemo(keys, message));
      } catch (e) {
        setEncResult({ error: e.message });
      }
      setRunning(false);
    }, 10);
  }

  function runRandomization() {
    if (!keys || keys.error) return;
    setRunning(true);
    setTimeout(() => {
      try {
        setRandomization(randomizedEncryptionDemo(keys, message));
      } catch (e) {
        setRandomization({ error: e.message });
      }
      setRunning(false);
    }, 10);
  }

  function runMalleability() {
    if (!keys || keys.error) return;
    setRunning(true);
    setTimeout(() => {
      try {
        const result = malleabilityDemo(keys, message, 2n);
        setMalleability(result);
        setTrickCounter((prev) => ({
          attempts: prev.attempts + 1,
          successes: prev.successes + (result.pass ? 1 : 0),
        }));
      } catch (e) {
        setMalleability({ error: e.message });
      }
      setRunning(false);
    }, 10);
  }

  function runMalleabilityCounter() {
    if (!keys || keys.error) return;
    setRunning(true);
    setTimeout(() => {
      try {
        const result = malleabilityCounterDemo(keys, message, trickTrials, 2n);
        setTrickBatch(result);
        setTrickCounter((prev) => ({
          attempts: prev.attempts + result.trials,
          successes: prev.successes + result.successes,
        }));
      } catch (e) {
        setTrickBatch({ error: e.message });
      }
      setRunning(false);
    }, 10);
  }

  function runCpa() {
    if (!keys || keys.error) return;
    setRunning(true);
    setTimeout(() => {
      try {
        setCpaResult(runIndCpaSimulation(keys, m0, m1, rounds));
      } catch (e) {
        setCpaResult({ error: e.message });
      }
      setRunning(false);
    }, 10);
  }

  function runDdhSample() {
    try {
      setDdh(sampleDdhTuples(DEFAULT_GROUP));
    } catch (e) {
      setDdh({ error: e.message });
    }
  }

  const trickRate = trickCounter.attempts === 0 ? Number.NaN : trickCounter.successes / trickCounter.attempts;

  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden" }}>
      {/* ── Header ── */}
      <div style={{ padding: "10px 16px", background: hdr.bg, borderBottom: `0.5px solid ${hdr.border}`, display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ fontSize: 10, fontWeight: 500, letterSpacing: "0.07em", textTransform: "uppercase", color: hdr.text }}>
          PA #16 — ElGamal Public-Key Cryptosystem
        </div>
        <div style={{ fontSize: 10, color: hdr.text, fontFamily: "var(--font-mono)" }}>
          c₁ = gʳ, c₂ = m·hʳ mod p
        </div>
      </div>

      <div style={{ padding: "16px" }}>
        <div style={{ padding: "10px 14px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", marginBottom: 14, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>
          ElGamal is randomized public-key encryption based on DDH hardness. It is IND-CPA secure, but it is multiplicatively malleable:
          changing <span style={{ fontFamily: "var(--font-mono)" }}>(c₁, c₂)</span> to <span style={{ fontFamily: "var(--font-mono)" }}>(c₁, 2c₂ mod p)</span> decrypts to <span style={{ fontFamily: "var(--font-mono)" }}>2m mod p</span>. The malleability trick is deterministic, so its success rate should be 100%.
        </div>

        {/* ═══ Group and key generation ═══ */}
        <SectionHeading>Group parameters from PA#11</SectionHeading>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))", gap: 10, marginBottom: 14 }}>
          <StatCard label="p" value={DEFAULT_GROUP.p.toString()} />
          <StatCard label="q" value={DEFAULT_GROUP.q.toString()} />
          <StatCard label="g" value={DEFAULT_GROUP.g.toString()} />
          <StatCard label="group" value="safe-prime subgroup" />
        </div>

        <div style={{ display: "flex", gap: 10, alignItems: "end", flexWrap: "wrap", marginBottom: 14 }}>
          <div style={{ width: 220 }}>
            <FieldLabel>Optional secret x override</FieldLabel>
            <TextInput value={secretOverride} onChange={setSecretOverride} placeholder="leave blank for random x" />
          </div>
          <ActionButton onClick={generateKeys} disabled={generating}>
            {generating ? "Generating…" : "Generate ElGamal keys"}
          </ActionButton>
        </div>

        {keys?.error && <div style={{ color: "#A32D2D", fontSize: 12, marginBottom: 12 }}>{keys.error}</div>}

        {keys && !keys.error && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))", gap: 10, marginBottom: 18 }}>
            <StatCard label="secret x" value={truncMiddle(keys.sk.x)} accent="#0F6E56" />
            <StatCard label="public h = g^x mod p" value={truncMiddle(keys.pk.h)} accent="#0F6E56" />
            <StatCard label="h hex" value={`0x${truncMiddle(bigintToHex(keys.pk.h))}`} />
          </div>
        )}

        {/* ═══ Encryption/decryption ═══ */}
        <SectionHeading>Encrypt and decrypt</SectionHeading>
        <div style={{ display: "flex", gap: 10, alignItems: "end", flexWrap: "wrap", marginBottom: 12 }}>
          <div style={{ width: 220 }}>
            <FieldLabel>Message representative m</FieldLabel>
            <TextInput value={message} onChange={setMessage} placeholder="integer, hex, or very short text" />
          </div>
          <ActionButton onClick={runEncryptDecrypt} disabled={!keys || keys.error || running}>Encrypt + decrypt</ActionButton>
          <ActionButton onClick={runRandomization} disabled={!keys || keys.error || running} tone="purple">Encrypt same m twice</ActionButton>
        </div>

        {encResult?.error && <div style={{ color: "#A32D2D", fontSize: 12, marginBottom: 12 }}>{encResult.error}</div>}
        {encResult && !encResult.error && (
          <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", padding: 12, marginBottom: 14 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
              <TestBadge pass={encResult.pass} />
              <span style={{ fontSize: 12, color: "var(--color-text-secondary)" }}>Dec(sk, Enc(pk, m)) = m</span>
            </div>
            <BigLine label="m" value={encResult.message} />
            <BigLine label="r" value={encResult.ciphertext.r} />
            <BigLine label="c1 = g^r" value={encResult.ciphertext.c1} />
            <BigLine label="h^r mask" value={encResult.ciphertext.sharedMask} />
            <BigLine label="c2 = m·h^r" value={encResult.ciphertext.c2} />
            <BigLine label="decrypted m" value={encResult.decrypted.m} />
            {encResult.maybeText && <BigLine label="decoded text" value={encResult.maybeText} />}
          </div>
        )}

        {randomization?.error && <div style={{ color: "#A32D2D", fontSize: 12, marginBottom: 12 }}>{randomization.error}</div>}
        {randomization && !randomization.error && (
          <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", padding: 12, marginBottom: 18 }}>
            <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8, flexWrap: "wrap" }}>
              <TestBadge pass={randomization.ciphertextsDiffer && randomization.bothDecrypt} />
              <span style={{ fontSize: 12, color: "var(--color-text-secondary)" }}>
                Same plaintext encrypts to different ciphertexts because fresh r is sampled each time.
              </span>
            </div>
            <HexLine label="ciphertext 1" value={`(${truncMiddle(randomization.enc1.c1)}, ${truncMiddle(randomization.enc1.c2)})`} />
            <HexLine label="ciphertext 2" value={`(${truncMiddle(randomization.enc2.c1)}, ${truncMiddle(randomization.enc2.c2)})`} />
            <BigLine label="Dec ct1" value={randomization.dec1.m} />
            <BigLine label="Dec ct2" value={randomization.dec2.m} />
          </div>
        )}

        {/* ═══ Malleability ═══ */}
        <SectionHeading>Required malleability attack — 100% success counter</SectionHeading>
        <div style={{ display: "flex", gap: 10, alignItems: "end", flexWrap: "wrap", marginBottom: 12 }}>
          <ActionButton onClick={runMalleability} disabled={!keys || keys.error || running} tone="orange">
            Run trick once
          </ActionButton>
          <div style={{ width: 120 }}>
            <FieldLabel>Counter trials</FieldLabel>
            <TextInput value={trickTrials} onChange={setTrickTrials} placeholder="20" />
          </div>
          <ActionButton onClick={runMalleabilityCounter} disabled={!keys || keys.error || running} tone="green">
            Run counter test
          </ActionButton>
          <ActionButton onClick={resetTrickCounter} disabled={running} tone="red">
            Reset counter
          </ActionButton>
          <span style={{ fontSize: 11, color: "var(--color-text-secondary)", alignSelf: "center" }}>
            The attacker does not need the secret key x.
          </span>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))", gap: 10, marginBottom: 12 }}>
          <StatCard label="trick successes" value={`${trickCounter.successes}/${trickCounter.attempts}`} accent={trickCounter.attempts > 0 && trickCounter.successes === trickCounter.attempts ? "#0F6E56" : undefined} />
          <StatCard label="trick success rate" value={percent(trickRate)} accent={trickCounter.attempts > 0 && trickCounter.successes === trickCounter.attempts ? "#0F6E56" : "#A32D2D"} />
          <StatCard label="expected by theory" value="100%" accent="#0F6E56" />
        </div>

        {malleability?.error && <div style={{ color: "#A32D2D", fontSize: 12, marginBottom: 12 }}>{malleability.error}</div>}
        {malleability && !malleability.error && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(260px,1fr))", gap: 12, marginBottom: 12 }}>
            <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", padding: 12 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: "var(--color-text-primary)", marginBottom: 8 }}>Original ciphertext</div>
              <BigLine label="m" value={malleability.message} />
              <BigLine label="c1" value={malleability.original.c1} />
              <BigLine label="c2" value={malleability.original.c2} />
              <BigLine label="Dec(c1,c2)" value={malleability.originalDec.m} />
            </div>
            <div style={{ border: "0.5px solid #E8A820", borderRadius: "var(--border-radius-md)", padding: 12, background: "#FFFBF2" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                <TestBadge pass={malleability.pass} />
                <span style={{ fontSize: 11, fontWeight: 600, color: "#7A5200" }}>Modified ciphertext decrypts to 2m</span>
              </div>
              <BigLine label="c1′ = c1" value={malleability.modified.c1} />
              <BigLine label="c2′ = 2c2 mod p" value={malleability.modified.c2} />
              <BigLine label="Dec(c1′,c2′)" value={malleability.modifiedDec.m} />
              <BigLine label="expected 2m mod p" value={malleability.expected} />
            </div>
          </div>
        )}

        {trickBatch?.error && <div style={{ color: "#A32D2D", fontSize: 12, marginBottom: 12 }}>{trickBatch.error}</div>}
        {trickBatch && !trickBatch.error && (
          <div style={{ border: "0.5px solid #1D9E75", borderRadius: "var(--border-radius-md)", padding: 12, background: "#F7FFFC", marginBottom: 18 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))", gap: 10, marginBottom: 10 }}>
              <StatCard label="last batch" value={`${trickBatch.successes}/${trickBatch.trials} succeeded`} accent={trickBatch.allPassed ? "#0F6E56" : "#A32D2D"} />
              <StatCard label="batch success rate" value={percent(trickBatch.successRate)} accent={trickBatch.allPassed ? "#0F6E56" : "#A32D2D"} />
              <StatCard label="failures" value={trickBatch.failures.toString()} accent={trickBatch.failures === 0 ? "#0F6E56" : "#A32D2D"} />
            </div>
            <MonoBox maxH={120}>
              {trickBatch.log.map(row => `#${row.round}: Dec(c1, 2c2 mod p) = ${row.decrypted}; expected ${row.expected}; ${row.pass ? "success" : "fail"}`).join("\n")}
            </MonoBox>
          </div>
        )}

        {/* ═══ IND-CPA game ═══ */}
        <SectionHeading>IND-CPA simulation</SectionHeading>
        <div style={{ padding: "8px 10px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", marginBottom: 12, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.6 }}>
          This is a random-guessing adversary, so its guess rate should hover near 50%. The 100% success-rate requirement belongs to the malleability trick above, not to IND-CPA guessing.
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "end", flexWrap: "wrap", marginBottom: 12 }}>
          <div style={{ width: 150 }}>
            <FieldLabel>m₀</FieldLabel>
            <TextInput value={m0} onChange={setM0} placeholder="11111" />
          </div>
          <div style={{ width: 150 }}>
            <FieldLabel>m₁</FieldLabel>
            <TextInput value={m1} onChange={setM1} placeholder="22222" />
          </div>
          <div style={{ width: 110 }}>
            <FieldLabel>Rounds</FieldLabel>
            <TextInput value={rounds} onChange={setRounds} placeholder="50" />
          </div>
          <ActionButton onClick={runCpa} disabled={!keys || keys.error || running} tone="purple">Run game</ActionButton>
        </div>

        {cpaResult?.error && <div style={{ color: "#A32D2D", fontSize: 12, marginBottom: 12 }}>{cpaResult.error}</div>}
        {cpaResult && !cpaResult.error && (
          <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", padding: 12, marginBottom: 18 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))", gap: 10, marginBottom: 10 }}>
              <StatCard label="rounds" value={cpaResult.rounds} />
              <StatCard label="correct guesses" value={cpaResult.correct} />
              <StatCard label="adversary guess rate" value={percent(cpaResult.successRate)} />
              <StatCard label="advantage" value={cpaResult.advantage.toFixed(3)} accent={cpaResult.advantage <= 0.25 ? "#0F6E56" : "#A32D2D"} />
            </div>
            <MonoBox maxH={110}>
              {cpaResult.log.map(row => `round ${row.round}: b=${row.b}, guess=${row.guess}, ${row.win ? "win" : "lose"}, c1=${truncMiddle(row.c1)}, c2=${truncMiddle(row.c2)}`).join("\n")}
            </MonoBox>
          </div>
        )}

        {/* ═══ DDH intuition ═══ */}
        <SectionHeading>DDH tuple intuition</SectionHeading>
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap", marginBottom: 12 }}>
          <ActionButton onClick={runDdhSample} tone="teal">Sample DDH tuples</ActionButton>
          <span style={{ fontSize: 11, color: "var(--color-text-secondary)" }}>
            ElGamal security relies on real tuples being indistinguishable from random tuples.
          </span>
        </div>
        {ddh?.error && <div style={{ color: "#A32D2D", fontSize: 12 }}>{ddh.error}</div>}
        {ddh && !ddh.error && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(260px,1fr))", gap: 12 }}>
            <div style={{ border: "0.5px solid #1D9E75", borderRadius: "var(--border-radius-md)", padding: 12, background: "#F7FFFC" }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: "#0F6E56", marginBottom: 8 }}>{ddh.realTuple.kind}</div>
              <BigLine label="A = g^a" value={ddh.realTuple.A} />
              <BigLine label="B = g^b" value={ddh.realTuple.B} />
              <BigLine label="C = g^(ab)" value={ddh.realTuple.C} />
            </div>
            <div style={{ border: "0.5px solid #7F77DD", borderRadius: "var(--border-radius-md)", padding: 12, background: "#FBFAFF" }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: "#3C3489", marginBottom: 8 }}>{ddh.randomTuple.kind}</div>
              <BigLine label="A = g^a" value={ddh.randomTuple.A} />
              <BigLine label="B = g^b" value={ddh.randomTuple.B} />
              <BigLine label="C = g^z" value={ddh.randomTuple.C} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

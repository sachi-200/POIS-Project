// ═══════════════════════════════════════════════════════════════════════════════
// NIST SP 800-22 style statistical tests — used by PA#1 and PA#2
// ═══════════════════════════════════════════════════════════════════════════════

function erfcApprox(x) {
  if (x < 0) return 2 - erfcApprox(-x);
  const t = 1 / (1 + 0.3275911 * x);
  return t * (0.254829592 + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429)))) * Math.exp(-x * x);
}

function chi2pval(chi2, df) {
  if (chi2 <= 0) return 1;
  const z = (Math.pow(chi2 / df, 1 / 3) - (1 - 2 / (9 * df))) / Math.sqrt(2 / (9 * df));
  return erfcApprox(z / Math.sqrt(2)) / 2;
}

/** Frequency (monobit) test — NIST SP 800-22 §2.1 */
export function frequencyTest(bs) {
  const n = bs.length, ones = bs.split("").filter(b => b === "1").length;
  const sObs = Math.abs(ones - (n - ones)) / Math.sqrt(n), pVal = erfcApprox(sObs / Math.sqrt(2));
  return { name: "Frequency (monobit)", ones, zeros: n - ones, ratio: ((ones / n) * 100).toFixed(1), sObs: sObs.toFixed(4), pVal: pVal.toFixed(4), pass: pVal >= 0.01 };
}

/** Runs test — NIST SP 800-22 §2.3 */
export function runsTest(bs) {
  const n = bs.length, pi = bs.split("").filter(b => b === "1").length / n;
  let runs = 1;
  for (let i = 1; i < bs.length; i++) if (bs[i] !== bs[i - 1]) runs++;
  const vObs = Math.abs(runs - 2 * n * pi * (1 - pi)) / (2 * Math.sqrt(2 * n) * pi * (1 - pi) || 1), pVal = erfcApprox(vObs);
  return { name: "Runs", runs, expected: (2 * n * pi * (1 - pi)).toFixed(1), vObs: vObs.toFixed(4), pVal: pVal.toFixed(4), pass: pVal >= 0.01 };
}

/** Serial (digram) test — NIST SP 800-22 §2.11 */
export function serialTest(bs) {
  const counts = { "00": 0, "01": 0, "10": 0, "11": 0 };
  for (let i = 0; i < bs.length - 1; i++) { const k = bs[i] + bs[i + 1]; if (counts[k] !== undefined) counts[k]++; }
  const n = bs.length - 1, expected = n / 4;
  const chi2 = Object.values(counts).reduce((s, c) => s + (c - expected) ** 2 / (expected || 1), 0), pVal = chi2pval(chi2, 3);
  return { name: "Serial (digrams)", counts, chi2: chi2.toFixed(4), pVal: pVal.toFixed(4), pass: pVal >= 0.01 };
}
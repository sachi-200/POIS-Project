// ═══════════════════════════════════════════════════════════════════════════════
// PA #9 — Birthday Attack (Collision Finding)
// Two variants:
// 1) Naive sort-based: O(k log k) time, O(k) space
// 2) Floyd tortoise-hare: O(2^(n/2)) time, O(1) extra space
// Attacks the truncated PA #8 DLP hash.
// ═══════════════════════════════════════════════════════════════════════════════

import { dlpHash, setupGroup, DEMO_P, DEMO_Q } from "../pa8/crypto.js";

export const BIT_OPTIONS = [8, 10, 12, 14, 16];
export const DEFAULT_BITS = 12;

const PROGRESS_YIELD_EVERY = 24;
const DEFAULT_MAX_MULTIPLIER = 24;
const DEFAULT_MAX_RESTARTS = 8;

function sleepNextTick() {
  return new Promise(resolve => setTimeout(resolve, 0));
}

function randomInt(maxExclusive) {
  return Math.floor(Math.random() * maxExclusive);
}

function randomHexBytes(byteLen = 8) {
  let out = "";
  for (let i = 0; i < byteLen; i += 1) {
    out += randomInt(256).toString(16).padStart(2, "0");
  }
  return out;
}

function normalizeBits(nBits) {
  if (BIT_OPTIONS.includes(nBits)) return nBits;
  return DEFAULT_BITS;
}

function normalizeHashOutput(raw, nBits) {
  const width = Math.ceil(nBits / 4);
  const mask = (1 << nBits) - 1;

  if (raw && typeof raw === "object" && raw.value !== undefined) {
    const value = Number(raw.value) & mask;
    const digestHex = (raw.digestHex || value.toString(16)).toString(16).padStart(width, "0").slice(-width);
    return { value, digestHex };
  }

  if (typeof raw === "number") {
    const value = raw & mask;
    return { value, digestHex: value.toString(16).padStart(width, "0") };
  }

  const clean = String(raw || "").replace(/^0x/i, "").replace(/[^0-9a-fA-F]/g, "");
  const parsed = Number.parseInt(clean || "0", 16) >>> 0;
  const value = parsed & mask;
  return { value, digestHex: value.toString(16).padStart(width, "0") };
}

function makeProgressTicker(onProgress) {
  let next = 1;
  return async function tick(count, force = false) {
    if (!onProgress) return;
    if (force || count >= next) {
      onProgress(count);
      next = count + PROGRESS_YIELD_EVERY;
      await sleepNextTick();
    }
  };
}

function stateToInputHex(state, nBits) {
  const width = Math.max(2, Math.ceil(nBits / 4));
  return `0x${state.toString(16).padStart(width, "0")}`;
}

function getMaxEvaluations(nBits, maxEvaluations) {
  if (maxEvaluations && maxEvaluations > 0) return maxEvaluations;
  const expected = expectedBirthdayCount(nBits);
  return Math.max(512, Math.ceil(expected * DEFAULT_MAX_MULTIPLIER));
}

export function expectedBirthdayCount(nBits) {
  return Math.pow(2, normalizeBits(nBits) / 2);
}

export function theoreticalCollisionProbability(k, nBits) {
  const n = normalizeBits(nBits);
  const num = k * Math.max(k - 1, 0);
  const den = Math.pow(2, n + 1);
  return 1 - Math.exp(-num / den);
}

export function createPA9Params() {
  return setupGroup(DEMO_P, DEMO_Q);
}

export function truncateHashToNBits(hashHex, nBits) {
  const n = normalizeBits(nBits);
  const clean = String(hashHex || "").replace(/^0x/i, "").replace(/[^0-9a-fA-F]/g, "");
  const parsed = Number.parseInt(clean || "0", 16) >>> 0;
  const value = parsed & ((1 << n) - 1);
  return {
    value,
    digestHex: value.toString(16).padStart(Math.ceil(n / 4), "0"),
  };
}

export function makeTruncatedPA8Hash(params, nBits) {
  const n = normalizeBits(nBits);
  return function truncatedHash(inputHex) {
    const full = dlpHash(inputHex, params);
    return truncateHashToNBits(full, n);
  };
}

function makeHashEvaluator({ nBits, params, hashEvaluator }) {
  if (!hashEvaluator) return makeTruncatedPA8Hash(params, nBits);
  return inputHex => normalizeHashOutput(hashEvaluator(inputHex), nBits);
}

export async function runNaiveSortBirthdayAttack({
  nBits = DEFAULT_BITS,
  params = createPA9Params(),
  maxEvaluations,
  onProgress,
  shouldCancel,
  hashEvaluator,
}) {
  const n = normalizeBits(nBits);
  const expected = expectedBirthdayCount(n);
  const maxEval = getMaxEvaluations(n, maxEvaluations);
  const evalHash = makeHashEvaluator({ nBits: n, params, hashEvaluator });

  const ticker = makeProgressTicker(onProgress);
  const samples = [];
  const seenByDigest = new Map();

  let evalCount = 0;
  let candidateFound = false;
  let fallbackLeft = null;
  let fallbackRight = null;
  let fallbackDigestHex = null;

  while (evalCount < maxEval) {
    if (shouldCancel && shouldCancel()) {
      await ticker(evalCount, true);
      return {
        found: false,
        cancelled: true,
        algorithm: "naive-sort",
        nBits: n,
        count: evalCount,
        expected,
      };
    }

    const input = `0x${randomHexBytes(8)}`;
    const digest = evalHash(input);
    samples.push({ input, value: digest.value, digestHex: digest.digestHex });
    evalCount += 1;

    const prev = seenByDigest.get(digest.value);
    if (prev && prev !== input) {
      candidateFound = true;
      fallbackLeft = prev;
      fallbackRight = input;
      fallbackDigestHex = digest.digestHex;
      await ticker(evalCount, true);
      break;
    }
    if (!prev) seenByDigest.set(digest.value, input);

    await ticker(evalCount, false);
  }

  if (candidateFound) {
    const sorted = [...samples].sort((a, b) => {
      if (a.value !== b.value) return a.value - b.value;
      return a.input.localeCompare(b.input);
    });

    for (let i = 1; i < sorted.length; i += 1) {
      const left = sorted[i - 1];
      const right = sorted[i];
      if (left.value === right.value && left.input !== right.input) {
        return {
          found: true,
          cancelled: false,
          algorithm: "naive-sort",
          nBits: n,
          count: evalCount,
          expected,
          ratio: evalCount / expected,
          input1: left.input,
          input2: right.input,
          digestHex: right.digestHex,
        };
      }
    }

    return {
      found: true,
      cancelled: false,
      algorithm: "naive-sort",
      nBits: n,
      count: evalCount,
      expected,
      ratio: evalCount / expected,
      input1: fallbackLeft,
      input2: fallbackRight,
      digestHex: fallbackDigestHex || "0",
    };
  }

  await ticker(evalCount, true);
  return {
    found: false,
    cancelled: false,
    algorithm: "naive-sort",
    nBits: n,
    count: evalCount,
    expected,
  };
}

export async function runFloydBirthdayAttack({
  nBits = DEFAULT_BITS,
  params = createPA9Params(),
  maxEvaluations,
  maxRestarts = DEFAULT_MAX_RESTARTS,
  onProgress,
  shouldCancel,
  hashEvaluator,
}) {
  const n = normalizeBits(nBits);
  const expected = expectedBirthdayCount(n);
  const maxEval = getMaxEvaluations(n, maxEvaluations);
  const evalHash = makeHashEvaluator({ nBits: n, params, hashEvaluator });
  const ticker = makeProgressTicker(onProgress);

  const domainSize = 1 << n;
  let evalCount = 0;

  const step = (state) => {
    const digest = evalHash(stateToInputHex(state, n));
    evalCount += 1;
    return digest.value;
  };

  for (let restart = 0; restart < maxRestarts; restart += 1) {
    if (shouldCancel && shouldCancel()) {
      await ticker(evalCount, true);
      return {
        found: false,
        cancelled: true,
        algorithm: "floyd",
        nBits: n,
        count: evalCount,
        expected,
      };
    }

    const seed = randomInt(domainSize);

    let tortoise = step(seed);
    let hare = step(step(seed));
    await ticker(evalCount, false);

    while (tortoise !== hare && evalCount < maxEval) {
      if (shouldCancel && shouldCancel()) {
        await ticker(evalCount, true);
        return {
          found: false,
          cancelled: true,
          algorithm: "floyd",
          nBits: n,
          count: evalCount,
          expected,
        };
      }
      tortoise = step(tortoise);
      hare = step(step(hare));
      await ticker(evalCount, false);
    }

    if (evalCount >= maxEval) break;

    let mu = 0;
    tortoise = seed;
    while (tortoise !== hare && evalCount < maxEval) {
      tortoise = step(tortoise);
      hare = step(hare);
      mu += 1;
      await ticker(evalCount, false);
    }

    if (evalCount >= maxEval) break;

    let lambda = 1;
    hare = step(tortoise);
    while (tortoise !== hare && evalCount < maxEval) {
      hare = step(hare);
      lambda += 1;
      await ticker(evalCount, false);
    }

    if (evalCount >= maxEval) break;

    if (mu === 0) {
      // Rare edge case: no strict predecessor before the cycle entry.
      continue;
    }

    let a = seed;
    for (let i = 0; i < mu - 1 && evalCount < maxEval; i += 1) {
      a = step(a);
      await ticker(evalCount, false);
    }

    if (evalCount >= maxEval) break;

    let b = seed;
    for (let i = 0; i < mu + lambda - 1 && evalCount < maxEval; i += 1) {
      b = step(b);
      await ticker(evalCount, false);
    }

    if (evalCount >= maxEval) break;

    const outA = step(a);
    const outB = step(b);
    await ticker(evalCount, true);

    if (a !== b && outA === outB) {
      return {
        found: true,
        cancelled: false,
        algorithm: "floyd",
        nBits: n,
        count: evalCount,
        expected,
        ratio: evalCount / expected,
        input1: stateToInputHex(a, n),
        input2: stateToInputHex(b, n),
        digestHex: outA.toString(16).padStart(Math.ceil(n / 4), "0"),
        mu,
        lambda,
        restartsUsed: restart,
      };
    }
  }

  await ticker(evalCount, true);
  return {
    found: false,
    cancelled: false,
    algorithm: "floyd",
    nBits: n,
    count: evalCount,
    expected,
  };
}

export async function runBirthdayAttack({ variant = "naive-sort", ...args }) {
  if (variant === "floyd") {
    return runFloydBirthdayAttack(args);
  }
  return runNaiveSortBirthdayAttack(args);
}

export async function runAttackTrials({
  variant = "naive-sort",
  nBits = DEFAULT_BITS,
  numTrials = 1,
  params = createPA9Params(),
  maxEvaluations,
  onTrialComplete,
  shouldCancel,
  hashEvaluator,
}) {
  const n = normalizeBits(nBits);
  const results = [];

  for (let i = 0; i < numTrials; i += 1) {
    if (shouldCancel && shouldCancel()) break;

    const res = await runBirthdayAttack({
      variant,
      nBits: n,
      params,
      maxEvaluations,
      hashEvaluator,
    });

    results.push(res);
    if (onTrialComplete) onTrialComplete(i + 1, res);
  }

  const successful = results.filter(r => r.found);
  const counts = successful.map(r => r.count).sort((a, b) => a - b);
  const avg = counts.length
    ? counts.reduce((sum, c) => sum + c, 0) / counts.length
    : null;
  const mid = counts.length ? counts[Math.floor(counts.length / 2)] : null;

  return {
    variant,
    nBits: n,
    numTrials,
    completedTrials: results.length,
    successRate: results.length ? (successful.length / results.length) : 0,
    counts,
    averageCount: avg,
    medianCount: mid,
    results,
  };
}

export async function birthdayAttack(hashFn, nBits, numTrials = 1, options = {}) {
  const n = normalizeBits(nBits);
  const wrapper = hashFn
    ? inputHex => normalizeHashOutput(hashFn(inputHex), n)
    : options.hashEvaluator;

  return runAttackTrials({
    variant: options.variant || "naive-sort",
    nBits: n,
    numTrials,
    params: options.params || createPA9Params(),
    maxEvaluations: options.maxEvaluations,
    onTrialComplete: options.onTrialComplete,
    shouldCancel: options.shouldCancel,
    hashEvaluator: wrapper,
  });
}

// Lightweight LCS diff for the Comparer, with word / char / line granularity.

export type DiffOp = { t: "eq" | "del" | "add"; v: string };
export type DiffMode = "word" | "char" | "line";

function tokenize(s: string, mode: DiffMode): string[] {
  s = s ?? "";
  if (mode === "char") return Array.from(s);
  if (mode === "line") return s.match(/[^\n]*\n|[^\n]+/g) || [];
  return s.match(/\s+|\S+/g) || []; // word (whitespace preserved as tokens)
}

function lcsDiff(a: string[], b: string[]): DiffOp[] {
  const n = a.length, m = b.length;
  // DP table of LCS lengths.
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let jj = m - 1; jj >= 0; jj--) {
      dp[i][jj] = a[i] === b[jj] ? dp[i + 1][jj + 1] + 1 : Math.max(dp[i + 1][jj], dp[i][jj + 1]);
    }
  }
  const ops: DiffOp[] = [];
  let i = 0, jj = 0;
  const push = (t: DiffOp["t"], v: string) => {
    const last = ops[ops.length - 1];
    if (last && last.t === t) last.v += v;
    else ops.push({ t, v });
  };
  while (i < n && jj < m) {
    if (a[i] === b[jj]) { push("eq", a[i]); i++; jj++; }
    else if (dp[i + 1][jj] >= dp[i][jj + 1]) { push("del", a[i]); i++; }
    else { push("add", b[jj]); jj++; }
  }
  while (i < n) { push("del", a[i]); i++; }
  while (jj < m) { push("add", b[jj]); jj++; }
  return ops;
}

export interface DiffResult {
  ops: DiffOp[];
  mode: DiffMode;
  downgraded: boolean; // true if we fell back to a coarser mode for size
  truncated: boolean;  // true if inputs were too large and were clipped
  addCount: number;
  delCount: number;
}

export function diff(A: string, B: string, mode: DiffMode): DiffResult {
  A = A ?? ""; B = B ?? "";
  let a = tokenize(A, mode);
  let b = tokenize(B, mode);
  let used: DiffMode = mode;
  let downgraded = false;
  let truncated = false;
  // Guard 1: O(n*m) memory. Fall back to line mode for very large inputs.
  const SOFT = 3_000_000;
  if (a.length * b.length > SOFT && mode !== "line") {
    a = tokenize(A, "line");
    b = tokenize(B, "line");
    used = "line";
    downgraded = true;
  }
  // Guard 2: even in line mode two huge files can blow past what an O(n*m)
  // matrix can allocate — `new Array(m+1)` then throws RangeError / OOM and
  // (without this) would blank the whole app. Clip both sides to keep the DP
  // table bounded. The diff is then partial but the UI stays alive.
  const HARD = 6_000_000;
  if (a.length * b.length > HARD) {
    const cap = Math.max(50, Math.floor(Math.sqrt(HARD)));
    if (a.length > cap) { a = a.slice(0, cap); truncated = true; }
    if (b.length > cap) { b = b.slice(0, cap); truncated = true; }
  }
  const ops = lcsDiff(a, b);
  let addCount = 0, delCount = 0;
  for (const o of ops) {
    if (o.t === "add") addCount++;
    else if (o.t === "del") delCount++;
  }
  return { ops, mode: used, downgraded, truncated, addCount, delCount };
}

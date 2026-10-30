import { useState } from "react";
import { api, IntruderResult, IntruderStatus } from "../api";
import { statusClass, sortBy, SortDir } from "../util";
import HttpView from "./HttpView";
import { useT } from "../i18n";

const RACC: Record<string, (r: IntruderResult) => any> = {
  index: (r) => r.index,
  payload: (r) => r.payloads.join(" , "),
  status: (r) => r.status_code,
  length: (r) => r.resp_length,
  ms: (r) => r.duration_ms,
  grep: (r) => r.matched,
  retry: (r) => r.retries || 0,
  error: (r) => r.error || "",
};
const RNUM = new Set(["index", "status", "length", "ms", "grep", "retry"]);

function download(text: string, name: string, mime: string) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function stamp(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

function exportCsv(rows: IntruderResult[]) {
  const header = ["index", "payloads", "status", "length", "ms", "grep", "retries", "error"];
  const esc = (s: any) => '"' + String(s ?? "").replace(/"/g, '""') + '"';
  const lines = [header.join(",")];
  for (const r of rows) {
    lines.push([
      r.index,
      r.payloads.join(" | "),
      r.status_code,
      r.resp_length,
      r.duration_ms,
      r.matches.join(" "),
      r.retries || 0,
      r.error || "",
    ].map(esc).join(","));
  }
  // BOM so Excel reads UTF-8 (keeps Japanese payloads readable).
  download("﻿" + lines.join("\r\n"), `intruder-${stamp()}.csv`, "text/csv;charset=utf-8");
}

function exportJson(rows: IntruderResult[]) {
  download(JSON.stringify(rows, null, 2), `intruder-${stamp()}.json`, "application/json");
}

interface Props {
  attackId: string | null;
  status: IntruderStatus | null;
  results: IntruderResult[];
  /** Optional pop-out handler; omitted inside the pop-out window itself. */
  onPopOut?: () => void;
}

export default function IntruderResults({ attackId, status, results: allResults, onPopOut }: Props) {
  const t = useT();
  const [sortCol, setSortCol] = useState("index");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [q, setQ] = useState("");
  const [selIdx, setSelIdx] = useState<number | null>(null);
  const [selDetail, setSelDetail] = useState<{ request: string; response: string } | null>(null);

  function onSort(c: string) {
    if (c === sortCol) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortCol(c); setSortDir(RNUM.has(c) ? "desc" : "asc"); }
  }
  const RTh = ({ c, label }: { c: string; label: string }) => (
    <th style={{ cursor: "pointer", userSelect: "none" }} onClick={() => onSort(c)}>
      {label}{sortCol === c ? (sortDir === "asc" ? " ▲" : " ▼") : ""}
    </th>
  );

  async function selectResult(index: number) {
    setSelIdx(index);
    setSelDetail(null);
    if (!attackId) return;
    try { setSelDetail(await api.intruderResultDetail(attackId, index)); }
    catch { /* ignore */ }
  }

  const sortedAll: IntruderResult[] = sortBy(allResults, RACC[sortCol] || RACC.index, sortDir);
  const results: IntruderResult[] = q
    ? sortedAll.filter((r) => {
        const hay = (r.payloads.join(" ") + " " + r.status_code + " " + r.resp_length + " " + (r.error || "")).toLowerCase();
        return hay.includes(q.toLowerCase());
      })
    : sortedAll;
  const sel = allResults.find((r) => r.index === selIdx) || null;

  return (
    <div style={{ marginTop: 12 }}>
      <div className="toolbar" style={{ borderRadius: 6, flexWrap: "wrap" }}>
        <b>{t("結果", "Results")}</b>
        <input type="text" placeholder={t("検索 (payload / status / length / error)", "Search (payload / status / length / error)")} value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 220 }} />
        <span className="muted">{results.length}{q ? ` / ${sortedAll.length}` : ""} {t("件", "")}</span>
        <div className="spacer" style={{ flex: 1 }} />
        <button onClick={() => exportCsv(sortedAll)} disabled={!allResults.length} title={t("表示中の全結果をCSVで保存", "Save all results as CSV")}>⭳ CSV</button>
        <button onClick={() => exportJson(sortedAll)} disabled={!allResults.length} title={t("表示中の全結果をJSONで保存", "Save all results as JSON")}>⭳ JSON</button>
        {onPopOut && (
          <button onClick={onPopOut} disabled={!attackId} title={t("結果を新しいウィンドウで開く", "Open results in a new window")}>⧉ {t("別ウィンドウ", "Pop out")}</button>
        )}
      </div>
      <div className="table-wrap" style={{ maxHeight: "48vh", border: "1px solid var(--border)", borderRadius: 6 }}>
        <table className="grid">
          <thead>
            <tr>
              <RTh c="index" label="#" />
              <RTh c="payload" label="payload" />
              <RTh c="status" label="status" />
              <RTh c="length" label="length" />
              <RTh c="ms" label="ms" />
              <RTh c="grep" label="grep" />
              <RTh c="retry" label="↻" />
              <RTh c="error" label="error" />
            </tr>
          </thead>
          <tbody>
            {results.map((r) => (
              <tr key={r.index} className={selIdx === r.index ? "sel" : ""} onClick={() => selectResult(r.index)}>
                <td className="mono">{r.index}</td>
                <td className="mono">{r.payloads.join(" , ")}</td>
                <td className={"mono " + statusClass(r.status_code)}>{r.status_code || "-"}</td>
                <td className="mono">{r.resp_length}</td>
                <td className="mono muted">{r.duration_ms}</td>
                <td className={r.matched ? "scope-yes" : "scope-no"}>{r.matched ? "● " + r.matches.join(",") : ""}</td>
                <td className="mono muted" style={{ color: r.retries ? "var(--amber, #c90)" : undefined }}>{r.retries ? "↻" + r.retries : ""}</td>
                <td className="muted" style={{ color: r.error ? "var(--red)" : undefined }}>{r.error}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {sel && (
        <div className="repeater-cols" style={{ marginTop: 10 }}>
          <div className="repeater-col">
            <div className="row" style={{ marginBottom: 4 }}>
              <b>Request</b><span className="muted mono">payload: {sel.payloads.join(" , ")}</span>
            </div>
            <div style={{ border: "1px solid var(--border)", borderRadius: 6, overflow: "auto", maxHeight: "40vh" }}>
              <HttpView raw={selDetail ? selDetail.request : t("読み込み中…", "Loading…")} />
            </div>
          </div>
          <div className="repeater-col">
            <div className="row" style={{ marginBottom: 4 }}>
              <b>Response</b>
              <span className={"mono " + statusClass(sel.status_code)}>{sel.status_code || "-"}</span>
              <span className="muted mono">{sel.resp_length}B · {sel.duration_ms}ms{sel.retries ? ` · ↻${sel.retries}` : ""}</span>
            </div>
            <div style={{ border: "1px solid var(--border)", borderRadius: 6, overflow: "auto", maxHeight: "40vh" }}>
              <HttpView raw={selDetail ? selDetail.response : (sel.error ? t("(送信エラー) ", "(send error) ") + sel.error : t("読み込み中…", "Loading…"))} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

import { useEffect, useRef, useState } from "react";
import { api, FlowSummary, FlowDetail } from "../api";
import { statusClass, fmtTime, fmtBytes, rawRequest, rawResponse, sortBy, SortDir } from "../util";
import HttpView from "./HttpView";
import { useT } from "../i18n";

const ACC: Record<string, (f: FlowSummary) => any> = {
  id: (f) => f.id,
  time: (f) => f.created_at || "",
  src: (f) => f.source,
  method: (f) => f.method,
  host: (f) => f.host,
  path: (f) => { try { return new URL(f.url).pathname; } catch { return f.url; } },
  code: (f) => f.status_code,
  type: (f) => f.mime || "",
  len: (f) => f.resp_length,
  ms: (f) => f.duration_ms,
  scope: (f) => f.in_scope,
};
const NUM = new Set(["id", "time", "code", "len", "ms", "scope"]);

interface Props {
  flows: FlowSummary[];
  onRefresh: () => void;
  sendToRepeater: (d: FlowDetail) => void;
  sendToIntruder: (d: FlowDetail) => void;
  sendToComparer: (text: string) => void;
  sendToScanner: (d: FlowDetail) => void;
}

export default function HistoryView({ flows, onRefresh, sendToRepeater, sendToIntruder, sendToComparer, sendToScanner }: Props) {
  const t = useT();
  const [sel, setSel] = useState<number | null>(null);
  const [detail, setDetail] = useState<FlowDetail | null>(null);
  const [q, setQ] = useState("");
  const [methodF, setMethodF] = useState("");
  const [sourceF, setSourceF] = useState("");
  const [sortCol, setSortCol] = useState("id");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  function onSort(c: string) {
    if (c === sortCol) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortCol(c); setSortDir(NUM.has(c) ? "desc" : "asc"); }
  }

  // Resizable columns (drag the divider at a header's right edge).
  const DEFAULT_W: Record<string, number> = {
    id: 52, time: 74, src: 62, method: 66, host: 200, path: 380,
    code: 54, type: 130, len: 74, ms: 52, scope: 54,
  };
  const [widths, setWidths] = useState<Record<string, number>>(() => {
    try { const s = localStorage.getItem("hist_widths"); return s ? { ...DEFAULT_W, ...JSON.parse(s) } : DEFAULT_W; }
    catch { return DEFAULT_W; }
  });
  useEffect(() => { try { localStorage.setItem("hist_widths", JSON.stringify(widths)); } catch { /* ignore */ } }, [widths]);
  const drag = useRef<{ col: string; startX: number; startW: number } | null>(null);
  function startResize(e: React.MouseEvent, col: string) {
    e.preventDefault(); e.stopPropagation();
    drag.current = { col, startX: e.clientX, startW: widths[col] || 100 };
    const move = (ev: MouseEvent) => {
      if (!drag.current) return;
      const w = Math.max(36, drag.current.startW + (ev.clientX - drag.current.startX));
      setWidths((p) => ({ ...p, [drag.current!.col]: w }));
    };
    const up = () => { drag.current = null; window.removeEventListener("mousemove", move); window.removeEventListener("mouseup", up); };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  }
  // `code` (status) sits right after `method` — before the wide host/path
  // columns — so it stays visible without scrolling right.
  const COLS = ["id", "time", "src", "method", "code", "host", "path", "type", "len", "ms", "scope"];
  const Th = ({ c, label }: { c: string; label: string }) => (
    <th style={{ cursor: "pointer", userSelect: "none" }} onClick={() => onSort(c)}>
      {label}{sortCol === c ? (sortDir === "asc" ? " ▲" : " ▼") : ""}
      <span className="col-resizer" onMouseDown={(e) => startResize(e, c)} onClick={(e) => e.stopPropagation()} />
    </th>
  );

  useEffect(() => {
    if (sel == null) return;
    api.flow(sel).then(setDetail).catch(() => setDetail(null));
  }, [sel]);

  const filtered = flows.filter((f) => {
    if (methodF && f.method !== methodF) return false;
    if (sourceF && f.source !== sourceF) return false;
    if (q && !(f.url.toLowerCase().includes(q.toLowerCase()))) return false;
    return true;
  });
  const sorted = sortBy(filtered, ACC[sortCol] || ACC.id, sortDir);

  return (
    <div className="split-h">
      <div className="split-v pane left">
        <div className="toolbar">
          <input
            type="text"
            placeholder={t("URL 検索 (filter)", "URL filter")}
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          <select value={methodF} onChange={(e) => setMethodF(e.target.value)}>
            <option value="">method: all</option>
            {["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"].map((m) => (
              <option key={m} value={m}>{m}</option>
            ))}
          </select>
          <select value={sourceF} onChange={(e) => setSourceF(e.target.value)}>
            <option value="">source: all</option>
            <option value="proxy">proxy</option>
            <option value="repeater">repeater</option>
            <option value="intruder">intruder</option>
            <option value="scanner">scanner</option>
          </select>
          <span className="muted">{filtered.length} / {flows.length}</span>
          <div className="spacer" style={{ flex: 1 }} />
          <button onClick={onRefresh}>↻ {t("更新", "Refresh")}</button>
          <button
            className="danger"
            onClick={async () => {
              if (confirm(t("履歴をすべて削除しますか?", "Clear all history?"))) {
                await api.clearFlows();
                setSel(null);
                setDetail(null);
                onRefresh();
              }
            }}
          >
            {t("クリア", "Clear")}
          </button>
        </div>
        <div className="table-wrap" style={{ flex: 1 }}>
          <table className="grid resizable">
            <colgroup>
              {COLS.map((c) => <col key={c} style={{ width: (widths[c] || 80) + "px" }} />)}
            </colgroup>
            <thead>
              <tr>
                <Th c="id" label="#" />
                <Th c="time" label="time" />
                <Th c="src" label="src" />
                <Th c="method" label="method" />
                <Th c="code" label="code" />
                <Th c="host" label="host" />
                <Th c="path" label="path" />
                <Th c="type" label="type" />
                <Th c="len" label="len" />
                <Th c="ms" label="ms" />
                <Th c="scope" label="scope" />
              </tr>
            </thead>
            <tbody>
              {sorted.map((f) => {
                let path = f.url;
                try { path = new URL(f.url).pathname; } catch { /* keep */ }
                return (
                  <tr key={f.id} data-flow-id={f.id} className={sel === f.id ? "sel" : ""} onClick={() => setSel(f.id)}>
                    <td className="mono">{f.id}</td>
                    <td className="mono">{fmtTime(f.created_at)}</td>
                    <td className={f.source === "proxy" ? "src-proxy" : "src-repeater"}>{f.source}</td>
                    <td className="mono">{f.method}</td>
                    <td className={"mono " + statusClass(f.status_code)}>{f.status_code || "-"}</td>
                    <td title={f.host}>{f.host}</td>
                    <td className="url mono" title={path}>{path}</td>
                    <td className="muted">{(f.mime || "").split(";")[0]}</td>
                    <td className="mono">{fmtBytes(f.resp_length)}</td>
                    <td className="mono muted">{f.duration_ms}</td>
                    <td className={f.in_scope ? "scope-yes" : "scope-no"}>{f.in_scope ? "●" : "○"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div className="pane detail">
        {!detail ? (
          <div className="section muted">{t("行を選択すると詳細が表示されます。", "Select a row to see details.")}</div>
        ) : (
          <>
            <div className="toolbar">
              <span className="mono">{detail.method} {detail.host}</span>
              <div className="spacer" style={{ flex: 1 }} />
              <button onClick={() => sendToComparer(rawResponse(detail.status_code, detail.reason, detail.resp_headers, detail.resp_body))}>→ Comparer</button>
              <button onClick={() => sendToScanner(detail)}>→ Scanner</button>
              <button onClick={() => sendToIntruder(detail)}>→ Intruder</button>
              <button className="primary" onClick={() => sendToRepeater(detail)}>→ Repeater</button>
            </div>
            <div className="msg">
              <h4>Request</h4>
              <HttpView raw={rawRequest(detail.method, detail.path, detail.req_headers, detail.req_body)} />
            </div>
            <div className="msg">
              <h4>
                Response {detail.resp_body_truncated ? t("(本文は保存上限で切り詰め)", "(body truncated at store limit)") : ""}
              </h4>
              <HttpView raw={rawResponse(detail.status_code, detail.reason, detail.resp_headers, detail.resp_body)} />
            </div>
          </>
        )}
      </div>
    </div>
  );
}

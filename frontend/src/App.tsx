import { useCallback, useEffect, useRef, useState, ReactNode } from "react";
import { api, FlowSummary, FlowDetail, PendingIntercept, ScopeRule } from "./api";
import { rawResponse } from "./util";
import { useT, useLang } from "./i18n";
import ContextMenu, { CtxItem } from "./components/ContextMenu";
import ErrorBoundary from "./components/ErrorBoundary";
import HistoryView from "./components/HistoryView";
import InterceptView from "./components/InterceptView";
import RepeaterView from "./components/RepeaterView";
import IntruderView from "./components/IntruderView";
import DecoderView from "./components/DecoderView";
import ComparerView from "./components/ComparerView";
import ScannerView from "./components/ScannerView";
import SitemapView from "./components/SitemapView";
import WebSocketView from "./components/WebSocketView";
import ScopeView from "./components/ScopeView";
import HelpView from "./components/HelpView";

type Tab = "history" | "intercept" | "repeater" | "intruder" | "decoder" | "comparer" | "scanner" | "sitemap" | "websocket" | "scope" | "help";

function Pane({ show, label, children }: { show: boolean; label?: string; children: ReactNode }) {
  // Each pane is isolated: a render error here shows a recoverable card instead
  // of unmounting the whole app (all panes are mounted at once).
  return (
    <div className={"view-pane" + (show ? "" : " hidden")}>
      <ErrorBoundary label={label}>{children}</ErrorBoundary>
    </div>
  );
}

const FLOW_CAP = 1000;
// Merge newly-seen flows into the list, de-duped by id and newest-first.
// Returns the SAME array reference when nothing is new, so React skips the
// re-render — the history grid stays cheap even while polling every few seconds.
function mergeFlows(prev: FlowSummary[], incoming: FlowSummary[]): FlowSummary[] {
  if (!incoming || incoming.length === 0) return prev;
  const seen = new Set(prev.map((f) => f.id));
  const add = incoming.filter((f) => f && !seen.has(f.id));
  if (add.length === 0) return prev;
  const merged = add.concat(prev);
  merged.sort((a, b) => b.id - a.id);
  return merged.length > FLOW_CAP ? merged.slice(0, FLOW_CAP) : merged;
}

export default function App() {
  const t = useT();
  const { lang, setLang } = useLang();
  const [tab, setTab] = useState<Tab>("history");
  const [flows, setFlows] = useState<FlowSummary[]>([]);
  const [status, setStatus] = useState<any>(null);
  const [interceptEnabled, setInterceptEnabled] = useState(false);
  const [pending, setPending] = useState<PendingIntercept[]>([]);
  const [scope, setScope] = useState<ScopeRule[]>([]);
  const [seed, setSeed] = useState<FlowDetail | null>(null);
  const [intruderSeed, setIntruderSeed] = useState<FlowDetail | null>(null);
  const [comparerSeed, setComparerSeed] = useState<string | null>(null);
  const [scannerSeed, setScannerSeed] = useState<FlowDetail | null>(null);
  const [decoderSeed, setDecoderSeed] = useState<string | null>(null);
  const [wsSeed, setWsSeed] = useState<{ url: string; headers: [string, string][] } | null>(null);
  const [menu, setMenu] = useState<{ x: number; y: number; items: CtxItem[] } | null>(null);
  const [toast, setToast] = useState("");
  const wsRef = useRef<WebSocket | null>(null);

  function showToast(m: string) {
    setToast(m);
    window.setTimeout(() => setToast(""), 2500);
  }

  const refreshFlows = useCallback(() => {
    api.flows({ limit: 500 }).then(setFlows).catch(() => {});
  }, []);
  const refreshIntercept = useCallback(() => {
    api.intercept().then((d) => {
      setInterceptEnabled(d.enabled);
      setPending(d.pending);
    }).catch(() => {});
  }, []);
  const refreshScope = useCallback(() => {
    api.scope().then(setScope).catch(() => {});
  }, []);

  // Track the highest flow id we hold, so polling only asks for newer rows.
  const maxIdRef = useRef(0);
  useEffect(() => {
    let m = 0;
    for (const f of flows) if (f.id > m) m = f.id;
    maxIdRef.current = m;
  }, [flows]);

  useEffect(() => {
    refreshFlows();
    refreshIntercept();
    refreshScope();
    // Status poll, single-flight so a slow backend never stacks requests.
    let statusBusy = false;
    const pollStatus = async () => {
      if (statusBusy) return;
      statusBusy = true;
      try { setStatus(await api.status()); } catch { /* ignore */ } finally { statusBusy = false; }
    };
    pollStatus();
    const t = setInterval(pollStatus, 4000);
    return () => clearInterval(t);
  }, []);

  // History self-heals: poll for new flows incrementally regardless of the
  // WebSocket. Single-flight + visibility-gated so it never piles up or runs
  // in a hidden tab. This is what keeps HTTP history current even if a push
  // was missed or the socket was briefly down.
  useEffect(() => {
    let stop = false;
    let busy = false;
    const poll = async () => {
      if (stop || busy || document.hidden) return;
      busy = true;
      try {
        const rows = await api.flows({ since_id: maxIdRef.current, limit: 500 });
        if (!stop && rows.length) setFlows((prev) => mergeFlows(prev, rows));
      } catch { /* ignore */ } finally { busy = false; }
    };
    const iv = setInterval(poll, 3500);
    const onVis = () => { if (!document.hidden) poll(); };
    document.addEventListener("visibilitychange", onVis);
    return () => { stop = true; clearInterval(iv); document.removeEventListener("visibilitychange", onVis); };
  }, []);

  // WebSocket for realtime updates, with auto-reconnect (backoff). The polling
  // fallback above covers any gap while the socket is down.
  useEffect(() => {
    let stop = false;
    let ws: WebSocket | null = null;
    let attempt = 0;
    let timer: number | undefined;
    const connect = () => {
      if (stop) return;
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/ws`);
      wsRef.current = ws;
      ws.onopen = () => { attempt = 0; };
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data);
          if (msg.type === "flow") {
            setFlows((prev) => mergeFlows(prev, [msg.data]));
          } else if (msg.type === "hello") {
            setInterceptEnabled(msg.data.intercept_enabled);
            setPending(msg.data.pending || []);
          } else if (msg.type.startsWith("intercept")) {
            refreshIntercept();
          }
        } catch { /* ignore */ }
      };
      ws.onclose = () => {
        wsRef.current = null;
        if (stop) return;
        attempt = Math.min(attempt + 1, 6);
        const delay = Math.min(1000 * 2 ** (attempt - 1), 15000); // 1s→…→15s
        timer = window.setTimeout(connect, delay);
      };
      ws.onerror = () => { try { ws?.close(); } catch { /* ignore */ } };
    };
    connect();
    return () => {
      stop = true;
      if (timer) clearTimeout(timer);
      try { ws?.close(); } catch { /* ignore */ }
    };
  }, [refreshIntercept]);

  function sendToRepeater(d: FlowDetail) {
    setSeed(d);
    setTab("repeater");
  }
  function sendToIntruder(d: FlowDetail) {
    setIntruderSeed(d);
    setTab("intruder");
  }
  function sendToComparer(text: string) {
    setComparerSeed(text);
    setTab("comparer");
  }
  function sendToScanner(d: FlowDetail) {
    setScannerSeed(d);
    setTab("scanner");
  }
  function sendToDecoder(text: string) {
    setDecoderSeed(text);
    setTab("decoder");
  }
  function sendToWsRepeater(d: FlowDetail) {
    const wsUrl = d.url.replace(/^http:/i, "ws:").replace(/^https:/i, "wss:");
    setWsSeed({ url: wsUrl, headers: d.req_headers });
    setTab("websocket");
  }

  // Apply an encode/decode op to a text selection: replace in place inside a
  // textarea/input, otherwise copy the result to the clipboard.
  async function applyToSelection(
    op: string,
    sel: { text: string; el: HTMLTextAreaElement | HTMLInputElement | null; start: number; end: number }
  ) {
    let out = "";
    try {
      const r = await api.transform(op, sel.text);
      if (r.error) { showToast(t("変換エラー: ", "Transform error: ") + r.error); return; }
      out = r.output;
    } catch (e: any) { showToast(t("変換エラー: ", "Transform error: ") + String(e.message || e)); return; }

    if (sel.el) {
      sel.el.focus();
      try { sel.el.setSelectionRange(sel.start, sel.end); } catch { /* ignore */ }
      const ok = document.execCommand("insertText", false, out);
      if (ok) { showToast(t("選択箇所を置換しました", "Replaced selection")); return; }
    }
    try { await navigator.clipboard.writeText(out); showToast(t("結果をクリップボードにコピーしました", "Copied result to clipboard")); }
    catch { showToast(t("結果: ", "Result: ") + out.slice(0, 120)); }
  }

  function onContextMenu(e: React.MouseEvent) {
    // 1) text selection -> encode/decode menu
    const ae = document.activeElement as any;
    let selText = "", el: HTMLTextAreaElement | HTMLInputElement | null = null, start = 0, end = 0;
    if (ae && (ae.tagName === "TEXTAREA" || ae.tagName === "INPUT") &&
        typeof ae.selectionStart === "number" && ae.selectionStart !== ae.selectionEnd) {
      el = ae; start = ae.selectionStart; end = ae.selectionEnd; selText = ae.value.slice(start, end);
    } else {
      selText = window.getSelection?.()?.toString() || "";
    }
    if (selText.trim()) {
      e.preventDefault();
      const sel = { text: selText, el, start, end };
      const items: CtxItem[] = [
        { header: t(`選択 ${selText.length} 文字`, `${selText.length} chars selected`) },
        { header: t("エンコード", "Encode") },
        { label: t("URL エンコード", "URL encode"), onClick: () => applyToSelection("urlencode", sel) },
        { label: t("Base64 エンコード", "Base64 encode"), onClick: () => applyToSelection("b64encode", sel) },
        { label: t("HTML エンコード", "HTML encode"), onClick: () => applyToSelection("htmlencode", sel) },
        { label: t("Hex エンコード", "Hex encode"), onClick: () => applyToSelection("hexencode", sel) },
        { sep: true },
        { header: t("デコード", "Decode") },
        { label: t("URL デコード", "URL decode"), onClick: () => applyToSelection("urldecode", sel) },
        { label: t("Base64 デコード", "Base64 decode"), onClick: () => applyToSelection("b64decode", sel) },
        { label: t("HTML デコード", "HTML decode"), onClick: () => applyToSelection("htmldecode", sel) },
        { label: t("Hex デコード", "Hex decode"), onClick: () => applyToSelection("hexdecode", sel) },
        { sep: true },
        { label: t("Decoder で開く", "Open in Decoder"), onClick: () => sendToDecoder(selText) },
      ];
      setMenu({ x: e.clientX, y: e.clientY, items });
      return;
    }
    // 2) history row -> send-to menu
    const tr = (e.target as HTMLElement).closest?.("tr[data-flow-id]");
    if (tr) {
      e.preventDefault();
      const id = Number(tr.getAttribute("data-flow-id"));
      const withDetail = (fn: (d: FlowDetail) => void) => () => api.flow(id).then(fn).catch(() => showToast(t("取得に失敗しました", "Failed to load")));
      const items: CtxItem[] = [
        { header: `#${id}` },
        { label: t("→ Repeater へ送る", "→ Send to Repeater"), onClick: withDetail(sendToRepeater) },
        { label: t("→ Intruder へ送る", "→ Send to Intruder"), onClick: withDetail(sendToIntruder) },
        { label: t("→ Scanner へ送る", "→ Send to Scanner"), onClick: withDetail(sendToScanner) },
        { label: t("→ Comparer へ送る(レスポンス)", "→ Send to Comparer (response)"), onClick: withDetail((d) => sendToComparer(rawResponse(d.status_code, d.reason, d.resp_headers, d.resp_body))) },
        { label: t("→ WS Repeater へ送る", "→ Send to WS Repeater"), onClick: withDetail(sendToWsRepeater) },
      ];
      setMenu({ x: e.clientX, y: e.clientY, items });
      return;
    }
    // otherwise: allow the native menu
  }

  const statusCode = (n: number) => n;
  const proxyOk = status?.proxy_running;

  return (
    <div className="app" onContextMenu={onContextMenu}>
      <div className="topbar">
        <div className="brand">
          WebSec<span className="sub">local testing proxy · authorized use only</span>
        </div>
        <div className="spacer" />
        <span className={"pill " + (proxyOk ? "ok" : "off")}>
          proxy {proxyOk ? "●" : "○"} 127.0.0.1:{status?.proxy_port ?? "…"}
        </span>
        <span className={"pill " + (interceptEnabled ? "warn" : "off")}>
          intercept {interceptEnabled ? "ON" : "OFF"}
          {pending.length > 0 ? ` · ${pending.length}` : ""}
        </span>
        <span className="pill">{scope.filter((s) => s.enabled).length} scoped</span>
        <select value={lang} onChange={(e) => setLang(e.target.value as "ja" | "en")} style={{ marginLeft: 8, padding: "2px 6px" }}>
          <option value="ja">日本語</option>
          <option value="en">English</option>
        </select>
      </div>

      <div className="tabs">
        {([
          ["history", t("HTTP履歴", "HTTP history")],
          ["intercept", `Intercept${pending.length ? " (" + pending.length + ")" : ""}`],
          ["repeater", "Repeater"],
          ["intruder", "Intruder"],
          ["decoder", "Decoder"],
          ["comparer", "Comparer"],
          ["scanner", "Scanner"],
          ["sitemap", "Sitemap"],
          ["websocket", "WebSocket"],
          ["scope", "Scope"],
          ["help", t("設定/使い方", "Setup / Help")],
        ] as [Tab, string][]).map(([k, label]) => (
          <div key={k} className={"tab " + (tab === k ? "active" : "")} onClick={() => setTab(k)}>
            {label}
          </div>
        ))}
      </div>

      <div className="body">
        {/* All views stay mounted so inputs / running attacks survive tab switches. */}
        <Pane show={tab === "history"} label="history">
          <HistoryView flows={flows} onRefresh={refreshFlows} sendToRepeater={sendToRepeater} sendToIntruder={sendToIntruder} sendToComparer={sendToComparer} sendToScanner={sendToScanner} />
        </Pane>
        <Pane show={tab === "intercept"} label="intercept">
          <InterceptView enabled={interceptEnabled} pending={pending} onChanged={refreshIntercept} />
        </Pane>
        <Pane show={tab === "repeater"} label="repeater">
          <RepeaterView seed={seed} onSeedConsumed={() => setSeed(null)} />
        </Pane>
        <Pane show={tab === "intruder"} label="intruder">
          <IntruderView seed={intruderSeed} onSeedConsumed={() => setIntruderSeed(null)} />
        </Pane>
        <Pane show={tab === "decoder"} label="decoder"><DecoderView seed={decoderSeed} onSeedConsumed={() => setDecoderSeed(null)} /></Pane>
        <Pane show={tab === "comparer"} label="comparer">
          <ComparerView seed={comparerSeed} onSeedConsumed={() => setComparerSeed(null)} />
        </Pane>
        <Pane show={tab === "scanner"} label="scanner">
          <ScannerView seed={scannerSeed} onSeedConsumed={() => setScannerSeed(null)} />
        </Pane>
        <Pane show={tab === "sitemap"} label="sitemap"><SitemapView /></Pane>
        <Pane show={tab === "websocket"} label="websocket">
          <WebSocketView seed={wsSeed} onSeedConsumed={() => setWsSeed(null)} />
        </Pane>
        <Pane show={tab === "scope"} label="scope"><ScopeView rules={scope} onChanged={refreshScope} /></Pane>
        <Pane show={tab === "help"} label="help"><HelpView /></Pane>
      </div>

      {menu && <ContextMenu x={menu.x} y={menu.y} items={menu.items} onClose={() => setMenu(null)} />}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}

import { useEffect, useRef, useState } from "react";
import { api, WsMessageSummary, WsRepeaterStatus } from "../api";
import { fmtTime } from "../util";
import { useT } from "../i18n";

interface Props {
  seed: { url: string; headers: [string, string][] } | null;
  onSeedConsumed: () => void;
}

function headersToText(hs: [string, string][]): string {
  return hs.filter((h) => ["cookie", "authorization", "origin", "sec-websocket-protocol", "user-agent"].includes(h[0].toLowerCase()))
    .map(([k, v]) => `${k}: ${v}`).join("\n");
}
function parseHeaders(text: string): [string, string][] {
  const out: [string, string][] = [];
  for (const line of text.split(/\r?\n/)) {
    const c = line.indexOf(":");
    if (c > 0) out.push([line.slice(0, c).trim(), line.slice(c + 1).trim()]);
  }
  return out;
}

export default function WebSocketView({ seed, onSeedConsumed }: Props) {
  const t = useT();
  // history
  const [msgs, setMsgs] = useState<WsMessageSummary[]>([]);
  const [q, setQ] = useState("");
  const [selBody, setSelBody] = useState<string>("");

  // repeater
  const [url, setUrl] = useState("");
  const [hdrText, setHdrText] = useState("");
  const [message, setMessage] = useState("");
  const [cid, setCid] = useState<string | null>(null);
  const [rep, setRep] = useState<WsRepeaterStatus | null>(null);
  const [error, setError] = useState("");
  const seededRef = useRef<string | null>(null);
  const logRef = useRef<HTMLDivElement | null>(null);

  function refreshHistory() {
    api.wsMessages({ q }).then(setMsgs).catch(() => {});
  }
  useEffect(() => { refreshHistory(); const t = setInterval(refreshHistory, 3000); return () => clearInterval(t); /* eslint-disable-next-line */ }, [q]);

  useEffect(() => {
    if (seed && seededRef.current !== seed.url) {
      seededRef.current = seed.url;
      setUrl(seed.url);
      setHdrText(headersToText(seed.headers));
      onSeedConsumed();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [seed]);

  // poll repeater connection
  useEffect(() => {
    if (!cid) return;
    let live = true;
    const tick = async () => {
      try {
        const s = await api.wsRepeaterGet(cid);
        if (!live) return;
        setRep(s);
        if (s.status === "open") setTimeout(tick, 700);
      } catch { /* stop */ }
    };
    tick();
    return () => { live = false; };
  }, [cid]);

  useEffect(() => { if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight; }, [rep?.messages.length]);

  async function connect() {
    setError("");
    try {
      const r = await api.wsConnect(url, parseHeaders(hdrText));
      setCid(r.conn_id);
      setRep({ conn_id: r.conn_id, url: r.url, host: "", status: r.status, error: "", messages: [] });
    } catch (e: any) { setError(String(e.message || e)); }
  }
  async function disconnect() { if (cid) { await api.wsCloseConn(cid); } }
  async function send() {
    if (!cid) return;
    try { await api.wsSend(cid, message, true); } catch (e: any) { setError(String(e.message || e)); }
  }

  async function showBody(id: number) {
    try { const d = await api.wsMessageDetail(id); setSelBody(d.content); } catch { /* ignore */ }
  }

  const connected = rep?.status === "open";

  return (
    <div className="section" style={{ maxWidth: "unset" }}>
      <div className="banner info">
        {t("WebSocket の傍受履歴と、対象への接続・メッセージ送信(WS Repeater)。送信は Scope 登録済みホストのみ。HTTP履歴の 101(Upgrade)行を右クリック → WS Repeater へ送る で URL と Cookie を引き継げます。","WebSocket capture history plus connect-and-send (WS Repeater). Sends only to scoped hosts. Right-click a 101 (Upgrade) row in HTTP history → Send to WS Repeater to carry over URL and Cookie.")}
      </div>

      <div className="row" style={{ alignItems: "flex-start", gap: 12 }}>
        {/* history */}
        <div className="card" style={{ flex: 1, minWidth: 0 }}>
          <div className="row" style={{ marginBottom: 6 }}>
            <b>{t("傍受履歴","Capture history")}</b>
            <input type="text" placeholder={t("本文検索","Search body")} value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 120 }} />
            <span className="muted">{msgs.length}</span>
            <div className="spacer" style={{ flex: 1 }} />
            <button onClick={refreshHistory}>↻</button>
            <button className="danger" onClick={async () => { if (confirm(t("WS履歴を削除?","Clear WS history?"))) { await api.clearWsMessages(); refreshHistory(); } }}>{t("クリア","Clear")}</button>
          </div>
          <div className="table-wrap" style={{ maxHeight: "32vh", border: "1px solid var(--border)", borderRadius: 6 }}>
            <table className="grid">
              <thead><tr><th>time</th><th>dir</th><th>host</th><th>path</th><th>len</th><th>preview</th></tr></thead>
              <tbody>
                {msgs.map((m) => (
                  <tr key={m.id} onClick={() => showBody(m.id)}>
                    <td className="mono">{fmtTime(m.created_at)}</td>
                    <td className={m.from_client ? "src-repeater" : "src-proxy"}>{m.from_client ? t("↑送信","↑ sent") : t("↓受信","↓ recv")}</td>
                    <td className="mono">{m.host}</td>
                    <td className="mono" style={{ maxWidth: 160, overflow: "hidden", textOverflow: "ellipsis" }} title={m.path}>{m.path}</td>
                    <td className="mono">{m.length}</td>
                    <td className="mono muted" style={{ maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis" }} title={m.preview}>{m.preview}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {selBody && (
            <div style={{ marginTop: 8 }}>
              <label>{t("メッセージ内容","Message content")}</label>
              <pre className="raw" style={{ border: "1px solid var(--border)", borderRadius: 6, maxHeight: 160 }}>{selBody}</pre>
            </div>
          )}
        </div>

        {/* repeater */}
        <div className="card" style={{ flex: 1, minWidth: 0 }}>
          <b>WS Repeater</b>
          <div className="field" style={{ marginTop: 6 }}>
            <label>{t("URL (ws:// または wss://)","URL (ws:// or wss://)")}</label>
            <input type="text" value={url} placeholder="wss://example.com/chat" onChange={(e) => setUrl(e.target.value)} />
          </div>
          <div className="field" style={{ marginTop: 6 }}>
            <label>{t("ヘッダー (Cookie 等・1行1個)","Headers (Cookie etc., one per line)")}</label>
            <textarea style={{ width: "100%", minHeight: 56 }} value={hdrText} onChange={(e) => setHdrText(e.target.value)} spellCheck={false} />
          </div>
          <div className="row" style={{ marginTop: 6 }}>
            {!connected
              ? <button className="primary" onClick={connect}>{t("接続","Connect")}</button>
              : <button className="danger" onClick={disconnect}>{t("切断","Disconnect")}</button>}
            {rep && <span className={"pill " + (connected ? "ok" : "off")}>{rep.status}{rep.error ? " · " + rep.error : ""}</span>}
          </div>
          {error && <div className="banner warn" style={{ marginTop: 6 }}>{error}</div>}

          <div className="field" style={{ marginTop: 8 }}>
            <label>{t("送信メッセージ","Message to send")}</label>
            <textarea style={{ width: "100%", minHeight: 70 }} value={message} onChange={(e) => setMessage(e.target.value)} spellCheck={false} />
          </div>
          <div className="row" style={{ marginTop: 6 }}>
            <button className="primary" disabled={!connected} onClick={send}>▶ {t("送信","Send")}</button>
          </div>

          <label style={{ marginTop: 8, display: "block" }}>{t("メッセージログ","Message log")}</label>
          <div ref={logRef} style={{ border: "1px solid var(--border)", borderRadius: 6, maxHeight: "30vh", overflow: "auto", padding: 6, fontFamily: "var(--mono)", fontSize: 12 }}>
            {(rep?.messages || []).map((m, i) => (
              <div key={i} style={{ padding: "2px 0", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                <span className={m.dir === "out" ? "src-repeater" : "scope-yes"}>{m.dir === "out" ? "↑ " : "↓ "}</span>
                {m.binary ? <span className="muted">[hex] </span> : null}{m.text}
              </div>
            ))}
            {(!rep || rep.messages.length === 0) && <span className="muted">{t("接続して送信するとここに表示されます。","Connect and send to see messages here.")}</span>}
          </div>
        </div>
      </div>
    </div>
  );
}

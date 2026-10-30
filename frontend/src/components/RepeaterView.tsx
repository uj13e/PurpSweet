import { useEffect, useRef, useState } from "react";
import { api, FlowDetail, RepeaterResponse } from "../api";
import { rawRequest, parseRawRequest, rawResponse, statusClass } from "../util";
import HttpView from "./HttpView";
import { useT } from "../i18n";

interface RepTab {
  id: number;
  name: string;
  scheme: string;
  host: string;
  port: number;
  raw: string;
  responses: RepeaterResponse[];
  activeResp: number;
  sending: boolean;
  error: string;
}

let TAB_SEQ = 1;

function blankTab(): RepTab {
  return {
    id: TAB_SEQ++,
    name: `Tab ${TAB_SEQ - 1}`,
    scheme: "https",
    host: "",
    port: 0,
    raw: "GET / HTTP/1.1\nHost: example.com\n\n",
    responses: [],
    activeResp: 0,
    sending: false,
    error: "",
  };
}

interface Props {
  seed: FlowDetail | null;
  onSeedConsumed: () => void;
}

export default function RepeaterView({ seed, onSeedConsumed }: Props) {
  const t = useT();
  const [tabs, setTabs] = useState<RepTab[]>([blankTab()]);
  const [active, setActive] = useState(0);
  const seededId = useRef<number | null>(null);

  useEffect(() => {
    if (seed && seededId.current !== seed.id) {
      seededId.current = seed.id;
      const t = blankTab();
      t.name = `${seed.method} ${seed.host}`;
      t.scheme = seed.scheme || "https";
      t.host = seed.host;
      t.port = seed.port || 0;
      // ensure Host header present
      let headers = seed.req_headers;
      if (!headers.some((h) => h[0].toLowerCase() === "host")) {
        headers = [["Host", seed.host], ...headers];
      }
      t.raw = rawRequest(seed.method, seed.path, headers, seed.req_body);
      setTabs((prev) => [...prev, t]);
      setActive(tabs.length); // new tab index
      onSeedConsumed();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [seed]);

  const tab = tabs[active];

  function update(patch: Partial<RepTab>) {
    setTabs((prev) => prev.map((t, i) => (i === active ? { ...t, ...patch } : t)));
  }

  async function send() {
    if (!tab) return;
    const parsed = parseRawRequest(tab.raw);
    // derive host from Host header if not set explicitly
    let host = tab.host;
    if (!host) {
      const h = parsed.headers.find((x) => x[0].toLowerCase() === "host");
      if (h) host = h[1].split(":")[0];
    }
    update({ sending: true, error: "" });
    try {
      const resp = await api.repeaterSend({
        method: parsed.method,
        scheme: tab.scheme,
        host,
        port: tab.port,
        path: parsed.path,
        headers: parsed.headers,
        body: parsed.body,
      });
      setTabs((prev) =>
        prev.map((t, i) =>
          i === active
            ? { ...t, sending: false, host, responses: [resp, ...t.responses], activeResp: 0 }
            : t
        )
      );
    } catch (e: any) {
      update({ sending: false, error: String(e.message || e) });
    }
  }

  const resp = tab?.responses[tab.activeResp];

  return (
    <div className="split-v" style={{ height: "100%" }}>
      <div className="toolbar">
        {tabs.map((t, i) => (
          <span
            key={t.id}
            className={"tab " + (i === active ? "active" : "")}
            style={{ padding: "4px 10px", border: "1px solid var(--border)", borderRadius: 5 }}
            onClick={() => setActive(i)}
          >
            {t.name}
            {tabs.length > 1 && (
              <span
                style={{ marginLeft: 6, color: "var(--fg-dim)" }}
                onClick={(e) => {
                  e.stopPropagation();
                  setTabs((prev) => prev.filter((_, j) => j !== i));
                  setActive((a) => (a >= i && a > 0 ? a - 1 : a));
                }}
              >
                ✕
              </span>
            )}
          </span>
        ))}
        <button onClick={() => { setTabs((p) => [...p, blankTab()]); setActive(tabs.length); }}>+ {t("タブ","Tab")}</button>
      </div>

      {tab && (
        <div className="repeater-cols" style={{ padding: 12, flex: 1 }}>
          <div className="repeater-col">
            <div className="row" style={{ marginBottom: 8 }}>
              <div className="field">
                <label>scheme</label>
                <select value={tab.scheme} onChange={(e) => update({ scheme: e.target.value })}>
                  <option value="https">https</option>
                  <option value="http">http</option>
                </select>
              </div>
              <div className="field grow">
                <label>host</label>
                <input type="text" value={tab.host} placeholder="example.com" onChange={(e) => update({ host: e.target.value })} />
              </div>
              <div className="field">
                <label>port {t("(0=既定)","(0=default)")}</label>
                <input type="number" style={{ width: 90 }} value={tab.port} onChange={(e) => update({ port: Number(e.target.value) })} />
              </div>
              <div className="field">
                <label>&nbsp;</label>
                <button className="primary" disabled={tab.sending} onClick={send}>
                  {tab.sending ? t("送信中…","Sending…") : "Send ▶"}
                </button>
              </div>
            </div>
            <textarea
              style={{ flex: 1, minHeight: 300 }}
              value={tab.raw}
              onChange={(e) => update({ raw: e.target.value })}
              spellCheck={false}
            />
            {tab.error && <div className="banner warn" style={{ marginTop: 8 }}>{t("送信エラー","Send error")}: {tab.error}</div>}
          </div>

          <div className="repeater-col">
            <div className="row" style={{ marginBottom: 8 }}>
              <label>{t("レスポンス履歴(比較用)","Response history (compare)")}:</label>
              <select
                value={tab.activeResp}
                onChange={(e) => update({ activeResp: Number(e.target.value) })}
                disabled={tab.responses.length === 0}
              >
                {tab.responses.length === 0 && <option>{t("まだありません","none yet")}</option>}
                {tab.responses.map((r, i) => (
                  <option key={i} value={i}>
                    #{tab.responses.length - i}: {r.status_code} · {r.resp_length}B · {r.duration_ms}ms
                  </option>
                ))}
              </select>
            </div>
            {resp ? (
              <>
                <div className="row" style={{ marginBottom: 6 }}>
                  <span className={"mono " + statusClass(resp.status_code)}>{resp.status_code} {resp.reason}</span>
                  <span className="muted mono">{resp.resp_length} bytes · {resp.duration_ms} ms · {resp.http_version}</span>
                </div>
                <div style={{ flex: 1, border: "1px solid var(--border)", borderRadius: 6, overflow: "auto" }}>
                  <HttpView raw={rawResponse(resp.status_code, resp.reason, resp.headers, resp.body)} />
                  {resp.truncated && <div className="muted" style={{ padding: "0 10px 8px" }}>[{t("本文は保存上限で切り詰め","body truncated at store limit")}]</div>}
                </div>
              </>
            ) : (
              <div className="muted">{t("Send を押すとレスポンスがここに表示されます。","Press Send to see the response here.")}</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

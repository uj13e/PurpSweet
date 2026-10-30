import { useEffect, useRef, useState } from "react";
import { api, ActiveScanStatus, CveStatus, FlowDetail, Finding } from "../api";
import { rawRequest, rawResponse, parseRawRequest, sevClass, sortBy, SortDir } from "../util";
import HttpView from "./HttpView";
import { useT } from "../i18n";

const buildCats = (t: (ja: string, en: string) => string): [string, string][] => [
  ["sqli", t("SQL インジェクション", "SQL injection")],
  ["xss", t("反射型 XSS", "Reflected XSS")],
  ["cmdi", t("OS コマンドインジェクション", "OS command injection")],
  ["traversal", t("パストラバーサル / LFI", "Path traversal / LFI")],
  ["ssti", t("SSTI (テンプレート注入)", "SSTI (template injection)")],
  ["openredirect", t("オープンリダイレクト", "Open redirect")],
  ["crlf", t("CRLF インジェクション", "CRLF injection")],
  ["xxe", t("XXE (XML 外部実体)", "XXE (XML external entity)")],
  ["nosql", t("NoSQL インジェクション", "NoSQL injection")],
  ["ldap", t("LDAP インジェクション", "LDAP injection")],
  ["hostheader", t("Host ヘッダ注入", "Host header injection")],
  ["cors", t("CORS オリジン反射", "CORS origin reflection")],
];

interface Props {
  seed: FlowDetail | null;
  onSeedConsumed: () => void;
}

export default function ScannerView({ seed, onSeedConsumed }: Props) {
  const t = useT();
  // findings list
  const [findings, setFindings] = useState<Finding[]>([]);
  const [kindF, setKindF] = useState("");
  const [sevF, setSevF] = useState("");
  const [sortCol, setSortCol] = useState("severity");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [selFinding, setSelFinding] = useState<Finding | null>(null);

  // passive
  const [inScopeOnly, setInScopeOnly] = useState(false);
  const [passiveMsg, setPassiveMsg] = useState("");

  // active
  const [scheme, setScheme] = useState("https");
  const [host, setHost] = useState("");
  const [port, setPort] = useState(0);
  const [template, setTemplate] = useState("GET /?id=1 HTTP/1.1\nHost: example.com\n\n");
  const CATS = buildCats(t);
  const [cats, setCats] = useState<Record<string, boolean>>({ sqli: true, xss: true, cmdi: true, traversal: true, ssti: true, openredirect: true, crlf: true, xxe: true, nosql: true, ldap: true, hostheader: true, cors: true });
  const [techs, setTechs] = useState<Record<string, boolean>>({ error: true, boolean: true, time: true, reflect: true });
  const [timeDelay, setTimeDelay] = useState(5);
  const [followRedirects, setFollowRedirects] = useState(true);
  const [scanHeaders, setScanHeaders] = useState(false);
  const [concurrency, setConcurrency] = useState(5);
  const [delayMs, setDelayMs] = useState(0);
  const [recordHistory, setRecordHistory] = useState(true);
  const [scan, setScan] = useState<ActiveScanStatus | null>(null);
  const [error, setError] = useState("");
  const seededId = useRef<number | null>(null);

  // proving-traffic viewer for a selected finding
  const [selFlow, setSelFlow] = useState<FlowDetail | null>(null);
  const [flowMsg, setFlowMsg] = useState("");

  // CVE / version diagnostics
  const [cveScan, setCveScan] = useState<CveStatus | null>(null);
  const [cveOnline, setCveOnline] = useState(false);
  const [cveApiKey, setCveApiKey] = useState("");
  const [cveKeySet, setCveKeySet] = useState(false);
  const [cveMsg, setCveMsg] = useState("");

  function refreshFindings() {
    api.findings({ kind: kindF, severity: sevF }).then(setFindings).catch(() => {});
  }
  useEffect(() => { refreshFindings(); /* eslint-disable-next-line */ }, [kindF, sevF]);

  // When a finding with a linked proving flow is selected, load that exchange.
  useEffect(() => {
    setSelFlow(null); setFlowMsg("");
    const fid = selFinding?.flow_id || 0;
    if (!fid) return;
    api.flow(fid).then(setSelFlow).catch(() => setFlowMsg(t("この通信は履歴に見つかりませんでした(クリア済み?)。", "Proving exchange not found in history (cleared?).")));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selFinding?.id]);

  useEffect(() => {
    if (seed && seededId.current !== seed.id) {
      seededId.current = seed.id;
      setScheme(seed.scheme || "https");
      setHost(seed.host);
      setPort(seed.port || 0);
      let headers = seed.req_headers;
      if (!headers.some((h) => h[0].toLowerCase() === "host")) headers = [["Host", seed.host], ...headers];
      setTemplate(rawRequest(seed.method, seed.path, headers, seed.req_body));
      onSeedConsumed();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [seed]);

  // poll active scan
  useEffect(() => {
    const id = scan?.scan_id;
    if (!id || scan?.status !== "running") return;
    let live = true;
    const tick = async () => {
      try {
        const s = await api.activeScanGet(id);
        if (!live) return;
        setScan(s);
        refreshFindings();
        if (s.status === "running") setTimeout(tick, 700);
      } catch { /* stop */ }
    };
    setTimeout(tick, 700);
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scan?.scan_id, scan?.status]);

  async function runPassive() {
    setPassiveMsg(t("実行中…","Running…"));
    try {
      const r = await api.passiveRun(inScopeOnly);
      setPassiveMsg(t("受動スキャン完了","Passive scan done") + `: ${r.scanned_flows} ${t("件解析","flows")}, ${r.new_findings} ${t("新規指摘","new findings")}.`);
      refreshFindings();
    } catch (e: any) {
      setPassiveMsg(t("エラー: ","Error: ") + String(e.message || e));
    }
  }

  async function startActive() {
    setError("");
    const parsed = parseRawRequest(template);
    let h = host;
    if (!h) { const m = template.match(/host:\s*([^\r\n:]+)/i); if (m) h = m[1].trim(); }
    if (!h) { setError(t("ターゲット host を入力してください。","Enter the target host.")); return; }
    const categories = Object.entries(cats).filter(([, v]) => v).map(([k]) => k);
    if (categories.length === 0) { setError(t("カテゴリを1つ以上選んでください。","Select at least one category.")); return; }
    try {
      const techniques = Object.entries(techs).filter(([, v]) => v).map(([k]) => k);
      const r = await api.activeScanStart({
        scheme, host: h, port,
        method: parsed.method, path: parsed.path, headers: parsed.headers, body: parsed.body,
        categories, techniques, time_delay: timeDelay,
        follow_redirects: followRedirects, scan_headers: scanHeaders,
        concurrency, delay_ms: delayMs, record_history: recordHistory,
      });
      setScan({ scan_id: r.scan_id, status: r.status, host: h, total: r.total, done: 0, found: 0, error: "", findings: [] });
    } catch (e: any) {
      setError(String(e.message || e));
    }
  }
  async function stopActive() { if (scan) await api.activeScanStop(scan.scan_id); }

  // load CVE/NVD defaults from settings
  useEffect(() => {
    api.getSettings().then((s) => { setCveOnline(s.nvd_online); setCveKeySet(s.nvd_api_key_set); }).catch(() => {});
  }, []);

  // poll CVE scan
  useEffect(() => {
    const id = cveScan?.cve_id;
    if (!id || cveScan?.status !== "running") return;
    let live = true;
    const tick = async () => {
      try {
        const s = await api.cveGet(id);
        if (!live) return;
        setCveScan(s);
        refreshFindings();
        if (s.status === "running") setTimeout(tick, 1000);
      } catch { /* stop */ }
    };
    setTimeout(tick, 1000);
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cveScan?.cve_id, cveScan?.status]);

  async function runCve() {
    setCveMsg(cveOnline ? t("指紋採取 + NVD照会中…(オンラインは数十秒かかる場合があります)", "Fingerprinting + querying NVD… (online may take tens of seconds)") : t("指紋採取 + 同梱DB照合中…", "Fingerprinting + matching bundled DB…"));
    try {
      const r = await api.cveRun({ in_scope_only: inScopeOnly, online: cveOnline, api_key: cveApiKey || undefined });
      if (cveApiKey) setCveKeySet(true);
      setCveScan({ cve_id: r.cve_id, status: r.status, online: r.online, total: r.techs, done: 0, found: 0, error: "", techs: [], findings: [] });
      setCveMsg(t("検出技術", "Detected components") + `: ${r.techs}`);
    } catch (e: any) {
      setCveMsg(t("エラー: ", "Error: ") + String(e.message || e));
    }
  }

  const running = scan?.status === "running";
  const sorted = sortBy(findings, (f) => {
    if (sortCol === "severity") return { high: 0, medium: 1, low: 2, info: 3 }[f.severity as "high"] ?? 9;
    return (f as any)[sortCol] ?? "";
  }, sortDir);
  function onSort(c: string) {
    if (c === sortCol) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortCol(c); setSortDir("asc"); }
  }
  const Th = ({ c, label }: { c: string; label: string }) => (
    <th style={{ cursor: "pointer", userSelect: "none" }} onClick={() => onSort(c)}>
      {label}{sortCol === c ? (sortDir === "asc" ? " ▲" : " ▼") : ""}
    </th>
  );

  return (
    <div className="section" style={{ maxWidth: "unset" }}>
      <div className="banner warn">
        <b>{t("認可されたテスト専用。","Authorized testing only.")}</b> 受動診断は送信を伴いません。能動診断は検出用ペイロードを
        {t(" 検出用ペイロードを Scope 登録済みホストのみ(デフォルト拒否)＋レート制御で送信し、脆弱性の可能性を報告します(武器化・データ奪取は行いません)。","Active checks send detection probes only to scoped hosts (default-deny) with rate limits, and report likely vulnerabilities (no weaponization or data exfiltration).")}
      </div>

      <div className="row" style={{ alignItems: "flex-start", gap: 12 }}>
        {/* Passive */}
        <div className="card" style={{ flex: 1 }}>
          <h3 style={{ marginTop: 0 }}>{t("受動診断","Passive")}</h3>
          <p className="muted">{t("傍受済みの通信を解析(ヘッダ欠如・Cookie属性・機微情報の露出)。送信なし。","Analyze captured traffic (missing headers, cookie attrs, secret exposure). No requests sent.")}</p>
          <label className="toggle" style={{ marginBottom: 8 }}>
            <input type="checkbox" checked={inScopeOnly} onChange={(e) => setInScopeOnly(e.target.checked)} />
            <span>{t("スコープ内のみ解析","In-scope only")}</span>
          </label>
          <div><button className="primary" onClick={runPassive}>{t("受動スキャン実行","Run passive scan")}</button></div>
          {passiveMsg && <p className="muted" style={{ marginTop: 8 }}>{passiveMsg}</p>}
        </div>

        {/* Active */}
        <div className="card" style={{ flex: 2 }}>
          <h3 style={{ marginTop: 0 }}>{t("能動診断(検出)","Active (detection)")}</h3>
          <div className="row" style={{ marginBottom: 6 }}>
            <div className="field"><label>scheme</label>
              <select value={scheme} onChange={(e) => setScheme(e.target.value)}>
                <option value="https">https</option><option value="http">http</option>
              </select>
            </div>
            <div className="field grow"><label>host</label>
              <input type="text" value={host} placeholder="example.com" onChange={(e) => setHost(e.target.value)} />
            </div>
            <div className="field"><label>port</label>
              <input type="number" style={{ width: 80 }} value={port} onChange={(e) => setPort(Number(e.target.value))} />
            </div>
          </div>
          <label>{t("対象リクエスト（クエリ/フォームの各パラメータを検査)","Target request (each query/form param is tested)")}</label>
          <textarea style={{ width: "100%", minHeight: 110 }} value={template} onChange={(e) => setTemplate(e.target.value)} spellCheck={false} />
          <div className="row" style={{ marginTop: 6 }}>
            <span className="muted" style={{ fontSize: 11 }}>{t("種類","Types")}:</span>
            {CATS.map(([k, l]) => (
              <label key={k} className="toggle">
                <input type="checkbox" checked={!!cats[k]} onChange={(e) => setCats((p) => ({ ...p, [k]: e.target.checked }))} />
                <span>{l}</span>
              </label>
            ))}
          </div>
          <div className="row" style={{ marginTop: 4 }}>
            <span className="muted" style={{ fontSize: 11 }}>{t("手法","Techniques")}:</span>
            {([["error", t("エラー","Error")], ["boolean", t("ブール差分","Boolean")], ["time", t("時間(ブラインド)","Time (blind)")], ["reflect", t("反射","Reflection")]] as [string, string][]).map(([k, l]) => (
              <label key={k} className="toggle">
                <input type="checkbox" checked={!!techs[k]} onChange={(e) => setTechs((p) => ({ ...p, [k]: e.target.checked }))} />
                <span>{l}</span>
              </label>
            ))}
          </div>
          <div className="row" style={{ marginTop: 4 }}>
            <div className="field"><label>{t("遅延秒(時間ベース)","Delay sec (time-based)")}</label><input type="number" style={{ width: 70 }} min={2} max={30} value={timeDelay} onChange={(e) => setTimeDelay(Math.max(2, Number(e.target.value)))} /></div>
            <label className="toggle"><input type="checkbox" checked={followRedirects} onChange={(e) => setFollowRedirects(e.target.checked)} /><span>{t("リダイレクト追従","Follow redirects")}</span></label>
            <label className="toggle"><input type="checkbox" checked={scanHeaders} onChange={(e) => setScanHeaders(e.target.checked)} /><span>{t("Cookie/UA/Referer も検査","Also test Cookie/UA/Referer")}</span></label>
            <label className="toggle" title={t("送信した全リクエストを HTTP履歴に記録します","Record every sent request into HTTP history")}><input type="checkbox" checked={recordHistory} onChange={(e) => setRecordHistory(e.target.checked)} /><span>{t("履歴に記録","Record to history")}</span></label>
          </div>
          <div className="row" style={{ marginTop: 6 }}>
            <div className="field"><label>{t("同時実行数","Concurrency")} *</label><input type="number" style={{ width: 80 }} min={1} value={concurrency} onChange={(e) => setConcurrency(Math.max(1, Number(e.target.value)))} /></div>
            <div className="field"><label>{t("間隔 ms","Delay ms")} *</label><input type="number" style={{ width: 90 }} min={0} value={delayMs} onChange={(e) => setDelayMs(Math.max(0, Number(e.target.value)))} /></div>
            <div className="field"><label>&nbsp;</label>
              {!running
                ? <button className="primary" onClick={startActive}>▶ {t("能動スキャン開始","Start active scan")}</button>
                : <button className="danger" onClick={stopActive}>■ {t("停止","Stop")}</button>}
            </div>
            {scan && <span className="muted mono">{scan.status} · {scan.done}/{scan.total} · 指摘 {scan.found}</span>}
          </div>
          {error && <div className="banner warn" style={{ marginTop: 8 }}>{error}</div>}
        </div>
      </div>

      {/* CVE / version diagnostics */}
      <div className="card" style={{ marginTop: 12 }}>
        <h3 style={{ marginTop: 0 }}>{t("CVE / バージョン診断", "CVE / version check")}</h3>
        <p className="muted">
          {t("傍受済み通信からソフト/ライブラリのバージョンを指紋採取し、既知CVEと突合します(検出のみ)。同梱DBは常時使用。オンラインNVDは明示ON時のみ nvd.nist.gov に製品名/版のみ問い合わせます。",
             "Fingerprints software/library versions from captured traffic and matches known CVEs (detection only). The bundled DB always runs; online NVD queries nvd.nist.gov (product/version only) only when enabled.")}
        </p>
        <div className="row" style={{ alignItems: "center" }}>
          <label className="toggle"><input type="checkbox" checked={inScopeOnly} onChange={(e) => setInScopeOnly(e.target.checked)} /><span>{t("スコープ内のみ", "In-scope only")}</span></label>
          <label className="toggle"><input type="checkbox" checked={cveOnline} onChange={(e) => setCveOnline(e.target.checked)} /><span>{t("オンラインNVD照会", "Online NVD lookup")}</span></label>
          <div className="field grow"><label>{t("NVD APIキー(任意・レート制限緩和)", "NVD API key (optional, higher rate limit)")} {cveKeySet ? "✓" : ""}</label>
            <input type="password" value={cveApiKey} placeholder={cveKeySet ? "********" : ""} onChange={(e) => setCveApiKey(e.target.value)} /></div>
          <div className="field"><label>&nbsp;</label>
            {cveScan?.status !== "running"
              ? <button className="primary" onClick={runCve}>▶ {t("CVE診断を実行", "Run CVE check")}</button>
              : <button disabled>… {t("実行中", "Running")}</button>}
          </div>
          {cveScan && <span className="muted mono">{cveScan.status} · {cveScan.done}/{cveScan.total} · CVE {cveScan.found}</span>}
        </div>
        {cveMsg && <p className="muted" style={{ marginTop: 6 }}>{cveMsg}</p>}
        {cveScan && cveScan.techs.length > 0 && (
          <div style={{ marginTop: 6 }}>
            <label>{t("検出した技術", "Detected components")} ({cveScan.techs.length})</label>
            <div className="row" style={{ flexWrap: "wrap", gap: 6 }}>
              {cveScan.techs.map((tk, i) => (
                <span key={i} className="pill" title={`${tk.source}: ${tk.evidence}`}>
                  {tk.product}{tk.version ? ` ${tk.version}` : ""} <span className="muted">· {tk.host}</span>
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Findings */}
      <div className="toolbar" style={{ marginTop: 12, borderRadius: 6 }}>
        <b>{t("指摘一覧","Findings")}</b>
        <select value={kindF} onChange={(e) => setKindF(e.target.value)}>
          <option value="">{t("種別: all","kind: all")}</option><option value="passive">passive</option><option value="active">active</option><option value="cve">cve</option>
        </select>
        <select value={sevF} onChange={(e) => setSevF(e.target.value)}>
          <option value="">{t("深刻度: all","severity: all")}</option><option value="high">high</option><option value="medium">medium</option><option value="low">low</option><option value="info">info</option>
        </select>
        <span className="muted">{sorted.length} 件</span>
        <div className="spacer" style={{ flex: 1 }} />
        <button onClick={refreshFindings}>↻ {t("更新","Refresh")}</button>
        <button className="danger" onClick={async () => { if (confirm(t("指摘をすべて削除しますか?","Clear all findings?"))) { await api.clearFindings(); refreshFindings(); } }}>{t("クリア","Clear")}</button>
      </div>
      <div className="table-wrap" style={{ maxHeight: "42vh", border: "1px solid var(--border)", borderRadius: 6 }}>
        <table className="grid">
          <thead>
            <tr>
              <Th c="severity" label={t("深刻度","Severity")} />
              <Th c="kind" label={t("種別","Kind")} />
              <Th c="title" label={t("指摘","Finding")} />
              <Th c="host" label="host" />
              <Th c="param" label="param" />
              <th>evidence</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((f) => (
              <tr key={f.id} className={selFinding?.id === f.id ? "sel" : ""} onClick={() => setSelFinding(f)}>
                <td><span className={"sev " + sevClass(f.severity)}>{f.severity}</span></td>
                <td className="muted">{f.kind}</td>
                <td title={f.detail}>{f.title} <span className="muted">({f.confidence})</span></td>
                <td className="mono">{f.host}</td>
                <td className="mono">{f.param}</td>
                <td className="mono muted" style={{ maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis" }} title={f.evidence}>{f.evidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selFinding && (
        <div className="card" style={{ marginTop: 10 }}>
          <div className="row" style={{ marginBottom: 6 }}>
            <span className={"sev " + sevClass(selFinding.severity)}>{selFinding.severity}</span>
            <b>{selFinding.title}</b>
            <span className="muted">({selFinding.kind} / {selFinding.confidence})</span>
            <div className="spacer" style={{ flex: 1 }} />
            <button onClick={() => setSelFinding(null)}>{t("閉じる","Close")}</button>
          </div>
          <div className="mono" style={{ fontSize: 12 }}>{selFinding.method} {selFinding.url}</div>
          {selFinding.param && <div className="muted mono" style={{ fontSize: 12 }}>param: {selFinding.param}</div>}
          <p style={{ margin: "8px 0 4px" }}>{selFinding.detail}</p>
          {selFinding.evidence && (
            <>
              <label>evidence</label>
              <pre className="raw" style={{ border: "1px solid var(--border)", borderRadius: 6, maxHeight: 200 }}>{selFinding.evidence}</pre>
            </>
          )}
          {/* Proving request/response — jump straight to the exchange that triggered this. */}
          {selFinding.flow_id ? (
            <div style={{ marginTop: 10 }}>
              <label>{t("この指摘を出した通信", "The request/response that proved this")}</label>
              {flowMsg && <p className="muted" style={{ fontSize: 12 }}>{flowMsg}</p>}
              {selFlow ? (
                <div className="repeater-cols">
                  <div className="repeater-col">
                    <div className="row" style={{ marginBottom: 4 }}><b>Request</b><span className="muted mono">{selFlow.method} {selFlow.path}</span></div>
                    <div style={{ border: "1px solid var(--border)", borderRadius: 6, overflow: "auto", maxHeight: "36vh" }}>
                      <HttpView raw={rawRequest(selFlow.method, selFlow.path, selFlow.req_headers, selFlow.req_body)} />
                    </div>
                  </div>
                  <div className="repeater-col">
                    <div className="row" style={{ marginBottom: 4 }}><b>Response</b><span className="muted mono">{selFlow.status_code} · {selFlow.resp_length}B</span></div>
                    <div style={{ border: "1px solid var(--border)", borderRadius: 6, overflow: "auto", maxHeight: "36vh" }}>
                      <HttpView raw={rawResponse(selFlow.status_code, selFlow.reason, selFlow.resp_headers, selFlow.resp_body)} />
                    </div>
                  </div>
                </div>
              ) : !flowMsg ? <p className="muted" style={{ fontSize: 12 }}>{t("読み込み中…", "Loading…")}</p> : null}
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}

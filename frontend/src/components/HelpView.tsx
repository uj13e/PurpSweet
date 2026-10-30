import { useEffect, useState } from "react";
import { api } from "../api";
import { useT } from "../i18n";

export default function HelpView() {
  const t = useT();
  const [ca, setCa] = useState<any>(null);
  const [prox, setProx] = useState("");
  const [ct, setCt] = useState(8);
  const [savedMsg, setSavedMsg] = useState("");
  useEffect(() => { api.ca().then(setCa).catch(() => {}); }, []);
  useEffect(() => { api.getSettings().then((s) => { setProx(s.upstream_proxy); setCt(s.connect_timeout); }).catch(() => {}); }, []);

  async function saveSettings() {
    try {
      const s = await api.setSettings({ upstream_proxy: prox, connect_timeout: ct });
      setProx(s.upstream_proxy); setCt(s.connect_timeout);
      setSavedMsg(t("保存しました", "Saved")); setTimeout(() => setSavedMsg(""), 2000);
    } catch (e: any) { setSavedMsg(t("エラー: ", "Error: ") + String(e.message || e)); }
  }

  return (
    <div className="section" style={{ maxWidth: 820 }}>
      <div className="banner warn">
        {t("本ツールは自社が所有、または明示的にテスト許可を得たシステムの診断専用です。許可のない対象への使用は行わないでください。すべてローカルで完結し、外部への送信は行いません。",
           "This tool is for testing systems you own or are explicitly authorized to test. Do not use it against targets you are not authorized for. Everything runs locally; nothing is sent externally.")}
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>{t("接続設定(重要)", "Connection settings (important)")}</h3>
        <p className="muted">
          {t("Repeater / Intruder / Scanner は対象へ直接接続します。「ConnectError: All connection attempts failed」が出る/全部失敗する場合、ブラウザと同じ経路(このツールのプロキシや社内プロキシ)を経由させてください。",
             "Repeater / Intruder / Scanner connect to the target directly. If you see \"ConnectError: All connection attempts failed\" / everything fails, route them through the same path your browser uses (this tool's proxy, or your corporate proxy).")}
        </p>
        <div className="field" style={{ marginBottom: 6 }}>
          <label>{t("上流プロキシ(空=直接接続)", "Upstream proxy (blank = direct)")}</label>
          <input type="text" value={prox} placeholder="http://127.0.0.1:8080" onChange={(e) => setProx(e.target.value)} />
        </div>
        <div className="row" style={{ marginBottom: 6 }}>
          <button onClick={() => setProx("http://127.0.0.1:8080")}>{t("このツールのプロキシ経由", "Via this tool's proxy")}</button>
          <button onClick={() => setProx("")}>{t("直接接続に戻す", "Direct")}</button>
          <div className="field"><label>{t("接続タイムアウト秒", "Connect timeout (s)")}</label>
            <input type="number" style={{ width: 80 }} min={1} max={60} value={ct} onChange={(e) => setCt(Math.max(1, Number(e.target.value)))} /></div>
          <div className="field"><label>&nbsp;</label><button className="primary" onClick={saveSettings}>{t("保存", "Save")}</button></div>
          {savedMsg && <span className="muted">{savedMsg}</span>}
        </div>
        <p className="muted" style={{ fontSize: 11 }}>
          {t("ヒント: ブラウザのプロキシを 127.0.0.1:8080 にして対象が見えているなら、ここも同じ 127.0.0.1:8080 にすれば Intruder 等も到達できます。",
             "Tip: if your browser proxy is 127.0.0.1:8080 and the target loads, set this to the same 127.0.0.1:8080 so Intruder etc. can reach it too.")}
        </p>
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>1. {t("プロキシの設定", "Configure the proxy")}</h3>
        <p>{t("ブラウザ / OS の HTTP・HTTPS プロキシを次に設定します:", "Set your browser/OS HTTP & HTTPS proxy to:")}</p>
        <pre className="raw" style={{ background: "var(--bg)", border: "1px solid var(--border)", borderRadius: 6 }}>
HTTP  Proxy: 127.0.0.1 : (proxy_port)
HTTPS Proxy: 127.0.0.1 : (proxy_port)</pre>
        <p className="muted">{t("既定のポートは 8080(", "Default port 8080 (")}<span className="kbd">WEBSEC_PROXY_PORT</span>{t(" で変更可)。", " to change).")}</p>
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>2. {t("HTTPS 復号用 CA のインストール", "Install the CA for HTTPS")}</h3>
        <p>
          {t("HTTPS を傍受するには、生成された CA 証明書を自分が管理する端末にのみ信頼済みルートとして導入します。プロキシ経由で一度通信すると CA が生成されます。",
             "To intercept HTTPS, install the generated CA as a trusted root only on devices you control. The CA is generated once you send traffic through the proxy.")}
        </p>
        {ca && Object.keys(ca.available || {}).length > 0 ? (
          <div className="row">
            {Object.keys(ca.available).map((k) => (
              <a key={k} href={`/api/ca/download?fmt=${k}`}><button>{t("CA をダウンロード", "Download CA")} (.{k})</button></a>
            ))}
          </div>
        ) : (
          <p className="muted">{t("まだ CA が生成されていません。プロキシ経由で 1 回通信してから再読込してください。",
                                  "CA not generated yet. Send one request through the proxy, then reload.")}</p>
        )}
        <p className="muted" style={{ marginTop: 8 }}>confdir: <span className="mono">{ca?.confdir}</span></p>
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>3. {t("使い方の流れ", "Workflow")}</h3>
        <ol>
          <li>{t("Scope タブで診断対象ホストを登録(能動送信はここに登録した対象のみ)。", "Add target hosts in the Scope tab (active sends only go to hosts listed there).")}</li>
          <li>{t("HTTP履歴 でプロキシを通った通信を確認。行を選ぶと詳細表示。右クリックで各ツールへ送信。", "See proxied traffic in HTTP history. Select a row for details; right-click to send to a tool.")}</li>
          <li>{t("Repeater で編集して繰り返し送信・比較。Intruder で自動送信、Scanner で脆弱性検出。", "Use Repeater to edit & resend, Intruder to automate, Scanner to detect vulnerabilities.")}</li>
          <li>{t("Intercept を ON にすると、リクエストを停止して編集/フォワード/ドロップ。", "Turn Intercept ON to pause a request and edit / forward / drop it.")}</li>
        </ol>
      </div>
    </div>
  );
}

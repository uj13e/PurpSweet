import { useEffect, useState } from "react";
import { api, PendingIntercept } from "../api";
import { rawRequest, parseRawRequest } from "../util";
import { useT } from "../i18n";

interface Props {
  enabled: boolean;
  pending: PendingIntercept[];
  onChanged: () => void;
}

export default function InterceptView({ enabled, pending, onChanged }: Props) {
  const t = useT();
  const current = pending[0] || null;
  const [draft, setDraft] = useState("");

  useEffect(() => {
    if (current) {
      setDraft(rawRequest(current.method, current.path, current.headers, current.body));
    } else {
      setDraft("");
    }
  }, [current?.flow_id]);

  async function forward() {
    if (!current) return;
    const parsed = parseRawRequest(draft);
    await api.resolveIntercept(current.flow_id, {
      action: "forward",
      method: parsed.method,
      path: parsed.path,
      headers: parsed.headers,
      body: parsed.body,
    });
    onChanged();
  }

  async function drop() {
    if (!current) return;
    await api.resolveIntercept(current.flow_id, { action: "drop" });
    onChanged();
  }

  return (
    <div className="intercept-box">
      <div className="row" style={{ marginBottom: 12 }}>
        <div
          className={"toggle " + (enabled ? "on" : "")}
          onClick={async () => {
            await api.setIntercept(!enabled);
            onChanged();
          }}
        >
          <span className="track"><span className="knob" /></span>
          <b>Intercept {enabled ? "ON" : "OFF"}</b>
        </div>
        <span className="muted">
          {t("待機中", "Queued")}: <b>{pending.length}</b>
        </span>
        {enabled && (
          <span className="pill warn">{t("ON の間、全リクエストが一時停止します", "While ON, every request is paused here")}</span>
        )}
      </div>

      {!enabled && (
        <div className="banner info">
          {t("Intercept を ON にすると、プロキシを通る各リクエストがここで停止します。内容を編集して「Forward」で送信、「Drop」で破棄できます。",
             "Turn Intercept ON to pause each request passing through the proxy. Edit it and Forward to send, or Drop to discard.")}
        </div>
      )}

      {enabled && !current && (
        <div className="banner info">{t("停止中のリクエストはありません。対象をブラウズすると停止します。", "No paused requests. Browse the target to pause one.")}</div>
      )}

      {current && (
        <div className="card">
          <div className="row" style={{ marginBottom: 8 }}>
            <span className="mono">
              {current.scheme}://{current.host}
              {current.port && ![80, 443].includes(current.port) ? ":" + current.port : ""}
            </span>
            <span className={current.in_scope ? "scope-yes" : "scope-no"}>
              {current.in_scope ? "● in scope" : "○ out of scope"}
            </span>
            <div className="spacer" style={{ flex: 1 }} />
            <button className="primary" onClick={forward}>Forward ▶</button>
            <button className="danger" onClick={drop}>Drop ✕</button>
          </div>
          <label>{t("リクエスト(生データ・編集可 / 先頭行 + ヘッダー + 空行 + ボディ)", "Request (raw, editable / request line + headers + blank line + body)")}</label>
          <textarea
            className="hdr-editor"
            style={{ minHeight: 320 }}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            spellCheck={false}
          />
          <p className="muted">
            {t("ホストとスキームは接続先のため変更できません(メソッド/パス/ヘッダー/ボディは編集可)。",
               "Host and scheme are the connection target and can't be changed (method/path/headers/body are editable).")}
          </p>
        </div>
      )}
    </div>
  );
}

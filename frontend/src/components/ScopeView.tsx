import { useState } from "react";
import { api, ScopeRule } from "../api";
import { useT } from "../i18n";

interface Props {
  rules: ScopeRule[];
  onChanged: () => void;
}

export default function ScopeView({ rules, onChanged }: Props) {
  const t = useT();
  const [host, setHost] = useState("");
  const [note, setNote] = useState("");

  async function add() {
    if (!host.trim()) return;
    await api.addScope(host.trim(), note.trim());
    setHost("");
    setNote("");
    onChanged();
  }

  return (
    <div className="section">
      <div className="banner warn">
        <b>{t("スコープ = 許可対象の許可リスト(デフォルト拒否)。", "Scope = allow-list of authorized targets (default-deny).")}</b>{" "}
        {t("Repeater / Intruder / Scanner などツールからの能動送信は、ここに登録され有効化されたホストにのみ実行されます。自社所有、または明示的にテスト許可を得た対象だけを登録してください。(プロキシでの受動的な閲覧・記録は制限しません。)",
           "Tool-initiated sends (Repeater / Intruder / Scanner) only run against hosts enabled here. Add only targets you own or are explicitly authorized to test. (Passive proxy viewing/logging is not restricted.)")}
      </div>

      <div className="card">
        <div className="row">
          <div className="field grow">
            <label>{t("ホスト名 / グロブ / IP / CIDR(例: example.com、*.staging.internal、192.168.1.10、10.0.0.0/8、2001:db8::/32)",
                      "Hostname / glob / IP / CIDR (e.g. example.com, *.staging.internal, 192.168.1.10, 10.0.0.0/8, 2001:db8::/32)")}</label>
            <input type="text" value={host} placeholder="example.com  /  10.0.0.0/8" onChange={(e) => setHost(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && add()} />
          </div>
          <div className="field grow">
            <label>{t("メモ(任意 / 許可の根拠など)", "Note (optional / authorization basis)")}</label>
            <input type="text" value={note} onChange={(e) => setNote(e.target.value)} />
          </div>
          <div className="field">
            <label>&nbsp;</label>
            <button className="primary" onClick={add}>{t("追加", "Add")}</button>
          </div>
        </div>
      </div>

      <table className="grid">
        <thead>
          <tr><th>{t("有効", "On")}</th><th>host pattern</th><th>note</th><th></th></tr>
        </thead>
        <tbody>
          {rules.length === 0 && (
            <tr><td colSpan={4} className="muted" style={{ padding: 12 }}>
              {t("スコープ未登録。この状態ではツールからの能動送信はすべて拒否されます。",
                 "No scope entries. In this state all tool-initiated sends are denied.")}
            </td></tr>
          )}
          {rules.map((r) => (
            <tr key={r.id}>
              <td>
                <div
                  className={"toggle " + (r.enabled ? "on" : "")}
                  onClick={async () => {
                    await api.updateScope(r.id, { host_pattern: r.host_pattern, enabled: !r.enabled, note: r.note });
                    onChanged();
                  }}
                >
                  <span className="track"><span className="knob" /></span>
                </div>
              </td>
              <td className="mono">{r.host_pattern}</td>
              <td className="muted">{r.note}</td>
              <td>
                <button className="danger" onClick={async () => { await api.deleteScope(r.id); onChanged(); }}>{t("削除", "Delete")}</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

import { useEffect, useState } from "react";
import { api, SitemapNode } from "../api";
import { useT } from "../i18n";

function TreeNode({ node, depth }: { node: SitemapNode; depth: number }) {
  const [open, setOpen] = useState(depth < 1);
  const hasChildren = node.children && node.children.length > 0;
  return (
    <div className="tree-node">
      <div className="tree-row">
        <span className="tree-toggle" onClick={() => hasChildren && setOpen(!open)}>
          {hasChildren ? (open ? "▾" : "▸") : "·"}
        </span>
        <span>{depth === 0 ? "" : "/"}{node.name}</span>
        <span className="tree-count">({node.count})</span>
        {node.methods && node.methods.length > 0 && (
          <span className="muted" style={{ fontSize: 10 }}>{node.methods.join(",")}</span>
        )}
      </div>
      {open && hasChildren && (
        <div className="tree-children">
          {node.children.map((c, i) => <TreeNode key={i} node={c} depth={depth + 1} />)}
        </div>
      )}
    </div>
  );
}

export default function SitemapView() {
  const t = useT();
  const [tree, setTree] = useState<SitemapNode[]>([]);
  const [msg, setMsg] = useState("");

  function refresh() { api.sitemap().then(setTree).catch(() => {}); }
  useEffect(() => { refresh(); }, []);

  async function addScope(host: string) {
    try {
      await api.addScope(host, "added from sitemap");
      setMsg(t("スコープに追加: ","Added to scope: ") + host);
    } catch (e: any) {
      setMsg(t("エラー: ","Error: ") + String(e.message || e));
    }
  }

  return (
    <div className="section">
      <div className="row" style={{ marginBottom: 10 }}>
        <b>{t("サイトマップ","Sitemap")}</b>
        <span className="muted">{t("傍受した通信の URL 構造。ホストをスコープに登録できます。","URL structure of captured traffic. You can add a host to Scope.")}</span>
        <div className="spacer" style={{ flex: 1 }} />
        <button onClick={refresh}>↻ {t("更新","Refresh")}</button>
      </div>
      {msg && <div className="banner info" style={{ marginBottom: 10 }}>{msg}</div>}
      {tree.length === 0 && <p className="muted">{t("まだ通信がありません。プロキシ経由でアクセスすると構造が現れます。","No traffic yet. Browse through the proxy to populate this.")}</p>}
      {tree.map((h, i) => (
        <div className="card" key={i} style={{ padding: 12, marginBottom: 10 }}>
          <div className="row" style={{ marginBottom: 8 }}>
            <b className="mono">{h.scheme}://{h.name}</b>
            <span className="tree-count">({h.count} {t("リクエスト","requests")})</span>
            <span className={h.in_scope ? "scope-yes" : "scope-no"}>{h.in_scope ? "● in scope" : "○ out of scope"}</span>
            <div className="spacer" style={{ flex: 1 }} />
            <button onClick={() => addScope(h.name)}>{t("スコープに追加","Add to scope")}</button>
          </div>
          <div className="tree">
            {h.children.map((c, j) => <TreeNode key={j} node={c} depth={1} />)}
          </div>
        </div>
      ))}
    </div>
  );
}

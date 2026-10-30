import { useEffect, useMemo, useRef, useState } from "react";
import { diff, DiffMode, DiffOp } from "../diff";
import { useT } from "../i18n";

interface Props {
  seed: string | null;
  onSeedConsumed: () => void;
}

function renderSide(ops: DiffOp[], side: "left" | "right") {
  const keep = side === "left" ? "del" : "add";
  return ops
    .filter((o) => o.t === "eq" || o.t === keep)
    .map((o, i) => {
      if (o.t === "eq") return <span key={i}>{o.v}</span>;
      const cls = o.t === "del" ? "diff-del" : "diff-add";
      return <span key={i} className={cls}>{o.v}</span>;
    });
}

export default function ComparerView({ seed, onSeedConsumed }: Props) {
  const t = useT();
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [mode, setMode] = useState<DiffMode>("word");
  const slot = useRef(0);

  useEffect(() => {
    if (seed != null) {
      if (slot.current % 2 === 0) setA(seed);
      else setB(seed);
      slot.current += 1;
      onSeedConsumed();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [seed]);

  const result = useMemo(() => {
    if (!a && !b) return null;
    return diff(a, b, mode);
  }, [a, b, mode]);

  return (
    <div className="section" style={{ maxWidth: "unset" }}>
      <div className="banner info">
        {t("2 つのテキスト(リクエスト/レスポンス等)を比較します。履歴の詳細から → Comparer で A→B の順に読み込めます。","Compare two texts (requests/responses). From a history detail, → Comparer loads A then B.")} <span className="scope-no">{t("赤=Aのみ(削除)","red = A only (removed)")}</span> / <span className="scope-yes">{t("緑=Bのみ(追加)","green = B only (added)")}</span>
      </div>

      <div className="diff-panes" style={{ marginBottom: 10 }}>
        <div className="field grow">
          <label>A ({a.length} {t("文字","chars")})</label>
          <textarea style={{ width: "100%", minHeight: 120 }} value={a} onChange={(e) => setA(e.target.value)} spellCheck={false} />
        </div>
        <div className="field grow">
          <label>B ({b.length} {t("文字","chars")})</label>
          <textarea style={{ width: "100%", minHeight: 120 }} value={b} onChange={(e) => setB(e.target.value)} spellCheck={false} />
        </div>
      </div>

      <div className="row" style={{ marginBottom: 10 }}>
        <label>{t("粒度","Granularity")}:</label>
        {(["word", "char", "line"] as DiffMode[]).map((m) => (
          <button key={m} className={mode === m ? "primary" : ""} onClick={() => setMode(m)}>
            {m === "word" ? t("単語","Word") : m === "char" ? t("バイト(文字)","Char") : t("行","Line")}
          </button>
        ))}
        <button onClick={() => { setA(""); setB(""); slot.current = 0; }}>{t("クリア","Clear")}</button>
        {result && (
          <span className="muted mono">
            −{result.delCount} / +{result.addCount}
            {result.downgraded ? t("（大きいため行単位に自動切替）"," (auto line mode for large input)") : ""}
            {result.truncated ? t("（巨大なため一部のみ比較）"," (too large — compared a prefix only)") : ""}
          </span>
        )}
      </div>

      {result && (
        <div className="diff-panes">
          <div className="diff-pane">
            <h4>A</h4>
            <pre>{renderSide(result.ops, "left")}</pre>
          </div>
          <div className="diff-pane">
            <h4>B</h4>
            <pre>{renderSide(result.ops, "right")}</pre>
          </div>
        </div>
      )}
    </div>
  );
}

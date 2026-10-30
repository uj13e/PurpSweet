import { useEffect, useState } from "react";
import { api } from "../api";
import { useT } from "../i18n";

interface Cell {
  op: string;      // label of the op that produced this text ("input" for the base)
  text: string;
  error?: string;
}

const OP_GROUPS: { label: string; ops: [string, string][] }[] = [
  { label: "Base64", ops: [["b64encode", "Encode"], ["b64decode", "Decode"]] },
  { label: "URL", ops: [["urlencode", "Encode"], ["urldecode", "Decode"]] },
  { label: "HTML", ops: [["htmlencode", "Encode"], ["htmldecode", "Decode"]] },
  { label: "Hex", ops: [["hexencode", "Encode"], ["hexdecode", "Decode"]] },
  { label: "Hash", ops: [["md5", "MD5"], ["sha1", "SHA1"], ["sha256", "SHA256"], ["sha512", "SHA512"]] },
];
const OP_LABEL: Record<string, string> = {
  b64encode: "Base64 ▸ Encode", b64decode: "Base64 ▸ Decode",
  urlencode: "URL ▸ Encode", urldecode: "URL ▸ Decode",
  htmlencode: "HTML ▸ Encode", htmldecode: "HTML ▸ Decode",
  hexencode: "Hex ▸ Encode", hexdecode: "Hex ▸ Decode",
  md5: "MD5", sha1: "SHA1", sha256: "SHA256", sha512: "SHA512",
};

export default function DecoderView({ seed, onSeedConsumed }: { seed?: string | null; onSeedConsumed?: () => void }) {
  const t = useT();
  const [input, setInput] = useState("");
  const [cells, setCells] = useState<Cell[]>([]);

  useEffect(() => {
    if (seed != null) {
      setInput(seed);
      setCells([]);
      onSeedConsumed?.();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [seed]);

  const working = cells.length ? cells[cells.length - 1].text : input;

  async function applyOp(op: string) {
    const src = working;
    const r = await api.transform(op, src);
    setCells((prev) => [...prev, { op: OP_LABEL[op] || op, text: r.output, error: r.error }]);
  }

  function resetStack() { setCells([]); }
  function truncateAt(i: number) { setCells((prev) => prev.slice(0, i)); }

  async function copy(text: string) {
    try { await navigator.clipboard.writeText(text); } catch { /* ignore */ }
  }

  return (
    <div className="section">
      <div className="banner info">
        {t("入力に対して変換を重ねがけできます(前段の出力が次段の入力)。すべてローカル処理。ハッシュ(MD5/SHA*)は一方向です。","Stack transforms on the input (each output feeds the next). All local. Hashes (MD5/SHA*) are one-way.")}
      </div>

      <div className="field" style={{ marginBottom: 8 }}>
        <label>{t("入力","Input")}</label>
        <textarea
          style={{ width: "100%", minHeight: 90 }}
          value={input}
          onChange={(e) => { setInput(e.target.value); setCells([]); }}
          placeholder={t("ここに文字列を貼り付け","Paste text here")}
          spellCheck={false}
        />
      </div>

      <div style={{ marginBottom: 10 }}>
        {OP_GROUPS.map((g) => (
          <span className="op-group" key={g.label}>
            <span className="lbl">{g.label}</span>
            {g.ops.map(([op, lbl]) => (
              <button key={op} onClick={() => applyOp(op)}>{lbl}</button>
            ))}
          </span>
        ))}
        {cells.length > 0 && (
          <button className="danger" style={{ marginLeft: 6 }} onClick={resetStack}>{t("スタック消去","Clear stack")}</button>
        )}
      </div>

      <div className="muted" style={{ marginBottom: 6 }}>
        {t("現在の作業対象","Current target")}: <b>{cells.length ? cells[cells.length - 1].op : t("入力","Input")}</b> ({working.length} {t("文字","chars")}) — {t("次の変換はこの出力に対して適用されます。","the next transform applies to this output.")}
      </div>

      {cells.map((c, i) => (
        <div className="dec-cell" key={i}>
          <div className="head">
            <b>{i + 1}. {c.op}</b>
            <span className="muted">{c.error ? "" : `${c.text.length} 文字`}</span>
            <div className="spacer" style={{ flex: 1 }} />
            <button onClick={() => copy(c.text)}>{t("コピー","Copy")}</button>
            <button onClick={() => truncateAt(i)}>{t("ここから削除","Remove from here")}</button>
          </div>
          {c.error
            ? <pre style={{ color: "var(--red)" }}>{t("エラー","Error")}: {c.error}</pre>
            : <pre>{c.text}</pre>}
        </div>
      ))}
    </div>
  );
}

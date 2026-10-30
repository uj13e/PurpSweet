import { useEffect, useRef, useState } from "react";
import { api, FlowDetail, IntruderResult, IntruderStatus, PayloadSetInput } from "../api";
import { rawRequest } from "../util";
import IntruderResults from "./IntruderResults";
import { useT } from "../i18n";

const MARK = "§"; // §

type SetType = "list" | "range" | "file";
interface SetEditor {
  type: SetType;
  list: string;
  from: number;
  to: number;
  step: number;
  fileValues: string[];
  fileName: string;
}
const blankSet = (): SetEditor => ({
  type: "list", list: "", from: 1, to: 100, step: 1, fileValues: [], fileName: "",
});

const buildModes = (t: (ja: string, en: string) => string): [string, string][] => [
  ["sniper", t("Sniper(1箇所ずつ・1リスト)", "Sniper (one position at a time, 1 list)")],
  ["battering_ram", t("Battering ram(全箇所に同じ値)", "Battering ram (same value in all)")],
  ["pitchfork", t("Pitchfork(位置ごとのリストを並列)", "Pitchfork (parallel list per position)")],
  ["cluster_bomb", t("Cluster bomb(全組み合わせ)", "Cluster bomb (all combinations)")],
];

function countPositions(t: string): number | null {
  const n = (t.match(/§/g) || []).length;
  if (n % 2 !== 0) return null; // unbalanced
  return n / 2;
}

function toPayload(s: SetEditor): PayloadSetInput {
  if (s.type === "range") return { type: "range", from: s.from, to: s.to, step: s.step };
  if (s.type === "file") return { type: "file", values: s.fileValues };
  return { type: "list", values: s.list.split(/\r?\n/).filter((x) => x.length > 0) };
}

interface Props {
  seed: FlowDetail | null;
  onSeedConsumed: () => void;
}

export default function IntruderView({ seed, onSeedConsumed }: Props) {
  const t = useT();
  const MODES = buildModes(t);
  const [scheme, setScheme] = useState("https");
  const [host, setHost] = useState("");
  const [port, setPort] = useState(0);
  const [template, setTemplate] = useState("GET /?q=test HTTP/1.1\nHost: example.com\n\n");
  const [attackType, setAttackType] = useState<"sniper" | "battering_ram" | "pitchfork" | "cluster_bomb">("sniper");
  const [sets, setSets] = useState<SetEditor[]>([blankSet()]);
  const [grep, setGrep] = useState("");
  const [concurrency, setConcurrency] = useState(20);
  const [delayMs, setDelayMs] = useState(0);
  const [retries, setRetries] = useState(3);
  const [autoPopout, setAutoPopout] = useState(false);
  const [recordHistory, setRecordHistory] = useState(false);
  const taRef = useRef<HTMLTextAreaElement>(null);

  const [attackId, setAttackId] = useState<string | null>(null);
  const [status, setStatus] = useState<IntruderStatus | null>(null);
  const [allResults, setAllResults] = useState<IntruderResult[]>([]);
  const receivedRef = useRef<number>(0);
  const [error, setError] = useState("");
  const seededId = useRef<number | null>(null);

  // seed from history
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

  const positions = countPositions(template);
  const neededSets = attackType === "sniper" || attackType === "battering_ram" ? 1 : positions || 0;

  // keep sets array sized to neededSets
  useEffect(() => {
    setSets((prev) => {
      if (neededSets <= 0) return prev;
      if (prev.length === neededSets) return prev;
      const next = prev.slice(0, neededSets);
      while (next.length < neededSets) next.push(blankSet());
      return next;
    });
  }, [neededSets]);

  // poll while running — incremental: only fetch results newer than lastIdx.
  useEffect(() => {
    if (!attackId) return;
    let live = true;
    const tick = async () => {
      try {
        const s = await api.intruderGet(attackId, receivedRef.current);
        if (!live) return;
        if (s.results.length) {
          receivedRef.current += s.results.length;
          setAllResults((prev) => prev.concat(s.results));
        }
        setStatus(s);
        const behind = s.result_count > receivedRef.current;
        if (s.status === "running" || behind) setTimeout(tick, behind ? 50 : 300);
      } catch {
        /* stop polling on error */
      }
    };
    tick();
    return () => { live = false; };
  }, [attackId]);

  function popOut(id: string | null = attackId) {
    if (!id) return;
    const url = location.pathname + location.search + "#intruder=" + encodeURIComponent(id);
    window.open(url, "intruder_" + id, "width=1200,height=850,menubar=no,toolbar=no");
  }

  function addMarker() {
    const ta = taRef.current;
    if (!ta) return;
    const s = ta.selectionStart, e = ta.selectionEnd;
    const v = template;
    const wrapped = v.slice(0, s) + MARK + v.slice(s, e) + MARK + v.slice(e);
    setTemplate(wrapped);
  }
  function clearMarkers() { setTemplate(template.split(MARK).join("")); }

  function updateSet(i: number, patch: Partial<SetEditor>) {
    setSets((prev) => prev.map((s, j) => (j === i ? { ...s, ...patch } : s)));
  }

  async function onFile(i: number, file: File) {
    const text = await file.text();
    const vals = text.split(/\r?\n/).filter((x) => x.length > 0);
    updateSet(i, { fileValues: vals, fileName: `${file.name} (${vals.length})` });
  }

  async function start() {
    setError("");
    if (positions === null) { setError(t("マーカー § の数が奇数です(位置ごとに §値§ のペアが必要)。", "Odd number of § markers (each position needs a §value§ pair).")); return; }
    if (positions === 0) { setError(t("差し込み位置がありません。テキストを選択して「§ 位置に設定」を押してください。", "No payload positions. Select text and click \"§ mark position\".")); return; }
    let h = host;
    if (!h) {
      const m = template.match(/host:\s*([^\r\n:]+)/i);
      if (m) h = m[1].trim();
    }
    if (!h) { setError(t("ターゲット host を入力してください。", "Enter the target host.")); return; }
    const payload_sets = sets.slice(0, neededSets).map(toPayload);
    // Pre-open the popup synchronously (inside the click) so popup blockers
    // don't kill it; we point it at the attack once we have the id.
    let win: Window | null = null;
    if (autoPopout) win = window.open("about:blank", "intruder_popup", "width=1200,height=850,menubar=no,toolbar=no");
    try {
      const r = await api.intruderStart({
        scheme, host: h, port,
        template, attack_type: attackType,
        payload_sets,
        grep: grep.split(/\r?\n/).filter((x) => x.length > 0),
        concurrency, delay_ms: delayMs, retries, record_history: recordHistory,
      });
      setStatus(null);
      setAllResults([]);
      receivedRef.current = 0;
      setAttackId(r.attack_id);
      if (win) win.location.href = location.pathname + location.search + "#intruder=" + encodeURIComponent(r.attack_id);
    } catch (e: any) {
      if (win) win.close();
      setError(String(e.message || e));
    }
  }

  async function stop() {
    if (attackId) await api.intruderStop(attackId);
  }

  const running = status?.status === "running";

  return (
    <div className="section" style={{ maxWidth: "unset" }}>
      <div className="banner info">
        {t("差し込み位置を", "Wrap payload positions in")} <span className="kbd">{MARK}{t("値", "value")}{MARK}</span>{t("で囲みます(テキストを選択して「§ 位置に設定」)。送信は Scope 登録済みホストのみ。", ". Select text and click \"§ mark position\". Sends only to scoped hosts.")} <b>{t("同時実行数を上げると高速化します。", "Raise concurrency to go faster.")}</b>
      </div>

      <div className="row" style={{ marginBottom: 10 }}>
        <div className="field"><label>scheme</label>
          <select value={scheme} onChange={(e) => setScheme(e.target.value)}>
            <option value="https">https</option><option value="http">http</option>
          </select>
        </div>
        <div className="field grow"><label>host</label>
          <input type="text" value={host} placeholder={t("example.com（空ならHostヘッダから）", "example.com (blank = from Host header)")} onChange={(e) => setHost(e.target.value)} />
        </div>
        <div className="field"><label>port {t("(0=既定)", "(0=default)")}</label>
          <input type="number" style={{ width: 90 }} value={port} onChange={(e) => setPort(Number(e.target.value))} />
        </div>
        <div className="field"><label>{t("攻撃モード", "Attack type")}</label>
          <select value={attackType} onChange={(e) => setAttackType(e.target.value as any)}>
            {MODES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </div>
      </div>

      <div className="repeater-cols" style={{ alignItems: "stretch" }}>
        {/* left: request template + positions */}
        <div className="repeater-col">
          <div className="row" style={{ marginBottom: 6 }}>
            <label>{t("リクエスト・テンプレート", "Request template")}</label>
            <div className="spacer" style={{ flex: 1 }} />
            <button onClick={addMarker}>§ {t("位置に設定", "mark position")}</button>
            <button onClick={clearMarkers}>{t("マーカー全消去", "Clear markers")}</button>
            <span className={"pill " + (positions === null ? "warn" : "")}>
              {positions === null ? t("§ が奇数", "§ odd") : `${t("位置", "Positions")}: ${positions}`}
            </span>
          </div>
          <textarea ref={taRef} style={{ flex: 1, minHeight: 260 }} value={template}
            onChange={(e) => setTemplate(e.target.value)} spellCheck={false} />
        </div>

        {/* right: payloads + rate + grep */}
        <div className="repeater-col">
          <label>{t("ペイロード", "Payloads")}{neededSets > 1 ? ` (${neededSets} ${t("セット", "sets")})` : ""}</label>
          <div style={{ overflow: "auto", maxHeight: 300 }}>
            {sets.slice(0, Math.max(1, neededSets)).map((s, i) => (
              <div className="card" key={i} style={{ padding: 10, marginBottom: 8 }}>
                <div className="row" style={{ marginBottom: 6 }}>
                  <b>{neededSets > 1 ? `位置 ${i + 1}` : "ペイロード"}</b>
                  <select value={s.type} onChange={(e) => updateSet(i, { type: e.target.value as SetType })}>
                    <option value="list">{t("リスト", "List")}</option>
                    <option value="range">{t("数値範囲", "Number range")}</option>
                    <option value="file">{t("ファイル", "File")}</option>
                  </select>
                </div>
                {s.type === "list" && (
                  <textarea style={{ width: "100%", minHeight: 80 }} placeholder={t("1行1値", "one value per line")} value={s.list}
                    onChange={(e) => updateSet(i, { list: e.target.value })} spellCheck={false} />
                )}
                {s.type === "range" && (
                  <div className="row">
                    <div className="field"><label>from</label><input type="number" style={{ width: 90 }} value={s.from} onChange={(e) => updateSet(i, { from: Number(e.target.value) })} /></div>
                    <div className="field"><label>to</label><input type="number" style={{ width: 90 }} value={s.to} onChange={(e) => updateSet(i, { to: Number(e.target.value) })} /></div>
                    <div className="field"><label>step</label><input type="number" style={{ width: 70 }} value={s.step} onChange={(e) => updateSet(i, { step: Number(e.target.value) })} /></div>
                  </div>
                )}
                {s.type === "file" && (
                  <div className="row">
                    <input type="file" onChange={(e) => e.target.files && e.target.files[0] && onFile(i, e.target.files[0])} />
                    <span className="muted">{s.fileName}</span>
                  </div>
                )}
              </div>
            ))}
          </div>

          <div className="row" style={{ marginTop: 6 }}>
            <div className="field"><label>{t("同時実行数", "Concurrency")} *</label><input type="number" style={{ width: 80 }} value={concurrency} min={1} onChange={(e) => setConcurrency(Math.max(1, Number(e.target.value)))} /></div>
            <div className="field"><label>{t("間隔 ms", "Delay ms")} *</label><input type="number" style={{ width: 90 }} value={delayMs} min={0} onChange={(e) => setDelayMs(Math.max(0, Number(e.target.value)))} /></div>
            <div className="field"><label title={t("接続/タイムアウト失敗時に自動で再試行する回数(0〜10)。精度重視なら3以上。", "Auto-retry count for connection/timeout failures (0-10). 3+ for accuracy.")}>{t("再試行", "Retries")}</label><input type="number" style={{ width: 70 }} value={retries} min={0} max={10} onChange={(e) => setRetries(Math.max(0, Math.min(10, Number(e.target.value))))} /></div>
            <div className="field grow"><label>{t("grep(1行1語・応答本文に含めば一致)", "grep (one per line; matches response body)")}</label>
              <input type="text" value={grep.replace(/\n/g, " ")} placeholder="error, SQL, root:" onChange={(e) => setGrep(e.target.value)} />
            </div>
          </div>

          <div className="row" style={{ marginTop: 8, alignItems: "center" }}>
            {!running ? (
              <button className="primary" onClick={start}>▶ {t("攻撃開始", "Start attack")}</button>
            ) : (
              <button className="danger" onClick={stop}>■ {t("停止", "Stop")}</button>
            )}
            <label className="muted" style={{ display: "flex", alignItems: "center", gap: 4, cursor: "pointer" }}>
              <input type="checkbox" checked={autoPopout} onChange={(e) => setAutoPopout(e.target.checked)} />
              {t("開始時に別ウィンドウで結果表示", "Open results in a new window on start")}
            </label>
            <label className="muted" style={{ display: "flex", alignItems: "center", gap: 4, cursor: "pointer" }} title={t("全リクエストをHTTP履歴にも記録(大量攻撃では履歴が膨れます)", "Also record every request into HTTP history (floods it for big attacks)")}>
              <input type="checkbox" checked={recordHistory} onChange={(e) => setRecordHistory(e.target.checked)} />
              {t("履歴に記録", "Record to history")}
            </label>
            {status && (
              <span className="muted mono">
                {status.status} · {status.done}/{status.total}
              </span>
            )}
          </div>
          {error && <div className="banner warn" style={{ marginTop: 8 }}>{error}</div>}
        </div>
      </div>

      {/* results */}
      {(status || allResults.length > 0) && (
        <IntruderResults attackId={attackId} status={status} results={allResults} onPopOut={() => popOut()} />
      )}
    </div>
  );
}

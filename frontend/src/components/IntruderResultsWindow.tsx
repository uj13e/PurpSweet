import { useEffect, useRef, useState } from "react";
import { api, IntruderResult, IntruderStatus } from "../api";
import IntruderResults from "./IntruderResults";
import { useT } from "../i18n";

/** Standalone, live-polling results view shown in a popped-out window.
 * Reads the attack id from the URL hash (#intruder=<id>) and polls the same
 * backend the main app uses, so it updates in real time on its own. */
export default function IntruderResultsWindow({ attackId }: { attackId: string }) {
  const t = useT();
  const [status, setStatus] = useState<IntruderStatus | null>(null);
  const [all, setAll] = useState<IntruderResult[]>([]);
  const recv = useRef(0);

  useEffect(() => {
    let live = true;
    const tick = async () => {
      try {
        const s = await api.intruderGet(attackId, recv.current);
        if (!live) return;
        if (s.results.length) {
          recv.current += s.results.length;
          setAll((prev) => prev.concat(s.results));
        }
        setStatus(s);
        document.title = `Intruder ${s.host || ""} ${s.done}/${s.total}`;
        const behind = s.result_count > recv.current;
        if (s.status === "running" || behind) setTimeout(tick, behind ? 50 : 400);
      } catch {
        if (live) setTimeout(tick, 1500);
      }
    };
    tick();
    return () => { live = false; };
  }, [attackId]);

  return (
    <div className="section" style={{ maxWidth: "unset", padding: 12 }}>
      <div className="toolbar" style={{ borderRadius: 6 }}>
        <b>Intruder</b>
        {status && <span className="muted mono">{status.host}</span>}
        {status && <span className="muted mono">{status.status} · {status.done}/{status.total}</span>}
        {status?.grep?.length ? <span className="muted mono">grep: {status.grep.join(", ")}</span> : null}
      </div>
      {status || all.length ? (
        <IntruderResults attackId={attackId} status={status} results={all} />
      ) : (
        <p className="muted">{t("結果を待っています…", "Waiting for results…")}</p>
      )}
    </div>
  );
}

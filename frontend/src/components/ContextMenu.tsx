import { useEffect } from "react";

export interface CtxItem {
  label?: string;
  onClick?: () => void;
  sep?: boolean;
  header?: string;
}

export default function ContextMenu({
  x, y, items, onClose,
}: { x: number; y: number; items: CtxItem[]; onClose: () => void }) {
  useEffect(() => {
    const close = () => onClose();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("click", close);
    window.addEventListener("resize", close);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("resize", close);
      window.removeEventListener("keydown", onKey);
    };
  }, [onClose]);

  // clamp to viewport
  const left = Math.min(x, window.innerWidth - 220);
  const top = Math.min(y, window.innerHeight - Math.min(items.length * 30 + 12, 400));

  return (
    <div className="ctx-menu" style={{ left, top }} onClick={(e) => e.stopPropagation()}>
      {items.map((it, i) =>
        it.sep ? (
          <div key={i} className="ctx-sep" />
        ) : it.header ? (
          <div key={i} className="ctx-label">{it.header}</div>
        ) : (
          <div key={i} className="ctx-item" onClick={() => { it.onClick?.(); onClose(); }}>
            {it.label}
          </div>
        )
      )}
    </div>
  );
}

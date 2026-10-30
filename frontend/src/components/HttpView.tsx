import type { ReactElement } from "react";

// Read-only, syntax-highlighted view of a raw HTTP request or response.
// Colors: method / path / version, header name vs value, and status code.

function codeClass(code: number): string {
  if (code >= 500) return "h-code-5xx";
  if (code >= 400) return "h-code-4xx";
  if (code >= 300) return "h-code-3xx";
  if (code >= 200) return "h-code-2xx";
  return "";
}

function renderFirstLine(line: string): ReactElement {
  // Response: HTTP/1.1 200 OK
  const resp = line.match(/^(HTTP\/[\d.]+)\s+(\d{3})\s*(.*)$/);
  if (resp) {
    return (
      <>
        <span className="h-ver">{resp[1]} </span>
        <span className={codeClass(Number(resp[2]))}>{resp[2]}</span>
        {resp[3] ? <span className="h-reason"> {resp[3]}</span> : null}
      </>
    );
  }
  // Request: GET /path HTTP/1.1
  const req = line.match(/^([A-Z]+)\s+(\S+)\s+(HTTP\/[\d.]+)$/);
  if (req) {
    return (
      <>
        <span className="h-method">{req[1]}</span>{" "}
        <span className="h-path">{req[2]}</span>{" "}
        <span className="h-ver">{req[3]}</span>
      </>
    );
  }
  return <span>{line}</span>;
}

function renderHeader(line: string): ReactElement {
  const c = line.indexOf(":");
  if (c <= 0) return <span>{line}</span>;
  return (
    <>
      <span className="h-hname">{line.slice(0, c)}</span>
      <span className="h-hsep">:</span>
      <span className="h-hval">{line.slice(c + 1)}</span>
    </>
  );
}

export default function HttpView({ raw, className }: { raw: string; className?: string }) {
  const norm = (raw || "").replace(/\r\n/g, "\n");
  const idx = norm.indexOf("\n\n");
  const head = idx >= 0 ? norm.slice(0, idx) : norm;
  const body = idx >= 0 ? norm.slice(idx + 2) : "";
  const lines = head.split("\n");

  const parts: ReactElement[] = [];
  lines.forEach((line, i) => {
    if (i > 0) parts.push(<span key={"nl" + i}>{"\n"}</span>);
    parts.push(<span key={i}>{i === 0 ? renderFirstLine(line) : renderHeader(line)}</span>);
  });
  if (idx >= 0) {
    parts.push(<span key="body" className="h-body">{"\n\n" + body}</span>);
  }

  return <pre className={"raw " + (className || "")}>{parts}</pre>;
}

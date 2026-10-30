export type SortDir = "asc" | "desc";

function cmp(a: any, b: any): number {
  if (typeof a === "boolean") a = a ? 1 : 0;
  if (typeof b === "boolean") b = b ? 1 : 0;
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a ?? "").localeCompare(String(b ?? ""), undefined, { numeric: true });
}

// Stable-ish sort by an accessor; returns a new array.
export function sortBy<T>(rows: T[], get: (r: T) => any, dir: SortDir): T[] {
  const arr = [...rows];
  arr.sort((x, y) => {
    const c = cmp(get(x), get(y));
    return dir === "asc" ? c : -c;
  });
  return arr;
}

export function statusClass(code: number): string {
  if (code >= 500) return "code-5xx";
  if (code >= 400) return "code-4xx";
  if (code >= 300) return "code-3xx";
  if (code >= 200) return "code-2xx";
  return "muted";
}

export function sevClass(sev: string): string {
  return "sev-" + sev; // sev-high | sev-medium | sev-low | sev-info
}

export function fmtTime(iso: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toLocaleTimeString();
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

// Render an HTTP request in raw form for display/edit.
export function rawRequest(
  method: string,
  path: string,
  headers: [string, string][],
  body: string
): string {
  const lines = [`${method || "GET"} ${path || "/"} HTTP/1.1`];
  for (const [k, v] of headers || []) lines.push(`${k}: ${v}`);
  lines.push("");
  lines.push(body || "");
  return lines.join("\n");
}

// Parse a raw request (first line + headers + blank + body) back into fields.
export function parseRawRequest(raw: string): {
  method: string;
  path: string;
  headers: [string, string][];
  body: string;
} {
  const norm = raw.replace(/\r\n/g, "\n");
  const idx = norm.indexOf("\n\n");
  const head = idx >= 0 ? norm.slice(0, idx) : norm;
  const body = idx >= 0 ? norm.slice(idx + 2) : "";
  const [first, ...hlines] = head.split("\n");
  const parts = first.trim().split(/\s+/);
  const method = parts[0] || "GET";
  const path = parts[1] || "/";
  const headers: [string, string][] = [];
  for (const line of hlines) {
    const c = line.indexOf(":");
    if (c > 0) headers.push([line.slice(0, c).trim(), line.slice(c + 1).trim()]);
  }
  return { method, path, headers, body };
}

export function rawResponse(
  status: number,
  reason: string,
  headers: [string, string][],
  body: string
): string {
  const lines = [`HTTP/1.1 ${status} ${reason || ""}`];
  for (const [k, v] of headers || []) lines.push(`${k}: ${v}`);
  lines.push("");
  lines.push(body || "");
  return lines.join("\n");
}

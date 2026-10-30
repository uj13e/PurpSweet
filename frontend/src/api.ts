// Typed API client for the local backend.

export interface FlowSummary {
  id: number;
  created_at: string | null;
  source: string;
  method: string;
  scheme?: string;
  host: string;
  url: string;
  status_code: number;
  mime: string;
  resp_length: number;
  duration_ms: number;
  in_scope: boolean;
}

export interface FlowDetail extends FlowSummary {
  port: number;
  path: string;
  req_headers: [string, string][];
  req_body: string;
  reason: string;
  resp_headers: [string, string][];
  resp_body: string;
  resp_body_truncated: boolean;
}

export interface PendingIntercept {
  flow_id: string;
  method: string;
  scheme: string;
  host: string;
  port: number;
  path: string;
  url: string;
  headers: [string, string][];
  body: string;
  in_scope: boolean;
}

export interface ScopeRule {
  id: number;
  host_pattern: string;
  enabled: boolean;
  note: string;
}

export interface RepeaterResponse {
  flow_id: number;
  status_code: number;
  reason: string;
  headers: [string, string][];
  body: string;
  resp_length: number;
  truncated: boolean;
  duration_ms: number;
  http_version: string;
}

async function j<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let msg = `${res.status}`;
    try {
      const b = await res.json();
      msg = b.detail || JSON.stringify(b);
    } catch {
      /* ignore */
    }
    throw new Error(msg);
  }
  return res.json();
}

export const api = {
  status: () => fetch("/api/status").then((r) => j<any>(r)),

  flows: (params: Record<string, string | number | boolean> = {}) => {
    const q = new URLSearchParams(
      Object.entries(params)
        .filter(([, v]) => v !== "" && v !== undefined && v !== null)
        .map(([k, v]) => [k, String(v)])
    );
    return fetch("/api/flows?" + q.toString()).then((r) => j<FlowSummary[]>(r));
  },
  flow: (id: number) => fetch(`/api/flows/${id}`).then((r) => j<FlowDetail>(r)),
  clearFlows: () => fetch("/api/flows", { method: "DELETE" }).then((r) => j<any>(r)),

  intercept: () =>
    fetch("/api/intercept").then((r) =>
      j<{ enabled: boolean; pending: PendingIntercept[] }>(r)
    ),
  setIntercept: (enabled: boolean) =>
    fetch("/api/intercept/state", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled }),
    }).then((r) => j<any>(r)),
  resolveIntercept: (
    flowId: string,
    decision: {
      action: "forward" | "drop";
      method?: string;
      path?: string;
      headers?: [string, string][];
      body?: string;
    }
  ) =>
    fetch(`/api/intercept/${flowId}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(decision),
    }).then((r) => j<any>(r)),

  repeaterSend: (payload: {
    method: string;
    scheme: string;
    host: string;
    port: number;
    path: string;
    headers: [string, string][];
    body: string;
    verify_tls?: boolean;
  }) =>
    fetch("/api/repeater/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }).then((r) => j<RepeaterResponse>(r)),

  scope: () => fetch("/api/scope").then((r) => j<ScopeRule[]>(r)),
  addScope: (host_pattern: string, note = "") =>
    fetch("/api/scope", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ host_pattern, note, enabled: true }),
    }).then((r) => j<any>(r)),
  updateScope: (id: number, r2: Partial<ScopeRule> & { host_pattern: string }) =>
    fetch(`/api/scope/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: true, note: "", ...r2 }),
    }).then((r) => j<any>(r)),
  deleteScope: (id: number) =>
    fetch(`/api/scope/${id}`, { method: "DELETE" }).then((r) => j<any>(r)),

  ca: () => fetch("/api/ca").then((r) => j<any>(r)),

  getSettings: () => fetch("/api/settings").then((r) => j<SettingsOut>(r)),
  setSettings: (p: { upstream_proxy?: string; connect_timeout?: number; nvd_online?: boolean; nvd_api_key?: string }) =>
    fetch("/api/settings", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(p),
    }).then((r) => j<SettingsOut>(r)),

  // ---- Intruder ----
  intruderPreview: (template: string) =>
    fetch("/api/intruder/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ template }),
    }).then((r) => j<{ positions: number; base_values: string[]; marker: string }>(r)),

  intruderStart: (payload: IntruderStartPayload) =>
    fetch("/api/intruder/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }).then((r) => j<{ attack_id: string; total: number; status: string; attack_type: string; concurrency: number; delay_ms: number }>(r)),

  intruderStop: (id: string) =>
    fetch(`/api/intruder/${id}/stop`, { method: "POST" }).then((r) => j<any>(r)),

  // Incremental poll: results in completion order starting at `offset`.
  intruderGet: (id: string, offset = 0) =>
    fetch(`/api/intruder/${id}?offset=${offset}`).then((r) => j<IntruderStatus>(r)),
  intruderResultDetail: (id: string, index: number) =>
    fetch(`/api/intruder/${id}/result/${index}`).then((r) => j<{ index: number; request: string; response: string }>(r)),

  // ---- Decoder ----
  transform: (op: string, input: string) =>
    fetch("/api/tools/transform", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ op, input }),
    }).then((r) => j<{ output: string; error?: string }>(r)),

  // ---- Scanner ----
  passiveRun: (in_scope_only: boolean) =>
    fetch("/api/scanner/passive/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ in_scope_only }),
    }).then((r) => j<{ scanned_flows: number; new_findings: number }>(r)),
  findings: (params: { kind?: string; severity?: string } = {}) => {
    const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v) as [string, string][]);
    return fetch("/api/scanner/findings?" + q.toString()).then((r) => j<Finding[]>(r));
  },
  clearFindings: () => fetch("/api/scanner/findings", { method: "DELETE" }).then((r) => j<any>(r)),
  activeScanStart: (payload: ActiveScanPayload) =>
    fetch("/api/scanner/active/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }).then((r) => j<{ scan_id: string; total: number; status: string }>(r)),
  activeScanStop: (id: string) => fetch(`/api/scanner/active/${id}/stop`, { method: "POST" }).then((r) => j<any>(r)),
  activeScanGet: (id: string) => fetch(`/api/scanner/active/${id}`).then((r) => j<ActiveScanStatus>(r)),

  cveRun: (p: { in_scope_only: boolean; online?: boolean; api_key?: string; limit?: number }) =>
    fetch("/api/scanner/cve/run", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(p),
    }).then((r) => j<{ cve_id: string; online: boolean; techs: number; status: string }>(r)),
  cveGet: (id: string) => fetch(`/api/scanner/cve/${id}`).then((r) => j<CveStatus>(r)),

  sitemap: () => fetch("/api/sitemap").then((r) => j<SitemapNode[]>(r)),

  // ---- WebSocket ----
  wsMessages: (params: { host?: string; conn?: string; q?: string } = {}) => {
    const p = new URLSearchParams(Object.entries(params).filter(([, v]) => v) as [string, string][]);
    return fetch("/api/ws/messages?" + p.toString()).then((r) => j<WsMessageSummary[]>(r));
  },
  wsMessageDetail: (id: number) => fetch(`/api/ws/messages/${id}`).then((r) => j<any>(r)),
  wsConns: () => fetch("/api/ws/conns").then((r) => j<any[]>(r)),
  clearWsMessages: () => fetch("/api/ws/messages", { method: "DELETE" }).then((r) => j<any>(r)),
  wsConnect: (url: string, headers: [string, string][]) =>
    fetch("/api/ws/repeater/connect", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, headers }),
    }).then((r) => j<{ conn_id: string; status: string; url: string }>(r)),
  wsSend: (cid: string, message: string, is_text = true) =>
    fetch(`/api/ws/repeater/${cid}/send`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, is_text }),
    }).then((r) => j<any>(r)),
  wsCloseConn: (cid: string) => fetch(`/api/ws/repeater/${cid}/close`, { method: "POST" }).then((r) => j<any>(r)),
  wsRepeaterGet: (cid: string) => fetch(`/api/ws/repeater/${cid}`).then((r) => j<WsRepeaterStatus>(r)),
};

export interface WsMessageSummary {
  id: number;
  created_at: string | null;
  conn_id: string;
  host: string;
  path: string;
  url: string;
  from_client: boolean;
  is_text: boolean;
  length: number;
  in_scope: boolean;
  preview: string;
}

export interface WsRepeaterMsg {
  dir: "in" | "out";
  text: string;
  binary: boolean;
  ts: number;
}

export interface WsRepeaterStatus {
  conn_id: string;
  url: string;
  host: string;
  status: string;
  error: string;
  messages: WsRepeaterMsg[];
}

export interface Finding {
  id: number;
  created_at: string | null;
  kind: string;
  severity: string;
  confidence: string;
  title: string;
  detail: string;
  host: string;
  url: string;
  method: string;
  param: string;
  evidence: string;
  flow_id?: number;
}

export interface ActiveScanPayload {
  scheme: string;
  host: string;
  port: number;
  method: string;
  path: string;
  headers: [string, string][];
  body: string;
  categories: string[];
  techniques: string[];
  time_delay: number;
  follow_redirects: boolean;
  scan_headers: boolean;
  concurrency: number;
  delay_ms: number;
  record_history?: boolean;
}

export interface ActiveScanStatus {
  scan_id: string;
  status: string;
  host: string;
  total: number;
  done: number;
  found: number;
  error: string;
  findings: Finding[];
}

export interface SettingsOut {
  upstream_proxy: string;
  connect_timeout: number;
  nvd_online: boolean;
  nvd_api_key_set: boolean;
}

export interface CveTech {
  host: string;
  url: string;
  product: string;
  version: string;
  source: string;
  evidence: string;
}

export interface CveStatus {
  cve_id: string;
  status: string;
  online: boolean;
  total: number;
  done: number;
  found: number;
  error: string;
  techs: CveTech[];
  findings: Finding[];
}

export interface SitemapNode {
  name: string;
  scheme?: string;
  in_scope?: boolean;
  count: number;
  methods: string[];
  children: SitemapNode[];
}

export interface PayloadSetInput {
  type: "list" | "range" | "file";
  values?: string[];
  from?: number;
  to?: number;
  step?: number;
}

export interface IntruderStartPayload {
  scheme: string;
  host: string;
  port: number;
  template: string;
  attack_type: "sniper" | "battering_ram" | "pitchfork" | "cluster_bomb";
  payload_sets: PayloadSetInput[];
  grep: string[];
  concurrency: number;
  delay_ms: number;
  retries: number;
  record_history?: boolean;
  verify_tls?: boolean;
}

export interface IntruderResult {
  index: number;
  payloads: string[];
  status_code: number;
  resp_length: number;
  duration_ms: number;
  matched: boolean;
  matches: string[];
  error: string;
  retries?: number;
  flow_id?: number;
  request?: string;
  response?: string;
}

export interface IntruderStatus {
  attack_id: string;
  status: string;
  attack_type: string;
  host: string;
  total: number;
  done: number;
  error: string;
  grep: string[];
  concurrency: number;
  delay_ms: number;
  results: IntruderResult[];
  result_count: number;
}

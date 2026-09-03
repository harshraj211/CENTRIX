/**
 * VulnGuard API Client
 * Thin facade over fetch + WebSocket for the backend at localhost:8000
 */

const BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000"
const WS_BASE = BASE.replace(/^http/, "ws")

export interface ScanConfig {
  target: string
  scope?: string[]
  imported_urls?: string[]
  imported_requests?: Record<string, any>[]
  sequence_workflows?: Record<string, any>[]
  browser_workflows?: Record<string, any>[]
  authorized: boolean
  profile?: "quick" | "full" | "api" | "custom"
  safety?: "passive" | "standard" | "aggressive"
  depth?: number
  timeout?: number
  concurrency?: number
  max_requests?: number
  respect_robots?: boolean
  auth_token?: string | null
  label?: string | null
  environment?: string
}

export interface ScanStatus {
  scan_id: string
  status: string
  stage: string
  progress: number
  findings_count: number
  requests_sent: number
  urls_discovered: number
  started_at: string | null
  finished_at: string | null
  duration_s: number | null
}

export interface ApiFinding {
  id: string
  scan_id: string
  title: string
  severity: string
  category: string
  target: string
  parameter: string
  confidence: string
  status: string
  found_at: string
  cwe: string | null
  cvss: number | null
}

export interface ApiReport {
  id: string
  scan_id: string
  name: string
  report_type: string
  target: string
  generated_at: string
  status: string
  findings_count: number
  size: string
  format: string
}

// ── Scan API ────────────────────────────────────────────────────────────────
export const scanApi = {
  async start(config: ScanConfig): Promise<{ scan_id: string; status: string; message: string }> {
    const res = await fetch(`${BASE}/api/scan/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(config),
    })
    if (!res.ok) throw new Error(`Failed to start scan: ${res.statusText}`)
    return res.json()
  },

  async status(scanId: string): Promise<ScanStatus> {
    const res = await fetch(`${BASE}/api/scan/${scanId}/status`)
    if (!res.ok) throw new Error(`Status fetch failed: ${res.statusText}`)
    return res.json()
  },

  async pause(scanId: string): Promise<void> {
    await fetch(`${BASE}/api/scan/${scanId}/pause`, { method: "POST" })
  },

  async stop(scanId: string): Promise<void> {
    await fetch(`${BASE}/api/scan/${scanId}/stop`, { method: "POST" })
  },

  async list(): Promise<any[]> {
    const res = await fetch(`${BASE}/api/scans`)
    if (!res.ok) return []
    return res.json()
  },
}

// ── Findings API ─────────────────────────────────────────────────────────────
export const findingsApi = {
  async list(scanId?: string): Promise<ApiFinding[]> {
    const url = scanId
      ? `${BASE}/api/findings?scan_id=${scanId}`
      : `${BASE}/api/findings`
    const res = await fetch(url)
    if (!res.ok) return []
    return res.json()
  },

  async get(findingId: string): Promise<ApiFinding | null> {
    const res = await fetch(`${BASE}/api/findings/${findingId}`)
    if (!res.ok) return null
    return res.json()
  },

  async updateStatus(findingId: string, status: "Open" | "In Review" | "Fixed" | "Accepted"): Promise<ApiFinding> {
    const res = await fetch(`${BASE}/api/findings/${findingId}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    })
    if (!res.ok) throw new Error(`Status update failed: ${await res.text()}`)
    return res.json()
  },

  async retest(findingId: string): Promise<{ scan_id: string; finding_id: string; status: string }> {
    const res = await fetch(`${BASE}/api/findings/${findingId}/retest`, { method: "POST" })
    if (!res.ok) throw new Error(`Retest failed: ${await res.text()}`)
    return res.json()
  },
}

// ── Reports API ──────────────────────────────────────────────────────────────
export const reportsApi = {
  async generate(params: {
    scan_id: string
    format?: "json" | "html" | "pdf" | "sarif" | "junit" | "evidence"
    report_type?: "technical" | "executive" | "compliance"
    target_scope?: string
  }): Promise<ApiReport> {
    const res = await fetch(`${BASE}/api/reports/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(params),
    })
    if (!res.ok) throw new Error(`Report generation failed: ${res.statusText}`)
    return res.json()
  },

  async list(): Promise<ApiReport[]> {
    const res = await fetch(`${BASE}/api/reports`)
    if (!res.ok) return []
    return res.json()
  },

  downloadUrl(reportId: string): string {
    return `${BASE}/api/reports/${reportId}/download`
  },
}

export const manualApi = {
  async replay(request: { scan_id: string; method: string; url: string; headers?: Record<string, string>; body?: string }) {
    const res = await fetch(`${BASE}/api/manual/replay`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(request) })
    if (!res.ok) throw new Error(`Replay failed: ${await res.text()}`)
    return res.json() as Promise<{ status: number; headers: Record<string, string>; body: string; length: number; duration_ms: number }>
  },
  async compare(left: object, right: object) {
    const res = await fetch(`${BASE}/api/manual/compare-responses`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ left, right }) })
    if (!res.ok) throw new Error(`Compare failed: ${await res.text()}`)
    return res.json() as Promise<{ left_status: number; right_status: number; left_length: number; right_length: number; status_changed: boolean; length_delta: number }>
  },
  async saveRequest(request: { scan_id: string; method: string; url: string; headers?: Record<string, string>; body?: string; response?: object; note?: string }) {
    const res = await fetch(`${BASE}/api/manual/save-request`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(request) })
    if (!res.ok) throw new Error(`Save failed: ${await res.text()}`)
    return res.json() as Promise<any>
  },
  async corpus(scanId?: string) {
    const res = await fetch(`${BASE}/api/manual/corpus${scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""}`)
    if (!res.ok) throw new Error("Corpus fetch failed")
    return res.json() as Promise<any[]>
  },
  async corpusItem(requestId: string) {
    const res = await fetch(`${BASE}/api/manual/corpus/${requestId}`)
    if (!res.ok) throw new Error("Corpus item fetch failed")
    return res.json() as Promise<any>
  },
  async compareCorpus(leftId: string, rightId: string) {
    const res = await fetch(`${BASE}/api/manual/compare-corpus?left_id=${encodeURIComponent(leftId)}&right_id=${encodeURIComponent(rightId)}`, { method: "POST" })
    if (!res.ok) throw new Error(`Corpus compare failed: ${await res.text()}`)
    return res.json() as Promise<any>
  },
  async intruder(request: { scan_id: string; method: string; url: string; headers?: Record<string, string>; body?: string; marker: string; payloads: string[]; delay_ms?: number; max_requests?: number; match_text?: string; extract_regex?: string }) {
    const res = await fetch(`${BASE}/api/manual/intruder/run`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(request) })
    if (!res.ok) throw new Error(`Intruder failed: ${await res.text()}`)
    return res.json() as Promise<{ scan_id: string; results: any[] }>
  },
  async runPassive(scanId: string) {
    const res = await fetch(`${BASE}/api/manual/passive/${scanId}/run`, { method: "POST" })
    if (!res.ok) throw new Error(`Passive scan failed: ${await res.text()}`)
    return res.json() as Promise<{ scan_id: string; imported: number }>
  },
  async decode(mode: string, value: string) {
    const res = await fetch(`${BASE}/api/manual/decode`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mode, value }) })
    if (!res.ok) throw new Error(`Decode failed: ${await res.text()}`)
    return res.json() as Promise<{ mode: string; output: string }>
  },
  async proxyStatus() {
    const res = await fetch(`${BASE}/api/manual/proxy/status`)
    if (!res.ok) throw new Error("Proxy status failed")
    return res.json() as Promise<any>
  },
  async proxyStart(scanId = "") {
    const res = await fetch(`${BASE}/api/manual/proxy/start${scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""}`, { method: "POST" })
    if (!res.ok) throw new Error("Proxy start failed")
    return res.json() as Promise<any>
  },
  async proxyStop() {
    const res = await fetch(`${BASE}/api/manual/proxy/stop`, { method: "POST" })
    if (!res.ok) throw new Error("Proxy stop failed")
    return res.json() as Promise<any>
  },
  async caStatus() {
    const res = await fetch(`${BASE}/api/manual/proxy/ca/status`)
    if (!res.ok) throw new Error("CA status failed")
    return res.json() as Promise<any>
  },
  async caGenerate() {
    const res = await fetch(`${BASE}/api/manual/proxy/ca/generate`, { method: "POST" })
    if (!res.ok) throw new Error(`CA generation failed: ${await res.text()}`)
    return res.json() as Promise<any>
  },
  caDownloadUrl() {
    return `${BASE}/api/manual/proxy/ca/download`
  },
  async leafGenerate(hostname: string) {
    const res = await fetch(`${BASE}/api/manual/proxy/ca/leaf/generate?hostname=${encodeURIComponent(hostname)}`, { method: "POST" })
    if (!res.ok) throw new Error(`Leaf generation failed: ${await res.text()}`)
    return res.json() as Promise<any>
  },
  async browserOpen(url: string, scanId = "", useProxy = false) {
    const res = await fetch(`${BASE}/api/manual/browser/open?url=${encodeURIComponent(url)}&scan_id=${encodeURIComponent(scanId)}&use_proxy=${useProxy}`, { method: "POST" })
    if (!res.ok) throw new Error(`Browser open failed: ${await res.text()}`)
    return res.json() as Promise<any>
  },
  async browserStatus() {
    const res = await fetch(`${BASE}/api/manual/browser/status`)
    if (!res.ok) throw new Error("Browser status failed")
    return res.json() as Promise<any>
  },
  async browserClose() {
    const res = await fetch(`${BASE}/api/manual/browser/close`, { method: "POST" })
    if (!res.ok) throw new Error("Browser close failed")
    return res.json() as Promise<any>
  },
}

export const importApi = {
  async preview(format: "openapi" | "postman" | "har" | "graphql", document: object, base_url?: string) {
    const res = await fetch(`${BASE}/api/import/preview`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ format, document, base_url }) })
    if (!res.ok) throw new Error(`Import failed: ${await res.text()}`)
    return res.json() as Promise<{ endpoints: { method: string; url: string }[] }>
  },
}
export const evidenceApi = { async list(scanId?: string) { const res = await fetch(`${BASE}/api/evidence${scanId ? `?scan_id=${scanId}` : ""}`); if (!res.ok) throw new Error("Evidence fetch failed"); return res.json() as Promise<any[]> } }

export const evidenceBundleUrl = (findingId: string) => `${BASE}/api/evidence/bundle/${findingId}`

export const integrationsApi = {
  async status() {
    const res = await fetch(`${BASE}/api/integrations/status`)
    if (!res.ok) throw new Error("Integration status failed")
    return res.json() as Promise<any>
  },
  async searchCves(query: string) {
    const res = await fetch(`${BASE}/api/integrations/cves/search?query=${encodeURIComponent(query)}`)
    if (!res.ok) throw new Error(`CVE search failed: ${await res.text()}`)
    return res.json() as Promise<{ query: string; results: any[] }>
  },
  async runNuclei(scan_id: string, severity: string[] = []) {
    const res = await fetch(`${BASE}/api/integrations/nuclei/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_id, severity }),
    })
    if (!res.ok) throw new Error(`Nuclei run failed: ${await res.text()}`)
    return res.json() as Promise<{ scan_id: string; imported: number; results: any[]; engine?: string }>
  },
  async pushFinding(findingId: string, destination: "local" | "slack" | "github" | "jira" = "local", note = "") {
    const res = await fetch(`${BASE}/api/integrations/findings/${findingId}/push`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ destination, note }),
    })
    if (!res.ok) throw new Error(`Push failed: ${await res.text()}`)
    return res.json() as Promise<any>
  },
  async outbox(findingId?: string) {
    const res = await fetch(`${BASE}/api/integrations/outbox${findingId ? `?finding_id=${encodeURIComponent(findingId)}` : ""}`)
    if (!res.ok) throw new Error("Outbox fetch failed")
    return res.json() as Promise<any[]>
  },
}

export const proofApi = {
  async list(findingId?: string) {
    const res = await fetch(`${BASE}/api/proof/tasks${findingId ? `?finding_id=${encodeURIComponent(findingId)}` : ""}`)
    if (!res.ok) throw new Error("Proof task fetch failed")
    return res.json() as Promise<any[]>
  },
  async create(findingId: string) {
    const res = await fetch(`${BASE}/api/proof/${findingId}/task`, { method: "POST" })
    if (!res.ok) throw new Error(`Proof task create failed: ${await res.text()}`)
    return res.json() as Promise<any>
  },
  async run(taskId: string) {
    const res = await fetch(`${BASE}/api/proof/${taskId}/run`, { method: "POST" })
    if (!res.ok) throw new Error(`Proof task run failed: ${await res.text()}`)
    return res.json() as Promise<any>
  },
}

export const schedulesApi = {
  async list() {
    const res = await fetch(`${BASE}/api/schedules`)
    if (!res.ok) throw new Error("Schedule fetch failed")
    return res.json() as Promise<any[]>
  },
  async create(payload: { name: string; frequency: "once" | "hourly" | "daily" | "weekly"; first_run_at?: string | null; config: ScanConfig }) {
    const res = await fetch(`${BASE}/api/schedules`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
    if (!res.ok) throw new Error(`Schedule create failed: ${await res.text()}`)
    return res.json() as Promise<any>
  },
  async run(scheduleId: string) {
    const res = await fetch(`${BASE}/api/schedules/${scheduleId}/run`, { method: "POST" })
    if (!res.ok) throw new Error(`Schedule run failed: ${await res.text()}`)
    return res.json() as Promise<any>
  },
  async setStatus(scheduleId: string, status: "enabled" | "paused" | "completed") {
    const res = await fetch(`${BASE}/api/schedules/${scheduleId}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    })
    if (!res.ok) throw new Error(`Schedule update failed: ${await res.text()}`)
    return res.json() as Promise<any>
  },
  async remove(scheduleId: string) {
    const res = await fetch(`${BASE}/api/schedules/${scheduleId}`, { method: "DELETE" })
    if (!res.ok) throw new Error(`Schedule delete failed: ${await res.text()}`)
    return res.json() as Promise<any>
  },
}

export const authzApi = {
  async profiles() {
    const res = await fetch(`${BASE}/api/authz/profiles`)
    if (!res.ok) throw new Error("Auth profiles fetch failed")
    return res.json() as Promise<any[]>
  },
  async createProfile(profile: { name: string; role: string; headers?: Record<string, string>; cookies?: Record<string, string>; notes?: string }) {
    const res = await fetch(`${BASE}/api/authz/profiles`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(profile) })
    if (!res.ok) throw new Error(`Create profile failed: ${await res.text()}`)
    return res.json() as Promise<any>
  },
  async deleteProfile(profileId: string) {
    const res = await fetch(`${BASE}/api/authz/profiles/${profileId}`, { method: "DELETE" })
    if (!res.ok) throw new Error(`Delete profile failed: ${await res.text()}`)
    return res.json() as Promise<any>
  },
  async matrixRuns(scanId?: string) {
    const res = await fetch(`${BASE}/api/authz/matrix/runs${scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""}`)
    if (!res.ok) throw new Error("Matrix runs fetch failed")
    return res.json() as Promise<any[]>
  },
  async runMatrix(payload: { scan_id: string; request_ids?: string[]; profile_ids?: string[] }) {
    const res = await fetch(`${BASE}/api/authz/matrix/run`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) })
    if (!res.ok) throw new Error(`Authorization matrix failed: ${await res.text()}`)
    return res.json() as Promise<any>
  },
}

export const oobApi = {
  async createToken(scanId = "", findingId = "") {
    const res = await fetch(`${BASE}/api/oob/token?scan_id=${encodeURIComponent(scanId)}&finding_id=${encodeURIComponent(findingId)}`, { method: "POST" })
    if (!res.ok) throw new Error(`OOB token failed: ${await res.text()}`)
    return res.json() as Promise<any>
  },
  async events(token?: string) {
    const res = await fetch(`${BASE}/api/oob/events${token ? `?token=${encodeURIComponent(token)}` : ""}`)
    if (!res.ok) throw new Error("OOB events fetch failed")
    return res.json() as Promise<any[]>
  },
  callbackUrl(token: string) {
    return `${BASE}/api/oob/hit/${token}`
  },
}

// ── WebSocket Log Stream ──────────────────────────────────────────────────────
export function createScanLogStream(
  scanId: string,
  onMessage: (msg: string) => void,
  onDone: () => void,
): WebSocket {
  const ws = new WebSocket(`${WS_BASE}/ws/scan/${scanId}`)

  ws.onmessage = (event) => {
    const msg: string = event.data
    if (msg === "__DONE__") {
      onDone()
      ws.close()
      return
    }
    if (msg !== "[PING]") {
      onMessage(msg)
    }
  }

  ws.onerror = () => {
    onMessage("[ERROR] WebSocket connection lost — check backend is running")
    onDone()
  }

  return ws
}

// ── Health Check ─────────────────────────────────────────────────────────────
export async function checkBackendHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${BASE}/health`, { signal: AbortSignal.timeout(3000) })
    return res.ok
  } catch {
    return false
  }
}

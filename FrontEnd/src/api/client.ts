/**
 * VulnGuard API Client
 * Thin facade over fetch + WebSocket for the backend at localhost:8000
 */

const BASE = "http://localhost:8000"
const WS_BASE = "ws://localhost:8000"

export interface ScanConfig {
  target: string
  scope?: string[]
  profile?: "quick" | "full" | "api" | "custom"
  safety?: "passive" | "standard" | "aggressive"
  depth?: number
  timeout?: number
  concurrency?: number
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
}

// ── Reports API ──────────────────────────────────────────────────────────────
export const reportsApi = {
  async generate(params: {
    scan_id: string
    format?: "json" | "html" | "pdf"
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

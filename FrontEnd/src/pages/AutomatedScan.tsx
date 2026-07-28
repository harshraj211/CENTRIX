import { useState, useEffect, useRef } from "react"
import {
  Pause,
  Square,
  CheckCircle2,
  Circle,
  Loader2,
  ExternalLink,
  Play,
  Download,
  Copy,
  ChevronDown,
} from "lucide-react"

interface AutomatedScanProps {
  onNavigate: (page: string) => void
  scanActive: boolean
  setScanActive: (active: boolean) => void
  progress: number
  setProgress: React.Dispatch<React.SetStateAction<number>>
}

const STAGES_DETAILS: Record<string, string[]> = {
  validate: ["DNS Resolution Lookup", "ICMP Ping Latency Check", "SSL Certificate Verification", "Robots.txt Scraping"],
  discover: ["TCP Port Scanning (80, 443, 8080)", "Virtual Host Fuzzing", "Parameter Mining", "Hidden Directory Fuzzing"],
  crawl: ["Recursive Sitemap Parser", "Dynamic HTML Page Crawling", "Form Input Discovery", "JS Code Mapping"],
  probe: ["SQL Injection Payloads", "Reflected XSS Signatures", "Path Traversal String Checks", "Broken Access Verification"],
  exploit: ["Software Composition Audit (SCA)", "CWE Severity Rating Mapping", "Confidence Validation Tests"],
  report: ["HTML Output compilation", "PDF Encryption Setup", "Executive Summary Generator"],
}

const STAGES = [
  { id: "validate", label: "Target Validation", duration: "0:04" },
  { id: "discover", label: "Discovery & Enumeration", duration: "1:23" },
  { id: "crawl", label: "Crawling & Sitemap", duration: "3:47" },
  { id: "probe", label: "Active Probing", duration: "8:12" },
  { id: "exploit", label: "Vulnerability Analysis", duration: "2:41" },
  { id: "report", label: "Report Generation", duration: "0:30" },
]

const FINDINGS_LIVE = [
  { id: "VLN-0247", title: "Server-side path traversal in file export", severity: "Critical", url: "/export?file=", ts: "14:26:02" },
  { id: "VLN-0246", title: "SQL Injection via user_id Parameter", severity: "Critical", url: "/api/users?user_id=", ts: "14:24:31" },
  { id: "VLN-0245", title: "Reflected XSS in search parameter", severity: "High", url: "/search?q=<>", ts: "14:28:11" },
  { id: "VLN-0244", title: "Insecure Direct Object Reference", severity: "High", url: "/api/users/{id}", ts: "14:24:38" },
  { id: "VLN-0243", title: "Open redirect on login callback", severity: "Medium", url: "/auth/callback?next=", ts: "14:22:19" },
  { id: "VLN-0242", title: "Cookie without HttpOnly flag", severity: "Low", url: "/", ts: "14:21:05" },
  { id: "VLN-0241", title: "TLS 1.0 still accepted", severity: "Low", url: "TLS negotiation", ts: "14:19:51" },
]

const SEV_CONFIG: Record<string, { text: string; bg: string; border: string }> = {
  Critical: { text: "text-critical", bg: "bg-critical/10", border: "border-critical/25" },
  High: { text: "text-high", bg: "bg-high/10", border: "border-high/25" },
  Medium: { text: "text-medium", bg: "bg-medium/10", border: "border-medium/25" },
  Low: { text: "text-low", bg: "bg-low/10", border: "border-low/25" },
  Info: { text: "text-info", bg: "bg-info/10", border: "border-info/25" },
}

const MOCK_CLI_LOGS = [
  "[INFO] Starting VulnGuard Engine v4.0.1...",
  "[INFO] Loading signature databases (12,845 checks loaded)...",
  "[INFO] Performing DNS lookup for api.acmecorp.com...",
  "[SUCCESS] Target IP resolved: 104.22.3.94",
  "[INFO] SSL/TLS Negotiation started...",
  "[WARN] TLS 1.0 is enabled on this endpoint (CVE-2015-2808).",
  "[INFO] Initiating crawler module...",
  "[INFO] Crawling sitemap.xml...",
  "[SUCCESS] Found 341 unique URLs in sitemap.",
  "[INFO] Discovery phase completed.",
  "[INFO] Starting active probing (SQLi, XSS, SSRF)...",
  "[INFO] Auditing /search endpoint...",
  "[ALERT] Potential parameter injection vulnerability detected on 'q'.",
  "[INFO] Auditing /api/profile/update endpoint...",
  "[INFO] Auditing /export endpoint...",
  "[ALERT] Path traversal suspected on parameter 'file'.",
  "[INFO] Launching automated exploitation analysis...",
  "[CRITICAL] Boolean-based SQL Injection CONFIRMED on /search parameter 'q'.",
  "[CRITICAL] File system read accomplished via path traversal on /export.",
  "[INFO] Generating final vulnerability report...",
  "[SUCCESS] Scan completed. 2 Critical, 2 High, 1 Medium, 2 Low vulnerabilities detected."
]

export default function AutomatedScan({
  onNavigate,
  scanActive,
  setScanActive,
  progress,
  setProgress,
}: AutomatedScanProps) {
  const [paused, setPaused] = useState(false)
  const [expandedStage, setExpandedStage] = useState<string | null>("probe")
  const [logs, setLogs] = useState<string[]>([])
  const [logFilter, setLogFilter] = useState<"all" | "info" | "alerts" | "success">("all")
  
  // RPS Fuzzing Graph Simulator State
  const [rpsPoints, setRpsPoints] = useState<number[]>([24, 28, 30, 22, 35, 41, 38, 45, 42, 50, 48, 55])

  const consoleEndRef = useRef<HTMLDivElement>(null)

  // Simulation loop for scan progress & console logs
  useEffect(() => {
    if (!scanActive) return
    const logsCount = Math.floor((progress / 100) * MOCK_CLI_LOGS.length)
    setLogs(MOCK_CLI_LOGS.slice(0, Math.max(1, logsCount)))
  }, [progress, scanActive])

  useEffect(() => {
    if (!scanActive || paused) return
    if (progress >= 100) {
      setScanActive(false)
      return
    }

    const interval = setInterval(() => {
      setProgress((prev) => {
        const next = Math.min(prev + 3, 100)
        return next
      })
      
      // Add a fluctuating RPS value
      setRpsPoints((prev) => {
        const nextVal = Math.floor(35 + Math.random() * 25)
        const updated = [...prev.slice(1), nextVal]
        return updated
      })
    }, 1500)

    return () => clearInterval(interval)
  }, [paused, progress, scanActive])

  // Scroll to bottom of terminal logs
  useEffect(() => {
    if (consoleEndRef.current) {
      consoleEndRef.current.scrollIntoView({ behavior: "smooth" })
    }
  }, [logs])

  // Filter logs logic
  const filteredLogs = logs.filter((log) => {
    if (logFilter === "all") return true
    if (logFilter === "info") return log.includes("[INFO]")
    if (logFilter === "alerts") return log.includes("[ALERT]") || log.includes("[CRITICAL]") || log.includes("[WARN]")
    if (logFilter === "success") return log.includes("[SUCCESS]")
    return true
  })

  // Convert RPS values into an SVG drawing path line
  const svgPathStr = rpsPoints
    .map((val, i) => `${i * 20},${100 - (val / 80) * 100}`)
    .join(" L ")

  const handleStopScan = () => {
    setScanActive(false)
  }

  // ────────────────────────────────────────────────────────
  // RENDER: Completed Scan / Inactive Workspace
  // ────────────────────────────────────────────────────────
  if (!scanActive) {
    return (
      <div className="p-6 max-w-5xl mx-auto space-y-6">
        <div className="bg-card border border-border rounded-lg p-6 flex flex-col md:flex-row items-center justify-between shadow-sm">
          <div className="space-y-1 mb-4 md:mb-0">
            <div className="flex items-center gap-2">
              <CheckCircle2 size={16} className="text-emerald" />
              <span className="text-emerald text-xs font-semibold uppercase tracking-wider">
                Scan Session Completed
              </span>
            </div>
            <h1 className="text-ink text-xl font-semibold">api.acmecorp.com</h1>
            <p className="text-ink-3 text-xs font-mono mt-0.5">
              SCN-0091 · Finished 14:32:01 UTC · Duration: 12m 42s
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => onNavigate("reports")}
              className="flex items-center gap-1.5 px-4 py-2 bg-accent text-white rounded text-xs font-semibold hover:bg-accent/90 transition-colors shadow-lg shadow-accent/20"
            >
              <Download size={12} />
              Export Report
            </button>
            <button
              onClick={() => onNavigate("scan-setup")}
              className="flex items-center gap-1.5 px-4 py-2 bg-elevated border border-border hover:border-border-hi rounded text-xs font-semibold text-ink transition-colors"
            >
              <Play size={12} fill="currentColor" />
              Configure New Scan
            </button>
          </div>
        </div>

        {/* Analytics Overview for Completed Scan */}
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: "Total Requests Sent", value: "21,492", sub: "100% complete" },
            { label: "Resolved Endpoints", value: "341", sub: "100% crawl depth" },
            { label: "Critical Findings", value: "2", sub: "SQLi & Traversal confirmed" },
            { label: "Average Response", value: "142ms", sub: "Host safety: STABLE" },
          ].map((c) => (
            <div key={c.label} className="bg-card border border-border rounded-lg p-4 font-sans">
              <p className="text-ink-3 text-[10px] font-semibold uppercase tracking-wider mb-2">{c.label}</p>
              <p className="text-ink text-xl font-bold font-mono">{c.value}</p>
              <p className="text-ink-3 text-[11px] mt-1">{c.sub}</p>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-3 gap-6">
          {/* List of findings for the completed scan (2/3 width) */}
          <div className="col-span-2 bg-card border border-border rounded-lg overflow-hidden">
            <div className="px-5 py-3 border-b border-border bg-panel/30 flex items-center justify-between">
              <p className="text-ink text-sm font-semibold">Detected Findings</p>
              <span className="text-ink-3 text-xs font-mono">7 findings total</span>
            </div>
            <div className="divide-y divide-border/60">
              {FINDINGS_LIVE.map((f) => {
                const sev = SEV_CONFIG[f.severity]
                return (
                  <div
                    key={f.id}
                    onClick={() => onNavigate("findings")}
                    className="p-4 hover:bg-elevated/20 transition-colors cursor-pointer flex justify-between items-start gap-4"
                  >
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`text-[10px] px-1.5 py-px rounded border font-semibold ${sev.text} ${sev.bg} ${sev.border}`}>
                          {f.severity}
                        </span>
                        <span className="text-ink text-xs font-semibold">{f.title}</span>
                      </div>
                      <span className="text-ink-3 text-[11px] font-mono">{f.url}</span>
                    </div>
                    <span className="text-ink-3 text-[11px] font-mono shrink-0">{f.ts}</span>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Raw Log Excerpts (1/3 width) */}
          <div className="bg-card border border-border rounded-lg p-5 flex flex-col justify-between">
            <div>
              <p className="text-ink text-sm font-semibold mb-3">Scan Logs summary</p>
              <div className="bg-canvas border border-border rounded p-4 font-mono text-[10px] text-[#a9b1d6] space-y-1.5 max-h-[220px] overflow-y-auto">
                <div>[INFO] Target resolved: 104.22.3.94</div>
                <div className="text-medium">[WARN] TLS 1.0 supported</div>
                <div>[INFO] Discovery: 341 URLs found</div>
                <div className="text-critical">[CRITICAL] SQL Injection proven</div>
                <div className="text-critical">[CRITICAL] Path traversal proven</div>
                <div className="text-emerald">[SUCCESS] Scan finished safely.</div>
              </div>
            </div>
            <button
              onClick={() => {
                // Simulate copying logs
                navigator.clipboard.writeText(MOCK_CLI_LOGS.join("\n"))
                alert("Logs copied to clipboard!")
              }}
              className="w-full flex items-center justify-center gap-2 py-2 bg-elevated border border-border hover:border-border-hi rounded text-ink text-xs font-semibold mt-4 transition-colors"
            >
              <Copy size={12} />
              Copy Full Console Log
            </button>
          </div>
        </div>
      </div>
    )
  }

  // ────────────────────────────────────────────────────────
  // RENDER: Running Active Scan Console
  // ────────────────────────────────────────────────────────
  return (
    <div className="flex h-full min-h-0 overflow-hidden">
      {/* ── Left: scan status ── */}
      <div className="flex-1 overflow-y-auto p-6 space-y-5">
        {/* Scan header */}
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="w-2 h-2 rounded-full bg-accent animate-pulse" />
              <span className="text-accent text-xs font-semibold uppercase tracking-wider">
                Scan Active
              </span>
            </div>
            <h1 className="text-ink text-xl font-semibold">api.acmecorp.com</h1>
            <p className="text-ink-3 text-xs font-mono mt-0.5">
              SCN-0091 · Full Scan · Target Mode: {STAGES.find((s) => progress < 100 && STAGES_DETAILS[s.id]?.length > 0)?.label || "Active Probing"}
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => setPaused(!paused)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-elevated border border-border rounded text-ink-2 text-xs hover:text-ink hover:border-border-hi transition-colors"
            >
              {paused ? <Play size={12} fill="currentColor" /> : <Pause size={12} />}
              {paused ? "Resume" : "Pause"}
            </button>
            <button
              onClick={handleStopScan}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-critical/8 border border-critical/20 rounded text-critical text-xs hover:bg-critical/12 transition-colors"
            >
              <Square size={12} />
              Stop
            </button>
          </div>
        </div>

        {/* Progress bar */}
        <div>
          <div className="flex justify-between mb-1.5">
            <span className="text-ink-2 text-xs font-medium">Overall Progress</span>
            <span className="text-ink text-xs font-mono font-bold">{progress}%</span>
          </div>
          <div className="h-1.5 bg-elevated rounded-full overflow-hidden">
            <div
              className="h-full bg-accent rounded-full transition-all duration-500"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>

        {/* Side-by-Side Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {/* Left Column: Pipeline with expandable accordion detail */}
          <div className="space-y-4">
            <div className="bg-card border border-border rounded-lg overflow-hidden shadow-sm">
              <div className="px-5 py-3 border-b border-border bg-panel/30">
                <p className="text-ink text-sm font-semibold">Execution Pipeline</p>
              </div>
              <div className="p-4 space-y-1">
                {STAGES.map((s, i) => {
                  let status = "pending"
                  // Calculate stage based on current progress
                  const currentIdx = Math.floor((progress / 100) * STAGES.length)
                  if (i < currentIdx) {
                    status = "done"
                  } else if (i === currentIdx) {
                    status = "running"
                  }

                  const isExpanded = expandedStage === s.id

                  return (
                    <div key={s.id} className="border-b border-border/40 last:border-0 py-1.5">
                      <div
                        onClick={() => setExpandedStage(isExpanded ? null : s.id)}
                        className="flex items-center justify-between cursor-pointer group"
                      >
                        <div className="flex items-center gap-3">
                          {status === "done" ? (
                            <CheckCircle2 size={15} className="text-emerald" />
                          ) : status === "running" ? (
                            <Loader2 size={15} className="text-accent animate-spin" />
                          ) : (
                            <Circle size={15} className="text-ink-3" />
                          )}
                          <span
                            className={`text-xs ${
                              status === "running"
                                ? "text-ink font-semibold"
                                : status === "done"
                                  ? "text-ink-2"
                                  : "text-ink-3"
                            }`}
                          >
                            {s.label}
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-ink-3 text-[10px] font-mono">{s.duration}</span>
                          <ChevronDown size={12} className={`text-ink-3 transition-transform ${isExpanded ? "rotate-180" : ""}`} />
                        </div>
                      </div>

                      {/* Accordion Detail list */}
                      {isExpanded && (
                        <div className="pl-6 pr-4 py-2 mt-1 bg-canvas/30 rounded space-y-1.5 text-[10px] font-mono text-ink-3">
                          {STAGES_DETAILS[s.id]?.map((task, idx) => (
                            <div key={idx} className="flex items-center justify-between">
                              <span>· {task}</span>
                              <span className={status === "done" || idx < 2 ? "text-emerald font-semibold" : status === "running" ? "text-accent font-semibold animate-pulse" : "text-ink-3"}>
                                {status === "done" || idx < 2 ? "COMPLETED" : status === "running" ? "FUZZING..." : "PENDING"}
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Simulated Live Requests-Per-Second Chart */}
            <div className="bg-card border border-border rounded-lg p-5 shadow-sm">
              <div className="flex justify-between items-center mb-3">
                <p className="text-ink text-sm font-semibold">Live Traffic Fuzz Rate</p>
                <div className="flex items-center gap-1.5 font-mono text-xs">
                  <span className="w-1.5 h-1.5 bg-accent rounded-full animate-ping" />
                  <span className="text-ink font-bold">{rpsPoints[rpsPoints.length - 1]} RPS</span>
                </div>
              </div>

              {/* Dynamic SVG Line */}
              <div className="h-[90px] w-full border border-border/40 bg-canvas/40 rounded p-1">
                <svg className="w-full h-full" viewBox="0 0 220 100" preserveAspectRatio="none">
                  {/* Fill background gradient path */}
                  <path
                    d={`M 0,100 L ${svgPathStr} L 220,100 Z`}
                    fill="rgba(90, 87, 255, 0.08)"
                  />
                  {/* Outline path line */}
                  <path
                    d={`M ${svgPathStr}`}
                    fill="none"
                    stroke="var(--color-accent)"
                    strokeWidth="1.5"
                    className="transition-all duration-300"
                  />
                </svg>
              </div>
            </div>
          </div>

          {/* Right Column: Live CLI Scan Console with search/filters */}
          <div className="bg-card border border-border rounded-lg overflow-hidden flex flex-col h-[400px] shadow-sm">
            <div className="px-4 py-2 border-b border-border flex items-center justify-between shrink-0 bg-panel/80">
              <div className="flex gap-2">
                {(["all", "info", "alerts", "success"] as const).map((lvl) => (
                  <button
                    key={lvl}
                    onClick={() => setLogFilter(lvl)}
                    className={`px-2 py-0.5 rounded text-[10px] uppercase font-semibold transition-colors ${
                      logFilter === lvl
                        ? "bg-accent/15 text-accent border border-accent/20"
                        : "text-ink-3 hover:text-ink-2"
                    }`}
                  >
                    {lvl}
                  </button>
                ))}
              </div>
              <span className="text-[10px] font-mono text-ink-3">Console Stream</span>
            </div>
            
            <div className="flex-1 bg-[#090d16] p-4 font-mono text-[11px] overflow-y-auto space-y-2 select-text shadow-inner">
              {filteredLogs.map((log, index) => {
                let colorClass = "text-[#a9b1d6]"
                if (log.startsWith("[SUCCESS]")) colorClass = "text-emerald font-semibold"
                else if (log.startsWith("[CRITICAL]")) colorClass = "text-critical font-semibold"
                else if (log.startsWith("[ALERT]")) colorClass = "text-high font-semibold"
                else if (log.startsWith("[WARN]")) colorClass = "text-medium font-semibold"
                else if (log.startsWith("[INFO]")) colorClass = "text-info"
                return (
                  <div key={index} className={colorClass}>
                    {log}
                  </div>
                )
              })}
              <div ref={consoleEndRef} />
            </div>

            <div className="px-4 py-2 border-t border-border shrink-0 bg-panel/30 flex items-center justify-between text-[10px] font-mono text-ink-3">
              <span>{filteredLogs.length} logs rendered</span>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(logs.join("\n"))
                  alert("Live log copied!")
                }}
                className="hover:text-ink flex items-center gap-1 transition-colors"
              >
                <Copy size={10} />
                Copy
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* ── Right: live findings ── */}
      <div className="w-[380px] shrink-0 border-l border-border flex flex-col overflow-hidden">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <p className="text-ink text-sm font-semibold">Live Vulnerabilities</p>
          <span className="text-ink-3 text-xs font-mono">
            {FINDINGS_LIVE.length} identified
          </span>
        </div>
        <div className="flex-1 overflow-y-auto">
          {FINDINGS_LIVE.map((f) => {
            const sev = SEV_CONFIG[f.severity]
            return (
              <div
                key={f.id}
                className="px-4 py-3.5 border-b border-border/60 hover:bg-elevated/20 transition-colors cursor-pointer"
                onClick={() => onNavigate("findings")}
              >
                <div className="flex items-start justify-between gap-2 mb-1.5">
                  <span
                    className={`shrink-0 px-1.5 py-px rounded-sm border text-[9px] font-bold tracking-wide uppercase ${sev.text} ${sev.bg} ${sev.border}`}
                  >
                    {f.severity}
                  </span>
                  <span className="text-ink-3 text-[10px] font-mono shrink-0">
                    {f.ts}
                  </span>
                </div>
                <p className="text-ink text-xs font-semibold leading-snug mb-1">{f.title}</p>
                <p className="text-ink-3 text-[10px] font-mono truncate">
                  {f.url}
                </p>
              </div>
            )
          })}
        </div>
        <div className="p-3 border-t border-border bg-panel/30">
          <button
            onClick={() => onNavigate("findings")}
            className="w-full flex items-center justify-center gap-1.5 py-2 bg-elevated border border-border hover:border-border-hi rounded text-ink text-xs font-semibold transition-colors"
          >
            Open Findings Dashboard <ExternalLink size={11} />
          </button>
        </div>
      </div>
    </div>
  )
}

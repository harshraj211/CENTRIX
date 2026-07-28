import { useState } from "react"
import {
  Play,
  AlertTriangle,
  ChevronRight,
  ExternalLink,
  TrendingDown,
  TrendingUp,
  Minus,
  Globe,
  Activity,
  CheckCircle,
  Loader2,
} from "lucide-react"

interface OverviewProps {
  onNavigate: (page: string, subTab?: string) => void
  findingsCount: number
  scanActive: boolean
}

export default function Overview({ onNavigate, findingsCount, scanActive }: OverviewProps) {
  // Quick scan target simulator state
  const [quickUrl, setQuickUrl] = useState("https://staging.acmecorp.com")
  const [quickScanning, setQuickScanning] = useState(false)
  const [quickScanStep, setQuickScanStep] = useState(0)

  const handleQuickScan = () => {
    if (quickScanning) return
    setQuickScanning(true)
    setQuickScanStep(1)
    setTimeout(() => setQuickScanStep(2), 1000)
    setTimeout(() => setQuickScanStep(3), 2000)
    setTimeout(() => {
      setQuickScanning(false)
      setQuickScanStep(0)
      onNavigate("scan-setup")
    }, 3200)
  }

  // Heatmap State
  const [selectedCell, setSelectedCell] = useState<{ l: number; i: number } | null>(null)

  const HEATMAP_VULS = [
    { id: "VLN-0245", name: "Logical SSRF Vector", host: "api.acmecorp.com", l: 4, i: 5, score: 20 },
    { id: "VLN-0246", name: "Boolean Blind SQLi", host: "app.acme.local", l: 3, i: 4, score: 12 },
    { id: "VLN-0247", name: "Path Traversal Export", host: "api.acmecorp.com", l: 5, i: 2, score: 10 },
  ]

  const getFilteredVuls = () => {
    if (!selectedCell) return HEATMAP_VULS
    return HEATMAP_VULS.filter(v => v.l === selectedCell.l && v.i === selectedCell.i)
  }

  // Dynamic calculations based on findingsCount prop (default 8)
  const totalFindings = findingsCount
  const criticalCount = totalFindings >= 8 ? 2 : totalFindings >= 4 ? 1 : 0
  const highCount = totalFindings >= 8 ? 3 : totalFindings >= 4 ? 2 : 1
  const mediumCount = totalFindings >= 8 ? 2 : totalFindings >= 3 ? 1 : 1
  const lowCount = totalFindings - (criticalCount + highCount + mediumCount)

  const SEVERITY = [
    { label: "Critical", count: criticalCount, pct: totalFindings > 0 ? Math.round((criticalCount / totalFindings) * 100) : 0, color: "#e54646" },
    { label: "High", count: highCount, pct: totalFindings > 0 ? Math.round((highCount / totalFindings) * 100) : 0, color: "#e07833" },
    { label: "Medium", count: mediumCount, pct: totalFindings > 0 ? Math.round((mediumCount / totalFindings) * 100) : 0, color: "#c99a1a" },
    { label: "Low", count: Math.max(0, lowCount), pct: totalFindings > 0 ? Math.round((Math.max(0, lowCount) / totalFindings) * 100) : 0, color: "#3d82f6" },
    { label: "Info", count: 0, pct: 0, color: "#64748b" },
  ]

  const BARS = [4, 6, 3, 7, 5, 8, 4, 9, 6, 11, 8, 12, 10, 14]
  const MAX_BAR = 15

  const SCANS = [
    {
      id: "SCN-0091",
      target: "api.acmecorp.com",
      type: "Full Scan",
      status: scanActive ? "Running" : "Completed",
      findings: scanActive ? totalFindings - 1 : totalFindings,
      critical: criticalCount,
      ran: "Just now",
    },
    {
      id: "SCN-0090",
      target: "app.acmecorp.com",
      type: "Quick Scan",
      status: "Completed",
      findings: 3,
      critical: 0,
      ran: "2 hours ago",
    },
    {
      id: "SCN-0089",
      target: "admin.acmecorp.com",
      type: "API Scan",
      status: "Completed",
      findings: 1,
      critical: 0,
      ran: "1 day ago",
    },
    {
      id: "SCN-0088",
      target: "auth.acmecorp.com",
      type: "Full Scan",
      status: "Failed",
      findings: 0,
      critical: 0,
      ran: "3 days ago",
    },
  ]

  const ALERTS = totalFindings >= 2 ? [
    {
      id: "VLN-0247",
      title: "Server-side Path Traversal in File Export",
      target: "api.acmecorp.com",
    },
    {
      id: "VLN-0246",
      title: "SQL Injection via user_id Parameter",
      target: "api.acmecorp.com",
    },
  ] : []

  const TARGETS = [
    { name: "api.acmecorp.com", grade: "F", color: "text-critical bg-critical/10 border-critical/20", issues: `${criticalCount} Critical, ${highCount} High` },
    { name: "app.acmecorp.com", grade: "B", color: "text-high bg-high/10 border-high/20", issues: "3 Medium, 1 Low" },
    { name: "admin.acmecorp.com", grade: "C", color: "text-medium bg-medium/10 border-medium/20", issues: "1 High" },
    { name: "auth.acmecorp.com", grade: "A", color: "text-emerald bg-emerald/10 border-emerald/20", issues: "0 Vulnerabilities" },
  ]

  const r = 52,
    cx = 70,
    cy = 70
  const circ = 2 * Math.PI * r
  let angle = 0
  const segments = SEVERITY.map((s) => {
    const arcLen = totalFindings > 0 ? (s.count / totalFindings) * circ : 0
    const rotation = angle - 90
    angle += totalFindings > 0 ? (s.count / totalFindings) * 360 : 0
    return { ...s, arcLen, rotation }
  })

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto">
      {/* ── Header ── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-ink text-xl font-semibold">Security Posture Overview</h1>
          <p className="text-ink-3 text-xs mt-0.5 font-mono">
            VulnGuard Engine v4.0.1 · Last updated: Just now
          </p>
        </div>
        <button
          onClick={() => onNavigate("scan-setup")}
          className="flex items-center gap-2 px-4 py-2 bg-accent text-white rounded text-sm font-medium hover:bg-accent/90 transition-colors shadow-lg shadow-accent/20"
        >
          <Play size={12} fill="currentColor" />
          Start New Scan
        </button>
      </div>

      {/* ── KPIs ── */}
      <div className="grid grid-cols-4 gap-4">
        {[
          {
            label: "Open Vulnerabilities",
            value: String(totalFindings),
            sub: `${totalFindings - 4} new this week`,
            trend: "up",
          },
          {
            label: "Critical Issues",
            value: String(criticalCount),
            sub: "Requires immediate attention",
            trend: "down",
          },
          {
            label: "Active Scans",
            value: scanActive ? "1" : "0",
            sub: scanActive ? "SCN-0091 executing" : "All scans finished",
            trend: scanActive ? "up" : "neutral",
          },
          {
            label: "Fixed This Month",
            value: "18",
            sub: "+12% improvement",
            trend: "up",
          },
        ].map((k) => (
          <div
            key={k.label}
            className="card-3d bg-card border border-border rounded-lg p-5 shadow-sm relative overflow-hidden group hover:border-border-hi transition-all duration-300"
          >
            <p className="text-ink-3 text-[10px] font-semibold uppercase tracking-widest mb-3">
              {k.label}
            </p>
            <p className="text-ink text-3xl font-semibold font-mono leading-none mb-2">
              {k.value}
            </p>
            <div className="flex items-center gap-1.5">
              {k.trend === "down" && (
                <TrendingDown size={12} className="text-emerald" />
              )}
              {k.trend === "up" && (
                <TrendingUp size={12} className="text-critical" />
              )}
              {k.trend === "neutral" && (
                <Minus size={12} className="text-ink-3" />
              )}
              <p
                className={`text-xs ${
                  k.trend === "down"
                    ? "text-emerald"
                    : k.trend === "up"
                      ? "text-critical/80"
                      : "text-ink-3"
                }`}
              >
                {k.sub}
              </p>
            </div>
            {/* Soft backdrop glow on hover */}
            <div className="absolute inset-0 bg-gradient-to-tr from-accent/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none" />
          </div>
        ))}
      </div>

      {/* ── Main Dashboard Content Grid ── */}
      <div className="space-y-5">
        {/* Row 1: Charts & Active Threat Path (3 columns) */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          {/* Donut Chart */}
          <div className="card-3d bg-card border border-border rounded-lg p-5 shadow-sm flex flex-col justify-between">
            <div>
              <p className="text-ink text-sm font-semibold mb-4">
                Severity Distribution
              </p>
              <div className="flex items-center gap-6">
                <div className="relative shrink-0">
                  <svg
                    width="140"
                    height="140"
                    viewBox="0 0 140 140"
                  >
                    <circle
                      cx={cx}
                      cy={cy}
                      r={r}
                      fill="none"
                      stroke="#161b26"
                      strokeWidth="11"
                    />
                    {segments.map((s, i) => (
                      <circle
                        key={i}
                        cx={cx}
                        cy={cy}
                        r={r}
                        fill="none"
                        stroke={s.color}
                        strokeWidth="11"
                        strokeDasharray={`${s.arcLen} ${circ - s.arcLen}`}
                        transform={`rotate(${s.rotation} ${cx} ${cy})`}
                        strokeLinecap="round"
                        className="transition-all duration-700"
                      />
                    ))}
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-ink font-mono text-2xl font-bold leading-none">
                      {totalFindings}
                    </span>
                    <span className="text-ink-3 text-[10px] uppercase font-semibold mt-1">
                      issues
                    </span>
                  </div>
                </div>
                
                <div className="space-y-2 flex-1">
                  {SEVERITY.map((s) => (
                    <div
                      key={s.label}
                      className="flex items-center justify-between"
                    >
                      <div className="flex items-center gap-2">
                        <span
                          className="w-2.5 h-2.5 rounded-sm shrink-0"
                          style={{ background: s.color }}
                        />
                        <span className="text-ink-2 text-xs font-medium">{s.label}</span>
                      </div>
                      <div className="flex items-center gap-2.5">
                        <span className="text-ink text-xs font-mono font-semibold">
                          {s.count}
                        </span>
                        <span className="text-ink-3 text-[10px] w-8 text-right font-mono">
                          {s.pct}%
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Bar chart */}
          <div className="card-3d bg-card border border-border rounded-lg p-5 shadow-sm flex flex-col justify-between">
            <div>
              <p className="text-ink text-sm font-semibold mb-3">
                Scan Traffic — Last 14 Days
              </p>
              <div className="flex items-end gap-1.5 h-24 pt-2">
                {BARS.map((v, i) => (
                  <div key={i} className="flex-1 flex items-end h-full">
                    <div
                      className="w-full rounded-sm transition-all hover:bg-accent cursor-pointer group relative"
                      style={{
                        height: `${(v / MAX_BAR) * 100}%`,
                        background:
                          i === BARS.length - 1
                            ? "var(--color-accent)"
                            : "rgba(90, 87, 255, 0.25)",
                      }}
                    >
                      {/* Tooltip */}
                      <span className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1 hidden group-hover:block bg-elevated border border-border text-[9px] font-mono text-ink px-1 py-0.5 rounded shadow-lg z-10 whitespace-nowrap">
                        {v} scans
                      </span>
                    </div>
                  </div>
                ))}
              </div>
              <div className="flex justify-between mt-2">
                <span className="text-ink-3 text-[10px] font-mono">14 days ago</span>
                <span className="text-ink-3 text-[10px] font-mono">Today</span>
              </div>
            </div>

            <div className="flex justify-between mt-3 pt-3 border-t border-border/80">
              {[
                { label: "Total Scans", value: "32" },
                { label: "Avg Duration", value: "8m 14s" },
                { label: "Success Rate", value: "96.8%" },
                { label: "API Requests", value: "245K" },
              ].map((m) => (
                <div key={m.label}>
                  <p className="text-ink-3 text-[9px] uppercase tracking-wider">
                    {m.label}
                  </p>
                  <p className="text-ink font-mono text-xs font-bold mt-0.5">
                    {m.value}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* Threat Canvas Mini-Card */}
          <div className="card-3d bg-card border border-border rounded-lg p-5 shadow-sm relative overflow-hidden flex flex-col justify-between">
            {/* Hologram scanline layer */}
            <div className="absolute inset-0 hologram-panel pointer-events-none z-0 opacity-40" />
            
            <div className="relative z-10 flex flex-col h-full justify-between">
              <div>
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-1.5">
                    <svg viewBox="0 0 24 24" width="14" height="14" fill="none" strokeWidth="2" className="text-critical" stroke="currentColor">
                      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    </svg>
                    <p className="text-ink text-sm font-semibold">Active Threat Path</p>
                  </div>
                  <span className="text-[9px] font-mono font-bold text-critical bg-critical/10 border border-critical/20 px-1.5 py-0.5 rounded animate-pulse">
                    SIMULATING EXFIL
                  </span>
                </div>
                
                <p className="text-ink-3 text-[11px] leading-relaxed mb-4">
                  Real-time attack graph mapping the lateral movement vector of active vulnerability <strong>VLN-0247</strong>.
                </p>

                <div className="bg-canvas/50 border border-border rounded p-4 mb-4 relative overflow-hidden flex items-center justify-between">
                  {/* Node-link visualization */}
                  <div className="flex items-center justify-between w-full relative z-10">
                    {/* Attacker Node */}
                    <div className="flex flex-col items-center gap-1">
                      <div className="w-6 h-6 rounded-full bg-critical/20 border border-critical/50 flex items-center justify-center text-[9px] font-semibold text-critical">
                        INT
                      </div>
                      <span className="text-[8px] font-mono text-ink-3">Attacker</span>
                    </div>

                    {/* Vector Connection Line */}
                    <div className="flex-1 h-0.5 border-t-2 border-dashed border-critical/40 relative mx-1">
                      <div className="absolute top-1/2 left-0 -translate-y-1/2 w-1.5 h-1.5 rounded-full bg-critical animate-ping" style={{ left: '50%' }} />
                    </div>

                    {/* Vulnerable Target */}
                    <div className="flex flex-col items-center gap-1">
                      <div className="w-6 h-6 rounded-full bg-high/20 border border-high/50 flex items-center justify-center text-[9px] font-semibold text-high animate-pulse">
                        APP
                      </div>
                      <span className="text-[8px] font-mono text-ink-3">SSRF</span>
                    </div>

                    {/* Vector Connection Line */}
                    <div className="flex-1 h-0.5 border-t-2 border-dashed border-medium/40 relative mx-1">
                      <div className="absolute top-1/2 left-0 -translate-y-1/2 w-1.5 h-1.5 rounded-full bg-medium animate-ping" style={{ left: '50%' }} />
                    </div>

                    {/* Exfiltrated Asset */}
                    <div className="flex flex-col items-center gap-1">
                      <div className="w-6 h-6 rounded-full bg-emerald/20 border border-emerald/50 flex items-center justify-center text-[9px] font-semibold text-emerald">
                        DB
                      </div>
                      <span className="text-[8px] font-mono text-ink-3">SQL_DB</span>
                    </div>
                  </div>
                  
                  {/* Grid Background Effect */}
                  <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(255,255,255,0.03)_1px,transparent_1px),linear-gradient(to_bottom,rgba(255,255,255,0.03)_1px,transparent_1px)] bg-[size:10px_10px]" />
                </div>
              </div>

              <button
                onClick={() => onNavigate("findings", "threat-path")}
                className="w-full flex items-center justify-center gap-1.5 py-1.5 bg-accent/10 border border-accent/20 hover:border-accent/40 text-accent rounded text-xs font-semibold transition-colors mt-auto"
              >
                Analyze Lateral Path Graph
              </button>
            </div>
          </div>
        </div>

        {/* Row 2: Recent Scan History & Quick Host Profiler */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          {/* Recent Scans Table */}
          <div className="lg:col-span-2 card-3d bg-card border border-border rounded-lg shadow-sm overflow-hidden flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between px-5 py-3.5 border-b border-border bg-panel/30">
                <p className="text-ink text-sm font-semibold">Recent Scan History</p>
                <button
                  onClick={() => onNavigate("automated-scan")}
                  className="text-accent text-xs font-semibold hover:underline flex items-center gap-0.5"
                >
                  View running console <ChevronRight size={12} />
                </button>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-border bg-[#0b0f17]">
                      {[
                        "Scan ID",
                        "Target Target",
                        "Profile Mode",
                        "Status",
                        "Findings",
                        "Last Run",
                        "Actions",
                      ].map((h) => (
                        <th
                          key={h}
                          className="px-5 py-2.5 text-left text-ink-3 text-[10px] font-semibold uppercase tracking-wider"
                        >
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {SCANS.map((s) => (
                      <tr
                        key={s.id}
                        className="hover:bg-elevated/20 transition-colors"
                      >
                        <td className="px-5 py-3 text-ink-3 text-xs font-mono font-medium">
                          {s.id}
                        </td>
                        <td className="px-5 py-3 text-ink text-xs font-semibold">{s.target}</td>
                        <td className="px-5 py-3 text-ink-2 text-xs font-mono">{s.type}</td>
                        <td className="px-5 py-3">
                          <span
                            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold border ${
                              s.status === "Running"
                                ? "text-accent bg-accent/8 border-accent/20 animate-pulse"
                                : s.status === "Completed"
                                  ? "text-emerald bg-emerald/8 border-emerald/20"
                                  : "text-critical bg-critical/8 border-critical/20"
                            }`}
                          >
                            {s.status === "Running" && <span className="w-1 h-1 rounded-full bg-accent animate-ping" />}
                            {s.status}
                          </span>
                        </td>
                        <td className="px-5 py-3">
                          <div className="flex items-center gap-1.5">
                            <span className="text-ink text-xs font-mono font-semibold">
                              {s.findings}
                            </span>
                            {s.critical > 0 && (
                              <span className="text-critical text-[10px] bg-critical/10 border border-critical/20 px-1 rounded font-semibold font-mono">
                                {s.critical} CRIT
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-5 py-3 text-ink-3 text-xs font-mono">
                          {s.ran}
                        </td>
                        <td className="px-5 py-3">
                          <button
                            onClick={() => onNavigate(s.status === "Running" ? "automated-scan" : "findings")}
                            className="text-ink-3 hover:text-ink transition-colors p-1"
                          >
                            <ExternalLink size={12} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Quick Fuzz Simulator */}
          <div className="lg:col-span-1 card-3d bg-card border border-border rounded-lg p-5 shadow-sm flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-1.5 mb-2">
                <Globe size={13} className="text-accent" />
                <p className="text-ink text-sm font-semibold">Quick Host Profiler</p>
              </div>
              <p className="text-ink-3 text-[11px] leading-relaxed mb-4">
                Instantly resolve target DNS, verify response headers, and scan security policies before running.
              </p>

              <div className="space-y-3">
                <input
                  type="text"
                  value={quickUrl}
                  onChange={(e) => setQuickUrl(e.target.value)}
                  disabled={quickScanning}
                  className="w-full bg-canvas border border-border rounded px-3 py-1.5 text-ink text-xs font-mono focus:border-accent transition-colors disabled:opacity-50"
                />

                {quickScanning ? (
                  <div className="bg-canvas border border-border rounded p-3 space-y-2 font-mono text-[10px]">
                    <div className="flex items-center gap-2 text-ink-2">
                      {quickScanStep >= 1 ? <CheckCircle size={10} className="text-emerald shrink-0" /> : <Loader2 size={10} className="animate-spin text-accent shrink-0" />}
                      <span>DNS Lookup for {quickUrl.replace("https://", "")}</span>
                    </div>
                    {quickScanStep >= 2 && (
                      <div className="flex items-center gap-2 text-ink-2">
                        {quickScanStep >= 2 ? <CheckCircle size={10} className="text-emerald shrink-0" /> : <Loader2 size={10} className="animate-spin text-accent shrink-0" />}
                        <span className="text-[#a5b4fc]">IP: 104.22.3.94 (US Cloudflare)</span>
                      </div>
                    )}
                    {quickScanStep >= 3 && (
                      <div className="flex items-center gap-2 text-ink-2">
                        <Loader2 size={10} className="animate-spin text-accent shrink-0" />
                        <span className="text-accent">Redirecting to full config...</span>
                      </div>
                    )}
                  </div>
                ) : (
                  <button
                    onClick={handleQuickScan}
                    className="w-full flex items-center justify-center gap-1.5 py-1.5 bg-elevated border border-border hover:border-border-hi rounded text-ink text-xs font-medium transition-colors"
                  >
                    <Activity size={12} className="text-accent" />
                    Analyze Host Config
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Row 3: Risk Heatmap Matrix & Critical Alerts */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          {/* Interactive 5x5 Risk Heatmap Matrix */}
          <div className="lg:col-span-2 card-3d bg-card border border-border rounded-lg p-5 shadow-sm flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-1.5">
                  <svg viewBox="0 0 24 24" width="14" height="14" fill="none" strokeWidth="2" className="text-accent" stroke="currentColor">
                    <rect x="3" y="3" width="18" height="18" rx="2" />
                    <path d="M9 3v18M15 3v18M3 9h18M3 15h18" />
                  </svg>
                  <p className="text-ink text-sm font-semibold">Risk Heatmap Matrix</p>
                </div>
                <span className="text-[9px] font-mono text-ink-3">5x5 Likelihood x Impact</span>
              </div>

              {/* Heatmap Grid and Details Split */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-2">
                {/* Cell Matrix */}
                <div className="relative pl-5">
                  {/* Y-Axis Label (Impact) */}
                  <div className="absolute left-0 top-1/2 -rotate-90 origin-center -translate-y-1/2 text-[8px] font-bold text-ink-3 uppercase tracking-wider select-none">
                    Impact
                  </div>

                  <div className="grid grid-cols-5 gap-1.5">
                    {/* Render 5x5 Cells starting from Impact=5 down to 1 */}
                    {[5, 4, 3, 2, 1].map((impact) => {
                      return [1, 2, 3, 4, 5].map((likelihood) => {
                        const score = likelihood * impact
                        let cellBg = "bg-emerald/20 hover:bg-emerald/30 border-emerald/40 text-emerald"
                        let riskLabel = "Low"
                        if (score >= 20) {
                          cellBg = "bg-critical/20 hover:bg-critical/30 border-critical/40 text-critical"
                          riskLabel = "Critical"
                        } else if (score >= 12) {
                          cellBg = "bg-high/20 hover:bg-high/30 border-high/40 text-high"
                          riskLabel = "High"
                        } else if (score >= 5) {
                          cellBg = "bg-yellow/20 hover:bg-yellow/30 border-yellow/40 text-yellow"
                          riskLabel = "Medium"
                        }

                        const hasVuls = (impact === 5 && likelihood === 4) || (impact === 4 && likelihood === 3) || (impact === 2 && likelihood === 5)
                        const isSelected = selectedCell?.l === likelihood && selectedCell?.i === impact

                        return (
                          <button
                            key={`${impact}-${likelihood}`}
                            onClick={() => {
                              setSelectedCell(isSelected ? null : { l: likelihood, i: impact })
                            }}
                            className={`aspect-square border rounded flex flex-col items-center justify-center relative transition-all ${cellBg} ${
                              isSelected ? "ring-2 ring-accent border-accent scale-105 z-10" : ""
                            }`}
                            title={`Likelihood: ${likelihood}, Impact: ${impact} (Score: ${score} - ${riskLabel})`}
                          >
                            <span className="text-[9px] font-mono font-bold">
                              {score}
                            </span>
                            {hasVuls && (
                              <span className="absolute bottom-1 right-1 w-1.5 h-1.5 rounded-full bg-ink animate-pulse" />
                            )}
                          </button>
                        )
                      })
                    })}
                  </div>

                  {/* X-Axis Label (Likelihood) */}
                  <div className="text-center text-[8px] font-bold text-ink-3 uppercase tracking-wider mt-2.5 select-none">
                    Likelihood
                  </div>
                </div>

                {/* Legend & Details */}
                <div className="flex flex-col justify-between space-y-3">
                  {/* Legend */}
                  <div className="grid grid-cols-2 gap-2 text-[8px] text-ink-3 font-mono border-b border-border/40 pb-2.5 font-semibold select-none">
                    <div className="flex items-center gap-1">
                      <span className="w-2.5 h-2.5 rounded-sm bg-emerald/20 border border-emerald/40 shrink-0" />
                      <span>Low (1-4)</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <span className="w-2.5 h-2.5 rounded-sm bg-yellow/20 border border-yellow/40 shrink-0" />
                      <span>Med (5-10)</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <span className="w-2.5 h-2.5 rounded-sm bg-high/20 border border-high/40 shrink-0" />
                      <span>High (12-16)</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <span className="w-2.5 h-2.5 rounded-sm bg-critical/20 border border-critical/40 shrink-0" />
                      <span>Crit (20-25)</span>
                    </div>
                  </div>

                  {/* Matching Vulnerabilities List */}
                  <div className="bg-canvas/50 border border-border rounded-lg p-3 space-y-2 flex-1 overflow-y-auto max-h-[160px]">
                    <span className="text-[9px] uppercase tracking-wider text-ink-3 font-bold block">
                      {selectedCell 
                        ? `Cell (L:${selectedCell.l}, I:${selectedCell.i}) Active Gaps`
                        : "Heatmap Active Anomalies"
                      }
                    </span>
                    
                    {getFilteredVuls().length === 0 ? (
                      <p className="text-[10px] text-ink-3 italic text-center py-2">No active anomalies mapped.</p>
                    ) : (
                      <div className="space-y-1.5">
                        {getFilteredVuls().map((vul) => (
                          <div key={vul.id} className="flex justify-between items-center text-xs py-1 border-b border-border/25 last:border-0">
                            <div className="min-w-0 pr-2">
                              <span className="text-ink font-semibold font-mono block truncate">{vul.id} · {vul.name}</span>
                              <span className="text-ink-3 text-[10px] block mt-0.5 truncate">{vul.host} · Risk: {vul.score}</span>
                            </div>
                            <button
                              onClick={() => onNavigate("findings")}
                              className="text-accent text-[9px] font-bold uppercase tracking-wider border border-accent/20 hover:border-accent/40 px-2 py-0.5 rounded bg-accent/5 hover:bg-accent/10 transition-colors shrink-0"
                            >
                              Triage
                            </button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Critical Alerts Alert-Box */}
          <div className="lg:col-span-1 flex flex-col justify-between">
            {ALERTS.length > 0 && (
              <div className="bg-critical/5 border border-critical/20 rounded-lg p-4 space-y-3 h-full flex flex-col justify-between">
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <AlertTriangle size={14} className="text-critical animate-pulse" />
                    <span className="text-critical text-xs font-semibold uppercase tracking-wider">
                      {ALERTS.length} Critical Actions Pending
                    </span>
                  </div>
                  <div className="space-y-2">
                    {ALERTS.map((a) => (
                      <div key={a.id} className="flex items-center justify-between text-xs py-1 border-b border-border/20 last:border-0 pb-2">
                        <div>
                          <span className="text-ink font-semibold block">{a.title}</span>
                          <span className="text-ink-3 font-mono text-[10px] mt-0.5 block">{a.target} · {a.id}</span>
                        </div>
                        <button
                          onClick={() => onNavigate("findings")}
                          className="text-accent text-[10px] font-bold hover:underline"
                        >
                          TRIAGE
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

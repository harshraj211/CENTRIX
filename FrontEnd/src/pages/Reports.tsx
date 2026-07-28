import { useState } from "react"
import {
  Download,
  FileText,
  Plus,
  ChevronDown,
  CheckCircle2,
  Clock,
  Printer,
  X,
  FileCheck2,
} from "lucide-react"

interface ReportsProps {
  onNavigate: (page: string) => void
  findingsCount: number
}

const REPORTS_INITIAL = [
  { id: "RPT-0047", name: "Full Assessment — api.acmecorp.com", type: "Technical", target: "api.acmecorp.com", generated: "Jul 26, 2026", status: "Ready", findings: 8, size: "2.1 MB" },
  { id: "RPT-0046", name: "Executive Summary — Q3 Security", type: "Executive", target: "All targets", generated: "Jul 25, 2026", status: "Ready", findings: 24, size: "480 KB" },
  { id: "RPT-0045", name: "Quick Scan — app.acmecorp.com", type: "Technical", target: "app.acmecorp.com", generated: "Jul 25, 2026", status: "Ready", findings: 5, size: "840 KB" },
  { id: "RPT-0044", name: "API Scan — admin.acmecorp.com", type: "Compliance", target: "admin.acmecorp.com", generated: "Jul 24, 2026", status: "Ready", findings: 11, size: "1.4 MB" },
  { id: "RPT-0043", name: "Auth Scan — auth.acmecorp.com", type: "Technical", target: "auth.acmecorp.com", generated: "Jul 23, 2026", status: "Pending", findings: 0, size: "—" },
]

const FORMATS = [
  { id: "pdf", label: "PDF", desc: "Formatted report with findings and appendices" },
  { id: "html", label: "HTML", desc: "Standalone interactive report" },
  { id: "json", label: "JSON", desc: "Machine-readable findings export" },
]

export default function Reports({ onNavigate, findingsCount }: ReportsProps) {
  const [reportsList, setReportsList] = useState(REPORTS_INITIAL)
  const [selectedReport, setSelectedReport] = useState<typeof REPORTS_INITIAL[0] | null>(REPORTS_INITIAL[0])
  const [format, setFormat] = useState("pdf")
  const [reportType, setReportType] = useState<"technical" | "executive" | "compliance">("technical")
  
  // Generator form state
  const [targetScope, setTargetScope] = useState("api.acmecorp.com")
  const [generating, setGenerating] = useState(false)

  const handleGenerateReport = () => {
    setGenerating(true)
    setTimeout(() => {
      setGenerating(false)
      const newReport = {
        id: `RPT-00${Math.floor(48 + Math.random() * 50)}`,
        name: `Custom ${reportType.charAt(0).toUpperCase() + reportType.slice(1)} Scan — ${targetScope}`,
        type: reportType.charAt(0).toUpperCase() + reportType.slice(1),
        target: targetScope,
        generated: "Just now",
        status: "Ready",
        findings: findingsCount,
        size: "1.2 MB",
      }
      setReportsList([newReport, ...reportsList])
      setSelectedReport(newReport)
    }, 1500)
  }

  return (
    <div className="flex h-full min-h-0 overflow-hidden bg-canvas">
      {/* Left Pane: Config Form & History (Split 60% if selecting a preview) */}
      <div className={`overflow-y-auto p-6 space-y-6 transition-all duration-200 ${selectedReport ? "w-[55%] border-r border-border" : "w-full"}`}>
        
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-ink text-xl font-semibold">Security Reports</h1>
            <p className="text-ink-3 text-xs mt-0.5">Generate, audit, and preview compliance and vulnerability metrics.</p>
          </div>
          <button
            onClick={() => onNavigate("findings")}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-elevated border border-border hover:border-border-hi rounded text-ink text-xs font-semibold transition-colors"
          >
            <FileText size={12} />
            Findings Database
          </button>
        </div>

        {/* Generate Report Configuration Panel */}
        <div className="bg-card border border-border rounded-lg p-5 shadow-sm space-y-4">
          <p className="text-ink text-sm font-semibold">Configure Assessment Exporter</p>

          <div className="grid grid-cols-2 gap-4">
            {/* Target Select */}
            <div className="space-y-1.5">
              <label className="text-ink-2 text-xs font-medium">Target Scope</label>
              <div className="relative">
                <select
                  value={targetScope}
                  onChange={(e) => setTargetScope(e.target.value)}
                  className="w-full appearance-none bg-canvas border border-border rounded px-3 py-1.5 text-ink text-xs pr-8 focus:border-accent"
                >
                  <option value="api.acmecorp.com">api.acmecorp.com</option>
                  <option value="app.acmecorp.com">app.acmecorp.com</option>
                  <option value="admin.acmecorp.com">admin.acmecorp.com</option>
                  <option value="All targets (cumulative)">All targets (cumulative)</option>
                </select>
                <ChevronDown size={11} className="absolute right-3 top-1/2 -translate-y-1/2 text-ink-3 pointer-events-none" />
              </div>
            </div>

            {/* Type Buttons */}
            <div className="space-y-1.5">
              <label className="text-ink-2 text-xs font-medium">Report Profile</label>
              <div className="flex gap-2 bg-canvas p-0.5 border border-border rounded">
                {(["technical", "executive", "compliance"] as const).map((t) => (
                  <button
                    key={t}
                    onClick={() => setReportType(t)}
                    className={`flex-1 py-1 rounded text-[10px] uppercase font-semibold transition-colors ${
                      reportType === t ? "bg-accent text-white" : "text-ink-3 hover:text-ink-2"
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Export formats radio list */}
          <div className="grid grid-cols-3 gap-2 pt-2">
            {FORMATS.map((f) => (
              <label
                key={f.id}
                className={`flex flex-col p-2.5 rounded-lg border cursor-pointer transition-all ${
                  format === f.id ? "border-accent bg-accent/5" : "border-border bg-canvas/30 hover:border-border-hi"
                }`}
              >
                <div className="flex items-center gap-2">
                  <input
                    type="radio"
                    name="format"
                    value={f.id}
                    checked={format === f.id}
                    onChange={() => setFormat(f.id)}
                    className="accent-accent"
                  />
                  <span className="text-ink text-xs font-bold">{f.label}</span>
                </div>
                <span className="text-ink-3 text-[10px] mt-1 leading-normal">{f.desc}</span>
              </label>
            ))}
          </div>

          <button
            onClick={handleGenerateReport}
            disabled={generating}
            className="w-full flex items-center justify-center gap-2 py-2 bg-accent text-white rounded text-xs font-semibold hover:bg-accent/90 transition-colors shadow-lg shadow-accent/20 disabled:opacity-50"
          >
            {generating ? (
              <>
                <Clock size={13} className="animate-spin" />
                <span>Compiling XML audit data...</span>
              </>
            ) : (
              <>
                <Plus size={13} />
                <span>Generate Assessment Document</span>
              </>
            )}
          </button>
        </div>

        {/* Report History list */}
        <div className="bg-card border border-border rounded-lg overflow-hidden shadow-sm">
          <div className="px-5 py-3 border-b border-border bg-panel/30 flex items-center justify-between">
            <p className="text-ink text-sm font-semibold">Report Exporter History</p>
            <span className="text-ink-3 text-xs font-mono">{reportsList.length} total</span>
          </div>

          <table className="w-full">
            <thead>
              <tr className="border-b border-border bg-[#0b0f17] text-[10px] font-semibold text-ink-3 uppercase font-mono">
                <th className="px-4 py-2 text-left pl-5">ID</th>
                <th className="px-4 py-2 text-left">Document Name</th>
                <th className="px-4 py-2 text-left w-20">Type</th>
                <th className="px-4 py-2 text-left w-16">Vulns</th>
                <th className="px-4 py-2 text-left w-24">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {reportsList.map((r) => (
                <tr
                  key={r.id}
                  onClick={() => setSelectedReport(r)}
                  className={`text-xs cursor-pointer transition-colors ${
                    selectedReport?.id === r.id ? "bg-accent/5" : "hover:bg-elevated/20"
                  }`}
                >
                  <td className="pl-5 pr-4 py-3 text-ink-3 font-mono font-medium">{r.id}</td>
                  <td className="px-4 py-3">
                    <p className="text-ink font-semibold">{r.name}</p>
                    <p className="text-ink-3 text-[10px] font-mono mt-0.5">{r.target}</p>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-ink-2 text-[10px] px-1.5 py-0.5 bg-elevated border border-border rounded-sm font-semibold">
                      {r.type}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-ink font-mono font-bold">
                    {r.findings > 0 ? (r.id === "RPT-0047" ? findingsCount : r.findings) : "—"}
                  </td>
                  <td className="px-4 py-3">
                    {r.status === "Ready" ? (
                      <span className="flex items-center gap-1.5 text-emerald font-semibold">
                        <CheckCircle2 size={11} />
                        Ready
                      </span>
                    ) : (
                      <span className="flex items-center gap-1.5 text-ink-3">
                        <Clock size={11} className="animate-pulse" />
                        Queued...
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Right Pane: Live Document Previewer */}
      {selectedReport && (
        <div className="flex-1 flex flex-col overflow-hidden bg-[#10141f]">
          {/* Preview Toolbar */}
          <div className="px-4 py-2.5 border-b border-border bg-panel flex items-center justify-between shrink-0">
            <span className="text-ink-2 text-xs font-semibold flex items-center gap-1.5">
              <FileCheck2 size={13} className="text-accent" />
              Live Report Previewer
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => window.print()}
                title="Print report preview"
                className="p-1 text-ink-3 hover:text-ink transition-colors"
              >
                <Printer size={13} />
              </button>
              <button
                onClick={() => window.print()}
                className="flex items-center gap-1.5 px-3 py-1 bg-accent text-white rounded text-xs font-semibold hover:bg-accent/90 transition-colors"
              >
                <Download size={11} />
                <span>Export PDF ({selectedReport.size})</span>
              </button>
              <button
                onClick={() => setSelectedReport(null)}
                className="text-ink-3 hover:text-ink transition-colors p-1"
              >
                <X size={14} />
              </button>
            </div>
          </div>

          {/* Interactive Simulated A4 PDF Document */}
          <div className="flex-1 overflow-y-auto p-8 flex flex-col items-center gap-8 bg-[#0a0d16] pdf-printable-area">
            
            {/* PAGE 1: COVER PAGE */}
            <div className="w-[595px] h-[842px] bg-white text-slate-800 p-12 shadow-2xl rounded-sm border border-slate-200 font-serif relative flex flex-col justify-between shrink-0 select-none print:p-0 print:border-none print:shadow-none print:w-full print:h-screen">
              {/* Header Corner Accent */}
              <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-950/5 rounded-bl-full pointer-events-none" />
              
              {/* Top Logo Block */}
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-indigo-950 flex items-center justify-center font-bold text-white text-sm font-sans tracking-wide">
                  VG
                </div>
                <div>
                  <span className="font-extrabold text-indigo-950 text-xs tracking-wider font-sans block leading-none">VULNGUARD</span>
                  <span className="text-[7px] text-slate-500 font-mono tracking-widest block mt-0.5 uppercase">Security Intelligence Suite</span>
                </div>
              </div>

              {/* Title Content */}
              <div className="my-auto space-y-5">
                <div className="w-16 h-1 bg-indigo-900 rounded" />
                <span className="text-slate-400 font-mono text-[9px] uppercase tracking-widest block font-bold">
                  Technical Security Assessment & Penetration Report
                </span>
                <h1 className="text-slate-900 text-3xl font-black font-sans leading-tight">
                  {selectedReport.name}
                </h1>
                <p className="text-slate-500 text-xs leading-relaxed max-w-[420px]">
                  An automated and manual vulnerability assessment covering target scopes, dynamic API payloads, software composition analysis (SCA), and lateral compromise routes.
                </p>
              </div>

              {/* Cover Metadata Footer */}
              <div className="border-t border-slate-200 pt-6 grid grid-cols-2 gap-y-4 gap-x-6 text-[9px] font-sans">
                <div>
                  <span className="text-slate-400 uppercase tracking-wider block font-bold mb-0.5">Assessment Target</span>
                  <span className="text-slate-800 font-bold font-mono text-[10px]">{selectedReport.target}</span>
                </div>
                <div>
                  <span className="text-slate-400 uppercase tracking-wider block font-bold mb-0.5">Generated Date</span>
                  <span className="text-slate-800 font-bold text-[10px]">{selectedReport.generated}</span>
                </div>
                <div>
                  <span className="text-slate-400 uppercase tracking-wider block font-bold mb-0.5">Report Classification</span>
                  <span className="text-red-700 font-bold uppercase tracking-wider text-[10px]">CONFIDENTIAL // INTERNAL ONLY</span>
                </div>
                <div>
                  <span className="text-slate-400 uppercase tracking-wider block font-bold mb-0.5">Assigned Document ID</span>
                  <span className="text-slate-800 font-bold font-mono text-[10px]">{selectedReport.id}</span>
                </div>
              </div>
            </div>

            {/* PAGE 2: EXECUTIVE SUMMARY & STATS */}
            <div className="w-[595px] h-[842px] bg-white text-slate-800 p-12 shadow-2xl rounded-sm border border-slate-200 font-serif relative flex flex-col justify-between shrink-0 select-none print:p-0 print:border-none print:shadow-none print:w-full print:h-screen">
              <div>
                {/* Header metadata row */}
                <div className="flex justify-between items-center border-b border-slate-200 pb-2.5 text-[8px] font-sans text-slate-400 uppercase tracking-widest mb-6">
                  <span>Security Assessment Report</span>
                  <span>ID: {selectedReport.id}</span>
                </div>

                <div className="space-y-5">
                  <h2 className="text-slate-900 text-lg font-bold font-sans">1. Executive Overview</h2>
                  
                  <div className="space-y-3 text-slate-600 text-xs leading-relaxed font-sans">
                    <p>
                      This technical document summarizes the security vulnerabilities verified during active audit iterations on target domain <strong>{selectedReport.target}</strong>. Assessment methodologies incorporated black-box fuzzing, software composition checks, and manual repeater validation.
                    </p>
                    <p>
                      The primary objective was to trace external entry points and evaluate how lateral pivots could compromise internal databases or private customer assets. Based on the aggregate volume of critical-threat exposures, immediate remediation is required.
                    </p>
                  </div>

                  {/* Postural health grade block */}
                  <div className="bg-slate-50 border border-slate-200 rounded p-4 flex items-center justify-between font-sans mt-2">
                    <div className="space-y-1">
                      <span className="text-slate-800 text-[10px] font-bold block uppercase tracking-wider">Postural Health Grade</span>
                      <p className="text-slate-500 text-[9px] max-w-[280px]">Derived from active vulnerabilities count, host criticality index, and remediation response windows.</p>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-3xl font-black text-red-600 border-2 border-red-200 px-3.5 py-1.5 rounded bg-red-50/50">D-</span>
                      <span className="text-[9px] font-bold text-white bg-red-600 px-2 py-0.5 rounded uppercase tracking-wide">HIGH RISK</span>
                    </div>
                  </div>

                  {/* Statistics */}
                  <div className="pt-2 space-y-3">
                    <span className="text-slate-800 text-[10px] font-bold uppercase font-sans tracking-wide block">Identified Exposure Counts</span>
                    <div className="grid grid-cols-4 gap-3 text-center font-sans">
                      <div className="border border-slate-200 rounded p-3 bg-red-50/10">
                        <span className="text-[20px] font-bold text-red-600 block leading-none font-mono mb-1">
                          {selectedReport.id === "RPT-0047" ? Math.max(2, Math.floor(findingsCount * 0.3)) : Math.floor(selectedReport.findings * 0.2) || 2}
                        </span>
                        <span className="text-[9px] text-slate-500 uppercase font-semibold">Critical</span>
                      </div>
                      <div className="border border-slate-200 rounded p-3 bg-amber-50/10">
                        <span className="text-[20px] font-bold text-amber-600 block leading-none font-mono mb-1">
                          {selectedReport.id === "RPT-0047" ? Math.max(3, Math.floor(findingsCount * 0.4)) : Math.floor(selectedReport.findings * 0.3) || 3}
                        </span>
                        <span className="text-[9px] text-slate-500 uppercase font-semibold">High</span>
                      </div>
                      <div className="border border-slate-200 rounded p-3 bg-yellow-50/10">
                        <span className="text-[20px] font-bold text-yellow-600 block leading-none font-mono mb-1">
                          {selectedReport.id === "RPT-0047" ? Math.max(2, Math.floor(findingsCount * 0.2)) : Math.floor(selectedReport.findings * 0.3) || 2}
                        </span>
                        <span className="text-[9px] text-slate-500 uppercase font-semibold">Medium</span>
                      </div>
                      <div className="border border-slate-200 rounded p-3 bg-slate-50">
                        <span className="text-[20px] font-bold text-slate-700 block leading-none font-mono mb-1">
                          {selectedReport.id === "RPT-0047" ? Math.max(1, Math.floor(findingsCount * 0.1)) : Math.floor(selectedReport.findings * 0.2) || 1}
                        </span>
                        <span className="text-[9px] text-slate-500 uppercase font-semibold">Low</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Page Number Footer */}
              <div className="flex justify-between items-center text-[8px] text-slate-400 font-sans border-t border-slate-100 pt-2.5">
                <span>CONFIDENTIAL · VULNGUARD CO.</span>
                <span>Page 2 of 4</span>
              </div>
            </div>

            {/* PAGE 3: DETAILED FINDINGS REGISTER */}
            <div className="w-[595px] h-[842px] bg-white text-slate-800 p-12 shadow-2xl rounded-sm border border-slate-200 font-serif relative flex flex-col justify-between shrink-0 select-none print:p-0 print:border-none print:shadow-none print:w-full print:h-screen">
              <div>
                {/* Header metadata row */}
                <div className="flex justify-between items-center border-b border-slate-200 pb-2.5 text-[8px] font-sans text-slate-400 uppercase tracking-widest mb-6">
                  <span>Security Assessment Report</span>
                  <span>ID: {selectedReport.id}</span>
                </div>

                <div className="space-y-4">
                  <h2 className="text-slate-900 text-lg font-bold font-sans">2. Vulnerability Register</h2>
                  
                  <p className="text-slate-500 text-[10px] leading-relaxed font-sans -mt-1">
                    The following register details the vulnerabilities identified within the scope.
                  </p>

                  <table className="w-full text-[9px] font-sans border-collapse mt-2">
                    <thead>
                      <tr className="border-b border-slate-300 text-slate-500 text-left">
                        <th className="py-2 pr-2 font-semibold">ID</th>
                        <th className="py-2 px-2 font-semibold">Vulnerability Title</th>
                        <th className="py-2 px-2 font-semibold">Severity</th>
                        <th className="py-2 px-2 font-semibold">Endpoint / Target</th>
                        <th className="py-2 pl-2 font-semibold">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 text-slate-600">
                      <tr>
                        <td className="py-2.5 pr-2 font-mono font-bold text-red-600">VLN-0247</td>
                        <td className="py-2.5 px-2 font-semibold text-slate-800">Server-side Path Traversal</td>
                        <td className="py-2.5 px-2"><span className="px-1 bg-red-100 text-red-700 text-[8px] font-bold rounded">CRITICAL</span></td>
                        <td className="py-2.5 px-2 font-mono text-[8px]">/export?file=</td>
                        <td className="py-2.5 pl-2 font-bold text-red-600">OPEN</td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-2 font-mono font-bold text-red-600">VLN-0246</td>
                        <td className="py-2.5 px-2 font-semibold text-slate-800">SQL Injection in user_id</td>
                        <td className="py-2.5 px-2"><span className="px-1 bg-red-100 text-red-700 text-[8px] font-bold rounded">CRITICAL</span></td>
                        <td className="py-2.5 px-2 font-mono text-[8px]">/api/users?user_id=</td>
                        <td className="py-2.5 pl-2 font-bold text-red-600">OPEN</td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-2 font-mono font-bold text-amber-600">VLN-0245</td>
                        <td className="py-2.5 px-2 font-semibold text-slate-800">IDOR on /admin/export</td>
                        <td className="py-2.5 px-2"><span className="px-1 bg-amber-100 text-amber-700 text-[8px] font-bold rounded">HIGH</span></td>
                        <td className="py-2.5 px-2 font-mono text-[8px]">/admin/export</td>
                        <td className="py-2.5 pl-2 text-slate-500">TRIAGED</td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-2 font-mono font-bold text-amber-600">VLN-0244</td>
                        <td className="py-2.5 px-2 font-semibold text-slate-800">Stored XSS in Profile</td>
                        <td className="py-2.5 px-2"><span className="px-1 bg-amber-100 text-amber-700 text-[8px] font-bold rounded">HIGH</span></td>
                        <td className="py-2.5 px-2 font-mono text-[8px]">/api/profile</td>
                        <td className="py-2.5 pl-2 text-slate-500">IN REVIEW</td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-2 font-mono font-bold text-amber-600">VLN-0243</td>
                        <td className="py-2.5 px-2 font-semibold text-slate-800">Reflected XSS in Search</td>
                        <td className="py-2.5 px-2"><span className="px-1 bg-amber-100 text-amber-700 text-[8px] font-bold rounded">HIGH</span></td>
                        <td className="py-2.5 px-2 font-mono text-[8px]">/search?q=</td>
                        <td className="py-2.5 pl-2 text-slate-500">OPEN</td>
                      </tr>
                    </tbody>
                  </table>

                  {/* Deep dive on top vulnerability */}
                  <div className="bg-slate-50 border border-slate-200 rounded p-3.5 space-y-1.5 font-sans mt-3">
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] font-extrabold text-red-600 uppercase tracking-wide">Spotlight Vulnerability: VLN-0247</span>
                      <span className="text-[8px] font-mono text-slate-400">CVSS: 9.8 (Critical)</span>
                    </div>
                    <p className="text-[9px] text-slate-600 leading-relaxed">
                      <strong>Description:</strong> The <code>/export</code> endpoint accepts a <code>file</code> parameter that is passed directly to a filesystem read operation without sanitization. An attacker can use directory traversal sequences (<code>../</code>) to extract sensitive server configuration files.
                    </p>
                    <p className="text-[9px] text-slate-500">
                      <strong>Mitigation:</strong> Enforce strict filename allowlists and verify resolved paths reside within parent directory targets before processing system exports.
                    </p>
                  </div>
                </div>
              </div>

              {/* Page Number Footer */}
              <div className="flex justify-between items-center text-[8px] text-slate-400 font-sans border-t border-slate-100 pt-2.5">
                <span>CONFIDENTIAL · VULNGUARD CO.</span>
                <span>Page 3 of 4</span>
              </div>
            </div>

            {/* PAGE 4: REMEDIATION ROADMAP & SIGN-OFF */}
            <div className="w-[595px] h-[842px] bg-white text-slate-800 p-12 shadow-2xl rounded-sm border border-slate-200 font-serif relative flex flex-col justify-between shrink-0 select-none print:p-0 print:border-none print:shadow-none print:w-full print:h-screen">
              <div>
                {/* Header metadata row */}
                <div className="flex justify-between items-center border-b border-slate-200 pb-2.5 text-[8px] font-sans text-slate-400 uppercase tracking-widest mb-6">
                  <span>Security Assessment Report</span>
                  <span>ID: {selectedReport.id}</span>
                </div>

                <div className="space-y-4">
                  <h2 className="text-slate-900 text-lg font-bold font-sans">3. Remediation & Verification Roadmap</h2>
                  
                  <p className="text-slate-500 text-[10px] leading-relaxed font-sans -mt-1">
                    Systematic mitigation workflows to eliminate vulnerabilities and run security regression checks.
                  </p>

                  <div className="space-y-3.5 text-[10px] font-sans pt-2">
                    <div className="flex gap-3">
                      <span className="w-5 h-5 rounded-full bg-indigo-900 text-white font-bold flex items-center justify-center text-[9px] shrink-0 font-sans mt-0.5">1</span>
                      <div>
                        <strong className="text-slate-900 block text-[10px]">Parameterize SQL Statements (VLN-0246)</strong>
                        <p className="text-slate-600 mt-0.5 leading-normal">
                          Replace raw query string concatenation inside target endpoints with pre-compiled statement arrays or use security-hardened ORM bindings.
                        </p>
                      </div>
                    </div>

                    <div className="flex gap-3">
                      <span className="w-5 h-5 rounded-full bg-indigo-900 text-white font-bold flex items-center justify-center text-[9px] shrink-0 font-sans mt-0.5">2</span>
                      <div>
                        <strong className="text-slate-900 block text-[10px]">Restrict Filesystem Read Boundaries (VLN-0247)</strong>
                        <p className="text-slate-600 mt-0.5 leading-normal">
                          Sanitize path arguments. Resolve relative tokens and check that output paths strictly begin with permitted directory targets.
                        </p>
                      </div>
                    </div>

                    <div className="flex gap-3">
                      <span className="w-5 h-5 rounded-full bg-indigo-900 text-white font-bold flex items-center justify-center text-[9px] shrink-0 font-sans mt-0.5">3</span>
                      <div>
                        <strong className="text-slate-900 block text-[10px]">Implement Indirect Object Reference Controls (VLN-0245)</strong>
                        <p className="text-slate-600 mt-0.5 leading-normal">
                          Verify session ownership before returning report artifacts. Transition to random UUID values rather than sequential integers for object identifier fields.
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* verification note */}
                  <div className="bg-slate-50 border-l-4 border-indigo-950 p-3 mt-4 text-[9px] text-slate-600 font-sans">
                    <strong className="text-indigo-950 uppercase tracking-wider block mb-0.5">Regression Testing Guideline</strong>
                    Re-run target configurations via the VulnGuard engine scheduler or target endpoints using automated scanner payloads to verify vulnerabilities are completely mitigated.
                  </div>
                </div>
              </div>

              {/* Signoff approvals block */}
              <div>
                <div className="border-t border-slate-200 pt-5 flex justify-between items-center text-[9px] text-slate-400 font-sans font-medium">
                  <div>
                    <p className="text-slate-800 font-bold">APPROVED BY: ALEX KIM</p>
                    <p className="mt-0.5 text-slate-500">Lead Security Architect, Security Assessment Group</p>
                  </div>
                  <div className="text-right">
                    <p className="text-slate-500">VulnGuard Assessment Engine v4.0.1</p>
                    <p className="mt-0.5 text-slate-500 font-bold">CLASSIFICATION: HIGHLY CONFIDENTIAL</p>
                  </div>
                </div>

                {/* Page Number Footer */}
                <div className="flex justify-between items-center text-[8px] text-slate-400 font-sans border-t border-slate-100 pt-2.5 mt-5">
                  <span>CONFIDENTIAL · VULNGUARD CO.</span>
                  <span>Page 4 of 4</span>
                </div>
              </div>
            </div>

          </div>
        </div>
      )}
    </div>
  )
}

import { useEffect, useState } from "react"
import { Download, FileText, RefreshCw } from "lucide-react"
import { reportsApi, scanApi, type ApiReport } from "../api/client"

interface ReportsProps {
  onNavigate: (page: string) => void
  findingsCount: number
}

type ReportFormat = "json" | "html" | "pdf" | "sarif" | "junit" | "evidence"

const FORMAT_LABELS: Record<ReportFormat, string> = {
  json: "JSON",
  html: "HTML",
  pdf: "PDF",
  sarif: "SARIF",
  junit: "JUnit XML",
  evidence: "Evidence bundle",
}

export default function Reports(_props: ReportsProps) {
  const [reports, setReports] = useState<ApiReport[]>([])
  const [scans, setScans] = useState<any[]>([])
  const [formats, setFormats] = useState<Record<string, ReportFormat>>({})
  const [busyScan, setBusyScan] = useState("")
  const [error, setError] = useState("")

  const load = async () => {
    try {
      const [nextReports, nextScans] = await Promise.all([reportsApi.list(), scanApi.list()])
      setReports(nextReports)
      setScans(nextScans)
      setFormats((current) => {
        const next = { ...current }
        for (const scan of nextScans) {
          if (!next[scan.id]) next[scan.id] = "html"
        }
        return next
      })
      setError("")
    } catch {
      setError("Could not load reports.")
    }
  }

  useEffect(() => {
    void load()
  }, [])

  const generate = async (scanId: string) => {
    setBusyScan(scanId)
    setError("")
    try {
      await reportsApi.generate({
        scan_id: scanId,
        format: formats[scanId] || "html",
        report_type: "technical",
      })
      await load()
    } catch {
      setError("Report generation failed.")
    } finally {
      setBusyScan("")
    }
  }

  return (
    <div className="p-6 max-w-[1200px] mx-auto">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-ink">Reports</h1>
          <p className="text-sm text-ink-3 mt-1">Generate technical exports from completed scan data and captured evidence.</p>
        </div>
        <button onClick={() => void load()} className="p-2 text-ink-3 hover:text-ink" title="Refresh reports">
          <RefreshCw size={16} />
        </button>
      </div>

      {error && <p className="text-xs text-critical mt-2">{error}</p>}

      <section className="mt-5 bg-card border border-border rounded-lg overflow-hidden">
        <header className="p-4 border-b border-border flex items-center gap-2">
          <FileText size={16} className="text-accent" />
          <h2 className="text-sm font-semibold text-ink">Generate report</h2>
        </header>
        {scans.length ? (
          <div className="divide-y divide-border">
            {scans.map((scan) => (
              <div key={scan.id} className="p-4 grid md:grid-cols-[1fr_180px_150px] gap-3 items-center">
                <div className="min-w-0">
                  <p className="text-sm text-ink truncate">{scan.target}</p>
                  <p className="text-xs text-ink-3 mt-1 font-mono">{scan.id} - {scan.status}</p>
                </div>
                <select
                  value={formats[scan.id] || "html"}
                  onChange={(event) => setFormats((current) => ({ ...current, [scan.id]: event.target.value as ReportFormat }))}
                  className="bg-canvas border border-border rounded px-3 py-2 text-sm text-ink"
                >
                  {(Object.keys(FORMAT_LABELS) as ReportFormat[]).map((format) => (
                    <option key={format} value={format}>{FORMAT_LABELS[format]}</option>
                  ))}
                </select>
                <button
                  onClick={() => void generate(scan.id)}
                  disabled={busyScan === scan.id}
                  className="px-3 py-2 bg-accent text-white rounded text-sm disabled:opacity-40"
                >
                  {busyScan === scan.id ? "Generating..." : "Generate"}
                </button>
              </div>
            ))}
          </div>
        ) : (
          <p className="p-4 text-sm text-ink-3">No scans available.</p>
        )}
      </section>

      <section className="mt-5 bg-card border border-border rounded-lg overflow-hidden">
        <header className="p-4 border-b border-border text-sm font-semibold text-ink">Saved reports</header>
        {reports.length ? (
          <div className="divide-y divide-border">
            {reports.map((report) => (
              <div key={report.id} className="p-4 grid md:grid-cols-[1fr_120px_120px] gap-3 items-center">
                <div className="min-w-0">
                  <p className="text-sm text-ink truncate">{report.name}</p>
                  <p className="text-xs text-ink-3 mt-1">
                    {report.findings_count} findings - {report.format.toUpperCase()} - {report.size}
                  </p>
                </div>
                <span className="text-xs text-ink-3 font-mono">{report.status}</span>
                <a
                  href={reportsApi.downloadUrl(report.id)}
                  className="inline-flex items-center justify-center gap-2 px-3 py-2 bg-elevated border border-border text-ink rounded text-sm"
                >
                  <Download size={15} />
                  Download
                </a>
              </div>
            ))}
          </div>
        ) : (
          <p className="p-4 text-sm text-ink-3">No reports generated.</p>
        )}
      </section>
    </div>
  )
}

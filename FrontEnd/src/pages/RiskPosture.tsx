import { useEffect, useMemo, useState } from "react"
import { Activity, RefreshCw } from "lucide-react"
import { findingsApi, scanApi, type ApiFinding } from "../api/client"

const ORDER = ["Critical", "High", "Medium", "Low", "Info"]

export default function RiskPosture() {
  const [findings, setFindings] = useState<ApiFinding[]>([])
  const [scans, setScans] = useState<any[]>([])

  const load = async () => {
    const [nextFindings, nextScans] = await Promise.all([findingsApi.list(), scanApi.list()])
    setFindings(nextFindings)
    setScans(nextScans)
  }

  useEffect(() => { void load().catch(() => undefined) }, [])

  const severity = useMemo(() => {
    const counts: Record<string, number> = Object.fromEntries(ORDER.map((item) => [item, 0]))
    findings.forEach((finding) => { counts[finding.severity] = (counts[finding.severity] || 0) + 1 })
    return counts
  }, [findings])

  const categories = useMemo(() => {
    const counts: Record<string, number> = {}
    findings.forEach((finding) => { counts[finding.category] = (counts[finding.category] || 0) + 1 })
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8)
  }, [findings])

  const open = findings.filter((finding) => finding.status === "Open").length
  const highSignal = findings.filter((finding) => ["Critical", "High"].includes(finding.severity)).length

  return (
    <div className="p-6 max-w-[1250px] mx-auto space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-ink">Risk Posture</h1>
          <p className="text-sm text-ink-3 mt-1">Executive summary of current DAST exposure and scan coverage.</p>
        </div>
        <button onClick={() => void load()} className="p-2 rounded border border-border text-ink-2"><RefreshCw size={15} /></button>
      </div>

      <div className="grid md:grid-cols-4 gap-4">
        <Metric label="Total findings" value={String(findings.length)} />
        <Metric label="Open findings" value={String(open)} />
        <Metric label="Critical / High" value={String(highSignal)} />
        <Metric label="Saved scans" value={String(scans.length)} />
      </div>

      <div className="grid lg:grid-cols-2 gap-5">
        <section className="bg-card border border-border rounded-lg overflow-hidden">
          <header className="p-4 border-b border-border flex items-center gap-2">
            <Activity size={15} className="text-accent" />
            <span className="text-sm font-semibold text-ink">Severity distribution</span>
          </header>
          <div className="p-4 space-y-3">
            {ORDER.map((item) => {
              const value = severity[item] || 0
              const pct = findings.length ? Math.round((value / findings.length) * 100) : 0
              return <Bar key={item} label={item} value={value} pct={pct} />
            })}
          </div>
        </section>

        <section className="bg-card border border-border rounded-lg overflow-hidden">
          <header className="p-4 border-b border-border text-sm font-semibold text-ink">Top categories</header>
          <div className="p-4 space-y-3">
            {categories.length ? categories.map(([label, value]) => <Bar key={label} label={label} value={value} pct={Math.round((value / findings.length) * 100)} />) : <p className="text-sm text-ink-3">No findings yet.</p>}
          </div>
        </section>
      </div>

      <section className="bg-card border border-border rounded-lg overflow-hidden">
        <header className="p-4 border-b border-border text-sm font-semibold text-ink">Recent scans</header>
        <div className="divide-y divide-border">
          {scans.slice(0, 8).map((scan) => (
            <div key={scan.id} className="grid md:grid-cols-[140px_1fr_110px_110px] gap-3 p-4 text-xs">
              <span className="font-mono text-accent">{scan.id}</span>
              <span className="text-ink-2 truncate">{scan.target}</span>
              <span className="text-ink-3">{scan.status}</span>
              <span className="text-ink-3">{scan.findings_count} findings</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div className="bg-card border border-border rounded-lg p-4"><p className="text-xs text-ink-3">{label}</p><p className="mt-1 text-2xl font-semibold text-ink">{value}</p></div>
}

function Bar({ label, value, pct }: { label: string; value: number; pct: number }) {
  return (
    <div>
      <div className="flex justify-between text-xs"><span className="text-ink-2">{label}</span><span className="text-ink-3">{value}</span></div>
      <div className="mt-1 h-2 rounded bg-canvas overflow-hidden"><div className="h-full bg-accent" style={{ width: `${pct}%` }} /></div>
    </div>
  )
}

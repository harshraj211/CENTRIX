import { useEffect, useState } from "react"
import { findingsApi, scanApi } from "../api/client"

interface OverviewProps { onNavigate: (page: string) => void; findingsCount: number; scanActive: boolean; onScanSelected?: (scanId: string) => void }

export default function Overview({ onNavigate, findingsCount, scanActive, onScanSelected }: OverviewProps) {
  const [scans, setScans] = useState<any[]>([])
  useEffect(() => { void scanApi.list().then(setScans).catch(() => setScans([])) }, [])
  const openScan = (scanId: string) => {
    onScanSelected?.(scanId)
    onNavigate("automated-scan")
  }
  return <div className="p-6 max-w-[1400px] mx-auto space-y-5"><div className="flex justify-between"><div><h1 className="text-lg font-semibold text-ink">Centrix DAST Overview</h1><p className="text-xs text-ink-3 mt-1">Live data from authorised dynamic application security tests.</p></div><button onClick={() => onNavigate("scan-setup")} className="px-4 py-2 rounded bg-accent text-white text-sm">New scan</button></div>
    <div className="grid md:grid-cols-3 gap-4"><Card label="Saved scans" value={String(scans.length)} /><Card label="DAST findings" value={String(findingsCount)} /><Card label="Scanner" value={scanActive ? "Running" : "Idle"} /></div>
    <section className="bg-card border border-border rounded-lg overflow-hidden"><header className="px-4 py-3 border-b border-border"><h2 className="text-sm font-semibold text-ink">Recent scans</h2></header>{scans.length ? scans.map((scan) => <button key={scan.id} onClick={() => openScan(scan.id)} className="w-full text-left grid grid-cols-4 gap-3 p-4 border-b border-border last:border-0 hover:bg-elevated"><span className="font-mono text-xs text-ink">{scan.id}</span><span className="text-xs text-ink-2 truncate">{scan.target}</span><span className="text-xs text-ink-2">{scan.status}</span><span className="text-xs text-ink-3">{scan.findings_count} findings</span></button>) : <p className="p-6 text-sm text-ink-3">No scans have been saved yet.</p>}</section>
  </div>
}
function Card({ label, value }: { label: string; value: string }) { return <div className="bg-card border border-border rounded-lg p-4"><p className="text-xs text-ink-3">{label}</p><p className="text-2xl font-semibold text-ink mt-1">{value}</p></div> }

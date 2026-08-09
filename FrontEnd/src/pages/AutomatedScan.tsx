import { useEffect, useMemo, useRef, useState } from "react"
import { Copy, Pause, Square } from "lucide-react"
import { createScanLogStream, findingsApi, scanApi, type ApiFinding } from "../api/client"

interface AutomatedScanProps {
  onNavigate: (page: string) => void
  scanActive: boolean
  setScanActive: (active: boolean) => void
  progress: number
  setProgress: React.Dispatch<React.SetStateAction<number>>
  activeScanId?: string | null
}

const isHeaderNoise = (finding: ApiFinding) =>
  finding.category === "Security Headers" ||
  finding.title.toLowerCase().startsWith("missing security header")

export default function AutomatedScan({
  onNavigate,
  scanActive,
  setScanActive,
  progress,
  setProgress,
  activeScanId,
}: AutomatedScanProps) {
  const [paused, setPaused] = useState(false)
  const [stage, setStage] = useState("waiting")
  const [status, setStatus] = useState("idle")
  const [logs, setLogs] = useState<string[]>([])
  const [findings, setFindings] = useState<ApiFinding[]>([])
  const socketRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!activeScanId) return

    const load = async () => {
      try {
        const [nextFindings, nextStatus] = await Promise.all([
          findingsApi.list(activeScanId),
          scanApi.status(activeScanId),
        ])
        setFindings(nextFindings)
        setProgress(nextStatus.progress)
        setStage(nextStatus.stage)
        setStatus(nextStatus.status)
        setPaused(nextStatus.status === "paused")
        setScanActive(["pending", "running", "paused"].includes(nextStatus.status))
      } catch {
        setStatus("unavailable")
        setScanActive(false)
      }
    }

    setLogs([])
    void load()
    const timer = window.setInterval(load, 2000)
    return () => window.clearInterval(timer)
  }, [activeScanId, setProgress, setScanActive])

  useEffect(() => {
    if (!scanActive || !activeScanId || !["pending", "running", "paused"].includes(status)) return

    socketRef.current = createScanLogStream(
      activeScanId,
      (message) => setLogs((items) => [...items, message]),
      () => setScanActive(false),
    )

    return () => {
      socketRef.current?.close()
      socketRef.current = null
    }
  }, [activeScanId, scanActive, status, setScanActive])

  const pause = async () => {
    if (!activeScanId) return
    await scanApi.pause(activeScanId)
    setPaused((value) => !value)
  }

  const stop = async () => {
    if (!activeScanId) return
    await scanApi.stop(activeScanId)
    setScanActive(false)
  }

  if (!activeScanId) return <Empty onNavigate={onNavigate} />

  const displayStatus =
    status === "completed" ? "Completed" :
    status === "paused" ? "Paused" :
    status === "running" ? "Running" :
    status === "pending" ? "Queued" :
    status === "error" ? "Failed" :
    status === "stopped" ? "Stopped" :
    status === "unavailable" ? "Unavailable" :
    "Idle"

  const logText = logs.length
    ? logs.join("\n")
    : scanActive
      ? "Waiting for scanner output..."
      : "Live logs are only available while the selected scan is running."

  const displayedFindings = useMemo(
    () => findings.filter((finding) => !isHeaderNoise(finding)),
    [findings],
  )

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-ink text-lg font-semibold">Automated Scan</h1>
          <p className="text-ink-3 text-xs mt-1 font-mono">{activeScanId} - {stage.toUpperCase()}</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-ink-2">{progress}%</span>
          <button disabled={!scanActive} onClick={pause} className="px-3 py-2 rounded border border-border text-xs disabled:opacity-40">
            <Pause size={12} className="inline mr-1" />
            {paused ? "Resume" : "Pause"}
          </button>
          <button disabled={!scanActive} onClick={stop} className="px-3 py-2 rounded bg-critical text-white text-xs disabled:opacity-40">
            <Square size={12} className="inline mr-1" />
            Stop
          </button>
        </div>
      </div>

      <div className="h-2 rounded bg-elevated overflow-hidden">
        <div className="h-full bg-accent transition-all" style={{ width: `${progress}%` }} />
      </div>

      <div className="grid md:grid-cols-3 gap-4">
        <Metric label="Status" value={displayStatus} />
        <Metric label="Findings" value={String(displayedFindings.length)} />
        <Metric label="Progress" value={`${progress}%`} />
      </div>

      <div className="grid lg:grid-cols-2 gap-5">
        <section className="bg-card border border-border rounded-lg overflow-hidden">
          <header className="px-4 py-3 border-b border-border flex justify-between">
            <span className="text-sm font-semibold text-ink">Live scanner log</span>
            <button onClick={() => navigator.clipboard.writeText(logs.join("\n"))} className="text-xs text-ink-2">
              <Copy size={12} className="inline mr-1" />
              Copy
            </button>
          </header>
          <pre className="min-h-80 max-h-[480px] overflow-auto p-4 text-xs text-ink-2 font-mono whitespace-pre-wrap">{logText}</pre>
        </section>

        <section className="bg-card border border-border rounded-lg overflow-hidden">
          <header className="px-4 py-3 border-b border-border">
            <span className="text-sm font-semibold text-ink">Findings</span>
          </header>
          <div className="divide-y divide-border">
            {displayedFindings.length ? displayedFindings.map((finding) => (
              <button key={finding.id} onClick={() => onNavigate("findings")} className="w-full text-left p-4 hover:bg-elevated">
                <span className="text-xs font-semibold text-ink">{finding.title}</span>
                <p className="text-[11px] text-ink-3 mt-1">{finding.severity} - {finding.target}</p>
              </button>
            )) : (
              <p className="p-4 text-xs text-ink-3">No findings recorded for this scan.</p>
            )}
          </div>
        </section>
      </div>
    </div>
  )
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <p className="text-xs text-ink-3">{label}</p>
      <p className="mt-1 text-xl text-ink font-semibold">{value}</p>
    </div>
  )
}

function Empty({ onNavigate }: { onNavigate: (page: string) => void }) {
  return (
    <div className="p-6 max-w-xl mx-auto text-center">
      <h1 className="text-lg font-semibold text-ink">No scan selected</h1>
      <p className="text-sm text-ink-3 mt-2">Start an authorised scan to view its live progress and findings here.</p>
      <button onClick={() => onNavigate("scan-setup")} className="mt-5 px-4 py-2 rounded bg-accent text-white text-sm">Configure scan</button>
    </div>
  )
}

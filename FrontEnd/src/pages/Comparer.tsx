import { useEffect, useState } from "react"
import { GitCompare } from "lucide-react"
import { manualApi, scanApi } from "../api/client"

export default function Comparer() {
  const [scans, setScans] = useState<any[]>([])
  const [scanId, setScanId] = useState("")
  const [items, setItems] = useState<any[]>([])
  const [leftId, setLeftId] = useState("")
  const [rightId, setRightId] = useState("")
  const [result, setResult] = useState<any>(null)
  const [error, setError] = useState("")

  useEffect(() => {
    void scanApi.list().then((next) => {
      setScans(next)
      if (next[0]) setScanId(next[0].id)
    }).catch(() => undefined)
  }, [])

  useEffect(() => {
    if (!scanId) return
    void manualApi.corpus(scanId).then((next) => {
      setItems(next)
      setLeftId(next[0]?.id || "")
      setRightId(next[1]?.id || next[0]?.id || "")
    }).catch(() => setItems([]))
  }, [scanId])

  const compare = async () => {
    setError("")
    try {
      setResult(await manualApi.compareCorpus(leftId, rightId))
    } catch (reason: any) {
      setError(reason.message || "Compare failed.")
    }
  }

  return (
    <div className="p-6 max-w-[1200px] mx-auto space-y-5">
      <div>
        <h1 className="text-lg font-semibold text-ink">Comparer</h1>
        <p className="text-sm text-ink-3 mt-1">Compare two saved corpus responses by status, length, timing, body hash, and headers.</p>
      </div>

      <section className="bg-card border border-border rounded-lg p-4 grid lg:grid-cols-[1fr_1fr_1fr_auto] gap-3 items-end">
        <label className="text-xs text-ink-3">Scan
          <select value={scanId} onChange={(event) => setScanId(event.target.value)} className="mt-1 w-full bg-canvas border border-border rounded px-3 py-2 text-sm text-ink">
            {scans.map((scan) => <option key={scan.id} value={scan.id}>{scan.id} - {scan.target}</option>)}
          </select>
        </label>
        <Selector label="Left response" value={leftId} setValue={setLeftId} items={items} />
        <Selector label="Right response" value={rightId} setValue={setRightId} items={items} />
        <button disabled={!leftId || !rightId} onClick={() => void compare()} className="inline-flex items-center gap-2 px-4 py-2 bg-accent text-white rounded text-sm disabled:opacity-40">
          <GitCompare size={15} /> Compare
        </button>
      </section>

      {error && <p className="text-xs text-critical">{error}</p>}

      <section className="bg-card border border-border rounded-lg p-4">
        {result ? (
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <Metric label="Status changed" value={result.status_changed ? "Yes" : "No"} />
            <Metric label="Length delta" value={String(result.length_delta)} />
            <Metric label="Time delta" value={`${Math.round(result.time_delta_ms)} ms`} />
            <Metric label="Body changed" value={result.body_hash_changed ? "Yes" : "No"} />
            <Metric label="Headers added" value={(result.header_keys_added || []).join(", ") || "-"} wide />
            <Metric label="Headers removed" value={(result.header_keys_removed || []).join(", ") || "-"} wide />
          </div>
        ) : (
          <p className="text-sm text-ink-3">Pick two captured responses to compare.</p>
        )}
      </section>
    </div>
  )
}

function Selector({ label, value, setValue, items }: { label: string; value: string; setValue: (value: string) => void; items: any[] }) {
  return (
    <label className="text-xs text-ink-3">{label}
      <select value={value} onChange={(event) => setValue(event.target.value)} className="mt-1 w-full bg-canvas border border-border rounded px-3 py-2 text-sm text-ink">
        {items.map((item) => <option key={item.id} value={item.id}>{item.method} {item.status || "-"} {item.path}</option>)}
      </select>
    </label>
  )
}

function Metric({ label, value, wide }: { label: string; value: string; wide?: boolean }) {
  return (
    <div className={`bg-canvas border border-border rounded p-3 ${wide ? "lg:col-span-2" : ""}`}>
      <p className="text-xs text-ink-3">{label}</p>
      <p className="mt-1 text-sm text-ink break-all">{value}</p>
    </div>
  )
}

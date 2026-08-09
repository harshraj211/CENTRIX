import { useEffect, useState } from "react"
import { Crosshair, Play } from "lucide-react"
import { manualApi, scanApi } from "../api/client"

export default function Intruder() {
  const [scans, setScans] = useState<any[]>([])
  const [scanId, setScanId] = useState("")
  const [method, setMethod] = useState("GET")
  const [url, setUrl] = useState("https://example.com/search?q={{payload}}")
  const [headers, setHeaders] = useState("{\n}")
  const [body, setBody] = useState("")
  const [marker, setMarker] = useState("{{payload}}")
  const [payloads, setPayloads] = useState("centrix-test\n'\n<script>alert(1)</script>")
  const [matchText, setMatchText] = useState("")
  const [extractRegex, setExtractRegex] = useState("")
  const [results, setResults] = useState<any[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")

  useEffect(() => {
    void scanApi.list().then((items) => {
      setScans(items)
      if (items[0]) {
        setScanId(items[0].id)
        setUrl(`${items[0].target}${items[0].target.includes("?") ? "&" : "?"}q={{payload}}`)
      }
    }).catch(() => undefined)
  }, [])

  const run = async () => {
    setBusy(true)
    setError("")
    setResults([])
    try {
      const parsedHeaders = JSON.parse(headers || "{}")
      const result = await manualApi.intruder({
        scan_id: scanId,
        method,
        url,
        headers: parsedHeaders,
        body: body || undefined,
        marker,
        payloads: payloads.split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
        max_requests: 50,
        delay_ms: 100,
        match_text: matchText,
        extract_regex: extractRegex,
      })
      setResults(result.results)
    } catch (reason: any) {
      setError(reason.message || "Intruder run failed.")
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-5">
      <div>
        <h1 className="text-lg font-semibold text-ink">Intruder</h1>
        <p className="text-sm text-ink-3 mt-1">Safe scoped payload runner with match and extract columns.</p>
      </div>

      <div className="grid xl:grid-cols-[420px_minmax(0,1fr)] gap-5">
        <section className="bg-card border border-border rounded-lg p-4 space-y-3">
          <select value={scanId} onChange={(event) => setScanId(event.target.value)} className="w-full bg-canvas border border-border rounded px-3 py-2 text-sm text-ink">
            {scans.map((scan) => <option key={scan.id} value={scan.id}>{scan.id} - {scan.target}</option>)}
          </select>
          <div className="grid grid-cols-[110px_1fr] gap-2">
            <select value={method} onChange={(event) => setMethod(event.target.value)} className="bg-canvas border border-border rounded px-3 py-2 text-sm text-ink">
              {["GET", "POST", "PUT", "PATCH", "DELETE"].map((item) => <option key={item}>{item}</option>)}
            </select>
            <input value={url} onChange={(event) => setUrl(event.target.value)} className="bg-canvas border border-border rounded px-3 py-2 text-sm text-ink" />
          </div>
          <input value={marker} onChange={(event) => setMarker(event.target.value)} className="w-full bg-canvas border border-border rounded px-3 py-2 text-sm text-ink" />
          <textarea value={headers} onChange={(event) => setHeaders(event.target.value)} spellCheck={false} className="w-full h-24 bg-canvas border border-border rounded p-2 text-xs font-mono text-ink" />
          <textarea value={body} onChange={(event) => setBody(event.target.value)} placeholder="Optional body with {{payload}} marker" className="w-full h-24 bg-canvas border border-border rounded p-2 text-xs font-mono text-ink" />
          <textarea value={payloads} onChange={(event) => setPayloads(event.target.value)} className="w-full h-36 bg-canvas border border-border rounded p-2 text-xs font-mono text-ink" />
          <input value={matchText} onChange={(event) => setMatchText(event.target.value)} placeholder="Grep match text" className="w-full bg-canvas border border-border rounded px-3 py-2 text-sm text-ink" />
          <input value={extractRegex} onChange={(event) => setExtractRegex(event.target.value)} placeholder="Extract regex, optional" className="w-full bg-canvas border border-border rounded px-3 py-2 text-sm text-ink" />
          {error && <p className="text-xs text-critical">{error}</p>}
          <button disabled={!scanId || !url || busy} onClick={() => void run()} className="inline-flex items-center justify-center gap-2 w-full px-4 py-2 bg-accent text-white rounded text-sm disabled:opacity-40">
            <Play size={15} /> {busy ? "Running..." : "Start attack"}
          </button>
        </section>

        <section className="bg-card border border-border rounded-lg overflow-hidden">
          <header className="p-3 border-b border-border flex items-center gap-2">
            <Crosshair size={15} className="text-accent" />
            <span className="text-sm font-semibold text-ink">Results</span>
          </header>
          <div className="grid grid-cols-[minmax(160px,1fr)_80px_100px_100px_90px_minmax(160px,1fr)] gap-3 px-4 py-3 border-b border-border text-[11px] uppercase text-ink-3">
            <span>Payload</span><span>Status</span><span>Length</span><span>Time</span><span>Match</span><span>Extracted</span>
          </div>
          <div className="divide-y divide-border max-h-[640px] overflow-auto">
            {results.length ? results.map((item, index) => (
              <div key={`${item.payload}-${index}`} className="grid grid-cols-[minmax(160px,1fr)_80px_100px_100px_90px_minmax(160px,1fr)] gap-3 p-4 text-xs">
                <span className="font-mono text-ink break-all">{item.payload}</span>
                <span className="text-ink-2">{item.status || "err"}</span>
                <span className="text-ink-2">{item.length || "-"}</span>
                <span className="text-ink-2">{item.duration_ms || "-"}</span>
                <span className={item.matched ? "text-emerald" : "text-ink-3"}>{item.matched ? "Yes" : "No"}</span>
                <span className="font-mono text-ink-3 break-all">{Array.isArray(item.extracted) ? item.extracted.join(", ") : item.error || ""}</span>
              </div>
            )) : <p className="p-6 text-sm text-ink-3">No Intruder results yet.</p>}
          </div>
        </section>
      </div>
    </div>
  )
}

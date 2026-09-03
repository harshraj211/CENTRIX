import { useEffect, useState } from "react"
import { RefreshCw, Search, Zap } from "lucide-react"
import { integrationsApi, scanApi } from "../api/client"

export default function NucleiCve() {
  const [status, setStatus] = useState<any>(null)
  const [scans, setScans] = useState<any[]>([])
  const [scanId, setScanId] = useState("")
  const [query, setQuery] = useState("")
  const [cves, setCves] = useState<any[]>([])
  const [nucleiResults, setNucleiResults] = useState<any[]>([])
  const [nucleiEngine, setNucleiEngine] = useState("")
  const [busy, setBusy] = useState("")
  const [error, setError] = useState("")

  const load = async () => {
    const [nextStatus, nextScans] = await Promise.all([integrationsApi.status(), scanApi.list()])
    setStatus(nextStatus)
    setScans(nextScans)
    if (!scanId && nextScans[0]) setScanId(nextScans[0].id)
  }

  useEffect(() => { void load().catch(() => undefined) }, [])

  const search = async () => {
    setBusy("cve")
    setError("")
    try {
      const result = await integrationsApi.searchCves(query)
      setCves(result.results)
    } catch (reason: any) {
      setError(reason.message || "CVE search failed.")
    } finally {
      setBusy("")
    }
  }

  const runNuclei = async () => {
    setBusy("nuclei")
    setError("")
    try {
      const result = await integrationsApi.runNuclei(scanId, ["critical", "high", "medium"])
      setNucleiResults(result.results)
      setNucleiEngine(result.engine || "")
    } catch (reason: any) {
      setError(reason.message || "Nuclei run failed.")
    } finally {
      setBusy("")
    }
  }

  return (
    <div className="p-6 max-w-[1250px] mx-auto space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-ink">Nuclei & CVE</h1>
          <p className="text-sm text-ink-3 mt-1">Template scan import and CVE intelligence, separated from Settings like Wraith.</p>
        </div>
        <button onClick={() => void load()} className="p-2 rounded border border-border text-ink-2"><RefreshCw size={15} /></button>
      </div>

      {error && <p className="text-xs text-critical">{error}</p>}

      <div className="grid lg:grid-cols-2 gap-5">
        <section className="bg-card border border-border rounded-lg overflow-hidden">
          <header className="p-4 border-b border-border text-sm font-semibold text-ink">Nuclei</header>
          <div className="p-4 space-y-3">
            <p className="text-xs text-ink-3">
              Status: {status?.nuclei?.available ? "Nuclei binary available" : "Using Centrix built-in templates"} · Mode: {status?.nuclei?.mode || "checking"}
            </p>
            <select value={scanId} onChange={(event) => setScanId(event.target.value)} className="w-full bg-canvas border border-border rounded px-3 py-2 text-sm text-ink">
              {scans.map((scan) => <option key={scan.id} value={scan.id}>{scan.id} - {scan.target}</option>)}
            </select>
            <button disabled={!scanId || busy === "nuclei"} onClick={() => void runNuclei()} className="inline-flex items-center gap-2 px-4 py-2 bg-accent text-white rounded text-sm disabled:opacity-40">
              <Zap size={15} /> {busy === "nuclei" ? "Running..." : "Run safe templates"}
            </button>
            {nucleiEngine && <p className="text-xs text-ink-3">Last run engine: {nucleiEngine}</p>}
            <div className="border border-border rounded divide-y divide-border max-h-80 overflow-auto">
              {nucleiResults.length ? nucleiResults.map((item, index) => <pre key={index} className="p-3 text-xs text-ink-2 whitespace-pre-wrap">{JSON.stringify(item, null, 2)}</pre>) : <p className="p-3 text-sm text-ink-3">No template results loaded yet.</p>}
            </div>
          </div>
        </section>

        <section className="bg-card border border-border rounded-lg overflow-hidden">
          <header className="p-4 border-b border-border text-sm font-semibold text-ink">CVE Lookup</header>
          <div className="p-4 space-y-3">
            <div className="flex gap-2">
              <input value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void search() }} placeholder="Search CVE, product, version..." className="flex-1 bg-canvas border border-border rounded px-3 py-2 text-sm text-ink" />
              <button disabled={!query || busy === "cve"} onClick={() => void search()} className="inline-flex items-center gap-2 px-4 py-2 bg-accent text-white rounded text-sm disabled:opacity-40">
                <Search size={15} /> Search
              </button>
            </div>
            <div className="border border-border rounded divide-y divide-border max-h-[520px] overflow-auto">
              {cves.length ? cves.map((cve) => (
                <a key={cve.id} href={cve.url} target="_blank" rel="noreferrer" className="block p-3 hover:bg-elevated">
                  <div className="flex justify-between gap-3">
                    <span className="font-mono text-xs text-accent">{cve.id}</span>
                    <span className="text-xs text-ink-3">{cve.score ? `CVSS ${cve.score}` : "No score"}</span>
                  </div>
                  <p className="mt-2 text-xs text-ink-2">{cve.summary}</p>
                </a>
              )) : <p className="p-3 text-sm text-ink-3">No CVE results yet.</p>}
            </div>
          </div>
        </section>
      </div>
    </div>
  )
}

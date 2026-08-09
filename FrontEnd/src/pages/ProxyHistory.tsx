import { useEffect, useMemo, useState } from "react"
import { Download, Globe, RefreshCw, Radio, ShieldCheck } from "lucide-react"
import { manualApi, scanApi } from "../api/client"

interface ProxyHistoryProps {
  onNavigate: (page: string) => void
  onSendToRepeater?: (request: any) => void
}

export default function ProxyHistory({ onNavigate, onSendToRepeater }: ProxyHistoryProps) {
  const [scans, setScans] = useState<any[]>([])
  const [scanId, setScanId] = useState("")
  const [items, setItems] = useState<any[]>([])
  const [selected, setSelected] = useState<any | null>(null)
  const [proxy, setProxy] = useState<any>(null)
  const [ca, setCa] = useState<any>(null)
  const [browser, setBrowser] = useState<any>(null)
  const [filter, setFilter] = useState("")
  const [message, setMessage] = useState("")

  const load = async () => {
    const [nextScans, nextProxy, nextCa, nextBrowser] = await Promise.all([scanApi.list(), manualApi.proxyStatus(), manualApi.caStatus(), manualApi.browserStatus()])
    setScans(nextScans)
    setProxy(nextProxy)
    setCa(nextCa)
    setBrowser(nextBrowser)
    const chosen = scanId || nextScans[0]?.id || ""
    if (chosen) {
      setScanId(chosen)
      const nextItems = await manualApi.corpus(chosen)
      setItems(nextItems)
      setSelected((current) => current || nextItems[0] || null)
    }
  }

  useEffect(() => { void load().catch(() => undefined) }, [])
  useEffect(() => {
    if (!scanId) return
    void manualApi.corpus(scanId).then((next) => {
      setItems(next)
      setSelected(next[0] || null)
    }).catch(() => setItems([]))
  }, [scanId])

  const filtered = useMemo(() => {
    const needle = filter.toLowerCase()
    return items.filter((item) => `${item.method} ${item.url} ${item.status}`.toLowerCase().includes(needle))
  }, [items, filter])

  const toggleProxy = async () => {
    setProxy(proxy?.running ? await manualApi.proxyStop() : await manualApi.proxyStart(scanId))
  }

  const generateCa = async () => {
    setCa(await manualApi.caGenerate())
    setMessage("Centrix local CA generated. Download and trust it only in an isolated test profile.")
  }

  const generateLeaf = async () => {
    const scan = scans.find((item) => item.id === scanId)
    const target = scan?.target || selected?.url || ""
    const hostname = new URL(target).hostname
    await manualApi.leafGenerate(hostname)
    setMessage(`Leaf certificate generated for ${hostname}.`)
  }

  const openBrowser = async () => {
    const scan = scans.find((item) => item.id === scanId)
    const target = scan?.target || selected?.url || ""
    const result = await manualApi.browserOpen(target, scanId, Boolean(proxy?.running))
    setBrowser(result)
    setMessage(result.ok ? "Controlled browser opened." : result.error || "Browser could not open.")
  }

  const runPassive = async () => {
    if (!scanId) return
    const result = await manualApi.runPassive(scanId)
    setMessage(`Passive analysis imported ${result.imported} findings from captured traffic.`)
  }

  return (
    <div className="p-6 max-w-[1500px] mx-auto space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-ink">Proxy History</h1>
          <p className="text-sm text-ink-3 mt-1">Captured and replayed traffic corpus for manual testing.</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => void runPassive()} disabled={!scanId} className="inline-flex items-center gap-2 px-3 py-2 rounded border border-border bg-elevated text-sm text-ink disabled:opacity-40">
            <ShieldCheck size={15} /> Passive scan
          </button>
          <button onClick={() => void toggleProxy()} className="inline-flex items-center gap-2 px-3 py-2 rounded bg-accent text-white text-sm">
            <Radio size={15} /> {proxy?.running ? "Stop proxy" : "Start proxy"}
          </button>
          <button onClick={() => void load()} className="p-2 rounded border border-border text-ink-2"><RefreshCw size={15} /></button>
        </div>
      </div>

      {message && <p className="text-xs text-emerald">{message}</p>}

      <div className="grid lg:grid-cols-[440px_minmax(0,1fr)] gap-5">
        <section className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="p-3 border-b border-border space-y-2">
            <select value={scanId} onChange={(event) => setScanId(event.target.value)} className="w-full bg-canvas border border-border rounded px-3 py-2 text-sm text-ink">
              {scans.map((scan) => <option key={scan.id} value={scan.id}>{scan.id} - {scan.target}</option>)}
            </select>
            <input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter method, URL, status" className="w-full bg-canvas border border-border rounded px-3 py-2 text-sm text-ink" />
          </div>
          <div className="max-h-[620px] overflow-auto divide-y divide-border">
            {filtered.length ? filtered.map((item) => (
              <button key={item.id} onClick={() => setSelected(item)} className={`w-full text-left p-3 hover:bg-elevated ${selected?.id === item.id ? "bg-accent/10" : ""}`}>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono text-accent">{item.method}</span>
                  <span className="text-xs text-ink-3">{item.status || "saved"}</span>
                </div>
                <p className="mt-1 text-xs font-mono text-ink-2 truncate">{item.url}</p>
              </button>
            )) : <p className="p-4 text-sm text-ink-3">No captured requests yet. Send something from Repeater or Intruder.</p>}
          </div>
        </section>

        <section className="space-y-5">
        <div className="bg-card border border-border rounded-lg p-4">
          <div className="flex flex-wrap gap-2 items-center">
            <button onClick={() => void generateCa()} className="px-3 py-2 bg-elevated border border-border rounded text-xs text-ink">
              {ca?.generated ? "Regenerate CA" : "Generate CA"}
            </button>
            {ca?.generated && <a href={manualApi.caDownloadUrl()} className="inline-flex items-center gap-2 px-3 py-2 bg-elevated border border-border rounded text-xs text-ink"><Download size={13} /> Download CA</a>}
            <button onClick={() => void generateLeaf()} disabled={!scanId || !ca?.generated} className="px-3 py-2 bg-elevated border border-border rounded text-xs text-ink disabled:opacity-40">Generate leaf cert</button>
            <button onClick={() => void openBrowser()} disabled={!scanId} className="inline-flex items-center gap-2 px-3 py-2 bg-accent text-white rounded text-xs disabled:opacity-40"><Globe size={13} /> Open controlled browser</button>
          </div>
          <p className="mt-3 text-xs text-ink-3">
            Proxy: {proxy?.running ? `${proxy.host}:${proxy.port} capturing HTTP + tunneling HTTPS` : "stopped"} · Captured: {proxy?.captured_count || 0} · HTTPS tunneled: {proxy?.https_connect_tunnel_count || 0} · blocked: {proxy?.https_connect_blocked_count || 0}
          </p>
          <p className="mt-1 text-xs text-ink-3">
            CA: {ca?.generated ? "generated" : "not generated"} · Browser: {browser?.running ? "running" : "stopped"} · HTTPS bodies are tunneled unless MITM capture is enabled later.
          </p>
        </div>

        <section className="bg-card border border-border rounded-lg overflow-hidden">
          <header className="p-3 border-b border-border flex items-center justify-between">
            <span className="text-sm font-semibold text-ink">Inspector</span>
            {selected && <button onClick={() => { onSendToRepeater?.(selected); onNavigate("repeater") }} className="px-3 py-1.5 bg-elevated border border-border rounded text-xs text-ink">Send to Repeater</button>}
          </header>
          {selected ? (
            <div className="grid xl:grid-cols-2 gap-0">
              <Panel title="Request" value={`${selected.method} ${selected.url}\n\n${JSON.stringify(selected.request_headers || {}, null, 2)}\n\n${selected.request_body || ""}`} />
              <Panel title="Response" value={`HTTP ${selected.status || "-"}\n\n${JSON.stringify(selected.response?.headers || {}, null, 2)}\n\n${selected.response?.body || selected.response_excerpt || ""}`} />
            </div>
          ) : (
            <p className="p-6 text-sm text-ink-3">Select a request to inspect it.</p>
          )}
        </section>
        </section>
      </div>
    </div>
  )
}

function Panel({ title, value }: { title: string; value: string }) {
  return (
    <div className="border-r border-border last:border-r-0">
      <div className="p-3 border-b border-border text-xs text-ink-3">{title}</div>
      <pre className="p-4 min-h-[520px] max-h-[620px] overflow-auto whitespace-pre-wrap break-all text-xs font-mono text-ink-2">{value}</pre>
    </div>
  )
}

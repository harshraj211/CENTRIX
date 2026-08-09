import { useEffect, useState } from "react"
import { Copy, RefreshCw, Satellite } from "lucide-react"
import { oobApi, scanApi } from "../api/client"

export default function OobMonitor() {
  const [scans, setScans] = useState<any[]>([])
  const [scanId, setScanId] = useState("")
  const [token, setToken] = useState("")
  const [events, setEvents] = useState<any[]>([])
  const [message, setMessage] = useState("")

  const load = async () => {
    const [nextScans, nextEvents] = await Promise.all([scanApi.list(), oobApi.events(token || undefined)])
    setScans(nextScans)
    if (!scanId && nextScans[0]) setScanId(nextScans[0].id)
    setEvents(nextEvents)
  }

  useEffect(() => { void load().catch(() => undefined) }, [])

  const create = async () => {
    const result = await oobApi.createToken(scanId)
    setToken(result.token)
    setMessage("OOB token created. Use a public tunnel if the target must call back from the internet.")
    setEvents([])
  }

  const callback = token ? oobApi.callbackUrl(token) : ""

  return (
    <div className="p-6 max-w-[1200px] mx-auto space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-ink">OOB Monitor</h1>
          <p className="text-sm text-ink-3 mt-1">Generate callback tokens and record out-of-band proof interactions.</p>
        </div>
        <button onClick={() => void load()} className="p-2 rounded border border-border text-ink-2"><RefreshCw size={15} /></button>
      </div>

      <section className="bg-card border border-border rounded-lg p-4 space-y-3">
        <div className="grid md:grid-cols-[1fr_auto] gap-3">
          <select value={scanId} onChange={(event) => setScanId(event.target.value)} className="bg-canvas border border-border rounded px-3 py-2 text-sm text-ink">
            {scans.map((scan) => <option key={scan.id} value={scan.id}>{scan.id} - {scan.target}</option>)}
          </select>
          <button onClick={() => void create()} className="inline-flex items-center gap-2 px-4 py-2 bg-accent text-white rounded text-sm">
            <Satellite size={15} /> New token
          </button>
        </div>
        {callback && (
          <div className="flex gap-2">
            <input readOnly value={callback} className="flex-1 bg-canvas border border-border rounded px-3 py-2 text-xs font-mono text-ink-2" />
            <button onClick={() => { void navigator.clipboard.writeText(callback); setMessage("Callback URL copied.") }} className="p-2 border border-border rounded text-ink-2"><Copy size={15} /></button>
          </div>
        )}
        {message && <p className="text-xs text-emerald">{message}</p>}
      </section>

      <section className="bg-card border border-border rounded-lg overflow-hidden">
        <header className="p-3 border-b border-border text-sm font-semibold text-ink">Captured callbacks</header>
        <div className="divide-y divide-border">
          {events.length ? events.map((event) => (
            <article key={event.id} className="p-4">
              <div className="flex justify-between gap-3">
                <p className="text-xs font-mono text-accent">{event.method} {event.token}</p>
                <p className="text-xs text-ink-3">{event.captured_at}</p>
              </div>
              <p className="mt-1 text-xs text-ink-2 break-all">{event.url}</p>
              {event.body_excerpt && <pre className="mt-2 p-3 bg-canvas border border-border rounded text-xs text-ink-3 whitespace-pre-wrap">{event.body_excerpt}</pre>}
            </article>
          )) : <p className="p-4 text-sm text-ink-3">No OOB callbacks captured yet.</p>}
        </div>
      </section>
    </div>
  )
}

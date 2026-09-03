import { useEffect, useState } from "react"
import { CalendarClock, Pause, Play, RefreshCw, Trash2 } from "lucide-react"
import { schedulesApi } from "../api/client"

type Frequency = "once" | "hourly" | "daily" | "weekly"

export default function ScheduledScans() {
  const [items, setItems] = useState<any[]>([])
  const [name, setName] = useState("Daily authorised scan")
  const [target, setTarget] = useState("")
  const [frequency, setFrequency] = useState<Frequency>("daily")
  const [firstRun, setFirstRun] = useState("")
  const [safety, setSafety] = useState<"passive" | "standard" | "aggressive">("standard")
  const [authorized, setAuthorized] = useState(false)
  const [busy, setBusy] = useState("")
  const [error, setError] = useState("")

  const load = async () => {
    setItems(await schedulesApi.list())
  }

  useEffect(() => { void load().catch(() => undefined) }, [])

  const create = async () => {
    setBusy("create")
    setError("")
    try {
      await schedulesApi.create({
        name,
        frequency,
        first_run_at: firstRun ? new Date(firstRun).toISOString() : null,
        config: {
          target,
          scope: [],
          imported_urls: [],
          imported_requests: [],
          authorized,
          profile: "full",
          safety,
          depth: 3,
          timeout: 30,
          concurrency: 10,
          max_requests: 500,
          respect_robots: false,
          environment: "Production",
        },
      })
      await load()
    } catch (reason: any) {
      setError(reason.message || "Could not create schedule.")
    } finally {
      setBusy("")
    }
  }

  const runNow = async (id: string) => {
    setBusy(id)
    setError("")
    try {
      await schedulesApi.run(id)
      await load()
    } catch (reason: any) {
      setError(reason.message || "Could not run schedule.")
    } finally {
      setBusy("")
    }
  }

  const toggle = async (item: any) => {
    setBusy(item.id)
    setError("")
    try {
      await schedulesApi.setStatus(item.id, item.status === "enabled" ? "paused" : "enabled")
      await load()
    } catch (reason: any) {
      setError(reason.message || "Could not update schedule.")
    } finally {
      setBusy("")
    }
  }

  const remove = async (id: string) => {
    setBusy(id)
    setError("")
    try {
      await schedulesApi.remove(id)
      await load()
    } catch (reason: any) {
      setError(reason.message || "Could not delete schedule.")
    } finally {
      setBusy("")
    }
  }

  return (
    <div className="p-6 max-w-[1200px] mx-auto space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-ink">Scheduled Scans</h1>
          <p className="text-sm text-ink-3 mt-1">Queue repeat DAST scans without running a separate scheduler service.</p>
        </div>
        <button onClick={() => void load()} className="p-2 rounded border border-border text-ink-2"><RefreshCw size={15} /></button>
      </div>

      <section className="bg-card border border-border rounded-lg p-4 space-y-3">
        <div className="grid lg:grid-cols-[1fr_1.4fr_140px_190px_150px] gap-3">
          <input value={name} onChange={(event) => setName(event.target.value)} placeholder="Schedule name" className="bg-canvas border border-border rounded px-3 py-2 text-sm text-ink" />
          <input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://target.example.com" className="bg-canvas border border-border rounded px-3 py-2 text-sm text-ink" />
          <select value={frequency} onChange={(event) => setFrequency(event.target.value as Frequency)} className="bg-canvas border border-border rounded px-3 py-2 text-sm text-ink">
            <option value="once">Once</option>
            <option value="hourly">Hourly</option>
            <option value="daily">Daily</option>
            <option value="weekly">Weekly</option>
          </select>
          <input type="datetime-local" value={firstRun} onChange={(event) => setFirstRun(event.target.value)} className="bg-canvas border border-border rounded px-3 py-2 text-sm text-ink" />
          <select value={safety} onChange={(event) => setSafety(event.target.value as typeof safety)} className="bg-canvas border border-border rounded px-3 py-2 text-sm text-ink">
            <option value="passive">Passive</option>
            <option value="standard">Standard</option>
            <option value="aggressive">Aggressive</option>
          </select>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <label className="flex gap-2 text-sm text-ink">
            <input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} />
            I own this target or have explicit authorisation to schedule scans.
          </label>
          <button disabled={busy === "create" || !target || !authorized} onClick={() => void create()} className="inline-flex items-center gap-2 px-4 py-2 bg-accent text-white rounded text-sm disabled:opacity-40">
            <CalendarClock size={15} /> Create schedule
          </button>
        </div>
      </section>

      {error && <p className="text-xs text-critical">{error}</p>}

      <section className="bg-card border border-border rounded-lg overflow-hidden">
        <header className="p-3 border-b border-border flex items-center gap-2">
          <CalendarClock size={15} className="text-accent" />
          <span className="text-sm font-semibold text-ink">Queue</span>
        </header>
        <div className="divide-y divide-border">
          {items.length ? items.map((item) => (
            <article key={item.id} className="p-4 grid xl:grid-cols-[1fr_120px_170px_150px_220px] gap-3 items-start">
              <div>
                <p className="text-sm text-ink">{item.name}</p>
                <p className="mt-1 text-xs text-ink-3 font-mono">{item.id} - {item.config?.target}</p>
                {item.last_scan_id && <p className="mt-1 text-xs text-accent font-mono">Last scan: {item.last_scan_id}</p>}
              </div>
              <span className="text-xs text-ink-3 capitalize">{item.frequency}</span>
              <span className="text-xs text-ink-3">{item.next_run_at ? new Date(item.next_run_at).toLocaleString() : "No next run"}</span>
              <span className="text-xs text-ink-3 capitalize">{item.status} · {item.run_count || 0} run(s)</span>
              <div className="flex flex-wrap gap-2">
                <button disabled={busy === item.id} onClick={() => void runNow(item.id)} className="inline-flex items-center gap-1.5 px-3 py-2 bg-elevated border border-border text-ink rounded text-xs disabled:opacity-40">
                  <Play size={13} /> Run now
                </button>
                <button disabled={busy === item.id} onClick={() => void toggle(item)} className="inline-flex items-center gap-1.5 px-3 py-2 bg-elevated border border-border text-ink rounded text-xs disabled:opacity-40">
                  {item.status === "enabled" ? <Pause size={13} /> : <Play size={13} />} {item.status === "enabled" ? "Pause" : "Enable"}
                </button>
                <button disabled={busy === item.id} onClick={() => void remove(item.id)} className="inline-flex items-center gap-1.5 px-3 py-2 bg-elevated border border-border text-critical rounded text-xs disabled:opacity-40">
                  <Trash2 size={13} /> Delete
                </button>
              </div>
            </article>
          )) : <p className="p-6 text-sm text-ink-3">No schedules yet.</p>}
        </div>
      </section>
    </div>
  )
}

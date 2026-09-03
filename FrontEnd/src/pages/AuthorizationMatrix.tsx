import { useEffect, useMemo, useState } from "react"
import { Play, Plus, RefreshCw, Trash2 } from "lucide-react"
import { authzApi, manualApi, scanApi } from "../api/client"

export default function AuthorizationMatrix() {
  const [scans, setScans] = useState<any[]>([])
  const [scanId, setScanId] = useState("")
  const [profiles, setProfiles] = useState<any[]>([])
  const [corpus, setCorpus] = useState<any[]>([])
  const [runs, setRuns] = useState<any[]>([])
  const [selectedProfiles, setSelectedProfiles] = useState<string[]>([])
  const [selectedRequests, setSelectedRequests] = useState<string[]>([])
  const [name, setName] = useState("Admin")
  const [role, setRole] = useState("admin")
  const [headers, setHeaders] = useState('{\n  "Authorization": "Bearer paste-token-here"\n}')
  const [cookies, setCookies] = useState("{\n}")
  const [busy, setBusy] = useState("")
  const [error, setError] = useState("")

  const load = async () => {
    const [nextScans, nextProfiles] = await Promise.all([scanApi.list(), authzApi.profiles()])
    setScans(nextScans)
    setProfiles(nextProfiles)
    const chosen = scanId || nextScans[0]?.id || ""
    if (chosen) setScanId(chosen)
  }

  useEffect(() => { void load().catch(() => undefined) }, [])
  useEffect(() => {
    if (!scanId) return
    void Promise.all([manualApi.corpus(scanId), authzApi.matrixRuns(scanId)]).then(([nextCorpus, nextRuns]) => {
      setCorpus(nextCorpus)
      setRuns(nextRuns)
      setSelectedRequests(nextCorpus.slice(0, 10).map((item) => item.id))
    }).catch(() => undefined)
  }, [scanId])

  const latestRun = runs[0]
  const selectedProfileCount = selectedProfiles.length || profiles.length
  const selectedRequestCount = selectedRequests.length || corpus.length

  const profileOptions = useMemo(() => profiles.map((profile) => ({
    ...profile,
    selected: selectedProfiles.includes(profile.id) || selectedProfiles.length === 0,
  })), [profiles, selectedProfiles])

  const createProfile = async () => {
    setBusy("create")
    setError("")
    try {
      await authzApi.createProfile({
        name,
        role,
        headers: JSON.parse(headers || "{}"),
        cookies: JSON.parse(cookies || "{}"),
      })
      await load()
    } catch (reason: any) {
      setError(reason.message || "Could not create auth profile.")
    } finally {
      setBusy("")
    }
  }

  const runMatrix = async () => {
    setBusy("run")
    setError("")
    try {
      await authzApi.runMatrix({
        scan_id: scanId,
        request_ids: selectedRequests,
        profile_ids: selectedProfiles,
      })
      setRuns(await authzApi.matrixRuns(scanId))
    } catch (reason: any) {
      setError(reason.message || "Could not run authorization matrix.")
    } finally {
      setBusy("")
    }
  }

  const toggle = (value: string, setter: (fn: (items: string[]) => string[]) => void) => {
    setter((items) => items.includes(value) ? items.filter((item) => item !== value) : [...items, value])
  }

  return (
    <div className="p-6 max-w-[1450px] mx-auto space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-ink">Authorization Matrix</h1>
          <p className="text-sm text-ink-3 mt-1">Replay captured requests across auth roles to spot IDOR and broken access control.</p>
        </div>
        <button onClick={() => void load()} className="p-2 rounded border border-border text-ink-2"><RefreshCw size={15} /></button>
      </div>

      {error && <p className="text-xs text-critical">{error}</p>}

      <div className="grid xl:grid-cols-[420px_minmax(0,1fr)] gap-5">
        <section className="space-y-5">
          <div className="bg-card border border-border rounded-lg p-4 space-y-3">
            <h2 className="text-sm font-semibold text-ink">Create auth profile</h2>
            <div className="grid grid-cols-2 gap-2">
              <input value={name} onChange={(event) => setName(event.target.value)} className="bg-canvas border border-border rounded px-3 py-2 text-sm text-ink" />
              <select value={role} onChange={(event) => setRole(event.target.value)} className="bg-canvas border border-border rounded px-3 py-2 text-sm text-ink">
                {["anonymous", "viewer", "user", "admin", "owner"].map((item) => <option key={item}>{item}</option>)}
              </select>
            </div>
            <textarea value={headers} onChange={(event) => setHeaders(event.target.value)} spellCheck={false} className="w-full h-28 bg-canvas border border-border rounded p-2 text-xs font-mono text-ink" />
            <textarea value={cookies} onChange={(event) => setCookies(event.target.value)} spellCheck={false} className="w-full h-20 bg-canvas border border-border rounded p-2 text-xs font-mono text-ink" />
            <button disabled={busy === "create"} onClick={() => void createProfile()} className="inline-flex items-center gap-2 px-4 py-2 bg-accent text-white rounded text-sm disabled:opacity-40">
              <Plus size={15} /> Save profile
            </button>
          </div>

          <div className="bg-card border border-border rounded-lg overflow-hidden">
            <header className="p-3 border-b border-border text-sm font-semibold text-ink">Profiles</header>
            <div className="divide-y divide-border max-h-72 overflow-auto">
              {profileOptions.length ? profileOptions.map((profile) => (
                <label key={profile.id} className="flex items-center gap-3 p-3 hover:bg-elevated">
                  <input type="checkbox" checked={profile.selected} onChange={() => toggle(profile.id, setSelectedProfiles)} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-ink truncate">{profile.name}</p>
                    <p className="text-xs text-ink-3">{profile.role} - {profile.id}</p>
                  </div>
                  <button onClick={(event) => { event.preventDefault(); void authzApi.deleteProfile(profile.id).then(load) }} className="p-1 text-ink-3 hover:text-critical"><Trash2 size={13} /></button>
                </label>
              )) : <p className="p-3 text-sm text-ink-3">No auth profiles yet. Anonymous is used by default.</p>}
            </div>
          </div>
        </section>

        <section className="space-y-5">
          <div className="bg-card border border-border rounded-lg p-4 grid lg:grid-cols-[1fr_auto] gap-3 items-end">
            <label className="text-xs text-ink-3">Scan corpus
              <select value={scanId} onChange={(event) => setScanId(event.target.value)} className="mt-1 w-full bg-canvas border border-border rounded px-3 py-2 text-sm text-ink">
                {scans.map((scan) => <option key={scan.id} value={scan.id}>{scan.id} - {scan.target}</option>)}
              </select>
            </label>
            <button disabled={!scanId || busy === "run"} onClick={() => void runMatrix()} className="inline-flex items-center gap-2 px-4 py-2 bg-accent text-white rounded text-sm disabled:opacity-40">
              <Play size={15} /> Run matrix ({selectedRequestCount} req / {selectedProfileCount} roles)
            </button>
          </div>

          <div className="bg-card border border-border rounded-lg overflow-hidden">
            <header className="p-3 border-b border-border text-sm font-semibold text-ink">Captured requests</header>
            <div className="divide-y divide-border max-h-72 overflow-auto">
              {corpus.length ? corpus.map((item) => (
                <label key={item.id} className="flex items-center gap-3 p-3 hover:bg-elevated">
                  <input type="checkbox" checked={selectedRequests.includes(item.id)} onChange={() => toggle(item.id, setSelectedRequests)} />
                  <span className="text-xs font-mono text-accent">{item.method}</span>
                  <span className="text-xs font-mono text-ink-2 truncate">{item.url}</span>
                </label>
              )) : <p className="p-3 text-sm text-ink-3">No corpus requests yet. Use Repeater or Proxy History first.</p>}
            </div>
          </div>

          <div className="bg-card border border-border rounded-lg overflow-hidden">
            <header className="p-3 border-b border-border text-sm font-semibold text-ink">Latest matrix result</header>
            {latestRun ? (
              <div>
                <div className="grid sm:grid-cols-3 gap-3 p-4">
                  <Metric label="Requests" value={String(latestRun.request_count)} />
                  <Metric label="Profiles" value={String(latestRun.profile_count)} />
                  <Metric label="Findings created" value={String(latestRun.findings_created)} />
                </div>
                <div className="divide-y divide-border max-h-96 overflow-auto">
                  {latestRun.rows?.map((row: any) => (
                    <div key={row.request_id} className="p-4">
                      <div className="flex justify-between gap-3">
                        <p className="text-xs font-mono text-ink-2 truncate">{row.method} {row.url}</p>
                        <span className={row.suspicious ? "text-xs text-critical" : "text-xs text-emerald"}>{row.suspicious ? "Suspicious" : "OK"}</span>
                      </div>
                      <p className="mt-1 text-xs text-ink-3">{row.reason}</p>
                    </div>
                  ))}
                </div>
              </div>
            ) : <p className="p-4 text-sm text-ink-3">No matrix run yet.</p>}
          </div>
        </section>
      </div>
    </div>
  )
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div className="bg-canvas border border-border rounded p-3"><p className="text-xs text-ink-3">{label}</p><p className="mt-1 text-xl text-ink font-semibold">{value}</p></div>
}

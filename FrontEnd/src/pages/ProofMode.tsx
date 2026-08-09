import { useEffect, useState } from "react"
import { Download, Play, Plus, RefreshCw, ShieldCheck } from "lucide-react"
import { evidenceBundleUrl, findingsApi, proofApi, type ApiFinding } from "../api/client"

export default function ProofMode() {
  const [findings, setFindings] = useState<ApiFinding[]>([])
  const [tasks, setTasks] = useState<any[]>([])
  const [findingId, setFindingId] = useState("")
  const [busy, setBusy] = useState("")
  const [error, setError] = useState("")

  const load = async () => {
    const [nextFindings, nextTasks] = await Promise.all([findingsApi.list(), proofApi.list()])
    setFindings(nextFindings)
    setTasks(nextTasks)
    if (!findingId && nextFindings[0]) setFindingId(nextFindings[0].id)
  }

  useEffect(() => { void load().catch(() => undefined) }, [])

  const create = async () => {
    if (!findingId) return
    setBusy("create")
    setError("")
    try {
      await proofApi.create(findingId)
      await load()
    } catch (reason: any) {
      setError(reason.message || "Could not create proof task.")
    } finally {
      setBusy("")
    }
  }

  const run = async (taskId: string) => {
    setBusy(taskId)
    setError("")
    try {
      await proofApi.run(taskId)
      await load()
    } catch (reason: any) {
      setError(reason.message || "Could not run proof task.")
    } finally {
      setBusy("")
    }
  }

  return (
    <div className="p-6 max-w-[1200px] mx-auto space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-ink">Proof Mode</h1>
          <p className="text-sm text-ink-3 mt-1">Create safe validation tasks and attach evidence-ready proof notes to findings.</p>
        </div>
        <button onClick={() => void load()} className="p-2 rounded border border-border text-ink-2"><RefreshCw size={15} /></button>
      </div>

      <section className="bg-card border border-border rounded-lg p-4 flex flex-col md:flex-row gap-3">
        <select value={findingId} onChange={(event) => setFindingId(event.target.value)} className="flex-1 bg-canvas border border-border rounded px-3 py-2 text-sm text-ink">
          {findings.map((finding) => <option key={finding.id} value={finding.id}>{finding.severity} - {finding.title} - {finding.target}</option>)}
        </select>
        <button disabled={!findingId || busy === "create"} onClick={() => void create()} className="inline-flex items-center gap-2 px-4 py-2 bg-accent text-white rounded text-sm disabled:opacity-40">
          <Plus size={15} /> Create task
        </button>
      </section>

      {error && <p className="text-xs text-critical">{error}</p>}

      <section className="bg-card border border-border rounded-lg overflow-hidden">
        <header className="p-3 border-b border-border flex items-center gap-2">
          <ShieldCheck size={15} className="text-accent" />
          <span className="text-sm font-semibold text-ink">Proof tasks</span>
        </header>
        <div className="divide-y divide-border">
          {tasks.length ? tasks.map((task) => (
            <article key={task.id} className="p-4 grid lg:grid-cols-[1fr_120px_120px_150px] gap-3 items-start">
              <div>
                <p className="text-sm text-ink">{task.title}</p>
                <p className="mt-1 text-xs text-ink-3 font-mono">{task.id} - {task.target}</p>
                {task.retest_scan_id && <p className="mt-1 text-xs text-accent font-mono">Retest scan: {task.retest_scan_id}</p>}
                {task.result && <p className="mt-2 text-xs text-ink-2">{task.result}</p>}
              </div>
              <span className="text-xs text-ink-3">{task.status}</span>
              <button disabled={busy === task.id} onClick={() => void run(task.id)} className="inline-flex items-center justify-center gap-2 px-3 py-2 bg-elevated border border-border text-ink rounded text-xs disabled:opacity-40">
                <Play size={13} /> Run
              </button>
              <a href={evidenceBundleUrl(task.finding_id)} className="inline-flex items-center justify-center gap-2 px-3 py-2 bg-elevated border border-border text-ink rounded text-xs">
                <Download size={13} /> Evidence bundle
              </a>
            </article>
          )) : <p className="p-6 text-sm text-ink-3">No proof tasks yet.</p>}
        </div>
      </section>
    </div>
  )
}

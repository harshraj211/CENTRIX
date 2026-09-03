import { useEffect, useMemo, useState } from "react"
import { RefreshCw, RotateCcw } from "lucide-react"
import { findingsApi, integrationsApi, type ApiFinding } from "../api/client"

interface FindingsProps {
  onNavigate: (page: string) => void
  findingsCount: number
  setFindingsCount: (count: number) => void
  initialTab?: string
}

type FindingStatus = "Open" | "In Review" | "Fixed" | "Accepted"

const STATUSES: FindingStatus[] = ["Open", "In Review", "Fixed", "Accepted"]

const isHeaderNoise = (finding: ApiFinding) =>
  finding.category === "Security Headers" ||
  finding.title.toLowerCase().startsWith("missing security header")

export default function Findings({ findingsCount, setFindingsCount }: FindingsProps) {
  const [findings, setFindings] = useState<ApiFinding[]>([])
  const [query, setQuery] = useState("")
  const [severity, setSeverity] = useState("All")
  const [showHeaderNoise, setShowHeaderNoise] = useState(false)
  const [busyId, setBusyId] = useState("")
  const [message, setMessage] = useState("")
  const [error, setError] = useState("")

  useEffect(() => {
    void load()
  }, [])

  const load = async () => {
    try {
      const result = await findingsApi.list()
      setFindings(result)
      setFindingsCount(result.filter((finding) => !isHeaderNoise(finding)).length)
      setError("")
    } catch {
      setError("Could not load findings. Check that the backend is running.")
    }
  }

  const hiddenHeaderNoiseCount = useMemo(
    () => findings.filter(isHeaderNoise).length,
    [findings],
  )

  const filtered = useMemo(
    () => findings.filter((finding) =>
      (showHeaderNoise || !isHeaderNoise(finding)) &&
      (severity === "All" || finding.severity === severity) &&
      `${finding.title} ${finding.target} ${finding.parameter} ${finding.category}`.toLowerCase().includes(query.toLowerCase()),
    ),
    [findings, query, severity, showHeaderNoise],
  )

  const updateStatus = async (findingId: string, status: FindingStatus) => {
    setBusyId(findingId)
    setMessage("")
    try {
      const updated = await findingsApi.updateStatus(findingId, status)
      setFindings((current) => current.map((finding) => finding.id === findingId ? updated : finding))
    } catch (reason: any) {
      setError(reason.message || "Could not update finding.")
    } finally {
      setBusyId("")
    }
  }

  const retest = async (findingId: string) => {
    setBusyId(findingId)
    setMessage("")
    try {
      const result = await findingsApi.retest(findingId)
      setMessage(`Retest queued: ${result.scan_id}`)
      await load()
    } catch (reason: any) {
      setError(reason.message || "Could not queue retest.")
    } finally {
      setBusyId("")
    }
  }

  const pushFinding = async (findingId: string, destination: "local" | "slack" | "github" | "jira") => {
    setBusyId(findingId)
    setMessage("")
    try {
      const result = await integrationsApi.pushFinding(findingId, destination)
      setMessage(`Finding pushed to ${destination}: ${result.status}`)
    } catch (reason: any) {
      setError(reason.message || "Could not push finding.")
    } finally {
      setBusyId("")
    }
  }

  return (
    <div className="p-6 max-w-[1500px] mx-auto space-y-5">
      <div className="flex justify-between items-start gap-4">
        <div>
          <h1 className="text-lg font-semibold text-ink">DAST Findings</h1>
          <p className="text-xs text-ink-3 mt-1">{findingsCount} real DAST findings from authorised scans.</p>
        </div>
        <button onClick={() => void load()} className="p-2 border border-border rounded text-ink" title="Refresh findings">
          <RefreshCw size={15} />
        </button>
      </div>

      <div className="flex gap-3">
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search findings"
          className="flex-1 rounded border border-border bg-card px-3 py-2 text-sm text-ink"
        />
        <select
          value={severity}
          onChange={(event) => setSeverity(event.target.value)}
          className="rounded border border-border bg-card px-3 py-2 text-sm text-ink"
        >
          {["All", "Critical", "High", "Medium", "Low", "Info"].map((value) => <option key={value}>{value}</option>)}
        </select>
        {hiddenHeaderNoiseCount > 0 && (
          <button
            onClick={() => setShowHeaderNoise((value) => !value)}
            className="rounded border border-border bg-card px-3 py-2 text-xs text-ink-2 hover:text-ink"
          >
            {showHeaderNoise ? "Hide" : "Show"} header noise ({hiddenHeaderNoiseCount})
          </button>
        )}
      </div>

      {message && <p className="text-xs text-emerald">{message}</p>}
      {error && <p className="text-xs text-critical">{error}</p>}

      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <div className="grid grid-cols-[95px_minmax(220px,1fr)_minmax(220px,1fr)_120px_120px_130px] gap-3 px-4 py-3 border-b border-border text-[11px] uppercase text-ink-3">
          <span>Severity</span>
          <span>Finding</span>
          <span>Target</span>
          <span>Status</span>
          <span>Retest</span>
          <span>Push</span>
        </div>
        {filtered.length ? (
          filtered.map((finding) => (
            <article key={finding.id} className="grid grid-cols-[95px_minmax(220px,1fr)_minmax(220px,1fr)_120px_120px_130px] gap-3 p-4 border-b border-border last:border-0 text-sm items-start">
              <span className="font-semibold text-ink">{finding.severity}</span>
              <div>
                <p className="font-medium text-ink">{finding.title}</p>
                <p className="text-xs text-ink-3 mt-1">{finding.cwe || "No CWE mapping"} - {finding.parameter || "No parameter"} - {finding.confidence}</p>
              </div>
              <p className="text-xs text-ink-2 break-all">{finding.target}</p>
              <select
                value={finding.status}
                disabled={busyId === finding.id}
                onChange={(event) => void updateStatus(finding.id, event.target.value as FindingStatus)}
                className="bg-canvas border border-border rounded px-2 py-1.5 text-xs text-ink"
              >
                {STATUSES.map((status) => <option key={status}>{status}</option>)}
              </select>
              <button
                disabled={busyId === finding.id}
                onClick={() => void retest(finding.id)}
                className="inline-flex items-center justify-center gap-2 bg-elevated border border-border text-ink rounded px-2 py-1.5 text-xs disabled:opacity-40"
              >
                <RotateCcw size={13} />
                Retest
              </button>
              <select
                disabled={busyId === finding.id}
                defaultValue=""
                onChange={(event) => {
                  const value = event.target.value as "local" | "slack" | "github" | "jira"
                  if (value) void pushFinding(finding.id, value)
                  event.currentTarget.value = ""
                }}
                className="bg-canvas border border-border rounded px-2 py-1.5 text-xs text-ink"
                title="Push finding"
              >
                <option value="">Push...</option>
                <option value="local">Local outbox</option>
                <option value="slack">Slack</option>
                <option value="github">GitHub</option>
                <option value="jira">Jira</option>
              </select>
            </article>
          ))
        ) : (
          <p className="p-6 text-center text-sm text-ink-3">No DAST findings match the current filter.</p>
        )}
      </div>
    </div>
  )
}

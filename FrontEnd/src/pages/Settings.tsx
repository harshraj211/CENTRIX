import { useEffect, useState } from "react"
import { RefreshCw, Search } from "lucide-react"
import { integrationsApi } from "../api/client"

interface SettingsProps {
  onNavigate: (page: string) => void
}

export default function SettingsPage(_props: SettingsProps) {
  const [status, setStatus] = useState<any>(null)
  const [query, setQuery] = useState("")
  const [cves, setCves] = useState<any[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")

  const loadStatus = async () => {
    try {
      setStatus(await integrationsApi.status())
      setError("")
    } catch {
      setError("Could not load integration status.")
    }
  }

  useEffect(() => {
    void loadStatus()
  }, [])

  const search = async () => {
    if (!query.trim()) return
    setBusy(true)
    setError("")
    try {
      const result = await integrationsApi.searchCves(query.trim())
      setCves(result.results)
    } catch (reason: any) {
      setError(reason.message || "CVE lookup failed.")
      setCves([])
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="p-6 max-w-[1100px] mx-auto">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-ink">Settings</h1>
          <p className="text-sm text-ink-3 mt-1">Backend API, safety controls, and scanner integrations.</p>
        </div>
        <button onClick={() => void loadStatus()} className="p-2 text-ink-3 hover:text-ink" title="Refresh integrations">
          <RefreshCw size={16} />
        </button>
      </div>

      {error && <p className="text-xs text-critical mt-3">{error}</p>}

      <div className="mt-5 grid lg:grid-cols-2 gap-5">
        <section className="p-4 bg-card border border-border rounded-lg">
          <h2 className="text-sm font-medium text-ink">Current security controls</h2>
          <ul className="mt-3 text-sm text-ink-3 space-y-1">
            <li>Authorisation confirmation required</li>
            <li>Public targets only</li>
            <li>Scope controls enabled; robots can be overridden for authorised scans</li>
            <li>Persistent local scan storage</li>
          </ul>
        </section>

        <section className="p-4 bg-card border border-border rounded-lg">
          <h2 className="text-sm font-medium text-ink">Wraith compatibility pass</h2>
          <p className="mt-2 text-sm text-ink-3">
            Extra non-SAST Wraith modules run after Centrix probes: IDOR, HPP, GraphQL, mass assignment,
            crypto, component/CMS, JWT, and optional WebSocket/gRPC checks.
          </p>
          <div className="mt-3 grid sm:grid-cols-2 gap-2 text-xs">
            <span className="rounded border border-border bg-canvas px-2 py-1 text-ink-2">Standard: GraphQL + API/CMS checks</span>
            <span className="rounded border border-border bg-canvas px-2 py-1 text-ink-2">Aggressive: WebSocket frame probes</span>
            <span className="rounded border border-border bg-canvas px-2 py-1 text-ink-2">Opt-in: gRPC reflection</span>
            <span className="rounded border border-border bg-canvas px-2 py-1 text-ink-2">SAST intentionally excluded</span>
          </div>
        </section>

        <section className="p-4 bg-card border border-border rounded-lg">
          <h2 className="text-sm font-medium text-ink">Integrations</h2>
          <div className="mt-3 grid sm:grid-cols-2 gap-3">
            <IntegrationTile label="Nuclei" value={status?.nuclei?.available ? "Available" : "Built-in fallback"} />
            <IntegrationTile label="CVE lookup" value={status?.cve_lookup?.available ? "Available" : "Unavailable"} />
            <IntegrationTile label="GitHub" value={status?.github?.configured ? "Configured" : "Token missing"} />
            <IntegrationTile label="Slack" value={status?.slack?.configured ? "Configured" : "Webhook missing"} />
          </div>
        </section>
      </div>

      <section className="mt-5 bg-card border border-border rounded-lg overflow-hidden">
        <header className="p-4 border-b border-border">
          <h2 className="text-sm font-medium text-ink">CVE Lookup</h2>
        </header>
        <div className="p-4">
          <div className="flex gap-2">
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={(event) => { if (event.key === "Enter") void search() }}
              placeholder="Search by product, CVE, or keyword"
              className="flex-1 bg-canvas border border-border rounded px-3 py-2 text-sm text-ink"
            />
            <button
              onClick={() => void search()}
              disabled={busy || !query.trim()}
              className="inline-flex items-center gap-2 px-4 py-2 bg-accent text-white rounded text-sm disabled:opacity-40"
            >
              <Search size={15} />
              {busy ? "Searching..." : "Search"}
            </button>
          </div>

          <div className="mt-4 divide-y divide-border border border-border rounded overflow-hidden">
            {cves.length ? (
              cves.map((cve) => (
                <a key={cve.id} href={cve.url} target="_blank" rel="noreferrer" className="block p-3 hover:bg-elevated">
                  <div className="flex items-center justify-between gap-3">
                    <p className="text-sm font-mono text-accent">{cve.id}</p>
                    <p className="text-xs text-ink-3">{cve.score ? `CVSS ${cve.score}` : "No score"}</p>
                  </div>
                  <p className="mt-2 text-xs text-ink-2 line-clamp-2">{cve.summary || "No summary available."}</p>
                </a>
              ))
            ) : (
              <p className="p-3 text-sm text-ink-3">No CVE results loaded.</p>
            )}
          </div>
        </div>
      </section>
    </div>
  )
}

function IntegrationTile({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-canvas border border-border rounded p-3">
      <p className="text-xs text-ink-3">{label}</p>
      <p className="mt-1 text-sm text-ink">{value}</p>
    </div>
  )
}

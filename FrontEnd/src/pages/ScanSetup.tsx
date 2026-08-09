import { useMemo, useState } from "react"
import { FileJson, Play, Upload, X } from "lucide-react"
import { checkBackendHealth, importApi, scanApi } from "../api/client"

type ImportFormat = "openapi" | "postman" | "har" | "graphql"
type ImportedEndpoint = { method: string; url: string; name?: string; source?: string }

interface ScanSetupProps {
  onNavigate: (page: string) => void
  setScanActive: (active: boolean) => void
  setScanProgress: (progress: number) => void
  onScanStarted?: (scanId: string) => void
}

const EXAMPLE_IMPORTS: Record<ImportFormat, string> = {
  openapi: '{\n  "openapi": "3.0.0",\n  "servers": [{ "url": "https://staging.example.com" }],\n  "paths": { "/api/users": { "get": {}, "post": {} } }\n}',
  postman: '{\n  "item": [{\n    "name": "Users",\n    "request": { "method": "GET", "url": { "raw": "https://staging.example.com/api/users" } }\n  }]\n}',
  har: '{\n  "log": { "entries": [{\n    "request": { "method": "GET", "url": "https://staging.example.com/api/users" }\n  }] }\n}',
  graphql: '{\n  "endpoint": "https://staging.example.com/graphql"\n}',
}

const EXAMPLE_SEQUENCE = '{\n  "name": "API login sequence",\n  "steps": [\n    {\n      "name": "login",\n      "method": "POST",\n      "url": "/login",\n      "json": { "username": "alice", "password": "password" },\n      "extract": { "token": { "jsonpath": "$.token" } },\n      "assertions": [{ "status_code": [200, 201] }]\n    },\n    {\n      "name": "profile",\n      "method": "GET",\n      "url": "/api/profile",\n      "headers": { "Authorization": "Bearer {{token}}" },\n      "assertions": [{ "status_code": 200 }]\n    }\n  ]\n}'

const EXAMPLE_BROWSER_WORKFLOW = '{\n  "name": "Browser login and discovery",\n  "steps": [\n    { "action": "goto", "url": "/login" },\n    { "action": "fill", "selector": "input[name=username]", "value": "admin" },\n    { "action": "fill", "selector": "input[name=password]", "value": "password" },\n    { "action": "click", "selector": "button[type=submit], input[type=submit]" },\n    { "action": "wait", "timeout": 1000 },\n    { "action": "goto", "url": "/vulnerabilities/sqli/" }\n  ]\n}'

export default function ScanSetup({
  onNavigate,
  setScanActive,
  setScanProgress,
  onScanStarted,
}: ScanSetupProps) {
  const [target, setTarget] = useState("")
  const [scope, setScope] = useState("")
  const [safety, setSafety] = useState<"passive" | "standard" | "aggressive">("standard")
  const [authorized, setAuthorized] = useState(false)
  const [busy, setBusy] = useState(false)
  const [importBusy, setImportBusy] = useState(false)
  const [error, setError] = useState("")
  const [importError, setImportError] = useState("")
  const [importFormat, setImportFormat] = useState<ImportFormat>("openapi")
  const [importText, setImportText] = useState(EXAMPLE_IMPORTS.openapi)
  const [importedEndpoints, setImportedEndpoints] = useState<ImportedEndpoint[]>([])
  const [sequenceText, setSequenceText] = useState("")
  const [browserWorkflowText, setBrowserWorkflowText] = useState("")

  const importedUrls = useMemo(
    () => Array.from(new Set(importedEndpoints.map((endpoint) => endpoint.url).filter(Boolean))),
    [importedEndpoints],
  )

  const scopeLines = useMemo(
    () => scope.split("\n").map((value) => value.trim()).filter(Boolean),
    [scope],
  )

  const previewImport = async () => {
    setImportError("")
    setImportBusy(true)
    try {
      const parsed = JSON.parse(importText)
      const result = await importApi.preview(importFormat, parsed, target || undefined)
      setImportedEndpoints(result.endpoints)
    } catch (reason: any) {
      setImportedEndpoints([])
      setImportError(reason.message || "Could not parse this import.")
    } finally {
      setImportBusy(false)
    }
  }

  const clearImport = () => {
    setImportedEndpoints([])
    setImportError("")
  }

  const changeFormat = (nextFormat: ImportFormat) => {
    setImportFormat(nextFormat)
    setImportText(EXAMPLE_IMPORTS[nextFormat])
    setImportedEndpoints([])
    setImportError("")
  }

  const launch = async () => {
    setError("")
    if (!authorized) {
      setError("You must confirm authorisation to scan this target.")
      return
    }
    setBusy(true)
    try {
      if (!(await checkBackendHealth())) {
        throw new Error("Cannot reach the backend at localhost:8000.")
      }
      let sequenceWorkflows: Record<string, any>[] = []
      if (sequenceText.trim()) {
        const parsedSequence = JSON.parse(sequenceText)
        sequenceWorkflows = Array.isArray(parsedSequence)
          ? parsedSequence
          : Array.isArray(parsedSequence.workflows)
            ? parsedSequence.workflows
            : [parsedSequence]
      }
      let browserWorkflows: Record<string, any>[] = []
      if (browserWorkflowText.trim()) {
        const parsedBrowserWorkflow = JSON.parse(browserWorkflowText)
        browserWorkflows = Array.isArray(parsedBrowserWorkflow)
          ? parsedBrowserWorkflow
          : Array.isArray(parsedBrowserWorkflow.workflows)
            ? parsedBrowserWorkflow.workflows
            : [parsedBrowserWorkflow]
      }
      const result = await scanApi.start({
        target,
        scope: scopeLines,
        imported_urls: importedUrls,
        imported_requests: importedEndpoints,
        sequence_workflows: sequenceWorkflows,
        browser_workflows: browserWorkflows,
        authorized,
        safety,
        profile: importedUrls.length ? "api" : "full",
        depth: 3,
        timeout: 30,
        concurrency: 10,
        max_requests: 500,
        respect_robots: false,
      })
      onScanStarted?.(result.scan_id)
      setScanProgress(0)
      setScanActive(true)
      onNavigate("automated-scan")
    } catch (reason: any) {
      setError(reason.message || "Could not start scan.")
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="p-6 max-w-[1180px] mx-auto">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-ink">New DAST Scan</h1>
          <p className="text-sm text-ink-3 mt-1">Only scan systems you own or have permission to test.</p>
        </div>
        <button
          disabled={busy || !target}
          onClick={() => void launch()}
          className="inline-flex items-center gap-2 px-4 py-2 bg-accent text-white rounded text-sm disabled:opacity-40"
        >
          <Play size={15} />
          {busy ? "Starting..." : "Start scan"}
        </button>
      </div>

      <div className="mt-5 grid xl:grid-cols-[minmax(0,1fr)_minmax(420px,0.9fr)] gap-5">
        <section className="bg-card border border-border rounded-lg p-5 space-y-4">
          <label className="block text-sm text-ink">
            Target URL
            <input
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder="https://staging.example.com"
              className="mt-2 w-full border border-border rounded bg-canvas px-3 py-2 text-ink"
            />
          </label>

          <label className="block text-sm text-ink">
            Scope patterns <span className="text-ink-3">(one per line; optional)</span>
            <textarea
              value={scope}
              onChange={(event) => setScope(event.target.value)}
              placeholder="https://staging.example.com/api/*"
              className="mt-2 w-full h-28 border border-border rounded bg-canvas px-3 py-2 text-ink"
            />
          </label>

          <div className="grid sm:grid-cols-2 gap-3">
            <label className="block text-sm text-ink">
              Safety mode
              <select
                value={safety}
                onChange={(event) => setSafety(event.target.value as typeof safety)}
                className="mt-2 w-full border border-border rounded bg-canvas px-3 py-2 text-ink"
              >
                <option value="passive">Passive</option>
                <option value="standard">Standard</option>
                <option value="aggressive">Aggressive</option>
              </select>
            </label>
            <div className="border border-border rounded bg-canvas p-3">
              <p className="text-xs text-ink-3">Imported API endpoints</p>
              <p className="mt-1 text-2xl font-semibold text-ink">{importedUrls.length}</p>
            </div>
          </div>

          <label className="flex gap-2 text-sm text-ink">
            <input
              type="checkbox"
              checked={authorized}
              onChange={(event) => setAuthorized(event.target.checked)}
            />
            I own this target or have explicit authorisation to scan it.
          </label>

          {error && <p className="text-sm text-critical">{error}</p>}
        </section>

        <section className="bg-card border border-border rounded-lg overflow-hidden">
          <header className="p-4 border-b border-border flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <FileJson size={16} className="text-accent" />
              <h2 className="text-sm font-medium text-ink">API Import</h2>
            </div>
            {importedEndpoints.length > 0 && (
              <button onClick={clearImport} className="p-1.5 text-ink-3 hover:text-ink" title="Clear import">
                <X size={15} />
              </button>
            )}
          </header>

          <div className="p-4 space-y-3">
            <div className="grid sm:grid-cols-[150px_1fr] gap-3">
              <select
                value={importFormat}
                onChange={(event) => changeFormat(event.target.value as ImportFormat)}
                className="border border-border rounded bg-canvas px-3 py-2 text-sm text-ink"
              >
                <option value="openapi">OpenAPI</option>
                <option value="postman">Postman</option>
                <option value="har">HAR</option>
                <option value="graphql">GraphQL</option>
              </select>
              <button
                disabled={importBusy || !importText.trim()}
                onClick={() => void previewImport()}
                className="inline-flex items-center justify-center gap-2 px-4 py-2 bg-elevated border border-border text-ink rounded text-sm disabled:opacity-40"
              >
                <Upload size={15} />
                {importBusy ? "Previewing..." : "Preview import"}
              </button>
            </div>

            <textarea
              value={importText}
              onChange={(event) => setImportText(event.target.value)}
              spellCheck={false}
              className="w-full h-56 border border-border rounded bg-canvas px-3 py-2 text-xs font-mono text-ink"
            />

            {importError && <p className="text-xs text-critical">{importError}</p>}

            <div className="border border-border rounded overflow-hidden">
              <div className="px-3 py-2 border-b border-border text-xs text-ink-3">
                Previewed endpoints
              </div>
              {importedEndpoints.length ? (
                <div className="max-h-56 overflow-auto divide-y divide-border">
                  {importedEndpoints.slice(0, 80).map((endpoint, index) => (
                    <div key={`${endpoint.method}-${endpoint.url}-${endpoint.name || ""}-${index}`} className="px-3 py-2 text-xs grid grid-cols-[64px_1fr] gap-2">
                      <span className="font-mono text-accent">{endpoint.method}</span>
                      <span className="min-w-0">
                        {endpoint.name && <span className="block text-ink truncate" title={endpoint.name}>{endpoint.name}</span>}
                        <span className="block font-mono text-ink-2 truncate" title={endpoint.url}>{endpoint.url}</span>
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="p-3 text-sm text-ink-3">No imported endpoints yet.</p>
              )}
            </div>
          </div>
        </section>

        <section className="bg-card border border-border rounded-lg overflow-hidden">
          <header className="p-4 border-b border-border flex items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-medium text-ink">API Sequence Workflow</h2>
              <p className="text-xs text-ink-3 mt-1">Optional Wraith-style setup flow: login, extract tokens, hit stateful API routes before probing.</p>
            </div>
            <button onClick={() => setSequenceText(sequenceText ? "" : EXAMPLE_SEQUENCE)} className="px-3 py-1.5 text-xs bg-elevated border border-border rounded text-ink">
              {sequenceText ? "Clear" : "Load example"}
            </button>
          </header>
          <div className="p-4">
            <textarea
              value={sequenceText}
              onChange={(event) => setSequenceText(event.target.value)}
              placeholder={EXAMPLE_SEQUENCE}
              spellCheck={false}
              className="w-full h-64 border border-border rounded bg-canvas px-3 py-2 text-xs font-mono text-ink"
            />
          </div>
        </section>

        <section className="bg-card border border-border rounded-lg overflow-hidden">
          <header className="p-4 border-b border-border flex items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-medium text-ink">Browser Macro Workflow</h2>
              <p className="text-xs text-ink-3 mt-1">Optional Wraith-style browser path: login, click/fill pages, then scan discovered URLs and forms.</p>
            </div>
            <button onClick={() => setBrowserWorkflowText(browserWorkflowText ? "" : EXAMPLE_BROWSER_WORKFLOW)} className="px-3 py-1.5 text-xs bg-elevated border border-border rounded text-ink">
              {browserWorkflowText ? "Clear" : "Load example"}
            </button>
          </header>
          <div className="p-4">
            <textarea
              value={browserWorkflowText}
              onChange={(event) => setBrowserWorkflowText(event.target.value)}
              placeholder={EXAMPLE_BROWSER_WORKFLOW}
              spellCheck={false}
              className="w-full h-64 border border-border rounded bg-canvas px-3 py-2 text-xs font-mono text-ink"
            />
          </div>
        </section>
      </div>
    </div>
  )
}

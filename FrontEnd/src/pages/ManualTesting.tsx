import { useState, useEffect, useRef } from "react"
import {
  Send,
  Plus,
  Copy,
  Play,
  CheckCircle,
  XCircle,
  Loader2,
  Terminal,
  Sparkles,
  Radio,
  Wifi,
  Globe,
  RefreshCw,
} from "lucide-react"

interface ManualTestingProps {
  onNavigate: (page: string) => void
  repeaterRequest: any
  setRepeaterRequest: (req: any) => void
}

const HISTORY = [
  { id: "REQ-0847", method: "POST", url: "/api/auth/login", status: 401, time: "142 ms", ts: "14:31", body: '{"username": "admin", "password": "123"}' },
  { id: "REQ-0846", method: "GET", url: "/api/users?user_id=1' AND 1=1--", status: 200, time: "89 ms", ts: "14:30", body: "" },
  { id: "REQ-0845", method: "GET", url: "/export?file=../../etc/passwd", status: 200, time: "67 ms", ts: "14:29", body: "" },
  { id: "REQ-0844", method: "DELETE", url: "/api/admin/export", status: 403, time: "204 ms", ts: "14:28", body: "" },
  { id: "REQ-0843", method: "GET", url: "/search?q=<script>alert(1)</script>", status: 200, time: "113 ms", ts: "14:27", body: "" },
  { id: "REQ-0842", method: "POST", url: "/api/profile/update", status: 200, time: "331 ms", ts: "14:25", body: '{"email":"attacker@evil.com"}' },
]

const METHOD_COLORS: Record<string, string> = {
  GET: "text-emerald",
  POST: "text-accent",
  PUT: "text-medium",
  DELETE: "text-critical",
  PATCH: "text-info",
}

const STATUS_COLORS = (s: number) =>
  s < 300 ? "text-emerald" : s < 400 ? "text-medium" : s < 500 ? "text-high" : "text-critical"

export default function ManualTesting({
  repeaterRequest,
  setRepeaterRequest,
}: ManualTestingProps) {
  const [activeTab, setActiveTab] = useState<"repeater" | "intruder" | "playpen" | "collaborator" | "terminal">("repeater")
  const [historyList, setHistoryList] = useState(HISTORY)
  const [selectedHistory, setSelectedHistory] = useState(0)

  // Collaborator State
  const [collaboratorPayload, setCollaboratorPayload] = useState("http://evd-4781.collaborator.vulnguard.net")
  const [collaboratorInteractions, setCollaboratorInteractions] = useState<any[]>([
    {
      id: "OOB-8930",
      time: "14:15:32",
      type: "DNS",
      sourceIp: "8.8.8.8",
      query: "A evd-4781.collaborator.vulnguard.net",
      payload: "http://evd-4781.collaborator.vulnguard.net",
      details: "A DNS lookup request was captured for the collaborator subdomain. This resolves network boundaries to check outbound resolution capability."
    },
    {
      id: "OOB-8931",
      time: "14:15:33",
      type: "HTTP",
      sourceIp: "104.22.3.94",
      query: "GET /api/ping",
      payload: "http://evd-4781.collaborator.vulnguard.net",
      details: "An HTTP payload callback was recorded. The server attempted to fetch the path /api/ping from our collaborator endpoint. Confirming full SSRF impact.",
      requestHeaders: "Host: evd-4781.collaborator.vulnguard.net\nUser-Agent: Mozilla/5.0 (Java SSRF client)\nConnection: keep-alive\nAccept: */*"
    }
  ])
  const [selectedOobId, setSelectedOobId] = useState<string>("OOB-8931")
  const [polling, setPolling] = useState(false)

  const handleGeneratePayload = () => {
    const randomSub = `evd-${Math.floor(1000 + Math.random() * 9000)}`
    setCollaboratorPayload(`http://${randomSub}.collaborator.vulnguard.net`)
    setCollaboratorInteractions([])
  }

  const handlePoll = () => {
    setPolling(true)
    setTimeout(() => {
      setPolling(false)
    }, 1000)
  }

  // Repeater State
  const [method, setMethod] = useState("POST")
  const [url, setUrl] = useState("/api/auth/login")
  const [reqHeaders, setReqHeaders] = useState("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\nContent-Type: application/json")
  const [reqBody, setReqBody] = useState('{"username": "admin", "password": "123"}')
  
  const [respStatus, setRespStatus] = useState(401)
  const [respTime, setRespTime] = useState("142 ms")
  const [respBody, setRespBody] = useState('{\n  "error": "Unauthorized",\n  "message": "Invalid password. Access Denied."\n}')
  const [respHeaders, setRespHeaders] = useState("HTTP/1.1 401 Unauthorized\nContent-Type: application/json\nConnection: close")
  const [repeaterLoading, setRepeaterLoading] = useState(false)

  const [reqSubTab, setReqSubTab] = useState<"headers" | "body">("body")
  const [respSubTab, setRespSubTab] = useState<"body" | "headers">("body")

  // Intruder State
  const [targetUrl, setTargetUrl] = useState("https://api.acmecorp.com")
  const [intruderUrl, setIntruderUrl] = useState("/api/users?user_id=§1§")
  const [payloads, setPayloads] = useState("1' OR 1=1--\n' UNION SELECT NULL,username,password FROM users--\n../../etc/passwd\n<script>alert(1)</script>\nstandard_user")
  const [intruderRunning, setIntruderRunning] = useState(false)
  const [intruderResults, setIntruderResults] = useState<any[]>([])
  const [intruderProgress, setIntruderProgress] = useState(0)

  // Playpen State
  const [playpenUrl, setPlaypenUrl] = useState("/api/search")
  const [paramKey, setParamKey] = useState("q")
  const [bypassMode, setBypassMode] = useState<"none" | "hex" | "unicode" | "double-url">("none")
  const [pocCodeType, setPocCodeType] = useState<"curl" | "python" | "go">("curl")
  const [playpenLogs, setPlaypenLogs] = useState<string[]>([])
  const [playpenRunning, setPlaypenRunning] = useState(false)

  // Prepopulate Repeater from Evidence
  useEffect(() => {
    if (repeaterRequest) {
      setMethod(repeaterRequest.method || "GET")
      setUrl(repeaterRequest.url || "")
      setReqBody(repeaterRequest.body || "")
      setReqHeaders(`Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\nContent-Type: application/json`)
      
      // Auto execute response
      setRespStatus(repeaterRequest.status || 200)
      setRespBody(repeaterRequest.response || "")
      setRespHeaders(`HTTP/1.1 ${repeaterRequest.status || 200} OK\nContent-Type: text/plain`)
      setRespTime("60 ms")

      // Clear the forwarding trigger
      setRepeaterRequest(null)
      setActiveTab("repeater")
    }
  }, [repeaterRequest, setRepeaterRequest])

  // Sync Repeater values when selected history item changes
  const handleSelectHistory = (idx: number) => {
    setSelectedHistory(idx)
    const item = historyList[idx]
    setMethod(item.method)
    setUrl(item.url)
    setReqBody(item.body)
    setRespStatus(item.status)
    setRespTime(item.time)
    
    // Set simulated responses
    if (item.url.includes("etc/passwd")) {
      setRespBody("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin")
      setRespHeaders("HTTP/1.1 200 OK\nContent-Type: text/plain\nServer: Nginx")
    } else if (item.url.includes("1' AND 1=1--")) {
      setRespBody('{\n  "status": "success",\n  "data": {\n    "id": 1,\n    "username": "admin",\n    "email": "admin@acmecorp.com"\n  }\n}')
      setRespHeaders("HTTP/1.1 200 OK\nContent-Type: application/json")
    } else if (item.url.includes("alert")) {
      setRespBody("<p>No search results for <script>alert(1)</script></p>")
      setRespHeaders("HTTP/1.1 200 OK\nContent-Type: text/html")
    } else {
      setRespBody('{\n  "success": true,\n  "message": "Action completed successfully"\n}')
      setRespHeaders("HTTP/1.1 200 OK\nContent-Type: application/json")
    }
  }

  // Repeater Send Simulation
  const handleSendRepeater = () => {
    setRepeaterLoading(true)
    setTimeout(() => {
      setRepeaterLoading(false)

      const isCollaborator = url.includes("collaborator.vulnguard.net") || reqBody.includes("collaborator.vulnguard.net") || reqHeaders.includes("collaborator.vulnguard.net")

      // Custom response mappings
      if (isCollaborator) {
        setRespStatus(200)
        setRespTime("189 ms")
        setRespBody('{\n  "status": "success",\n  "description": "Collaborator payload registered. Check Out-of-Band console for asynchronous callbacks."\n}')
        setRespHeaders("HTTP/1.1 200 OK\nContent-Type: application/json\nConnection: keep-alive")
        
        setTimeout(() => {
          const timestamp = new Date().toLocaleTimeString()
          const cleanHost = collaboratorPayload.replace("http://", "")
          const newOobHttp = {
            id: `OOB-${Math.floor(1000 + Math.random() * 9000)}`,
            time: timestamp,
            type: "HTTP",
            sourceIp: "104.22.3.94",
            query: "GET /metrics HTTP/1.1",
            payload: collaboratorPayload,
            details: "Asynchronous HTTP hit captured. The server evaluated the request payload and invoked an out-of-band GET callback to resolve resource metrics.",
            requestHeaders: `Host: ${cleanHost}\nUser-Agent: VulnGuard-SSRF-Scanner/1.0\nAccept: application/json\nConnection: close`
          }
          const newOobDns = {
            id: `OOB-${Math.floor(1000 + Math.random() * 9000)}`,
            time: timestamp,
            type: "DNS",
            sourceIp: "172.18.94.12",
            query: `A ${cleanHost}`,
            payload: collaboratorPayload,
            details: "DNS Query captured. The target resolved the DNS address of the payload host via its primary nameservers before initiating network transport."
          }
          setCollaboratorInteractions(prev => [newOobHttp, newOobDns, ...prev])
        }, 1200)
      } else if (url.includes("etc/passwd")) {
        setRespStatus(200)
        setRespTime("45 ms")
        setRespBody("root:x:0:0:root:/root:/bin/bash\nadmin:x:1001:1001::/home/admin:/bin/bash")
        setRespHeaders("HTTP/1.1 200 OK\nContent-Type: text/plain\nContent-Length: 104")
      } else if (url.includes("1' OR 1=1--") || url.includes("AND 1=1")) {
        setRespStatus(200)
        setRespTime("62 ms")
        setRespBody('{\n  "authenticated": true,\n  "user": "admin",\n  "bypass": "SQLi Injection Successful"\n}')
        setRespHeaders("HTTP/1.1 200 OK\nContent-Type: application/json")
      } else if (url.includes("script")) {
        setRespStatus(200)
        setRespTime("81 ms")
        setRespBody("<html>\n  <body>\n    <p>Output: <script>alert(1)</script></p>\n  </body>\n</html>")
        setRespHeaders("HTTP/1.1 200 OK\nContent-Type: text/html")
      } else if (url.includes("admin")) {
        setRespStatus(403)
        setRespTime("112 ms")
        setRespBody('{\n  "error": "Forbidden",\n  "message": "Access denied to admin path."\n}')
        setRespHeaders("HTTP/1.1 403 Forbidden\nContent-Type: application/json")
      } else {
        setRespStatus(200)
        setRespTime("54 ms")
        setRespBody('{\n  "status": "online",\n  "ping": "pong"\n}')
        setRespHeaders("HTTP/1.1 200 OK\nContent-Type: application/json")
      }

      // Add to history list dynamically
      const newReq = {
        id: `REQ-0${Math.floor(800 + Math.random() * 200)}`,
        method,
        url,
        status: url.includes("admin") ? 403 : 200,
        time: isCollaborator ? "189 ms" : "54 ms",
        ts: "Just now",
        body: reqBody,
      }
      setHistoryList([newReq, ...historyList])
      setSelectedHistory(0)
    }, 800)
  }

  // Intruder Brute Force Fuzzer Simulation
  const handleStartIntruder = () => {
    if (intruderRunning) return
    setIntruderRunning(true)
    setIntruderResults([])
    setIntruderProgress(0)

    const payloadLines = payloads.split("\n").filter((l) => l.trim() !== "")
    let index = 0

    const interval = setInterval(() => {
      if (index >= payloadLines.length) {
        clearInterval(interval)
        setIntruderRunning(false)
        return
      }

      const p = payloadLines[index]
      let status = 404
      let len = "120 B"
      let match = false
      let details = "Negative match"

      if (p.includes("OR 1=1") || p.includes("UNION SELECT")) {
        status = 200
        len = "4.2 KB"
        match = true
        details = "SQL Injection bypass confirmed"
      } else if (p.includes("etc/passwd")) {
        status = 200
        len = "1.8 KB"
        match = true
        details = "Path Traversal payload exposed data"
      } else if (p.includes("script")) {
        status = 200
        len = "850 B"
        match = true
        details = "XSS Reflection detected"
      } else {
        status = 404
        len = "68 B"
        match = false
        details = "Resource not found"
      }

      const newResult = {
        pos: index + 1,
        payload: p,
        status,
        length: len,
        match,
        details,
      }

      setIntruderResults((prev) => [...prev, newResult])
      setIntruderProgress(Math.round(((index + 1) / payloadLines.length) * 100))
      index++
    }, 600)
  }

  // DAST Playpen Exploitation Fuzzing Simulation
  const handlePlaypenRun = () => {
    if (playpenRunning) return
    setPlaypenRunning(true)
    setPlaypenLogs([])

    const appendLog = (msg: string, delay: number) => {
      setTimeout(() => {
        setPlaypenLogs((prev) => [...prev, msg])
      }, delay)
    }

    const payload = bypassMode === "hex" 
      ? "%2527%2520OR%25201%253D1" 
      : bypassMode === "unicode" 
        ? "%u0027%20OR%201%3D1" 
        : "admin' OR 1=1--"

    appendLog(`[INFO] Fuzzing endpoint ${playpenUrl} on parameter '${paramKey}'`, 200)
    appendLog(`[INFO] Bypass encoding strategy: ${bypassMode.toUpperCase()}`, 600)
    appendLog(`[SEND] Injecting payload: ${payload}`, 1100)
    appendLog(`[INFO] Sending HTTP requests fuzz parameters...`, 1600)
    
    if (bypassMode !== "none") {
      appendLog(`[SUCCESS] Web application firewall (WAF) rule bypassed successfully!`, 2200)
      appendLog(`[CRITICAL] Server response contains SQL parsing exception: SELECT * FROM admin`, 2800)
      appendLog(`[SUCCESS] Exploit simulation confirmed: Target is vulnerable!`, 3400)
    } else {
      appendLog(`[WARN] Request blocked by Cloudflare WAF (HTTP 403 Forbidden)`, 2200)
      appendLog(`[ALERT] Payload blocked, try changing bypass encoding strategy.`, 2800)
    }

    setTimeout(() => setPlaypenRunning(false), 3500)
  }

  // Generated code templates for Playpen
  const pocPayload = bypassMode === "hex" 
    ? "%2527%2520OR%25201%253D1" 
    : "admin' OR 1=1--"
  
  const curlCode = `curl -X POST "${targetUrl}${playpenUrl}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"${paramKey}": "${pocPayload}"}'`
  
  const pythonCode = `import requests\n\nurl = "${targetUrl}${playpenUrl}"\nheaders = {"Content-Type": "application/json"}\ndata = {"${paramKey}": "${pocPayload}"}\n\nresponse = requests.post(url, json=data, headers=headers)\nprint(f"Status Code: {response.status_code}")\nprint(response.text)`
  
  const goCode = `package main\n\nimport (\n\t"bytes"\n\t"fmt"\n\t"net/http"\n)\n\nfunc main() {\n\turl := "${targetUrl}${playpenUrl}"\n\tvar jsonStr = []byte(\`{"${paramKey}": "${pocPayload}"}\`)\n\treq, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))\n\treq.Header.Set("Content-Type", "application/json")\n\tclient := &http.Client{}\n\tresp, _ := client.Do(req)\n\tdefer resp.Body.Close()\n\tfmt.Println("Response Status:", resp.Status)\n}`

  return (
    <div className="flex flex-col h-full overflow-hidden bg-canvas">
      {/* Sub-tab navigation */}
      <div className="flex border-b border-border bg-panel px-4 shrink-0 justify-between items-center">
        <div className="flex">
          <button
            onClick={() => setActiveTab("repeater")}
            className={`px-4 py-2.5 text-xs font-semibold border-b-2 -mb-px transition-colors ${
              activeTab === "repeater" ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink-2"
            }`}
          >
            HTTP Repeater
          </button>
          <button
            onClick={() => setActiveTab("intruder")}
            className={`px-4 py-2.5 text-xs font-semibold border-b-2 -mb-px transition-colors ${
              activeTab === "intruder" ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink-2"
            }`}
          >
            Intruder Fuzzer
          </button>
          <button
            onClick={() => setActiveTab("playpen")}
            className={`px-4 py-2.5 text-xs font-semibold border-b-2 -mb-px transition-colors ${
              activeTab === "playpen" ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink-2"
            }`}
          >
            DAST Payload Playpen
          </button>
          <button
            onClick={() => setActiveTab("collaborator")}
            className={`px-4 py-2.5 text-xs font-semibold border-b-2 -mb-px transition-colors flex items-center gap-1.5 ${
              activeTab === "collaborator" ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink-2"
            }`}
          >
            <Radio size={12} className={activeTab === "collaborator" ? "text-accent animate-pulse" : ""} />
            OOB Collaborator
          </button>
          <button
            onClick={() => setActiveTab("terminal")}
            className={`px-4 py-2.5 text-xs font-semibold border-b-2 -mb-px transition-colors flex items-center gap-1.5 ${
              activeTab === "terminal" ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink-2"
            }`}
          >
            <Terminal size={12} className={activeTab === "terminal" ? "text-accent" : ""} />
            Security CLI
          </button>
        </div>
        <div className="flex items-center gap-1.5 text-ink-3 text-[10px] font-mono">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald" />
          Workbench Connected
        </div>
      </div>

      <div className="flex-1 min-h-0">
        {/* ────────────────────────────────────────────────────────
            TAB: HTTP REPEATER
            ──────────────────────────────────────────────────────── */}
        {activeTab === "repeater" && (
          <div className="flex h-full min-h-0 overflow-hidden">
            {/* Request history sidebar */}
            <div className="w-[260px] shrink-0 border-r border-border flex flex-col bg-panel/10">
              <div className="px-3 py-2.5 border-b border-border flex items-center justify-between">
                <span className="text-ink-2 text-xs font-semibold">Request History</span>
                <button
                  onClick={() => {
                    const freshReq = {
                      id: `REQ-0${Math.floor(800 + Math.random() * 200)}`,
                      method: "GET",
                      url: "/api/health",
                      status: 200,
                      time: "12 ms",
                      ts: "Just now",
                      body: "",
                    }
                    setHistoryList([freshReq, ...historyList])
                    setSelectedHistory(0)
                  }}
                  className="text-ink-3 hover:text-ink transition-colors"
                >
                  <Plus size={13} />
                </button>
              </div>
              <div className="flex-1 overflow-y-auto">
                {historyList.map((r, i) => (
                  <div
                    key={r.id}
                    onClick={() => handleSelectHistory(i)}
                    className={`px-3 py-2.5 cursor-pointer border-b border-border transition-colors ${
                      i === selectedHistory
                        ? "bg-accent/8 border-l-2 border-l-accent"
                        : "hover:bg-elevated/40 border-l-2 border-l-transparent"
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className={`text-[10px] font-semibold font-mono w-12 shrink-0 ${METHOD_COLORS[r.method] ?? "text-ink-2"}`}>
                        {r.method}
                      </span>
                      <span className={`text-[10px] font-mono font-medium ${STATUS_COLORS(r.status)}`}>
                        {r.status}
                      </span>
                      <span className="text-ink-3 text-[10px] font-mono ml-auto">{r.ts}</span>
                    </div>
                    <p className="text-ink-2 text-xs font-mono truncate">{r.url}</p>
                    <p className="text-ink-3 text-[10px] font-mono mt-0.5">{r.time}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Split Panel: Request (Left), Response (Right) */}
            <div className="flex-1 flex divide-x divide-border overflow-hidden">
              {/* Request Panel */}
              <div className="flex-1 flex flex-col overflow-hidden bg-card">
                <div className="px-4 py-2 border-b border-border flex items-center gap-2 shrink-0 bg-panel/30">
                  <select
                    value={method}
                    onChange={(e) => setMethod(e.target.value)}
                    className="bg-canvas border border-border rounded px-2 py-1 text-ink text-xs font-mono focus:border-accent"
                  >
                    {["GET", "POST", "PUT", "DELETE", "PATCH"].map((m) => (
                      <option key={m} value={m}>{m}</option>
                    ))}
                  </select>
                  <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    className="flex-1 bg-canvas border border-border rounded px-3 py-1 text-ink text-xs font-mono focus:border-accent"
                  />
                  <button
                    onClick={handleSendRepeater}
                    disabled={repeaterLoading}
                    className="flex items-center gap-1 px-3 py-1 bg-accent text-white rounded text-xs font-semibold hover:bg-accent/90 transition-colors shadow shadow-accent/20 disabled:opacity-50"
                  >
                    {repeaterLoading ? <Loader2 size={11} className="animate-spin" /> : <Send size={11} />}
                    <span>Send</span>
                  </button>
                </div>

                <div className="flex border-b border-border shrink-0 bg-[#0f1420]">
                  {["headers", "body"].map((t) => (
                    <button
                      key={t}
                      onClick={() => setReqSubTab(t as any)}
                      className={`px-4 py-2 text-xs font-medium capitalize border-b-2 -mb-px transition-colors ${
                        reqSubTab === t ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink-2"
                      }`}
                    >
                      {t}
                    </button>
                  ))}
                </div>

                <div className="flex-1 p-4 overflow-auto">
                  {reqSubTab === "headers" ? (
                    <textarea
                      value={reqHeaders}
                      onChange={(e) => setReqHeaders(e.target.value)}
                      className="w-full h-full bg-transparent text-ink-2 text-xs font-mono resize-none focus:outline-none leading-relaxed"
                    />
                  ) : (
                    <textarea
                      value={reqBody}
                      onChange={(e) => setReqBody(e.target.value)}
                      className="w-full h-full bg-transparent text-ink-2 text-xs font-mono resize-none focus:outline-none leading-relaxed"
                    />
                  )}
                </div>
              </div>

              {/* Response Panel */}
              <div className="flex-1 flex flex-col overflow-hidden bg-card">
                <div className="px-4 py-2 border-b border-border flex items-center justify-between shrink-0 bg-panel/30 h-10">
                  <div className="flex items-center gap-3">
                    <span className="text-ink-3 text-xs font-semibold">Response Status:</span>
                    <span className={`text-xs font-mono font-bold ${STATUS_COLORS(respStatus)}`}>
                      {respStatus}
                    </span>
                    <span className="text-ink-3 text-[10px] font-mono">{respTime}</span>
                  </div>
                </div>

                <div className="flex border-b border-border shrink-0 bg-[#0f1420]">
                  {["body", "headers"].map((t) => (
                    <button
                      key={t}
                      onClick={() => setRespSubTab(t as any)}
                      className={`px-4 py-2 text-xs font-medium capitalize border-b-2 -mb-px transition-colors ${
                        respSubTab === t ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink-2"
                      }`}
                    >
                      {t}
                    </button>
                  ))}
                </div>

                <div className="flex-1 p-4 overflow-auto bg-[#090c15]">
                  {repeaterLoading ? (
                    <div className="h-full flex flex-col items-center justify-center text-ink-3 text-xs font-mono gap-2">
                      <Loader2 size={16} className="text-accent animate-spin" />
                      <span>Transmitting HTTP frames...</span>
                    </div>
                  ) : respSubTab === "headers" ? (
                    <pre className="text-ink-2 text-xs font-mono whitespace-pre-wrap leading-relaxed">
                      {respHeaders}
                    </pre>
                  ) : (
                    <pre className="text-emerald text-xs font-mono whitespace-pre-wrap leading-relaxed select-all">
                      {respBody}
                    </pre>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ────────────────────────────────────────────────────────
            TAB: INTRUDER FUZZER
            ──────────────────────────────────────────────────────── */}
        {activeTab === "intruder" && (
          <div className="flex h-full min-h-0 overflow-hidden divide-x divide-border">
            {/* Left sidebar: payload configuration */}
            <div className="w-[320px] shrink-0 p-5 space-y-4 overflow-y-auto bg-panel/10">
              <p className="text-ink text-sm font-semibold">Intruder Fuzz Engine</p>
              
              <div className="space-y-1.5">
                <label className="text-ink-2 text-[11px] font-medium uppercase font-mono">Target Host</label>
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  className="w-full bg-canvas border border-border rounded px-3 py-1.5 text-ink text-xs font-mono focus:border-accent"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-ink-2 text-[11px] font-medium uppercase font-mono">Payload Position</label>
                <input
                  type="text"
                  value={intruderUrl}
                  onChange={(e) => setIntruderUrl(e.target.value)}
                  className="w-full bg-canvas border border-border rounded px-3 py-1.5 text-ink text-xs font-mono focus:border-accent"
                />
                <span className="text-ink-3 text-[10px] block leading-normal">
                  Define payload index using § markers (e.g. §1§).
                </span>
              </div>

              <div className="space-y-1.5">
                <div className="flex justify-between items-center">
                  <label className="text-ink-2 text-[11px] font-medium uppercase font-mono">Payload List</label>
                  <span className="text-ink-3 text-[9px] font-mono">One item per line</span>
                </div>
                <textarea
                  rows={6}
                  value={payloads}
                  onChange={(e) => setPayloads(e.target.value)}
                  className="w-full bg-canvas border border-border rounded px-3 py-2 text-ink text-xs font-mono resize-none focus:border-accent"
                />
              </div>

              <button
                onClick={handleStartIntruder}
                disabled={intruderRunning}
                className="w-full flex items-center justify-center gap-2 py-2 bg-accent text-white rounded text-xs font-semibold hover:bg-accent/90 shadow shadow-accent/20 transition-colors disabled:opacity-50"
              >
                {intruderRunning ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} fill="currentColor" />}
                <span>Start Fuzzing Attack</span>
              </button>

              {intruderRunning && (
                <div className="space-y-1.5">
                  <div className="flex justify-between text-[10px] font-mono text-ink-3">
                    <span>Attack progress</span>
                    <span>{intruderProgress}%</span>
                  </div>
                  <div className="h-1 bg-elevated rounded-full overflow-hidden">
                    <div className="h-full bg-accent rounded-full" style={{ width: `${intruderProgress}%` }} />
                  </div>
                </div>
              )}
            </div>

            {/* Results Grid */}
            <div className="flex-1 flex flex-col bg-card overflow-hidden">
              <div className="px-5 py-3 border-b border-border bg-panel/30 flex items-center justify-between shrink-0">
                <span className="text-ink text-sm font-semibold">Fuzz Attack Results</span>
                <span className="text-ink-3 text-xs font-mono">{intruderResults.length} requests parsed</span>
              </div>

              <div className="flex-1 overflow-auto">
                <table className="w-full border-collapse">
                  <thead className="sticky top-0 bg-[#0c1018] border-b border-border text-[10px] font-semibold text-ink-3 uppercase font-mono">
                    <tr>
                      <th className="px-4 py-2.5 text-left w-12">Pos</th>
                      <th className="px-4 py-2.5 text-left">Payload Value</th>
                      <th className="px-4 py-2.5 text-left w-20">HTTP Status</th>
                      <th className="px-4 py-2.5 text-left w-24">Response Len</th>
                      <th className="px-4 py-2.5 text-left">Fuzz Match Alert</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {intruderResults.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="px-4 py-12 text-center text-ink-3 text-xs font-mono italic">
                          Click "Start Fuzzing Attack" on the sidebar to initiate request generation.
                        </td>
                      </tr>
                    ) : (
                      intruderResults.map((res) => (
                        <tr
                          key={res.pos}
                          className={`text-xs hover:bg-elevated/20 transition-colors font-mono ${
                            res.match ? "bg-critical/5 text-critical" : "text-ink-2"
                          }`}
                        >
                          <td className="px-4 py-3">{res.pos}</td>
                          <td className="px-4 py-3 font-semibold">{res.payload}</td>
                          <td className={`px-4 py-3 font-bold ${STATUS_COLORS(res.status)}`}>{res.status}</td>
                          <td className="px-4 py-3">{res.length}</td>
                          <td className="px-4 py-3 font-sans">
                            <div className="flex items-center gap-1.5">
                              {res.match ? (
                                <>
                                  <XCircle size={12} className="text-critical shrink-0 animate-pulse" />
                                  <span className="font-semibold">{res.details}</span>
                                </>
                              ) : (
                                <>
                                  <CheckCircle size={12} className="text-emerald shrink-0" />
                                  <span className="text-ink-3">{res.details}</span>
                                </>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ────────────────────────────────────────────────────────
            TAB: DAST PAYLOAD PLAYPEN
            ──────────────────────────────────────────────────────── */}
        {activeTab === "playpen" && (
          <div className="flex h-full min-h-0 overflow-hidden divide-x divide-border">
            {/* Left form config (1/2 width) */}
            <div className="flex-1 p-5 space-y-4 overflow-y-auto bg-card">
              <div className="flex items-center gap-2 mb-2">
                <Sparkles size={14} className="text-accent" />
                <p className="text-ink text-sm font-semibold">Active Exploitation Sandbox</p>
              </div>

              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <label className="text-ink-2 text-xs font-semibold">Target Endpoint</label>
                    <input
                      type="text"
                      value={playpenUrl}
                      onChange={(e) => setPlaypenUrl(e.target.value)}
                      className="w-full bg-canvas border border-border rounded px-3 py-1.5 text-ink text-xs font-mono focus:border-accent"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-ink-2 text-xs font-semibold">Inject Parameter Key</label>
                    <input
                      type="text"
                      value={paramKey}
                      onChange={(e) => setParamKey(e.target.value)}
                      className="w-full bg-canvas border border-border rounded px-3 py-1.5 text-ink text-xs font-mono focus:border-accent"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <label className="text-ink-2 text-xs font-semibold block">WAF Evasion Strategy</label>
                  <div className="grid grid-cols-4 gap-2">
                    {(["none", "hex", "unicode", "double-url"] as const).map((mode) => (
                      <button
                        key={mode}
                        onClick={() => setBypassMode(mode)}
                        className={`py-2 rounded-lg border text-xs font-semibold uppercase transition-all ${
                          bypassMode === mode
                            ? "border-accent bg-accent/5 text-accent shadow-sm"
                            : "border-border bg-canvas/30 text-ink-3 hover:border-border-hi"
                        }`}
                      >
                        {mode}
                      </button>
                    ))}
                  </div>
                </div>

                <button
                  onClick={handlePlaypenRun}
                  disabled={playpenRunning}
                  className="w-full flex items-center justify-center gap-2 py-2.5 bg-accent text-white rounded text-xs font-semibold hover:bg-accent/90 shadow shadow-accent/20 transition-all disabled:opacity-50"
                >
                  {playpenRunning ? <Loader2 size={13} className="animate-spin" /> : <Terminal size={13} />}
                  <span>Execute Fuzz Payload</span>
                </button>
              </div>
            </div>

            {/* Right log and PoC console (1/2 width) */}
            <div className="flex-1 flex flex-col overflow-hidden bg-canvas">
              {/* Exploitation logs */}
              <div className="flex-1 p-5 flex flex-col min-h-0 bg-[#07090f]">
                <div className="flex items-center justify-between pb-2 shrink-0">
                  <span className="text-ink-2 text-xs font-semibold">Exploitation Log</span>
                  <span className="text-[10px] font-mono text-ink-3">sandbox-terminal.sh</span>
                </div>
                <div className="flex-1 bg-black/40 border border-border/80 rounded-lg p-3 font-mono text-[11px] overflow-y-auto space-y-1.5 leading-relaxed">
                  {playpenLogs.length === 0 ? (
                    <span className="text-ink-3 italic">Waiting for active payload injection...</span>
                  ) : (
                    playpenLogs.map((log, idx) => {
                      let colorClass = "text-[#a9b1d6]"
                      if (log.startsWith("[SUCCESS]")) colorClass = "text-emerald font-semibold"
                      else if (log.startsWith("[CRITICAL]")) colorClass = "text-critical font-semibold"
                      else if (log.startsWith("[ALERT]")) colorClass = "text-high font-semibold animate-pulse"
                      else if (log.startsWith("[WARN]")) colorClass = "text-medium"
                      else if (log.startsWith("[SEND]")) colorClass = "text-accent"
                      return (
                        <div key={idx} className={colorClass}>
                          {log}
                        </div>
                      )
                    })
                  )}
                </div>
              </div>

              {/* Generated PoC */}
              <div className="h-[200px] border-t border-border p-5 flex flex-col min-h-0 bg-card">
                <div className="flex items-center justify-between pb-2 shrink-0">
                  <span className="text-ink-2 text-xs font-semibold">Generated Proof of Concept (PoC)</span>
                  <div className="flex bg-canvas border border-border rounded p-0.5">
                    {(["curl", "python", "go"] as const).map((t) => (
                      <button
                        key={t}
                        onClick={() => setPocCodeType(t)}
                        className={`px-2 py-0.5 rounded text-[9px] uppercase font-mono font-medium transition-colors ${
                          pocCodeType === t ? "bg-accent text-white" : "text-ink-3 hover:text-ink-2"
                        }`}
                      >
                        {t}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="flex-1 bg-[#090c14] border border-border/60 rounded p-3 font-mono text-[11px] overflow-auto leading-relaxed text-indigo-200 select-all whitespace-pre">
                  {pocCodeType === "curl" && curlCode}
                  {pocCodeType === "python" && pythonCode}
                  {pocCodeType === "go" && goCode}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ────────────────────────────────────────────────────────
            TAB: OUT-OF-BAND COLLABORATOR CLIENT
            ──────────────────────────────────────────────────────── */}
        {activeTab === "collaborator" && (
          <div className="flex h-full min-h-0 overflow-hidden divide-x divide-border">
            {/* Left side: list of interactions (2/3 width) */}
            <div className="flex-1 flex flex-col bg-canvas overflow-hidden">
              {/* Toolbar */}
              <div className="px-5 py-3 border-b border-border bg-[#0b0e16] flex items-center justify-between shrink-0">
                <div className="flex items-center gap-3">
                  <span className="text-ink text-xs font-semibold">Collaborator Payload</span>
                  <div className="flex items-center gap-2 bg-canvas border border-border rounded px-2.5 py-1">
                    <span className="text-accent text-[11px] font-mono select-all">{collaboratorPayload}</span>
                    <button
                      onClick={() => navigator.clipboard.writeText(collaboratorPayload)}
                      className="text-ink-3 hover:text-ink transition-colors p-0.5"
                      title="Copy Payload URL"
                    >
                      <Copy size={11} />
                    </button>
                  </div>
                  <button
                    onClick={handleGeneratePayload}
                    className="px-2.5 py-1 bg-elevated hover:bg-elevated/80 border border-border rounded text-ink text-[10px] font-semibold transition-colors"
                  >
                    Regenerate
                  </button>
                </div>
                
                <div className="flex items-center gap-3">
                  <span className="flex items-center gap-1.5 text-[10px] text-emerald font-semibold font-mono">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald animate-pulse" />
                    LISTENING
                  </span>
                  <button
                    onClick={handlePoll}
                    disabled={polling}
                    className="flex items-center gap-1.5 px-3 py-1 bg-accent text-white rounded text-[10px] font-semibold hover:bg-accent/90 transition-colors shadow shadow-accent/20"
                  >
                    {polling ? <Loader2 size={10} className="animate-spin" /> : <RefreshCw size={10} />}
                    <span>Poll Payload</span>
                  </button>
                </div>
              </div>

              {/* Interactions Table */}
              <div className="flex-1 overflow-auto">
                {collaboratorInteractions.length === 0 ? (
                  <div className="h-full flex flex-col items-center justify-center text-center p-6 bg-canvas/30">
                    <Wifi size={24} className="text-ink-3 mb-2 animate-pulse" />
                    <span className="text-ink-2 text-xs font-semibold">No Out-of-Band interactions detected yet.</span>
                    <p className="text-ink-3 text-[10px] mt-1 max-w-sm">
                      Copy the collaborator URL, inject it into an HTTP request field (e.g. Host, Referer, or custom SSRF inputs), and hit Send.
                    </p>
                  </div>
                ) : (
                  <table className="w-full border-collapse">
                    <thead className="sticky top-0 bg-[#0c1018] border-b border-border text-[10px] font-semibold text-ink-3 uppercase font-mono">
                      <tr>
                        <th className="px-4 py-2 text-left pl-5 w-24">Time</th>
                        <th className="px-4 py-2 text-left w-20">Type</th>
                        <th className="px-4 py-2 text-left w-32">Source IP</th>
                        <th className="px-4 py-2 text-left">Query / Host</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/60">
                      {collaboratorInteractions.map((item) => {
                        const isSelected = selectedOobId === item.id
                        const isDns = item.type === "DNS"
                        return (
                          <tr
                            key={item.id}
                            onClick={() => setSelectedOobId(item.id)}
                            className={`text-xs cursor-pointer transition-colors ${
                              isSelected ? "bg-accent/10 border-l-2 border-l-accent" : "hover:bg-elevated/20 border-l-2 border-l-transparent"
                            }`}
                          >
                            <td className="px-4 py-3 pl-5 font-mono text-ink-3">{item.time}</td>
                            <td className="px-4 py-3">
                              <span
                                className={`px-1.5 py-0.5 rounded border text-[9px] font-bold font-mono tracking-wide ${
                                  isDns
                                    ? "bg-blue-500/10 text-blue-400 border-blue-500/20"
                                    : "bg-accent/10 text-accent border-accent/20"
                                }`}
                              >
                                {item.type}
                              </span>
                            </td>
                            <td className="px-4 py-3 font-mono text-ink-2">{item.sourceIp}</td>
                            <td className="px-4 py-3 font-mono text-ink truncate max-w-xs">{item.query}</td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                )}
              </div>
            </div>

            {/* Right side: details inspector (1/3 width) */}
            <div className="w-[360px] shrink-0 p-5 overflow-y-auto bg-card flex flex-col min-h-0 border-l border-border">
              {(() => {
                const selectedItem = collaboratorInteractions.find(i => i.id === selectedOobId)
                if (!selectedItem) {
                  return (
                    <div className="h-full flex items-center justify-center text-ink-3 text-xs italic">
                      Select an interaction to inspect details.
                    </div>
                  )
                }

                return (
                  <div className="space-y-4 flex flex-col h-full">
                    <div className="border-b border-border pb-3">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[9px] font-mono uppercase tracking-widest text-ink-3 font-semibold">
                          Interaction details
                        </span>
                        <span className="text-[10px] font-mono text-ink-3 bg-canvas border border-border px-1.5 py-0.5 rounded">
                          {selectedItem.id}
                        </span>
                      </div>
                      <h4 className="text-ink text-sm font-bold flex items-center gap-1.5">
                        <Globe size={13} className="text-accent" />
                        {selectedItem.type} Interaction
                      </h4>
                    </div>

                    <div className="space-y-3.5 flex-1 min-h-0 text-xs">
                      <div className="bg-canvas border border-border rounded p-3">
                        <span className="text-ink-3 text-[9px] uppercase tracking-wider block mb-1 font-semibold">Query / Path</span>
                        <span className="text-ink font-mono font-medium">{selectedItem.query}</span>
                      </div>

                      <div className="bg-canvas border border-border rounded p-3">
                        <span className="text-ink-3 text-[9px] uppercase tracking-wider block mb-1 font-semibold">Source Address</span>
                        <span className="text-ink font-mono font-medium">{selectedItem.sourceIp}</span>
                      </div>

                      <div className="bg-canvas border border-border rounded p-3 space-y-1">
                        <span className="text-ink-3 text-[9px] uppercase tracking-wider block font-semibold">Triggered Payload</span>
                        <span className="text-accent font-mono font-medium text-[10px] break-all">{selectedItem.payload}</span>
                      </div>

                      <div className="bg-canvas border border-border rounded p-3 space-y-1.5">
                        <span className="text-ink-3 text-[9px] uppercase tracking-wider block font-semibold">Security Analysis</span>
                        <p className="text-ink-2 leading-relaxed font-sans">{selectedItem.details}</p>
                      </div>

                      {selectedItem.requestHeaders && (
                        <div className="bg-canvas border border-border rounded p-3 flex flex-col min-h-0">
                          <span className="text-ink-3 text-[9px] uppercase tracking-wider block mb-1.5 font-semibold">Captured HTTP Headers</span>
                          <pre className="text-[10px] font-mono text-ink-2 bg-panel/30 border border-border/40 rounded p-2 overflow-x-auto whitespace-pre leading-relaxed select-all">
                            {selectedItem.requestHeaders}
                          </pre>
                        </div>
                      )}
                    </div>
                  </div>
                )
              })()}
            </div>
          </div>
        )}

        {/* ────────────────────────────────────────────────────────
            TAB: SECURITY CLI TERMINAL
            ──────────────────────────────────────────────────────── */}
        {activeTab === "terminal" && <SecurityTerminal />}
      </div>
    </div>
  )
}

function SecurityTerminal() {
  const [input, setInput] = useState("")
  const [history, setHistory] = useState<Array<{ text: string; type: "system" | "input" | "error" | "success" | "info" }>>([
    { text: "VulnGuard Security Workbench Terminal v1.0", type: "system" },
    { text: "Initializing secure interface tunnel...", type: "system" },
    { text: "Type 'help' to view available operations.", type: "info" },
    { text: "", type: "system" }
  ])
  const consoleEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    consoleEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [history])

  const handleCommand = (e: React.FormEvent) => {
    e.preventDefault()
    const cmd = input.trim()
    if (!cmd) return

    const newHistory = [...history, { text: `vulnguard-user@workbench:~$ ${cmd}`, type: "input" as const }]
    const commandLower = cmd.toLowerCase()

    if (commandLower === "help") {
      newHistory.push(
        { text: "Available Commands:", type: "system" },
        { text: "  help          - Show this command reference matrix", type: "info" },
        { text: "  scan          - Launch mock discovery port-scan on target host", type: "info" },
        { text: "  fuzz          - Run fuzz parameters injection checks", type: "info" },
        { text: "  exploit       - Simulate SSRF exfiltration credential hijacking", type: "info" },
        { text: "  vuln-info     - Retrieve listing of database vulnerabilities", type: "info" },
        { text: "  clear         - Clear terminal stream buffer", type: "info" }
      )
    } else if (commandLower === "clear") {
      setHistory([
        { text: "VulnGuard Security Workbench Terminal v1.0", type: "system" },
        { text: "Type 'help' to view available operations.", type: "info" },
        { text: "", type: "system" }
      ])
      setInput("")
      return
    } else if (commandLower === "scan") {
      newHistory.push(
        { text: "[*] Initiating port scan on target host (api.acmecorp.com)...", type: "system" },
        { text: "[+] Resolving domain coordinates: 104.22.3.94", type: "success" },
        { text: "[+] Scanning top 100 system ports...", type: "system" },
        { text: "[+] Port 80/tcp   [OPEN]  Service: nginx v1.18.0", type: "success" },
        { text: "[+] Port 443/tcp  [OPEN]  Service: OpenSSL/TLS v1.3", type: "success" },
        { text: "[+] Port 8080/tcp [OPEN]  Service: Node Express", type: "success" },
        { text: "[*] Port discovery scan complete. All services registered.", type: "system" }
      )
    } else if (commandLower === "fuzz") {
      newHistory.push(
        { text: "[*] Launching parameter fuzz test against endpoint /api/users...", type: "system" },
        { text: "[*] Injecting payloads to parameter: user_id", type: "system" },
        { text: "[*] Transmitting payload: 1' OR '1'='1 -- (SQLi)", type: "system" },
        { text: "[!] CRITICAL: SQL syntax parse exception intercepted!", type: "error" },
        { text: "[+] Vulnerability Confirmed: SQL Injection vulnerability matched (VLN-0246)", type: "success" }
      )
    } else if (commandLower === "exploit") {
      newHistory.push(
        {
          text: `===================================================
 __   __    _        _____                 _ 
 \\ \\ / /   | |      |  __ \\               | |
  \\ V / _  | | _ __ | |  |_| _   _   __ _ | | _ 
   \\ / / | | || '_ \\| |  ___| | | | / _\` || || |
   | | | |_| || | | | |__| || |_| || (_| || || |
   \\_/  \\__,_||_| |_|\\_____/ \\__,_| \\__,_||_||_|
===================================================`, type: "system"
        },
        { text: "[*] Initiating Proof-of-Concept Exploit sequence (VLN-0245 SSRF)...", type: "system" },
        { text: "[*] Packaging custom HTTP boundary payload...", type: "system" },
        { text: "[*] Transmitting SSRF bypass request to EC2 IMDSv1 interface...", type: "system" },
        { text: "[+] OOB Collaborator callback received from 169.254.169.254!", type: "success" },
        { text: "[+] Intercepted AWS IAM Token: ASIAXXXXXX_REDACTED", type: "success" },
        { text: "[+] Exploit validation successful. Target credentials acquired.", type: "success" }
      )
    } else if (commandLower === "vuln-info") {
      newHistory.push(
        { text: "Identified Active Vulnerabilities:", type: "system" },
        { text: "  - VLN-0244: CORS Misconfiguration (Origin mismatch allowed) - Low", type: "info" },
        { text: "  - VLN-0245: Server-Side Request Forgery (SSRF Endpoint) - Critical", type: "info" },
        { text: "  - VLN-0246: SQL Injection in user_id Query Parameter - High", type: "info" },
        { text: "  - VLN-0247: Server-side Path Traversal in Export Handler - High", type: "info" }
      )
    } else {
      newHistory.push({ text: `bash: command not found: ${cmd}. Type 'help' to see options.`, type: "error" })
    }

    setHistory(newHistory)
    setInput("")
  }

  return (
    <div className="h-full flex flex-col bg-[#070a10] p-5 font-mono text-xs">
      <div className="flex justify-between items-center border-b border-border/60 pb-2 mb-3 shrink-0">
        <div className="flex items-center gap-2">
          <Terminal size={14} className="text-accent animate-pulse" />
          <span className="text-ink font-semibold">Live Security Sandbox Terminal</span>
        </div>
        <span className="text-[10px] text-ink-3">sec-terminal@vulnguard.sh</span>
      </div>

      {/* Terminal Output */}
      <div className="flex-1 bg-black/30 border border-border/40 rounded-lg p-4 overflow-y-auto mb-3 space-y-2 leading-relaxed text-ink-2 select-all whitespace-pre-wrap">
        {history.map((line, idx) => {
          let color = "text-[#a9b1d6]"
          if (line.type === "system") color = "text-accent font-semibold"
          else if (line.type === "input") color = "text-ink font-bold"
          else if (line.type === "error") color = "text-critical font-semibold"
          else if (line.type === "success") color = "text-emerald font-semibold"
          else if (line.type === "info") color = "text-yellow/90"

          return (
            <div key={idx} className={color}>
              {line.text}
            </div>
          )
        })}
        <div ref={consoleEndRef} />
      </div>

      {/* Input Prompt Form */}
      <form onSubmit={handleCommand} className="flex gap-2 items-center bg-canvas/30 border border-border rounded-lg px-3 py-1.5 shrink-0">
        <span className="text-accent font-bold select-none">vulnguard-user@workbench:~$</span>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Run help, scan, fuzz, exploit..."
          className="flex-1 bg-transparent border-0 outline-none text-ink font-mono text-xs focus:ring-0 focus:outline-none placeholder-ink-3/50"
          autoFocus
        />
        <button type="submit" className="text-ink-3 hover:text-ink transition-colors">
          <Send size={12} />
        </button>
      </form>
    </div>
  )
}

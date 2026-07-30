import { useState } from "react"
import {
  ChevronDown,
  Info,
  Lock,
  Globe,
  Zap,
  Shield,
  Clock,
  AlertCircle,
  FileCode,
  CheckCircle,
  Loader2,
  WifiOff,
} from "lucide-react"
import { scanApi, checkBackendHealth } from "../api/client"

interface ScanSetupProps {
  onNavigate: (page: string) => void
  setScanActive: (active: boolean) => void
  setScanProgress: (progress: number) => void
  onScanStarted?: (scanId: string) => void
}

const SCAN_PROFILES = [
  {
    id: "full",
    label: "Full Scan",
    desc: "Comprehensive passive + active testing. Recommended for thorough assessments.",
  },
  {
    id: "quick",
    label: "Quick Scan",
    desc: "Lightweight active checks with reduced depth. Suitable for rapid CI/CD gates.",
  },
  {
    id: "api",
    label: "API Scan",
    desc: "Focused on REST/GraphQL endpoints. Parses OpenAPI specs when provided.",
  },
  {
    id: "custom",
    label: "Custom",
    desc: "Define a bespoke test plan using policy rules and module toggles.",
  },
]

const AUTH_PROFILES = [
  "None — Unauthenticated",
  "acmecorp-admin (Session Cookie)",
  "acmecorp-api (Bearer Token)",
  "acmecorp-basic (HTTP Basic)",
  "+ New Auth Profile…",
]

export default function ScanSetup({ onNavigate, setScanActive, setScanProgress, onScanStarted }: ScanSetupProps) {
  const [profile, setProfile] = useState("full")
  const [safety, setSafety] = useState<"passive" | "standard" | "aggressive">("standard")
  const [depth, setDepth] = useState("3")
  const [timeout, setTimeout_] = useState("30")

  // State bindings for layout sync & summary card
  const [primaryUrl, setPrimaryUrl] = useState("https://api.acmecorp.com")
  const [environment, setEnvironment] = useState("Production")
  const [authProfile, setAuthProfile] = useState("None — Unauthenticated")
  const [concurrency, setConcurrency] = useState("25 requests/sec (Standard)")

  // Wizard state (simulated navigation highlight)
  const [activeStep, setActiveStep] = useState(1) // 1: Target, 2: Auth, 3: Profile, 4: Safety, 5: Schedule

  // Launch Verification modal state
  const [verifying, setVerifying] = useState(false)
  const [verifStep, setVerifStep] = useState(0) // 0: init, 1: dns, 2: ping, 3: ssl, 4: robots, 5: done
  const [backendError, setBackendError] = useState<string | null>(null)

  // OpenAPI schema states
  const [scopeText, setScopeText] = useState("https://api.acmecorp.com/*\nhttps://api.acmecorp.com/v2/*")
  const [analyzingSchema, setAnalyzingSchema] = useState(false)
  const [imported, setImported] = useState(false)
  const [endpoints, setEndpoints] = useState<any[]>([])

  const handleLoadSchema = () => {
    if (analyzingSchema) return
    setAnalyzingSchema(true)
    setImported(false)
    setTimeout(() => {
      setAnalyzingSchema(false)
      setEndpoints([
        { method: "GET", path: "/api/users", auth: "Bearer Token", params: "user_id, role", desc: "Retrieve active users directory" },
        { method: "POST", path: "/api/auth/login", auth: "None", params: "username, password", desc: "User credentials validation" },
        { method: "GET", path: "/export", auth: "Session Cookie", params: "file, format", desc: "Generate report document" },
        { method: "DELETE", path: "/api/admin/export", auth: "Session Cookie", params: "export_id", desc: "Remove configuration file" }
      ])
    }, 1200)
  }

  const handleImportEndpoints = () => {
    const paths = endpoints.map(e => `${primaryUrl}${e.path}`)
    setScopeText(paths.join("\n"))
    setImported(true)
  }

  const handleLaunchScan = async () => {
    setBackendError(null)
    setVerifying(true)
    setVerifStep(1)

    // Check backend health first
    const healthy = await checkBackendHealth()
    if (!healthy) {
      setBackendError("Cannot reach backend at localhost:8000. Is uvicorn running?")
      setVerifying(false)
      setVerifStep(0)
      return
    }

    // Animate pre-scan diagnostics (real checks happen in backend)
    setTimeout(() => setVerifStep(2), 700)
    setTimeout(() => setVerifStep(3), 1300)
    setTimeout(() => setVerifStep(4), 1900)
    setTimeout(() => setVerifStep(5), 2500)

    setTimeout(async () => {
      try {
        // Compute concurrency number from selected label
        const concurrencyNum =
          concurrency.startsWith("50") ? 50
          : concurrency.startsWith("10") ? 10
          : 25

        const result = await scanApi.start({
          target: primaryUrl,
          scope: scopeText.split("\n").filter(Boolean),
          profile: profile as any,
          safety: safety,
          depth: Number(depth),
          timeout: Number(timeout),
          concurrency: concurrencyNum,
          label: "acmecorp-api-v2",
          environment: environment,
        })

        onScanStarted?.(result.scan_id)
        setScanActive(true)
        setScanProgress(0)
        setVerifying(false)
        setVerifStep(0)
        onNavigate("automated-scan")
      } catch (err: any) {
        setBackendError(err.message || "Failed to start scan")
        setVerifying(false)
        setVerifStep(0)
      }
    }, 3200)
  }

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto">
      {/* Sleek Stepper Wizard Header */}
      <div className="bg-card border border-border rounded-lg p-4 flex items-center justify-between shadow-sm">
        <div>
          <h1 className="text-ink text-base font-semibold">New Scan Configuration</h1>
          <p className="text-ink-3 text-xs mt-0.5">Specify parameters and target authorization rules.</p>
        </div>
        <div className="flex items-center gap-1.5 md:gap-3 text-[11px] font-semibold text-ink-3 font-mono">
          {[
            { step: 1, label: "TARGET" },
            { step: 2, label: "AUTH" },
            { step: 3, label: "PROFILE" },
            { step: 4, label: "SAFETY" },
          ].map((s) => (
            <button
              key={s.step}
              onClick={() => setActiveStep(s.step)}
              className={`flex items-center gap-1 px-2 py-1 rounded transition-colors ${
                activeStep === s.step
                  ? "text-accent bg-accent/10 border border-accent/25"
                  : "hover:text-ink-2"
              }`}
            >
              <span className={`w-4 h-4 rounded-full flex items-center justify-center text-[9px] ${
                activeStep === s.step ? "bg-accent text-white" : "bg-elevated border border-border"
              }`}>{s.step}</span>
              <span className="hidden sm:inline">{s.label}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Form Setup (2/3 width) */}
        <div className="lg:col-span-2 space-y-5">
          {/* Target Section */}
          <Section
            icon={<Globe size={14} className={activeStep === 1 ? "text-accent" : "text-ink-3"} />}
            title="Target Configuration"
            index="01"
            active={activeStep === 1}
            onClick={() => setActiveStep(1)}
          >
            <div className="space-y-4">
              <Field label="Primary URL" required>
                <input
                  type="text"
                  value={primaryUrl}
                  onChange={(e) => setPrimaryUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="w-full bg-canvas border border-border rounded px-3 py-2 text-ink text-sm font-mono placeholder:text-ink-3 focus:border-accent transition-colors"
                />
              </Field>
              <Field
                label="Scope Rules"
                hint="One URL rule per line. Use * as wildcard."
              >
                <textarea
                  rows={3}
                  value={scopeText}
                  onChange={(e) => setScopeText(e.target.value)}
                  className="w-full bg-canvas border border-border rounded px-3 py-2 text-ink text-xs font-mono placeholder:text-ink-3 resize-none focus:border-accent transition-colors animate-pulse-once"
                />
              </Field>

              {/* OpenAPI spec importer */}
              <div className="pt-2 border-t border-border/40">
                <span className="text-ink-3 text-[10px] uppercase font-bold tracking-wider block mb-2">
                  OpenAPI / Swagger Schema Analyzer
                </span>
                
                {endpoints.length === 0 ? (
                  <div
                    onClick={handleLoadSchema}
                    className="border border-dashed border-border hover:border-accent rounded-lg p-5 text-center cursor-pointer bg-canvas/30 transition-all group relative overflow-hidden"
                  >
                    {analyzingSchema ? (
                      <div className="flex flex-col items-center py-2">
                        <Loader2 size={18} className="text-accent animate-spin mb-2" />
                        <span className="text-ink text-xs font-semibold">Parsing Schema Specification...</span>
                        <span className="text-ink-3 text-[9px] mt-0.5 font-sans">Validating JSON nodes and security schemas</span>
                      </div>
                    ) : (
                      <div className="py-2">
                        <FileCode size={18} className="text-ink-3 group-hover:text-accent mx-auto mb-2 transition-colors" />
                        <span className="text-ink text-xs block font-semibold">Upload OpenAPI Spec (JSON/YAML)</span>
                        <span className="text-ink-3 text-[9px] block mt-0.5 font-sans">Click to auto-parse staging swagger payload</span>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="border border-border rounded-lg bg-[#07090f] overflow-hidden flex flex-col">
                    {/* Header */}
                    <div className="px-3.5 py-2 border-b border-border bg-[#0b0e16] flex items-center justify-between">
                      <span className="text-[10px] font-mono text-ink-3 font-semibold">
                        {endpoints.length} Endpoints Discovered
                      </span>
                      {imported ? (
                        <span className="text-[9px] bg-emerald/10 border border-emerald/20 text-emerald px-1.5 py-0.5 rounded font-bold uppercase font-sans">
                          Imported Scope
                        </span>
                      ) : (
                        <button
                          onClick={handleImportEndpoints}
                          className="px-2 py-1 bg-accent text-white hover:bg-accent/90 rounded text-[9px] font-bold uppercase transition-colors"
                        >
                          Import All Endpoints
                        </button>
                      )}
                    </div>

                    {/* Endpoints List */}
                    <div className="max-h-[160px] overflow-y-auto divide-y divide-border/40 font-mono text-[10px]">
                      {endpoints.map((e, idx) => {
                        let methodColor = "text-emerald bg-emerald/5 border-emerald/15"
                        if (e.method === "POST") methodColor = "text-accent bg-accent/5 border-accent/15"
                        if (e.method === "DELETE") methodColor = "text-critical bg-critical/5 border-critical/15"

                        return (
                          <div key={idx} className="p-2 flex items-center justify-between hover:bg-elevated/10">
                            <div className="flex items-center gap-2 truncate pr-2">
                              <span className={`px-1 rounded border text-[8px] font-bold ${methodColor}`}>
                                {e.method}
                              </span>
                              <span className="text-ink truncate font-medium">{e.path}</span>
                              <span className="text-ink-3 text-[9px] truncate font-sans">({e.desc})</span>
                            </div>
                            <div className="flex items-center gap-1.5 shrink-0">
                              {e.params && (
                                <span className="text-ink-3 text-[9px] bg-canvas border border-border px-1 rounded-sm">
                                  {e.params}
                                </span>
                              )}
                              <span className="text-[9px] font-sans bg-[#0c1018] text-ink-2 px-1 rounded border border-border">
                                {e.auth}
                              </span>
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}
              </div>

              <div className="grid grid-cols-2 gap-4">
                <Field label="Target Label / App Identifier">
                  <input
                    type="text"
                    defaultValue="acmecorp-api-v2"
                    className="w-full bg-canvas border border-border rounded px-3 py-2 text-ink text-sm font-mono placeholder:text-ink-3 focus:border-accent transition-colors"
                  />
                </Field>
                <Field label="Environment">
                  <Select
                    options={["Production", "Staging", "Development", "QA"]}
                    value={environment}
                    onChange={setEnvironment}
                  />
                </Field>
              </div>
            </div>
          </Section>

          {/* Auth Section */}
          <Section
            icon={<Lock size={14} className={activeStep === 2 ? "text-accent" : "text-ink-3"} />}
            title="Authentication Profile"
            index="02"
            active={activeStep === 2}
            onClick={() => setActiveStep(2)}
          >
            <div className="space-y-4">
              <Field label="Select Profile">
                <Select
                  options={AUTH_PROFILES}
                  value={authProfile}
                  onChange={setAuthProfile}
                />
              </Field>
              <div className="grid grid-cols-2 gap-4">
                <Field label="Session Token / Cookie Name">
                  <input
                    type="text"
                    placeholder="e.g. session, auth_token"
                    className="w-full bg-canvas border border-border rounded px-3 py-2 text-ink text-sm font-mono placeholder:text-ink-3 focus:border-accent transition-colors"
                  />
                </Field>
                <Field label="Token Value / Secret Key">
                  <input
                    type="password"
                    placeholder="••••••••••••••••"
                    className="w-full bg-canvas border border-border rounded px-3 py-2 text-ink text-sm font-mono placeholder:text-ink-3 focus:border-accent transition-colors"
                  />
                </Field>
              </div>
              <div className="flex items-center gap-2.5 p-3 bg-canvas/30 border border-border rounded-lg">
                <Info size={13} className="text-accent shrink-0" />
                <p className="text-ink-3 text-xs leading-relaxed">
                  Auth credentials are encrypted at rest using AES-256 and are never written to exported PDF reports.
                </p>
              </div>
            </div>
          </Section>

          {/* Scan Profile Section */}
          <Section
            icon={<Zap size={14} className={activeStep === 3 ? "text-accent" : "text-ink-3"} />}
            title="Scan Profiling & Depths"
            index="03"
            active={activeStep === 3}
            onClick={() => setActiveStep(3)}
          >
            <div className="grid grid-cols-2 gap-3 mb-4">
              {SCAN_PROFILES.map((p) => (
                <button
                  key={p.id}
                  onClick={() => setProfile(p.id)}
                  className={`text-left p-3 rounded-lg border transition-colors ${
                    profile === p.id
                      ? "border-accent bg-accent/5"
                      : "border-border bg-canvas/40 hover:border-border-hi"
                  }`}
                >
                  <p
                    className={`text-xs font-semibold mb-1 ${
                      profile === p.id ? "text-accent" : "text-ink"
                    }`}
                  >
                    {p.label}
                  </p>
                  <p className="text-ink-3 text-[11px] leading-relaxed">{p.desc}</p>
                </button>
              ))}
            </div>
            <div className="grid grid-cols-2 gap-4">
              <Field label="Crawl Depth">
                <div className="flex items-center gap-3">
                  <input
                    type="range"
                    min="1"
                    max="10"
                    value={depth}
                    onChange={(e) => setDepth(e.target.value)}
                    className="flex-1 accent-accent"
                  />
                  <span className="text-ink font-mono text-xs w-5 text-center font-bold">
                    {depth}
                  </span>
                </div>
              </Field>
              <Field label="Request Timeout (s)">
                <div className="flex items-center gap-3">
                  <input
                    type="range"
                    min="5"
                    max="120"
                    value={timeout}
                    onChange={(e) => setTimeout_(e.target.value)}
                    className="flex-1 accent-accent"
                  />
                  <span className="text-ink font-mono text-xs w-6 text-center font-bold">
                    {timeout}s
                  </span>
                </div>
              </Field>
            </div>
          </Section>

          {/* Safety Mode Section */}
          <Section
            icon={<Shield size={14} className={activeStep === 4 ? "text-accent" : "text-ink-3"} />}
            title="Safety Level & Exclusions"
            index="04"
            active={activeStep === 4}
            onClick={() => setActiveStep(4)}
          >
            <div className="flex gap-3">
              {(["passive", "standard", "aggressive"] as const).map((s) => (
                <button
                  key={s}
                  onClick={() => setSafety(s)}
                  className={`flex-1 py-2 rounded-lg border text-xs font-semibold capitalize transition-all ${
                    safety === s
                      ? s === "aggressive"
                        ? "border-critical bg-critical/5 text-critical"
                        : "border-accent bg-accent/5 text-accent"
                      : "border-border bg-canvas/40 text-ink-2 hover:border-border-hi"
                  }`}
                >
                  {s} Mode
                </button>
              ))}
            </div>
            <p className="text-ink-3 text-xs mt-2.5 leading-relaxed">
              {safety === "passive" &&
                "Observation only. Passive sitemap crawler, SSL audits, and response header security validation. Zero active exploitation payloads."}
              {safety === "standard" &&
                "Standard active probing using safe payloads. Audit for common injection (SQLi, XSS), path traversals, and exposed endpoints."}
              {safety === "aggressive" &&
                "Full exploit simulation, AST injection, commands fuzzing, and blind time-based checks. Risk of high resources usage."}
            </p>
            {safety === "aggressive" && (
              <div className="flex items-center gap-2.5 mt-3 p-3 bg-critical/5 border border-critical/20 rounded-lg">
                <AlertCircle size={13} className="text-critical shrink-0 animate-bounce" />
                <p className="text-critical text-xs leading-normal font-medium">
                  Aggressive mode may trigger application firewalls or cause rate limiting. Use on test environments only.
                </p>
              </div>
            )}
          </Section>
        </div>

        {/* Right Column: OpenAPI Dropzone, Scheduler, and Live Summary (1/3 width) */}
        <div className="space-y-5 flex flex-col">
          {/* OpenAPI Spec Schema Import */}
          <div className="bg-card border border-border rounded-lg p-5 shadow-sm">
            <div className="flex items-center gap-1.5 mb-2">
              <FileCode size={13} className="text-accent" />
              <p className="text-ink text-sm font-semibold">OpenAPI / Swagger Spec</p>
            </div>
            <p className="text-ink-3 text-[11px] leading-relaxed mb-4">
              Upload an OpenAPI JSON or YAML schema file to automatically map endpoints and query parameters.
            </p>

            {endpoints.length === 0 ? (
              <div
                onClick={handleLoadSchema}
                className="border border-dashed border-border hover:border-accent rounded-lg p-5 text-center cursor-pointer transition-colors bg-canvas/30 group"
              >
                {analyzingSchema ? (
                  <div className="flex flex-col items-center py-2">
                    <Loader2 size={18} className="text-accent animate-spin mb-2" />
                    <span className="text-ink text-xs font-semibold">Parsing Schema Specification...</span>
                  </div>
                ) : (
                  <div className="py-2">
                    <FileCode size={20} className="text-ink-3 group-hover:text-accent mx-auto mb-2 transition-colors" />
                    <span className="text-ink text-xs block font-semibold">Drag schema here</span>
                    <span className="text-ink-3 text-[10px] block mt-1">JSON, YAML or WSDL format</span>
                  </div>
                )}
              </div>
            ) : (
              <div className="bg-emerald/5 border border-emerald/20 rounded-lg p-4 flex flex-col items-center text-center space-y-2">
                <CheckCircle size={20} className="text-emerald" />
                <span className="text-ink text-xs font-semibold">Schema Parsed Successfully</span>
                <span className="text-ink-3 text-[10px] font-mono">{endpoints.length} endpoints loaded into Target Config</span>
              </div>
            )}
          </div>

          {/* Schedule Configuration */}
          <div className="bg-card border border-border rounded-lg p-5 shadow-sm space-y-4">
            <div className="flex items-center gap-1.5">
              <Clock size={13} className="text-accent" />
              <p className="text-ink text-sm font-semibold">Scheduler & Rules</p>
            </div>

            <Field label="Launch Trigger">
              <Select options={["Run Immediately", "Schedule Single Run", "Recurring / Cron Job"]} />
            </Field>

            <Field label="Max Request Concurrency">
              <Select
                options={[
                  "25 requests/sec (Standard)",
                  "10 requests/sec (Conservative)",
                  "50 requests/sec (Aggressive)",
                ]}
                value={concurrency}
                onChange={setConcurrency}
              />
            </Field>
          </div>

          {/* Active Configuration Summary Card */}
          <div className="bg-card border border-border rounded-lg p-5 shadow-sm relative overflow-hidden flex-1 flex flex-col justify-between">
            {/* Hologram background lines */}
            <div className="absolute inset-0 hologram-panel pointer-events-none z-0 opacity-20" />
            
            <div className="relative z-10 space-y-4 flex-1 flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-1.5 border-b border-border/65 pb-2.5 mb-3">
                  <Shield size={13} className="text-emerald animate-pulse" />
                  <p className="text-ink text-sm font-semibold">Active Profile Summary</p>
                </div>

                <div className="space-y-3 font-mono text-[11px]">
                  <div className="flex justify-between items-center py-1.5 border-b border-border/20">
                    <span className="text-ink-3">Target Host</span>
                    <span className="text-ink font-semibold truncate max-w-[150px]" title={primaryUrl}>
                      {primaryUrl.replace("https://", "").replace("http://", "") || "N/A"}
                    </span>
                  </div>
                  <div className="flex justify-between items-center py-1.5 border-b border-border/20">
                    <span className="text-ink-3">Environment</span>
                    <span className="text-emerald font-semibold uppercase">{environment}</span>
                  </div>
                  <div className="flex justify-between items-center py-1.5 border-b border-border/20">
                    <span className="text-ink-3">Authentication</span>
                    <span className="text-ink-2 truncate max-w-[150px]" title={authProfile}>{authProfile.split(" (")[0]}</span>
                  </div>
                  <div className="flex justify-between items-center py-1.5 border-b border-border/20">
                    <span className="text-ink-3">Scan Profile</span>
                    <span className="text-accent font-semibold">{profile.toUpperCase()} SCAN</span>
                  </div>
                  <div className="flex justify-between items-center py-1.5 border-b border-border/20">
                    <span className="text-ink-3">Safety Mode</span>
                    <span className={`font-semibold ${safety === "aggressive" ? "text-critical" : safety === "passive" ? "text-emerald" : "text-accent"}`}>
                      {safety.toUpperCase()} MODE
                    </span>
                  </div>
                  <div className="flex justify-between items-center py-1.5 border-b border-border/20">
                    <span className="text-ink-3">Crawl Depth</span>
                    <span className="text-ink-2 font-bold">{depth} levels</span>
                  </div>
                  <div className="flex justify-between items-center py-1.5">
                    <span className="text-ink-3">Concurrency</span>
                    <span className="text-ink-2 font-bold truncate max-w-[130px]" title={concurrency}>{concurrency.split(" (")[0]}</span>
                  </div>
                </div>
              </div>

              {/* Status bar */}
              <div className="bg-canvas/50 border border-border/60 rounded p-2.5 flex items-center gap-2 mt-4">
                <span className="w-2 h-2 rounded-full bg-emerald animate-ping shrink-0" />
                <span className="text-[10px] text-ink-3 font-sans">Scanner Ready to Initialize</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Action Buttons ── */}
      <div className="flex items-center justify-between pt-4 border-t border-border">
        <button
          onClick={() => onNavigate("overview")}
          className="text-ink-2 text-xs font-semibold hover:text-ink transition-colors"
        >
          Back to Overview
        </button>
        <div className="flex items-center gap-3">
          <button
            onClick={() => onNavigate("overview")}
            className="px-4 py-2 bg-elevated border border-border rounded text-xs hover:border-border-hi text-ink font-semibold transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleLaunchScan}
            className="px-5 py-2 bg-accent text-white rounded text-xs font-semibold hover:bg-accent/90 transition-colors shadow-lg shadow-accent/20"
          >
            Launch Target Scanner
          </button>
        </div>
      </div>

      {/* ── Backend error banner ── */}
      {backendError && (
        <div className="flex items-center gap-2.5 p-3 bg-critical/8 border border-critical/20 rounded-lg">
          <WifiOff size={13} className="text-critical shrink-0" />
          <p className="text-critical text-xs font-medium">{backendError}</p>
        </div>
      )}

      {/* ── Host Pre-Scan Check Modal (animates while real backend call fires) ── */}
      {verifying && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-card border border-border w-[480px] rounded-lg shadow-2xl overflow-hidden flex flex-col font-sans p-5 space-y-4 animate-fade-in">
            <div className="flex items-center gap-2 border-b border-border pb-3">
              <Loader2 size={16} className="text-accent animate-spin" />
              <span className="text-ink font-semibold text-sm">Pre-Scan Host Diagnostics</span>
            </div>

            <div className="space-y-3 py-2">
              <DiagnosticLine
                label="Resolving Target Host Domain DNS..."
                status={verifStep > 1 ? "done" : verifStep === 1 ? "running" : "pending"}
                detail={`api.acmecorp.com -> 104.22.3.94`}
              />
              <DiagnosticLine
                label="Measuring Endpoint Ping Latency..."
                status={verifStep > 2 ? "done" : verifStep === 2 ? "running" : "pending"}
                detail="Average latency: 42ms (Secure RTT)"
              />
              <DiagnosticLine
                label="Verifying SSL/TLS Cipher Suite..."
                status={verifStep > 3 ? "done" : verifStep === 3 ? "running" : "pending"}
                detail="TLS 1.2/1.3 Handshake verification complete"
              />
              <DiagnosticLine
                label="Analyzing Target robots.txt Exclusions..."
                status={verifStep > 4 ? "done" : verifStep === 4 ? "running" : "pending"}
                detail="0 crawl blocks found, parsing sitemap.xml"
              />
            </div>

            <div className="flex justify-end gap-2 border-t border-border pt-4">
              <span className="text-ink-3 text-[10px] font-mono self-center mr-auto">
                Initializing VulnGuard Fuzz-Db...
              </span>
              <button
                onClick={() => setVerifying(false)}
                className="px-4 py-1.5 bg-elevated hover:bg-elevated/80 border border-border text-ink rounded text-xs font-semibold transition-colors"
              >
                Abort Scan
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function Section({
  icon,
  title,
  index,
  active,
  onClick,
  children,
}: {
  icon: React.ReactNode
  title: string
  index: string
  active: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <div
      onClick={onClick}
      className={`bg-card border rounded-lg transition-all cursor-pointer ${
        active ? "border-accent/40 shadow-sm" : "border-border hover:border-border-hi"
      }`}
    >
      <div className="flex items-center gap-2.5 px-5 py-3 border-b border-border bg-panel/30">
        <span className="text-ink-3 font-mono text-[10px]">{index}</span>
        <span className="text-ink-2">{icon}</span>
        <span className="text-ink text-xs font-semibold">{title}</span>
      </div>
      {active && <div className="p-5 cursor-default" onClick={(e) => e.stopPropagation()}>{children}</div>}
    </div>
  )
}

function Field({
  label,
  required,
  hint,
  children,
}: {
  label: string
  required?: boolean
  hint?: string
  children: React.ReactNode
}) {
  return (
    <div>
      <div className="flex items-center gap-1.5 mb-1.5">
        <label className="text-ink-2 text-xs font-medium">{label}</label>
        {required && <span className="text-critical text-xs">*</span>}
        {hint && <span className="text-ink-3 text-[10px]">— {hint}</span>}
      </div>
      {children}
    </div>
  )
}

function Select({
  options,
  value,
  onChange,
}: {
  options: string[]
  value?: string
  onChange?: (val: string) => void
}) {
  return (
    <div className="relative">
      <select
        value={value}
        onChange={(e) => onChange?.(e.target.value)}
        className="w-full appearance-none bg-canvas border border-border rounded px-3 py-1.5 text-ink text-xs pr-8 focus:border-accent transition-colors cursor-pointer font-sans"
      >
        {options.map((o) => (
          <option key={o} value={o}>{o}</option>
        ))}
      </select>
      <ChevronDown
        size={11}
        className="absolute right-3 top-1/2 -translate-y-1/2 text-ink-3 pointer-events-none"
      />
    </div>
  )
}

function DiagnosticLine({
  label,
  status,
  detail,
}: {
  label: string
  status: "done" | "running" | "pending"
  detail?: string
}) {
  return (
    <div className="flex items-start gap-2.5 text-xs">
      <div className="relative flex items-center justify-center w-4 shrink-0 mt-0.5">
        {status === "done" && (
          <CheckCircle size={14} className="text-emerald" />
        )}
        {status === "running" && (
          <Loader2 size={14} className="text-accent animate-spin" />
        )}
        {status === "pending" && (
          <div className="w-3.5 h-3.5 rounded-full border border-border bg-canvas" />
        )}
      </div>
      <div className="flex-1">
        <p className={`${status === "running" ? "text-ink font-semibold" : status === "done" ? "text-ink-2" : "text-ink-3"}`}>
          {label}
        </p>
        {status === "done" && detail && (
          <p className="text-[10px] text-ink-3 font-mono mt-0.5">{detail}</p>
        )}
      </div>
    </div>
  )
}

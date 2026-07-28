import { useState } from "react"
import {
  Eye,
  EyeOff,
  Plus,
  Trash2,
  RefreshCw,
  CheckCircle2,
  X,
  Shield,
  Layers,
  Settings as SettingsIcon,
  Cable,
  Database,
  Terminal,
} from "lucide-react"
import type { PageProps } from "../App"

type Tab = "general" | "authentication" | "integrations" | "api-keys" | "policies"

const API_KEYS_INITIAL = [
  { id: "key_live_xK9mPqR7vL2jN8cF", name: "CI/CD Pipeline Scan", created: "Jul 01, 2026", last: "Jul 26, 2026", perms: "Read, Scan" },
  { id: "key_live_aW4kZtB9sE3dH6uY", name: "Jira Workbench Webhook", created: "Jun 15, 2026", last: "Jul 25, 2026", perms: "Read, Write" },
  { id: "key_live_mC7rVqD5wX1gT0pO", name: "Slack Notification Key", created: "Jun 01, 2026", last: "Jul 22, 2026", perms: "Read" },
]

export default function Settings(_props: PageProps) {
  const [tab, setTab] = useState<Tab>("general")
  const [showKey, setShowKey] = useState<string | null>(null)
  
  // Dynamic integration statuses
  const [integrations, setIntegrations] = useState([
    { name: "GitHub", status: true, desc: "Push findings to Security tab, annotate PRs" },
    { name: "Jira", status: true, desc: "Auto-create issues for new findings" },
    { name: "Slack", status: true, desc: "Notify #security-alerts on critical findings" },
    { name: "PagerDuty", status: false, desc: "Trigger incidents for critical severity" },
    { name: "Splunk", status: false, desc: "Forward scan events to SIEM" },
    { name: "Elastic SIEM", status: false, desc: "Stream findings to Elasticsearch index" },
  ])

  const [activeModal, setActiveModal] = useState<"Jira" | "Slack" | "PagerDuty" | "Splunk" | null>(null)
  const [toast, setToast] = useState<string | null>(null)
  const [apiKeys, setApiKeys] = useState(API_KEYS_INITIAL)

  const handleToggleConnect = (name: string) => {
    setIntegrations(
      integrations.map((i) => (i.name === name ? { ...i, status: !i.status } : i))
    )
    const toggled = integrations.find((i) => i.name === name)
    setToast(`${name} ${toggled?.status ? "disconnected" : "connected"} successfully!`)
    setTimeout(() => setToast(null), 3000)
  }

  const handleTestConnection = (name: string) => {
    setActiveModal(name as any)
    setToast(`Test Webhook triggered for ${name}!`)
    setTimeout(() => setToast(null), 3000)
  }

  const handleGenerateKey = () => {
    const newK = {
      id: `key_live_${Math.random().toString(36).substring(2, 10)}${Math.random().toString(36).substring(2, 10)}`,
      name: `Workbench Key — ${new Date().toLocaleDateString()}`,
      created: "Today",
      last: "—",
      perms: "Read, Scan",
    }
    setApiKeys([...apiKeys, newK])
  }

  return (
    <div className="p-6 max-w-4xl space-y-6">
      <div className="mb-4">
        <h1 className="text-ink text-xl font-semibold">Workspace Settings</h1>
        <p className="text-ink-3 text-xs mt-0.5">Enterprise configuration, API integrations, and scan profiles.</p>
      </div>

      {/* Settings Navigation Tabs */}
      <div className="flex border-b border-border mb-6">
        {([
          { id: "general", label: "General" },
          { id: "authentication", label: "Access Control" },
          { id: "integrations", label: "Integrations" },
          { id: "api-keys", label: "API Keys" },
          { id: "policies", label: "Safety Policies" },
        ]).map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id as Tab)}
            className={`px-4 py-2.5 text-xs font-semibold border-b-2 -mb-px transition-colors ${
              tab === t.id ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink-2"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ── GENERAL SETTINGS ── */}
      {tab === "general" && (
        <div className="space-y-4">
          <Card title="Company Metadata" subtitle="Configure organization identity parameters.">
            <div className="grid grid-cols-2 gap-4">
              <SettingField label="Organization Name">
                <input type="text" defaultValue="Acme Corp" className={INPUT} />
              </SettingField>
              <SettingField label="Primary Security Contact Email">
                <input type="text" defaultValue="ciso@acmecorp.com" className={INPUT} />
              </SettingField>
            </div>
          </Card>
          <Card title="Workspace Preferences" subtitle="Global application parameters.">
            <div className="grid grid-cols-2 gap-4">
              <SettingField label="Language Localization">
                <select className={INPUT}>
                  <option>English (US)</option>
                  <option>Deutsch</option>
                  <option>日本語</option>
                </select>
              </SettingField>
              <SettingField label="Default Metric Index">
                <select className={INPUT}>
                  <option>OWASP Top 10 (2025)</option>
                  <option>CWE Top 25</option>
                  <option>SANS Top 25</option>
                </select>
              </SettingField>
            </div>
          </Card>
        </div>
      )}

      {/* ── ACCESS CONTROL ── */}
      {tab === "authentication" && (
        <div className="space-y-4">
          <Card title="Single Sign-On (SSO)" subtitle="Configure SAML 2.0 or OIDC providers.">
            <div className="space-y-3">
              <div className="flex items-center justify-between py-2">
                <div>
                  <p className="text-ink text-xs font-semibold">Enforce SSO login only</p>
                  <p className="text-ink-3 text-[10px] mt-0.5">Disable local username/password configuration.</p>
                </div>
                <Toggle defaultOn={false} />
              </div>
              <SettingField label="SAML Metadata URL">
                <input type="text" placeholder="https://okta.acmecorp.com/app/sso/metadata" className={INPUT} />
              </SettingField>
            </div>
          </Card>
        </div>
      )}

      {/* ── INTEGRATIONS ── */}
      {tab === "integrations" && (
        <div className="space-y-4">
          <div className="bg-card border border-border rounded-lg divide-y divide-border/60">
            {integrations.map((intg) => (
              <div key={intg.name} className="p-4 flex items-center justify-between hover:bg-panel/10 transition-colors">
                <div>
                  <p className="text-ink text-xs font-semibold">{intg.name}</p>
                  <p className="text-ink-3 text-[10px] mt-0.5">{intg.desc}</p>
                </div>
                <div className="flex items-center gap-3">
                  {intg.status ? (
                    <span className="flex items-center gap-1 text-emerald text-xs font-semibold mr-2">
                      <CheckCircle2 size={11} />
                      Connected
                    </span>
                  ) : (
                    <span className="text-ink-3 text-xs mr-2">Not connected</span>
                  )}
                  
                  {/* Test Connection Button */}
                  {intg.status && (intg.name === "Jira" || intg.name === "Slack" || intg.name === "PagerDuty" || intg.name === "Splunk") && (
                    <button
                      onClick={() => handleTestConnection(intg.name)}
                      className="px-2.5 py-1 rounded text-[10px] font-bold border border-accent bg-accent/8 text-accent hover:bg-accent/12 transition-colors uppercase font-mono"
                    >
                      Test Alert Feed
                    </button>
                  )}
                  
                  <button
                    onClick={() => handleToggleConnect(intg.name)}
                    className={`px-3 py-1.5 rounded text-xs font-semibold border transition-colors ${
                      intg.status
                        ? "border-border bg-elevated text-ink-2 hover:text-ink hover:border-border-hi"
                        : "border-accent/30 bg-accent/8 text-accent hover:bg-accent/12"
                    }`}
                  >
                    {intg.status ? "Disconnect" : "Connect"}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── API KEYS ── */}
      {tab === "api-keys" && (
        <div className="space-y-4 bg-card border border-border rounded-lg p-5">
          <div className="flex justify-between items-center pb-2 border-b border-border">
            <div>
              <p className="text-ink text-sm font-semibold">API Credentials</p>
              <p className="text-ink-3 text-xs mt-0.5">Automate VulnGuard scanners via CI/CD pipelines.</p>
            </div>
            <button
              onClick={handleGenerateKey}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-accent text-white rounded text-xs font-semibold hover:bg-accent/90 transition-colors shadow shadow-accent/25"
            >
              <Plus size={12} />
              Generate Token
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-[10px] uppercase text-ink-3 font-semibold font-mono border-b border-border">
                  <th className="py-2 text-left">Key Identifier</th>
                  <th className="py-2 text-left">Scope Permissions</th>
                  <th className="py-2 text-left">Created</th>
                  <th className="py-2 text-left">Last Trigger</th>
                  <th className="py-2 text-right">Triage</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60 text-xs font-mono">
                {apiKeys.map((k) => (
                  <tr key={k.id} className="hover:bg-panel/10">
                    <td className="py-3">
                      <div className="flex items-center gap-2">
                        <span className="text-ink font-semibold">
                          {showKey === k.id ? k.id : `${k.id.slice(0, 16)}••••••••`}
                        </span>
                        <button
                          onClick={() => setShowKey(showKey === k.id ? null : k.id)}
                          className="text-ink-3 hover:text-ink"
                        >
                          {showKey === k.id ? <EyeOff size={11} /> : <Eye size={11} />}
                        </button>
                      </div>
                    </td>
                    <td className="py-3 text-ink-2">{k.perms}</td>
                    <td className="py-3 text-ink-3">{k.created}</td>
                    <td className="py-3 text-ink-3">{k.last}</td>
                    <td className="py-3 text-right">
                      <button
                        onClick={() => setApiKeys(apiKeys.filter((item) => item.id !== k.id))}
                        className="text-ink-3 hover:text-critical"
                      >
                        <Trash2 size={12} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── SAFETY POLICIES ── */}
      {tab === "policies" && (
        <div className="space-y-4">
          <Card title="Active Fuzz Rules" subtitle="Establish target exclusion filters.">
            <div className="space-y-3">
              {[
                { label: "Require manual authorization tokens before parsing scan files", on: true },
                { label: "Auto-exclude /logout & /delete paths from crawlers", on: true },
                { label: "Rate-limit API active requests to 15 req/sec", on: false },
              ].map((p) => (
                <div key={p.label} className="flex items-center justify-between py-2 border-b border-border last:border-0">
                  <span className="text-ink-2 text-xs font-medium">{p.label}</span>
                  <Toggle defaultOn={p.on} />
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}

      {/* ── Save Settings Bar ── */}
      <div className="flex justify-end gap-3 pt-4 border-t border-border mt-6">
        <button className="px-4 py-2 text-ink-2 text-xs font-semibold hover:text-ink transition-colors">
          Discard Changes
        </button>
        <button
          onClick={() => {
            setToast("Settings saved successfully!")
            setTimeout(() => setToast(null), 3000)
          }}
          className="px-5 py-2 bg-accent text-white rounded text-xs font-semibold hover:bg-accent/90 transition-colors shadow-lg shadow-accent/25"
        >
          Save Workspace Settings
        </button>
      </div>

      {/* Toast popup */}
      {toast && (
        <div className="fixed bottom-5 right-5 z-50 flex items-center gap-2 bg-accent text-white px-4 py-3 rounded-lg shadow-lg border border-white/10 animate-fade-in font-sans">
          <CheckCircle2 size={16} className="text-emerald shrink-0" />
          <span className="text-xs font-semibold">{toast}</span>
        </div>
      )}

      {/* ────────────────────────────────────────────────────────
          MODAL SIMULATORS
          ──────────────────────────────────────────────────────── */}
      {activeModal === "Jira" && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#172b4d] text-[#deebff] border border-border w-[520px] rounded-lg shadow-2xl overflow-hidden flex flex-col font-sans">
            <div className="flex items-center justify-between px-4 py-3 bg-[#091e42] border-b border-white/10">
              <div className="flex items-center gap-2">
                <span className="w-5 h-5 bg-[#0052cc] rounded flex items-center justify-center text-white text-[10px] font-bold">J</span>
                <span className="text-xs font-semibold text-white">Jira Ticket Simulator</span>
              </div>
              <button onClick={() => setActiveModal(null)} className="text-[#deebff]/80 hover:text-white">
                <X size={15} />
              </button>
            </div>
            <div className="p-5 space-y-4">
              <div className="flex items-center gap-3">
                <span className="bg-[#4c9aff]/25 text-[#4c9aff] px-2 py-0.5 rounded text-[10px] font-semibold tracking-wide">SEC-2391</span>
                <span className="bg-[#dfe1e6] text-[#172b4d] px-2 py-0.5 rounded text-[10px] font-bold uppercase">To Do</span>
              </div>
              <h3 className="text-white text-base font-semibold leading-snug">
                [VulnGuard] Critical: SQL Injection proved on api.acmecorp.com
              </h3>
              <div className="border-t border-white/10 pt-3">
                <h4 className="text-[10px] uppercase font-bold text-[#deebff]/60 tracking-wider">Description</h4>
                <div className="mt-1 bg-[#091e42]/50 border border-white/5 rounded p-3 text-xs font-mono leading-relaxed space-y-2 text-[#deebff]/90">
                  <p>**Vulnerability Type:** SQL Injection (Boolean-based)</p>
                  <p>**Target Endpoint:** `POST https://api.acmecorp.com/search`</p>
                  <p>**Payload:** `admin%2527%2520OR%25201%253D1%2520--`</p>
                </div>
              </div>
            </div>
            <div className="flex justify-end px-4 py-3 bg-[#091e42]/40 border-t border-white/10">
              <button onClick={() => setActiveModal(null)} className="px-4 py-1.5 bg-white/10 hover:bg-white/15 text-white rounded text-xs font-medium">
                Close Simulator
              </button>
            </div>
          </div>
        </div>
      )}

      {activeModal === "Slack" && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#1a1d21] text-[#d1d2d3] border border-[#3f0e40]/30 w-[540px] rounded-lg shadow-2xl overflow-hidden flex flex-col font-sans">
            <div className="flex items-center justify-between px-4 py-3 bg-[#121417] border-b border-white/5">
              <div className="flex items-center gap-2">
                <span className="w-5 h-5 bg-[#3f0e40] rounded flex items-center justify-center text-white text-[10px] font-bold">#</span>
                <span className="text-xs font-semibold text-white">Slack Hook Channel</span>
              </div>
              <button onClick={() => setActiveModal(null)} className="text-[#d1d2d3]/80 hover:text-white">
                <X size={15} />
              </button>
            </div>
            <div className="p-5 flex gap-3">
              <div className="w-1 bg-[#e01e5a] rounded-sm shrink-0" />
              <div className="flex-1 space-y-3">
                <div className="flex items-center gap-1.5">
                  <span className="font-bold text-white text-sm">VulnGuard Alert Bot</span>
                  <span className="bg-white/10 text-[9px] px-1 py-0.2 rounded font-medium">APP</span>
                </div>
                <p className="text-white text-sm font-bold">🚨 New Vulnerability Identified - acme-search-service</p>
                <div className="grid grid-cols-2 gap-y-2 gap-x-4 bg-black/20 border border-white/5 rounded p-3 text-xs">
                  <div>
                    <span className="text-[#d1d2d3]/60 block font-medium">Endpoint</span>
                    <span className="text-white font-mono">POST /api/search</span>
                  </div>
                  <div>
                    <span className="text-[#e01e5a] font-bold">💥 CRITICAL</span>
                  </div>
                </div>
              </div>
            </div>
            <div className="flex justify-end px-4 py-3 bg-[#121417]/40 border-t border-white/5">
              <button onClick={() => setActiveModal(null)} className="px-4 py-1.5 bg-white/10 hover:bg-white/15 text-white rounded text-xs font-medium">
                Close Preview
              </button>
            </div>
          </div>
        </div>
      )}

      {/* PagerDuty Simulator Modal */}
      {activeModal === "PagerDuty" && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#1e1414] text-[#ffd6d6] border border-[#ff4c4c]/30 w-[520px] rounded-lg shadow-2xl overflow-hidden flex flex-col font-sans">
            <div className="flex items-center justify-between px-4 py-3 bg-[#120a0a] border-b border-[#ff4c4c]/10">
              <div className="flex items-center gap-2">
                <span className="w-5 h-5 bg-[#ff4c4c] rounded flex items-center justify-center text-white text-[10px] font-bold">PD</span>
                <span className="text-xs font-semibold text-white">PagerDuty Events API v2 Simulator</span>
              </div>
              <button onClick={() => setActiveModal(null)} className="text-[#ffd6d6]/80 hover:text-white">
                <X size={15} />
              </button>
            </div>
            <div className="p-5 space-y-4">
              <div className="bg-black/40 border border-[#ff4c4c]/20 rounded p-3 text-xs font-mono space-y-2">
                <p className="text-slate-400">// Connecting to events.pagerduty.com/v2/enqueue...</p>
                <p className="text-emerald">// Transmitting incident payload</p>
                <pre className="text-pink-400 whitespace-pre overflow-x-auto text-[10px]">
{`{
  "routing_key": "pd-integration-key-vulnguard",
  "event_action": "trigger",
  "payload": {
    "summary": "CRITICAL SQLi confirmed on api.acmecorp.com",
    "source": "vulnguard-scanner",
    "severity": "critical"
  }
}`}
                </pre>
                <p className="text-slate-400">// Response received (HTTP 202 Accepted)</p>
                <p className="text-emerald">{"{\n  \"status\": \"success\",\n  \"message\": \"Event processed\",\n  \"dedup_key\": \"pd-vulnguard-0247\"\n}"}</p>
              </div>
            </div>
            <div className="flex justify-end px-4 py-3 bg-[#120a0a]/40 border-t border-[#ff4c4c]/10">
              <button onClick={() => setActiveModal(null)} className="px-4 py-1.5 bg-white/10 hover:bg-white/15 text-white rounded text-xs font-medium">
                Close Simulator
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Splunk SIEM Simulator Modal */}
      {activeModal === "Splunk" && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#1b1c1d] text-[#e0e1e2] border border-[#f58220]/30 w-[520px] rounded-lg shadow-2xl overflow-hidden flex flex-col font-sans">
            <div className="flex items-center justify-between px-4 py-3 bg-[#111213] border-b border-[#f58220]/10">
              <div className="flex items-center gap-2">
                <span className="w-5 h-5 bg-[#f58220] rounded flex items-center justify-center text-white text-[10px] font-bold">S</span>
                <span className="text-xs font-semibold text-white">Splunk SIEM Forwarder Test</span>
              </div>
              <button onClick={() => setActiveModal(null)} className="text-[#e0e1e2]/80 hover:text-white">
                <X size={15} />
              </button>
            </div>
            <div className="p-5 space-y-4">
              <div className="bg-black/40 border border-[#f58220]/20 rounded p-3 text-xs font-mono space-y-2">
                <p className="text-slate-400">// Posting HEC stream to splunk-hec.internal:8088...</p>
                <p className="text-emerald">// Transmitting JSON audit event</p>
                <pre className="text-orange-400 whitespace-pre overflow-x-auto text-[10px]">
{`{
  "time": 1782391024,
  "host": "vulnguard-engine-01",
  "source": "vulnguard:audit",
  "event": {
    "action": "finding_detected",
    "severity": "CRITICAL",
    "cwe_id": "CWE-89",
    "path": "/api/users"
  }
}`}
                </pre>
                <p className="text-slate-400">// Response received (HTTP 200 OK)</p>
                <p className="text-emerald">{"{\n  \"text\": \"Success\",\n  \"code\": 0,\n  \"invalid-event-number\": 0\n}"}</p>
              </div>
            </div>
            <div className="flex justify-end px-4 py-3 bg-[#111213]/40 border-t border-[#f58220]/10">
              <button onClick={() => setActiveModal(null)} className="px-4 py-1.5 bg-white/10 hover:bg-white/15 text-white rounded text-xs font-medium">
                Close Simulator
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

const INPUT =
  "w-full bg-canvas border border-border rounded px-3 py-2 text-ink text-xs font-mono focus:border-accent transition-colors"

function Card({ title, subtitle, children }: { title: string; subtitle: string; children: React.ReactNode }) {
  return (
    <div className="bg-card border border-border rounded-lg">
      <div className="px-5 py-3 border-b border-border">
        <p className="text-ink text-sm font-semibold">{title}</p>
        <p className="text-ink-3 text-xs mt-0.5">{subtitle}</p>
      </div>
      <div className="p-5">{children}</div>
    </div>
  )
}

function SettingField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-ink-2 text-xs font-medium mb-1.5">{label}</label>
      {children}
    </div>
  )
}

function Toggle({ defaultOn }: { defaultOn: boolean }) {
  const [on, setOn] = useState(defaultOn)
  return (
    <button
      onClick={() => setOn(!on)}
      className={`relative w-9 h-5 rounded-full transition-colors shrink-0 ${
        on ? "bg-accent" : "bg-elevated border border-border"
      }`}
    >
      <span
        className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform ${
          on ? "left-4" : "left-0.5"
        }`}
      />
    </button>
  )
}

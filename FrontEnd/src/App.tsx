import { useState } from "react"
import {
  LayoutDashboard,
  Target,
  Cpu,
  Terminal,
  Radio,
  Crosshair,
  Code2,
  GitCompare,
  ShieldAlert,
  ShieldCheck,
  KeyRound,
  Satellite,
  FolderOpen,
  FileText,
  Zap,
  Settings,
  Search,
  Bell,
  BarChart3,
  CalendarClock,
} from "lucide-react"
import Overview from "./pages/Overview"
import ScanSetup from "./pages/ScanSetup"
import AutomatedScan from "./pages/AutomatedScan"
import ManualTesting from "./pages/ManualTesting"
import ProxyHistory from "./pages/ProxyHistory"
import Intruder from "./pages/Intruder"
import Decoder from "./pages/Decoder"
import Comparer from "./pages/Comparer"
import Findings from "./pages/Findings"
import Evidence from "./pages/Evidence"
import Reports from "./pages/Reports"
import SettingsPage from "./pages/Settings"
import ProofMode from "./pages/ProofMode"
import NucleiCve from "./pages/NucleiCve"
import RiskPosture from "./pages/RiskPosture"
import AuthorizationMatrix from "./pages/AuthorizationMatrix"
import OobMonitor from "./pages/OobMonitor"
import ScheduledScans from "./pages/ScheduledScans"

export type Page = "overview" | "scan-setup" | "automated-scan" | "scheduled-scans" | "manual-testing" | "proxy-history" | "intruder" | "decoder" | "comparer" | "findings" | "evidence" | "proof-mode" | "auth-matrix" | "oob-monitor" | "nuclei-cve" | "risk-posture" | "reports" | "settings"

const NAV: { id: Page; label: string; Icon: React.ElementType; badge?: string }[] =
  [
    { id: "overview", label: "Overview", Icon: LayoutDashboard },
    { id: "scan-setup", label: "Scan Setup", Icon: Target },
    { id: "automated-scan", label: "Automated Scan", Icon: Cpu, badge: "0" },
    { id: "scheduled-scans", label: "Scheduled Scans", Icon: CalendarClock },
    { id: "manual-testing", label: "Repeater", Icon: Terminal },
    { id: "proxy-history", label: "Proxy History", Icon: Radio },
    { id: "intruder", label: "Intruder", Icon: Crosshair },
    { id: "decoder", label: "Decoder", Icon: Code2 },
    { id: "comparer", label: "Comparer", Icon: GitCompare },
    { id: "findings", label: "Findings", Icon: ShieldAlert, badge: "0" },
    { id: "evidence", label: "Evidence", Icon: FolderOpen },
    { id: "proof-mode", label: "Proof Mode", Icon: ShieldCheck },
    { id: "auth-matrix", label: "Auth Matrix", Icon: KeyRound },
    { id: "oob-monitor", label: "OOB Monitor", Icon: Satellite },
    { id: "nuclei-cve", label: "Nuclei & CVE", Icon: Zap },
    { id: "risk-posture", label: "Risk Posture", Icon: BarChart3 },
    { id: "reports", label: "Reports", Icon: FileText },
    { id: "settings", label: "Settings", Icon: Settings },
  ]

export interface PageProps {
  onNavigate: (page: Page) => void
}

export default function App() {
  const [active, setActive] = useState<Page>("overview")
  const [findingsCount, setFindingsCount] = useState(0)
  const [scanActive, setScanActive] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [repeaterRequest, setRepeaterRequest] = useState<any>(null)
  const [activeScanId, setActiveScanId] = useState<string | null>(null)

  const handleNavigate = (page: string, subTab?: string) => {
    setActive(page as Page)
  }

  const handleSendToRepeater = (reqData: any) => {
    setRepeaterRequest(reqData)
    setActive("manual-testing")
  }

  return (
    <div className="flex h-screen overflow-hidden bg-canvas font-sans">
      {/* ── Sidebar ─────────────────────────────────────── */}
      <aside className="w-[220px] shrink-0 flex flex-col bg-panel border-r border-border">
        {/* Brand */}
        <div className="h-12 px-5 flex items-center border-b border-border gap-2.5">
          <svg viewBox="0 0 24 24" width="20" height="20" fill="none" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <defs>
              <linearGradient id="logo-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#a5b4fc" />
                <stop offset="100%" stopColor="#5a57ff" />
              </linearGradient>
            </defs>
            {/* Shield */}
            <path
              d="M 14.5,3.5 L 21,6.5 L 21,12.5 C 21,16.5 17.5,18.5 14.5,20.5 C 11.5,18.5 8,16.5 8,12.5 L 8,6.5 Z"
              stroke="url(#logo-grad)"
            />
            {/* Top Node */}
            <circle cx="5" cy="5" r="1.2" fill="url(#logo-grad)" stroke="url(#logo-grad)" strokeWidth="0.5" />
            <path d="M 5,6.2 L 5,9 L 8,9" stroke="url(#logo-grad)" />

            {/* Middle Node */}
            <circle cx="3.5" cy="11.5" r="1.2" fill="url(#logo-grad)" stroke="url(#logo-grad)" strokeWidth="0.5" />
            <path d="M 4.7,11.5 L 8,11.5" stroke="url(#logo-grad)" />

            {/* Bottom Node */}
            <circle cx="6" cy="18" r="1.2" fill="url(#logo-grad)" stroke="url(#logo-grad)" strokeWidth="0.5" />
            <path d="M 6,16.8 L 6,14 L 8,14" stroke="url(#logo-grad)" />

            {/* Magnifier */}
            <circle cx="17.5" cy="14.5" r="3.5" fill="#0f1420" stroke="url(#logo-grad)" />
            <path d="M 20,17 L 23,20" stroke="url(#logo-grad)" />
            <path d="M 18,12.5 A 1.8,1.8 0 0,1 19, 14" stroke="url(#logo-grad)" />
          </svg>
          <span className="text-ink font-semibold text-sm tracking-[0.12em]">
            VULNGUARD
          </span>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-3 px-2 space-y-px">
          {NAV.map(({ id, label, Icon }) => {
            const on = active === id
            let displayBadge: string | undefined = undefined
            if (id === "findings") {
              displayBadge = String(findingsCount)
            } else if (id === "automated-scan") {
              displayBadge = scanActive ? "ACTIVE" : undefined
            }

            return (
              <button
                key={id}
                onClick={() => setActive(id)}
                className={`w-full flex items-center gap-2.5 px-3 py-2 rounded text-sm transition-colors duration-100 ${
                  on
                    ? "bg-accent/10 text-accent font-medium"
                    : "text-ink-2 hover:text-ink hover:bg-elevated"
                }`}
              >
                <Icon size={14} strokeWidth={on ? 2 : 1.5} />
                <span className="flex-1 text-left">{label}</span>
                {displayBadge && (
                  <span
                    className={`font-mono text-[10px] px-1.5 py-px rounded-sm ${
                      on
                        ? "bg-accent/20 text-accent font-semibold"
                        : id === "automated-scan"
                          ? "bg-emerald/10 text-emerald border border-emerald/20 animate-pulse font-semibold"
                          : "bg-canvas text-ink-3"
                    }`}
                  >
                    {displayBadge}
                  </span>
                )}
              </button>
            )
          })}
        </nav>

        {/* User */}
        <div className="border-t border-border p-3">
          <div className="flex items-center gap-2.5 px-1">
            <div className="w-6 h-6 rounded-full bg-accent/15 flex items-center justify-center shrink-0">
              <span className="text-accent text-[10px] font-semibold">AK</span>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-ink text-xs font-medium truncate">Alex Kim</p>
              <p className="text-ink-3 text-[11px] truncate">
                Security Engineer
              </p>
            </div>
          </div>
        </div>
      </aside>

      {/* ── Main ────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Topbar */}
        <header className="h-12 shrink-0 border-b border-border bg-surface flex items-center px-5 gap-4">
          <Search size={13} className="text-ink-3 shrink-0" />
          <input
            type="text"
            placeholder="Search targets, findings, CVEs…"
            className="bg-transparent text-ink text-sm placeholder:text-ink-3 flex-1 max-w-sm"
          />
          <div className="flex-1" />
          <div className="flex items-center gap-1.5 px-2.5 py-1 bg-elevated rounded border border-border text-ink-3 text-xs font-mono">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald animate-pulse" />
            Production
          </div>
          <button className="relative p-1.5 text-ink-3 hover:text-ink transition-colors">
            <Bell size={14} />
            <span className="absolute top-0.5 right-0.5 w-1.5 h-1.5 bg-critical rounded-full" />
          </button>
        </header>

        {/* Content */}
        <main className="flex-1 overflow-y-auto bg-surface">
          {active === "overview" && (
            <Overview
              onNavigate={handleNavigate}
              findingsCount={findingsCount}
              scanActive={scanActive}
              onScanSelected={setActiveScanId}
            />
          )}
          {active === "scan-setup" && (
                      <ScanSetup
              onNavigate={handleNavigate}
              setScanActive={setScanActive}
              setScanProgress={setScanProgress}
              onScanStarted={setActiveScanId}
            />
          )}
          {active === "automated-scan" && (
                      <AutomatedScan
              onNavigate={handleNavigate}
              scanActive={scanActive}
              setScanActive={setScanActive}
              progress={scanProgress}
              setProgress={setScanProgress}
              activeScanId={activeScanId}
            />
          )}
          {active === "scheduled-scans" && <ScheduledScans />}
          {active === "manual-testing" && (
            <ManualTesting
              onNavigate={handleNavigate}
              repeaterRequest={repeaterRequest}
              setRepeaterRequest={setRepeaterRequest}
            />
          )}
          {active === "proxy-history" && (
            <ProxyHistory
              onNavigate={handleNavigate}
              onSendToRepeater={handleSendToRepeater}
            />
          )}
          {active === "intruder" && <Intruder />}
          {active === "decoder" && <Decoder />}
          {active === "comparer" && <Comparer />}
          {active === "findings" && (
            <Findings
              onNavigate={handleNavigate}
              findingsCount={findingsCount}
              setFindingsCount={setFindingsCount}
            />
          )}
          {active === "evidence" && (
            <Evidence
              onNavigate={handleNavigate}
              onSendToRepeater={handleSendToRepeater}
            />
          )}
          {active === "proof-mode" && <ProofMode />}
          {active === "auth-matrix" && <AuthorizationMatrix />}
          {active === "oob-monitor" && <OobMonitor />}
          {active === "nuclei-cve" && <NucleiCve />}
          {active === "risk-posture" && <RiskPosture />}
          {active === "reports" && (
            <Reports
              onNavigate={handleNavigate}
              findingsCount={findingsCount}
            />
          )}
          {active === "settings" && (
            <SettingsPage
              onNavigate={handleNavigate}
            />
          )}
        </main>
      </div>
    </div>
  )
}

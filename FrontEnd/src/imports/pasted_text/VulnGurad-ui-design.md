Design a premium, dark-mode frontend for a modern enterprise vulnerability scanner platform called VulnGuard. The product is a professional AppSec security workbench for security engineers, penetration testers, DevSecOps teams, and CISOs. The UI should feel like a high-end security operations platform, not a generic dashboard or a toy app. It should look polished, trustworthy, technical, and mature.

Core product identity:
- This is a vulnerability scanning and security analysis platform with automated scanning, manual testing, evidence review, report generation, and enterprise workflow support.
- The product should feel powerful, calm, and credible, similar to a hybrid of Burp Suite Enterprise, Snyk, GitHub Security, and a modern internal security platform.
- The design should be professional, minimal, and highly usable, with a serious enterprise tone.

Visual direction:
- Use a dark-first theme with a deep charcoal/blue-black background.
- Create a premium, subtle, modern look with restrained contrast and clean hierarchy.
- Avoid childish borders, exaggerated gradients, flashy animations, or overly playful UI.
- Avoid heavy glassmorphism, neon accents, or cluttered card styles.
- Use a refined visual system: soft depth, subtle panel separation, precise spacing, strong typography, and controlled shadowing.
- The interface should feel “secure, confident, and intelligent.”

Color system:
- Primary background: deep navy/charcoal black.
- Surface panels: slightly lighter dark tones for elevation.
- Accent colors: muted electric blue, cyan, and emerald for highlights.
- Severity colors should be clear and professional:
  - Critical: strong red
  - High: orange/red
  - Medium: amber
  - Low: blue/teal
  - Info: cool gray
- Keep accents subtle and intentional, not loud or playful.

Typography:
- Use a modern, technical sans-serif font such as Inter, Manrope, or Système UI.
- Strong hierarchy with clear labels, compact metadata, and high readability.
- Use clean heading sizes, dense but elegant tables, and structured content blocks.
- The interface should feel crisp, analytical, and enterprise-ready.

Layout and structure:
- Design as a desktop-first SaaS dashboard with strong left navigation and top command area.
- Use a clear app shell:
  - Left sidebar for major modules: Overview, Scan Setup, Automated Scan, Manual Testing, Findings, Reports, Evidence, Settings.
  - Top bar for global search, status, notifications, and environment context.
  - Main content area for dashboards, scan execution, results, and exploration.
  - Optional right-side detail drawer for vulnerabilities, request/response inspection, or evidence.
- Keep the layout structured, spacious, and easy to scan.

Key screens to design:
1. Landing / Overview Dashboard
   - Executive summary of security posture
   - Scan health, recent activity, severity distribution, and important alerts
   - Clean KPI cards and trend visuals
   - Include “Start Scan” action and quick access to recent targets

2. Scan Setup / New Scan
   - Target URL, auth profile, scan type, depth, timeout, safety mode
   - Form should feel precise and professional, not overly long or cluttered
   - Include progressive sections and smart defaults
   - Support both automated scan and manual scan entry points

3. Automated Scan Workspace
   - Scan progress timeline
   - Live status panel with stages like discovery, crawling, exploitation, analysis
   - Findings list with severity badge and status
   - Panels for metrics, categories, and evidence summary
   - A strong “workbench” feel, like a secure operations console

4. Manual Testing Workbench
   - Request history, repeater, intruder-style controls, response viewer, and request editing
   - Show a clean split-pane layout for request/response analysis
   - Include a strong inspection experience for security analysts

5. Findings / Vulnerability Detail View
   - List of vulnerabilities with severity, confidence, category, and status
   - Detailed drawer for issue explanation, evidence, proof, affected parameter, recommendation, and remediation guidance
   - Make the issue detail experience feel serious and investigative

6. Evidence Corpus / Request History
   - Structured view of requests, responses, proof details, and sanitized evidence
   - Clean, searchable, table-driven interface with technical detail
   - Feel like a professional forensic workspace

7. Reports / Export Center
   - Summary dashboard with export actions, findings count, summary cards, and downloadable report states
   - Professional report style with strong readability and trust

8. Settings / Enterprise Configuration
   - Auth settings, integrations, API keys, security configurations, policies
   - Structured but compact panels and clear state management

Interaction and motion design:
- Use subtle, non-flashy transitions.
- Motion should be smooth, minimal, and professional.
- Avoid bounce, elastic effects, or playful micro-interactions.
- Preferred motion: gentle fade, subtle slide, soft opacity changes, and precise hover feedback.
- Animations should support clarity, not decoration.

Component style:
- Cards should be clean and understated, with low visual noise.
- Tables should be precise, minimal, and technical.
- Buttons should be simple and high confidence.
- Use clear states for loading, empty, error, success, and disabled conditions.
- Create reusable, modular components for cards, tables, panels, badges, tabs, drawers, filters, and status pills.

Content and data behavior:
- The UI should make it easy to understand scan status, severity trends, open issues, and next actions.
- Prioritize technical clarity and operational usefulness.
- Show important information without overwhelming the user.
- Use strong visual hierarchy for high severity items and critical actions.

Design principles:
- Professional
- Secure
- Calm
- Technical
- Enterprise-grade
- Efficient
- Minimal but expressive
- Clean, modern, and trustworthy

Deliverables:
- Design a full dark-mode UI system for this product
- Create a cohesive set of screens for the core workflows
- Define a polished component library
- Ensure the design feels premium and ready for implementation in React/Tailwind
- Make the experience feel like a serious cybersecurity platform, not a generic dashboard
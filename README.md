# Centrix

Centrix is a web application for authorised dynamic application security testing (DAST). It is an early MVP intended for systems you own or are explicitly permitted to test.

## Run locally

Backend:

```powershell
cd backend
py -3 -m pip install -r requirements.txt
py -3 -m uvicorn main:app --reload --port 8000
```

Frontend, in another terminal:

```powershell
cd FrontEnd
npm ci
npm run dev
```

The frontend runs at `http://localhost:8443`; the API documentation is at `http://localhost:8000/docs`.

To run the built application in containers, use `docker compose up --build`, then open `http://localhost:8080`.

## Safety model

- Every scan requires an explicit authorization confirmation.
- Only `http` and `https` targets are accepted.
- Targets resolving to localhost, private, link-local, or reserved IP addresses are rejected.
- Crawling stays on the target origin, honours configured scope patterns, does not follow redirects, and can honour `robots.txt` when enabled. Authorised DAST scans default to full in-scope coverage.
- Scan settings limit concurrency and the total request budget.

Never use Centrix against a target without written permission. Test detection rules against a deliberately vulnerable local training environment or a designated staging system.

## Current capabilities

- Target validation: DNS, reachability, TLS, and robots discovery
- Controlled endpoint discovery and crawling
- Header checks, reflected XSS, basic SQLi, and path traversal checks
- Findings with CWE/CVSS mapping and JSON/HTML reports
- Persistent local scan, finding, report, and log storage in SQLite

## Next engineering milestones

- Replace SQLite with PostgreSQL and use Redis-backed workers for multi-process deployments.
- Add authenticated scans, OpenAPI import, reliable form handling, and richer evidence capture.
- Add integration tests against dedicated vulnerable applications and CI checks.

import asyncio
import json
import socket
import unittest
from datetime import datetime, timedelta

import aiohttp
from aiohttp import web

from api.models import ApiImport, EvidenceArtifact, Finding, FindingStatus, ScanConfig, ScanState, Severity
from api.routes.integrations import _builtin_template_match
from api.routes.imports import _extract
from api.routes.reports import _build_junit_report, _build_sarif_report
from api.routes import schedules
from reporting.pdf_report import build_centrix_pdf_report
from scanner import engine
from scanner.manual.capture_proxy import CaptureProxyConfig, CentrixCaptureProxy
from scanner.browser_workflows import execute_browser_workflow, load_browser_workflows
from scanner.sequence_runner import run_sequence_workflows, sequence_requests_and_urls
from scanner.stages import analyze, passive, wraith_advanced
from scanner.stages import probe as probe_stage


async def _noop_log(_message: str) -> None:
    return None


def _free_tcp_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    try:
        return int(sock.getsockname()[1])
    finally:
        sock.close()


class WraithPortTests(unittest.TestCase):
    def test_openapi_import_extracts_methods_and_urls(self):
        payload = ApiImport(
            format="openapi",
            document={
                "servers": [{"url": "https://example.com"}],
                "paths": {
                    "/api/users": {"get": {}, "post": {}, "parameters": []},
                    "/api/users/{id}": {"delete": {}},
                },
            },
        )

        endpoints = _extract(payload)

        self.assertIn({"method": "GET", "url": "https://example.com/api/users", "source": "openapi", "name": "GET /api/users"}, endpoints)
        self.assertIn({"method": "POST", "url": "https://example.com/api/users", "source": "openapi", "name": "POST /api/users"}, endpoints)
        self.assertIn({"method": "DELETE", "url": "https://example.com/api/users/1", "source": "openapi", "name": "DELETE /api/users/{id}"}, endpoints)

    def test_openapi_import_extracts_query_and_body_examples(self):
        payload = ApiImport(
            format="openapi",
            document={
                "servers": [{"url": "https://example.com"}],
                "paths": {
                    "/api/search": {
                        "post": {
                            "operationId": "searchUsers",
                            "parameters": [{"name": "q", "in": "query", "schema": {"type": "string", "example": "admin"}}],
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {"role": {"type": "string", "example": "admin"}},
                                        }
                                    }
                                }
                            },
                        }
                    },
                },
            },
        )

        endpoints = _extract(payload)

        self.assertIn({
            "method": "POST",
            "url": "https://example.com/api/search?q=admin",
            "source": "openapi",
            "name": "searchUsers",
            "headers": {"Content-Type": "application/json"},
            "body": {"role": "admin"},
            "content_type": "application/json",
        }, endpoints)

    def test_postman_import_resolves_variables_headers_and_body(self):
        payload = ApiImport(
            format="postman",
            document={
                "variable": [{"key": "baseUrl", "value": "https://example.com"}, {"key": "token", "value": "abc"}],
                "item": [{
                    "name": "Create user",
                    "request": {
                        "method": "POST",
                        "url": "{{baseUrl}}/api/users",
                        "header": [{"key": "Authorization", "value": "Bearer {{token}}"}, {"key": "Content-Type", "value": "application/json"}],
                        "body": {"mode": "raw", "raw": "{\"name\":\"centrix\"}"},
                    },
                }],
            },
        )

        endpoints = _extract(payload)

        self.assertIn({
            "method": "POST",
            "url": "https://example.com/api/users",
            "source": "postman",
            "name": "Create user",
            "headers": {"Authorization": "Bearer abc", "Content-Type": "application/json"},
            "body": {"name": "centrix"},
            "content_type": "application/json",
        }, endpoints)

    def test_graphql_import_builds_operations_from_introspection(self):
        payload = ApiImport(
            format="graphql",
            base_url="https://example.com/graphql",
            document={
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "types": [
                            {"name": "Query", "fields": [{"name": "viewer", "args": [], "type": {"name": "User"}}]},
                            {"name": "User", "fields": [{"name": "id", "type": {"name": "ID"}}, {"name": "email", "type": {"name": "String"}}]},
                        ],
                    }
                }
            },
        )

        endpoints = _extract(payload)

        self.assertIn({
            "method": "POST",
            "url": "https://example.com/graphql",
            "source": "graphql",
            "name": "GraphQL query: viewer",
            "headers": {"Content-Type": "application/json"},
            "body": {"query": "query { viewer { id email } }"},
            "content_type": "application/json",
        }, endpoints)

    def test_imported_json_requests_become_probeable_api_forms(self):
        forms = engine._forms_from_imported_requests([{
            "method": "POST",
            "url": "https://example.com/api/users",
            "headers": {"Content-Type": "application/json", "Content-Length": "999"},
            "content_type": "application/json",
            "body": {"user": {"id": 1, "name": "centrix"}, "role": "user"},
        }])

        self.assertEqual(forms[0]["action"], "https://example.com/api/users")
        self.assertIn({"name": "user.id", "type": "number", "value": "1"}, forms[0]["fields"])
        self.assertNotIn("Content-Length", forms[0]["headers"])

        kwargs = probe_stage._submission_kwargs(forms[0], {"user.name": "<script>alert(1)</script>", "role": "admin"})

        self.assertEqual(kwargs["headers"], {"Content-Type": "application/json"})
        self.assertEqual(kwargs["json"]["user"]["name"], "<script>alert(1)</script>")
        self.assertEqual(kwargs["json"]["role"], "admin")

    def test_schedule_next_run_calculation(self):
        now = datetime(2026, 8, 5, 12, 0, 0)

        self.assertEqual(schedules._next_run("hourly", now), (now + timedelta(hours=1)).isoformat())
        self.assertEqual(schedules._next_run("daily", now), (now + timedelta(days=1)).isoformat())
        self.assertEqual(schedules._next_run("weekly", now), (now + timedelta(days=7)).isoformat())
        self.assertEqual(schedules._next_run("once", now), "")

    def test_sequence_workflow_extracts_variables_and_builds_scan_inputs(self):
        async def run_case():
            app = web.Application()

            async def login(_request):
                return web.json_response({"token": "token-123"})

            async def profile(request):
                if request.headers.get("Authorization") != "Bearer token-123":
                    return web.json_response({"error": "unauthorized"}, status=401)
                return web.json_response({"id": "user-1"})

            app.router.add_post("/login", login)
            app.router.add_get("/api/profile", profile)
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            base_url = f"http://127.0.0.1:{port}"
            try:
                results = await run_sequence_workflows({
                    "name": "login-profile",
                    "steps": [
                        {"name": "login", "method": "POST", "url": "/login", "json": {"username": "alice"}, "extract": {"token": {"jsonpath": "$.token"}}, "assertions": [{"status_code": 200}]},
                        {"name": "profile", "method": "GET", "url": "/api/profile", "headers": {"Authorization": "Bearer {{token}}"}, "assertions": [{"jsonpath": "$.id", "equals": "user-1"}]},
                        {"name": "delete", "method": "DELETE", "url": "/api/profile"},
                    ],
                }, base_url=base_url, safety_mode="safe", timeout=5)
            finally:
                await runner.cleanup()
            return results

        results = asyncio.run(run_case())
        urls, forms, evidence = sequence_requests_and_urls(results)

        self.assertEqual(results[0].status, "succeeded")
        self.assertEqual(results[0].variables["token"], "token-123")
        self.assertEqual([step.status for step in results[0].steps], ["executed", "executed", "skipped"])
        self.assertTrue(any(url.endswith("/api/profile") for url in urls))
        self.assertTrue(any(form["source"] == "sequence-workflow" for form in forms))
        self.assertEqual(len(evidence), 2)

    def test_browser_workflow_executes_wraith_style_steps(self):
        class FakeLocator:
            def __init__(self, page, selector):
                self.page = page
                self.selector = selector

            @property
            def first(self):
                return self

            async def click(self, **_kwargs):
                self.page.actions.append(("click", self.selector))

            async def fill(self, value, **_kwargs):
                self.page.actions.append(("fill", self.selector, value))

            async def press(self, key, **_kwargs):
                self.page.actions.append(("press", self.selector, key))

            async def check(self, **_kwargs):
                self.page.actions.append(("check", self.selector))

            async def uncheck(self, **_kwargs):
                self.page.actions.append(("uncheck", self.selector))

            async def select_option(self, value, **_kwargs):
                self.page.actions.append(("select", self.selector, value))

        class FakePage:
            def __init__(self):
                self.url = "https://example.com/"
                self.actions = []

            def locator(self, selector):
                return FakeLocator(self, selector)

            async def goto(self, url, **_kwargs):
                self.url = url
                self.actions.append(("goto", url))

            async def wait_for_selector(self, selector, **_kwargs):
                self.actions.append(("wait_for_selector", selector))

            async def wait_for_timeout(self, timeout):
                self.actions.append(("wait_for_timeout", timeout))

            async def wait_for_url(self, url, **_kwargs):
                self.actions.append(("wait_for_url", url))

            async def evaluate(self, script, arg=None):
                self.actions.append(("evaluate", script, arg))

        workflows = load_browser_workflows({
            "workflows": [{
                "name": "login-sequence",
                "steps": [
                    {"action": "goto", "url": "/auth/login"},
                    {"action": "fill", "selector": "#user", "value": "admin"},
                    {"action": "fill", "selector": "#pass", "value": "admin123"},
                    {"action": "click", "selector": "button[type=submit]"},
                    {"action": "wait", "selector": "#dashboard"},
                    {"action": "set_storage", "storage": "localStorage", "key": "token", "value": "abc123"},
                ],
            }]
        })
        page = FakePage()

        result = asyncio.run(execute_browser_workflow(page, workflows[0], base_url="https://example.com", timeout_ms=1000))

        self.assertEqual(result.status, "succeeded")
        self.assertEqual(result.final_url, "https://example.com/auth/login")
        self.assertIn(("fill", "#user", "admin"), page.actions)
        self.assertIn(("click", "button[type=submit]"), page.actions)
        self.assertEqual(page.actions[-1], ("evaluate", "(args) => window[args.storage].setItem(args.key, args.value)", {"storage": "localStorage", "key": "token", "value": "abc123"}))

    def test_capture_proxy_records_in_scope_http_exchange(self):
        async def run_case():
            app = web.Application()

            async def hello(request):
                return web.json_response({"ok": True, "path": request.path})

            app.router.add_get("/hello", hello)
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            upstream_port = site._server.sockets[0].getsockname()[1]
            target = f"http://127.0.0.1:{upstream_port}"
            proxy_port = _free_tcp_port()
            saved: list[dict] = []

            async def save_payload(payload):
                saved.append(payload)
                return payload

            def corpus_factory(request, response, note=""):
                return {
                    "id": "REQ-TEST",
                    "scan_id": request.scan_id,
                    "method": request.method,
                    "url": request.url,
                    "request_headers": request.headers,
                    "request_body": request.body or "",
                    "response": response or {},
                    "status": response.get("status") if response else None,
                    "note": note,
                    "source": "manual",
                }

            class ScanStub:
                config = type("ConfigStub", (), {"authorized": True, "target": target, "scope": []})()

            async def get_scan(_scan_id):
                return ScanStub()

            proxy = CentrixCaptureProxy()
            try:
                status = proxy.start(
                    config=CaptureProxyConfig(host="127.0.0.1", port=proxy_port, scan_id="SCN-PROXY"),
                    save_payload=save_payload,
                    corpus_factory=corpus_factory,
                    scan_resolver=get_scan,
                )
                self.assertTrue(status["running"])
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"{target}/hello", proxy=f"http://127.0.0.1:{proxy_port}") as response:
                        body = await response.json()
                        self.assertEqual(response.status, 200)
                        self.assertTrue(body["ok"])
            finally:
                proxy.stop()
                await runner.cleanup()
            return saved, proxy.status()

        saved, status = asyncio.run(run_case())

        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]["source"], "proxy")
        self.assertEqual(saved[0]["status"], 200)
        self.assertTrue(saved[0]["url"].endswith("/hello"))
        self.assertFalse(status["running"])

    def test_capture_proxy_tunnels_in_scope_https_connect(self):
        async def run_case():
            async def echo(reader, writer):
                data = await reader.read(64)
                writer.write(b"echo:" + data)
                await writer.drain()
                writer.close()

            upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
            upstream_port = upstream.sockets[0].getsockname()[1]
            target = f"https://127.0.0.1:{upstream_port}/"
            proxy_port = _free_tcp_port()

            async def save_payload(payload):
                return payload

            def corpus_factory(request, response, note=""):
                return {"id": "REQ-TEST", "scan_id": request.scan_id, "url": request.url, "response": response, "note": note}

            class ScanStub:
                config = type("ConfigStub", (), {"authorized": True, "target": target, "scope": []})()

            async def get_scan(_scan_id):
                return ScanStub()

            proxy = CentrixCaptureProxy()
            try:
                proxy.start(
                    config=CaptureProxyConfig(host="127.0.0.1", port=proxy_port, scan_id="SCN-TUNNEL"),
                    save_payload=save_payload,
                    corpus_factory=corpus_factory,
                    scan_resolver=get_scan,
                )
                reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
                writer.write(f"CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n".encode())
                await writer.drain()
                header = await reader.readuntil(b"\r\n\r\n")
                writer.write(b"hello")
                await writer.drain()
                tunneled = await reader.read(64)
                writer.close()
                await writer.wait_closed()
                status = proxy.status()
            finally:
                proxy.stop()
                upstream.close()
                await upstream.wait_closed()
            return header, tunneled, status

        header, tunneled, status = asyncio.run(run_case())

        self.assertTrue(header.startswith(b"HTTP/1.1 200 Connection Established"))
        self.assertEqual(tunneled, b"echo:hello")
        self.assertEqual(status["https_connect_tunnel_count"], 1)
        self.assertEqual(status["https_connect_blocked_count"], 0)

    def test_passive_detector_flags_wraith_dast_surfaces(self):
        evidence = [{
            "url": "https://example.com/api/item?id=42&callback=https%3A%2F%2Fhooks.example.net%2Fhit",
            "content_type": "application/json",
            "response_headers": {
                "Set-Cookie": "session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.signature12345; Path=/",
            },
            "response_excerpt": 'window.ws="wss://example.com/socket"; {"graphql":true}',
            "forms": [{"method": "POST", "action": "https://example.com/update", "inputs": ["name"]}],
        }]

        findings = asyncio.run(passive.run(evidence, _noop_log))
        types = {finding["type"] for finding in findings}

        self.assertIn("idor", types)
        self.assertIn("ssrf", types)
        self.assertIn("jwt", types)
        self.assertIn("graphql", types)
        self.assertIn("websocket", types)
        self.assertIn("csrf", types)

    def test_passive_detector_flags_state_changing_get_form_without_csrf_token(self):
        evidence = [{
            "url": "https://example.com/vulnerabilities/csrf/",
            "content_type": "text/html",
            "response_headers": {},
            "response_excerpt": "",
            "forms": [{
                "method": "GET",
                "action": "https://example.com/vulnerabilities/csrf/",
                "inputs": ["password_new", "password_conf", "Change"],
                "fields": [
                    {"name": "password_new", "type": "password", "value": ""},
                    {"name": "password_conf", "type": "password", "value": ""},
                    {"name": "Change", "type": "submit", "value": "Change"},
                ],
            }],
        }]

        findings = asyncio.run(passive.run(evidence, _noop_log))

        self.assertTrue(any(finding["type"] == "csrf" for finding in findings))

    def test_wraith_advanced_extracts_graphql_and_websocket_targets(self):
        evidence = [{
            "url": "https://example.com/app/",
            "response_excerpt": """
                const gql = "/api/graphql";
                const socket = new WebSocket("/ws/events");
                const absolute = "wss://example.com/live";
            """,
        }]

        graphql = wraith_advanced._extract_graphql_urls("https://example.com", [], evidence)
        websockets = wraith_advanced._extract_websocket_targets("https://example.com", [], evidence)

        self.assertIn("https://example.com/api/graphql", graphql)
        self.assertIn({"url": "wss://example.com/ws/events", "messages": [{"type": "ping", "message": "centrix"}]}, websockets)
        self.assertIn({"url": "wss://example.com/live", "messages": [{"type": "ping", "message": "centrix"}]}, websockets)

    def test_passive_missing_headers_are_telemetry_only(self):
        evidence = [
            {"url": "https://example.com/a", "response_headers": {}, "response_excerpt": "", "content_type": "text/html", "forms": []},
            {"url": "https://example.com/b", "response_headers": {}, "response_excerpt": "", "content_type": "text/html", "forms": []},
        ]

        findings = asyncio.run(passive.run(evidence, _noop_log))
        missing = [finding for finding in findings if finding["type"] == "missing_header"]

        self.assertEqual(missing, [])

    def test_analyzer_suppresses_missing_header_noise(self):
        raw = [
            {"type": "missing_header", "url": "https://example.com/a", "param": "Content-Security-Policy", "payload": "", "evidence": "missing", "confidence": "Confirmed"},
            {"type": "missing_header", "url": "https://example.com/b", "param": "content-security-policy", "payload": "", "evidence": "missing", "confidence": "Confirmed"},
        ]

        findings = asyncio.run(analyze.run("SCN-TEST", raw, _noop_log))

        self.assertEqual(len(findings), 0)

    def test_report_export_helpers_emit_standard_formats(self):
        scan = type("ScanStub", (), {
            "config": type("ConfigStub", (), {"target": "https://example.com"})(),
        })()
        finding = Finding(
            id="VLN-TEST",
            scan_id="SCN-TEST",
            title="Missing Header",
            severity=Severity.low,
            category="Security Headers",
            target="https://example.com",
            parameter="Content-Security-Policy",
            confidence="Confirmed",
            status=FindingStatus.open,
            description="desc",
            recommendation="fix",
            evidence="evidence",
            cwe="CWE-693",
            cvss=5.3,
        )

        sarif = json.loads(_build_sarif_report("RPT-TEST", scan, [finding]))
        junit = _build_junit_report("RPT-TEST", scan, [finding])
        pdf_state = ScanState(id="SCN-TEST", config=ScanConfig(target="https://example.com", authorized=True))
        pdf = build_centrix_pdf_report(
            "RPT-TEST",
            pdf_state,
            [finding],
            [EvidenceArtifact(id="EV-TEST", scan_id="SCN-TEST", url="https://example.com", status_code=200)],
        )

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("<testsuite", junit)
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))

    def test_builtin_nuclei_templates_match_strong_signals_only(self):
        env = _builtin_template_match(
            "/.env",
            "https://example.com/.env",
            200,
            {"Content-Type": "text/plain"},
            "APP_KEY=abc\nDB_PASSWORD=swordfish",
        )
        blank = _builtin_template_match(
            "/.env",
            "https://example.com/.env",
            200,
            {"Content-Type": "text/plain"},
            "hello world",
        )

        self.assertIsNotNone(env)
        self.assertEqual(env["template-id"], "centrix-exposed-env")
        self.assertIsNone(blank)


if __name__ == "__main__":
    unittest.main()

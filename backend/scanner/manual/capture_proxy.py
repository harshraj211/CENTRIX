"""Local HTTP/HTTPS proxy for Centrix manual testing.

HTTP traffic is captured. HTTPS CONNECT traffic is scope-checked and tunneled so
the controlled browser can browse HTTPS targets through Centrix without failing;
full HTTPS body capture still requires the MITM certificate interception layer.
"""
from __future__ import annotations

import asyncio
from http import HTTPStatus
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

from aiohttp import ClientSession, ClientTimeout, web

from api.models import EvidenceArtifact, ManualRequest
from scanner.safety import url_in_scope

SavePayload = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]
CorpusFactory = Callable[[ManualRequest, dict[str, Any] | None, str], dict[str, Any]]
EvidenceSaver = Callable[[EvidenceArtifact], Awaitable[None]]
ScanResolver = Callable[[str], Awaitable[Any]]


@dataclass
class CaptureProxyConfig:
    host: str = "127.0.0.1"
    port: int = 8088
    scan_id: str = ""
    scope: list[str] = field(default_factory=list)


class CentrixCaptureProxy:
    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._runner: web.AppRunner | None = None
        self._server: asyncio.Server | None = None
        self._lock = threading.RLock()
        self._config = CaptureProxyConfig()
        self._save_payload: SavePayload | None = None
        self._corpus_factory: CorpusFactory | None = None
        self._scan_resolver: ScanResolver | None = None
        self._state: dict[str, Any] = {
            "running": False,
            "host": "127.0.0.1",
            "port": 8088,
            "mode": "http-capture+https-tunnel",
            "https_mitm": False,
            "started_at": None,
            "scan_id": "",
            "captured_count": 0,
            "blocked_count": 0,
            "https_connect_blocked_count": 0,
            "https_connect_tunnel_count": 0,
            "error": "",
        }

    def start(
        self,
        *,
        config: CaptureProxyConfig,
        save_payload: SavePayload,
        corpus_factory: CorpusFactory,
        scan_resolver: ScanResolver,
    ) -> dict[str, Any]:
        with self._lock:
            if self._state["running"]:
                return self.status()
            self._config = config
            self._save_payload = save_payload
            self._corpus_factory = corpus_factory
            self._scan_resolver = scan_resolver
            self._state.update({
                "running": False,
                "host": config.host,
                "port": config.port,
                "scan_id": config.scan_id,
                "started_at": datetime.utcnow().isoformat(),
                "error": "",
            })
            self._thread = threading.Thread(target=self._run_thread, daemon=True)
            self._thread.start()

        deadline = time.time() + 3
        while time.time() < deadline:
            if self._state["running"] or self._state.get("error"):
                break
            time.sleep(0.05)
        return self.status()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            loop = self._loop
            runner = self._runner
            server = self._server
            if loop and server:
                async def close_server() -> None:
                    server.close()
                    await server.wait_closed()

                future = asyncio.run_coroutine_threadsafe(close_server(), loop)
                try:
                    future.result(timeout=2)
                except Exception:
                    pass
                loop.call_soon_threadsafe(loop.stop)
            if loop and runner:
                future = asyncio.run_coroutine_threadsafe(runner.cleanup(), loop)
                try:
                    future.result(timeout=2)
                except Exception:
                    pass
                loop.call_soon_threadsafe(loop.stop)
            if self._thread:
                self._thread.join(timeout=2)
            self._thread = None
            self._loop = None
            self._runner = None
            self._server = None
            self._state["running"] = False
            return self.status()

    def status(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._state)

    def _run_thread(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            server = loop.run_until_complete(asyncio.start_server(self._handle_raw_client, self._config.host, self._config.port))
            self._server = server
            self._state["running"] = True
            loop.run_forever()
        except Exception as exc:
            self._state.update({"running": False, "error": str(exc)})
        finally:
            try:
                if self._server:
                    self._server.close()
                    loop.run_until_complete(self._server.wait_closed())
            except Exception:
                pass
            self._state["running"] = False
            loop.close()

    async def _handle_raw_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except Exception:
            writer.close()
            await self._wait_writer_closed(writer)
            return
        try:
            first, headers = self._parse_head(head)
            method, target, _version = first
        except Exception:
            await self._write_raw_response(writer, 400, b"Malformed proxy request.")
            return

        if method == "CONNECT":
            await self._handle_connect_raw(reader, writer, target, headers)
            return

        length = int(headers.get("content-length", "0") or "0")
        body = await reader.readexactly(length) if length else b""
        await self._handle_http_raw(writer, method, target, headers, body)

    async def _handle_http_raw(self, writer: asyncio.StreamWriter, method: str, raw_target: str, request_headers: dict[str, str], body_bytes: bytes) -> None:
        target_url = self._target_url_raw(raw_target, request_headers)
        if not target_url:
            self._state["blocked_count"] += 1
            await self._write_raw_response(writer, 400, b"Proxy request must include an absolute HTTP URL.")
            return

        scan = await self._scan()
        if not scan or not getattr(scan.config, "authorized", False):
            self._state["blocked_count"] += 1
            await self._write_raw_response(writer, 403, b"No authorised scan is attached to the proxy.")
            return
        if not url_in_scope(target_url, scan.config.target, scan.config.scope):
            self._state["blocked_count"] += 1
            await self._write_raw_response(writer, 403, b"Proxy request is outside the saved Centrix scan scope.")
            return

        headers = self._forward_headers(request_headers)
        started = time.perf_counter()
        try:
            async with ClientSession(timeout=ClientTimeout(total=30)) as session:
                async with session.request(
                    method,
                    target_url,
                    headers=headers,
                    data=body_bytes if body_bytes else None,
                    allow_redirects=False,
                    ssl=False,
                ) as upstream:
                    response_bytes = await upstream.content.read(1024 * 1024)
                    response_text = response_bytes.decode(upstream.charset or "utf-8", errors="replace")
                    response_headers = dict(upstream.headers)
                    result = {
                        "status": upstream.status,
                        "headers": response_headers,
                        "body": response_text,
                        "length": len(response_bytes),
                        "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                        "content_type": upstream.headers.get("Content-Type", ""),
                    }
        except Exception as exc:
            self._state["blocked_count"] += 1
            await self._write_raw_response(writer, 502, f"Proxy upstream request failed: {exc}".encode())
            return

        await self._persist_manual(method, target_url, headers, body_bytes, result)
        await self._write_raw_response(writer, int(result["status"]), response_bytes, self._response_headers(response_headers))

    async def _handle_connect_raw(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, target: str, _headers: dict[str, str]) -> None:
        host, port = self._connect_target_text(target)
        if not host or not port:
            self._state["https_connect_blocked_count"] += 1
            self._state["blocked_count"] += 1
            await self._write_raw_response(writer, 400, b"CONNECT target must be host:port.")
            return

        target_url = f"https://{host}:{port}/"
        scan = await self._scan()
        if not scan or not getattr(scan.config, "authorized", False):
            self._state["https_connect_blocked_count"] += 1
            self._state["blocked_count"] += 1
            await self._write_raw_response(writer, 403, b"No authorised scan is attached to the proxy.")
            return
        if not url_in_scope(target_url, scan.config.target, scan.config.scope):
            self._state["https_connect_blocked_count"] += 1
            self._state["blocked_count"] += 1
            await self._write_raw_response(writer, 403, b"HTTPS tunnel target is outside the saved Centrix scan scope.")
            return

        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(host, port)
        except Exception as exc:
            self._state["https_connect_blocked_count"] += 1
            self._state["blocked_count"] += 1
            await self._write_raw_response(writer, 502, f"HTTPS tunnel failed: {exc}".encode())
            return

        writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: Centrix\r\n\r\n")
        await writer.drain()
        self._state["https_connect_tunnel_count"] += 1

        async def pipe(source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
            try:
                while True:
                    chunk = await source.read(64 * 1024)
                    if not chunk:
                        break
                    destination.write(chunk)
                    await destination.drain()
            except Exception:
                pass
            finally:
                try:
                    destination.close()
                except Exception:
                    pass

        await asyncio.wait(
            {asyncio.create_task(pipe(reader, upstream_writer)), asyncio.create_task(pipe(upstream_reader, writer))},
            return_when=asyncio.FIRST_COMPLETED,
        )

    async def _handle(self, request: web.Request) -> web.StreamResponse:
        if request.method.upper() == "CONNECT":
            return await self._handle_connect(request)

        target_url = self._target_url(request)
        if not target_url:
            self._state["blocked_count"] += 1
            return web.Response(status=400, text="Proxy request must include an absolute HTTP URL.")

        scan = await self._scan()
        if not scan or not getattr(scan.config, "authorized", False):
            self._state["blocked_count"] += 1
            return web.Response(status=403, text="No authorised scan is attached to the proxy.")
        if not url_in_scope(target_url, scan.config.target, scan.config.scope):
            self._state["blocked_count"] += 1
            return web.Response(status=403, text="Proxy request is outside the saved Centrix scan scope.")

        body_bytes = await request.read()
        headers = self._forward_headers(request.headers)
        started = time.perf_counter()
        try:
            async with ClientSession(timeout=ClientTimeout(total=30)) as session:
                async with session.request(
                    request.method,
                    target_url,
                    headers=headers,
                    data=body_bytes if body_bytes else None,
                    allow_redirects=False,
                    ssl=False,
                ) as upstream:
                    response_bytes = await upstream.content.read(1024 * 1024)
                    response_text = response_bytes.decode(upstream.charset or "utf-8", errors="replace")
                    response_headers = dict(upstream.headers)
                    result = {
                        "status": upstream.status,
                        "headers": response_headers,
                        "body": response_text,
                        "length": len(response_bytes),
                        "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                        "content_type": upstream.headers.get("Content-Type", ""),
                    }
        except Exception as exc:
            self._state["blocked_count"] += 1
            return web.Response(status=502, text=f"Proxy upstream request failed: {exc}")

        await self._persist(request, target_url, headers, body_bytes, result)
        return web.Response(
            status=int(result["status"]),
            body=response_bytes,
            headers=self._response_headers(response_headers),
        )

    async def _handle_connect(self, request: web.Request) -> web.StreamResponse:
        host, port = self._connect_target(request)
        if not host or not port:
            self._state["https_connect_blocked_count"] += 1
            self._state["blocked_count"] += 1
            return web.Response(status=400, text="CONNECT target must be host:port.")

        target_url = f"https://{host}:{port}/"
        scan = await self._scan()
        if not scan or not getattr(scan.config, "authorized", False):
            self._state["https_connect_blocked_count"] += 1
            self._state["blocked_count"] += 1
            return web.Response(status=403, text="No authorised scan is attached to the proxy.")
        if not url_in_scope(target_url, scan.config.target, scan.config.scope):
            self._state["https_connect_blocked_count"] += 1
            self._state["blocked_count"] += 1
            return web.Response(status=403, text="HTTPS tunnel target is outside the saved Centrix scan scope.")

        transport = request.transport
        if transport is None:
            self._state["https_connect_blocked_count"] += 1
            self._state["blocked_count"] += 1
            return web.Response(status=500, text="Client transport is unavailable.")

        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(host, port)
        except Exception as exc:
            self._state["https_connect_blocked_count"] += 1
            self._state["blocked_count"] += 1
            return web.Response(status=502, text=f"HTTPS tunnel failed: {exc}")

        response = web.StreamResponse(status=200, reason="Connection Established")
        response.headers["Proxy-Agent"] = "Centrix"
        await response.prepare(request)
        self._state["https_connect_tunnel_count"] += 1

        async def client_to_upstream() -> None:
            try:
                while True:
                    chunk = await request.content.readany()
                    if not chunk:
                        break
                    upstream_writer.write(chunk)
                    await upstream_writer.drain()
            except Exception:
                pass
            finally:
                upstream_writer.close()

        async def upstream_to_client() -> None:
            try:
                while True:
                    chunk = await upstream_reader.read(64 * 1024)
                    if not chunk:
                        break
                    await response.write(chunk)
            except Exception:
                pass

        await asyncio.wait(
            {asyncio.create_task(client_to_upstream()), asyncio.create_task(upstream_to_client())},
            return_when=asyncio.FIRST_COMPLETED,
        )
        try:
            await response.write_eof()
        except Exception:
            pass
        return response

    def _target_url(self, request: web.Request) -> str:
        raw = request.raw_path
        if raw.startswith("http://") or raw.startswith("https://"):
            return raw
        host = request.headers.get("Host", "")
        if host:
            return f"http://{host}{request.rel_url}"
        return ""

    def _target_url_raw(self, raw_target: str, headers: dict[str, str]) -> str:
        if raw_target.startswith("http://") or raw_target.startswith("https://"):
            return raw_target
        host = headers.get("host", "")
        if host:
            return f"http://{host}{raw_target}"
        return ""

    def _connect_target(self, request: web.Request) -> tuple[str, int]:
        raw = request.raw_path or request.path_qs or request.path
        if raw.startswith("/"):
            raw = raw[1:]
        host_port = raw or request.headers.get("Host", "")
        if ":" not in host_port:
            return host_port, 443
        host, port_text = host_port.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError:
            return "", 0
        return host.strip("[]"), port

    def _connect_target_text(self, host_port: str) -> tuple[str, int]:
        if ":" not in host_port:
            return host_port, 443
        host, port_text = host_port.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError:
            return "", 0
        return host.strip("[]"), port

    async def _scan(self) -> Any:
        if not self._scan_resolver:
            return None
        return await self._scan_resolver(self._config.scan_id)

    async def _persist(self, request: web.Request, target_url: str, headers: dict[str, str], body: bytes, response: dict[str, Any]) -> None:
        await self._persist_manual(request.method.upper(), target_url, headers, body, response)

    async def _persist_manual(self, method: str, target_url: str, headers: dict[str, str], body: bytes, response: dict[str, Any]) -> None:
        if not self._save_payload or not self._corpus_factory:
            return
        manual = ManualRequest(
            scan_id=self._config.scan_id,
            method=method,
            url=target_url,
            headers=headers,
            body=body.decode("utf-8", errors="replace") if body else None,
        )
        payload = self._corpus_factory(manual, response, "Captured by Centrix proxy")
        payload["source"] = "proxy"
        payload["id"] = f"PRX-{uuid.uuid4().hex[:10].upper()}"
        await self._save_payload(payload)
        self._state["captured_count"] += 1

    def _parse_head(self, head: bytes) -> tuple[tuple[str, str, str], dict[str, str]]:
        text = head.decode("iso-8859-1", errors="replace")
        lines = text.split("\r\n")
        method, target, version = lines[0].split(" ", 2)
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        return (method.upper(), target, version), headers

    async def _write_raw_response(self, writer: asyncio.StreamWriter, status: int, body: bytes, headers: dict[str, str] | None = None) -> None:
        reason = HTTPStatus(status).phrase if status in HTTPStatus._value2member_map_ else "Status"
        response_headers = self._response_headers(headers or {})
        response_headers["Content-Length"] = str(len(body))
        if body and not any(key.lower() == "content-type" for key in response_headers):
            response_headers["Content-Type"] = "text/plain; charset=utf-8"
        head = f"HTTP/1.1 {status} {reason}\r\n" + "".join(f"{key}: {value}\r\n" for key, value in response_headers.items()) + "\r\n"
        writer.write(head.encode("iso-8859-1", errors="replace") + body)
        await writer.drain()
        writer.close()
        await self._wait_writer_closed(writer)

    async def _wait_writer_closed(self, writer: asyncio.StreamWriter) -> None:
        try:
            await writer.wait_closed()
        except Exception:
            pass

    def _forward_headers(self, headers: Any) -> dict[str, str]:
        blocked = {"host", "proxy-connection", "connection", "keep-alive", "transfer-encoding", "content-length", "accept-encoding"}
        return {str(key): str(value) for key, value in headers.items() if str(key).lower() not in blocked}

    def _response_headers(self, headers: dict[str, str]) -> dict[str, str]:
        blocked = {"transfer-encoding", "content-encoding", "connection", "keep-alive", "content-length"}
        return {str(key): str(value) for key, value in headers.items() if str(key).lower() not in blocked}

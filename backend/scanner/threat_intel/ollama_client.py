"""
scanner/threat_intel/ollama_client.py
--------------------------------------
Async Ollama inference client with:
  - Exponential-backoff retry on transient errors
  - Streaming chat completions
  - Embedding generation (for nomic-embed-text or any Ollama embed model)
  - Graceful fallback: returns a structured error dict instead of raising
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

from .config import cfg

logger = logging.getLogger("wraith.threat_intel.ollama")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _backoff(attempt: int, base: float = 2.0, cap: float = 32.0) -> float:
    """Exponential backoff with jitter, capped at `cap` seconds."""
    import random
    delay = min(base ** attempt, cap)
    return delay * (0.5 + random.random() * 0.5)


_TRANSIENT = (
    httpx.ConnectError,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.RemoteProtocolError,
)


# ─────────────────────────────────────────────────────────────────────────────
# Main client
# ─────────────────────────────────────────────────────────────────────────────

class OllamaClient:
    """
    Thin async wrapper around the Ollama REST API.

    Usage
    -----
    client = OllamaClient()
    response = await client.chat("Explain CVE-2024-1234")
    embedding = await client.embed("some text chunk")
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        chat_model: Optional[str] = None,
        embed_model: Optional[str] = None,
        timeout: Optional[int] = None,
        max_retries: Optional[int] = None,
    ) -> None:
        self.base_url = (base_url or cfg.ollama_base_url).rstrip("/")
        self.chat_model = chat_model or cfg.ollama_chat_model
        self.embed_model = embed_model or cfg.ollama_embed_model
        self.timeout = timeout or cfg.ollama_timeout
        self.max_retries = max_retries or cfg.ollama_max_retries

    # ── Low-level HTTP ───────────────────────────────────────────────────────

    async def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """POST with retry + backoff. Returns parsed JSON or raises."""
        url = f"{self.base_url}{path}"
        last_exc: Exception = RuntimeError("No attempts made")
        for attempt in range(self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(url, json=payload)
                    if resp.status_code == 429:
                        # Rate-limited by Ollama – back off and retry
                        retry_after = float(resp.headers.get("Retry-After", 5))
                        logger.warning("Ollama rate-limited; sleeping %.1fs", retry_after)
                        await asyncio.sleep(retry_after)
                        continue
                    resp.raise_for_status()
                    return resp.json()
            except _TRANSIENT as exc:
                last_exc = exc
                if attempt < self.max_retries:
                    delay = _backoff(attempt)
                    logger.warning(
                        "Ollama transient error (%s); retry %d/%d in %.1fs",
                        exc,
                        attempt + 1,
                        self.max_retries,
                        delay,
                    )
                    await asyncio.sleep(delay)
            except httpx.HTTPStatusError as exc:
                raise RuntimeError(f"Ollama HTTP {exc.response.status_code}: {exc.response.text}") from exc
        raise RuntimeError(f"Ollama unreachable after {self.max_retries} retries: {last_exc}") from last_exc

    # ── Streaming ────────────────────────────────────────────────────────────

    async def stream_chat(
        self,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
    ) -> AsyncIterator[str]:
        """Yield text tokens as they are streamed from Ollama."""
        import json

        model = model or self.chat_model
        messages: List[Dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        url = f"{self.base_url}/api/chat"
        payload = {"model": model, "messages": messages, "stream": True}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            async with client.stream("POST", url, json=payload) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    delta = chunk.get("message", {}).get("content", "")
                    if delta:
                        yield delta
                    if chunk.get("done"):
                        break

    # ── Non-streaming chat ───────────────────────────────────────────────────

    async def chat(
        self,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Single-shot chat completion.

        Returns
        -------
        {
          "content": "<full response text>",
          "model": "<model name>",
          "done": True,
          "error": None   # or error message string on failure
        }
        """
        model = model or self.chat_model
        messages: List[Dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        try:
            data = await self._post(
                "/api/chat",
                {"model": model, "messages": messages, "stream": False},
            )
            return {
                "content": data.get("message", {}).get("content", ""),
                "model": data.get("model", model),
                "done": data.get("done", True),
                "error": None,
            }
        except Exception as exc:
            logger.error("Ollama chat failed: %s", exc)
            return {
                "content": "",
                "model": model,
                "done": False,
                "error": str(exc),
            }

    # ── Embeddings ───────────────────────────────────────────────────────────

    async def embed(
        self,
        text: str,
        model: Optional[str] = None,
    ) -> List[float]:
        """
        Generate a dense embedding vector for `text`.

        Returns an empty list on failure (caller should handle gracefully).
        """
        model = model or self.embed_model
        try:
            data = await self._post(
                "/api/embed",
                {"model": model, "input": text},
            )
            # Ollama returns {"embeddings": [[...]]}
            embeddings = data.get("embeddings") or data.get("embedding") or []
            if embeddings and isinstance(embeddings[0], list):
                return embeddings[0]
            if embeddings and isinstance(embeddings[0], float):
                return embeddings  # type: ignore[return-value]
            return []
        except Exception as exc:
            logger.error("Ollama embed failed: %s", exc)
            return []

    async def embed_batch(
        self,
        texts: List[str],
        model: Optional[str] = None,
    ) -> List[List[float]]:
        """Embed a list of texts, returning one vector per text."""
        tasks = [self.embed(t, model) for t in texts]
        return await asyncio.gather(*tasks)

    # ── Health check ─────────────────────────────────────────────────────────

    async def health(self) -> bool:
        """Return True if the Ollama server is reachable."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                return resp.status_code == 200
        except Exception:
            return False

    async def list_models(self) -> List[str]:
        """Return the list of locally pulled model names."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                resp.raise_for_status()
                data = resp.json()
                return [m.get("name", "") for m in data.get("models", [])]
        except Exception:
            return []


# ─────────────────────────────────────────────────────────────────────────────
# Sync convenience wrappers (for use in sync contexts like Flask routes)
# ─────────────────────────────────────────────────────────────────────────────

def _run(coro: Any) -> Any:
    """Run an async coroutine in whatever event loop is available."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Inside an existing event loop (e.g. Flask-SocketIO) – use a
            # new thread-bound loop to avoid blocking.
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


class SyncOllamaClient:
    """Synchronous façade over OllamaClient for non-async call sites."""

    def __init__(self, **kwargs: Any) -> None:
        self._async = OllamaClient(**kwargs)

    def chat(self, prompt: str, system: Optional[str] = None, model: Optional[str] = None) -> Dict[str, Any]:
        return _run(self._async.chat(prompt, system=system, model=model))  # type: ignore[return-value]

    def embed(self, text: str, model: Optional[str] = None) -> List[float]:
        return _run(self._async.embed(text, model=model))  # type: ignore[return-value]

    def embed_batch(self, texts: List[str], model: Optional[str] = None) -> List[List[float]]:
        return _run(self._async.embed_batch(texts, model=model))  # type: ignore[return-value]

    def health(self) -> bool:
        return _run(self._async.health())  # type: ignore[return-value]

    def list_models(self) -> List[str]:
        return _run(self._async.list_models())  # type: ignore[return-value]

"""Browser macro workflows adapted from Wraith for Centrix DAST scans.

These workflows let an authorised scan drive a headless Chromium session before
the normal crawler/prober runs. The reached URLs, forms, response evidence, and
browser-discovered links are then fed into the rest of Centrix.
"""
from __future__ import annotations

import fnmatch
import json
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse


@dataclass
class BrowserStepResult:
    action: str
    status: str
    selector: str = ""
    url: str = ""
    value: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BrowserWorkflowResult:
    name: str
    status: str
    final_url: str = ""
    urls: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    steps: list[BrowserStepResult] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "final_url": self.final_url,
            "urls": self.urls,
            "forms": self.forms,
            "evidence": self.evidence,
            "steps": [step.to_dict() for step in self.steps],
            "error": self.error,
        }


def load_browser_workflows(definition: Any) -> list[dict[str, Any]]:
    """Normalize Wraith-style workflow definitions.

    Accepted shapes:
    - {"workflows": [{...}]}
    - {"name": "...", "steps": [...]}
    - [{...}, {...}]
    - JSON string containing one of the shapes above
    """
    if not definition:
        return []
    loaded = definition
    if isinstance(loaded, str):
        try:
            loaded = json.loads(loaded)
        except Exception:
            return []
    if isinstance(loaded, dict):
        if isinstance(loaded.get("workflows"), list):
            loaded = loaded["workflows"]
        elif isinstance(loaded.get("steps"), list):
            loaded = [loaded]
        else:
            return []
    if not isinstance(loaded, list):
        return []

    workflows: list[dict[str, Any]] = []
    for index, workflow in enumerate(loaded):
        if not isinstance(workflow, dict):
            continue
        steps = workflow.get("steps")
        if not isinstance(steps, list) or not steps:
            continue
        workflows.append({
            "name": str(workflow.get("name") or f"browser-workflow-{index + 1}"),
            "match": workflow.get("match"),
            "start_url": str(workflow.get("start_url") or workflow.get("url") or ""),
            "once": bool(workflow.get("once", True)),
            "variables": dict(workflow.get("variables") or {}),
            "steps": [step for step in steps if isinstance(step, dict)],
        })
    return workflows


def workflow_matches(workflow: dict[str, Any], url: str) -> bool:
    pattern = workflow.get("match")
    if not pattern:
        return True
    if isinstance(pattern, list):
        return any(workflow_matches({**workflow, "match": item}, url) for item in pattern)
    text = str(pattern)
    parsed = urlparse(url or "")
    path = parsed.path or "/"
    return fnmatch.fnmatch(url, text) or fnmatch.fnmatch(path, text) or text in url or text in path


async def run_browser_workflows(
    definitions: Any,
    *,
    base_url: str,
    timeout: int = 30,
    headless: bool = True,
) -> list[BrowserWorkflowResult]:
    workflows = load_browser_workflows(definitions)
    if not workflows:
        return []

    try:
        from playwright.async_api import async_playwright
    except Exception as exc:
        return [
            BrowserWorkflowResult(
                name=workflow.get("name") or "browser-workflow",
                status="failed",
                error=f"Playwright is unavailable: {exc}",
            )
            for workflow in workflows
        ]

    timeout_ms = max(1000, int(timeout or 30) * 1000)
    results: list[BrowserWorkflowResult] = []
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=headless)
        try:
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            captured: list[dict[str, Any]] = []

            async def on_response(response: Any) -> None:
                try:
                    headers = await response.all_headers()
                except Exception:
                    try:
                        headers = dict(response.headers)
                    except Exception:
                        headers = {}
                excerpt = ""
                content_type = headers.get("content-type") or headers.get("Content-Type") or ""
                if _is_textual(content_type):
                    try:
                        excerpt = (await response.text())[:2000]
                    except Exception:
                        excerpt = ""
                captured.append({
                    "url": response.url,
                    "status_code": int(response.status),
                    "content_type": content_type,
                    "response_length": len(excerpt),
                    "response_excerpt": excerpt,
                    "response_headers": headers,
                    "forms": [],
                })

            page.on("response", on_response)
            for workflow in workflows:
                start_index = len(captured)
                result = await execute_browser_workflow(page, workflow, base_url=base_url, timeout_ms=timeout_ms)
                result.final_url = getattr(page, "url", "") or result.final_url
                collected = await _collect_page_inputs(page, base_url)
                result.urls = _unique([*result.urls, result.final_url, *collected["urls"]])
                result.forms = collected["forms"]
                result.evidence = _evidence_for_workflow(captured[start_index:], result.forms)
                if not result.evidence and result.final_url:
                    result.evidence = [{
                        "url": result.final_url,
                        "status_code": 200,
                        "content_type": "text/html",
                        "response_length": 0,
                        "response_excerpt": "",
                        "response_headers": {},
                        "forms": result.forms,
                    }]
                results.append(result)
            await context.close()
        finally:
            await browser.close()
    return results


async def execute_browser_workflow(page: Any, workflow: dict[str, Any], *, base_url: str, timeout_ms: int = 30_000) -> BrowserWorkflowResult:
    result = BrowserWorkflowResult(name=str(workflow.get("name") or "browser-workflow"), status="succeeded")
    variables = {"base_url": base_url.rstrip("/"), **dict(workflow.get("variables") or {})}
    effective_base = str(variables.get("base_url") or base_url).rstrip("/")
    start_url = str(workflow.get("start_url") or "").strip()
    if start_url:
        await page.goto(_normalize_url(_render(start_url, variables), effective_base), wait_until="domcontentloaded", timeout=timeout_ms)

    for index, raw_step in enumerate(workflow.get("steps") or []):
        step = dict(raw_step or {})
        action = str(step.get("action") or step.get("type") or "click").lower()
        try:
            await _execute_step(page, step, action, effective_base, variables, timeout_ms)
            result.steps.append(BrowserStepResult(
                action=action,
                status="executed",
                selector=str(step.get("selector") or ""),
                url=_normalize_url(str(_render(step.get("url") or "", variables)), effective_base) if step.get("url") else "",
                value=str(_render(step.get("value") or step.get("text") or step.get("key") or "", variables)),
            ))
        except Exception as exc:
            result.status = "failed"
            result.error = str(exc)
            result.steps.append(BrowserStepResult(
                action=action,
                status="failed",
                selector=str(step.get("selector") or ""),
                url=str(step.get("url") or ""),
                reason=f"step-{index + 1}: {exc}",
            ))
            if not workflow.get("continue_on_error", False):
                break
    result.final_url = getattr(page, "url", "") or ""
    result.urls = _unique([result.final_url])
    return result


async def browser_results_to_scan_inputs(results: list[BrowserWorkflowResult]) -> tuple[list[str], list[dict[str, Any]], list[dict[str, Any]]]:
    urls: list[str] = []
    forms: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for workflow in results:
        if workflow.status == "failed" and not workflow.urls and not workflow.forms:
            continue
        urls.extend(workflow.urls)
        forms.extend(workflow.forms)
        evidence.extend(workflow.evidence)
    return _unique(urls), forms, evidence


async def _execute_step(page: Any, step: dict[str, Any], action: str, base_url: str, variables: dict[str, Any], timeout_ms: int) -> None:
    selector = step.get("selector")
    value = _render(step.get("value", step.get("text", "")), variables)
    if action == "goto":
        url = _normalize_url(str(_render(step.get("url") or "", variables)), base_url)
        await page.goto(url, wait_until=str(step.get("wait_until") or "domcontentloaded"), timeout=timeout_ms)
        return
    if action == "click":
        await _locator(page, selector).click(timeout=timeout_ms)
        return
    if action == "fill":
        await _locator(page, selector).fill(str(value), timeout=timeout_ms)
        return
    if action == "press":
        key = str(_render(step.get("key") or value or "Enter", variables))
        await _locator(page, selector).press(key, timeout=timeout_ms)
        return
    if action == "check":
        await _locator(page, selector).check(timeout=timeout_ms)
        return
    if action == "uncheck":
        await _locator(page, selector).uncheck(timeout=timeout_ms)
        return
    if action == "select":
        await _locator(page, selector).select_option(value=str(value), timeout=timeout_ms)
        return
    if action == "wait":
        if selector:
            await page.wait_for_selector(str(selector), timeout=timeout_ms)
        else:
            await page.wait_for_timeout(int(step.get("timeout") or step.get("ms") or 1000))
        return
    if action == "wait_for_url":
        await page.wait_for_url(str(_render(step.get("url") or "**", variables)), timeout=timeout_ms)
        return
    if action == "set_storage":
        storage = "sessionStorage" if str(step.get("storage") or "localStorage") == "sessionStorage" else "localStorage"
        key = str(_render(step.get("key") or "", variables))
        stored = str(_render(step.get("value") or "", variables))
        await page.evaluate(
            "(args) => window[args.storage].setItem(args.key, args.value)",
            {"storage": storage, "key": key, "value": stored},
        )
        variables[key] = stored
        return
    if action == "evaluate":
        await page.evaluate(str(_render(step.get("script") or step.get("expression") or "", variables)))
        return
    raise ValueError(f"unsupported browser workflow action: {action}")


def _locator(page: Any, selector: Any) -> Any:
    if not selector:
        raise ValueError("selector is required")
    found = page.locator(str(selector))
    return found.first


async def _collect_page_inputs(page: Any, base_url: str) -> dict[str, list[Any]]:
    try:
        urls = await page.eval_on_selector_all(
            "a[href], link[href], script[src], img[src]",
            """(els) => els.map((el) => el.href || el.src).filter(Boolean)""",
        )
    except Exception:
        urls = []
    try:
        forms = await page.eval_on_selector_all(
            "form",
            """
            (forms) => forms.map((form) => ({
              method: (form.method || "GET").toUpperCase(),
              action: form.action || window.location.href,
              inputs: Array.from(form.querySelectorAll("input, textarea, select, button"))
                .map((el) => el.name || el.id || el.getAttribute("aria-label") || "")
                .filter(Boolean),
              fields: Array.from(form.querySelectorAll("input, textarea, select, button")).map((el) => ({
                name: el.name || el.id || el.getAttribute("aria-label") || "",
                type: el.type || el.tagName.toLowerCase(),
                value: el.value || ""
              })).filter((field) => field.name),
              source: "browser-workflow"
            }))
            """,
        )
    except Exception:
        forms = []
    normalized_forms = []
    for form in forms if isinstance(forms, list) else []:
        if not isinstance(form, dict):
            continue
        action = _normalize_url(str(form.get("action") or ""), base_url)
        normalized_forms.append({**form, "action": action, "source": "browser-workflow", "name": f"Browser form {action}"})
    return {
        "urls": [_normalize_url(str(url), base_url) for url in urls if isinstance(url, str)],
        "forms": normalized_forms,
    }


def _evidence_for_workflow(captured: list[dict[str, Any]], forms: list[dict[str, Any]]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for item in captured:
        cloned = dict(item)
        cloned["forms"] = forms if _same_url_without_fragment(str(cloned.get("url") or ""), forms) else cloned.get("forms") or []
        evidence.append(cloned)
    return evidence


def _same_url_without_fragment(url: str, forms: list[dict[str, Any]]) -> bool:
    parsed = urlparse(url)
    base = parsed._replace(fragment="").geturl()
    for form in forms:
        action = urlparse(str(form.get("action") or ""))._replace(fragment="").geturl()
        if action == base:
            return True
    return False


def _normalize_url(candidate: str, base_url: str) -> str:
    if not candidate:
        return base_url
    parsed = urlparse(candidate)
    if parsed.scheme and parsed.netloc:
        return candidate
    return urljoin(base_url.rstrip("/") + "/", candidate.lstrip("/"))


def _render(value: Any, variables: dict[str, Any]) -> Any:
    if isinstance(value, str):
        rendered = value
        for key, child in variables.items():
            rendered = rendered.replace("{{" + str(key) + "}}", str(child))
            rendered = rendered.replace("{{ " + str(key) + " }}", str(child))
        return rendered
    return value


def _is_textual(content_type: str) -> bool:
    lowered = (content_type or "").lower()
    return any(marker in lowered for marker in ("text/", "json", "xml", "html", "javascript", "x-www-form-urlencoded"))


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique

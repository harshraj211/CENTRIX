"""Stateful API sequence workflows adapted from Wraith for Centrix."""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import aiohttp

BLOCKED_SAFE_METHODS = {"DELETE", "PATCH", "PUT"}
TEMPLATE_RE = re.compile(r"\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}")


@dataclass
class SequenceAssertionResult:
    assertion: dict[str, Any]
    passed: bool
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SequenceStepResult:
    name: str
    status: str
    method: str
    url: str
    status_code: int = 0
    reason: str = ""
    extracted: dict[str, Any] = field(default_factory=dict)
    assertions: list[SequenceAssertionResult] = field(default_factory=list)
    response_time_ms: int = 0
    request: dict[str, Any] = field(default_factory=dict)
    response_excerpt: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["assertions"] = [item.to_dict() for item in self.assertions]
        return data


@dataclass
class SequenceWorkflowResult:
    name: str
    status: str
    steps: list[SequenceStepResult] = field(default_factory=list)
    variables: dict[str, Any] = field(default_factory=dict)
    skipped: int = 0
    failed_step: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "steps": [step.to_dict() for step in self.steps],
            "variables": self.variables,
            "skipped": self.skipped,
            "failed_step": self.failed_step,
        }


def load_sequence_workflows(definition: Any) -> list[dict[str, Any]]:
    if not definition:
        return []
    loaded = definition
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
            "name": str(workflow.get("name") or f"sequence-{index + 1}"),
            "base_url": str(workflow.get("base_url") or ""),
            "safety_mode": str(workflow.get("safety_mode") or ""),
            "variables": dict(workflow.get("variables") or {}),
            "continue_on_error": bool(workflow.get("continue_on_error", False)),
            "steps": [step for step in steps if isinstance(step, dict)],
        })
    return workflows


async def run_sequence_workflows(
    definitions: Any,
    *,
    base_url: str,
    safety_mode: str = "safe",
    timeout: int = 10,
) -> list[SequenceWorkflowResult]:
    workflows = load_sequence_workflows(definitions)
    runner = SequenceRunner(base_url=base_url, safety_mode=safety_mode, timeout=timeout)
    return [await runner.run(workflow) for workflow in workflows]


class SequenceRunner:
    def __init__(self, *, base_url: str, safety_mode: str = "safe", timeout: int = 10) -> None:
        self.base_url = base_url.rstrip("/")
        self.safety_mode = safety_mode if safety_mode in {"safe", "intrusive", "lab"} else "safe"
        self.timeout = int(timeout or 10)

    async def run(self, workflow: dict[str, Any]) -> SequenceWorkflowResult:
        variables = {"base_url": workflow.get("base_url") or self.base_url, **dict(workflow.get("variables") or {})}
        effective_base = str(variables.get("base_url") or self.base_url)
        effective_safety = str(workflow.get("safety_mode") or self.safety_mode)
        if effective_safety not in {"safe", "intrusive", "lab"}:
            effective_safety = self.safety_mode

        result = SequenceWorkflowResult(name=str(workflow.get("name") or "sequence"), status="succeeded")
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            for index, raw_step in enumerate(workflow.get("steps") or []):
                step = dict(raw_step)
                name = str(step.get("name") or step.get("id") or f"step-{index + 1}")
                method = str(_request_field(step, "method", "GET") or "GET").upper()
                raw_url = _request_field(step, "url", "")
                url = _normalize_url(str(render_template(raw_url, variables)), effective_base)

                reason = self._blocked_reason(step, method, url, effective_base, effective_safety)
                if reason:
                    result.steps.append(SequenceStepResult(name=name, status="skipped", method=method, url=url, reason=reason))
                    result.skipped += 1
                    continue

                step_result = await self._execute_step(session, name, step, method, url, variables)
                result.steps.append(step_result)
                variables.update(step_result.extracted)
                result.variables = dict(variables)
                if step_result.status == "failed":
                    result.status = "failed"
                    result.failed_step = name
                    if not workflow.get("continue_on_error", False):
                        break

        if result.status != "failed" and result.skipped and not any(step.status == "executed" for step in result.steps):
            result.status = "skipped"
        result.variables = dict(variables)
        return result

    async def _execute_step(
        self,
        session: aiohttp.ClientSession,
        name: str,
        step: dict[str, Any],
        method: str,
        url: str,
        variables: dict[str, Any],
    ) -> SequenceStepResult:
        headers = render_template(dict(_request_field(step, "headers", {}) or {}), variables)
        params = render_template(dict(_request_field(step, "params", {}) or {}), variables)
        body_format = str(_request_field(step, "body_format", "") or "").lower()
        json_body = _request_field(step, "json", None)
        body = _request_field(step, "body", "")
        request_body = render_template(json_body if json_body is not None else body, variables)
        request_url = _url_with_params(url, dict(params or {}))
        started = time.perf_counter()
        request_record = {"method": method, "url": request_url, "headers": headers, "body": request_body}
        try:
            kwargs = _send_kwargs(headers, params, request_body, body_format, json_body is not None, method)
            async with session.request(method, url, **kwargs, ssl=False, allow_redirects=True) as response:
                text = await response.text(errors="replace")
                response_headers = dict(response.headers)
                status_code = response.status
        except Exception as exc:
            return SequenceStepResult(name=name, status="failed", method=method, url=request_url, reason=str(exc), request=request_record)

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        extracted = _extract_variables(step.get("extract") or {}, status_code, response_headers, text)
        assertions = _run_assertions(step.get("assertions") or [], status_code, response_headers, text, variables | extracted)
        failed = [item for item in assertions if not item.passed]
        return SequenceStepResult(
            name=name,
            status="failed" if failed else "executed",
            method=method,
            url=request_url,
            status_code=status_code,
            reason="; ".join(item.message for item in failed),
            extracted=extracted,
            assertions=assertions,
            response_time_ms=elapsed_ms,
            request=request_record,
            response_excerpt=text[:2000],
            response_headers=response_headers,
        )

    def _blocked_reason(self, step: dict[str, Any], method: str, url: str, base_url: str, safety_mode: str) -> str:
        if not _in_scope(url, base_url) and not step.get("allow_external", False):
            return "URL is outside workflow scope"
        if safety_mode == "safe":
            marked_safe = bool(step.get("safe") or step.get("allow_in_safe_mode") or step.get("disposable") or step.get("uses_disposable_resource"))
            if method in BLOCKED_SAFE_METHODS and not marked_safe:
                return f"{method} is skipped in safe mode unless the step is explicitly marked safe/disposable"
            if step.get("destructive") and not marked_safe:
                return "destructive step is skipped in safe mode"
        return ""


def render_template(value: Any, variables: dict[str, Any]) -> Any:
    if isinstance(value, str):
        def repl(match: re.Match[str]) -> str:
            found = _lookup_variable(variables, match.group(1))
            return "" if found is None else str(found)
        return TEMPLATE_RE.sub(repl, value)
    if isinstance(value, dict):
        return {str(render_template(key, variables)): render_template(child, variables) for key, child in value.items()}
    if isinstance(value, list):
        return [render_template(item, variables) for item in value]
    return value


def sequence_requests_and_urls(results: list[SequenceWorkflowResult]) -> tuple[list[str], list[dict[str, Any]], list[dict[str, Any]]]:
    urls: list[str] = []
    forms: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for workflow in results:
        for step in workflow.steps:
            if step.status != "executed":
                continue
            if step.url not in urls:
                urls.append(step.url)
            request = step.request or {}
            forms.append({
                "method": step.method,
                "action": step.url,
                "inputs": list((request.get("body") if isinstance(request.get("body"), dict) else {}) or {}),
                "fields": [{"name": key, "type": "text", "value": str(value)} for key, value in ((request.get("body") if isinstance(request.get("body"), dict) else {}) or {}).items()],
                "headers": request.get("headers") or {},
                "body_template": request.get("body"),
                "content_type": (request.get("headers") or {}).get("Content-Type"),
                "source": "sequence-workflow",
                "name": step.name,
            })
            evidence.append({
                "url": step.url,
                "status_code": step.status_code,
                "content_type": step.response_headers.get("Content-Type", ""),
                "response_length": len(step.response_excerpt or ""),
                "response_excerpt": step.response_excerpt,
                "response_headers": step.response_headers,
                "forms": [],
            })
    return urls, forms, evidence


def _request_field(step: dict[str, Any], field: str, default: Any = None) -> Any:
    request = step.get("request")
    if isinstance(request, dict) and field in request:
        return request.get(field)
    return step.get(field, default)


def _send_kwargs(headers: dict[str, Any], params: dict[str, Any], body: Any, body_format: str, explicit_json: bool, method: str) -> dict[str, Any]:
    kwargs: dict[str, Any] = {"headers": headers or None, "params": params or None}
    if method != "GET":
        normalized = body_format or ("json" if explicit_json or isinstance(body, (dict, list)) else "form")
        if normalized in {"json", "graphql"}:
            kwargs["json"] = body
            kwargs["headers"] = {**(headers or {}), "Content-Type": "application/json"}
        elif normalized == "xml":
            kwargs["data"] = body
            kwargs["headers"] = {**(headers or {}), "Content-Type": "application/xml"}
        else:
            kwargs["data"] = body
    return kwargs


def _extract_variables(extract: Any, status_code: int, headers: dict[str, str], text: str) -> dict[str, Any]:
    if not isinstance(extract, dict):
        return {}
    values = {}
    for name, spec in extract.items():
        value = _extract_one(spec, status_code, headers, text)
        if value is not None:
            values[str(name)] = value
    return values


def _extract_one(spec: Any, _status_code: int, headers: dict[str, str], text: str) -> Any:
    if isinstance(spec, str):
        return _json_path(_response_json(text), spec)
    if not isinstance(spec, dict):
        return None
    if spec.get("jsonpath") or spec.get("json_path"):
        return _json_path(_response_json(text), str(spec.get("jsonpath") or spec.get("json_path")))
    if spec.get("header"):
        return headers.get(str(spec["header"]))
    if spec.get("regex"):
        source = str(spec.get("source") or "body")
        haystack = "\n".join(f"{k}: {v}" for k, v in headers.items()) if source == "header" else text
        match = re.search(str(spec["regex"]), haystack, re.DOTALL)
        if not match:
            return None
        group = int(spec.get("group", 1))
        try:
            return match.group(group)
        except Exception:
            return match.group(0)
    return None


def _run_assertions(assertions: Any, status_code: int, headers: dict[str, str], text: str, variables: dict[str, Any]) -> list[SequenceAssertionResult]:
    if isinstance(assertions, dict):
        assertions = [assertions]
    if not isinstance(assertions, list):
        return []
    return [_run_assertion(assertion, status_code, headers, text, variables) for assertion in assertions if isinstance(assertion, dict)]


def _run_assertion(assertion: dict[str, Any], status_code: int, headers: dict[str, str], text: str, variables: dict[str, Any]) -> SequenceAssertionResult:
    rendered = render_template(assertion, variables)
    if "status_code" in rendered:
        allowed = rendered["status_code"] if isinstance(rendered["status_code"], list) else [rendered["status_code"]]
        passed = status_code in {int(item) for item in allowed}
        return SequenceAssertionResult(rendered, passed, "" if passed else f"expected status {allowed}, got {status_code}")
    if "contains" in rendered:
        needle = str(rendered["contains"])
        passed = needle in text
        return SequenceAssertionResult(rendered, passed, "" if passed else f"response did not contain {needle!r}")
    if "not_contains" in rendered:
        needle = str(rendered["not_contains"])
        passed = needle not in text
        return SequenceAssertionResult(rendered, passed, "" if passed else f"response contained {needle!r}")
    if "header" in rendered:
        header = str(rendered["header"])
        value = headers.get(header)
        expected = rendered.get("equals")
        passed = value is not None if expected is None else str(value) == str(expected)
        return SequenceAssertionResult(rendered, passed, "" if passed else f"header {header!r} assertion failed")
    if "jsonpath" in rendered or "json_path" in rendered:
        path = str(rendered.get("jsonpath") or rendered.get("json_path"))
        value = _json_path(_response_json(text), path)
        if "equals" in rendered:
            passed = str(value) == str(rendered["equals"])
            return SequenceAssertionResult(rendered, passed, "" if passed else f"{path} expected {rendered['equals']!r}, got {value!r}")
        return SequenceAssertionResult(rendered, value is not None, "" if value is not None else f"{path} not found")
    if "regex" in rendered:
        passed = re.search(str(rendered["regex"]), text, re.DOTALL) is not None
        return SequenceAssertionResult(rendered, passed, "" if passed else "regex assertion did not match")
    return SequenceAssertionResult(rendered, True, "")


def _response_json(text: str) -> Any:
    try:
        return json.loads(text or "")
    except Exception:
        return None


def _json_path(value: Any, path: str) -> Any:
    if value is None:
        return None
    normalized = str(path or "").strip()
    if normalized in {"", "$"}:
        return value
    if normalized.startswith("$."):
        normalized = normalized[2:]
    elif normalized.startswith("$"):
        normalized = normalized[1:].lstrip(".")
    current = value
    for part in _split_json_path(normalized):
        if isinstance(part, int):
            if not isinstance(current, list) or part >= len(current):
                return None
            current = current[part]
        elif isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _split_json_path(path: str) -> list[Any]:
    parts: list[Any] = []
    for raw in filter(None, re.split(r"\.", path)):
        match = re.match(r"^([A-Za-z0-9_-]+)(.*)$", raw)
        if not match:
            continue
        parts.append(match.group(1))
        for index in re.findall(r"\[(\d+)\]", match.group(2) or ""):
            parts.append(int(index))
    return parts


def _lookup_variable(variables: dict[str, Any], path: str) -> Any:
    current: Any = variables
    for part in str(path).split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _normalize_url(candidate: str, base_url: str) -> str:
    parsed = urlparse(candidate or "")
    if parsed.scheme and parsed.netloc:
        return candidate
    return urljoin(base_url.rstrip("/") + "/", str(candidate or "").lstrip("/"))


def _in_scope(url: str, base_url: str) -> bool:
    parsed_url = urlparse(url or "")
    parsed_base = urlparse(base_url or "")
    if not parsed_base.netloc:
        return True
    return parsed_url.netloc == parsed_base.netloc


def _url_with_params(url: str, params: dict[str, Any]) -> str:
    if not params:
        return url
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for key, value in params.items():
        query[str(key)] = value
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))

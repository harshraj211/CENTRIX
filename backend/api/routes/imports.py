"""API-surface importers adapted from Wraith: OpenAPI, Postman, HAR and GraphQL."""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote, urlencode, urljoin

from fastapi import APIRouter, HTTPException

from api.models import ApiImport

router = APIRouter(prefix="/api/import", tags=["api-import"])

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
VARIABLE_RE = re.compile(r"{{\s*([^}]+?)\s*}}")


@router.post("/preview")
async def preview_api_import(payload: ApiImport):
    try:
        endpoints = _extract(payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid {payload.format} document: {exc}") from exc

    unique: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in endpoints:
        if not item.get("url"):
            continue
        fingerprint = item.get("name") or _stable_body_fingerprint(item.get("body"))
        unique[(str(item.get("method", "GET")).upper(), item["url"], fingerprint)] = item
    return {"format": payload.format, "endpoints": list(unique.values())[:500]}


def _extract(payload: ApiImport) -> list[dict[str, Any]]:
    doc, base = payload.document or {}, (payload.base_url or "").rstrip("/")
    if payload.format == "openapi":
        return _extract_openapi(doc, base)
    if payload.format == "postman":
        return _extract_postman(doc, base)
    if payload.format == "har":
        return _extract_har(doc)
    if payload.format == "graphql":
        return _extract_graphql(doc, base)
    raise ValueError("unsupported format")


def _extract_openapi(doc: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    base = base_url or _openapi_base_url(doc)
    endpoints: list[dict[str, Any]] = []
    for raw_path, path_item in (doc.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        inherited_params = path_item.get("parameters") or []
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            params = [*inherited_params, *(operation.get("parameters") or [])]
            path = _materialize_path_params(str(raw_path), params)
            query = _query_examples(params)
            url = _join_url(base, path)
            if query:
                url = f"{url}?{urlencode(query, doseq=True)}"
            body, content_type = _openapi_request_body(operation)
            endpoints.append(_clean_endpoint({
                "method": method.upper(),
                "url": url,
                "source": "openapi",
                "name": operation.get("operationId") or operation.get("summary") or f"{method.upper()} {raw_path}",
                "headers": {"Content-Type": content_type} if content_type else {},
                "body": body,
                "content_type": content_type,
            }))
    return endpoints


def _openapi_base_url(doc: dict[str, Any]) -> str:
    servers = doc.get("servers") or []
    if servers and isinstance(servers[0], dict) and servers[0].get("url"):
        return str(servers[0]["url"]).rstrip("/")
    host = str(doc.get("host") or "").strip()
    if host:
        scheme = (doc.get("schemes") or ["https"])[0]
        base_path = str(doc.get("basePath") or "").strip("/")
        return f"{scheme}://{host}" + (f"/{base_path}" if base_path else "")
    return ""


def _materialize_path_params(path: str, params: list[dict[str, Any]]) -> str:
    path_params = {str(param.get("name")): _param_example(param) for param in params if param.get("in") == "path"}

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        value = path_params.get(name) or _fallback_param_value(name)
        return quote(str(value), safe="")

    return re.sub(r"{([^}/]+)}", replace, path)


def _query_examples(params: list[dict[str, Any]]) -> list[tuple[str, str]]:
    query: list[tuple[str, str]] = []
    for param in params:
        if param.get("in") != "query" or not param.get("name"):
            continue
        value = _param_example(param)
        if value is None:
            value = _fallback_param_value(str(param["name"]))
        if isinstance(value, list):
            query.extend((str(param["name"]), str(item)) for item in value[:3])
        else:
            query.append((str(param["name"]), str(value)))
    return query


def _param_example(param: dict[str, Any]) -> Any:
    if "example" in param:
        return param["example"]
    schema = param.get("schema") or {}
    if isinstance(schema, dict):
        if "example" in schema:
            return schema["example"]
        if "default" in schema:
            return schema["default"]
        examples = schema.get("examples")
        if isinstance(examples, list) and examples:
            return examples[0]
        enum = schema.get("enum")
        if isinstance(enum, list) and enum:
            return enum[0]
        return _sample_for_schema(schema, str(param.get("name") or "value"))
    return None


def _openapi_request_body(operation: dict[str, Any]) -> tuple[Any, str | None]:
    body = operation.get("requestBody")
    if not isinstance(body, dict):
        return None, None
    content = body.get("content") or {}
    preferred = next((ct for ct in content if "json" in ct), None) or next(iter(content), None)
    if not preferred:
        return None, None
    media = content.get(preferred) or {}
    if "example" in media:
        return media["example"], preferred
    examples = media.get("examples")
    if isinstance(examples, dict) and examples:
        first = next(iter(examples.values()))
        if isinstance(first, dict) and "value" in first:
            return first["value"], preferred
    schema = media.get("schema") or {}
    return _sample_for_schema(schema, "body"), preferred


def _sample_for_schema(schema: dict[str, Any], name: str = "value") -> Any:
    if not isinstance(schema, dict):
        return "sample"
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if "enum" in schema and schema["enum"]:
        return schema["enum"][0]
    schema_type = schema.get("type")
    if schema_type == "object" or schema.get("properties"):
        return {
            key: _sample_for_schema(value, key)
            for key, value in list((schema.get("properties") or {}).items())[:20]
        } or {"name": "centrix"}
    if schema_type == "array":
        return [_sample_for_schema(schema.get("items") or {}, name)]
    if schema_type in {"integer", "number"}:
        return 1
    if schema_type == "boolean":
        return True
    return _fallback_param_value(name)


def _extract_postman(doc: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    variables = _postman_variables(doc)
    if base_url:
        variables.setdefault("baseUrl", base_url)
        variables.setdefault("base_url", base_url)
    endpoints: list[dict[str, Any]] = []

    def visit(items: list[dict[str, Any]], folder: list[str]) -> None:
        for item in items or []:
            if item.get("item"):
                visit(item["item"], [*folder, str(item.get("name") or "Folder")])
                continue
            req = item.get("request")
            if not isinstance(req, dict):
                continue
            method = str(req.get("method") or "GET").upper()
            url = _resolve_postman_url(req.get("url"), variables)
            headers = _postman_headers(req.get("header"), variables)
            body, content_type = _postman_body(req.get("body"), headers, variables)
            endpoints.append(_clean_endpoint({
                "method": method,
                "url": url,
                "source": "postman",
                "name": " / ".join([*folder, str(item.get("name") or method)]),
                "headers": headers,
                "body": body,
                "content_type": content_type,
            }))

    visit(doc.get("item") or [], [])
    return endpoints


def _postman_variables(doc: dict[str, Any]) -> dict[str, str]:
    variables: dict[str, str] = {}
    for var in doc.get("variable") or []:
        if isinstance(var, dict) and var.get("key") is not None:
            variables[str(var["key"])] = str(var.get("value") or var.get("initial") or "")
    return variables


def _resolve_postman_url(url_obj: Any, variables: dict[str, str]) -> str:
    if isinstance(url_obj, str):
        return _replace_variables(url_obj, variables)
    if not isinstance(url_obj, dict):
        return ""
    raw = url_obj.get("raw")
    if raw:
        return _replace_variables(str(raw), variables)
    protocol = _replace_variables(str(url_obj.get("protocol") or "https"), variables)
    host = url_obj.get("host") or []
    path = url_obj.get("path") or []
    host_text = ".".join(_replace_variables(str(part), variables) for part in host) if isinstance(host, list) else _replace_variables(str(host), variables)
    path_text = "/".join(quote(_replace_variables(str(part), variables), safe=":@{}") for part in path) if isinstance(path, list) else _replace_variables(str(path), variables)
    query = []
    for item in url_obj.get("query") or []:
        if isinstance(item, dict) and not item.get("disabled") and item.get("key") is not None:
            query.append((str(item["key"]), _replace_variables(str(item.get("value") or ""), variables)))
    built = f"{protocol}://{host_text}" + (f"/{path_text}" if path_text else "")
    return f"{built}?{urlencode(query)}" if query else built


def _postman_headers(headers_obj: Any, variables: dict[str, str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for header in headers_obj or []:
        if isinstance(header, dict) and not header.get("disabled") and header.get("key"):
            headers[str(header["key"])] = _replace_variables(str(header.get("value") or ""), variables)
    return headers


def _postman_body(body_obj: Any, headers: dict[str, str], variables: dict[str, str]) -> tuple[Any, str | None]:
    if not isinstance(body_obj, dict):
        return None, None
    mode = body_obj.get("mode")
    if mode == "raw":
        raw = _replace_variables(str(body_obj.get("raw") or ""), variables)
        content_type = headers.get("Content-Type") or headers.get("content-type")
        if content_type and "json" in content_type:
            try:
                return json.loads(raw), content_type
            except json.JSONDecodeError:
                return raw, content_type
        return raw, content_type
    if mode in {"urlencoded", "formdata"}:
        fields = {}
        for field in body_obj.get(mode) or []:
            if isinstance(field, dict) and not field.get("disabled") and field.get("key"):
                fields[str(field["key"])] = _replace_variables(str(field.get("value") or ""), variables)
        return fields, "application/x-www-form-urlencoded" if mode == "urlencoded" else "multipart/form-data"
    return None, None


def _extract_har(doc: dict[str, Any]) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    for entry in ((doc.get("log") or {}).get("entries") or []):
        req = entry.get("request") if isinstance(entry, dict) else None
        if not isinstance(req, dict):
            continue
        headers = {str(header.get("name")): str(header.get("value") or "") for header in req.get("headers") or [] if isinstance(header, dict) and header.get("name")}
        post_data = req.get("postData") if isinstance(req.get("postData"), dict) else {}
        body: Any = post_data.get("text")
        content_type = post_data.get("mimeType") or headers.get("Content-Type") or headers.get("content-type")
        if body and content_type and "json" in str(content_type):
            try:
                body = json.loads(body)
            except json.JSONDecodeError:
                pass
        elif not body and post_data.get("params"):
            body = {str(param.get("name")): str(param.get("value") or "") for param in post_data.get("params") or [] if isinstance(param, dict) and param.get("name")}
        endpoints.append(_clean_endpoint({
            "method": str(req.get("method") or "GET").upper(),
            "url": req.get("url") or "",
            "source": "har",
            "name": entry.get("pageref") or req.get("url") or "HAR request",
            "headers": headers,
            "body": body,
            "content_type": content_type,
        }))
    return endpoints


def _extract_graphql(doc: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    endpoint = base_url or str(doc.get("endpoint") or doc.get("url") or "").rstrip("/")
    if not endpoint:
        return []
    schema = ((doc.get("data") or {}).get("__schema") or doc.get("__schema") or {})
    operations = _graphql_operations_from_schema(schema)
    if not operations:
        operations = [{"name": "GraphQL health query", "query": "{ __typename }"}]
    return [
        _clean_endpoint({
            "method": "POST",
            "url": endpoint,
            "source": "graphql",
            "name": operation["name"],
            "headers": {"Content-Type": "application/json"},
            "body": {"query": operation["query"]},
            "content_type": "application/json",
        })
        for operation in operations[:80]
    ]


def _graphql_operations_from_schema(schema: dict[str, Any]) -> list[dict[str, str]]:
    if not isinstance(schema, dict):
        return []
    types = {item.get("name"): item for item in schema.get("types") or [] if isinstance(item, dict)}
    operations: list[dict[str, str]] = []
    for root_key, prefix in (("queryType", "query"), ("mutationType", "mutation")):
        root_name = (schema.get(root_key) or {}).get("name")
        root = types.get(root_name)
        if not root:
            continue
        for field in root.get("fields") or []:
            if not isinstance(field, dict) or not field.get("name"):
                continue
            field_name = str(field["name"])
            args = field.get("args") or []
            if args:
                continue
            selection = _graphql_selection(field.get("type"), types)
            query = f"{prefix} {{ {field_name}{selection} }}"
            operations.append({"name": f"GraphQL {prefix}: {field_name}", "query": query})
    return operations


def _graphql_selection(type_obj: Any, types: dict[str, dict[str, Any]]) -> str:
    name = _graphql_type_name(type_obj)
    gql_type = types.get(name or "")
    if not gql_type or not gql_type.get("fields"):
        return ""
    scalar_names = []
    for field in gql_type.get("fields") or []:
        field_name = field.get("name") if isinstance(field, dict) else None
        if field_name and _graphql_type_name(field.get("type")) in {"ID", "String", "Int", "Float", "Boolean"}:
            scalar_names.append(str(field_name))
        if len(scalar_names) >= 5:
            break
    return " { " + " ".join(scalar_names or ["__typename"]) + " }"


def _graphql_type_name(type_obj: Any) -> str | None:
    current = type_obj
    for _ in range(6):
        if not isinstance(current, dict):
            return None
        if current.get("name"):
            return str(current["name"])
        current = current.get("ofType")
    return None


def _join_url(base: str, path: str) -> str:
    if not base:
        return path
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _replace_variables(value: str, variables: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        key = match.group(1).strip()
        return variables.get(key) or f"{{{{{key}}}}}"

    return VARIABLE_RE.sub(replace, value)


def _fallback_param_value(name: str) -> str:
    lowered = name.lower()
    if "id" in lowered:
        return "1"
    if "email" in lowered:
        return "user@example.com"
    if "url" in lowered or "callback" in lowered or "redirect" in lowered:
        return "https://example.com"
    if "token" in lowered:
        return "centrix-token"
    if "page" in lowered or "limit" in lowered:
        return "1"
    return "centrix"


def _stable_body_fingerprint(body: Any) -> str:
    if body is None:
        return ""
    try:
        return json.dumps(body, sort_keys=True, default=str)[:160]
    except TypeError:
        return str(body)[:160]


def _clean_endpoint(endpoint: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in endpoint.items() if value not in (None, {}, [], "")}

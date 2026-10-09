"""Reusable, dependency-free pieces for the IoTBec dashboard.

The upstream repository is a research artifact with hard-coded experiment
scripts. This module keeps the paper's IS/VS/VIS matching idea, while adding
safe request generation and an optional black-box HTTP runner for a lab target.
It intentionally does not execute exploit PoCs or shell commands.
"""

from __future__ import annotations

import ast
import json
import re
import time
from difflib import SequenceMatcher
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit
from urllib.request import (HTTPBasicAuthHandler, HTTPPasswordMgrWithDefaultRealm,
                            HTTPCookieProcessor, Request, build_opener)

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = Path("code/result/database.json")
MATCH_FIELDS = {"URI": 50, "form_parameter": 40, "form_format": 10, "button": 10, "navigation": 40}
SAFE_VARIANTS = ("IOTBEC-MARKER", "A" * 32, "0" * 32, "test%00marker", "127.0.0.1", "{}", "unicode-%E4%B8%AD")
PROVIDER_DEFAULTS = {
    "mimo": {"label": "小米 MiMo", "protocol": "mimo", "base_url": "https://token-plan-cn.xiaomimimo.com/v1", "model": "mimo-v2.5-pro"},
    "openai": {"label": "OpenAI GPT", "protocol": "openai", "base_url": "https://api.openai.com/v1", "model": "gpt-4o-mini"},
    "deepseek": {"label": "DeepSeek", "protocol": "openai", "base_url": "https://api.deepseek.com/v1", "model": "deepseek-chat"},
    "claude": {"label": "Anthropic Claude", "protocol": "anthropic", "base_url": "https://api.anthropic.com", "model": "claude-3-5-sonnet-latest"},
}


def resolve_repo_path(value: str | Path, must_exist: bool = False) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = REPO_ROOT / candidate
    candidate = candidate.resolve()
    try:
        candidate.relative_to(REPO_ROOT)
    except ValueError as exc:
        raise ValueError("Path must stay inside the IoTBec project directory") from exc
    if must_exist and not candidate.exists():
        raise FileNotFoundError(candidate)
    return candidate


def load_json(value: str | Path) -> Any:
    path = resolve_repo_path(value, must_exist=True)
    return json.loads(path.read_text(encoding="utf-8"))


def _normalize_captured_uri(value: str) -> str:
    parsed = urlsplit(str(value or ""))
    path = parsed.path or "/"
    marker = "/;stok="
    if marker in path:
        suffix = path.split(marker, 1)[1]
        path = "/" + suffix.split("/", 1)[1] if "/" in suffix else "/"
    return f"{path}?{parsed.query}" if parsed.query else path


def parse_interface_capture(raw: Any) -> list[dict[str, Any]]:
    """Convert an IS JSON list or HAR object into sanitized IS entries."""
    if isinstance(raw, list):
        return raw
    entries = raw.get("log", {}).get("entries", []) if isinstance(raw, dict) else []
    interfaces: list[dict[str, Any]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for entry in entries:
        request = entry.get("request", {}) if isinstance(entry, dict) else {}
        if not isinstance(request, dict):
            continue
        method = str(request.get("method", "GET")).upper()
        uri = _normalize_captured_uri(request.get("url", ""))
        if not uri.startswith("/"):
            continue
        parameters: list[str] = []
        seed_body: dict[str, str] = {}
        parsed = urlsplit(uri)
        for key, val in parse_qsl(parsed.query, keep_blank_values=True):
            if key not in parameters:
                parameters.append(key)
            seed_body[key] = val
        post_data = request.get("postData", {})
        if isinstance(post_data, dict):
            for item in post_data.get("params", []) or []:
                if not isinstance(item, dict) or not item.get("name"):
                    continue
                key = str(item["name"])
                if key not in parameters:
                    parameters.append(key)
                seed_body[key] = str(item.get("value", ""))
            if not post_data.get("params") and isinstance(post_data.get("text"), str):
                for key, val in parse_qsl(post_data["text"], keep_blank_values=True):
                    if key not in parameters:
                        parameters.append(key)
                    seed_body[key] = val
        signature = (method, uri, tuple(sorted(parameters)))
        if signature in seen:
            continue
        seen.add(signature)
        headers = {str(item.get("name", "")).lower(): str(item.get("value", ""))
                   for item in request.get("headers", []) if isinstance(item, dict) and item.get("name")}
        interfaces.append({"URI": uri, "form_parameter": parameters, "form_format": "key-value",
                           "button": "", "navigation": _normalize_captured_uri(headers.get("referer", "")), "method": method,
                           "seed_body": seed_body, "source": "network-capture"})
    return interfaces


def load_interface_capture(value: str | Path) -> list[dict[str, Any]]:
    """Load and sanitize an IS JSON file or a browser-exported HAR file."""
    return parse_interface_capture(load_json(value))


def provider_defaults() -> dict[str, dict[str, str]]:
    return {key: dict(value) for key, value in PROVIDER_DEFAULTS.items()}


def _provider_request(provider: str, api_key: str, base_url: str, model: str, messages: list[dict[str, str]],
                     max_tokens: int, timeout: float) -> str:
    if provider not in PROVIDER_DEFAULTS or not api_key.strip():
        return ""
    base = base_url.rstrip("/")
    if PROVIDER_DEFAULTS[provider]["protocol"] == "anthropic":
        url = base if base.endswith("/messages") else f"{base}/v1/messages"
        payload = {"model": model, "max_tokens": max_tokens, "messages": messages}
        headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
    else:
        url = base if base.endswith("/chat/completions") else f"{base}/chat/completions"
        payload = {"model": model, "messages": messages, "max_tokens": max_tokens, "temperature": 0, "stream": False}
        headers = ({"api-key": api_key} if provider == "mimo" else {"Authorization": f"Bearer {api_key}"})
        headers["Content-Type"] = "application/json"
    request = Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    with build_opener().open(request, timeout=timeout) as response:
        data = json.loads(response.read(512 * 1024).decode("utf-8", errors="replace"))
    if PROVIDER_DEFAULTS[provider]["protocol"] == "anthropic":
        return "".join(part.get("text", "") for part in data.get("content", []) if isinstance(part, dict))
    return data.get("choices", [{}])[0].get("message", {}).get("content", "")


def search_nvd(vendor: str, product: str, version: str = "", keywords: str = "", api_key: str = "",
               timeout: float = 30.0, max_results: int = 100) -> list[dict[str, Any]]:
    """Fetch current CVE records from NVD 2.0; no LLM claims are used as evidence."""
    terms = [part.strip() for part in (vendor, product, version, keywords) if part and part.strip()]
    if not terms:
        raise ValueError("Vendor or product is required")
    query = urlencode({"keywordSearch": " ".join(terms), "noRejected": "", "resultsPerPage": min(max_results, 200)})
    request = Request(f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}", headers={"User-Agent": "IoTBec-Lab/0.1"})
    if api_key.strip():
        request.add_header("apiKey", api_key.strip())
    with build_opener().open(request, timeout=timeout) as response:
        data = json.loads(response.read(4 * 1024 * 1024).decode("utf-8", errors="replace"))
    return data.get("vulnerabilities", [])[:max_results]


def _cve_text(record: dict[str, Any]) -> str:
    cve = record.get("cve", record)
    descriptions = cve.get("descriptions", [])
    for description in descriptions:
        if description.get("lang") == "en":
            return str(description.get("value", ""))
    return str(descriptions[0].get("value", "")) if descriptions else ""


def _vul_type(text: str) -> str:
    lowered = text.lower()
    for keyword, label in (("command injection", "Command Injection"), ("sql injection", "Injection"),
                           ("buffer overflow", "Overflow"), ("stack overflow", "Overflow"),
                           ("cross-site scripting", "XSS"), ("cross-site request forgery", "CSRF"),
                           ("path traversal", "Path Traversal"), ("authentication bypass", "Authentication Bypass")):
        if keyword in lowered:
            return label
    return "Unknown"


def normalize_cves(records: list[dict[str, Any]], vendor: str, product: str, version: str = "") -> list[dict[str, Any]]:
    entries = []
    for record in records:
        cve = record.get("cve", {})
        cve_id = cve.get("id", "")
        description = _cve_text(record)
        if not cve_id:
            continue
        entries.append({"CVE ID": cve_id, "vendor": vendor, "product": product, "version": version,
                        "URI": "", "form_parameter": "", "form_format": "key-value", "button": "",
                        "navigation": "", "vul_type": _vul_type(description), "function name": "",
                        "parameter or argument": "", "POC": "", "description": description,
                        "references": [ref.get("url", "") for ref in cve.get("references", [])[:8] if ref.get("url")]})
    return entries


def llm_enrich_cves(provider: str, api_key: str, base_url: str, model: str, records: list[dict[str, Any]],
                    vendor: str, product: str, version: str = "", timeout: float = 45.0) -> list[dict[str, Any]]:
    """Enrich only fields the source text supports; unknown URI/parameters must remain empty."""
    base_entries = normalize_cves(records, vendor, product, version)
    if not base_entries or not api_key.strip():
        return base_entries
    compact = [{"CVE ID": item["CVE ID"], "description": item["description"], "references": item["references"]} for item in base_entries[:40]]
    prompt = ("Return only a JSON array. For each input CVE, preserve CVE ID and fill IoTBec fields. "
              "Infer URI, form_parameter, function name, or parameter only when explicitly supported by the description or references; otherwise use empty strings. "
              "Never invent exploit payloads, commands, URLs, or parameters. Keep POC empty. "
              f"Required fields: CVE ID, vendor, product, version, URI, form_parameter, form_format, button, navigation, vul_type, function name, parameter or argument, POC, description, references. "
              f"Vendor={vendor}; Product={product}; Version={version}; Input={json.dumps(compact, ensure_ascii=False)}")
    try:
        text = _provider_request(provider, api_key, base_url, model, [{"role": "user", "content": prompt}], 7000, timeout)
        match = re.search(r"\[[\s\S]*\]", text)
        values = json.loads(match.group(0)) if match else []
        allowed = {item["CVE ID"]: item for item in base_entries}
        enriched = {item["CVE ID"]: dict(item) for item in base_entries}
        for value in values if isinstance(values, list) else []:
            if not isinstance(value, dict) or value.get("CVE ID") not in allowed:
                continue
            item = enriched[value["CVE ID"]]
            for field in ("URI", "form_parameter", "form_format", "button", "navigation", "vul_type", "function name", "parameter or argument"):
                if isinstance(value.get(field), str) and len(value[field]) <= 500:
                    item[field] = value[field]
        return list(enriched.values())
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, IndexError, AttributeError, TypeError):
        return base_entries


def test_provider(provider: str, api_key: str, base_url: str, model: str, timeout: float = 20.0) -> dict[str, Any]:
    """Make a minimal non-streaming request and return only safe diagnostics."""
    if provider not in PROVIDER_DEFAULTS:
        raise ValueError("Unsupported provider")
    if not api_key.strip():
        raise ValueError("API key is required")
    base = base_url.rstrip("/")
    started = time.perf_counter()
    if PROVIDER_DEFAULTS[provider]["protocol"] == "anthropic":
        url = base if base.endswith("/messages") else f"{base}/v1/messages"
        payload = {"model": model, "max_tokens": 16, "messages": [{"role": "user", "content": "Reply with OK."}]}
        headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
    else:
        url = base if base.endswith("/chat/completions") else f"{base}/chat/completions"
        payload = {"model": model, "messages": [{"role": "user", "content": "Reply with OK."}], "max_tokens": 16, "stream": False}
        headers = ({"api-key": api_key} if provider == "mimo" else {"Authorization": f"Bearer {api_key}"})
        headers["Content-Type"] = "application/json"
    request = Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    try:
        with build_opener().open(request, timeout=timeout) as response:
            body = response.read(128 * 1024)
            return {"ok": 200 <= response.status < 300, "provider": provider, "model": model,
                    "status": response.status, "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                    "response_preview": body[:180].decode("utf-8", errors="replace")}
    except HTTPError as error:
        body = error.read(128 * 1024) if error.fp else b""
        return {"ok": False, "provider": provider, "model": model, "status": error.code,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                "error": body[:240].decode("utf-8", errors="replace")}
    except (URLError, TimeoutError) as error:
        return {"ok": False, "provider": provider, "model": model, "status": 0,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 1), "error": str(error)}


def llm_variants(provider: str, api_key: str, base_url: str, model: str,
                 interfaces: Iterable[dict[str, Any]], timeout: float = 30.0) -> list[str]:
    """Ask the configured model for bounded, non-executable marker strings."""
    if provider not in PROVIDER_DEFAULTS or not api_key.strip():
        return []
    summary = []
    for item in list(interfaces)[:12]:
        interface = item.get("interface", {})
        summary.append({"uri": interface.get("URI", "/"), "parameters": parse_parameters(interface.get("form_parameter")),
                        "vulnerability_types": sorted({entry.get("vul_type", "") for entry in item.get("matches", []) if entry.get("vul_type")})})
    prompt = ("Return only a JSON array of at most 8 short strings for safe black-box robustness testing. "
              "Use markers, boundary values, encoding probes, or benign structured values only. "
              "Do not include shell commands, URLs, file paths, exploit code, or instructions. "
              f"Interface summary: {json.dumps(summary, ensure_ascii=False)}")
    base = base_url.rstrip("/")
    if PROVIDER_DEFAULTS[provider]["protocol"] == "anthropic":
        url = base if base.endswith("/messages") else f"{base}/v1/messages"
        payload = {"model": model, "max_tokens": 180, "messages": [{"role": "user", "content": prompt}]}
        headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
    else:
        url = base if base.endswith("/chat/completions") else f"{base}/chat/completions"
        payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "max_tokens": 180, "temperature": 0, "stream": False}
        headers = ({"api-key": api_key} if provider == "mimo" else {"Authorization": f"Bearer {api_key}"})
        headers["Content-Type"] = "application/json"
    request = Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    try:
        with build_opener().open(request, timeout=timeout) as response:
            data = json.loads(response.read(128 * 1024).decode("utf-8", errors="replace"))
        if PROVIDER_DEFAULTS[provider]["protocol"] == "anthropic":
            text = "".join(part.get("text", "") for part in data.get("content", []) if isinstance(part, dict))
        else:
            text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        match = re.search(r"\[[\s\S]*\]", text)
        values = json.loads(match.group(0)) if match else []
        if not isinstance(values, list):
            return []
        safe = []
        for value in values:
            value = str(value).strip()
            if 1 <= len(value) <= 80 and re.fullmatch(r"[A-Za-z0-9%{}._:/?=+\-\\一-龥]+", value) and value not in safe:
                safe.append(value)
        return safe[:8]
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, IndexError, AttributeError, TypeError):
        return []


def parse_parameters(value: Any) -> list[str]:
    """Normalize the repository's list-string and query-string formats."""
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value or "").strip()
    if not text:
        return []
    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = ast.literal_eval(text)
            if isinstance(parsed, (list, tuple)):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except (ValueError, SyntaxError):
            pass
    return [key for key, _ in parse_qsl(text, keep_blank_values=True)]


def _stringify(value: Any) -> str:
    if isinstance(value, (list, tuple, dict)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return str(value or "").strip()


def similarity(left: Any, right: Any) -> float:
    # The paper uses a case-sensitive fuzz.ratio score for every field.
    return SequenceMatcher(None, _stringify(left), _stringify(right)).ratio() * 100


def _parameter_signature(value: Any) -> str:
    """Represent parameter names like the original VIS JSON records."""
    parsed = parse_parameters(value)
    return repr(parsed) if parsed else _stringify(value)


def field_similarity(field: str, left: Any, right: Any) -> float:
    if field == "form_parameter":
        return similarity(_parameter_signature(left), _parameter_signature(right))
    return similarity(left, right)


def weighted_match(target: dict[str, Any], candidate: dict[str, Any]) -> float:
    total = sum(MATCH_FIELDS.values())
    score = sum(field_similarity(field, target.get(field), candidate.get(field)) * weight
                for field, weight in MATCH_FIELDS.items())
    return round(score / total, 2) if total else 0.0


def match_signatures(interface_data: Any, database_data: Any, threshold: float) -> list[dict[str, Any]]:
    interfaces = interface_data if isinstance(interface_data, list) else [interface_data]
    database = database_data if isinstance(database_data, list) else [database_data]
    matches: list[dict[str, Any]] = []
    for interface in interfaces:
        if not isinstance(interface, dict):
            continue
        ranked = []
        for vulnerability in database:
            if not isinstance(vulnerability, dict):
                continue
            score = weighted_match(interface, vulnerability)
            if score >= threshold:
                ranked.append({"score": score, "vulnerability": vulnerability})
        ranked.sort(key=lambda item: item["score"], reverse=True)
        matches.append({"interface": interface, "matches": ranked[:10], "match_count": len(ranked)})
    return matches


def _focus_parameters(interface: dict[str, Any], matches: list[dict[str, Any]]) -> list[str]:
    critical: list[str] = []
    for match in matches:
        vulnerability = match.get("vulnerability", {})
        for raw in parse_parameters(vulnerability.get("parameter or argument")):
            if raw and raw not in critical:
                critical.append(raw)
    return critical or parse_parameters(interface.get("form_parameter"))


def generate_cases(matched_interfaces: Iterable[dict[str, Any]], max_cases: int, method: str = "POST",
                   variants: Iterable[str] | None = None) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    variants = tuple(variants or SAFE_VARIANTS)
    for item in matched_interfaces:
        # The paper activates fuzzing only after an IS has matched at least one
        # VIS.  match_signatures() deliberately returns every discovered
        # interface so that the UI can report discovery statistics; do not
        # turn the unmatched entries into broad, unguided fuzzing cases.
        matches = item.get("matches", [])
        if not matches:
            continue
        interface = item["interface"]
        parameters = _focus_parameters(interface, matches) or ["value"]
        base = {str(key): str(value) for key, value in (interface.get("seed_body") or {}).items()}
        base.update({parameter: base.get(parameter, "") for parameter in parameters})
        for parameter in parameters:
            for variant in variants:
                body = dict(base)
                body[parameter] = variant
                vulnerabilities = [entry["vulnerability"] for entry in matches]
                cases.append({
                    "id": f"case-{len(cases) + 1:04d}", "method": str(interface.get("method", method)).upper(), "uri": interface.get("URI", "/"),
                    "parameter": parameter, "value": variant, "body": body,
                    "match_score": max(entry["score"] for entry in matches),
                    "matched_cves": [entry.get("CVE ID", "") for entry in vulnerabilities if entry.get("CVE ID")],
                    "matched_records": [entry.get("record_id", "") for entry in vulnerabilities if entry.get("record_id")],
                    "vulnerability_types": sorted({entry.get("vul_type", "") for entry in vulnerabilities if entry.get("vul_type")}),
                })
                if len(cases) >= max_cases:
                    return cases
    return cases


class _InterfaceParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "a" and values.get("href"):
            self.links.append(values["href"])
        elif tag.lower() == "form":
            self._form = {"action": values.get("action", ""), "method": values.get("method", "POST").upper(), "parameters": [], "button": ""}
            self.forms.append(self._form)
        elif self._form is not None and tag.lower() in {"input", "select", "textarea"} and values.get("name"):
            if values["name"] not in self._form["parameters"]:
                self._form["parameters"].append(values["name"])
            if tag.lower() == "input" and values.get("type", "").lower() in {"submit", "button"} and values.get("value"):
                self._form["button"] = values["value"]
        elif self._form is not None and tag.lower() == "button" and values.get("name"):
            if values["name"] not in self._form["parameters"]:
                self._form["parameters"].append(values["name"])

    def handle_endtag(self, tag: str):
        if tag.lower() == "form":
            self._form = None


def _same_origin(base: str, candidate: str) -> bool:
    return urlsplit(base).netloc.lower() == urlsplit(candidate).netloc.lower()


def _relative_uri(base: str, candidate: str) -> str:
    parsed = urlsplit(candidate)
    path = parsed.path or "/"
    return f"{path}?{parsed.query}" if parsed.query else path


def discover_interfaces(client: "BlackBoxClient", max_pages: int = 30, max_depth: int = 2) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Discover live web interfaces for the target IS without using VS URI seeds."""
    root = client.base_url.rstrip("/")
    queue: list[tuple[str, int]] = [(root + "/", 0)]
    visited: set[str] = set()
    interfaces: list[dict[str, Any]] = []
    seen_signatures: set[tuple[str, str, tuple[str, ...]]] = set()
    pages = 0
    errors: list[str] = []

    def add_interface(uri: str, method: str, parameters: list[str], button: str, navigation: str):
        signature = (method.upper(), uri, tuple(sorted(set(parameters))))
        if signature in seen_signatures:
            return
        seen_signatures.add(signature)
        interfaces.append({"URI": uri, "form_parameter": list(dict.fromkeys(parameters)), "form_format": "key-value",
                           "button": button, "navigation": navigation, "method": method.upper(), "source": "blackbox"})

    while queue and pages < max_pages:
        page_url, depth = queue.pop(0)
        if page_url in visited or not _same_origin(root, page_url):
            continue
        visited.add(page_url)
        document = client.fetch_page(page_url)
        if document.get("status", 0) == 0:
            errors.append(f"{page_url}: {document.get('error', 'request failed')}")
            continue
        pages += 1
        text = document.get("body", b"").decode("utf-8", errors="replace")
        parser = _InterfaceParser()
        try:
            parser.feed(text)
        except Exception as error:
            errors.append(f"{page_url}: parser {error}")
        page_uri = _relative_uri(root, page_url)
        if parser.forms:
            for form in parser.forms:
                action = urljoin(page_url, form.get("action") or page_url)
                if _same_origin(root, action):
                    add_interface(_relative_uri(root, action), form.get("method", "POST"), form.get("parameters", []), form.get("button", ""), page_uri)
        else:
            parsed_page = urlsplit(page_url)
            add_interface(page_uri, "GET", [key for key, _ in parse_qsl(parsed_page.query, keep_blank_values=True)], "", page_uri)
        for link in parser.links:
            if link.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            target = urljoin(page_url, link)
            if _same_origin(root, target):
                target_uri = _relative_uri(root, target)
                if urlsplit(target).query:
                    add_interface(target_uri, "GET", [key for key, _ in parse_qsl(urlsplit(target).query, keep_blank_values=True)], "", page_uri)
                if depth < max_depth and not re.search(r"\.(?:css|js|png|jpg|jpeg|gif|svg|ico|woff2?)$", urlsplit(target).path, re.I):
                    queue.append((target, depth + 1))
        for token in re.findall(r"[\"']((?:/|\.\.?/)[^\"'\s<>]{2,160})[\"']", text):
            target = urljoin(page_url, token)
            if _same_origin(root, target) and re.search(r"(?:api|cgi|form|goform|action|login|rpc)", token, re.I):
                add_interface(_relative_uri(root, target), "POST", [], "", page_uri)

    return interfaces, {"pages": pages, "queued": len(queue), "seeded": 0,
                        "errors": errors[:20], "source": "blackbox"}


class BlackBoxClient:
    def __init__(self, base_url: str, username: str = "", password: str = "", timeout: float = 8.0):
        self.base_url = base_url.rstrip("/") + "/"
        self.username, self.password, self.timeout = username, password, timeout
        self.route_base = ""
        self.route_prefix = ""
        self.cookies = CookieJar()
        handlers = [HTTPCookieProcessor(self.cookies)]
        if username and password:
            manager = HTTPPasswordMgrWithDefaultRealm()
            manager.add_password(None, self.base_url, username, password)
            handlers.append(HTTPBasicAuthHandler(manager))
        self.opener = build_opener(*handlers)

    def login(self, login_path: str, username_field: str, password_field: str) -> dict[str, Any]:
        if not login_path:
            return {"status": "skipped", "reason": "No login path configured"}
        self.route_base = urlsplit(login_path).path.rstrip("/")
        payload = urlencode({username_field: self.username, password_field: self.password}).encode()
        request = Request(urljoin(self.base_url, login_path.lstrip("/")), data=payload,
                          headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
        return self._request(request, stage="login")

    def build_target(self, uri: str) -> str:
        """Build a target URL, preserving LuCI's session route for API calls."""
        parsed = urlsplit(str(uri or "/"))
        path = parsed.path or "/"
        if self.route_prefix and (path == "/api" or path.startswith("/api/")) and not path.startswith(self.route_prefix + "/"):
            path = f"{self.route_prefix.rstrip('/')}/{path.lstrip('/')}"
        suffix = f"{path}?{parsed.query}" if parsed.query else path
        return urljoin(self.base_url, suffix.lstrip("/"))

    def _remember_session_route(self, location: str, body: bytes) -> None:
        text = f"{location}\n{body[:512 * 1024].decode('utf-8', errors='replace')}"
        match = re.search(r"[;?]stok=([A-Za-z0-9._~-]+)", text)
        if not match:
            return
        token = match.group(1)
        if self.route_base:
            self.route_prefix = f"{self.route_base}/;stok={token}"
            return
        prefix = re.search(r"(/(?:[^\"'<>\s]+/)*;stok=" + re.escape(token) + r")", text)
        if prefix:
            self.route_prefix = prefix.group(1)

    def send_case(self, case: dict[str, Any]) -> dict[str, Any]:
        target = self.build_target(case["uri"])
        headers = {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "IoTBec-Lab/0.1",
                   "X-Requested-With": "XMLHttpRequest"}
        if self.route_prefix:
            headers["Referer"] = urljoin(self.base_url, f"{self.route_prefix.lstrip('/')}/")
        if case["method"] == "GET":
            separator = "&" if urlsplit(target).query else "?"
            target = f"{target}{separator}{urlencode(case['body'])}" if case["body"] else target
            payload = None
        else:
            payload = urlencode(case["body"]).encode()
        request = Request(target, data=payload, headers=headers, method=case["method"])
        result = self._request(request, stage=case["id"])
        result["case_id"] = case["id"]
        result["anomaly"] = result.get("status", 0) >= 500 or result.get("error_type") in {"timeout", "connection"}
        return result

    @staticmethod
    def _read_body(stream, limit: int) -> bytes:
        try:
            return stream.read(limit) if stream else b""
        except (TimeoutError, OSError):
            return b""

    def fetch_page(self, target: str) -> dict[str, Any]:
        request = Request(target, headers={"User-Agent": "IoTBec-Lab/0.1", "Accept": "text/html,application/xhtml+xml,application/json"}, method="GET")
        started = time.perf_counter()
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body = self._read_body(response, 512 * 1024)
                self._remember_session_route(response.geturl(), body)
                return {"status": response.status, "body": body, "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)}
        except HTTPError as error:
            body = self._read_body(error, 512 * 1024)
            self._remember_session_route(error.geturl(), body)
            return {"status": error.code, "body": body, "error": "http"}
        except (TimeoutError, OSError):
            return {"status": 0, "body": b"", "error": "timeout"}
        except URLError as error:
            return {"status": 0, "body": b"", "error": str(error.reason)}

    def _request(self, request: Request, stage: str) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body = self._read_body(response, 256 * 1024)
                self._remember_session_route(response.geturl(), body)
                result = {"stage": stage, "status": response.status, "bytes": len(body), "elapsed_ms": round((time.perf_counter() - started) * 1000, 1), "response_preview": body[:240].decode("utf-8", errors="replace")}
                if stage == "login":
                    text = body.decode("utf-8", errors="replace")
                    result["login_form_detected"] = bool(re.search(r"name=[\"']username[\"']", text, re.I) and re.search(r"name=[\"']password[\"']", text, re.I))
                    result["authenticated"] = not result["login_form_detected"]
                return result
        except HTTPError as error:
            body = self._read_body(error, 256 * 1024)
            self._remember_session_route(error.geturl(), body)
            return {"stage": stage, "status": error.code, "bytes": len(body), "elapsed_ms": round((time.perf_counter() - started) * 1000, 1), "response_preview": body[:240].decode("utf-8", errors="replace"), "error_type": "http"}
        except (TimeoutError, OSError):
            return {"stage": stage, "status": 0, "bytes": 0, "elapsed_ms": round((time.perf_counter() - started) * 1000, 1), "error_type": "timeout", "error": "request timed out"}
        except URLError as error:
            return {"stage": stage, "status": 0, "bytes": 0, "elapsed_ms": round((time.perf_counter() - started) * 1000, 1), "error_type": "connection", "error": str(error.reason)}


def catalog() -> dict[str, Any]:
    result_root = REPO_ROOT / "code" / "result"
    interface_files, database_files = [], []
    if result_root.exists():
        for path in result_root.rglob("*.json"):
            relative = path.relative_to(REPO_ROOT).as_posix()
            try:
                content = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            entry = {"path": relative, "count": len(content) if isinstance(content, list) else 1}
            is_har = isinstance(content, dict) and isinstance(content.get("log", {}).get("entries"), list)
            if path.name.endswith("_page.json") or path.name.endswith("_IS.json") or is_har:
                interface_files.append(entry)
            if path.name == "database.json" or path.name.endswith("_CVE.json") or path.name == "AC18.json":
                database_files.append(entry)
    return {"interface_files": sorted(interface_files, key=lambda item: item["path"]), "database_files": sorted(database_files, key=lambda item: item["path"]), "default_database": DEFAULT_DATABASE.as_posix()}

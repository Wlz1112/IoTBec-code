"""Local Web UI and API for the IoTBec research workflow."""

from __future__ import annotations

import json
import copy
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from engine import (BlackBoxClient, DEFAULT_DATABASE, REPO_ROOT, catalog, discover_interfaces, generate_cases,
                    llm_enrich_cves, llm_variants, load_interface_capture, load_json, match_signatures,
                    parse_interface_capture, provider_defaults, search_nvd, test_provider)

APP_ROOT = Path(__file__).resolve().parent
STATIC_ROOT = APP_ROOT / "static"
DATA_ROOT = APP_ROOT / "data"
TASKS_PATH = DATA_ROOT / "tasks.json"
TASKS: dict[str, dict] = {}
LOCK = threading.RLock()
STOP_EVENTS: dict[str, threading.Event] = {}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def save_tasks() -> None:
    DATA_ROOT.mkdir(exist_ok=True)
    visible = {key: public_task(value, include_results=False) for key, value in TASKS.items()}
    TASKS_PATH.write_text(json.dumps(visible, ensure_ascii=False, indent=2), encoding="utf-8")


def load_tasks() -> None:
    if not TASKS_PATH.exists():
        return
    try:
        values = json.loads(TASKS_PATH.read_text(encoding="utf-8"))
        if isinstance(values, dict):
            TASKS.update(values)
    except (OSError, json.JSONDecodeError):
        return


def add_log(task_id: str, message: str) -> None:
    with LOCK:
        task = TASKS[task_id]
        task.setdefault("logs", []).append({"time": now(), "message": message})
        task["updated_at"] = now()
        save_tasks()


def update_task(task_id: str, **changes) -> None:
    with LOCK:
        TASKS[task_id].update(changes)
        TASKS[task_id]["updated_at"] = now()
        save_tasks()


def redact(value):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key.lower() in {"password", "api_key", "apikey", "authorization", "secret"}:
                result[key] = "********"
            else:
                result[key] = redact(item)
        return result
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def public_task(task: dict, include_results: bool = True) -> dict:
    visible = copy.deepcopy(task)
    if not include_results:
        visible.pop("results", None)
    visible.pop("stop_event", None)
    return redact(visible)


def run_task(task_id: str) -> None:
    task = TASKS[task_id]
    config = task["config"]
    stop_event = STOP_EVENTS[task_id]
    try:
        client = None
        login_result = None
        discovery = {"source": "offline-json", "pages": 0, "queued": 0, "seeded": 0, "errors": []}
        database_data = load_json(config.get("database_path") or DEFAULT_DATABASE)
        interface_source = config.get("interface_source", "blackbox")
        if interface_source == "blackbox":
            client = BlackBoxClient(config["target_url"], config.get("username", ""), config.get("password", ""), float(config.get("timeout", 8)))
            login_result = client.login(config.get("login_path", ""), config.get("username_field", "username"), config.get("password_field", "password"))
            if login_result.get("login_form_detected"):
                add_log(task_id, "Login stage: HTTP response still contains the login form; credentials or session may be invalid")
            elif login_result.get("status") not in {"skipped", 200, 302}:
                add_log(task_id, f"Login stage: {login_result.get('status', 'unknown')}")
            interface_data, discovery = discover_interfaces(client, int(config.get("max_pages", 30)), int(config.get("max_depth", 2)))
            discovery["source"] = "blackbox-is"
            add_log(task_id, f"Paper IS discovery: {discovery.get('pages', 0)} pages, {len(interface_data)} live interfaces; VS URI seeding disabled")
        elif interface_source in {"har-json", "offline-json"}:
            interface_data = config.get("interface_json") or load_interface_capture(config["interface_path"])
            discovery = {"source": "network-capture-is" if interface_source == "har-json" else "offline-is",
                         "pages": 0, "queued": 0, "seeded": 0, "errors": []}
            label = "browser network capture" if interface_source == "har-json" else "existing IS JSON"
            add_log(task_id, f"Paper IS import: {len(interface_data)} interfaces from {label}; VS URI seeding disabled")
        else:
            raise ValueError("Unsupported interface source")
        if not interface_data:
            raise ValueError("No web interfaces discovered; check target URL, login settings and network reachability")
        update_task(task_id, discovered_interfaces=len(interface_data), discovered_pages=discovery.get("pages", 0), discovery=discovery)
        update_task(task_id, phase="matching")
        matched = match_signatures(interface_data, database_data, float(config.get("threshold", 75)))
        variants = None
        if config.get("llm_enabled"):
            provider = config.get("provider", "mimo")
            api_key = config.get("api_key", "") or os.getenv(f"IOTBEC_{provider.upper()}_API_KEY", "")
            variants = llm_variants(provider, api_key, config.get("base_url", ""), config.get("model", ""), matched,
                                     float(config.get("timeout", 8)) + 10)
            add_log(task_id, f"Model-assisted markers: {len(variants)} accepted")
        cases = generate_cases(matched, int(config.get("max_cases", 50)), config.get("method", "POST"), variants)
        matches_count = sum(item["match_count"] for item in matched)
        update_task(task_id, total=len(cases), matches=matches_count, phase="prepared", matches_detail=matched)
        add_log(task_id, f"Prepared {len(cases)} safe test cases across {len(matched)} interfaces")

        results = []
        if config.get("mode") == "live":
            if not config.get("authorized"):
                raise ValueError("Live mode requires the authorization confirmation")
            if client is None:
                client = BlackBoxClient(config["target_url"], config.get("username", ""), config.get("password", ""), float(config.get("timeout", 8)))
                login_result = client.login(config.get("login_path", ""), config.get("username_field", "username"), config.get("password_field", "password"))
            login = login_result or {"status": "skipped"}
            if login.get("login_form_detected"):
                raise ValueError("Login failed: target returned the login form; check credentials and session settings before live testing")
            results.append({"kind": "login", **login})
            if login.get("login_form_detected"):
                add_log(task_id, "Login stage: HTTP response still contains the login form; live validation may be unauthenticated")
            else:
                add_log(task_id, f"Login stage: {login.get('status', 'unknown')}")
            consecutive_failures = 0
            for index, case in enumerate(cases, start=1):
                if stop_event.is_set():
                    update_task(task_id, status="stopped", phase="stopped")
                    break
                result = client.send_case(case)
                results.append({"kind": "case", **case, **result})
                update_task(task_id, processed=index, anomalies=sum(1 for item in results if item.get("anomaly")))
                if result.get("error_type") in {"timeout", "connection"}:
                    consecutive_failures += 1
                    if consecutive_failures == 1:
                        add_log(task_id, f"Target did not respond for {case.get('id')}: {result.get('error_type')}")
                    if consecutive_failures >= 3:
                        update_task(task_id, status="stopped", phase="stopped", error="Target stopped responding")
                        add_log(task_id, "Stopped after 3 consecutive target connection failures")
                        break
                else:
                    consecutive_failures = 0
                time.sleep(max(0, float(config.get("delay_ms", 250))) / 1000)
        else:
            results = [{"kind": "preview", **case, "status": "not_sent", "anomaly": False} for case in cases]
            update_task(task_id, processed=len(results), phase="preview")

        report_path = DATA_ROOT / f"{task_id}.json"
        report_path.write_text(json.dumps({"task": public_task(task), "discovery": discovery, "matches": matched, "results": redact(results)}, ensure_ascii=False, indent=2), encoding="utf-8")
        with LOCK:
            task["results"] = results
        if TASKS[task_id].get("status") != "stopped":
            update_task(task_id, status="completed", phase="completed", report=f"dashboard/data/{task_id}.json")
            add_log(task_id, "Task completed")
        else:
            update_task(task_id, report=f"dashboard/data/{task_id}.json")
            add_log(task_id, "Task stopped with partial results")
    except Exception as error:
        update_task(task_id, status="failed", phase="failed", error=str(error))
        add_log(task_id, f"Task failed: {error}")


class Handler(BaseHTTPRequestHandler):
    server_version = "IoTBecDashboard/0.1"

    def log_message(self, format, *args):
        return

    def _json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8"))

    def do_GET(self):
        route = urlparse(self.path).path.rstrip("/") or "/"
        if route == "/api/health":
            return self._json({"ok": True, "service": "IoTBec dashboard"})
        if route == "/api/providers":
            providers = provider_defaults()
            for provider in providers:
                providers[provider]["configured"] = bool(os.getenv(f"IOTBEC_{provider.upper()}_API_KEY"))
            return self._json(providers)
        if route == "/api/catalog":
            return self._json(catalog())
        if route == "/api/tasks":
            with LOCK:
                return self._json([public_task(task) for task in TASKS.values()])
        if route.startswith("/api/tasks/"):
            parts = route.split("/")
            task_id = parts[3] if len(parts) > 3 else ""
            with LOCK:
                task = TASKS.get(task_id)
                if not task:
                    return self._json({"error": "Task not found"}, 404)
                if len(parts) > 4 and parts[4] == "results":
                    return self._json({"task": public_task(task), "results": redact(task.get("results", []))})
                return self._json(public_task(task))
        if route == "/" or route == "/index.html":
            return self._static("index.html", "text/html; charset=utf-8")
        if route.startswith("/static/"):
            return self._static(route.removeprefix("/static/"))
        return self._json({"error": "Not found"}, 404)

    def _static(self, name, content_type=None):
        path = (STATIC_ROOT / name).resolve()
        try:
            path.relative_to(STATIC_ROOT.resolve())
        except ValueError:
            return self._json({"error": "Not found"}, 404)
        if not path.exists() or not path.is_file():
            return self._json({"error": "Not found"}, 404)
        body = path.read_bytes()
        content_type = content_type or {".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8"}.get(path.suffix, "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        route = urlparse(self.path).path.rstrip("/")
        try:
            if route == "/api/tasks":
                config = self._body()
                task_id = uuid.uuid4().hex[:10]
                config.setdefault("mode", "preview")
                config.setdefault("threshold", 75)
                config.setdefault("max_cases", 50)
                config.setdefault("delay_ms", 250)
                if config.get("mode") == "live" and not config.get("authorized"):
                    return self._json({"error": "Live mode requires authorization confirmation"}, 400)
                if not config.get("target_url", "").startswith(("http://", "https://")):
                    return self._json({"error": "Target URL must start with http:// or https://"}, 400)
                config.setdefault("interface_source", "blackbox")
                if config.get("interface_source") == "har-json" and isinstance(config.get("interface_json"), dict):
                    config["interface_json"] = parse_interface_capture(config["interface_json"])
                if config.get("interface_source") in {"offline-json", "har-json"} and not config.get("interface_json") and not config.get("interface_path"):
                    return self._json({"error": "A captured IS/HAR JSON path is required"}, 400)
                task = {"id": task_id, "status": "queued", "phase": "queued", "created_at": now(), "updated_at": now(), "processed": 0, "total": 0, "matches": 0, "anomalies": 0, "logs": [], "config": config, "results": []}
                with LOCK:
                    TASKS[task_id] = task
                    STOP_EVENTS[task_id] = threading.Event()
                    save_tasks()
                threading.Thread(target=run_task, args=(task_id,), daemon=True).start()
                return self._json(public_task(task), 202)
            if route == "/api/providers/test":
                config = self._body()
                provider = config.get("provider", "")
                api_key = config.get("api_key", "") or os.getenv(f"IOTBEC_{provider.upper()}_API_KEY", "")
                result = test_provider(provider, api_key,
                                       config.get("base_url", ""), config.get("model", ""),
                                       float(config.get("timeout", 20)))
                return self._json(result, 200 if result.get("ok") else 502)
            if route == "/api/cve/search":
                config = self._body()
                vendor = str(config.get("vendor", "")).strip()
                product = str(config.get("product", "")).strip()
                version = str(config.get("version", "")).strip()
                keywords = str(config.get("keywords", "")).strip()
                if not vendor and not product:
                    return self._json({"error": "Vendor or product is required"}, 400)
                records = search_nvd(vendor, product, version, keywords, os.getenv("NVD_API_KEY", ""), timeout=30, max_results=100)
                provider = config.get("provider", "mimo")
                llm_key = config.get("api_key", "") or os.getenv(f"IOTBEC_{provider.upper()}_API_KEY", "")
                entries = llm_enrich_cves(provider, llm_key, config.get("base_url", ""), config.get("model", ""), records, vendor, product, version)
                output_root = REPO_ROOT / "code" / "result" / "generated"
                output_root.mkdir(parents=True, exist_ok=True)
                slug = re.sub(r"[^A-Za-z0-9._-]+", "_", "_".join(part for part in (vendor, product, version) if part))[:120].strip("._") or "cve_database"
                output_path = output_root / f"{slug}_CVE.json"
                output_path.write_text(json.dumps(entries, ensure_ascii=False, indent=2), encoding="utf-8")
                source = "NVD 2.0 + LLM normalization (best effort)" if llm_key and provider else "NVD 2.0 deterministic normalization"
                return self._json({"ok": True, "vendor": vendor, "product": product, "version": version,
                                   "source": source, "cve_count": len(entries),
                                   "path": output_path.relative_to(REPO_ROOT).as_posix(),
                                   "cve_ids": [item["CVE ID"] for item in entries]})
            if route.startswith("/api/tasks/") and route.endswith("/stop"):
                task_id = route.split("/")[3]
                if task_id not in STOP_EVENTS:
                    return self._json({"error": "Task not found"}, 404)
                STOP_EVENTS[task_id].set()
                add_log(task_id, "Stop requested")
                return self._json({"ok": True})
            return self._json({"error": "Not found"}, 404)
        except (ValueError, FileNotFoundError, json.JSONDecodeError) as error:
            return self._json({"error": str(error)}, 400)
        except Exception as error:
            return self._json({"error": str(error)}, 500)


def main():
    load_tasks()
    port = 8765
    print(f"IoTBec dashboard: http://127.0.0.1:{port}")
    print("Default mode is preview; only test authorized lab devices in live mode.")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()

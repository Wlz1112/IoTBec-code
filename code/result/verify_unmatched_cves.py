"""Find CVE records omitted from a VIS file and verify their IS evidence.

This is an offline structural check. It does not claim that a CVE is
exploitable on the target device; that requires sending a payload to an
authorized isolated target and reviewing its runtime behavior.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
from pathlib import Path
from typing import Any


def load_records(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"Expected a JSON list of objects: {path}")
    return value


def parameter_names(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value or "").strip()
    if not text:
        return []
    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = ast.literal_eval(text)
        except (ValueError, SyntaxError):
            parsed = None
        if isinstance(parsed, (list, tuple)):
            return [str(item).strip() for item in parsed if str(item).strip()]
    return [part for part in re.split(r"[,/\s]+", text) if part]


def verify_unmatched(cve_records: list[dict[str, Any]], vis_records: list[dict[str, Any]],
                     interface_records: list[dict[str, Any]]) -> dict[str, Any]:
    known_ids = {str(item.get("CVE ID", "")).strip() for item in vis_records}
    page_by_uri = {
        str(item.get("URI", "")).strip(): item
        for item in interface_records
        if str(item.get("URI", "")).strip()
    }
    missing = [item for item in cve_records if str(item.get("CVE ID", "")).strip() not in known_ids]
    candidates: list[dict[str, Any]] = []
    reviewed: list[dict[str, Any]] = []
    for cve in missing:
        uri = str(cve.get("URI", "")).strip()
        interface = page_by_uri.get(uri)
        critical = parameter_names(cve.get("parameter or argument"))
        interface_parameters = parameter_names(interface.get("form_parameter")) if interface else []
        present = [item for item in critical if item in interface_parameters]
        absent = [item for item in critical if item not in interface_parameters]
        if interface is None:
            status = "no_matching_interface"
        elif not absent:
            status = "structural_candidate"
        else:
            status = "parameter_needs_review"
        record = {
            "CVE ID": cve.get("CVE ID", ""),
            "vendor": cve.get("vendor", ""),
            "product": cve.get("product", ""),
            "URI": uri,
            "vul_type": cve.get("vul_type", ""),
            "function name": cve.get("function name", ""),
            "parameter or argument": cve.get("parameter or argument", ""),
            "status": status,
            "evidence": {
                "uri_exact_match": interface is not None,
                "critical_parameters": critical,
                "parameters_present_in_interface": present,
                "parameters_missing_from_interface": absent,
                "interface_parameters": interface_parameters,
                "button": interface.get("button", "") if interface else "",
                "navigation": interface.get("navigation", "") if interface else "",
            },
        }
        reviewed.append(record)
        if status == "structural_candidate":
            candidates.append(record)
    return {
        "method": "exact URI plus critical-parameter containment",
        "claim": "structural candidate only; live validation is required to confirm exploitability",
        "source_counts": {
            "cve_records": len(cve_records),
            "known_vis_records": len(vis_records),
            "target_interfaces": len(interface_records),
            "cves_not_in_vis": len(missing),
        },
        "candidate_count": len(candidates),
        "candidates": candidates,
        "all_unmatched_records": reviewed,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify CVEs omitted from an IoTBec VIS database.")
    parser.add_argument("--cve", type=Path, required=True, help="Extracted CVE JSON")
    parser.add_argument("--vis", type=Path, required=True, help="Known VIS JSON")
    parser.add_argument("--is", dest="interface", type=Path, required=True, help="Target IS JSON")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = verify_unmatched(load_records(args.cve), load_records(args.vis), load_records(args.interface))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(args.output), "candidate_count": report["candidate_count"],
                      **report["source_counts"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()

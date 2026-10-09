import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "dashboard"))

import engine  # noqa: E402


class GenerateCasesTests(unittest.TestCase):
    def test_unmatched_interface_does_not_generate_cases(self):
        matched_interfaces = [
            {
                "interface": {
                    "URI": "/goform/example",
                    "form_parameter": ["name"],
                    "method": "POST",
                },
                "matches": [],
                "match_count": 0,
            }
        ]

        self.assertEqual(engine.generate_cases(matched_interfaces, 50), [])

    def test_matched_interface_uses_vis_critical_parameter(self):
        matched_interfaces = [
            {
                "interface": {
                    "URI": "/goform/example",
                    "form_parameter": ["name", "enabled"],
                    "method": "POST",
                    "seed_body": {"name": "router", "enabled": "1"},
                },
                "matches": [
                    {
                        "score": 88.5,
                        "vulnerability": {
                            "CVE ID": "CVE-2026-0001",
                            "vul_type": "Overflow",
                            "parameter or argument": "name",
                        },
                    }
                ],
                "match_count": 1,
            }
        ]

        cases = engine.generate_cases(matched_interfaces, 10, variants=["MARKER"])

        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["parameter"], "name")
        self.assertEqual(cases[0]["body"], {"name": "MARKER", "enabled": "1"})
        self.assertEqual(cases[0]["matched_cves"], ["CVE-2026-0001"])
        self.assertEqual(cases[0]["match_score"], 88.5)


if __name__ == "__main__":
    unittest.main()

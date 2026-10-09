import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "code" / "result"))

from verify_unmatched_cves import load_records, verify_unmatched  # noqa: E402


class UnmatchedCveTests(unittest.TestCase):
    def test_ac18_candidates_have_interface_evidence(self):
        base = PROJECT_ROOT / "code" / "result" / "Tenda" / "AC" / "AC18"
        report = verify_unmatched(
            load_records(base / "AC18_CVE.json"),
            load_records(base / "AC18.json"),
            load_records(base / "AC18_page.json"),
        )

        self.assertEqual(report["source_counts"]["cves_not_in_vis"], 54)
        self.assertEqual(report["candidate_count"], 3)
        self.assertEqual(
            {item["CVE ID"] for item in report["candidates"]},
            {"CVE-2020-13394", "CVE-2020-13393", "CVE-2020-13389"},
        )
        self.assertTrue(all(item["evidence"]["uri_exact_match"] for item in report["candidates"]))
        self.assertTrue(all(not item["evidence"]["parameters_missing_from_interface"]
                            for item in report["candidates"]))


if __name__ == "__main__":
    unittest.main()

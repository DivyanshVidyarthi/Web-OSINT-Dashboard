"""
Unit tests for findings.py — pure logic over already-collected results,
so no network or external services are needed.
"""
import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.osint.findings import build_findings  # noqa: E402


class TestFindings(unittest.TestCase):
    def test_no_data_produces_info_fallback(self):
        findings = build_findings("example.com", "domain", {})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["level"], "INFO")

    def test_dns_records_produce_info_finding(self):
        results = {
            "dns": {
                "available": True,
                "data": {"records": {"A": ["1.2.3.4"], "MX": [], "TXT": [], "NS": [], "AAAA": [], "CNAME": [], "SOA": []}},
            }
        }
        findings = build_findings("example.com", "domain", results)
        levels = [f["level"] for f in findings]
        self.assertIn("INFO", levels)

    def test_missing_spf_flagged_low(self):
        results = {
            "dns": {
                "available": True,
                "data": {"records": {"A": ["1.2.3.4"], "TXT": ["some-other-record"], "MX": [], "NS": [], "AAAA": [], "CNAME": [], "SOA": []}},
            }
        }
        findings = build_findings("example.com", "domain", results)
        self.assertTrue(any("SPF" in f["text"] for f in findings))

    def test_virustotal_malicious_flagged_high(self):
        results = {
            "threat_intelligence": {
                "virustotal": {"source": "VirusTotal", "available": True, "data": {"found": True, "malicious": 3}}
            }
        }
        findings = build_findings("1.2.3.4", "ip", results)
        high = [f for f in findings if f["level"] == "HIGH"]
        self.assertTrue(any("VirusTotal" in f["source"] for f in high))

    def test_disposable_email_flagged_medium(self):
        results = {
            "email": {
                "available": True,
                "data": {"is_disposable_domain": True, "has_mail_server": True},
            }
        }
        findings = build_findings("user@mailinator.com", "email", results)
        self.assertTrue(any(f["level"] == "MEDIUM" and "disposable" in f["text"].lower() for f in findings))

    def test_every_finding_has_a_source(self):
        results = {
            "whois": {"available": False, "error": "Not available"},
        }
        findings = build_findings("example.com", "domain", results)
        for f in findings:
            self.assertIn("source", f)
            self.assertTrue(f["source"])


if __name__ == "__main__":
    unittest.main()

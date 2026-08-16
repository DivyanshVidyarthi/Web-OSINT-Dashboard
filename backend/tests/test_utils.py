"""
Unit tests for the network-independent OSINT utilities: target detection,
validation, and SSRF blocking. These run with zero external dependencies
(stdlib `unittest`, no pytest, no network) so they work in any environment,
including CI runners with no outbound access.

Run with:
    python3 -m unittest backend.tests.test_utils -v
or, from backend/:
    python3 -m unittest tests.test_utils -v
"""
import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.osint.utils import (  # noqa: E402
    detect_target_type, TargetType, ValidationError,
    is_blocked_ip, sanitize_input, strip_www,
)


class TestTargetDetection(unittest.TestCase):
    def test_domain(self):
        t, v = detect_target_type("example.com")
        self.assertEqual(t, TargetType.DOMAIN)
        self.assertEqual(v, "example.com")

    def test_domain_uppercase_normalized(self):
        t, v = detect_target_type("EXAMPLE.com")
        self.assertEqual(t, TargetType.DOMAIN)
        self.assertEqual(v, "example.com")

    def test_ipv4(self):
        t, v = detect_target_type("8.8.8.8")
        self.assertEqual(t, TargetType.IP)
        self.assertEqual(v, "8.8.8.8")

    def test_ipv6(self):
        t, v = detect_target_type("2001:4860:4860::8888")
        self.assertEqual(t, TargetType.IP)

    def test_url(self):
        t, v = detect_target_type("https://example.com/path?x=1")
        self.assertEqual(t, TargetType.URL)

    def test_email(self):
        t, v = detect_target_type("user@example.com")
        self.assertEqual(t, TargetType.EMAIL)
        self.assertEqual(v, "user@example.com")

    def test_email_lowercased(self):
        t, v = detect_target_type("User@Example.com")
        self.assertEqual(v, "user@example.com")

    def test_invalid_input_raises(self):
        with self.assertRaises(ValidationError):
            detect_target_type("not a valid target !!!")

    def test_empty_input_raises(self):
        with self.assertRaises(ValidationError):
            detect_target_type("   ")

    def test_invalid_url_scheme_falls_through_and_fails(self):
        with self.assertRaises(ValidationError):
            detect_target_type("ftp://example.com")

    def test_www_and_apex_domain_normalize_to_same_target(self):
        _, with_www = detect_target_type("www.example.com")
        _, without_www = detect_target_type("example.com")
        self.assertEqual(with_www, without_www)
        self.assertEqual(with_www, "example.com")


class TestStripWww(unittest.TestCase):
    def test_strips_www_prefix(self):
        self.assertEqual(strip_www("www.example.com"), "example.com")

    def test_leaves_apex_domain_unchanged(self):
        self.assertEqual(strip_www("example.com"), "example.com")

    def test_leaves_other_subdomains_unchanged(self):
        self.assertEqual(strip_www("blog.example.com"), "blog.example.com")
        self.assertEqual(strip_www("shop.example.com"), "shop.example.com")

    def test_lowercases(self):
        self.assertEqual(strip_www("WWW.Example.COM"), "example.com")


class TestSanitizeInput(unittest.TestCase):
    def test_strips_whitespace(self):
        self.assertEqual(sanitize_input("  example.com  "), "example.com")

    def test_rejects_empty(self):
        with self.assertRaises(ValidationError):
            sanitize_input("")

    def test_rejects_oversized(self):
        with self.assertRaises(ValidationError):
            sanitize_input("a" * 3000)


class TestSSRFBlocking(unittest.TestCase):
    def test_loopback_blocked(self):
        self.assertTrue(is_blocked_ip("127.0.0.1"))

    def test_private_10_blocked(self):
        self.assertTrue(is_blocked_ip("10.0.0.5"))

    def test_private_192_blocked(self):
        self.assertTrue(is_blocked_ip("192.168.1.1"))

    def test_link_local_metadata_blocked(self):
        # 169.254.169.254 is the common cloud metadata endpoint — must be blocked
        self.assertTrue(is_blocked_ip("169.254.169.254"))

    def test_public_ip_allowed(self):
        self.assertFalse(is_blocked_ip("8.8.8.8"))

    def test_malformed_ip_fails_closed(self):
        self.assertTrue(is_blocked_ip("not-an-ip"))


if __name__ == "__main__":
    unittest.main()

"""Network-free regression tests for the first Artemis v3 delivery."""
import contextlib
import io
import unittest
from unittest.mock import patch

from artemis_v3.cli import main
from artemis_v3.engine import investigate
from artemis_v3.indicators import parse_indicator, is_external_lookup_safe
from artemis_v3.providers import DemoProvider, ProviderError, VirusTotalProvider


class IndicatorTests(unittest.TestCase):
    def test_hashes_normalized(self):
        for count, kind in ((32, "md5"), (40, "sha1"), (64, "sha256")):
            item = parse_indicator("A" * count)
            self.assertEqual(item.kind, kind)
            self.assertEqual(item.value, "a" * count)

    def test_ipv4_ipv6_and_domain(self):
        self.assertEqual(parse_indicator("8.8.8.8").kind, "ipv4")
        self.assertEqual(parse_indicator("2001:4860:4860::8888").kind, "ipv6")
        self.assertEqual(parse_indicator("Example.COM.").value, "example.com")
        self.assertEqual(parse_indicator("例子.测试").kind, "domain")

    def test_invalid_inputs(self):
        for value in ("", "http://example.com", "127.0.0.1/path", "bad_domain.com",
                      "999.999.999.999", "a" * 254, "abc def", "127.0.0.1:80", "user@example.com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_indicator(value)

    def test_external_query_guard(self):
        self.assertFalse(is_external_lookup_safe(parse_indicator("192.168.1.1")))
        self.assertFalse(is_external_lookup_safe(parse_indicator("203.0.113.10")))
        self.assertFalse(is_external_lookup_safe(parse_indicator("demo.example")))
        self.assertTrue(is_external_lookup_safe(parse_indicator("8.8.8.8")))


class EngineTests(unittest.TestCase):
    def test_demo_fixtures_are_labeled(self):
        report = investigate("demo.example", [DemoProvider()])
        self.assertEqual(report.status, "completed")
        self.assertTrue(report.evidence[0].synthetic)
        self.assertIn("DEMO DATA", report.as_markdown())

    def test_unknown_is_not_marked_safe(self):
        report = investigate("unknown.example", [DemoProvider()])
        self.assertEqual(report.status, "no_evidence")
        self.assertIn("does not mean benign", report.as_markdown())

    def test_provider_failure_is_not_a_clean_verdict(self):
        class FailingProvider:
            name = "failure"

            def lookup(self, indicator):
                raise ProviderError("temporarily unavailable")

        report = investigate("demo.example", [DemoProvider(), FailingProvider()])
        self.assertEqual(report.status, "partial")
        self.assertEqual(len(report.errors), 1)
        report2 = investigate("demo.example", [FailingProvider()])
        self.assertEqual(report2.status, "failed")

    def test_separate_invocations_do_not_share_evidence(self):
        first = investigate("demo.example", [DemoProvider()])
        second = investigate("unknown.example", [DemoProvider()])
        self.assertEqual(len(first.evidence), 1)
        self.assertEqual(len(second.evidence), 0)


class ProviderTests(unittest.TestCase):
    def test_live_provider_requires_key(self):
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(ValueError):
                VirusTotalProvider()

    def test_live_provider_blocks_private_ip_without_network(self):
        provider = VirusTotalProvider(api_key="fake-test-key")
        with patch("artemis_v3.providers.urlopen") as mock_network:
            with self.assertRaises(ProviderError):
                provider.lookup(parse_indicator("10.0.0.10"))
            mock_network.assert_not_called()

    def test_cli_offline_demo(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            status = main(["demo.example", "--format", "json"])
        self.assertEqual(status, 0)
        self.assertIn('"synthetic": true', buf.getvalue())


if __name__ == "__main__":
    unittest.main()

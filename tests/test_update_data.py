import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import update_data as U  # noqa: E402

XML = b"""<!DOCTYPE article SYSTEM "../../dtd/article.dtd">
<article name="nginx security advisories"><section><security>
<item name="Excessive CPU usage in TLS 1.3 with ssl_early_data" cve="2026-132779"
      good="1.31.10+, 1.30.8+" vulnerable="1.21.4-1.31.9"></item>
<item name="Memory corruption in HTTP/2 flow control" cve="2026-123007"
      good="1.31.9+, 1.30.7+" vulnerable="1.9.5-1.31.8"></item>
<item name="Vulnerabilities with Windows 8.3 filename pseudonyms" core="CORE-2010-0121"
      good="0.8.33+, 0.7.65+" vulnerable="nginx/Windows 0.7.52-0.8.32"><patch name="p.txt" /></item>
<item name="An error log data are not sanitized" cve="2009-4487" good="none" vulnerable="all"></item>
</security></section></article>"""

OLD = {"advisories": [{"id": "CVE-2026-123007", "title": "Memory corruption in HTTP/2 flow control",
                       "nginx_severity": "major", "severity": "critical", "vulnerable": [["1.9.5", "1.31.8"]],
                       "fixed": ["1.31.9", "1.30.7"], "requires": ["http2"],
                       "requires_source": "Wiz disclosure, Nov 2026", "cvss": 9.2}]}


def cve_record(score, sev):
    return json.dumps({"containers": {"cna": {"metrics": [{"cvssV4_0": {"baseScore": score, "baseSeverity": sev}}]}}}).encode()


class Parsing(unittest.TestCase):
    def test_items(self):
        items = U.parse_advisories(XML)
        self.assertEqual([i["id"] for i in items], ["CVE-2026-132779", "CVE-2026-123007", "CORE-2010-0121", "CVE-2009-4487"])

    def test_entities_refused(self):
        with self.assertRaises(U.SourceError):
            U.parse_advisories(b'<!DOCTYPE a [<!ENTITY x "xx">]><a>&x;</a>')

    def test_bad_versions_stop_the_run(self):
        with self.assertRaises(U.SourceError):
            U.ranges("1.2-latest")
        with self.assertRaises(U.SourceError):
            U.fixed("1.31.10+, soon")


class Building(unittest.TestCase):
    def test_new_existing_and_skipped(self):
        adv, notes = U.build(U.parse_advisories(XML), OLD, fetcher=lambda url: cve_record(6.9, "MEDIUM"))
        by = {a["id"]: a for a in adv}
        self.assertNotIn("CVE-2009-4487", by)                       # informational entry skipped
        self.assertEqual(by["CVE-2026-123007"], OLD["advisories"][0])  # reviewed entry untouched
        new = by["CVE-2026-132779"]
        self.assertEqual((new["severity"], new["cvss"], new["requires"]), ("medium", 6.9, ["early_data"]))
        self.assertEqual(new["severity_source"], "CVE record (F5)")
        self.assertEqual(by["CORE-2010-0121"]["requires"], ["windows"])
        self.assertTrue(any(n.startswith("NEW CVE-2026-132779") for n in notes))

    def test_critical_from_cvss_and_unrated(self):
        adv, _ = U.build(U.parse_advisories(XML), OLD, fetcher=lambda url: cve_record(9.3, "CRITICAL"))
        self.assertEqual({a["id"]: a for a in adv}["CVE-2026-132779"]["severity"], "critical")

        def down(url):
            raise OSError("offline")
        adv, _ = U.build(U.parse_advisories(XML), OLD, fetcher=down)
        new = {a["id"]: a for a in adv}["CVE-2026-132779"]
        self.assertEqual(new["severity"], "medium")
        self.assertIn("not rated yet", new["severity_source"])

    def test_running_twice_changes_nothing(self):
        first, _ = U.build(U.parse_advisories(XML), OLD, fetcher=lambda url: cve_record(6.9, "MEDIUM"))
        second, notes = U.build(U.parse_advisories(XML), {"advisories": first},
                                fetcher=lambda url: self.fail("existing advisories mustn't be refetched"))
        self.assertEqual(first, second)
        self.assertEqual(notes, [])


class SafetyChecks(unittest.TestCase):
    def setUp(self):
        self.adv = [{"id": f"CVE-2026-{i}"} for i in range(U.MIN_ADVISORIES)]
        self.latest = {"1.30": "1.30.7", "1.31": "1.31.9"}

    def test_passes_when_sane(self):
        U.check({"advisories": self.adv[:5]}, self.adv, self.latest, {"1.30": "1.30.8", "1.31": "1.31.10"})

    def test_too_few(self):
        with self.assertRaises(U.SourceError):
            U.check({"advisories": []}, self.adv[:3], self.latest, self.latest)

    def test_advisory_disappeared(self):
        with self.assertRaises(U.SourceError):
            U.check({"advisories": [{"id": "CVE-2009-1"}]}, self.adv, self.latest, self.latest)

    def test_release_went_backwards_or_vanished(self):
        with self.assertRaises(U.SourceError):
            U.check({"advisories": []}, self.adv, self.latest, {"1.30": "1.30.6", "1.31": "1.31.9"})
        with self.assertRaises(U.SourceError):
            U.check({"advisories": []}, self.adv, self.latest, {"1.31": "1.31.9"})


class Tags(unittest.TestCase):
    def test_latest_per_branch(self):
        lines = "\n".join(f"abc\trefs/tags/release-1.{b}.{p}" for b in range(0, 32) for p in range(0, 4))
        lines += "\nabc\trefs/tags/release-1.31.10\nabc\trefs/tags/release-1.31.10^{}"
        fake = lambda *a, **k: subprocess.CompletedProcess(a, 0, lines, "")  # noqa: E731
        latest = U.latest_tags(runner=fake)
        self.assertEqual(latest["1.31"], "1.31.10")   # numeric, not text, comparison
        self.assertEqual(latest["1.5"], "1.5.3")

    def test_failure_stops_the_run(self):
        fake = lambda *a, **k: subprocess.CompletedProcess(a, 128, "", "fatal: unable to access")  # noqa: E731
        with self.assertRaises(U.SourceError):
            U.latest_tags(runner=fake)


if __name__ == "__main__":
    unittest.main()

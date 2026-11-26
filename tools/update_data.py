"""Keep nginxwatch's data current.

    python tools/update_data.py            # update nginxwatch/data/*.json in place
    python tools/update_data.py --check    # report what would change, write nothing

Sources (all official, all on GitHub):
  * advisories: nginx.org's own source, github.com/nginx/nginx.org, xml/en/security_advisories.xml
  * severity of new advisories: the CVE record F5 publishes, github.com/CVEProject/cvelistV5
  * newest release per branch: release tags of github.com/nginx/nginx

Advisories already in the data keep their reviewed details (the configuration a bug
needs, impact notes, severity); only their version ranges are refreshed. New advisories
get their conditions from the title rules below, or none, meaning "applies to any
setup", so nginxwatch errs towards warning.

The run stops with an error, and changes nothing, if the sources look wrong: too few
advisories, an advisory that disappeared, versions it can't read, or a branch whose
newest release went backwards.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "nginxwatch", "data")
ADVISORIES_URL = "https://raw.githubusercontent.com/nginx/nginx.org/main/xml/en/security_advisories.xml"
CVE_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}xxx/CVE-{id}.json"
TAGS_REPO = "https://github.com/nginx/nginx"
MIN_ADVISORIES = 60

# Conditions from the November 2026 disclosure (Wiz), kept exact
EXACT = {
    "CVE-2026-123007": ["http2"],
    "CVE-2026-123633": ["http2", "proxy"],
    "CVE-2026-121810": ["http3", "proxy"],
    "CVE-2026-123634": ["resolver"],
    "CVE-2026-113425": ["mail_auth_http"],
    "CVE-2026-118899": ["tls13"],
    "CVE-2026-120993": ["proxy_protocol"],
    "CVE-2026-125283": ["alias_try_files"],
    "CVE-2026-123640": ["ssl_preread"],
    "CVE-2026-120967": ["stream_client_cert"],
}
# Everything else: read from the advisory title, first match wins
BY_TITLE = [
    (r"ssl_early_data|early data", ["early_data"]),
    (r"alias with rewrite", ["alias_rewrite"]),
    (r"alias with try_files", ["alias_try_files"]),
    (r"PROXY protocol", ["proxy_protocol"]),
    (r"map and regex", ["map_regex"]),
    (r"OCSP result bypass in stream", ["stream_ocsp"]),
    (r"resolver use-after-free in OCSP", ["ocsp", "resolver"]),
    (r"proxy_v2_module|grpc_module", ["grpc"]),
    (r"HTTP/2 request injection in the ngx_http_proxy_module", ["http2_upstream"]),
    (r"SSL upstream injection", ["proxy_ssl"]),
    (r"HTTP/3|ngx_http_v3_module|QUIC", ["http3"]),
    (r"HTTP/2", ["http2"]),
    (r"SPDY", ["spdy"]),
    (r"ssl_preread", ["ssl_preread"]),
    (r"resolver|CNAME", ["resolver"]),
    (r"mp4", ["mp4"]), (r"dav_module", ["dav"]), (r"slice_module", ["slice"]), (r"ssi_module", ["ssi"]),
    (r"charset_module", ["charset"]), (r"scgi_module|uwsgi_module", ["scgi_uwsgi"]),
    (r"rewrite_module", ["rewrite"]), (r"asynchronous file I/O|AIO", ["aio"]),
    (r"session tickets", ["ssl"]), (r"SSL session reuse", ["ssl"]), (r"TLS 1\.3", ["tls13"]),
    (r"CRAM-MD5|APOP", ["mail_cram_apop"]), (r"auth_http and XCLIENT", ["mail"]),
    (r"mail|SMTP|STARTTLS|IMAP|POP3", ["mail"]),
    (r"Windows", ["windows"]),
    (r"renegotiation vulnerability in SSL", ["ssl"]),
]
VERSION = re.compile(r"^\d+\.\d+\.\d+$")


class SourceError(Exception):
    """The sources look wrong; refuse to publish."""


def fetch(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "nginxwatch-data-updater"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(5 * 1024 * 1024)


def parse_advisories(xml_bytes: bytes) -> list:
    if b"<!ENTITY" in xml_bytes:
        raise SourceError("advisory XML declares entities; refusing to parse it")
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        raise SourceError(f"advisory XML doesn't parse: {e}") from e
    out = []
    for item in root.iter("item"):
        if item.get("good") is None or item.get("vulnerable") is None:
            continue
        aid = f"CVE-{item.get('cve')}" if item.get("cve") else (item.get("core") or "").strip()
        out.append({"id": aid, "title": (item.get("name") or "").strip(),
                    "good": item.get("good").strip(), "vulnerable": item.get("vulnerable").strip()})
    return out


def ranges(vulnerable: str):
    windows = vulnerable.startswith("nginx/Windows")
    out = []
    for part in vulnerable.replace("nginx/Windows", "").split(","):
        part = part.strip()
        lo, _, hi = part.partition("-")
        hi = hi or lo
        if not (VERSION.match(lo) and VERSION.match(hi)):
            raise SourceError(f"can't read vulnerable range {part!r}")
        out.append([lo, hi])
    return out, windows


def fixed(good: str):
    out = [g.strip().rstrip("+") for g in good.split(",")]
    for g in out:
        if not VERSION.match(g):
            raise SourceError(f"can't read fixed version {g!r}")
    return out


def conditions(aid: str, title: str, windows: bool, previous: dict):
    if windows:
        return ["windows"], "advisory title"
    if aid in EXACT:
        return EXACT[aid], "Wiz disclosure, Nov 2026"
    if previous:
        return previous["requires"], previous["requires_source"]
    return next((r for pat, r in BY_TITLE if re.search(pat, title, re.I)), []), "advisory title"


def cve_severity(aid: str, fetcher=fetch):
    """(severity, cvss) from F5's CVE record; CVSS 4.0 preferred, then 3.1."""
    m = re.match(r"CVE-(\d{4})-(\d+)$", aid)
    if not m:
        return None, None
    year, num = m.groups()
    try:
        rec = json.loads(fetcher(CVE_URL.format(year=year, bucket=int(num) // 1000, id=f"{year}-{num}")))
    except Exception:  # noqa: BLE001  any failure just means "no rating yet"
        return None, None
    best = {}
    for metric in rec.get("containers", {}).get("cna", {}).get("metrics", []):
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
            if key in metric and key not in best:
                best[key] = metric[key]
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
        if key in best:
            score = best[key].get("baseScore")
            sev = (best[key].get("baseSeverity") or "").lower()
            if sev in ("critical", "high", "medium", "low"):
                return sev, score
    return None, None


def build(items: list, old: dict, fetcher=fetch):
    prev = {a["id"]: a for a in old.get("advisories", [])}
    out, notes = [], []
    for it in items:
        if it["good"] == "none" or it["vulnerable"] == "all":
            continue  # informational entries with no version answer
        vul, windows = ranges(it["vulnerable"])
        p = prev.get(it["id"])
        req, src = conditions(it["id"], it["title"], windows, p)
        e = {"id": it["id"], "title": it["title"], "vulnerable": vul, "fixed": fixed(it["good"]),
             "requires": req, "requires_source": src}
        if p:
            for k in ("nginx_severity", "severity", "cvss", "impact", "severity_source"):
                if k in p:
                    e[k] = p[k]
            if p["vulnerable"] != vul or p["fixed"] != e["fixed"]:
                notes.append(f"{it['id']}: versions changed ({', '.join(e['fixed'])} fixed)")
        else:
            sev, score = cve_severity(it["id"], fetcher)
            e["nginx_severity"] = ""
            e["severity"] = sev or "medium"
            if score is not None:
                e["cvss"] = score
                if score >= 9.0:
                    e["severity"] = "critical"
            e["severity_source"] = "CVE record (F5)" if sev else "not rated yet; assumed medium"
            notes.append(f"NEW {it['id']}: {it['title']} ({e['severity']}"
                         + (f", CVSS {score}" if score is not None else "") + f"; fixed in {', '.join(e['fixed'])})")
        out.append({k: e[k] for k in ("id", "title", "nginx_severity", "severity", "vulnerable", "fixed",
                                       "requires", "requires_source") if k in e}
                   | {k: e[k] for k in ("cvss", "impact", "severity_source") if k in e})
    return out, notes


def latest_tags(runner=subprocess.run) -> dict:
    r = runner(["git", "ls-remote", "--tags", TAGS_REPO], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise SourceError(f"couldn't list nginx release tags: {r.stderr.strip()[:200]}")
    latest = {}
    for v in re.findall(r"refs/tags/release-(\d+\.\d+\.\d+)$", r.stdout, re.M):
        a, b, c = map(int, v.split("."))
        key = f"{a}.{b}"
        if key not in latest or (a, b, c) > tuple(map(int, latest[key].split("."))):
            latest[key] = v
    if len(latest) < 30:
        raise SourceError(f"only {len(latest)} release branches found in the tags")
    return dict(sorted(latest.items()))


def check(old: dict, new_adv: list, old_latest: dict, new_latest: dict):
    if len(new_adv) < MIN_ADVISORIES:
        raise SourceError(f"only {len(new_adv)} advisories parsed (expected at least {MIN_ADVISORIES})")
    gone = {a["id"] for a in old.get("advisories", [])} - {a["id"] for a in new_adv}
    if gone:
        raise SourceError(f"advisories disappeared from the source: {', '.join(sorted(gone))}")
    for branch, v in old_latest.items():
        nv = new_latest.get(branch)
        if nv is None or tuple(map(int, nv.split("."))) < tuple(map(int, v.split("."))):
            raise SourceError(f"branch {branch}: newest release went from {v} to {nv}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="report changes without writing")
    ap.add_argument("--xml", help="read the advisory XML from this file instead of GitHub")
    args = ap.parse_args(argv)
    adv_path, latest_path = os.path.join(DATA, "advisories.json"), os.path.join(DATA, "latest_in_branch.json")
    with open(adv_path, encoding="utf-8") as fh:
        old = json.load(fh)
    with open(latest_path, encoding="utf-8") as fh:
        old_latest = json.load(fh)
    try:
        xml_bytes = open(args.xml, "rb").read() if args.xml else fetch(ADVISORIES_URL)
        new_adv, notes = build(parse_advisories(xml_bytes), old)
        new_latest = latest_tags()
        check(old, new_adv, old_latest, new_latest)
    except (SourceError, OSError) as e:
        print(f"update_data: stopped, nothing changed: {e}", file=sys.stderr)
        return 2
    for branch, v in new_latest.items():
        if old_latest.get(branch) != v:
            notes.append(f"release {v}" + (f" (was {old_latest[branch]})" if branch in old_latest else " (new branch)"))
    adv_changed = new_adv != old.get("advisories")
    latest_changed = new_latest != old_latest
    if not (adv_changed or latest_changed):
        print("update_data: already up to date")
        return 0
    print("update_data: " + "; ".join(notes))
    if args.check:
        return 0
    if adv_changed:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with open(adv_path, "w", encoding="utf-8") as fh:
            json.dump({"source": "https://nginx.org/en/security_advisories.html", "retrieved": today,
                       "advisories": new_adv}, fh, indent=1)
    if latest_changed:
        with open(latest_path, "w", encoding="utf-8") as fh:
            json.dump(new_latest, fh, indent=0, sort_keys=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("## nginxwatch data update\n\n" + "\n".join(f"- {n}" for n in notes) + "\n")
    with open(os.path.join(HERE, "..", ".data-changes.txt"), "w", encoding="utf-8") as fh:
        fh.write("; ".join(notes)[:900] + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

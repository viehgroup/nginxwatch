"""Turn the nginx.org advisory list into nginxwatch's data file.

    python tools/build_data.py   (reads tools/advisories_raw.txt, writes nginxwatch/data/advisories.json)

advisories_raw.txt is copied from https://nginx.org/en/security_advisories.html,
one advisory per line: title|severity|ids|not vulnerable|vulnerable.
"""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))

# What each advisory needs in the configuration before it matters.
# The November 2026 entries follow the conditions Wiz published with the disclosure;
# the rest are read from each advisory's title. None means "applies to any setup".
WIZ_CVSS = {"CVE-2026-123007": 9.2, "CVE-2026-123633": 9.2, "CVE-2026-121810": 9.2, "CVE-2026-123634": 9.2,
            "CVE-2026-113425": 9.2, "CVE-2026-118899": 8.7, "CVE-2026-120993": 6.9, "CVE-2026-125283": 6.9,
            "CVE-2026-123640": 6.9, "CVE-2026-120967": 6.3}
WIZ_IMPACT = {
    "CVE-2026-123007": "remote code execution without authentication, in default configurations with HTTP/2 enabled",
    "CVE-2026-123633": "remote code execution without authentication when HTTP/2 is used with proxying",
    "CVE-2026-121810": "remote code execution when HTTP/3 is used with proxying",
    "CVE-2026-123634": "remote code execution when an attacker controls an upstream host name",
    "CVE-2026-113425": "remote code execution when used as a mail proxy with auth_http",
    "CVE-2026-118899": "denial of service when TLS 1.3 is supported",
}
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
BY_TITLE = [  # first match wins
    (r"alias with rewrite", ["alias_rewrite"]),
    (r"PROXY protocol", ["proxy_protocol"]),
    (r"map and regex", ["map_regex"]),
    (r"OCSP result bypass in stream", ["stream_ocsp"]),
    (r"resolver use-after-free in OCSP", ["ocsp", "resolver"]),
    (r"proxy_v2_module|grpc_module", ["grpc"]),
    (r"HTTP/2 request injection in the ngx_http_proxy_module", ["http2_upstream"]),
    (r"SSL upstream injection", ["proxy_ssl"]),
    (r"HTTP/3|ngx_http_v3_module", ["http3"]),
    (r"HTTP/2", ["http2"]),
    (r"SPDY", ["spdy"]),
    (r"resolver|CNAME", ["resolver"]),
    (r"mp4", ["mp4"]), (r"dav_module", ["dav"]), (r"slice_module", ["slice"]), (r"ssi_module", ["ssi"]),
    (r"charset_module", ["charset"]), (r"scgi_module|uwsgi_module", ["scgi_uwsgi"]),
    (r"rewrite_module", ["rewrite"]), (r"asynchronous file I/O|AIO", ["aio"]),
    (r"session tickets", ["ssl"]), (r"SSL session reuse", ["ssl"]),
    (r"CRAM-MD5|APOP", ["mail_cram_apop"]), (r"auth_http and XCLIENT", ["mail"]),
    (r"mail|SMTP|STARTTLS", ["mail"]),
    (r"Windows", ["windows"]),
    (r"renegotiation vulnerability in SSL", ["ssl"]),
]
SEVERITY = {"major": "high", "medium": "medium", "minor": "low", "low": "low"}

out = []
for line in open(os.path.join(HERE, "advisories_raw.txt"), encoding="utf-8"):
    title, sev, ids, fixed, vuln = line.rstrip("\n").split("|")
    if sev == "none":
        continue  # informational (log sanitising), applies to every version
    cves = re.findall(r"CVE-\d{4}-\d+|CORE-\d{4}-\d+", ids)
    cve = cves[0] if cves else ids.split()[-1]
    windows_only = vuln.startswith("nginx/Windows")
    ranges = [r.strip() for r in vuln.replace("nginx/Windows", "").split(",")]
    req = EXACT.get(cve)
    source = "Wiz disclosure, Nov 2026" if req is not None else "advisory title"
    if req is None:
        req = next((r for pat, r in BY_TITLE if re.search(pat, title, re.I)), [])
    if windows_only:
        req = ["windows"]
    entry = {"id": cve, "title": title, "nginx_severity": sev, "severity": SEVERITY[sev],
             "vulnerable": [tuple(x.split("-")) if "-" in x else (x, x) for x in ranges],
             "fixed": [f.strip().rstrip("+") for f in fixed.split(",")], "requires": req, "requires_source": source}
    if cve in WIZ_CVSS:
        entry["cvss"] = WIZ_CVSS[cve]
        if cve in WIZ_IMPACT:
            entry["impact"] = WIZ_IMPACT[cve]
        if WIZ_CVSS[cve] >= 9.0:
            entry["severity"] = "critical"
    out.append(entry)

json.dump({"source": "https://nginx.org/en/security_advisories.html", "retrieved": "2026-11-20",
           "advisories": out}, open(os.path.join(HERE, "..", "nginxwatch", "data", "advisories.json"), "w"), indent=1)
print(len(out), "advisories written;", sum(1 for e in out if not e["requires"]), "apply to any setup")

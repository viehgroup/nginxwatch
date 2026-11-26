"""Put version, configuration and distribution patches together into a verdict."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .advisories import Advisory, Database, Version, upgrade_target, vstr
from .config import Features

# What each condition means, in words people use
FEATURE_WORDS = {
    "http2": "HTTP/2", "http3": "HTTP/3 (QUIC)", "proxy": "proxying to a backend", "resolver": "the resolver directive",
    "mail_auth_http": "the mail proxy with auth_http", "mail": "the mail proxy", "tls13": "TLS 1.3",
    "proxy_protocol": "the PROXY protocol on a listener", "alias_try_files": "alias together with try_files",
    "alias_rewrite": "alias together with rewrite", "ssl_preread": "ssl_preread in stream",
    "stream_client_cert": "client certificates in stream", "stream_ocsp": "OCSP in stream", "ocsp": "OCSP",
    "grpc": "gRPC or HTTP/2 to backends", "http2_upstream": "HTTP/2 to backends", "proxy_ssl": "HTTPS to backends",
    "spdy": "SPDY", "mp4": "the mp4 module", "dav": "WebDAV", "slice": "the slice module", "ssi": "SSI",
    "charset": "charset conversion", "scgi_uwsgi": "SCGI or uWSGI", "rewrite": "rewrite rules", "aio": "AIO",
    "ssl": "TLS", "mail_cram_apop": "CRAM-MD5 or APOP mail auth", "map_regex": "map with regular expressions",
    "windows": "nginx on Windows", "early_data": "TLS 1.3 early data (ssl_early_data)",
}
MITIGATIONS = {
    "CVE-2026-123007": "If you can't upgrade today, turning HTTP/2 off (remove `http2` from `listen`, or `http2 off;`) "
                       "removes the condition this needs.",
    "CVE-2026-123633": "If you can't upgrade today, turning HTTP/2 off removes the condition this needs.",
    "CVE-2026-121810": "If you can't upgrade today, turning HTTP/3 off (remove `quic` listeners) removes the condition.",
}

EXPOSED, UNKNOWN, NOT_USED, PATCHED = "exposed", "unknown", "not used", "patched by distribution"
ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}


@dataclass
class Hit:
    advisory: Advisory
    status: str
    why: str


@dataclass
class Verdict:
    target: str                       # what was checked
    version: Optional[Version]
    hits: List[Hit] = field(default_factory=list)
    upgrade_to: Optional[Version] = None
    notes: List[str] = field(default_factory=list)

    @property
    def exposed(self) -> List[Hit]:
        return [h for h in self.hits if h.status in (EXPOSED, UNKNOWN)]

    @property
    def worst(self) -> Optional[str]:
        sevs = [h.advisory.severity for h in self.exposed]
        return max(sevs, key=lambda s: ORDER[s]) if sevs else None


def judge(db: Database, target: str, version: Optional[Version], features: Features,
          backported: Set[str] = frozenset(), missing: Set[str] = frozenset(), windows: bool = False,
          package: str = "") -> Verdict:
    v = Verdict(target, version)
    if version is None:
        v.notes.append("couldn't tell which nginx version this is")
        return v
    affecting = db.affecting(version)
    still_open: List[Advisory] = []
    for a in affecting:
        if a.id in backported:
            v.hits.append(Hit(a, PATCHED, f"the fix is in {package or 'the distribution package'}"))
            continue
        reqs = list(a.requires)
        if "windows" in reqs:
            if not windows:
                continue  # Windows-only bugs don't apply elsewhere
            reqs.remove("windows")
        blocked = [r for r in reqs if r in missing]
        if blocked:
            v.hits.append(Hit(a, NOT_USED, f"nginx was built without {FEATURE_WORDS.get(blocked[0], blocked[0])}"))
            still_open.append(a)
            continue
        states: Dict[str, Optional[bool]] = {r: features.has(r) for r in reqs}
        if any(s is False for s in states.values()):
            off = next(r for r, s in states.items() if s is False)
            v.hits.append(Hit(a, NOT_USED, f"your configuration doesn't use {FEATURE_WORDS.get(off, off)}"))
        elif any(s is None for s in states.values()):
            v.hits.append(Hit(a, UNKNOWN, "needs " + " and ".join(FEATURE_WORDS.get(r, r) for r in reqs)
                              + "; the configuration wasn't available to check"))
        else:
            ev = [features.found[r] for r in reqs]
            why = "; ".join(f"{FEATURE_WORDS.get(r, r)} is on ({e.where})" for r, e in zip(reqs, ev)) if reqs \
                else "affects every configuration"
            v.hits.append(Hit(a, EXPOSED, why))
        still_open.append(a)
    v.hits.sort(key=lambda h: (h.status != EXPOSED, h.status != UNKNOWN, -ORDER[h.advisory.severity]))
    open_hits = [h.advisory for h in v.hits if h.status != PATCHED]
    v.upgrade_to = upgrade_target(version, open_hits) if open_hits else None
    if backported:
        v.notes.append(f"{len([h for h in v.hits if h.status == PATCHED])} fix(es) were backported by your distribution "
                       f"({package}); the version number alone would overstate the risk")
    return v


def summary_line(v: Verdict) -> str:
    if v.version is None:
        return "version unknown"
    ex = [h for h in v.hits if h.status == EXPOSED]
    un = [h for h in v.hits if h.status == UNKNOWN]
    if not v.hits:
        return "not affected by any known nginx advisory"
    if not ex and not un:
        pat = sum(1 for h in v.hits if h.status == PATCHED)
        nu = len(v.hits) - pat
        why = []
        if pat:
            why.append(f"{pat} fixed by your distribution's package")
        if nu:
            why.append(f"{nu} need features this setup doesn't use")
        tail = f"; upgrading to {vstr(v.upgrade_to)} still closes the rest" if (nu and v.upgrade_to) else ""
        return f"no exploitable advisories: {len(v.hits)} affect this version, but " + " and ".join(why) + tail
    parts = []
    if ex:
        crit = sum(1 for h in ex if h.advisory.severity == "critical")
        parts.append(f"{len(ex)} exploitable with this configuration" + (f" ({crit} critical)" if crit else ""))
    if un:
        parts.append(f"{len(un)} possibly exploitable (configuration unknown)")
    nu = [h for h in v.hits if h.status == NOT_USED]
    if nu:
        parts.append(f"{len(nu)} affect this version but not this configuration")
    if v.upgrade_to:
        parts.append(f"upgrade to {vstr(v.upgrade_to)}")
    return "; ".join(parts)

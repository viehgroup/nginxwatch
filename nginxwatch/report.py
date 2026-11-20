import json
import shutil
import textwrap
from typing import List

from . import __version__
from .advisories import vstr
from .analyze import EXPOSED, MITIGATIONS, NOT_USED, ORDER, PATCHED, UNKNOWN, Verdict, summary_line

_C = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "dim": "2", "bold": "1", "ok": "32"}
_ICON = {"critical": "🔴", "high": "🔴", "medium": "🟠", "low": "🔵"}
ADVISORY_URL = "https://nginx.org/en/security_advisories.html"


def _p(on: bool):
    return lambda s, k: f"\033[{_C[k]}m{s}\033[0m" if on else s


def _sev_label(h) -> str:
    a = h.advisory
    return f"{a.severity}" + (f", CVSS {a.cvss}" if a.cvss else "")


def text(verdicts: List[Verdict], color: bool, show_all: bool = False, extra: List[str] = ()) -> str:
    p = _p(color)
    width = min(100, shutil.get_terminal_size((80, 24)).columns)
    out = []
    for v in verdicts:
        ver = vstr(v.version) if v.version else "unknown version"
        exposed = [h for h in v.hits if h.status == EXPOSED]
        unknown = [h for h in v.hits if h.status == UNKNOWN]
        if exposed:
            mark = p("⚠️  VULNERABLE", v.worst if v.worst else "high")
        elif unknown:
            mark = p("⚠️  POSSIBLY VULNERABLE", "medium")
        elif v.version is None:
            mark = p("?  UNKNOWN", "dim")
        else:
            mark = p("✅ OK", "ok")
        out.append(f"{mark}  {p(v.target, 'bold')}  nginx {ver}")
        for line in textwrap.wrap(summary_line(v), width - 4):
            out.append("    " + line)
        for h in exposed + unknown:
            a = h.advisory
            out.append(f"  {p(f'{a.severity:<8}', a.severity)} {a.id}" + (f"  CVSS {a.cvss}" if a.cvss else ""))
            for line in textwrap.wrap(a.title, width - 6):
                out.append("      " + p(line, "bold"))
            if a.impact:
                for line in textwrap.wrap(a.impact[0].upper() + a.impact[1:], width - 6):
                    out.append("      " + line)
            for line in textwrap.wrap(("Why: " if h.status == EXPOSED else "") + h.why, width - 6):
                out.append("      " + p(line, "dim"))
            if a.id in MITIGATIONS:
                for line in textwrap.wrap("Until you upgrade: " + MITIGATIONS[a.id], width - 6):
                    out.append("      " + line)
        rest = [h for h in v.hits if h.status in (NOT_USED, PATCHED)]
        if rest and show_all:
            for h in rest:
                out.append(f"  {p(f'{h.advisory.severity:<8}', 'dim')} {h.advisory.id}")
                out.append("      " + h.advisory.title)
                out.append("      " + p(f"{h.status}: {h.why}", "dim"))
        elif rest:
            out.append("    " + p(f"({len(rest)} more that don't apply here; --all lists them)", "dim"))
        if v.upgrade_to and (exposed or unknown):
            out.append("    " + p(f"Fix: upgrade to nginx {vstr(v.upgrade_to)} or newer.", "bold"))
        for n in v.notes:
            for line in textwrap.wrap("Note: " + n, width - 4):
                out.append("    " + p(line, "dim"))
        out.append("")
    for e in extra:
        out.extend(textwrap.wrap(e, width, break_long_words=False))
    if verdicts:
        bad = sum(1 for v in verdicts if any(h.status == EXPOSED for h in v.hits))
        maybe = sum(1 for v in verdicts if not any(h.status == EXPOSED for h in v.hits)
                    and any(h.status == UNKNOWN for h in v.hits))
        out.extend(textwrap.wrap(f"{len(verdicts)} checked: {bad} vulnerable, {maybe} possibly vulnerable. "
                                 f"Advisories from {ADVISORY_URL}", width, break_long_words=False))
    return "\n".join(out).rstrip()


def markdown(verdicts: List[Verdict], extra: List[str] = ()) -> str:
    lines = ["## nginxwatch"]
    flagged = [v for v in verdicts if any(h.status in (EXPOSED, UNKNOWN) for h in v.hits)]
    if not flagged:
        lines.append("✅ No exploitable nginx vulnerabilities found.")
    for v in flagged:
        ver = vstr(v.version) if v.version else "unknown"
        lines.append(f"\n### `{v.target}` (nginx {ver})")
        lines.append(summary_line(v))
        lines.append("\n| | Advisory | Why it applies |\n|---|---|---|")
        for h in v.hits:
            if h.status in (EXPOSED, UNKNOWN):
                why = h.why.replace("|", "\\|")
                lines.append(f"| {_ICON[h.advisory.severity]} | {h.advisory.id} {h.advisory.title} ({_sev_label(h)}) | {why} |")
        if v.upgrade_to:
            lines.append(f"\n**Fix:** upgrade to nginx {vstr(v.upgrade_to)} or newer.")
    for e in extra:
        lines.append(f"\n{e}")
    lines.append(f"\n<sub>nginxwatch {__version__} · advisories from nginx.org</sub>")
    return "\n".join(lines) + "\n"


def as_json(verdicts: List[Verdict]) -> str:
    return json.dumps({"version": __version__, "results": [{
        "target": v.target, "nginx": vstr(v.version) if v.version else None,
        "summary": summary_line(v), "upgrade_to": vstr(v.upgrade_to) if v.upgrade_to else None, "notes": v.notes,
        "advisories": [{"id": h.advisory.id, "title": h.advisory.title, "severity": h.advisory.severity,
                        "nginx_severity": h.advisory.nginx_severity, "cvss": h.advisory.cvss,
                        "status": h.status, "why": h.why} for h in v.hits]} for v in verdicts]}, indent=2)


def sarif(verdicts: List[Verdict]) -> str:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    results, rules = [], {}
    for v in verdicts:
        for h in v.hits:
            if h.status not in (EXPOSED, UNKNOWN):
                continue
            a = h.advisory
            rules[a.id] = {"id": a.id, "name": a.id.replace("-", ""), "shortDescription": {"text": a.title},
                           "helpUri": ADVISORY_URL}
            file = v.target.split(":")[0] if ":" in v.target and not v.target.startswith("http") else v.target
            results.append({"ruleId": a.id, "level": level[a.severity],
                            "message": {"text": f"nginx {vstr(v.version) if v.version else '?'}: {a.title}. {h.why}"
                                        + (f" Upgrade to {vstr(v.upgrade_to)}." if v.upgrade_to else "")},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": file}}}]})
    return json.dumps({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
                       "runs": [{"tool": {"driver": {"name": "nginxwatch", "version": __version__,
                                                     "informationUri": "https://github.com/viehgroup/nginxwatch",
                                                     "rules": list(rules.values())}},
                                 "results": results}]}, indent=2)


def github(verdicts: List[Verdict]) -> str:
    kind = {"critical": "error", "high": "error", "medium": "warning", "low": "notice"}

    def esc(s):
        return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")

    lines = []
    for v in verdicts:
        for h in v.hits:
            if h.status not in (EXPOSED, UNKNOWN):
                continue
            file, _, line = v.target.partition(":")
            loc = f"file={esc(file)},line={line}," if line.isdigit() else ""
            title = esc(f"{h.advisory.id} ({h.advisory.severity})").replace(":", "%3A").replace(",", "%2C")
            msg = f"nginx {vstr(v.version) if v.version else '?'}: {h.advisory.title}. {h.why}"
            if v.upgrade_to:
                msg += f" Upgrade to {vstr(v.upgrade_to)}."
            lines.append(f"::{kind[h.advisory.severity]} {loc}title={title}::{esc(msg)}")
    return "\n".join(lines)


def worst(verdicts: List[Verdict]) -> int:
    sevs = [ORDER[h.advisory.severity] for v in verdicts for h in v.hits if h.status in (EXPOSED, UNKNOWN)]
    return max(sevs) if sevs else -1

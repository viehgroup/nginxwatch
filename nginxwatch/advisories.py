"""nginx.org advisories and how a version is matched against them.

nginx.org publishes each advisory as a vulnerable range plus a list of fixed
releases, one per maintained branch, e.g.

    Not vulnerable: 1.31.9+, 1.30.7+
    Vulnerable:     1.9.5-1.31.8

1.30.7 sits inside the vulnerable range numerically, but it's the stable-branch
fix. So a version is fixed if it is at least the fix for its own branch
(1.30.x >= 1.30.7) or at least the newest fix overall (>= 1.31.9).
"""

import json
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "advisories.json")

Version = Tuple[int, ...]


def parse_version(s: str) -> Optional[Version]:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", s or "")
    return tuple(int(x) for x in m.groups()) if m else None


def vstr(v: Version) -> str:
    return ".".join(map(str, v))


def branch(v: Version) -> Tuple[int, int]:
    return v[0], v[1]


@dataclass
class Advisory:
    id: str
    title: str
    severity: str
    nginx_severity: str
    vulnerable: List[Tuple[Version, Version]]
    fixed: List[Version]
    requires: List[str]
    requires_source: str
    cvss: Optional[float] = None
    impact: str = ""

    def affects(self, v: Version) -> bool:
        if not any(lo <= v <= hi for lo, hi in self.vulnerable):
            return False
        return not self.is_fixed_in(v)

    def is_fixed_in(self, v: Version) -> bool:
        if self.fixed and v >= max(self.fixed):
            return True
        return any(branch(f) == branch(v) and v >= f for f in self.fixed)

    def fix_for(self, v: Version) -> Optional[Version]:
        """The release to move to: the fix in this branch, else the nearest newer fix."""
        same = [f for f in self.fixed if branch(f) == branch(v)]
        if same:
            return same[0]
        newer = sorted(f for f in self.fixed if f > v)
        return newer[0] if newer else None


@dataclass
class Database:
    advisories: List[Advisory] = field(default_factory=list)
    retrieved: str = ""
    source: str = ""

    def affecting(self, v: Version) -> List[Advisory]:
        return [a for a in self.advisories if a.affects(v)]


def load(path: str = DATA) -> Database:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    db = Database(retrieved=raw.get("retrieved", ""), source=raw.get("source", ""))
    for e in raw["advisories"]:
        db.advisories.append(Advisory(
            id=e["id"], title=e["title"], severity=e["severity"], nginx_severity=e["nginx_severity"],
            vulnerable=[(parse_version(lo), parse_version(hi)) for lo, hi in e["vulnerable"]],
            fixed=[parse_version(f) for f in e["fixed"] if parse_version(f)],
            requires=e["requires"], requires_source=e["requires_source"],
            cvss=e.get("cvss"), impact=e.get("impact", "")))
    return db


def upgrade_target(v: Version, hits: List[Advisory]) -> Optional[Version]:
    """One release that fixes everything in `hits`, staying in the current branch when it's maintained."""
    targets = [a.fix_for(v) for a in hits]
    targets = [t for t in targets if t]
    if not targets:
        return None
    same = [t for t in targets if branch(t) == branch(v)]
    other = [t for t in targets if branch(t) != branch(v)]
    if same and not other:
        return max(same)
    # leaving the branch: the target must also be past every fix in its own new branch
    best = max(other) if other else max(same)
    for a in hits:
        fixes_in_best_branch = [f for f in a.fixed if branch(f) == branch(best)]
        if fixes_in_best_branch and best < fixes_in_best_branch[0]:
            best = fixes_in_best_branch[0]
        elif not fixes_in_best_branch and a.fixed and best < max(a.fixed):
            best = max(a.fixed)
    return best

"""Inspect the nginx installed on this machine.

Runs only read-only commands: `nginx -V` (version and build options) and
`nginx -T` (the configuration it would load). Reads the distribution's
package changelog to find security fixes backported into older versions.
"""

import glob
import gzip
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Set

from . import config as C
from .advisories import Version, parse_version

DEBIAN_CHANGELOGS = "/usr/share/doc/nginx*/changelog.Debian.gz"   # patched in tests
CANDIDATES = ["nginx", "/usr/sbin/nginx", "/usr/local/sbin/nginx", "/usr/local/nginx/sbin/nginx",
              "/opt/nginx/sbin/nginx", "/usr/local/openresty/nginx/sbin/nginx", "/opt/homebrew/bin/nginx",
              "/usr/local/bin/nginx"]


@dataclass
class Install:
    binary: str
    version: Optional[Version]
    raw_version: str = ""
    configure: str = ""
    conf_path: str = ""
    prefix: str = ""
    package: str = ""                  # "nginx-core 1.24.0-2ubuntu7.21" when installed from a package
    backported: Set[str] = field(default_factory=set)
    backport_source: str = ""
    features: C.Features = field(default_factory=C.no_config)
    config_note: str = ""
    missing_modules: Set[str] = field(default_factory=set)


def _run(cmd: List[str], timeout: int = 30) -> Optional[subprocess.CompletedProcess]:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


def find_binaries(explicit: Optional[str] = None) -> List[str]:
    if explicit:
        return [explicit]
    out = []
    for c in CANDIDATES:
        p = shutil.which(c) if os.sep not in c else (c if os.access(c, os.X_OK) else None)
        if p and os.path.realpath(p) not in {os.path.realpath(x) for x in out}:
            out.append(p)
    return out


def _modules(configure: str) -> Set[str]:
    """Features that can't be on because the module was never compiled in."""
    missing = set()
    if configure:
        if "--with-http_v2_module" not in configure:
            missing.add("http2")
        if "--with-http_v3_module" not in configure:
            missing.add("http3")
        if "--with-mail" not in configure:
            missing.update({"mail", "mail_auth_http", "mail_cram_apop"})
        if "--with-stream_ssl_preread_module" not in configure:
            missing.add("ssl_preread")
        if "--with-http_mp4_module" not in configure:
            missing.add("mp4")
        if "--with-http_dav_module" not in configure:
            missing.add("dav")
        if "--with-http_slice_module" not in configure:
            missing.add("slice")
        if "--with-http_ssl_module" not in configure:
            missing.update({"ssl", "tls13", "ocsp"})
    return missing


def backports() -> (Set[str], str, str):
    """CVE ids fixed by the distribution's nginx package, plus the package and where we looked."""
    # Debian, Ubuntu and derivatives
    for path in sorted(glob.glob(DEBIAN_CHANGELOGS)):
        try:
            with gzip.open(path, "rt", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        pkg = ""
        r = _run(["dpkg-query", "-W", "-f=${Package} ${Version}\\n", "nginx-core", "nginx", "nginx-full",
                  "nginx-light", "nginx-extras"])
        if r and r.stdout.strip():
            pkg = r.stdout.strip().splitlines()[0]
        return set(re.findall(r"CVE-\d{4}-\d+", text)), pkg, path
    # RHEL, Fedora, CentOS, Rocky, Alma, Amazon Linux, SUSE
    r = _run(["rpm", "-q", "--changelog", "nginx"])
    if r and r.returncode == 0:
        pkg = (_run(["rpm", "-q", "nginx"]) or subprocess.CompletedProcess([], 0, "", "")).stdout.strip()
        return set(re.findall(r"CVE-\d{4}-\d+", r.stdout)), pkg, "rpm -q --changelog nginx"
    return set(), "", ""


def inspect(binary: Optional[str] = None, conf: Optional[str] = None) -> List[Install]:
    out = []
    for b in find_binaries(binary):
        r = _run([b, "-V"])
        if not r:
            continue
        text = r.stderr + r.stdout
        m = re.search(r"nginx version: (?:nginx|openresty)/(\S+)", text)
        inst = Install(binary=b, version=parse_version(m.group(1)) if m else None,
                       raw_version=m.group(1) if m else "")
        cm = re.search(r"configure arguments: (.*)", text)
        inst.configure = cm.group(1) if cm else ""
        pm = re.search(r"--prefix=(\S+)", inst.configure)
        inst.prefix = pm.group(1) if pm else ""
        cpm = re.search(r"--conf-path=(\S+)", inst.configure)
        inst.conf_path = conf or (cpm.group(1) if cpm else (os.path.join(inst.prefix, "conf/nginx.conf") if inst.prefix else ""))
        inst.missing_modules = _modules(inst.configure)
        if os.path.realpath(b).startswith("/usr/sbin/") or os.path.realpath(b).startswith("/usr/bin/"):
            inst.backported, inst.package, inst.backport_source = backports()
        _load_config(inst, conf)
        out.append(inst)
    return out


def _load_config(inst: Install, conf: Optional[str]):
    # Prefer `nginx -T`: it's exactly what the server loads, includes and all
    cmd = [inst.binary, "-T"] + (["-c", conf] if conf else [])
    r = _run(cmd)
    dump = (r.stdout if r else "")
    files = C.split_dump(dump)
    if files:
        loader = C.Loader(files, prefix=os.path.dirname(list(files)[0]))
        tree = loader.load(list(files)[0])
        inst.features = C.features(tree, inst.version)
        inst.config_note = f"from `nginx -T` ({len(files)} file{'s' if len(files) != 1 else ''})"
        return
    if inst.conf_path and os.path.exists(inst.conf_path):
        loader = C.Loader(prefix=os.path.dirname(inst.conf_path))
        tree = loader.load(inst.conf_path)
        inst.features = C.features(tree, inst.version)
        inst.config_note = f"read from {inst.conf_path} ({len(loader.seen)} file{'s' if len(loader.seen) != 1 else ''})"
        if loader.errors:
            inst.config_note += f"; {len(loader.errors)} could not be read"
        return
    err = (r.stderr.strip().splitlines()[-1] if r and r.stderr.strip() else "no configuration found")
    inst.config_note = f"configuration not available ({err[:120]}); try running as root"

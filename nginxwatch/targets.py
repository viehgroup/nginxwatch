"""Other things to check: a repository, a container image tag, a URL."""

import json
import os
import re
import socket
import ssl
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from . import config as C
from .advisories import Version, parse_version

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "latest_in_branch.json")
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build"}
NGINX_IMAGES = re.compile(r"(?:^|/)(?:nginx|nginx-unprivileged|nginxinc/nginx-unprivileged|bitnami/nginx)$")


def latest_in_branch() -> dict:
    with open(DATA, encoding="utf-8") as fh:
        return json.load(fh)


# ------------------------------------------------------------------ image tags

@dataclass
class ImageRef:
    image: str
    tag: str
    file: str
    line: int
    version: Optional[Version] = None
    floating: str = ""          # why the tag doesn't pin a version


def resolve_tag(tag: str) -> Tuple[Optional[Version], str]:
    """nginx:1.31.8-alpine -> 1.31.8; nginx:1.25 -> newest 1.25.x; nginx:stable -> floating."""
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", tag)
    if m:
        return tuple(map(int, m.groups())), ""
    m = re.match(r"^(\d+)\.(\d+)(?![.\d])", tag)
    if m:
        latest = latest_in_branch().get(f"{m.group(1)}.{m.group(2)}")
        if latest:
            return parse_version(latest), (f"'{tag}' follows the {m.group(1)}.{m.group(2)} branch, whose newest "
                                           f"release is {latest}; an image pulled earlier can be older")
        return None, f"'{tag}' names an unknown branch"
    return None, (f"'{tag or 'latest'}' moves with every release, so the version depends on when the image was "
                  "pulled; pin a version, or rebuild with a fresh pull")


def find_images(path: str, text: str) -> List[ImageRef]:
    out = []
    base = os.path.basename(path).lower()
    is_docker = base.startswith("dockerfile") or base.endswith(".dockerfile") or base == "containerfile"
    for n, line in enumerate(text.splitlines(), 1):
        if is_docker:
            m = re.match(r"\s*FROM\s+(?:--platform=\S+\s+)?([^\s:@]+)(?::([^\s@]+))?", line, re.I)
        else:
            m = re.match(r"\s*-?\s*image:\s*['\"]?([^\s:'\"@]+)(?::([^\s'\"@]+))?", line)
        if not m:
            continue
        image, tag = m.group(1), m.group(2) or "latest"
        if not NGINX_IMAGES.search(image.split("docker.io/")[-1]):
            continue
        version, floating = resolve_tag(tag)
        out.append(ImageRef(image, tag, path, n, version, floating))
    return out


# ------------------------------------------------------------------ repositories

@dataclass
class RepoScan:
    configs: List[Tuple[str, C.Features, List[str]]] = field(default_factory=list)   # (root file, features, errors)
    images: List[ImageRef] = field(default_factory=list)


def _looks_like_nginx(text: str) -> bool:
    return bool(re.search(r"^\s*(?:http|server|events|stream|upstream)\s*\{", text, re.M)) or \
        bool(re.search(r"^\s*(?:listen|server_name|proxy_pass|location)\s", text, re.M))


def scan_repo(root: str) -> RepoScan:
    rs = RepoScan()
    conf_files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            p = os.path.join(dirpath, fn)
            low = fn.lower()
            want_conf = low.endswith(".conf") or low == "nginx.conf" or low.endswith(".nginx") or ".conf.template" in low
            want_img = low.startswith("dockerfile") or low.endswith((".yml", ".yaml", ".dockerfile")) or low == "containerfile"
            if not (want_conf or want_img):
                continue
            try:
                if os.path.getsize(p) > 2_000_000:
                    continue
                with open(p, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            if want_img:
                rs.images.extend(find_images(os.path.relpath(p, root), text))
            if want_conf and _looks_like_nginx(text):
                conf_files.append(p)
    # Analyse each file whole, following includes; files pulled in by another one aren't analysed twice
    included = set()
    loaders = []
    # folders holding an nginx.conf are configuration prefixes for files below them
    prefixes = sorted({os.path.dirname(p) for p in conf_files if os.path.basename(p) == "nginx.conf"}, key=len)
    for p in conf_files:
        own = [px for px in prefixes if os.path.normpath(p).startswith(os.path.normpath(px) + os.sep)]
        loader = C.Loader(prefix=own[-1] if own else os.path.dirname(p), roots=[os.path.dirname(p), root])
        tree = loader.load(p)
        loaders.append((p, loader, tree))
        included |= {os.path.normpath(x) for x in loader.seen if os.path.normpath(x) != os.path.normpath(p)}
    for p, loader, tree in loaders:
        if os.path.normpath(p) in included:
            continue
        rs.configs.append((os.path.relpath(p, root), C.features(tree), loader.errors))
    return rs


# ------------------------------------------------------------------ URLs

@dataclass
class Probe:
    url: str
    server: str = ""
    version: Optional[Version] = None
    http2: Optional[bool] = None
    http3: Optional[bool] = None
    tls13: Optional[bool] = None
    error: str = ""


def probe(url: str, timeout: float = 10) -> Probe:
    """What any client sees on connect: the Server header and the protocols offered. Nothing more."""
    if "://" not in url:
        url = "https://" + url
    u = urllib.parse.urlsplit(url)
    pr = Probe(url)
    host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        pr.error = f"couldn't connect: {e}"
        return pr
    sock = raw
    try:
        if u.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE   # we only read headers; certificate problems shouldn't hide the answer
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            sock = ctx.wrap_socket(raw, server_hostname=host)
            pr.http2 = sock.selected_alpn_protocol() == "h2"
            pr.tls13 = sock.version() == "TLSv1.3"
            if pr.http2:  # ask again over HTTP/1.1 to read the headers
                sock.close()
                raw = socket.create_connection((host, port), timeout=timeout)
                ctx2 = ssl.create_default_context()
                ctx2.check_hostname = False
                ctx2.verify_mode = ssl.CERT_NONE
                ctx2.set_alpn_protocols(["http/1.1"])
                sock = ctx2.wrap_socket(raw, server_hostname=host)
        path = u.path or "/"
        sock.sendall(f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: nginxwatch\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        head = data.split(b"\r\n\r\n")[0].decode("latin-1")
        for line in head.split("\r\n")[1:]:
            k, _, val = line.partition(":")
            if k.strip().lower() == "server":
                pr.server = val.strip()
            if k.strip().lower() == "alt-svc" and "h3" in val:
                pr.http3 = True
        m = re.search(r"nginx/(\d+\.\d+\.\d+)", pr.server)
        pr.version = parse_version(m.group(1)) if m else None
        if pr.http3 is None:
            pr.http3 = False
    except (OSError, ssl.SSLError) as e:
        pr.error = f"connection failed: {e}"
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return pr

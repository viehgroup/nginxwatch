"""Read an nginx configuration and work out which risky features it uses.

Works on files on disk (following `include`) or on the output of `nginx -T`,
which prints every configuration file the server actually loaded.
"""

import fnmatch
import glob
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .advisories import Version


class ConfigError(Exception):
    pass


@dataclass
class Directive:
    name: str
    args: List[str]
    block: Optional[List["Directive"]]
    file: str
    line: int


def tokenize(text: str):
    """Yield (token, line, quoted). Tokens: words, quoted strings, '{', '}', ';'."""
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif c in " \t\r":
            i += 1
        elif c == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif c in "{};":
            yield c, line, False
            i += 1
        elif c in "\"'":
            q, j, buf = c, i + 1, []
            while j < n and text[j] != q:
                if text[j] == "\\" and j + 1 < n:
                    buf.append(text[j + 1])
                    j += 2
                    continue
                if text[j] == "\n":
                    line += 1
                buf.append(text[j])
                j += 1
            yield "".join(buf), line, True
            i = j + 1
        else:
            j, buf = i, []
            while j < n and text[j] not in " \t\r\n;{}\"'":
                if text[j] == "$" and j + 1 < n and text[j + 1] == "{":
                    k = text.find("}", j)  # ${var} is part of a word, not a block
                    if k < 0:
                        break
                    buf.append(text[j:k + 1])
                    j = k + 1
                    continue
                if text[j] == "#" and j > i:  # '#' only starts a comment at a token boundary
                    buf.append("#")
                    j += 1
                    continue
                buf.append(text[j])
                j += 1
            yield "".join(buf), line, False
            i = j


def parse(text: str, file: str = "nginx.conf") -> List[Directive]:
    toks = list(tokenize(text))
    pos = 0

    def block(depth: int) -> List[Directive]:
        nonlocal pos
        out: List[Directive] = []
        words: List[str] = []
        start = None
        while pos < len(toks):
            tok, line, quoted = toks[pos]
            pos += 1
            if not quoted and tok == ";":
                if words:
                    out.append(Directive(words[0], words[1:], None, file, start))
                words, start = [], None
            elif not quoted and tok == "{":
                if not words:
                    raise ConfigError(f"{file}:{line}: block without a directive name")
                d = Directive(words[0], words[1:], [], file, start)
                d.block = block(depth + 1)
                out.append(d)
                words, start = [], None
            elif not quoted and tok == "}":
                if depth == 0:
                    raise ConfigError(f"{file}:{line}: unexpected '}}'")
                return out
            else:
                if start is None:
                    start = line
                words.append(tok)
        if depth:
            raise ConfigError(f"{file}: missing '}}' at end of file")
        return out

    return block(0)


# Files every nginx install ships; a repository that includes them doesn't need to contain them
STANDARD_FILES = {"mime.types", "fastcgi_params", "fastcgi.conf", "scgi_params", "uwsgi_params",
                  "koi-utf", "koi-win", "win-utf", "proxy_params", "snippets/fastcgi-php.conf"}


class Loader:
    """Resolves `include` against either the real filesystem or an `nginx -T` dump.

    nginx resolves relative includes against its configuration prefix (the folder of
    the main nginx.conf). For loose files in a repository we also try the including
    file's folder and the repository root, since that's where the prefix usually maps.
    """

    def __init__(self, files: Optional[Dict[str, str]] = None, prefix: str = "", roots: List[str] = ()):
        self.files = files  # path -> text when working from nginx -T
        self.prefix = prefix
        self.roots = [r for r in roots if r]
        self.seen: Set[str] = set()
        self.errors: List[str] = []

    def read(self, path: str) -> Optional[str]:
        if self.files is not None:
            return self.files.get(path)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError as e:
            if os.path.basename(path) not in STANDARD_FILES and not path.endswith(tuple(STANDARD_FILES)):
                self.errors.append(f"{path}: {e.strerror}")
            return None

    def expand(self, pattern: str, base: str) -> List[str]:
        if os.path.isabs(pattern):
            candidates = [pattern]
        else:
            candidates = [os.path.join(b, pattern) for b in [self.prefix or base, base] + self.roots]
        if self.files is not None:
            for c in candidates:
                hits = sorted(p for p in self.files if fnmatch.fnmatch(p, c))
                if hits:
                    return hits
            return []
        for c in dict.fromkeys(candidates):
            hits = sorted(glob.glob(c))
            if hits:
                return hits
        if any(ch in pattern for ch in "*?["):
            return []  # an empty glob is fine for nginx too
        return [candidates[0]]

    def load(self, path: str) -> List[Directive]:
        real = os.path.normpath(path)
        if real in self.seen:
            return []
        self.seen.add(real)
        text = self.read(path)
        if text is None:
            return []
        try:
            tree = parse(text, path)
        except ConfigError as e:
            self.errors.append(str(e))
            return []
        return self._inline(tree, os.path.dirname(path))

    def _inline(self, tree: List[Directive], base: str) -> List[Directive]:
        out = []
        for d in tree:
            if d.name == "include" and d.args and d.block is None:
                for p in self.expand(d.args[0], base):
                    out.extend(self.load(p))
                continue
            if d.block is not None:
                d.block = self._inline(d.block, base)
            out.append(d)
        return out


def split_dump(text: str) -> Dict[str, str]:
    """`nginx -T` prints '# configuration file /path:' before each file."""
    files: Dict[str, str] = {}
    current = None
    buf: List[str] = []
    for line in text.splitlines(keepends=True):
        m = re.match(r"# configuration file (.+):\s*$", line)
        if m:
            if current:
                files[current] = "".join(buf)
            current, buf = m.group(1), []
        elif current:
            buf.append(line)
    if current:
        files[current] = "".join(buf)
    return files


# ------------------------------------------------------------------ features

PASSES = ("proxy_pass", "grpc_pass", "fastcgi_pass", "uwsgi_pass", "scgi_pass", "memcached_pass")


@dataclass
class Evidence:
    where: str      # "file:line"
    detail: str


@dataclass
class Features:
    found: Dict[str, Evidence] = field(default_factory=dict)
    known: bool = True  # False when we had no configuration to look at
    absent: Set[str] = field(default_factory=set)  # known to be off even when the rest is unknown

    def add(self, name: str, d: Directive, detail: str = ""):
        self.found.setdefault(name, Evidence(f"{d.file}:{d.line}", detail or " ".join([d.name] + d.args)[:100]))

    def mark(self, name: str, on: Optional[bool], where: str):
        """Record something observed from outside, like a probe's protocol check."""
        if on:
            self.found.setdefault(name, Evidence(where, "observed"))
        elif on is False:
            self.absent.add(name)

    def has(self, name: str) -> Optional[bool]:
        if name in self.found:
            return True
        if name in self.absent:
            return False
        return False if self.known else None


def features(tree: List[Directive], version: Optional[Version] = None) -> Features:
    f = Features()
    tls13_default = version is None or version >= (1, 23, 4)  # TLSv1.3 joined the defaults in 1.23.4

    def walk(nodes: List[Directive], ctx: List[str], inherited: Dict[str, Directive]):
        local = dict(inherited)
        for d in nodes:
            if d.name in ("ssl_protocols", "http2", "http3"):
                local[d.name] = d
        for d in nodes:
            name, args = d.name, d.args
            top = ctx[0] if ctx else ""
            if name == "listen":
                low = [a.lower() for a in args]
                if "http2" in low:
                    f.add("http2", d)
                if "quic" in low:
                    f.add("http3", d)
                if "proxy_protocol" in low:
                    f.add("proxy_protocol", d)
                if "spdy" in low:
                    f.add("spdy", d)
                if "ssl" in low:
                    f.add("ssl", d)
                    protos = local.get("ssl_protocols")
                    if (protos is None and tls13_default) or (protos is not None and "TLSv1.3" in protos.args):
                        f.add("tls13", d, "TLS listener with TLSv1.3 " + ("(the default)" if protos is None else "enabled"))
            elif name == "http2" and args[:1] == ["on"]:
                f.add("http2", d)
            elif name == "http3" and args[:1] == ["on"]:
                f.add("http3", d)
            elif name == "ssl" and args[:1] == ["on"]:
                f.add("ssl", d)
            elif name in PASSES and top == "http":
                f.add("proxy", d)
                if name == "grpc_pass":
                    f.add("grpc", d)
                if name == "proxy_pass" and args and args[0].lower().startswith("https://"):
                    f.add("proxy_ssl", d)
                if name in ("scgi_pass", "uwsgi_pass"):
                    f.add("scgi_uwsgi", d)
            elif name == "proxy_pass" and top == "stream":
                f.add("proxy", d)
            elif name == "proxy_http_version" and args[:1] == ["2"]:
                f.add("grpc", d)
                f.add("http2_upstream", d)
            elif name == "resolver":
                f.add("resolver", d)
            elif name in ("ssl_stapling", "ssl_ocsp") and args[:1] in (["on"], ["leaf"]):
                f.add("ocsp", d)
                if top == "stream" and name == "ssl_ocsp":
                    f.add("stream_ocsp", d)
            elif name == "ssl_preread" and args[:1] == ["on"]:
                f.add("ssl_preread", d)
            elif name == "ssl_verify_client" and top == "stream" and args[:1] in (["on"], ["optional"], ["optional_no_ca"]):
                f.add("stream_client_cert", d)
            elif name == "auth_http" and top == "mail":
                f.add("mail_auth_http", d)
            elif name in ("smtp_auth", "pop3_auth", "imap_auth") and any(a.lower() in ("cram-md5", "apop") for a in args):
                f.add("mail_cram_apop", d)
            elif name == "mp4":
                f.add("mp4", d)
            elif name == "dav_methods" and args[:1] != ["off"]:
                f.add("dav", d)
            elif name == "slice":
                f.add("slice", d)
            elif name == "ssi" and args[:1] == ["on"]:
                f.add("ssi", d)
            elif name in ("charset", "source_charset") and args[:1] != ["off"]:
                f.add("charset", d)
            elif name == "rewrite":
                f.add("rewrite", d)
            elif name == "aio" and args[:1] and args[0] != "off":
                f.add("aio", d)
            elif name == "map" and d.block:
                if any(c.name.startswith("~") for c in d.block):
                    f.add("map_regex", d)
            if name == "mail" and d.block is not None:
                f.add("mail", d)
            if name == "location" and d.block:
                inner = {c.name for c in d.block}
                if "alias" in inner and "try_files" in inner:
                    f.add("alias_try_files", d, "location with alias and try_files")
                if "alias" in inner and "rewrite" in inner:
                    f.add("alias_rewrite", d, "location with alias and rewrite")
            if d.block is not None:
                walk(d.block, ctx + [name], local)

    walk(tree, [], {})
    return f


def no_config() -> Features:
    return Features(known=False)

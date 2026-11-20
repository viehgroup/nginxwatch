import argparse
import os
import sys
from typing import List

from . import __version__, analyze, local, report, targets
from . import config as C
from .advisories import load as load_db
from .advisories import parse_version, vstr
from .analyze import ORDER, Verdict

COMMANDS = {"local", "version", "url", "repo", "advisories"}
CHECKED_CONDITIONS = ["http2", "proxy", "http3", "resolver", "mail_auth_http", "tls13", "proxy_protocol",
                      "alias_try_files", "ssl_preread", "stream_client_cert"]


def build_parser():
    p = argparse.ArgumentParser(prog="nginxwatch",
                                description="Is my nginx exploitable? Checks version, configuration and "
                                            "distribution patches against nginx.org's security advisories.",
                                epilog="With no command, checks the nginx installed on this machine.")
    p.add_argument("--version", action="version", version=f"nginxwatch {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=["text", "json", "sarif", "github", "markdown"], default="text")
    common.add_argument("-o", "--output")
    common.add_argument("--summary", metavar="FILE", help="also append a Markdown summary (e.g. $GITHUB_STEP_SUMMARY)")
    common.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "never"], default="high")
    common.add_argument("--all", action="store_true", help="also list advisories that don't apply")
    common.add_argument("--no-color", action="store_true")
    sub = p.add_subparsers(dest="cmd")
    lc = sub.add_parser("local", parents=[common], help="check nginx on this machine (default)")
    lc.add_argument("--binary", help="path to the nginx binary")
    lc.add_argument("--conf", help="configuration file to check instead of the default")
    vc = sub.add_parser("version", parents=[common], help="check a version number, optionally with a config")
    vc.add_argument("number")
    vc.add_argument("--config", help="nginx.conf to check alongside the version")
    uc = sub.add_parser("url", parents=[common], help="check what a server you run shows from outside")
    uc.add_argument("urls", nargs="+")
    rc = sub.add_parser("repo", parents=[common], help="check nginx configs, Dockerfiles and manifests in a folder")
    rc.add_argument("path", nargs="?", default=".")
    sub.add_parser("advisories", help="list the advisories nginxwatch knows")
    return p


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0] not in COMMANDS and argv[0] not in ("-h", "--help", "--version")):
        argv.insert(0, "local")
    try:
        return _main(argv)
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
    except KeyboardInterrupt:
        return 130


def _main(argv: List[str]) -> int:
    args = build_parser().parse_args(argv)
    db = load_db()
    if args.cmd == "advisories":
        for a in db.advisories:
            print(f"{a.id:16} {a.severity:8} {a.title}\n{'':17}fixed in {', '.join(vstr(f) for f in a.fixed)}"
                  + (f"; needs {', '.join(a.requires)}" if a.requires else ""))
        print(f"\n{len(db.advisories)} advisories from {db.source}, retrieved {db.retrieved}")
        return 0

    verdicts: List[Verdict] = []
    extra: List[str] = []
    if args.cmd == "local":
        installs = local.inspect(args.binary, args.conf)
        if not installs:
            print("nginxwatch: no nginx found on this machine. Use --binary, or `nginxwatch version X.Y.Z`.",
                  file=sys.stderr)
            return 2
        for inst in installs:
            v = analyze.judge(db, inst.binary, inst.version, inst.features, inst.backported, inst.missing_modules,
                              windows=os.name == "nt", package=inst.package)
            v.notes.insert(0, f"configuration {inst.config_note}")
            verdicts.append(v)
    elif args.cmd == "version":
        version = parse_version(args.number)
        if not version:
            print(f"nginxwatch: '{args.number}' isn't a version like 1.24.0", file=sys.stderr)
            return 2
        feats = C.no_config()
        if args.config:
            loader = C.Loader(prefix=os.path.dirname(os.path.abspath(args.config)))
            feats = C.features(loader.load(args.config), version)
        verdicts.append(analyze.judge(db, f"nginx {args.number}" + (f" with {args.config}" if args.config else ""),
                                      version, feats))
    elif args.cmd == "url":
        for url in args.urls:
            pr = targets.probe(url)
            feats = C.no_config()
            for name, on in (("http2", pr.http2), ("http3", pr.http3), ("tls13", pr.tls13)):
                feats.mark(name, on, "seen from outside")
            v = analyze.judge(db, url, pr.version, feats)
            if pr.error:
                v.notes.append(pr.error)
            elif pr.version is None:
                v.notes.append(f"the server doesn't reveal its version (Server: {pr.server or 'none'}); "
                               "run nginxwatch on the server itself")
            v.notes.append("seen from outside: HTTP/2 " + ("on" if pr.http2 else "off") + ", HTTP/3 "
                           + ("advertised" if pr.http3 else "not advertised")
                           + "; proxying and resolver use can only be checked on the server")
            verdicts.append(v)
    else:  # repo
        if not os.path.isdir(args.path):
            print(f"nginxwatch: {args.path} isn't a folder", file=sys.stderr)
            return 2
        rs = targets.scan_repo(args.path)
        # A repository may not hold the whole runtime configuration (templates, generated files), so
        # features we can't find are unknown rather than off
        union = C.Features(known=False)
        for path, feats, errs in rs.configs:
            for k, e in feats.found.items():
                file, _, line = e.where.rpartition(":")
                rel = os.path.relpath(file, args.path) if os.path.isabs(file) or os.path.exists(file) else file
                union.found.setdefault(k, C.Evidence(f"{rel}:{line}", e.detail))
        floating = [i for i in rs.images if i.version is None]
        if floating:
            refs = ", ".join(f"{i.file}:{i.line} ({i.image.split('/')[-1]}:{i.tag})" for i in floating[:6])
            more = f" and {len(floating) - 6} more" if len(floating) > 6 else ""
            extra.append(f"{len(floating)} image reference(s) use tags that don't pin a version, so they can't be "
                         f"checked here: {refs}{more}. Pin a version, or make sure images are pulled fresh.")
        for img in rs.images:
            if img.version is None:
                continue
            feats = union if rs.configs else C.no_config()
            v = analyze.judge(db, f"{img.file}:{img.line}", img.version, feats)
            v.target = f"{img.file}:{img.line}"
            if img.floating:
                v.notes.append(img.floating)
            if rs.configs:
                v.notes.append("conditions checked against the nginx configuration in this repository")
            verdicts.append(v)
        for path, feats, errs in rs.configs:
            used = [analyze.FEATURE_WORDS[c] for c in CHECKED_CONDITIONS if c in feats.found]
            if used:
                extra.append(f"{path}: uses {', '.join(used)}. With nginx older than 1.30.7 (stable) or 1.31.9 "
                             "(mainline) that is enough for the November 2026 advisories to apply.")
            for e in errs:
                extra.append(f"{path}: {e}")
        if not rs.images and not rs.configs:
            extra.append("No nginx configuration, Dockerfile or manifest using an nginx image found.")

    if args.format == "json":
        out = report.as_json(verdicts)
    elif args.format == "sarif":
        out = report.sarif(verdicts)
    elif args.format == "github":
        out = report.github(verdicts)
    elif args.format == "markdown":
        out = report.markdown(verdicts, extra)
    else:
        color = not args.output and sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
        out = report.text(verdicts, color, args.all, extra)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
    elif out:
        print(out)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(report.markdown(verdicts, extra) + "\n")
    if args.fail_on == "never":
        return 0
    return 1 if report.worst(verdicts) >= ORDER[args.fail_on] else 0

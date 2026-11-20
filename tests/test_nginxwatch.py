import gzip
import io
import json
import os
import shutil
import stat
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from nginxwatch import analyze, cli, local, report, targets
from nginxwatch import config as C
from nginxwatch.advisories import load, parse_version as v, upgrade_target, vstr

DB = load()


def adv(cve):
    return next(a for a in DB.advisories if a.id == cve)


def statuses(verdict):
    return {h.advisory.id: h.status for h in verdict.hits}


class Versions(unittest.TestCase):
    def test_this_weeks_fix_on_both_branches(self):
        a = adv("CVE-2026-123007")
        self.assertTrue(a.affects(v("1.31.8")))
        self.assertTrue(a.affects(v("1.30.6")))
        self.assertTrue(a.affects(v("1.24.0")))
        self.assertFalse(a.affects(v("1.31.9")))
        self.assertFalse(a.affects(v("1.30.7")))   # stable fix, though numerically below 1.31.8
        self.assertFalse(a.affects(v("1.9.4")))    # before HTTP/2 existed

    def test_mainline_only_advisory(self):
        a = adv("CVE-2026-120993")  # 1.31.4-1.31.8 only
        self.assertTrue(a.affects(v("1.31.5")))
        self.assertFalse(a.affects(v("1.30.6")))

    def test_upgrade_targets(self):
        for ver, want in (("1.31.8", "1.31.9"), ("1.30.6", "1.30.7"), ("1.24.0", "1.30.7"), ("1.31.5", "1.31.9")):
            hits = DB.affecting(v(ver))
            self.assertEqual(vstr(upgrade_target(v(ver), hits)), want, ver)
        self.assertEqual(DB.affecting(v("1.30.7")), [])
        self.assertEqual(DB.affecting(v("1.31.9")), [])

    def test_data_is_complete(self):
        self.assertEqual(len(DB.advisories), 77)
        for a in DB.advisories:
            self.assertTrue(a.vulnerable and a.fixed, a.id)
            self.assertIn(a.severity, ("critical", "high", "medium", "low"))


CONF = """
events {}
http {
    map $uri $x { ~^/a 1; default 0; }   # a comment with { braces }
    server {
        listen 443 ssl;
        http2 on;
        server_name "example.test";
        add_header X-Test "a;b{c}";
        location /static/ { alias /srv/static/; try_files $uri =404; }
        location /api/ { proxy_pass http://127.0.0.1:${port}; }
    }
}
"""


class Config(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, rel, text):
        p = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(text)
        return p

    def test_parser_handles_quotes_comments_and_vars(self):
        tree = C.parse(CONF)
        server = [d for d in tree if d.name == "http"][0].block[1]
        names = [d.name for d in server.block]
        self.assertEqual(names, ["listen", "http2", "server_name", "add_header", "location", "location"])
        self.assertEqual(server.block[3].args, ["X-Test", "a;b{c}"])

    def test_features(self):
        f = C.features(C.parse(CONF), v("1.31.8"))
        for name in ("http2", "ssl", "tls13", "proxy", "alias_try_files", "map_regex"):
            self.assertIn(name, f.found, name)
        self.assertNotIn("http3", f.found)
        self.assertNotIn("resolver", f.found)

    def test_tls13_default_depends_on_version(self):
        tree = C.parse("http { server { listen 443 ssl; } }")
        self.assertIn("tls13", C.features(tree, v("1.24.0")).found)
        self.assertNotIn("tls13", C.features(tree, v("1.22.1")).found)  # default gained TLSv1.3 in 1.23.4
        off = C.parse("http { ssl_protocols TLSv1.2; server { listen 443 ssl; } }")
        self.assertNotIn("tls13", C.features(off, v("1.31.8")).found)

    def test_includes_like_nginx(self):
        main = self.write("nginx.conf", "events {}\nhttp { include mime.types; include conf.d/*.conf; }\n")
        self.write("conf.d/site.conf", "server { listen 443 ssl http2; include snippets/proxy.conf; }\n")
        self.write("conf.d/.hidden.conf", "server { listen 8443 quic; }\n")  # nginx's glob skips dotfiles
        self.write("snippets/proxy.conf", "location / { proxy_pass http://app; }\n")
        loader = C.Loader(prefix=self.tmp)
        f = C.features(loader.load(main))
        self.assertIn("http2", f.found)
        self.assertIn("proxy", f.found)
        self.assertNotIn("http3", f.found)
        self.assertEqual(loader.errors, [])  # mime.types ships with nginx; not an error
        self.assertIn("conf.d/site.conf:1", f.found["http2"].where)

    def test_nginx_T_dump(self):
        dump = ("# configuration file /etc/nginx/nginx.conf:\nhttp { include /etc/nginx/conf.d/*.conf; }\n\n"
                "# configuration file /etc/nginx/conf.d/a.conf:\nserver { listen 443 quic; location / { proxy_pass http://x; } }\n")
        files = C.split_dump(dump)
        self.assertEqual(list(files), ["/etc/nginx/nginx.conf", "/etc/nginx/conf.d/a.conf"])
        f = C.features(C.Loader(files).load("/etc/nginx/nginx.conf"))
        self.assertIn("http3", f.found)

    def test_broken_config_is_reported_not_raised(self):
        p = self.write("bad.conf", "http { server { listen 80;\n")
        loader = C.Loader(prefix=self.tmp)
        self.assertEqual(loader.load(p), [])
        self.assertIn("missing '}'", loader.errors[0])


class Verdicts(unittest.TestCase):
    def test_exposed_not_used_and_fixed(self):
        f = C.features(C.parse(CONF), v("1.31.8"))
        verdict = analyze.judge(DB, "t", v("1.31.8"), f)
        st = statuses(verdict)
        self.assertEqual(st["CVE-2026-123007"], analyze.EXPOSED)
        self.assertEqual(st["CVE-2026-123633"], analyze.EXPOSED)
        self.assertEqual(st["CVE-2026-121810"], analyze.NOT_USED)   # no HTTP/3
        self.assertEqual(st["CVE-2026-123634"], analyze.NOT_USED)   # no resolver
        self.assertEqual(st["CVE-2026-125283"], analyze.EXPOSED)    # alias + try_files
        self.assertEqual(vstr(verdict.upgrade_to), "1.31.9")
        self.assertEqual(analyze.judge(DB, "t", v("1.30.7"), f).hits, [])

    def test_unknown_config_and_distribution_backports(self):
        verdict = analyze.judge(DB, "t", v("1.24.0"), C.no_config())
        self.assertTrue(all(h.status == analyze.UNKNOWN for h in verdict.hits))
        patched = {"CVE-2026-123007", "CVE-2026-123633"}
        verdict = analyze.judge(DB, "t", v("1.24.0"), C.no_config(), backported=patched, package="nginx 1.24.0-2ubuntu7.21")
        self.assertEqual(statuses(verdict)["CVE-2026-123007"], analyze.PATCHED)
        self.assertEqual(statuses(verdict)["CVE-2026-123634"], analyze.UNKNOWN)

    def test_module_not_compiled(self):
        f = C.features(C.parse(CONF), v("1.31.8"))
        verdict = analyze.judge(DB, "t", v("1.31.8"), f, missing={"http2"})
        self.assertEqual(statuses(verdict)["CVE-2026-123007"], analyze.NOT_USED)

    def test_windows_only_advisories(self):
        self.assertNotIn("CVE-2011-4963", statuses(analyze.judge(DB, "t", v("1.2.0"), C.no_config())))
        self.assertIn("CVE-2011-4963", statuses(analyze.judge(DB, "t", v("1.2.0"), C.no_config(), windows=True)))


FAKE_NGINX = r"""#!/bin/sh
case "$1" in
  -V) cat >&2 <<'EOF'
nginx version: nginx/1.31.8
built with OpenSSL 3.0.13 30 Jan 2024
configure arguments: --prefix=/opt/nginx --with-http_ssl_module --with-http_v2_module
EOF
  ;;
  -T) cat <<'EOF'
# configuration file /opt/nginx/conf/nginx.conf:
http { server { listen 443 ssl; http2 on; location / { proxy_pass http://app; } } }
EOF
  ;;
esac
"""


class Local(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.bin = os.path.join(self.tmp, "nginx")
        with open(self.bin, "w") as fh:
            fh.write(FAKE_NGINX)
        os.chmod(self.bin, os.stat(self.bin).st_mode | stat.S_IEXEC)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_inspect_with_nginx_T(self):
        inst = local.inspect(self.bin)[0]
        self.assertEqual(inst.version, (1, 31, 8))
        self.assertIn("http2", inst.features.found)
        self.assertIn("http3", inst.missing_modules)   # built without --with-http_v3_module
        verdict = analyze.judge(DB, self.bin, inst.version, inst.features, missing=inst.missing_modules)
        self.assertEqual(statuses(verdict)["CVE-2026-123633"], analyze.EXPOSED)
        self.assertEqual(statuses(verdict)["CVE-2026-121810"], analyze.NOT_USED)

    def test_debian_changelog_backports(self):
        log = os.path.join(self.tmp, "doc", "nginx", "changelog.Debian.gz")
        os.makedirs(os.path.dirname(log))
        with gzip.open(log, "wt") as fh:
            fh.write("nginx (1.24.0-2ubuntu7.21) noble-security\n  * CVE-2026-123007\n  * CVE-2026-123633\n")
        with mock.patch.object(local, "DEBIAN_CHANGELOGS", os.path.join(self.tmp, "doc", "nginx*", "changelog.Debian.gz")):
            fixed, pkg, src = local.backports()
        self.assertEqual(fixed, {"CVE-2026-123007", "CVE-2026-123633"})


class Repos(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        files = {
            "Dockerfile": "FROM node:22 AS build\nFROM nginx:1.25-alpine\n",
            "docker-compose.yml": "services:\n  web:\n    image: nginx:1.31.8\n  api:\n    image: \"nginx:1.30.7-alpine\"\n"
                                  "  db:\n    image: postgres:16\n",
            "k8s/web.yaml": "containers:\n  - name: web\n    image: docker.io/library/nginx:latest\n",
            "nginx/nginx.conf": "events {}\nhttp { include conf.d/*.conf; }\n",
            "nginx/conf.d/site.conf": "server { listen 443 ssl; http2 on; location / { proxy_pass http://api; } }\n",
        }
        for rel, text in files.items():
            p = os.path.join(self.tmp, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                fh.write(text)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_tag_resolution(self):
        self.assertEqual(targets.resolve_tag("1.31.8-alpine")[0], (1, 31, 8))
        self.assertEqual(targets.resolve_tag("1.25")[0], (1, 25, 5))  # newest 1.25.x
        self.assertIsNone(targets.resolve_tag("stable")[0])

    def test_scan(self):
        rs = targets.scan_repo(self.tmp)
        tags = sorted((i.file, i.tag) for i in rs.images)
        self.assertEqual(tags, [("Dockerfile", "1.25-alpine"), ("docker-compose.yml", "1.30.7-alpine"),
                                ("docker-compose.yml", "1.31.8"), ("k8s/web.yaml", "latest")])
        self.assertEqual(len(rs.configs), 1)   # site.conf is included by nginx.conf, not a separate root
        self.assertIn("http2", rs.configs[0][1].found)

    def test_cli_repo(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(["repo", self.tmp, "--format", "json"])
        results = {r["target"]: r for r in json.loads(buf.getvalue())["results"]}
        self.assertEqual(code, 1)
        self.assertEqual(results["docker-compose.yml:3"]["upgrade_to"], "1.31.9")
        self.assertEqual(results["Dockerfile:2"]["upgrade_to"], "1.30.7")
        self.assertEqual(results["docker-compose.yml:5"]["advisories"], [])
        why = next(a for a in results["docker-compose.yml:3"]["advisories"] if a["id"] == "CVE-2026-123007")["why"]
        self.assertIn("nginx/conf.d/site.conf:1", why)


class _Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Server", "nginx/1.31.8")
        self.send_header("Alt-Svc", 'h3=":443"; ma=86400')
        self.end_headers()

    def log_message(self, *a):
        pass


class Remote(unittest.TestCase):
    def test_probe_reads_only_headers(self):
        srv = HTTPServer(("127.0.0.1", 0), _Handler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            pr = targets.probe(f"http://127.0.0.1:{srv.server_port}/")
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(pr.version, (1, 31, 8))
        self.assertTrue(pr.http3)
        self.assertEqual(pr.error, "")


class Cli(unittest.TestCase):
    def run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(list(argv))
        return code, buf.getvalue()

    def test_version_command_and_formats(self):
        code, out = self.run_cli("version", "1.31.8", "--no-color")
        self.assertEqual(code, 1)
        self.assertIn("POSSIBLY VULNERABLE", out)
        self.assertEqual(self.run_cli("version", "1.30.7")[0], 0)
        self.assertEqual(json.loads(self.run_cli("version", "1.31.8", "--format", "sarif")[1])["version"], "2.1.0")
        self.assertTrue(self.run_cli("version", "1.31.8", "--format", "github")[1].startswith("::error"))
        self.assertIn("1.31.9", self.run_cli("version", "1.31.8", "--format", "markdown")[1])

    def test_bad_input(self):
        self.assertEqual(self.run_cli("version", "latest")[0], 2)

    def test_report_without_findings(self):
        self.assertIn("No exploitable", report.markdown([]))


if __name__ == "__main__":
    unittest.main()

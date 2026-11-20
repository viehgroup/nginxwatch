# nginxwatch

**Is my nginx exploitable?** Checks the nginx version, its configuration and your
distribution's security patches against every nginx.org advisory, and tells you
what actually applies to you.

```
$ nginxwatch local --binary /opt/ngx/1.31.8/sbin/nginx

⚠️  VULNERABLE  /opt/ngx/1.31.8/sbin/nginx  nginx 1.31.8
    3 exploitable with this configuration (2 critical); 7 affect
    this version but not this configuration; upgrade to 1.31.9
  critical CVE-2026-123007  CVSS 9.2
      Memory corruption in HTTP/2 flow control
      Remote code execution without authentication, in default
      configurations with HTTP/2 enabled
      Why: HTTP/2 is on (/opt/ngx/1.31.8/conf/nginx.conf:5)
      Until you upgrade: If you can't upgrade today, turning
      HTTP/2 off (remove `http2` from `listen`, or `http2 off;`)
      removes the condition this needs.
  critical CVE-2026-123633  CVSS 9.2
      Use-after-free in HTTP/2
      Remote code execution without authentication when HTTP/2 is
      used with proxying
      Why: HTTP/2 is on (/opt/ngx/1.31.8/conf/nginx.conf:5);
      proxying to a backend is on
      (/opt/ngx/1.31.8/conf/nginx.conf:10)
      Until you upgrade: If you can't upgrade today, turning
      HTTP/2 off removes the condition this needs.
  ...
    Fix: upgrade to nginx 1.31.9 or newer.
```

<sub>Real output from nginx 1.31.8, built from the official source, serving HTTPS
with HTTP/2 and a reverse proxy.</sub>

## Why

In November 2026 Wiz disclosed a batch of nginx vulnerabilities, two of them
unauthenticated remote code execution (CVE-2026-123007 and CVE-2026-123633, CVSS 9.2).
CVE-2026-123007 goes back to nginx 1.9.5 from 2015 and works on default configurations
with HTTP/2 enabled. nginx powers over 225 million websites.

"Am I affected?" isn't answered by the version number alone:

- **Configuration decides.** Each issue needs a particular feature: HTTP/2, HTTP/3,
  proxying, the resolver, the mail proxy, `alias` with `try_files`, and so on.
- **Fixes ship on two branches.** 1.30.7 (stable) and 1.31.9 (mainline). 1.30.7 is safe
  even though it's "older" than 1.31.8.
- **Distributions backport.** Ubuntu's nginx still says 1.24.0, but its package carries
  the November 2026 fixes. A version-only check calls it critically vulnerable; it isn't.

nginxwatch reads all three and gives a plain answer, with the line in your
configuration that makes each issue apply and the release that fixes it.

## Quick start

```
pip install git+https://github.com/viehgroup/nginxwatch

sudo nginxwatch
nginxwatch repo .
nginxwatch version 1.24.0 --config nginx.conf
nginxwatch url https://your-site.example
```

Check the nginx on this machine, a repository (configs, Dockerfiles, Compose and
Kubernetes files), a version with an optional config, or a server from outside.

No dependencies. It only runs `nginx -V` and `nginx -T` (read-only) and reads files.
`url` connects like a browser and reads the `Server` header and the protocols offered;
it never sends anything that could trigger a vulnerability. Use it on servers you run.

## What it checks

**On a server** (`nginxwatch`): the version and build options from `nginx -V`, the
configuration nginx actually loads from `nginx -T` (or from disk), and on Debian, Ubuntu
and RPM-based systems the package changelog, to credit backported fixes.

**In a repository** (`nginxwatch repo`): nginx configurations (following `include` the way
nginx does), and `nginx` images in Dockerfiles, Compose files and Kubernetes manifests.
`nginx:1.25-alpine` is resolved to the newest 1.25.x; tags like `latest` or `stable` are
listed as unpinned, since their version depends on when the image was pulled. Features the
repository doesn't show (templates, generated files) count as unknown, not off.

**From outside** (`nginxwatch url`): the version if the server shows it, and whether HTTP/2,
HTTP/3 and TLS 1.3 are on. Proxying and resolver use can only be seen on the server.

Each advisory ends up in one of four states:

| State | Meaning |
|---|---|
| exploitable | this version is affected and the configuration uses what the bug needs |
| possibly exploitable | affected version; the configuration couldn't be checked |
| doesn't apply here | affected version, but the needed feature is off or not compiled in |
| patched by distribution | the fix is in your distribution's package |

## GitHub Action

```yaml
on: [push, pull_request]
permissions:
  contents: read
jobs:
  nginxwatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: viehgroup/nginxwatch@main
        with:
          fail-on: high
```

Findings show as annotations and in the job summary. Pin the action to a commit SHA in
production workflows.

Options: `--format text|json|sarif|github|markdown`, `--fail-on critical|high|medium|low|never`,
`--all` (also list advisories that don't apply), `--summary FILE`. The exit code is `1` when
something at or above `--fail-on` (default `high`) is exploitable or possibly exploitable.

## Where the data comes from

All 78 advisories on [nginx.org/en/security_advisories.html](https://nginx.org/en/security_advisories.html)
(77 used; one is informational), retrieved 20 November 2026, with each one's vulnerable
range and fixed releases. `tools/advisories_raw.txt` is the snapshot and
`tools/build_data.py` rebuilds the data file from it. Severity is nginx.org's, raised to
critical where Wiz rated an issue CVSS 9.0 or above.

The conditions for the November 2026 batch follow Wiz's disclosure. For example, "HTTP/2 as
a proxy server" is read as HTTP/2 enabled together with `proxy_pass`, `grpc_pass` or
another `*_pass` directive. Conditions for older advisories are read from each advisory's
title (the mp4 module, WebDAV, SSI, and so on); ten older advisories apply to any setup.

## How it was tested

- **Real nginx builds** from the official source: 1.31.8 with HTTPS, HTTP/2 and a reverse
  proxy is reported exploitable to CVE-2026-123007, CVE-2026-123633 and CVE-2026-118899,
  with the lines responsible and 1.31.9 as the fix. 1.30.7 with the identical configuration
  is reported clean.
- **Ubuntu 24.04's nginx** (1.24.0-2ubuntu7.21): all 29 advisories that match its version
  number are credited as backported from the package changelog, so it's reported clean.
- **Include handling checked against nginx itself:** on h5bp/server-configs-nginx,
  nginxwatch loads exactly the 8 files that `nginx -T` lists (hidden files in `conf.d` are
  skipped, as nginx skips them).
- **Real repositories:** docker/awesome-compose, mailcow, nextcloud/docker, nginx-proxy, h5bp
  and docker-nginx-unprivileged scan without errors. nginx-proxy's pinned
  `nginx:1.31.6` is reported as needing 1.31.9; mailcow's 1.30.7 as clean.
- 23 unit tests on Python 3.9, 3.11 and 3.13. CI also runs it on Ubuntu's nginx package and
  runs the action, requiring it to fail on a vulnerable setup and pass a patched one.

```
python -m unittest discover -s . -p "test_*.py" -v
```

## Limits

- Conditions are read from configuration with rules, not from nginx's own parser. Unusual
  setups (configuration generated at start-up, Lua, templates) can hide a feature;
  nginxwatch then says "possibly" rather than "no".
- Backported fixes are recognised on Debian, Ubuntu and RPM-based systems from the package
  changelog. Other distributions and vendor builds (OpenResty, Tengine, NGINX Plus) are
  matched by version only.
- The advisory data is a snapshot. Rebuild it with `tools/build_data.py` when nginx.org
  publishes new advisories.
- The safest answer is still to upgrade: "doesn't apply here" today can change with a
  configuration edit tomorrow.

## Related

From the same team:
[ghostwatch](https://github.com/viehgroup/ghostwatch) finds hidden instructions for AI,
[bumpwatch](https://github.com/viehgroup/bumpwatch) catches hijacked dependency updates,
[extwatch](https://github.com/viehgroup/extwatch) catches backdoored editor extensions,
[agentscan](https://github.com/viehgroup/agentscan) finds risky AI agent configs, and
[slopwatch](https://github.com/viehgroup/slopwatch) blocks hallucinated packages.

## License

MIT. Built and maintained by the **VIEH Security Team**.

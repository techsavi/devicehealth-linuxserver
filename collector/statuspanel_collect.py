#!/usr/bin/env python3
"""
StatusPanel collector: health of a Linux web server.

Gathers system health, security/update state, web traffic per hosted site and
SSH/sudo login activity as one JSON document for the dashboard.

  * Python 3.8+ standard library only - nothing to pip install.
  * Runs as root (it reads auth logs, web server config, firewall and package state).
  * Normally invoked by the local poller over SSH: a restricted key whose forced
    command is `sudo -n /usr/bin/python3 <this file> --stdout`. Nothing is served
    from the server itself.

Usage:
  statuspanel_collect.py [--config /etc/statuspanel/config.json] (--stdout | --print)
"""

import argparse
import bisect
import calendar
import collections
import concurrent.futures
import fcntl
import glob
import gzip
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.0.0"
DEFAULT_CONFIG_PATH = "/etc/statuspanel/config.json"
SELF_UA = "statuspanel-selfcheck/"

DEFAULT_CONFIG = {
    # The main site whose sub folders are the individual websites.
    # Set the real values in /etc/statuspanel/config.json on the server.
    "main_site_root": "/var/www/example.com",
    "main_site_url": "https://example.com",
    # Every other directory in here is treated as a site that should NOT be public
    # unless it is listed in public_www_dirs.
    "www_root": "/var/www",
    "public_www_dirs": [],
    "ignore_www_dirs": [],
    # Sub folders of main_site_root that are assets rather than websites.
    "ignore_subfolders": [".well-known", "assets", "css", "js", "img", "images", "fonts", "static", "cgi-bin"],
    # Request paths never counted as traffic.
    "exclude_paths": [],

    "output_dir": "/var/lib/statuspanel/www",
    "state_dir": "/var/lib/statuspanel",
    "interval_seconds": 300,
    "lookback_days": 7,
    "history_days": 7,

    "access_log_globs": [
        "/var/log/caddy/*.log*",
        "/var/log/nginx/*access*.log*",
        "/var/log/apache2/*access*.log*",
        "/var/log/httpd/*access*log*",
    ],
    # Explicit log -> document root mappings, for logs the config parser cannot attribute.
    # e.g. {"/var/log/nginx/oldsite.log": "/var/www/oldsite"}
    "log_map": {},
    "caddy_conf": "/etc/caddy/Caddyfile",
    "nginx_conf_globs": ["/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*"],
    "apache_conf_globs": [
        "/etc/apache2/apache2.conf", "/etc/apache2/conf-enabled/*.conf", "/etc/apache2/sites-enabled/*",
        "/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d/*.conf",
    ],
    "auth_log_globs": ["/var/log/auth.log*", "/var/log/secure*"],

    "http_checks": True,
    "extra_urls": [],
    "check_other_vhosts": True,
    "tls_extra_domains": [],

    # apt: refresh package lists if older than this (0 disables; then rely on apt-daily).
    "apt_refresh_hours": 12,
    "dnf_cache_minutes": 60,

    "expected_public_ports": {"tcp": [22, 80, 443], "udp": [68, 443, 546, 41641]},   # udp 443 = HTTP/3, 41641 = Tailscale
    # Logins from these IPs/CIDRs are never flagged as unusual.
    "trusted_ips": [],
    # The account the local poller logs in as. Its routine logins are counted, not listed.
    "monitor_user": "spmon",

    "thresholds": {
        "disk_warn_pct": 80, "disk_crit_pct": 90,
        "inode_warn_pct": 80,
        "mem_warn_pct": 90, "swap_warn_pct": 50,
        "cpu_warn_pct": 85, "cpu24_warn_pct": 70,
        "load_per_core_warn": 1.5,
        "cert_warn_days": 14, "cert_crit_days": 5,
        "http_slow_ms": 2000,
        "failed_login_surge_factor": 3, "failed_login_surge_min": 200,
        "bruteforce_success_min_failures": 5,
        "wp_login_warn": 200,
        "update_grace_minutes": 60,     # pending security updates / reboot: alert only after this long
    },
}

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

# Combined / vhost_combined access log. The optional leading token is the vhost
# ("%v:%p" in Apache's vhost_combined, or "$host" if you add it to nginx log_format).
ACCESS_RE = re.compile(
    r'^(?:(?P<vhost>[^\s\[]+) )?(?P<ip>[0-9a-fA-F:.]+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<bytes>\d+|-)'
    r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?')

BOT_RE = re.compile(
    r'bot|crawl|spider|slurp|archiver|curl|wget|python|go-http|httpclient|java/|libwww|scrapy|'
    r'headless|phantom|monitor|uptime|pingdom|facebookexternalhit|preview|axios|node-fetch|okhttp|'
    r'zgrab|masscan|nmap|nuclei|censys|expanse|internet-measurement|scan|feedfetcher|statuspanel',
    re.I)

# On a static site, anything matching this is somebody probing for vulnerabilities.
SCAN_RE = re.compile(
    r'wp-login|wp-admin|wp-content|wp-includes|xmlrpc|\.php\b|\.asp|\.env\b|/\.git|\.svn|\.aws|\.ssh|'
    r'\.ds_store|phpmyadmin|myadmin|/pma\b|cgi-bin|/vendor/|phpunit|/actuator|/solr|/boaform|hnap1|'
    r'/owa/|autodiscover|/server-status|/shell|eval-stdin|/admin\b|/administrator|/login\b|/backup|'
    r'\.sql\b|\.bak\b|\.old\b|\.zip\b|\.tar|/console|/manager/html|/jenkins|cscoe|/remote/login|'
    r'/geoserver|/druid|/telescope|/debug|/config\.|/\.vscode|/etc/passwd|\.\./', re.I)

OK_METHODS = {"GET", "HEAD", "OPTIONS"}
DYNAMIC_METHODS = OK_METHODS | {"POST"}
PAGE_EXT_RE = re.compile(r'(/|\.html?|\.php|/[^./]*)$', re.I)
WP_LOGIN_RE = re.compile(r'/(wp-login\.php|xmlrpc\.php)$', re.I)

# End of standard security support. After this date only Ubuntu Pro (ESM) / Debian LTS
# keeps publishing fixes, so "no updates pending" stops meaning "up to date".
OS_SUPPORT_END = {
    ("ubuntu", "18.04"): "2023-05-31", ("ubuntu", "20.04"): "2025-05-31", ("ubuntu", "22.04"): "2027-06-01",
    ("ubuntu", "24.04"): "2029-05-31", ("ubuntu", "26.04"): "2031-05-31",
    ("debian", "10"): "2024-06-30", ("debian", "11"): "2026-08-31", ("debian", "12"): "2028-06-30",
    ("debian", "13"): "2030-06-30",
}
# Upstream PHP security support ends (php.net). Distros may backport fixes, ESM especially.
PHP_SUPPORT_END = {
    "7.4": "2022-11-28", "8.0": "2023-11-26", "8.1": "2025-12-31", "8.2": "2026-12-31",
    "8.3": "2027-12-31", "8.4": "2028-12-31", "8.5": "2029-12-31",
}
ROTATED_RE = re.compile(r'(?:[.-]\d+)?(?:\.gz)?$')

ISO_LINE_RE = re.compile(
    r'^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.\d+)?(Z|[+-]\d\d:?\d\d)?\s+\S+\s+'
    r'([\w\-./]+?)(?:\[(\d+)\])?:\s?(.*)$')
SYSLOG_LINE_RE = re.compile(
    r'^([A-Z][a-z]{2})\s+(\d{1,2})\s(\d\d):(\d\d):(\d\d)\s+\S+\s+([\w\-./]+?)(?:\[(\d+)\])?:\s?(.*)$')

SSH_ACCEPTED = re.compile(r'^Accepted (\S+) for (\S+) from (\S+) port \d+')
SSH_FAILED = re.compile(r'^Failed (\S+) for (invalid user )?(.*?) from (\S+) port \d+')
SSH_INVALID = re.compile(r'^Invalid user (.*?) from (\S+)')
SSH_PREAUTH = re.compile(r'^(?:Connection closed|Disconnected from) (?:by )?(?:authenticating|invalid) user (.*?) (\S+) port \d+ \[preauth\]')
SSH_PROBE = re.compile(r'^(?:Did not receive identification string from (\S+)|Unable to negotiate with (\S+)|'
                       r'banner exchange: Connection from (\S+)|kex_exchange_identification.*?from (\S+)|'
                       r'Bad protocol version identification .* from (\S+))')
SUDO_CMD = re.compile(r'^\s*(\S+) : .*COMMAND=(.*)$')
SUDO_FAIL = re.compile(r'^\s*(\S+) : (?:\d+ incorrect password attempts?|user NOT in sudoers|.*authentication failure)')
PAM_FAIL = re.compile(r'pam_unix\((sudo|su|su-l|login):auth\): authentication failure;.*?(?:logname=(\S*))?.*?user=(\S*)')
SU_FAIL = re.compile(r'^FAILED SU \(to (\S+)\) (\S+)')

REAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "vfat", "f2fs", "reiserfs", "jfs",
           "ntfs", "ntfs3", "exfat", "nfs", "nfs4", "cifs", "fuseblk"}


# ----------------------------------------------------------------------------- helpers

def run(cmd, timeout=30):
    """Run a command. Returns (returncode, stdout, stderr); returncode is None if it
    could not be run or timed out."""
    exe = shutil.which(cmd[0], path=os.environ.get("PATH", "") + ":/usr/sbin:/sbin:/usr/bin:/bin")
    if not exe:
        return None, "", "not found"
    env = dict(os.environ, LC_ALL="C", LANG="C")
    try:
        p = subprocess.run([exe] + list(cmd[1:]), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, universal_newlines=True, errors="replace", env=env)
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.SubprocessError) as e:
        return None, "", str(e)


def have(cmd):
    return shutil.which(cmd, path=os.environ.get("PATH", "") + ":/usr/sbin:/sbin") is not None


def read(path, default=None):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return default


def mtime(path):
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


def open_text(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def deep_merge(base, over):
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def norm(p):
    return os.path.normpath(p) if p else p


def under(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def parse_clf_time(s):
    # "03/Oct/2026:12:34:56 +0000"
    try:
        ts = calendar.timegm((int(s[7:11]), MONTHS[s[3:6]], int(s[0:2]),
                              int(s[12:14]), int(s[15:17]), int(s[18:20])))
        tz = s[21:26]
        off = int(tz[1:3]) * 3600 + int(tz[3:5]) * 60
        return ts - off if tz[0] == "+" else ts + off
    except (KeyError, ValueError, IndexError):
        return None


def iso_offset(tz):
    if not tz or tz == "Z":
        return 0
    tz = tz.replace(":", "")
    off = int(tz[1:3]) * 3600 + int(tz[3:5]) * 60
    return off if tz[0] == "+" else -off


def files_since(patterns, since):
    """Existing regular files matching any glob, modified after `since`, oldest first."""
    seen = {}
    for pat in patterns:
        for p in glob.glob(pat):
            try:
                st = os.stat(p)
            except OSError:
                continue
            if not os.path.isfile(p) or st.st_mtime < since:
                continue
            seen[os.path.realpath(p)] = st.st_mtime
    return [p for p, _ in sorted(seen.items(), key=lambda kv: kv[1])]


def make_ip_matcher(entries):
    nets = []
    for e in entries:
        try:
            nets.append(ipaddress.ip_network(e, strict=False))
        except ValueError:
            pass

    def match(ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in nets)
    return match


def top(counter, n=10):
    return [[k, v] for k, v in counter.most_common(n)]


# ----------------------------------------------------------------------------- web server config

def nginx_tokens(text):
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == "#":
            j = text.find("\n", i)
            i = n if j < 0 else j + 1
        elif c in "{};":
            yield c
            i += 1
        elif c in "\"'":
            j, buf = i + 1, []
            while j < n and text[j] != c:
                if text[j] == "\\" and j + 1 < n:
                    j += 1
                buf.append(text[j])
                j += 1
            yield "".join(buf)
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in "{};":
                j += 1
            yield text[i:j]
            i = j


def nginx_parse(text):
    """Parse nginx config into a tree of (name, args, children-or-None)."""
    root = []
    stack, cur = [root], []
    for t in nginx_tokens(text):
        if t == ";":
            if cur:
                stack[-1].append((cur[0], cur[1:], None))
            cur = []
        elif t == "{":
            node = (cur[0] if cur else "", cur[1:], [])
            stack[-1].append(node)
            stack.append(node[2])
            cur = []
        elif t == "}":
            if len(stack) > 1:
                stack.pop()
            cur = []
        else:
            cur.append(t)
    return root


def discover_nginx(cfg):
    text = None
    rc, out, _ = run(["nginx", "-T"], timeout=20)
    if rc == 0 and out.strip():
        text = out
    else:
        parts = []
        for pat in cfg["nginx_conf_globs"]:
            for p in sorted(glob.glob(pat)):
                if os.path.isfile(p):
                    parts.append(read(p, ""))
        text = "\n".join(parts)
    if not text.strip():
        return []
    tree = nginx_parse(text)

    default_logs = ["/var/log/nginx/access.log"]
    for name, args, children in tree:
        if name == "http" and children:
            logs = [a[0] for n, a, _ in children if n == "access_log" and a]
            if logs:
                default_logs = [] if logs == ["off"] else [l for l in logs if l != "off"]

    vhosts = []

    def walk(nodes):
        for name, args, children in nodes:
            if children is None:
                continue
            if name == "server":
                vhosts.append(nginx_server(children, default_logs))
            else:
                walk(children)
    walk(tree)
    return vhosts


def nginx_server(children, default_logs):
    vh = {"server": "nginx", "names": [], "listen": [], "root": None, "aliases": [],
          "logs": [], "default": False, "ssl": False}
    own_logs = None
    for name, args, sub in children:
        if name == "server_name":
            vh["names"] += [a.lower() for a in args]
        elif name == "listen":
            vh["listen"].append(" ".join(args))
            if "default_server" in args or "default" in args:
                vh["default"] = True
            if "ssl" in args or (args and args[0].split(":")[-1] == "443"):
                vh["ssl"] = True
        elif name == "root" and args:
            vh["root"] = norm(args[0])
        elif name == "access_log" and args:
            own_logs = own_logs or []
            if args[0] != "off":
                own_logs.append(args[0])
        elif name == "location" and sub is not None and args:
            if args[0] in ("~", "~*", "@") or args[0].startswith("@"):
                continue
            prefix = args[-1]
            for n2, a2, _ in sub:
                if n2 == "alias" and a2:
                    vh["aliases"].append((prefix, norm(a2[0])))
                elif n2 == "root" and a2:
                    vh["aliases"].append((prefix, norm(os.path.join(a2[0], prefix.lstrip("/")))))
    vh["logs"] = own_logs if own_logs is not None else list(default_logs)
    if not vh["listen"]:
        vh["listen"] = ["80"]
    return vh


def discover_apache(cfg):
    files = []
    for pat in cfg["apache_conf_globs"]:
        files += [p for p in sorted(glob.glob(pat)) if os.path.isfile(p)]
    if not files:
        return []
    server_root = "/etc/httpd" if os.path.isdir("/etc/httpd") else "/etc/apache2"
    log_dir = "/var/log/httpd" if os.path.isdir("/var/log/httpd") else "/var/log/apache2"
    envvars = read("/etc/apache2/envvars", "")
    m = re.search(r'APACHE_LOG_DIR=(\S+)', envvars)
    if m and "$" not in m.group(1):
        log_dir = m.group(1)

    def clean(v):
        v = v.strip().strip('"').strip("'")
        v = re.sub(r'\$\{APACHE_LOG_DIR\}', log_dir, v)
        return v

    def log_path(v):
        v = clean(v)
        if v.startswith("|"):
            return None
        return v if os.path.isabs(v) else os.path.join(server_root, v)

    vhosts, global_logs, cur = [], [], None
    for path in files:
        for raw in (read(path, "") or "").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r'<VirtualHost\s+([^>]+)>', line, re.I)
            if m:
                cur = {"server": "apache", "names": [], "listen": m.group(1).split(), "root": None,
                       "aliases": [], "logs": [], "default": False,
                       "ssl": any(a.endswith(":443") for a in m.group(1).split())}
                continue
            if re.match(r'</VirtualHost>', line, re.I):
                if cur is not None:
                    vhosts.append(cur)
                cur = None
                continue
            parts = line.split(None, 2)
            key = parts[0].lower()
            if cur is None:
                if key == "customlog" and len(parts) > 1:
                    lp = log_path(parts[1])
                    if lp:
                        global_logs.append(lp)
                continue
            if key == "servername" and len(parts) > 1:
                cur["names"].append(clean(parts[1]).split(":")[0].lower())
            elif key == "serveralias" and len(parts) > 1:
                cur["names"] += [clean(x).lower() for x in line.split()[1:]]
            elif key == "documentroot" and len(parts) > 1:
                cur["root"] = norm(clean(parts[1]))
            elif key == "customlog" and len(parts) > 1:
                lp = log_path(parts[1])
                if lp:
                    cur["logs"].append(lp)
            elif key == "alias" and len(parts) > 2:
                cur["aliases"].append((clean(parts[1]), norm(clean(parts[2]))))
            elif key == "sslengine" and len(parts) > 1 and parts[1].lower() == "on":
                cur["ssl"] = True
    for vh in vhosts:
        if not vh["logs"]:
            vh["logs"] = list(global_logs)
    if vhosts:
        vhosts[0]["default"] = True
    return vhosts


def has_index(folder):
    return any(os.path.isfile(os.path.join(folder, f)) for f in ("index.html", "index.htm", "index.php"))


def parse_caddyfile(text):
    """Minimal Caddyfile reader: a tree of (tokens, children-or-None), one node per line."""
    root, stack = [], []
    cur = root
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = re.sub(r'\s+#.*$', '', line)
        while line.startswith("}"):
            cur = stack.pop() if stack else root
            line = line[1:].strip()
        if not line:
            continue
        opens = line.endswith("{")
        toks = [t.strip('"') for t in re.findall(r'"[^"]*"|\S+', line[:-1] if opens else line)]
        node = (toks, [] if opens else None)
        cur.append(node)
        if opens:
            stack.append(cur)
            cur = node[1]
    return root


def discover_caddy(cfg):
    path = cfg.get("caddy_conf", "/etc/caddy/Caddyfile")
    text = read(path)
    if text is None:
        return []
    base = os.path.dirname(path)
    tree = parse_caddyfile(text)
    snippets = {t[0][1:-1]: kids for t, kids in tree if kids is not None and len(t) == 1 and t[0].startswith("(")}

    def expand(nodes, depth=0):
        out = []
        for toks, kids in nodes:
            if toks and toks[0] == "import" and len(toks) > 1 and depth < 10:
                name, args = toks[1], toks[2:]
                if name in snippets:
                    def sub(n):
                        t, k = n
                        t = [re.sub(r'\{args\[(\d+)\]\}', lambda m: args[int(m.group(1))] if int(m.group(1)) < len(args) else "", x) for x in t]
                        return (t, [sub(c) for c in k] if k is not None else None)
                    out += expand([sub(n) for n in snippets[name]], depth + 1)
                else:
                    for f in sorted(glob.glob(name if os.path.isabs(name) else os.path.join(base, name))):
                        out += expand(parse_caddyfile(read(f, "") or ""), depth + 1)
                continue
            out.append((toks, expand(kids, depth) if kids is not None else None))
        return out

    tree = expand(tree)
    vhosts = []
    for toks, kids in tree:
        if kids is None or not toks or toks[0].startswith("("):
            continue                      # global options block or snippet
        addrs = [a for a in re.split(r'[,\s]+', " ".join(toks)) if a]
        vh = {"server": "caddy", "names": [], "listen": addrs, "root": None, "aliases": [], "logs": [],
              "default": False, "ssl": not all(a.startswith("http://") for a in addrs)}
        for a in addrs:
            host = re.sub(r'^\w+://', '', a).split("/")[0]
            host = host.rsplit(":", 1)[0] if ":" in host and not host.endswith("]") else host
            if host in ("", "*"):
                vh["default"] = True
            else:
                vh["names"].append(host.lower())

        def walk(nodes, prefix=None):
            for t, k in nodes:
                if not t:
                    continue
                if t[0] == "root" and len(t) > 1:
                    if prefix is None:
                        vh["root"] = vh["root"] or norm(t[-1])
                    else:
                        vh["aliases"].append((prefix, norm(t[-1])))
                elif t[0] == "output" and len(t) > 2 and t[1] == "file":
                    vh["logs"].append(t[2])
                elif k is not None:
                    walk(k, t[1].rstrip("*") if t[0] in ("handle_path", "handle") and len(t) > 1 and t[1].startswith("/") else prefix)
        walk(kids)
        vhosts.append(vh)
    return vhosts


def parse_access_line(line):
    """One access-log line -> dict, from combined/vhost_combined (Apache, nginx) or
    Caddy's JSON access log. None if the line is neither."""
    if line.startswith("{"):
        try:
            d = json.loads(line)
            req = d["request"]
        except (ValueError, KeyError, TypeError):
            return None
        hdr = req.get("headers") or {}
        first = lambda k: (hdr.get(k) or [""])[0]
        try:
            ts = float(d.get("ts"))
        except (TypeError, ValueError):
            ts = None
        return {"ts": ts, "ip": req.get("client_ip") or req.get("remote_ip") or "",
                "method": req.get("method") or "", "target": req.get("uri") or "",
                "status": int(d.get("status") or 0), "bytes": int(d.get("size") or 0),
                "ua": first("User-Agent"), "ref": first("Referer"), "vhost": req.get("host")}
    m = ACCESS_RE.match(line)
    if not m:
        return None
    parts = m.group("req").split(" ")
    return {"ts": parse_clf_time(m.group("time")), "ip": m.group("ip"),
            "method": parts[0] if len(parts) >= 2 else "", "target": parts[1] if len(parts) >= 2 else "",
            "status": int(m.group("status")), "bytes": int(m.group("bytes")) if m.group("bytes") != "-" else 0,
            "ua": m.group("ua") or "", "ref": m.group("ref") or "", "vhost": m.group("vhost")}


# ----------------------------------------------------------------------------- traffic stats

class SiteStats(object):
    def __init__(self, days, keep_recent=False):
        self.days = days
        self.requests = 0
        self.daily_req = [0] * days
        self.daily_pv = [0] * days
        self.daily_vis = [set() for _ in range(days)]
        self.req24 = self.pv24 = self.bot24 = self.scan24 = self.bytes24 = self.ok24 = 0
        self.status24 = collections.Counter()
        self.hourly = [0] * 24
        self.ips24 = collections.Counter()
        self.ok_ips24 = set()
        self.human_ips24 = set()
        self.pages = collections.Counter()
        self.referrers = collections.Counter()
        self.notfound = collections.Counter()
        self.probes24 = 0
        self.wp_login24 = 0
        self.dynamic = False
        self.last_seen = None
        self.last_ok = None
        self.recent = collections.deque(maxlen=15) if keep_recent else None

    def add(self, r):
        d = r["day"]
        self.requests += 1
        self.daily_req[d] += 1
        if self.last_seen is None or r["ts"] > self.last_seen:
            self.last_seen = r["ts"]
        ok = 200 <= r["status"] < 300 or r["status"] == 304
        if ok and (self.last_ok is None or r["ts"] > self.last_ok):
            self.last_ok = r["ts"]
        human = r["cls"] == "human"
        if human and r["page"]:
            self.daily_vis[d].add(r["ip"])
            if ok:
                self.daily_pv[d] += 1
        if self.recent is not None:
            self.recent.append([r["ts"], r["ip"], r["method"], r["path"][:200], r["status"], r["ua"][:160]])
        if r["hour"] is None:
            return
        self.req24 += 1
        self.hourly[r["hour"]] += 1
        self.bytes24 += r["bytes"]
        self.status24["%dxx" % (r["status"] // 100)] += 1
        self.ips24[r["ip"]] += 1
        if r["cls"] == "bot":
            self.bot24 += 1
        elif r["cls"] == "scanner":
            self.scan24 += 1
        if ok:
            self.ok24 += 1
            self.ok_ips24.add(r["ip"])
        if human:
            if r["page"]:
                self.human_ips24.add(r["ip"])
            if ok and r["page"]:
                self.pv24 += 1
                self.pages[r["path"][:200]] += 1
            if r["ref_host"]:
                self.referrers[r["ref_host"]] += 1
        if r["status"] == 404:
            self.notfound[r["path"][:200]] += 1

    def to_json(self):
        out = {
            "requests_7d": self.requests,
            "requests_24h": self.req24,
            "pageviews_24h": self.pv24,
            "visitors_24h": len(self.human_ips24),
            "bot_requests_24h": self.bot24,
            "scanner_requests_24h": self.scan24,
            "bytes_24h": self.bytes24,
            "ok_requests_24h": self.ok24,
            "ok_ips_24h": len(self.ok_ips24),
            "status_24h": dict(self.status24),
            "hourly_requests": list(reversed(self.hourly)),
            "daily_requests": list(reversed(self.daily_req)),
            "daily_pageviews": list(reversed(self.daily_pv)),
            "daily_visitors": [len(s) for s in reversed(self.daily_vis)],
            "top_pages": top(self.pages, 10),
            "top_referrers": top(self.referrers, 10),
            "top_404": top(self.notfound, 10),
            "top_ips": top(self.ips24, 10),
            "probes_24h": self.probes24,
            "dynamic": self.dynamic,
            "wp_login_posts_24h": self.wp_login24,
            "last_seen": self.last_seen,
            "last_ok": self.last_ok,
        }
        if self.recent is not None:
            out["recent"] = sorted(self.recent, key=lambda r: r[0], reverse=True)
        return out


# ----------------------------------------------------------------------------- collector

class Collector(object):
    def __init__(self, cfg):
        self.cfg = cfg
        self.th = cfg["thresholds"]
        self.now = time.time()
        self.alerts = []
        self.errors = []
        self.state_path = os.path.join(cfg["state_dir"], "state.json")
        self.history_path = os.path.join(cfg["state_dir"], "history.json")
        try:
            with open(self.state_path) as f:
                self.state = json.load(f)
        except (OSError, ValueError):
            self.state = {}
        self.trusted = make_ip_matcher(cfg.get("trusted_ips", []))
        self.banned_ips = set()

    def alert(self, level, area, message, key=None):
        """key identifies the condition across runs (numbers in the message change,
        the key does not), so downstream consumers only notify when it is new."""
        if key is None:
            key = area.lower() + ":" + re.sub(r"\d+(?:\.\d+)?", "#", message.lower())
        if any(a["key"] == key for a in self.alerts):
            return                       # one alert per condition (e.g. repeated logins from one IP)
        self.alerts.append({"level": level, "area": area, "message": message, "key": key})

    def section(self, name, fn, *args):
        try:
            return fn(*args)
        except Exception as e:  # one broken probe must never take the whole panel down
            self.errors.append("%s: %s: %s" % (name, type(e).__name__, e))
            return None

    # ---------------------------------------------------------------- system

    def read_cpu(self):
        f = [int(x) for x in read("/proc/stat").splitlines()[0].split()[1:]]
        f += [0] * (8 - len(f))
        return {"total": sum(f[:8]), "idle": f[3] + f[4], "iowait": f[4], "steal": f[7]}

    def collect_system(self):
        s = {}
        osr = dict(re.findall(r'^(\w+)="?([^"\n]*)"?', read("/etc/os-release", ""), re.M))
        s["hostname"] = socket.getfqdn() or socket.gethostname()
        s["os"] = osr.get("PRETTY_NAME", sys.platform)
        s["kernel"] = os.uname().release
        up = float(read("/proc/uptime", "0").split()[0])
        s["uptime_seconds"] = up
        s["boot_time"] = self.now - up
        s["load"] = list(os.getloadavg())
        s["cpu_count"] = os.cpu_count() or 1

        cur = self.read_cpu()
        prev = self.state.get("cpu")
        if not prev or self.now - prev["t"] > 3600 or cur["total"] <= prev["v"]["total"]:
            time.sleep(1)
            prev = {"t": self.now - 1, "v": cur}
            cur = self.read_cpu()
        dt = float(cur["total"] - prev["v"]["total"]) or 1.0
        s["cpu_pct"] = round(100.0 * (1 - (cur["idle"] - prev["v"]["idle"]) / dt), 1)
        s["cpu_iowait_pct"] = round(100.0 * (cur["iowait"] - prev["v"]["iowait"]) / dt, 1)
        s["cpu_steal_pct"] = round(100.0 * (cur["steal"] - prev["v"]["steal"]) / dt, 1)
        s["cpu_window_seconds"] = round(time.time() - prev["t"])
        self.state["cpu"] = {"t": time.time(), "v": cur}

        mi = {}
        for line in read("/proc/meminfo", "").splitlines():
            k, _, v = line.partition(":")
            mi[k] = int(v.split()[0]) * 1024 if v.split() else 0
        total, avail = mi.get("MemTotal", 0), mi.get("MemAvailable", mi.get("MemFree", 0))
        s["memory"] = {"total": total, "available": avail, "used": total - avail,
                       "pct": round(100.0 * (total - avail) / total, 1) if total else 0,
                       "swap_total": mi.get("SwapTotal", 0),
                       "swap_used": mi.get("SwapTotal", 0) - mi.get("SwapFree", 0)}
        st = s["memory"]["swap_total"]
        s["memory"]["swap_pct"] = round(100.0 * s["memory"]["swap_used"] / st, 1) if st else 0

        disks, seen = [], {}
        for line in read("/proc/mounts", "").splitlines():
            parts = line.split()
            if len(parts) < 3 or parts[2] not in REAL_FS:
                continue
            dev, mnt = parts[0], parts[1].replace("\\040", " ")
            if mnt.startswith("/snap/") or (dev in seen and len(seen[dev]) <= len(mnt)):
                continue
            seen[dev] = mnt
        for dev, mnt in seen.items():
            try:
                v = os.statvfs(mnt)
            except OSError:
                continue
            used = (v.f_blocks - v.f_bfree) * v.f_frsize
            free = v.f_bavail * v.f_frsize
            if used + free <= 0:
                continue
            disks.append({"mount": mnt, "device": dev, "size": used + free, "used": used, "free": free,
                          "pct": round(100.0 * used / (used + free), 1),
                          "inode_pct": round(100.0 * (v.f_files - v.f_ffree) / v.f_files, 1) if v.f_files else None})
        s["disks"] = sorted(disks, key=lambda d: d["mount"])

        net, rates = {}, []
        for line in read("/proc/net/dev", "").splitlines()[2:]:
            name, _, rest = line.partition(":")
            name, f = name.strip(), rest.split()
            if name == "lo" or name.startswith(("veth", "docker", "br-")) or len(f) < 9:
                continue
            net[name] = [int(f[0]), int(f[8])]
        prev = self.state.get("net")
        if prev:
            dt = max(1.0, self.now - prev["t"])
            for name, (rx, tx) in net.items():
                p = prev["v"].get(name)
                if p and rx >= p[0] and tx >= p[1]:
                    rates.append({"iface": name, "rx_bps": round((rx - p[0]) / dt), "tx_bps": round((tx - p[1]) / dt)})
        s["network"] = rates
        self.state["net"] = {"t": self.now, "v": net}

        rc, out, _ = run(["ps", "-eo", "pid,user,rss,pcpu,comm", "--sort=-rss", "--no-headers"])
        procs = []
        for line in out.splitlines()[:6]:
            f = line.split(None, 4)
            if len(f) == 5:
                procs.append({"pid": int(f[0]), "user": f[1], "rss": int(f[2]) * 1024,
                              "cpu": float(f[3]), "cmd": f[4]})
        s["top_memory"] = procs

        rc, out, _ = run(["who"])
        s["logged_in"] = [l.split() for l in out.splitlines() if l.strip()] if rc == 0 else []

        s["services"], s["failed_units"] = self.collect_services()

        # alerts
        for d in s["disks"]:
            if d["pct"] >= self.th["disk_crit_pct"]:
                self.alert("critical", "System", "Disk %s is %.0f%% full" % (d["mount"], d["pct"]), "disk:" + d["mount"])
            elif d["pct"] >= self.th["disk_warn_pct"]:
                self.alert("warning", "System", "Disk %s is %.0f%% full" % (d["mount"], d["pct"]), "disk:" + d["mount"])
            if d["inode_pct"] and d["inode_pct"] >= self.th["inode_warn_pct"]:
                self.alert("warning", "System", "Disk %s inodes %.0f%% used" % (d["mount"], d["inode_pct"]))
        if s["memory"]["pct"] >= self.th["mem_warn_pct"]:
            self.alert("warning", "System", "Memory %.0f%% used" % s["memory"]["pct"])
        if s["memory"]["swap_pct"] >= self.th["swap_warn_pct"]:
            self.alert("warning", "System", "Swap %.0f%% used" % s["memory"]["swap_pct"])
        if s["cpu_pct"] >= self.th["cpu_warn_pct"]:
            self.alert("warning", "System", "CPU %.0f%% busy over the last %d s" % (s["cpu_pct"], s["cpu_window_seconds"]))
        if s["load"][1] / s["cpu_count"] >= self.th["load_per_core_warn"]:
            self.alert("warning", "System", "5-min load %.2f on %d cores" % (s["load"][1], s["cpu_count"]))
        for u in s["failed_units"]:
            self.alert("warning", "System", "systemd unit failed: %s" % u)
        return s

    def collect_services(self):
        rc, out, _ = run(["systemctl", "list-unit-files", "--no-legend", "--no-pager"])
        if rc is None:
            return [], []
        known = {l.split()[0] for l in out.splitlines() if l.strip()}
        wanted = ["caddy.service", "nginx.service", "apache2.service", "httpd.service", "ssh.service", "ssh.socket",
                  "sshd.service", "fail2ban.service", "ufw.service", "firewalld.service",
                  "unattended-upgrades.service", "cron.service", "crond.service",
                  "certbot.timer", "snap.certbot.renew.timer", "apt-daily-upgrade.timer"]
        units = [u for u in wanted if u in known]
        services = []
        if units:
            _, out, _ = run(["systemctl", "is-active"] + units)
            for u, st in zip(units, out.split()):
                services.append({"unit": u, "state": st})
        rc, out, _ = run(["systemctl", "--failed", "--no-legend", "--plain", "--no-pager"])
        failed = [l.split()[0] for l in out.splitlines() if l.strip()] if rc == 0 else []
        for sv in services:
            if sv["unit"].split(".")[0] in ("caddy", "nginx", "apache2", "httpd") and sv["state"] != "active":
                self.alert("critical", "Web", "Web server %s is %s" % (sv["unit"], sv["state"]))
        return services, failed

    # ---------------------------------------------------------------- updates

    def collect_updates(self):
        if have("apt-get"):
            u = self.collect_apt()
        elif have("dnf") or have("yum"):
            u = self.collect_dnf()
        else:
            u = {"manager": None}
        u["os_support"] = self.section("os support", self.collect_os_support)
        u["php"] = self.section("php", self.collect_php, (u["os_support"] or {}).get("esm"))
        return u

    def collect_os_support(self):
        osr = dict(re.findall(r'^(\w+)="?([^"\n]*)"?', read("/etc/os-release", ""), re.M))
        dist, ver = osr.get("ID", "").lower(), osr.get("VERSION_ID", "")
        out = {"release": osr.get("PRETTY_NAME"), "support_end": None, "eol": None, "esm": None}
        end = OS_SUPPORT_END.get((dist, ver))
        if end:
            out["support_end"] = calendar.timegm(time.strptime(end, "%Y-%m-%d"))
        if dist == "ubuntu" and have("pro"):
            rc, o, _ = run(["pro", "status", "--format", "json"], timeout=60)
            try:
                st = json.loads(o)
                infra = next((x for x in st.get("services", []) if x.get("name") == "esm-infra"), {})
                out["esm"] = bool(st.get("attached")) and infra.get("status") == "enabled"
            except ValueError:
                pass
        if out["support_end"]:
            out["eol"] = self.now > out["support_end"]
            day = time.strftime("%Y-%m-%d", time.gmtime(out["support_end"]))
            if out["eol"] and not out["esm"]:
                self.alert("critical", "Updates",
                           "%s reached end of standard support on %s and Ubuntu Pro/ESM is not active: "
                           "no security updates are being published for this server" % (out["release"], day), "os-eol")
            elif out["eol"]:
                self.alert("info", "Updates", "%s is past standard support (%s); security fixes come from ESM" % (out["release"], day), "os-esm")
            elif out["support_end"] - self.now < 180 * 86400:
                self.alert("warning", "Updates", "%s standard support ends on %s - plan an upgrade" % (out["release"], day), "os-eol-soon")
        return out

    def collect_php(self, esm):
        rc, o, _ = run(["php", "-r", "echo PHP_VERSION;"], timeout=15)
        if rc != 0 or not o.strip():
            return None
        full = o.strip()
        minor = ".".join(full.split(".")[:2])
        end = PHP_SUPPORT_END.get(minor)
        out = {"version": full, "support_end": calendar.timegm(time.strptime(end, "%Y-%m-%d")) if end else None}
        out["eol"] = bool(out["support_end"] and self.now > out["support_end"])
        if out["eol"]:
            self.alert("info" if esm else "warning", "Updates",
                       "PHP %s is past upstream security support (%s)%s" % (
                           full, end, "; Ubuntu ESM backports fixes" if esm else " - upgrade PHP and test the WordPress sites"),
                       "php-eol")
        return out

    def collect_apt(self):
        u = {"manager": "apt"}
        stamp = None
        for p in ("/var/lib/apt/periodic/update-success-stamp", "/var/cache/apt/pkgcache.bin", "/var/lib/apt/lists"):
            stamp = mtime(p)
            if stamp:
                break
        hours = self.cfg.get("apt_refresh_hours", 0)
        if hours and (not stamp or self.now - stamp > hours * 3600) and os.geteuid() == 0:
            rc, _, err = run(["apt-get", "update", "-qq"], timeout=240)
            if rc == 0:
                stamp = time.time()
            else:
                self.errors.append("apt-get update failed: %s" % err.strip()[:200])
        u["lists_updated"] = stamp

        _, out, _ = run(["apt", "list", "--upgradable"], timeout=120)
        pkgs = []
        for line in out.splitlines():
            m = re.match(r'^(\S+?)/(\S+)\s+(\S+)\s+(\S+)\s+\[upgradable from: ([^\]]+)\]', line)
            if m:
                pkgs.append({"name": m.group(1), "origin": m.group(2), "version": m.group(3),
                             "from": m.group(5), "security": "-security" in m.group(2)})
        u["upgradable"] = len(pkgs)
        u["security"] = sum(1 for p in pkgs if p["security"])
        u["packages"] = sorted(pkgs, key=lambda p: (not p["security"], p["name"]))[:200]

        u["reboot_required"] = os.path.exists("/var/run/reboot-required")
        u["reboot_since"] = mtime("/var/run/reboot-required")
        u["reboot_packages"] = (read("/var/run/reboot-required.pkgs", "") or "").split()

        # apt-config merges every apt.conf.d file, wherever the setting lives.
        rc, auto, _ = run(["apt-config", "dump", "APT::Periodic::Unattended-Upgrade"])
        if rc != 0:
            auto = read("/etc/apt/apt.conf.d/20auto-upgrades", "") or ""
        # A day count ("1"), or "always" to run on every apt-daily-upgrade timer tick; "0" is off.
        u["unattended_enabled"] = bool(re.search(r'Unattended-Upgrade\s+"(?!0*")[^"]+"', auto)) and have("unattended-upgrade")
        u["unattended_last_run"] = mtime("/var/log/unattended-upgrades/unattended-upgrades.log")

        hist = read("/var/log/apt/history.log", "") or ""
        last = None
        for block in hist.split("\n\n"):
            m = re.search(r'Start-Date:\s+(\d{4}-\d\d-\d\d)\s+(\d\d:\d\d:\d\d)', block)
            if m and re.search(r'^(Upgrade|Install):', block, re.M):
                last = time.mktime(time.strptime(m.group(1) + " " + m.group(2), "%Y-%m-%d %H:%M:%S"))
        u["last_upgrade"] = last
        u["update_failures"] = self.section("update failures", self.update_failures) or []
        self.update_alerts(u)
        return u

    def collect_dnf(self):
        cache = self.state.get("dnf_cache")
        if cache and self.now - cache["t"] < self.cfg["dnf_cache_minutes"] * 60:
            u = cache["v"]
        else:
            tool = "dnf" if have("dnf") else "yum"
            u = {"manager": tool}
            _, out, _ = run([tool, "-q", "updateinfo", "list", "--security"], timeout=180)
            sec = {l.split()[-1] for l in out.splitlines() if len(l.split()) >= 3}
            rc, out, _ = run([tool, "-q", "check-update"], timeout=180)
            pkgs = []
            for line in out.splitlines():
                f = line.split()
                if len(f) == 3 and "." in f[0] and not line.startswith(" "):
                    name = f[0].rsplit(".", 1)[0]
                    is_sec = any(s.startswith(name + "-") for s in sec)
                    pkgs.append({"name": name, "origin": f[2], "version": f[1], "from": "", "security": is_sec})
            u["upgradable"] = len(pkgs)
            u["security"] = sum(1 for p in pkgs if p["security"]) or len(sec)
            u["packages"] = sorted(pkgs, key=lambda p: (not p["security"], p["name"]))[:200]
            rc, _, _ = run(["needs-restarting", "-r"], timeout=60)
            u["reboot_required"] = rc == 1
            u["unattended_enabled"] = os.path.exists("/etc/dnf/automatic.conf")
            self.state["dnf_cache"] = {"t": self.now, "v": u}
        self.update_alerts(u)
        return u

    def patch_grace(self, u):
        """Remember when each pending security update (and the reboot flag) was first seen.
        Automatic updates usually install them within the grace period, so nothing is
        alerted until one has been outstanding for longer than that."""
        grace = float(self.th.get("update_grace_minutes", 60)) * 60
        seen = self.state.get("pending_since", {})
        current = {}
        for p in u.get("packages") or []:
            if p.get("security"):
                k = "%s=%s" % (p["name"], p["version"])
                current[k] = seen.get(k, self.now)
        if u.get("security") and not current:          # dnf may count advisories without package detail
            current["security"] = seen.get("security", self.now)
        if u.get("reboot_required"):
            current["reboot"] = seen.get("reboot", u.get("reboot_since") or self.now)
        self.state["pending_since"] = current
        sec = [t for k, t in current.items() if k != "reboot"]
        u["grace_minutes"] = round(grace / 60)
        u["security_first_seen"] = min(sec) if sec else None
        u["security_overdue"] = sum(1 for t in sec if self.now - t >= grace)
        u["reboot_first_seen"] = current.get("reboot")
        u["reboot_overdue"] = bool(current.get("reboot") and self.now - current["reboot"] >= grace)

    def update_failures(self):
        """Failed update runs: the last unattended-upgrades run, the last apt run, and
        packages dpkg left half-installed. A later successful apt run clears the first two."""
        fails = []
        hist = (read("/var/log/apt/history.log.1", "") or "") + "\n\n" + (read("/var/log/apt/history.log", "") or "")
        last_ok = None
        for block in [b for b in hist.split("\n\n") if "Start-Date:" in b]:
            m = re.search(r'Start-Date:\s+(\d{4}-\d\d-\d\d)\s+(\d\d:\d\d:\d\d)', block)
            ts = time.mktime(time.strptime(m.group(1) + " " + m.group(2), "%Y-%m-%d %H:%M:%S")) if m else None
            err = re.search(r'^Error:\s*(.+)$', block, re.M)
            if err:
                cmd = re.search(r'^Commandline:\s*(.+)$', block, re.M)
                fails = [f for f in fails if f["source"] != "apt"]
                fails.append({"source": "apt", "ts": ts, "message": err.group(1).strip()[:200],
                              "command": cmd.group(1).strip()[:120] if cmd else None})
            elif ts:
                last_ok = ts
                fails = [f for f in fails if f["source"] != "apt"]   # a later clean run supersedes it

        log = (read("/var/log/unattended-upgrades/unattended-upgrades.log.1", "") or "") + \
            (read("/var/log/unattended-upgrades/unattended-upgrades.log", "") or "")
        lines = log.splitlines()
        starts = [i for i, l in enumerate(lines) if "Starting unattended upgrades script" in l]
        if starts:
            run_lines = lines[starts[-1]:]
            errs = [l for l in run_lines if re.search(r'\b(ERROR|CRITICAL)\b|Package installation failed|dpkg returned an error', l)]
            stamps = [time.mktime(time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S"))
                      for m in (re.match(r'(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)', l) for l in run_lines) if m]
            ts, ended = (stamps[0], stamps[-1]) if stamps else (None, None)
            # unattended-upgrades writes its own apt history entries mid-run, so only a clean
            # apt run that started after this run ended counts as fixing it
            if errs and not (ended and last_ok and last_ok > ended):
                fails.append({"source": "unattended-upgrades", "ts": ts,
                              "message": re.sub(r'^\S+ \S+ (ERROR|CRITICAL)\s*', '', errs[0]).strip()[:200]})

        rc, out, _ = run(["dpkg", "--audit"], timeout=60)
        if rc is not None and out.strip():
            pkgs = re.findall(r'^ (\S+)\s', out, re.M)
            fails.append({"source": "dpkg", "ts": None, "packages": pkgs[:20],
                          "message": "packages left half-installed or unconfigured: %s" % (", ".join(pkgs[:8]) or out.strip()[:120])})
        return fails

    def update_alerts(self, u):
        self.patch_grace(u)
        grace = u["grace_minutes"]
        clock = lambda t: time.strftime("%H:%M UTC", time.gmtime(t))   # messages travel to tablets and MQTT
        if u.get("security_overdue"):
            since = u["security_first_seen"]
            self.alert("warning", "Updates", "%d security update(s) still not installed %d min after they were found (first seen %s)" % (
                u["security"], (self.now - since) // 60, clock(since)), "updates:security")
        elif u.get("upgradable") and not u.get("security"):
            self.alert("info", "Updates", "%d package update(s) available" % u["upgradable"])
        # Security updates (or a reboot) younger than the grace period raise nothing: automatic
        # updates normally install them in time, and the dashboard shows them as pending.
        if u.get("reboot_overdue"):
            self.alert("warning", "Updates", "Reboot required to finish installing updates (pending since %s)" % clock(u["reboot_first_seen"]),
                       "updates:reboot")
        for f in u.get("update_failures") or []:
            if f["source"] == "dpkg":
                self.alert("warning", "Updates", "Update incomplete: %s" % f["message"], "updates:broken")
            else:
                what = "Automatic update run" if f["source"] == "unattended-upgrades" else "Package update (%s)" % (f.get("command") or "apt")
                self.alert("warning", "Updates", "%s failed%s: %s" % (what, " at " + clock(f["ts"]) if f.get("ts") else "", f["message"]),
                           "updates:failed:" + f["source"])
        if u.get("lists_updated") and self.now - u["lists_updated"] > 3 * 86400:
            self.alert("warning", "Updates", "Package lists not refreshed for %d days" % ((self.now - u["lists_updated"]) // 86400))
        if u.get("unattended_enabled") is False:
            self.alert("info", "Updates", "Automatic security updates are not enabled")

    # ---------------------------------------------------------------- security posture

    def collect_security(self):
        sec = {"firewall": self.collect_firewall(), "ssh": self.collect_sshd(),
               "fail2ban": self.collect_fail2ban()}
        sec["ports"] = self.collect_ports(sec["ssh"])
        return sec

    def collect_firewall(self):
        if have("ufw"):
            rc, out, _ = run(["ufw", "status"])
            if rc is not None and rc != 0:
                return {"tool": "ufw", "active": None, "detail": ["ufw status needs root"]}
            if rc is not None:
                active = "Status: active" in out
                rules = [l for l in out.splitlines() if re.search(r'\b(ALLOW|DENY|REJECT|LIMIT)\b', l)]
                fw = {"tool": "ufw", "active": active, "rules": len(rules),
                      "detail": [re.sub(r'\s{2,}', "  ", l.strip()) for l in rules[:30]]}
                if not active:
                    self.alert("warning", "Security", "Firewall (ufw) is not active")
                return fw
        if have("firewall-cmd"):
            rc, out, _ = run(["firewall-cmd", "--state"])
            active = out.strip() == "running"
            _, svc, _ = run(["firewall-cmd", "--list-all"])
            if not active:
                self.alert("warning", "Security", "Firewall (firewalld) is not running")
            return {"tool": "firewalld", "active": active, "detail": [l.strip() for l in svc.splitlines()[:30]]}
        if have("nft"):
            rc, out, _ = run(["nft", "list", "ruleset"])
            active = rc == 0 and "hook input" in out
            if active:
                return {"tool": "nftables", "active": True, "rules": out.count("\n"), "detail": []}
        if have("iptables"):
            rc, out, _ = run(["iptables", "-S", "INPUT"])
            lines = out.splitlines()
            active = rc == 0 and (len(lines) > 1 or "-P INPUT DROP" in out)
            if not active:
                self.alert("warning", "Security", "No active firewall detected")
            return {"tool": "iptables", "active": active, "rules": max(0, len(lines) - 1), "detail": lines[:30]}
        self.alert("warning", "Security", "No firewall tooling detected")
        return {"tool": None, "active": False}

    def collect_sshd(self):
        rc, out, err = run(["sshd", "-T"], timeout=15)
        if rc != 0:
            return {"available": False, "error": (err or "").strip()[:200]}
        kv = {}
        for line in out.splitlines():
            k, _, v = line.partition(" ")
            kv.setdefault(k, v)
        ssh = {"available": True,
               "ports": [int(p) for p in re.findall(r'^port (\d+)', out, re.M)],
               "permit_root_login": kv.get("permitrootlogin"),
               "password_auth": kv.get("passwordauthentication"),
               "kbd_interactive_auth": kv.get("kbdinteractiveauthentication", kv.get("challengeresponseauthentication")),
               "pubkey_auth": kv.get("pubkeyauthentication"),
               "max_auth_tries": kv.get("maxauthtries")}
        if ssh["permit_root_login"] == "yes":
            self.alert("warning", "Security", "SSH allows root login with a password (PermitRootLogin yes)")
        if ssh["password_auth"] == "yes":
            self.alert("info", "Security", "SSH password authentication is enabled - consider key-only")
        return ssh

    def collect_fail2ban(self):
        rc, out, _ = run(["fail2ban-client", "status"], timeout=15)
        if rc != 0:
            # Querying the socket needs root; fall back to systemd for "is it running".
            _, st, _ = run(["systemctl", "is-active", "fail2ban"])
            return {"installed": have("fail2ban-client"), "running": st.strip() == "active", "jails": [],
                    "detail_unavailable": rc is not None}
        m = re.search(r'Jail list:\s*(.*)', out)
        jails = []
        for j in [x.strip() for x in (m.group(1) if m else "").split(",") if x.strip()]:
            _, o, _ = run(["fail2ban-client", "status", j], timeout=15)

            def num(label):
                mm = re.search(label + r':\s*(\d+)', o)
                return int(mm.group(1)) if mm else 0
            ips = re.search(r'Banned IP list:\s*(.*)', o or "")
            banned = ips.group(1).split() if ips else []
            self.banned_ips.update(banned)
            jails.append({"name": j, "currently_failed": num("Currently failed"), "total_failed": num("Total failed"),
                          "currently_banned": num("Currently banned"), "total_banned": num("Total banned"),
                          "banned_ips": banned[:50]})
        return {"installed": True, "running": True, "jails": jails}

    def collect_ports(self, ssh):
        rc, out, _ = run(["ss", "-H", "-tulnp"])
        if rc != 0:
            return []
        exp = self.cfg["expected_public_ports"]
        expected = {"tcp": set(exp.get("tcp", [])) | set(ssh.get("ports") or []), "udp": set(exp.get("udp", []))}
        ports = {}
        for line in out.splitlines():
            f = line.split()
            if len(f) < 5:
                continue
            proto = f[0]
            host, _, port = f[4].rpartition(":")
            # ss writes a scoped address as [fd7a:...:d767]%tailscale0: drop the scope, then the brackets.
            host = host.split("%")[0].strip("[]")
            try:
                port = int(port)
            except ValueError:
                continue
            # Public = reachable from the internet: bound to all interfaces or to a global
            # address. Loopback, private/VPC and Tailscale (100.64/10, fd7a::/48) are not.
            public = True
            if host not in ("0.0.0.0", "::", "*", ""):
                try:
                    public = ipaddress.ip_address(host).is_global
                except ValueError:
                    public = True
            procs = sorted(set(re.findall(r'\("([^"]+)"', line)))
            key = (proto, port)
            e = ports.setdefault(key, {"proto": proto, "port": port, "addresses": [], "process": [], "public": False})
            if host not in e["addresses"]:
                e["addresses"].append(host or "*")
            e["process"] = sorted(set(e["process"]) | set(procs))
            e["public"] = e["public"] or public
        result = sorted(ports.values(), key=lambda e: (not e["public"], e["proto"], e["port"]))
        for e in result:
            e["unexpected"] = e["public"] and e["port"] not in expected.get(e["proto"], set())
            if e["unexpected"]:
                self.alert("warning", "Security", "Unexpected public %s port %d (%s)" % (
                    e["proto"].upper(), e["port"], ", ".join(e["process"]) or "unknown process"),
                    "port:%s:%d" % (e["proto"], e["port"]))
        return result

    # ---------------------------------------------------------------- web traffic

    def collect_web(self):
        cfg = self.cfg
        days = int(cfg["lookback_days"])
        main_root = norm(cfg["main_site_root"])
        www_root = norm(cfg["www_root"])
        main_host = (urllib.parse.urlparse(cfg["main_site_url"]).hostname or "").lower()

        vhosts = []
        for fn in (discover_caddy, discover_nginx, discover_apache):
            got = self.section("web config (%s)" % fn.__name__, fn, cfg)
            vhosts += got or []
        for lp, root in cfg.get("log_map", {}).items():
            vhosts.append({"server": "manual", "names": [], "listen": [], "root": norm(root), "aliases": [],
                           "logs": [lp], "default": False, "ssl": False})
        for vh in vhosts:
            vh["aliases"].sort(key=lambda a: -len(a[0]))
            vh["is_main"] = bool(vh["root"] and under(vh["root"], main_root)) or main_host in vh["names"]

        main_vh = next((v for v in vhosts if v["is_main"] and v["root"]), None) or \
            {"server": "assumed", "names": [main_host], "listen": [], "root": main_root, "aliases": [],
             "logs": [], "default": False, "ssl": True, "is_main": True}

        def ordered(cands):
            return sorted(cands, key=lambda v: (not v["is_main"], not v["default"]))

        log_vhosts = collections.defaultdict(list)
        for vh in vhosts:
            for lp in vh["logs"]:
                log_vhosts[norm(lp)].append(vh)
        name_vhosts = {}
        for vh in vhosts:
            for n in vh["names"]:
                name_vhosts.setdefault(n, vh)

        try:
            subsites = sorted(d for d in os.listdir(main_root)
                              if os.path.isdir(os.path.join(main_root, d)) and not d.startswith(".")
                              and d not in cfg["ignore_subfolders"])
        except OSError:
            subsites = []
            self.errors.append("cannot list %s" % main_root)
        subset = set(subsites)
        main_name = os.path.relpath(main_root, www_root).split("/")[0] if under(main_root, www_root) else None
        try:
            other_dirs = sorted(d for d in os.listdir(www_root)
                                if os.path.isdir(os.path.join(www_root, d)) and d != main_name
                                and d not in cfg["ignore_www_dirs"])
        except OSError:
            other_dirs = []
        other_set = set(other_dirs)

        exists_cache = {}

        def exists(p):
            if p not in exists_cache:
                exists_cache[p] = os.path.exists(p)
            return exists_cache[p]

        def fs_for(vh, path, seg):
            for prefix, target in vh["aliases"]:
                if path.startswith(prefix):
                    rest = path[len(prefix):].lstrip("/").split("/")[0]
                    return os.path.join(target, rest) if rest else target
            if vh["root"]:
                return os.path.join(vh["root"], seg) if seg else vh["root"]
            return None

        def resolve(cands, path, seg):
            first = None
            for vh in cands:
                fs = fs_for(vh, path, seg)
                if fs is None:
                    continue
                if first is None:
                    first = (fs, vh)
                if len(cands) == 1 or exists(fs):
                    return fs, vh
            return first or (os.path.join(main_root, seg), main_vh)

        classify_cache = {}

        def classify(fs, vh):
            key = (fs, vh.get("root"))
            if key in classify_cache:
                return classify_cache[key]
            fs = norm(fs)
            if under(fs, main_root):
                comp = os.path.relpath(fs, main_root).split("/")[0]
                res = ("main", comp if comp in subset else "/")
            elif under(fs, www_root):
                rel = os.path.relpath(fs, www_root)
                res = ("other", rel.split("/")[0] if rel != "." else "(www root)")
            else:
                res = ("other", vh.get("root") or fs)
            classify_cache[key] = res
            return res

        dynamic_cache = {}

        def dynamic(kind, name):
            """True when the site's directory holds PHP (WordPress etc.), checked two levels deep."""
            key = (kind, name)
            if key not in dynamic_cache:
                if kind == "main":
                    base, depth = (main_root, 1) if name == "/" else (os.path.join(main_root, name), 2)
                else:
                    base, depth = (name if name.startswith("/") else os.path.join(www_root, name)), 2
                found = False
                stack = [(base, 0)]
                while stack and not found:
                    d, lvl = stack.pop()
                    try:
                        for e in os.scandir(d):
                            if e.is_file() and e.name.endswith(".php"):
                                found = True
                                break
                            if lvl + 1 < depth and e.is_dir(follow_symlinks=False) and not e.name.startswith("."):
                                stack.append((e.path, lvl + 1))
                    except OSError:
                        pass
                dynamic_cache[key] = found
            return dynamic_cache[key]

        main_stats = {n: SiteStats(days) for n in ["/"] + subsites}
        other_stats = {n: SiteStats(days, keep_recent=True) for n in other_dirs}
        total = SiteStats(days)
        scan = {"hits": 0, "ips": collections.Counter(), "paths": collections.Counter(),
                "hourly": [0] * 24, "methods": collections.Counter()}
        hourly_cls = {"human": [0] * 24, "bot": [0] * 24, "scanner": [0] * 24}
        our_hosts = set(name_vhosts) | {main_host}

        t0, t24 = self.now - days * 86400, self.now - 86400
        files = files_since(cfg["access_log_globs"], t0)
        files_info, bad_lines, shared_logs = [], 0, set()
        excl = tuple(cfg.get("exclude_paths", []))

        for path in files:
            base = norm(ROTATED_RE.sub("", path))
            cands = log_vhosts.get(base) or log_vhosts.get(norm(path))
            if not cands:
                cands = [main_vh]
            cands = ordered(cands)
            shared = len(cands) > 1
            parsed = 0
            try:
                fh = open_text(path)
            except OSError as e:
                self.errors.append("cannot read %s: %s" % (path, e))
                continue
            with fh:
                for line in fh:
                    e = parse_access_line(line)
                    if e is None:
                        bad_lines += 1
                        continue
                    ts = e["ts"]
                    if ts is None or ts < t0 or ts > self.now + 300:
                        continue
                    ua = e["ua"]
                    if ua.startswith(SELF_UA):
                        continue
                    method, target = e["method"], e["target"]
                    junk = not (method.isalpha() and method.isupper() and target)
                    if junk:
                        method, target = "", "/"
                    if "://" in target[:10]:
                        target = urllib.parse.urlsplit(target).path or "/"
                    upath = urllib.parse.unquote(target.split("?", 1)[0].split("#", 1)[0]) or "/"
                    if not upath.startswith("/"):
                        upath = "/" + upath
                    if excl and upath.startswith(excl):
                        continue
                    seg = upath.lstrip("/").split("/")[0]
                    if seg in (".", ".."):
                        seg = ""
                    status = e["status"]

                    vcands = cands
                    if shared and not e["vhost"]:
                        shared_logs.add(base)    # only approximate when the line doesn't name its host
                    if e["vhost"]:
                        h = e["vhost"].lower()
                        h = h.rsplit(":", 1)[0] if ":" in h and not h.endswith("]") else h
                        if h in name_vhosts:
                            vcands = [name_vhosts[h]]
                    fs, vh = resolve(vcands, upath, seg)
                    kind, name = classify(fs, vh)
                    dyn = dynamic(kind, name)
                    wp_login = dyn and method == "POST" and bool(WP_LOGIN_RE.search(upath))

                    if dyn:
                        # PHP/WordPress: .php and wp-* paths are normal. A probe is a miss on a
                        # suspicious path; a POST to wp-login/xmlrpc is (almost always) brute force.
                        is_scan = junk or wp_login or method not in DYNAMIC_METHODS or \
                            (status >= 400 and bool(SCAN_RE.search(upath)))
                    else:
                        is_scan = junk or method not in OK_METHODS or bool(SCAN_RE.search(upath))
                    if is_scan:
                        cls = "scanner"
                    elif ua in ("", "-") or BOT_RE.search(ua) or upath == "/robots.txt":
                        cls = "bot"
                    else:
                        cls = "human"
                    ref = e["ref"]
                    ref_host = None
                    if ref and ref != "-":
                        rh = (urllib.parse.urlsplit(ref).hostname or "").lower()
                        if rh and rh not in our_hosts and not rh.endswith("." + main_host):
                            ref_host = rh
                    hour = int((self.now - ts) // 3600) if ts >= t24 else None
                    if hour is not None and hour > 23:
                        hour = 23
                    r = {"ts": ts, "ip": e["ip"], "method": method or "(junk)", "path": upath,
                         "status": status, "bytes": e["bytes"], "ua": ua, "cls": cls,
                         "page": bool(PAGE_EXT_RE.search(upath)), "ref_host": ref_host,
                         "day": min(days - 1, max(0, int((self.now - ts) // 86400))), "hour": hour}

                    if kind == "main":
                        site_stats = main_stats[name]
                    else:
                        if name not in other_stats:
                            other_stats[name] = SiteStats(days, keep_recent=True)
                        site_stats = other_stats[name]
                    site_stats.add(r)
                    site_stats.dynamic = dyn
                    if wp_login and hour is not None:
                        site_stats.wp_login24 += 1
                    total.add(r)
                    if hour is not None:
                        hourly_cls[cls][hour] += 1
                        if seg in other_set and not (kind == "other" and name == seg):
                            other_stats[seg].probes24 += 1
                        if cls == "scanner":
                            scan["hits"] += 1
                            scan["ips"][r["ip"]] += 1
                            scan["paths"][upath[:120]] += 1
                            scan["hourly"][hour] += 1
                            scan["methods"][method or "(junk)"] += 1
                    parsed += 1
            files_info.append({"path": path, "lines": parsed, "bytes": os.path.getsize(path)})

        checks = self.http_checks(main_vh, subsites, vhosts, other_dirs, www_root) if cfg["http_checks"] else {}

        sites = []
        for n in ["/"] + subsites:
            url = cfg["main_site_url"].rstrip("/") + ("/" if n == "/" else "/%s/" % n)
            st = main_stats[n].to_json()
            st["dynamic"] = dynamic("main", n)
            path = main_root if n == "/" else os.path.join(main_root, n)
            sites.append({"name": n, "path": path, "url": url, "check": checks.get(url), "stats": st,
                          "has_index": n == "/" or has_index(path)})
            c = checks.get(url)
            if c and c.get("status") in (401, 403):
                self.alert("warning", "Web", "%s answers %s - no index page or access restricted? Add the folder to "
                           "ignore_subfolders if it is not a site" % (url, c["status"]), "restricted:" + url)
            elif c and not c["ok"]:
                self.alert("critical", "Web", "%s is not responding correctly (%s)" % (url, c.get("error") or c.get("status")), "down:" + url)
            elif c and c["ms"] > self.th["http_slow_ms"]:
                self.alert("warning", "Web", "%s responded slowly (%d ms)" % (url, c["ms"]), "slow:" + url)

        # Extra watched URLs (e.g. App Store support/privacy pages)
        for c in checks.values():
            if c["kind"] != "extra":
                continue
            if c.get("status") in (401, 403):
                self.alert("warning", "Web", "%s answers %s (restricted?)" % (c["url"], c["status"]), "restricted:" + c["url"])
            elif not c["ok"]:
                self.alert("critical", "Web", "%s is not responding correctly (%s)" % (c["url"], c.get("error") or c.get("status")), "down:" + c["url"])

        others = []
        public = set(cfg.get("public_www_dirs", []))
        for n in sorted(other_stats):
            st = other_stats[n].to_json()
            st["dynamic"] = dynamic("other", n)
            path = os.path.join(www_root, n) if not n.startswith("/") else n
            exposure = []
            for vh in vhosts:
                label = ", ".join(vh["names"][:4]) or "(no server_name)"
                if vh["root"] and under(vh["root"], path):
                    exposure.append({"type": "vhost", "via": label, "server": vh["server"], "default": vh["default"]})
                elif vh["root"] and under(path, vh["root"]) and vh["root"] != path:
                    exposure.append({"type": "path", "via": label, "server": vh["server"],
                                     "url_path": "/" + os.path.relpath(path, vh["root"]) + "/"})
                for prefix, target in vh["aliases"]:
                    if under(target, path) or under(path, target):
                        exposure.append({"type": "alias", "via": label, "server": vh["server"], "url_path": prefix})
            ext_checks = [c for c in checks.values() if c.get("site") == n]
            if st["wp_login_posts_24h"] >= self.th["wp_login_warn"]:
                self.alert("warning", "Hidden sites" if n not in public else "Web",
                           "WordPress login brute force on %s: %d POSTs to wp-login/xmlrpc in 24 h" % (path, st["wp_login_posts_24h"]),
                           "wp-bruteforce:" + path)
            intended = n in public
            flagged = not intended and (st["ok_requests_24h"] > 0 or any(c["ok"] for c in ext_checks))
            others.append({"name": n, "path": path, "exists": os.path.isdir(path), "intended_public": intended,
                           "exposure": exposure, "checks": ext_checks, "flagged": flagged, "stats": st})
            if flagged and st["ok_requests_24h"]:
                self.alert("warning", "Hidden sites",
                           "%s served %d successful request(s) to %d IP(s) in the last 24 h" % (
                               path, st["ok_requests_24h"], st["ok_ips_24h"]), "hidden-traffic:" + path)
            for c in ext_checks:
                if c["ok"] and not intended:
                    self.alert("warning", "Hidden sites", "%s answers publicly at %s (HTTP %s)" % (path, c["url"], c["status"]),
                               "hidden-public:" + c["url"])

        tot = total.to_json()
        notes = []
        if shared_logs:
            notes.append("These logs are shared by several virtual hosts, so traffic is attributed by matching the "
                         "request path to files on disk: %s. For exact attribution give each vhost its own "
                         "access_log, or prefix the log format with the host name." % ", ".join(sorted(shared_logs)))
        if not files:
            notes.append("No access logs found (looked at %s)." % ", ".join(cfg["access_log_globs"]))
        if bad_lines:
            notes.append("%d log line(s) were not in combined log format and were skipped." % bad_lines)

        return {
            "main": {"root": main_root, "url": cfg["main_site_url"], "sites": sites},
            "others": others,
            "totals": {k: tot[k] for k in ("requests_24h", "requests_7d", "pageviews_24h", "visitors_24h",
                                            "bot_requests_24h", "scanner_requests_24h", "bytes_24h", "status_24h",
                                            "daily_requests", "daily_pageviews", "daily_visitors", "top_ips")},
            "hourly_by_class": {k: list(reversed(v)) for k, v in hourly_cls.items()},
            "scanners": {"hits_24h": scan["hits"], "top_ips": top(scan["ips"], 10), "top_paths": top(scan["paths"], 15),
                         "methods": top(scan["methods"], 8), "hourly": list(reversed(scan["hourly"]))},
            "vhosts": [{"server": v["server"], "names": v["names"][:6], "root": v["root"], "listen": v["listen"][:4],
                        "logs": v["logs"], "default": v["default"], "ssl": v["ssl"]} for v in vhosts],
            "log_files": files_info,
            "notes": notes,
            "_tls_names": sorted({n for v in vhosts if v["ssl"] for n in v["names"]} | {main_host}),
        }

    def http_checks(self, main_vh, subsites, vhosts, other_dirs, www_root):
        cfg = self.cfg
        base = cfg["main_site_url"].rstrip("/")
        # Only folders with a front page are "sites"; others (e.g. shared report files) are
        # reached by direct links, so checking their folder URL would only report a false 404.
        main_root = norm(cfg["main_site_root"])
        jobs = [(base + "/", "main", "/")] + [(base + "/%s/" % s, "main", s) for s in subsites
                                              if has_index(os.path.join(main_root, s))]
        if cfg.get("check_other_vhosts"):
            seen = set()
            for vh in vhosts:
                if vh["is_main"] or not vh["root"] or not under(vh["root"], www_root) or vh["root"] == www_root:
                    continue
                site = os.path.relpath(vh["root"], www_root).split("/")[0]
                for n in vh["names"]:
                    if n in seen or n in ("_", "localhost") or "*" in n or n.startswith("~") or re.match(r'^[\d.:]+$', n):
                        continue
                    seen.add(n)
                    jobs.append((("https://" if vh["ssl"] else "http://") + n + "/", "other", site))
        jobs += [(u, "extra", None) for u in cfg.get("extra_urls", [])]
        jobs = jobs[:40]

        def check(job):
            url, kind, site = job
            res = {"url": url, "kind": kind, "site": site, "ok": False, "status": None, "ms": None, "error": None}
            req = urllib.request.Request(url, headers={"User-Agent": SELF_UA + VERSION})
            t = time.time()
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    resp.read(65536)
                    res["status"] = resp.status
                    res["final_url"] = resp.geturl()
            except urllib.error.HTTPError as e:
                res["status"] = e.code
            except Exception as e:
                res["error"] = str(getattr(e, "reason", e))[:200]
            res["ms"] = int((time.time() - t) * 1000)
            res["ok"] = res["status"] is not None and 200 <= res["status"] < 400
            return res

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            return {r["url"]: r for r in ex.map(check, jobs)}

    # ---------------------------------------------------------------- TLS

    def collect_tls(self, names):
        names = [n for n in names if n and n != "_" and "*" not in n and n != "localhost"
                 and not re.match(r'^[\d.:]+$', n)]
        names = sorted(set(names) | set(self.cfg.get("tls_extra_domains", [])))[:25]

        def check(name):
            r = {"domain": name, "valid": False, "expires": None, "days_left": None, "issuer": None, "error": None}
            for host in ("127.0.0.1", name):
                try:
                    ctx = ssl.create_default_context()
                    with socket.create_connection((host, 443), timeout=8) as sock:
                        with ctx.wrap_socket(sock, server_hostname=name) as ss:
                            cert = ss.getpeercert()
                    exp = ssl.cert_time_to_seconds(cert["notAfter"])
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    r.update(valid=True, expires=exp, days_left=round((exp - self.now) / 86400, 1),
                             issuer=issuer.get("organizationName") or issuer.get("commonName"), error=None)
                    return r
                except ssl.SSLCertVerificationError as e:
                    r["error"] = e.verify_message or str(e)
                    return r
                except Exception as e:
                    r["error"] = str(e)[:200]
            return r

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            results = list(ex.map(check, names))
        for r in results:
            if r["valid"]:
                if r["days_left"] < self.th["cert_crit_days"]:
                    self.alert("critical", "TLS", "Certificate for %s expires in %.0f days" % (r["domain"], r["days_left"]), "cert:" + r["domain"])
                elif r["days_left"] < self.th["cert_warn_days"]:
                    self.alert("warning", "TLS", "Certificate for %s expires in %.0f days" % (r["domain"], r["days_left"]), "cert:" + r["domain"])
            elif r["error"] and "refused" not in r["error"].lower():
                self.alert("warning", "TLS", "Certificate problem for %s: %s" % (r["domain"], r["error"]), "cert-error:" + r["domain"])
        return results

    # ---------------------------------------------------------------- logins

    def auth_lines(self, since):
        files = files_since(self.cfg["auth_log_globs"], since)
        if files:
            for p in files:
                try:
                    with open_text(p) as fh:
                        for line in fh:
                            yield line
                except OSError as e:
                    self.errors.append("cannot read %s: %s" % (p, e))
            return
        rc, out, _ = run(["journalctl", "--no-pager", "-q", "-o", "short-iso",
                          "--since", "@%d" % int(since), "-t", "sshd", "-t", "sshd-session",
                          "-t", "sudo", "-t", "su", "-t", "login"], timeout=120)
        if rc is None:
            self.errors.append("no auth log files and journalctl unavailable")
        for line in out.splitlines():
            yield line

    def parse_auth_time(self, line):
        m = ISO_LINE_RE.match(line)
        if m:
            g = m.groups()
            ts = calendar.timegm(tuple(int(x) for x in g[:6])) - iso_offset(g[6])
            return ts, g[7], g[8], g[9]
        m = SYSLOG_LINE_RE.match(line)
        if m:
            g = m.groups()
            lt = time.localtime(self.now)
            ts = time.mktime((lt.tm_year, MONTHS.get(g[0], 1), int(g[1]), int(g[2]), int(g[3]), int(g[4]), 0, 0, -1))
            if ts > self.now + 86400:
                ts = time.mktime((lt.tm_year - 1, MONTHS.get(g[0], 1), int(g[1]), int(g[2]), int(g[3]), int(g[4]), 0, 0, -1))
            return ts, g[5], g[6], g[7]
        return None

    def collect_logins(self):
        days = int(self.cfg["lookback_days"])
        t0, t24 = self.now - days * 86400, self.now - 86400
        failures = []             # (ts, ip, user, invalid)
        accepted = []             # (ts, user, ip, method)
        probes = collections.Counter()
        sudo_fail, sudo_cmds, su_fail = [], 0, []
        pending = {}              # sshd connection -> (ts, ip, user, invalid) not yet counted
        has_failed = set()

        for line in self.auth_lines(t0):
            p = self.parse_auth_time(line)
            if not p:
                continue
            ts, prog, pid, msg = p
            if ts < t0:
                continue
            if prog in ("sshd", "sshd-session"):
                m = SSH_FAILED.match(msg)
                if m:
                    failures.append((ts, m.group(4), m.group(3), bool(m.group(2))))
                    has_failed.add((pid, m.group(4)))
                    pending.pop((pid, m.group(4)), None)
                    continue
                m = SSH_ACCEPTED.match(msg)
                if m:
                    accepted.append((ts, m.group(2), m.group(3), m.group(1)))
                    pending.pop((pid, m.group(3)), None)
                    continue
                m = SSH_INVALID.match(msg)
                if m:
                    key = (pid, m.group(2))
                    if key not in has_failed:
                        pending[key] = (ts, m.group(2), m.group(1), True)
                    continue
                m = SSH_PREAUTH.match(msg)
                if m:
                    key = (pid, m.group(2))
                    if key not in has_failed and key not in pending:
                        pending[key] = (ts, m.group(2), m.group(1), False)
                    continue
                m = SSH_PROBE.match(msg)
                if m:
                    ip = next((g for g in m.groups() if g), None)
                    if ip and ts >= t24:
                        probes[ip] += 1
            elif prog == "sudo":
                m = SUDO_FAIL.match(msg)
                if m:
                    sudo_fail.append({"ts": ts, "user": m.group(1), "message": msg.strip()[:200]})
                    if "NOT in sudoers" in msg and ts >= t24:
                        self.alert("warning", "Logins", "User %s tried to use sudo but is not in sudoers" % m.group(1))
                elif SUDO_CMD.match(msg):
                    if ts >= t24 and SUDO_CMD.match(msg).group(1) != self.cfg.get("monitor_user"):
                        sudo_cmds += 1
            elif prog in ("su", "login"):
                if SU_FAIL.match(msg) or PAM_FAIL.search(msg):
                    su_fail.append({"ts": ts, "message": msg.strip()[:200]})
        failures += list(pending.values())
        failures.sort()

        f24 = [f for f in failures if f[0] >= t24]
        daily = [0] * days
        for f in failures:
            daily[min(days - 1, int((self.now - f[0]) // 86400))] += 1
        daily = list(reversed(daily))
        hourly = [0] * 24
        for f in f24:
            hourly[min(23, int((self.now - f[0]) // 3600))] += 1
        hourly = list(reversed(hourly))

        fail_by_ip_all = collections.Counter(f[1] for f in failures)
        ip24 = collections.Counter(f[1] for f in f24)
        users24 = collections.Counter(f[2] for f in f24)
        last_seen, users_by_ip = {}, collections.defaultdict(collections.Counter)
        for f in f24:
            last_seen[f[1]] = f[0]
            users_by_ip[f[1]][f[2]] += 1
        attackers = [{"ip": ip, "count": c, "last": last_seen[ip], "users": [u for u, _ in users_by_ip[ip].most_common(5)],
                      "banned": ip in self.banned_ips} for ip, c in ip24.most_common(15)]

        # Successful logins: flag new IPs, root, and success after brute force.
        known = self.state.setdefault("known_login_ips", {})
        first_run = "baseline_ts" not in self.state
        baseline = self.state.setdefault("baseline_ts", self.now)
        logins, monitor = [], {"logins_24h": 0, "last": None, "ips": []}
        monitor_user = self.cfg.get("monitor_user")
        fail_times = collections.defaultdict(list)
        for f in failures:
            fail_times[f[1]].append(f[0])
        for ts, user, ip, method in accepted:
            if ip not in known:
                known[ip] = baseline if first_run else ts
            prior_fail = bisect.bisect_left(fail_times.get(ip, []), ts)
            trusted = self.trusted(ip)
            flags = []
            if not trusted:
                if known[ip] > baseline and self.now - known[ip] < 7 * 86400:
                    flags.append("new-ip")
                if user == "root":
                    flags.append("root")
                if method in ("password", "keyboard-interactive/pam"):
                    flags.append("password")
                if prior_fail >= self.th["bruteforce_success_min_failures"]:
                    flags.append("after-failures")
            if user == monitor_user and not ({"new-ip", "after-failures"} & set(flags)):
                # The local poller logging in on schedule - count it, don't list it.
                monitor["last"] = ts
                monitor["logins_24h"] += ts >= t24
                if ip not in monitor["ips"]:
                    monitor["ips"].append(ip)
                continue
            logins.append({"ts": ts, "user": user, "ip": ip, "method": method, "flags": flags,
                           "prior_failures": prior_fail, "trusted": trusted})
            if ts >= t24:
                if "after-failures" in flags:
                    self.alert("critical", "Logins", "Successful SSH login as %s from %s after %d failed attempts" % (user, ip, prior_fail),
                               "login-after-failures:%s:%s" % (user, ip))
                elif "new-ip" in flags:
                    self.alert("warning", "Logins", "SSH login as %s from a new IP address %s" % (user, ip), "login-new-ip:%s:%s" % (user, ip))
                if "root" in flags:
                    self.alert("warning", "Logins", "Direct root SSH login from %s" % ip, "login-root:" + ip)

        # Baseline: average over the earlier days that have any data at all (a new server
        # has none), and only judge a surge once there are at least 3 such days.
        prev_days = [n for n in daily[:-1] if n]
        avg_prev = (sum(prev_days) / float(len(prev_days))) if prev_days else 0
        surge = len(prev_days) >= 3 and len(f24) >= self.th["failed_login_surge_min"] and \
            len(f24) > self.th["failed_login_surge_factor"] * avg_prev
        if surge:
            self.alert("warning", "Logins", "Failed SSH logins surging: %d in 24 h vs %.0f/day average" % (len(f24), avg_prev), "login-surge")
        sf24 = [s for s in sudo_fail if s["ts"] >= t24]
        if sf24:
            self.alert("warning", "Logins", "%d failed sudo attempt(s) in the last 24 h" % len(sf24), "sudo-failures")

        return {
            "failed_24h": len(f24), "failed_7d": len(failures),
            "invalid_user_24h": sum(1 for f in f24 if f[3]),
            "unique_ips_24h": len(ip24), "avg_failed_per_day": round(avg_prev, 1), "surge": surge,
            "daily_failed": daily, "hourly_failed": hourly,
            "top_attackers": attackers, "top_usernames": top(users24, 12),
            "repeat_offenders_7d": top(fail_by_ip_all, 10),
            "ssh_probes_24h": sum(probes.values()), "ssh_probe_ips": top(probes, 10),
            "successful": list(reversed(logins))[:30],
            "sudo_failures": list(reversed(sudo_fail))[:15], "sudo_commands_24h": sudo_cmds,
            "su_failures": list(reversed(su_fail))[:10],
            "monitor": monitor,
        }

    # ---------------------------------------------------------------- history

    def update_history(self, system, web):
        try:
            with open(self.history_path) as f:
                hist = json.load(f)
        except (OSError, ValueError):
            hist = []
        root_disk = next((d["pct"] for d in system.get("disks", []) if d["mount"] == "/"), None) if system else None
        rx = sum(n["rx_bps"] for n in system.get("network", [])) if system else 0
        tx = sum(n["tx_bps"] for n in system.get("network", [])) if system else 0
        if system:
            hist.append([round(self.now), system["cpu_pct"], system["memory"]["pct"], round(system["load"][0], 2),
                         root_disk, rx, tx])
        cutoff = self.now - self.cfg["history_days"] * 86400
        hist = [h for h in hist if h[0] >= cutoff]
        tmp = self.history_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(hist, f, separators=(",", ":"))
        os.replace(tmp, self.history_path)

        day = [h for h in hist if h[0] >= self.now - 86400]
        def avg(rows, i):
            vals = [r[i] for r in rows if r[i] is not None]
            return round(sum(vals) / len(vals), 1) if vals else None
        cpu24 = avg(day, 1)
        if cpu24 is not None and len(day) > 12 and cpu24 >= self.th["cpu24_warn_pct"]:
            self.alert("warning", "System", "CPU averaged %.0f%% over the last 24 h" % cpu24)
        return {
            "columns": ["t", "cpu", "mem", "load1", "disk_root", "rx_bps", "tx_bps"],
            "points": day,
            "cpu_avg_24h": cpu24, "cpu_max_24h": max((r[1] for r in day), default=None),
            "cpu_avg_7d": avg(hist, 1), "mem_avg_24h": avg(day, 2),
            "samples_7d": len(hist),
        }

    # ---------------------------------------------------------------- main

    def collect(self):
        t = time.time()
        system = self.section("system", self.collect_system)
        security = self.section("security", self.collect_security) or {}
        updates = self.section("updates", self.collect_updates)
        web = self.section("web", self.collect_web)
        tls = self.section("tls", self.collect_tls, (web or {}).pop("_tls_names", [])) if web else []
        logins = self.section("logins", self.collect_logins)
        history = self.section("history", self.update_history, system or {}, web or {})

        if logins and logins["failed_24h"] and not (security.get("fail2ban") or {}).get("running"):
            self.alert("info", "Security", "fail2ban is not running; %d failed SSH logins in 24 h went unblocked" % logins["failed_24h"])
        for e in self.errors:
            self.alert("info", "Collector", e, "collector-error:" + e.split(":")[0])

        order = {"critical": 0, "warning": 1, "info": 2}
        self.alerts.sort(key=lambda a: order.get(a["level"], 3))
        overall = "ok"
        if any(a["level"] == "critical" for a in self.alerts):
            overall = "critical"
        elif any(a["level"] == "warning" for a in self.alerts):
            overall = "warning"

        return {
            "version": VERSION,
            "generated_at": round(self.now),
            "interval_seconds": self.cfg["interval_seconds"],
            "duration_ms": int((time.time() - t) * 1000),
            "overall": overall,
            "alerts": self.alerts,
            "system": system,
            "history": history,
            "updates": updates,
            "security": security,
            "web": web,
            "tls": tls,
            "logins": logins,
            "errors": self.errors,
        }

    def save_state(self):
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.state, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.state_path)


def main():
    ap = argparse.ArgumentParser(description="Collect server status for the StatusPanel dashboard.")
    ap.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    ap.add_argument("--print", action="store_true", help="print indented status JSON to stdout instead of writing it")
    ap.add_argument("--stdout", action="store_true", help="write compact status JSON to stdout (used over SSH)")
    args = ap.parse_args()

    cfg = DEFAULT_CONFIG
    if os.path.exists(args.config):
        with open(args.config) as f:
            cfg = deep_merge(DEFAULT_CONFIG, json.load(f))

    os.makedirs(cfg["state_dir"], exist_ok=True)
    lock = open(os.path.join(cfg["state_dir"], "collect.lock"), "w")
    deadline = time.time() + 120
    while True:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except OSError:
            if time.time() > deadline:
                sys.stderr.write("another collector run is still in progress\n")
                sys.exit(75)
            time.sleep(1)
    c = Collector(cfg)
    data = c.collect()
    c.save_state()

    text = json.dumps(data, separators=(",", ":"), default=str)
    if args.print:
        print(json.dumps(data, indent=2, default=str))
        return
    if args.stdout:
        sys.stdout.write(text)
        sys.stdout.flush()
        return
    os.makedirs(cfg["output_dir"], exist_ok=True)
    out = os.path.join(cfg["output_dir"], "status.json")
    tmp = out + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, out)


if __name__ == "__main__":
    main()

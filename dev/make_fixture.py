#!/usr/bin/env python3
"""
Build a fake server layout (web roots, nginx config, access logs, auth log) under a
directory and write a matching collector config, so the collector and dashboard can
be exercised on any Linux box (or WSL) without touching real system paths.

  python3 dev/make_fixture.py /tmp/spfix
  python3 collector/statuspanel_collect.py --config /tmp/spfix/config.json
  # -> /tmp/spfix/out/status.json
"""

import gzip
import json
import os
import random
import sys
import time

random.seed(7)
B = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "/tmp/spfix")
NOW = time.time()

SUBSITES = {"clientA": 1.0, "portfolio": 0.6, "blog": 1.8, "events": 0.25}
UAS_HUMAN = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
]
UAS_BOT = ["Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
           "Mozilla/5.0 (compatible; bingbot/2.0)", "Mozilla/5.0 (compatible; AhrefsBot/7.0)", "curl/8.5.0"]
SCAN_PATHS = ["/wp-login.php", "/.env", "/.git/config", "/xmlrpc.php", "/phpmyadmin/", "/admin/",
              "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/cgi-bin/luci", "/boaform/admin/formLogin"]
REFS = ["https://www.google.com/", "https://www.bing.com/", "https://www.linkedin.com/", "-", "-", "-"]


def mk(path, content=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def ip():
    return "%d.%d.%d.%d" % (random.choice([24, 51, 66, 73, 98, 104, 142, 173, 203]),
                            random.randint(0, 255), random.randint(0, 255), random.randint(1, 254))


def clf(ts):
    return time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime(ts))


def line(ts, addr, method, path, status, size, ref, ua):
    return '%s - - [%s] "%s %s HTTP/1.1" %d %d "%s" "%s"\n' % (addr, clf(ts), method, path, status, size, ref, ua)


# ---- web roots
www = os.path.join(B, "www")
main = os.path.join(www, "example.com")
mk(os.path.join(main, "index.html"), "<h1>Example</h1>")
for s in SUBSITES:
    mk(os.path.join(main, s, "index.html"), "<h1>%s</h1>" % s)
mk(os.path.join(main, "assets", "site.css"))
for d in ("oldsite", "staging", "html"):
    mk(os.path.join(www, d, "index.html"))

# ---- nginx config (example.com + default share access.log; staging has its own log;
#      a forgotten "legacy" server exposes all of /var/www on :8080)
logd = os.path.join(B, "log", "nginx")
os.makedirs(logd, exist_ok=True)
mk(os.path.join(B, "nginx", "nginx.conf"), """
user www-data;
http {
    access_log %(logd)s/access.log;
    include /etc/nginx/sites-enabled/*;
}
""" % locals())
mk(os.path.join(B, "nginx", "sites-enabled", "example.com"), """
server {
    listen 443 ssl http2;
    server_name example.com www.example.com;
    root %(main)s;
    location /statuspanel/ { alias /var/lib/statuspanel/www/; auth_basic "Status"; }
}
server { listen 80; server_name example.com www.example.com; return 301 https://$host$request_uri; }
""" % locals())
mk(os.path.join(B, "nginx", "sites-enabled", "default"), """
server { listen 80 default_server; server_name _; root %(www)s/html; }
server { listen 8080; server_name legacy.example.com; root %(www)s; }
""" % locals())
mk(os.path.join(B, "nginx", "sites-enabled", "staging"), """
server {
    listen 443 ssl;
    server_name staging.example.com;
    root %(www)s/staging;
    access_log %(logd)s/staging.access.log;
}
""" % locals())

# ---- access logs: 7 days, written into access.log / .1 / .2.gz like logrotate
main_lines, staging_lines = [], []
visitors = [ip() for _ in range(400)]
for h in range(7 * 24, 0, -1):
    t_hour = NOW - h * 3600
    hod = time.gmtime(t_hour).tm_hour
    diurnal = 0.35 + 0.65 * max(0, 1 - abs(hod - 16) / 10.0)
    for site, weight in SUBSITES.items():
        for _ in range(int(random.gauss(9, 3) * weight * diurnal) + 1):
            ts = t_hour + random.random() * 3600
            v = random.choice(visitors)
            ua = random.choice(UAS_HUMAN)
            page = random.choice(["/%s/" % site, "/%s/about.html" % site, "/%s/contact.html" % site, "/%s/" % site])
            main_lines.append((ts, line(ts, v, "GET", page, 200, random.randint(3000, 30000), random.choice(REFS), ua)))
            main_lines.append((ts + 0.2, line(ts + 0.2, v, "GET", "/assets/site.css", 200, 4100, "-", ua)))
            if random.random() < 0.04:
                main_lines.append((ts + 1, line(ts + 1, v, "GET", "/%s/missing.html" % site, 404, 150, "-", ua)))
    for _ in range(random.randint(1, 4)):
        ts = t_hour + random.random() * 3600
        main_lines.append((ts, line(ts, ip(), "GET", "/", 200, 9000, "-", random.choice(UAS_HUMAN))))
    for _ in range(random.randint(4, 12)):
        ts = t_hour + random.random() * 3600
        main_lines.append((ts, line(ts, ip(), "GET", random.choice(["/", "/blog/", "/robots.txt", "/clientA/"]),
                                    200, 5000, "-", random.choice(UAS_BOT))))
    for _ in range(random.randint(2, 9) * (4 if h < 6 else 1)):
        ts = t_hour + random.random() * 3600
        main_lines.append((ts, line(ts, random.choice(["45.148.10.%d" % random.randint(2, 9), ip()]),
                                    random.choice(["GET", "GET", "POST"]), random.choice(SCAN_PATHS), 404, 162, "-",
                                    random.choice(["Mozilla/5.0", "-", "zgrab/0.x"]))))
    if h < 30 and random.random() < 0.3:   # someone still uses the forgotten legacy path
        ts = t_hour + random.random() * 3600
        main_lines.append((ts, line(ts, "198.51.100.23", "GET", "/oldsite/", 200, 2200, "-", UAS_HUMAN[0])))
    if random.random() < 0.15:
        ts = t_hour + random.random() * 3600
        main_lines.append((ts, line(ts, ip(), "GET", "/staging/", 404, 150, "-", UAS_HUMAN[1])))
    if h < 48 and random.random() < 0.5:
        ts = t_hour + random.random() * 3600
        staging_lines.append((ts, line(ts, "203.0.113.%d" % random.randint(5, 9), "GET",
                                       random.choice(["/", "/preview.html"]), 200, 7000, "-", UAS_HUMAN[2])))

main_lines.sort()
cut1, cut2 = NOW - 86400 * 1, NOW - 86400 * 2
cur = "".join(l for t, l in main_lines if t >= cut1)
one = "".join(l for t, l in main_lines if cut2 <= t < cut1)
older = "".join(l for t, l in main_lines if t < cut2)
mk(os.path.join(logd, "access.log"), cur)
mk(os.path.join(logd, "access.log.1"), one)
with gzip.open(os.path.join(logd, "access.log.2.gz"), "wt") as f:
    f.write(older)
mk(os.path.join(logd, "staging.access.log"), "".join(l for t, l in sorted(staging_lines)))

# ---- auth log (ISO timestamps, as on Ubuntu 24.04)
auth, pid = [], 1000
def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + ".000000+00:00"
attackers = ["45.148.10.%d" % i for i in range(2, 9)] + [ip() for _ in range(40)]
for h in range(7 * 24, 0, -1):
    rate = random.randint(5, 25) * (6 if h < 5 else 1)
    for _ in range(rate):
        pid += 1
        ts = NOW - h * 3600 + random.random() * 3600
        a = random.choice(attackers)
        u = random.choice(["root", "admin", "ubuntu", "test", "oracle", "git", "postgres", "user"])
        if u == "root":
            auth.append((ts, "%s web1 sshd-session[%d]: Connection closed by authenticating user root %s port %d [preauth]"
                         % (iso(ts), pid, a, random.randint(30000, 60000))))
        else:
            auth.append((ts, "%s web1 sshd-session[%d]: Invalid user %s from %s port %d" % (iso(ts), pid, u, a, 40000)))
            auth.append((ts + 1, "%s web1 sshd-session[%d]: Connection closed by invalid user %s %s port %d [preauth]"
                         % (iso(ts + 1), pid, u, a, 40000)))
for d in (6, 4, 2, 0.2):
    pid += 1
    ts = NOW - d * 86400
    auth.append((ts, "%s web1 sshd-session[%d]: Accepted publickey for alice from 192.0.2.10 port 51234 ssh2: ED25519 SHA256:abc"
                 % (iso(ts), pid)))
for i in range(1, 288):   # the local poller logging in every 5 minutes
    pid += 1
    ts = NOW - i * 300
    auth.append((ts, "%s web1 sshd-session[%d]: Accepted publickey for spmon from 192.0.2.10 port 6%04d ssh2: ED25519 SHA256:mon"
                 % (iso(ts), pid, i)))
    auth.append((ts + 1, "%s web1 sudo:    spmon : PWD=/var/lib/spmon ; USER=root ; COMMAND=/usr/bin/python3 /opt/statuspanel/statuspanel_collect.py --stdout"
                 % iso(ts + 1)))
ts = NOW - 3 * 3600
auth.append((ts, "%s web1 sshd-session[%d]: Accepted publickey for alice from 192.0.2.77 port 50111 ssh2: ED25519 SHA256:abc" % (iso(ts), pid + 1)))
auth.append((ts + 60, "%s web1 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt upgrade" % iso(ts + 60)))
auth.append((NOW - 7200, "%s web1 sudo:   deploy : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash" % iso(NOW - 7200)))
mk(os.path.join(B, "log", "auth.log"), "\n".join(l for t, l in sorted(auth)) + "\n")

# Pretend 192.0.2.77 is new: seed state with an earlier baseline that only knows the home IP.
os.makedirs(os.path.join(B, "state"), exist_ok=True)
with open(os.path.join(B, "state", "state.json"), "w") as f:
    json.dump({"baseline_ts": NOW - 30 * 86400, "known_login_ips": {"192.0.2.10": NOW - 30 * 86400}}, f)

# 24 h of 5-minute samples so the CPU/memory chart has something to draw.
hist = []
for i in range(288, 0, -1):
    t = NOW - i * 300
    hod = time.gmtime(t).tm_hour
    cpu = max(0.5, random.gauss(6 + 10 * max(0, 1 - abs(hod - 16) / 8.0), 2) + (55 if 140 < i < 146 else 0))
    hist.append([round(t), round(cpu, 1), round(41 + random.gauss(0, 1.5), 1), round(cpu / 40, 2), 61.2, 0, 0])
with open(os.path.join(B, "state", "history.json"), "w") as f:
    json.dump(hist, f)

cfg = {
    "main_site_root": main, "www_root": www, "main_site_url": "https://example.com",
    "output_dir": os.path.join(B, "out"), "state_dir": os.path.join(B, "state"),
    "access_log_globs": [os.path.join(logd, "*access*.log*")],
    "nginx_conf_globs": [os.path.join(B, "nginx", "nginx.conf"), os.path.join(B, "nginx", "sites-enabled", "*")],
    "apache_conf_globs": [], "auth_log_globs": [os.path.join(B, "log", "auth.log*")],
    "apt_refresh_hours": 0, "http_checks": "--live" in sys.argv,
}
mk(os.path.join(B, "config.json"), json.dumps(cfg, indent=2))
print("fixture written to", B)

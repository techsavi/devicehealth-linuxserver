# StatusPanel

A health dashboard for a Linux web server that lives entirely on your local network. Nothing on the server listens for it, so no telemetry ever reaches a public web page. A poller on this machine pulls the data over SSH every 5 minutes, serves the dashboard and a small REST API on 127.0.0.1:3003 (published to the LAN by `../webserver`), and pushes alerts to the tablets run by `../tebletpanel`.

```
             internet                    │                     local network
                                         │
 your server (example.com)               │   this PC
 ┌──────────────────────────────┐  SSH   │   ┌───────────────────────────────────────────┐
 │ sshd  ── spmon key ──────────┼────────┼───┤ local/poller.mjs (every 5 min)            │
 │   forced command:            │  JSON  │   │   ├─ also checks https://example.com       │
 │   sudo statuspanel_collect.py│ ──────►│   │   ├─ serves web/ + /api on :3003 ──► ../webserver ──► browser
 │   --stdout                   │        │   │   └─ POST /api/alerts ──► ../tebletpanel ──► tablets
 └──────────────────────────────┘        │   └───────────────────────────────────────────┘
```

## Why this is private

| Layer | Protection |
|---|---|
| Server | No HTTP endpoint, no files under any web root, no new open port. Only the existing SSH port is used |
| SSH key | Dedicated `spmon` account with no password. The key is pinned in `authorized_keys` with `restrict` (no shell, no PTY, no port or agent forwarding) and `command=`, so the key can only run the collector. With Tailscale, `from=` limits it to your tailnet, so it is refused from the public internet |
| Privilege | sudoers allows `spmon` to run exactly one command line as root. Nothing else |
| Transport | Encrypted SSH. The server's host key is pinned in `local/keys/known_hosts` after the first connection |
| Dashboard | The poller listens on 127.0.0.1 only; `../webserver` publishes it to the LAN only: Caddy refuses non-private client addresses, and the firewall rule allows port 80 from the local subnet on the Private profile |
| Tablets | Receive only alert titles and messages, over the LAN |

If the private key on this PC were stolen, the thief could run the collector and read its output, and nothing more. Restricting the key to the tailnet makes even that useless outside your network.

## What it shows

| Section | Details |
|---|---|
| **Overview** | Overall status, prioritised alerts, server reachability, CPU (interval and 24 h average/peak), load, memory, root disk, pending security updates, failed SSH logins, page views |
| **System** | 24 h CPU/memory chart, disks and inodes, network throughput, iowait/steal, key services, failed systemd units, biggest processes, logged-in users |
| **Security & updates** | apt or dnf updates with security ones listed first, whether a reboot is required, unattended-upgrades status, failed update runs, firewall, sshd settings, fail2ban jails, listening ports with unexpected public ports flagged. Pending security updates and reboots have a **60-minute grace period**: they are checked every poll and shown as pending, but alert only if still outstanding after the grace period (`update_grace_minutes` in the server config), because automatic updates normally install them first. A failed update run, or packages left half-installed, alerts immediately |
| **Websites** | Each sub folder of your main site (`main_site_root`, e.g. `/var/www/example.com`): whether it is up **as seen from your network**, page views, visitors, requests, bot share, 4xx/5xx counts, a 7-day trend and last visit. Click a row for hourly traffic, top pages, referrers and 404s |
| **Hidden sites** | Every other directory in `/var/www`: how it is still reachable (its own vhost, a path under another vhost's root, an alias, or not configured), successful requests in 24 h, which IPs made them, and guesses at `/<name>/` on other sites |
| **Logins** | Failed SSH logins per day, attacking IPs and the user names they tried, fail2ban bans, and every successful login, flagged when it comes from a **new IP**, is a **root** login, uses a **password**, or comes **after failed attempts** from the same IP (critical). The poller's own routine logins are counted, not listed |
| **Web probes** | Requests for `wp-login.php`, `.env`, `.git` and similar |
| **Certificates** | TLS expiry for every HTTPS server name |

When the server can't be reached, the dashboard keeps the last data and tells you which case you're in:

| Situation | Dashboard | Tablets |
|---|---|---|
| SSH fails twice but the website answers | Amber "Not reporting" with the SSH error | Warning |
| SSH fails twice and the website doesn't answer | Red "Server down" | Critical, full screen |
| The poller itself stops | Page doesn't load (the poller serves it) | Nothing (nothing is running to send it) |
| `../webserver` is down | Not reachable from the LAN; still at http://127.0.0.1:3003/ on this PC | Not affected |

## Setup

### 1. Create the poller's key (this PC)

```sh
cd statuspanel\local
node poller.mjs keygen
```

This creates `local/keys/id_statuspanel` (on Windows its permissions are restricted to your account). It then prints the exact command for step 2.

### 2. Install the collector (server)

**Recommended: connect over Tailscale.** This PC is mobile and switches between uplinks, so its public IP keeps changing. Allow-listing a public IP would lock the poller out. With Tailscale the server always sees this PC at the same tailnet address, whichever connection is active.

1. On the server, install Tailscale and join it to your tailnet:
   ```sh
   curl -fsSL https://tailscale.com/install.sh | sh
   sudo tailscale up            # open the printed link to approve the server
   ```
2. Copy this folder to the server, then run the command `keygen` printed, with `tailscale` as the second argument:
   ```sh
   sudo sh deploy/install-server.sh "ssh-ed25519 AAAA... statuspanel@PC" tailscale
   ```
   The key is then accepted only from tailnet addresses (100.64.0.0/10). The script prints the server's tailnet name for the poller's `ssh.host`. To allow just this PC, pass its tailnet IP (`tailscale ip -4` on this PC) instead of `tailscale`.

Without Tailscale, pass a fixed public IP or CIDR, or leave the second argument off. The key can still only run the collector.

The script installs the collector to `/opt/statuspanel` and the config to `/etc/statuspanel/config.json`. It creates `spmon`, the sudoers entry and the restricted `authorized_keys` line, then runs a test exactly the way the poller will. If sshd uses `AllowUsers`, it warns you to add `spmon`. Run it again later to upgrade. With no key argument it only updates the collector.

### 3. Configure and test the poller (this PC)

```sh
copy config.example.json config.json      # set ssh.host to the server's tailnet name; tebletpanel URL/API key
node poller.mjs once
```

The first connection records the server's host key. Confirm it is really your server by comparing fingerprints:

```sh
ssh-keygen -lf keys\known_hosts                           # this PC
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub     # server
```

### 4. Run it

```sh
node poller.mjs start      # background; log in local/.run/poller.log
node poller.mjs status
node poller.mjs stop
```

To start it automatically when you log in:

```bat
schtasks /Create /TN "StatusPanel poller" /SC ONLOGON /TR "\"C:\Program Files\nodejs\node.exe\" \"C:\path\to\statuspanel\local\poller.mjs\" start"
```

### 5. View it

While running, the poller serves the dashboard at **http://127.0.0.1:3003/** (Node only, no other web server needed). `../webserver` routes it to **http://localhost/statuspanel/**, and to other devices on the LAN or tailnet at **http://<this PC's address>/statuspanel/**. Its front proxy on port 80 serves only private and Tailscale client addresses and disconnects anyone else. Change the address with `http.host` / `http.port` in `local/config.json`, or set `http.enabled` to `false` to serve `web/` with any static server instead.

#### REST API

Read-only, JSON, same address as the dashboard:

| Endpoint | Returns |
|---|---|
| `GET /api/summary` | Compact health summary for other pages (e.g. the webserver front-page tile): `host`, `overall` (`ok`/`warning`/`critical`/`unknown`), `stale` (no successful poll for 3 intervals), `last_success`, `error`, `site_up`, `alerts` (counts per level and the top 5 non-info alerts with `since`), `metrics` (CPU, memory, root disk %, load, uptime), `tls` (domains, invalid, `min_days_left`), `updates`, `logins.failed_24h` |
| `GET /api/status` | The full `status.json` the dashboard renders (503 before the first poll) |

The summary's field names are stable; build on it rather than on `status.json`, whose layout follows the collector.

Windows Firewall must allow inbound port 80 from the LAN. Run this once in an **administrator** PowerShell (use your own LAN's subnet):

```powershell
New-NetFirewallRule -DisplayName "webserver HTTP (LAN only)" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow -Profile Private -RemoteAddress 192.168.1.0/24
```

If Windows asks whether to allow `caddy.exe`, choose Cancel. The rule above is narrower than the program-wide rule that dialog would create.

### 6. Alerts: MQTT and the tablets

**Through MQTT (the default):** with `mqtt.enabled`, the poller publishes every alert as a retained message on `alerts/statuspanel/<id>` on `../webserver`'s MQTT broker, and clears it when the condition goes away. Anyone can subscribe: the webserver's tiles page and `/mqtt/` page show them, and its `bridge-tabletpanel` puts warnings and criticals on the tablets with the same rules as below (see `../webserver/README.md`, "MQTT"). Run `npm install` in `local/` once, and put the `statuspanel` login from `node serve.mjs mqtt-user statuspanel` (in `../webserver`) in `mqtt.password`. Keep `tabletpanel.enabled` off then, or the tablets get every alert twice.

After every poll it also publishes the `/api/summary` object (plus `interval_seconds` and `poller_started`) as a retained message on `devices/statuspanel/summary`. It holds what the webserver's "Server status" tile shows, so a display on the bus can show the same thing without HTTP, for example `../pi_display`'s server status view.

**Directly to the tablets** (`tabletpanel.enabled`, without the broker): with tebletpanel's server running, check that the poller can reach it:

```sh
node poller.mjs test-alert
```

How alerts reach the tablets (directly, or through the bridge):

- Warning and critical alerts go to tebletpanel's `POST /api/alerts`, as `<site.name> · <area>` with the alert message. Set `minSeverity` to `info` to forward everything, or `critical` for only the serious ones.
- Each condition has a stable key, so an ongoing problem is posted **once**. It isn't posted again every 5 minutes; it is only re-posted if it escalates, or after `repostHours` (default 24).
- When a condition clears on the server, its alert is removed from the tablets.
- The dashboard shows how long each alert has been active (hover for the exact time). The poller records when it first saw each condition in `local/.run/poller-state.json`; one that clears and comes back starts over.
- Critical alerts take over the tablet screen until dismissed. Dismissing on a tablet doesn't silence the condition; it comes back after `repostHours` if still true.
- If tebletpanel has an `API_KEY`, put it in `tabletpanel.apiKey`.

## Configuration

**Server, `/etc/statuspanel/config.json`.** Any key you leave out uses the defaults at the top of `collector/statuspanel_collect.py`.

| Key | Purpose |
|---|---|
| `main_site_root`, `main_site_url` | The site whose sub folders are reported as individual websites |
| `www_root` | Every other directory in here is treated as "should not be public" |
| `public_www_dirs` | Directories under `www_root` that are meant to be public, so their traffic doesn't raise alerts |
| `ignore_subfolders` | Sub folders that are assets rather than sites |
| `trusted_ips` | IPs/CIDRs whose logins are never flagged |
| `monitor_user` | The poller account (`spmon`). Its routine logins and sudo calls are counted, not listed |
| `expected_public_ports` | Ports allowed to listen publicly. The SSH port is added automatically |
| `log_map` | Manual `"log file": "document root"` mappings for logs the config parser can't attribute |
| `apt_refresh_hours` | Run `apt-get update` when package lists are older than this. Set `0` to rely on `apt-daily` |
| `thresholds` | Alert levels for disk, memory, CPU, certificates and login surges |

**This PC, `local/config.json`**

| Key | Default | Purpose |
|---|---|---|
| `ssh.host`, `ssh.port`, `ssh.user` | your-server.example, 22, spmon | Where to collect from (the server's tailnet name with Tailscale) |
| `site.name`, `site.server`, `site.publicIp`, `site.provider` | example.com, your-server, —, — | Your site's name (page and alert titles), the name you SSH to, the IP its DNS should resolve to, and your hosting provider. Used in the how-to-fix steps |
| `ssh.identity`, `ssh.knownHosts` | `keys/…` | Key and pinned host key, relative to `local/` |
| `intervalSeconds` | 300 | How often to poll |
| `siteUrl` | https://example.com/ | Checked from this network on every poll. Each sub folder site is checked too |
| `downAfterFailures` | 2 | Consecutive SSH failures before alerting |
| `tabletpanel.url`, `.apiKey` | http://127.0.0.1:8787 | tebletpanel server |
| `tabletpanel.minSeverity`, `.repostHours` | warning, 24 | What to forward, and when to repeat an unchanged alert |
| `command` | — | Replaces the ssh call entirely (testing, jump hosts) |

## Your site's details stay out of git

The repo contains only placeholders (`example.com`, `your-server`). Your real values live in two files that are never committed:

| File | Holds |
|---|---|
| `local/config.json` (this PC, git-ignored) | Server address (`ssh.host`), site details (`site.*`: name, SSH name, public IP, provider), MQTT/tablet credentials |
| `/etc/statuspanel/config.json` (on the server) | `main_site_root`, `main_site_url`, `public_www_dirs`, `trusted_ips`, watched URLs |

`local/keys/` (the poller's SSH key), `local/.run/` and `web/status.json` (live data) are git-ignored too. `dev/sample-status.json` is synthetic.

## Server requirements

| | Needed |
|---|---|
| OS | A Linux release that still gets security updates. Ubuntu 24.04/26.04 LTS or Debian 12/13 are ideal. The collector raises a critical alert on an end-of-life release without ESM |
| Python | 3.8 or newer (standard library only) |
| Access | `sudo`, `useradd`, `visudo`, and sshd with public-key authentication |
| Web server | Apache or nginx writing combined/vhost_combined access logs |
| Tailscale | A VM with `/dev/net/tun` (any normal cloud VM), and outbound HTTPS and UDP. No inbound ports |
| Resources | Negligible. A poll takes a few seconds and around 50 MB of RAM |

## How traffic is attributed

The collector reads the Caddyfile, the nginx config (`nginx -T`) or the Apache config to find every virtual host's document root, aliases and access log. It then maps each access-log line (including rotated `.1` and `.gz` files from the last 7 days) to the file on disk the request would hit. Anything under `<main_site_root>/<folder>` counts for that folder. Anything under another `/var/www/<dir>` counts for that hidden site.

When several virtual hosts share one log file, the line doesn't say which host was requested, so attribution is by which path exists, and the dashboard shows a note. For exact numbers, give each vhost its own `access_log` or add the host to the log format:

```nginx
log_format vhost_combined '$host $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"';
access_log /var/log/nginx/access.log vhost_combined;
```

Visitors are classified as **people**, **bots** (crawler user agents, curl, empty UA) or **scanners**. Scanner rules depend on the site:

- **Static sites:** non-GET methods, malformed requests, and any probe for PHP, WordPress or dotfiles.
- **PHP/WordPress sites:** detected from `.php` files on disk. Only misses on suspicious paths count, plus POSTs to `wp-login.php`/`xmlrpc.php`, which are also counted per site as WordPress brute-force attempts.

Page views and visitors count people only. The poller's own website checks are excluded.

## Notes and limits

- **Log data is untrusted.** Request paths, user names and user agents are attacker-controlled. The dashboard inserts them as text only, and the poller's web server sends a strict Content-Security-Policy.
- **Supported servers.** Debian/Ubuntu (apt, ufw, `auth.log` or journald). RHEL-family systems also work (dnf, firewalld, `/var/log/secure`). Python 3.8 or newer.
- **Load.** Each poll re-reads up to 7 days of access logs, which takes a second or two for a static site. On a busy server, lower `lookback_days` or raise `intervalSeconds`.
- **Notifications** reach the tablets only while this PC, the poller and tebletpanel are running.

## Development

`dev/make_fixture.py` builds a fake server: web roots, nginx config, 7 days of access logs, an auth log with brute-force noise, routine poller logins and a login from a new IP, plus 24 h of history. Run the whole pipeline locally (WSL shown) by pointing the poller's `command` at it instead of ssh:

```sh
wsl python3 dev/make_fixture.py ~/spfix
# local/config.json: "command": ["wsl", "python3", "/mnt/d/dev/statuspanel/collector/statuspanel_collect.py", "--config", "/home/<you>/spfix/config.json", "--stdout"]
node local/poller.mjs once
```

Keep the fixture out of `/tmp` in WSL. It is wiped when the distro idles. `dev/sample-status.json` is an example of the poller's output.

## Files

```
collector/statuspanel_collect.py   collector, runs on the server (stdlib only)
deploy/install-server.sh           server install/upgrade + key authorisation
deploy/config.example.json         starter server config
local/poller.mjs                   poller: SSH pull, outside-in checks, tablet alerts, dashboard + REST API server
local/config.example.json          starter poller config (copy to config.json)
web/index.html, app.js, style.css  dashboard (served by the poller)
dev/make_fixture.py                fake server for testing
dev/sample-status.json             example poller output
```

`local/config.json`, `local/keys/`, `local/.run/` and `web/status.json` are machine-specific and git-ignored.

#!/usr/bin/env node
/*
 * StatusPanel local poller.
 *
 * Every few minutes: run the collector on the server over SSH (restricted key,
 * forced command), check the public website from outside, write ../web/status.json
 * for the LAN dashboard, and forward warning/critical alerts to tebletpanel.
 * If the server cannot be reached the dashboard keeps the last data and a
 * "server down" alert is raised instead.
 *
 * While running it also serves the dashboard (../web) and a read-only REST API
 * over HTTP, by default on 127.0.0.1:3003:
 *   GET /api/summary   compact health summary (overall, alerts, key metrics)
 *   GET /api/status    the full status.json
 *
 *   node poller.mjs once|run|start|stop|status|keygen|test-alert
 */
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, openSync, closeSync, unlinkSync } from 'node:fs';
import { createServer } from 'node:http';
import { hostname } from 'node:os';
import { dirname, extname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const VERSION = '2.0.0';
const here = dirname(fileURLToPath(import.meta.url));
const runtime = join(here, '.run');
const statePath = join(runtime, 'poller-state.json');
const pidPath = join(runtime, 'poller.pid');
const configPath = process.env.STATUSPANEL_CONFIG || join(here, 'config.json');
const SELF_UA = 'statuspanel-selfcheck/' + VERSION;   // the collector leaves these out of traffic stats
const RANK = { info: 0, warning: 1, critical: 2 };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const log = (...a) => console.log(new Date().toISOString(), ...a);

const DEFAULTS = {
  ssh: {
    binary: 'ssh', host: 'your-server.example', port: 22, user: 'spmon',
    identity: 'keys/id_statuspanel', knownHosts: 'keys/known_hosts', connectTimeout: 15,
  },
  command: null,                  // argv that replaces ssh entirely (testing, jump hosts...)
  intervalSeconds: 300,
  timeoutSeconds: 300,
  output: '../web/status.json',
  http: { enabled: true, host: '127.0.0.1', port: 3003, root: '../web' },   // dashboard + REST API
  siteUrl: 'https://example.com/',
  // About your site, for page titles and the how-to-fix steps (set them in local/config.json):
  // name: shown in titles; server: how you SSH in (`ssh <server>`); publicIp: what its DNS
  // should resolve to; provider: where its control panel / console / snapshots are.
  site: { name: 'example.com', server: 'your-server', publicIp: '', provider: 'your hosting provider' },
  checkSiteUrls: true,
  downAfterFailures: 2,
  tabletpanel: {
    enabled: true, url: 'http://127.0.0.1:8787', apiKey: '',
    minSeverity: 'warning', repostHours: 24, titlePrefix: '',   // '' = site.name
  },
  // Publish every alert (all levels) as a retained message on alerts/statuspanel/<id> for any
  // subscriber (../webserver's broker; its bridge puts them on the tablets, so turn
  // tabletpanel.enabled off when this is on). Needs `npm install` in this folder.
  mqtt: {
    enabled: false, url: 'mqtt://127.0.0.1:1883', username: 'statuspanel', password: '',
    titlePrefix: '',   // '' = site.name
  },
};

// ------------------------------------------------------------------ config & state

function merge(base, over) {
  const out = { ...base };
  for (const [k, v] of Object.entries(over || {})) {
    out[k] = v && typeof v === 'object' && !Array.isArray(v) && base[k] && typeof base[k] === 'object' ? merge(base[k], v) : v;
  }
  return out;
}
function readJson(path, dflt = null) {
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { return dflt; }
}
function writeAtomic(path, text) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = path + '.tmp';
  writeFileSync(tmp, text);
  try { renameSync(tmp, path); }
  catch { writeFileSync(path, text); try { unlinkSync(tmp); } catch {} }   // Windows: target briefly locked by a reader
}
function loadConfig() {
  const cfg = merge(DEFAULTS, readJson(configPath, {}));
  const abs = p => p && resolve(here, p);
  cfg.ssh.identity = abs(cfg.ssh.identity);
  cfg.ssh.knownHosts = abs(cfg.ssh.knownHosts);
  cfg.output = abs(cfg.output);
  cfg.http.root = abs(cfg.http.root);
  cfg.tabletpanel.titlePrefix ||= cfg.site.name;
  cfg.mqtt.titlePrefix ||= cfg.site.name;
  SITE = cfg.site;
  SRV = `on the server (\`ssh ${SITE.server}\`)`;
  return cfg;
}
const loadState = () => readJson(statePath, { consecutiveFailures: 0, lastSuccess: null, posted: {} });
const saveState = st => writeAtomic(statePath, JSON.stringify(st, null, 1));

// ------------------------------------------------------------------ SSH collection

function capture(argv, timeoutMs) {
  return new Promise(done => {
    const out = [], err = [];
    let finished = false;
    const finish = (code, message) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      done({ code, stdout: Buffer.concat(out).toString('utf8'), stderr: message || Buffer.concat(err).toString('utf8') });
    };
    let child;
    try { child = spawn(argv[0], argv.slice(1), { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }); }
    catch (e) { finish(null, e.message); return; }
    const timer = setTimeout(() => { child.kill(); finish(null, `timed out after ${timeoutMs / 1000} s`); }, timeoutMs);
    child.stdout.on('data', d => out.push(d));
    child.stderr.on('data', d => err.push(d));
    child.on('error', e => finish(null, e.code === 'ENOENT' ? `${argv[0]} not found` : e.message));
    child.on('close', code => finish(code));
  });
}

function sshArgv(cfg) {
  if (Array.isArray(cfg.command) && cfg.command.length) return cfg.command;
  const s = cfg.ssh, slash = p => p.replace(/\\/g, '/');
  return [s.binary, '-i', slash(s.identity), '-p', String(s.port),
    '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', `ConnectTimeout=${s.connectTimeout}`,
    '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=4',
    '-o', 'StrictHostKeyChecking=accept-new', '-o', `UserKnownHostsFile=${slash(s.knownHosts)}`,
    '-o', 'LogLevel=ERROR', '-C', '-T', `${s.user}@${s.host}`, 'statuspanel'];
}

async function collect(cfg) {
  const t = Date.now();
  const r = await capture(sshArgv(cfg), cfg.timeoutSeconds * 1000);
  const ms = Date.now() - t;
  if (r.code !== 0) {
    const msg = (r.stderr || '').trim().split(/\r?\n/).filter(Boolean).slice(-2).join(' · ');
    return { data: null, ms, error: (msg || `ssh exited with code ${r.code}`).slice(0, 300) };
  }
  try {
    const data = JSON.parse(r.stdout);
    if (!data || typeof data.generated_at !== 'number') throw new Error('not collector output');
    return { data, ms, error: null };
  } catch (e) {
    return { data: null, ms, error: `unexpected output (${e.message}): ${r.stdout.slice(0, 80)}` };
  }
}

// ------------------------------------------------------------------ outside-in website checks

async function checkUrl(url) {
  const t = Date.now();
  try {
    const r = await fetch(url, { redirect: 'follow', headers: { 'User-Agent': SELF_UA }, signal: AbortSignal.timeout(15000) });
    await r.arrayBuffer();
    return { url, status: r.status, ok: r.status >= 200 && r.status < 400, ms: Date.now() - t, error: null };
  } catch (e) {
    return { url, status: null, ok: false, ms: Date.now() - t, error: String(e.cause?.code || e.cause?.message || e.message).slice(0, 160) };
  }
}

function siteUrls(cfg, data) {
  const urls = [cfg.siteUrl.replace(/\/?$/, '/')];
  if (cfg.checkSiteUrls && data?.web?.main?.sites) {
    for (const s of data.web.main.sites) if (s.has_index !== false) urls.push(s.url);   // skip link-only folders
  }
  return [...new Set(urls)].slice(0, 30);
}

// ------------------------------------------------------------------ alerts

const alertKey = a => a.key || `${String(a.area).toLowerCase()}:${String(a.message).toLowerCase().replace(/\d+(?:\.\d+)?/g, '#')}`;

/* What an alert means and exactly how to fix it, added to every alert as "help" (status.json and
   MQTT) for the dashboard, the webserver banner and other displays: the first line says what is
   wrong, each further line is one numbered step; `backticks` mark a command to run (on the server,
   unless it says otherwise). "link" points to the dashboard section with the details, only where
   that section shows something to act on. Each entry: [pattern matched against "<key>\n<message>",
   section or null, (match, alert) => [what is wrong, ...steps]]. First match wins. */
let SITE = DEFAULTS.site;
let SRV = 'on the server';   // set from site.server by loadConfig()
const dnsShouldGive = () => SITE.publicIp ? `should give ${SITE.publicIp}` : "should give the server's public IP";
const ALERT_FIXES = [
  [/^monitor:down$/m, null, () => [
    'This PC can reach neither the server over SSH nor the website: the server or its network is down.',
    `Open the server in the ${SITE.provider} control panel and check that it is running.`,
    'If it is stuck, use Power cycle there, or its Recovery console to look at it.',
    'Nothing else to do here: this clears on the next poll after the server is back (every 5 minutes).']],
  [/^monitor:ssh$/m, null, () => [
    'The website answers, but this PC cannot collect the server\'s data over SSH.',
    `On this PC, \`tailscale status\` should list ${SITE.server} as online; if not, start Tailscale on this PC.`,
    `If ${SITE.server} is offline in Tailscale, open the server's console at ${SITE.provider} and run \`sudo tailscale up\`.`,
    `To see the exact SSH error, run \`node poller.mjs once\` in ${here} on this PC.`]],
  [/^down:(\S+)/m, 'websites', (m) => [
    `${m[1]} does not load.`,
    'Open it in a browser to see what visitors get.',
    `Check the web server ${SRV}: \`sudo systemctl status caddy\`; if it isn't running, \`sudo systemctl restart caddy\`.`,
    'Read why it failed: `sudo journalctl -u caddy --since -1h`.',
    `If it works on the server but not from outside, check DNS on this PC: \`nslookup ${new URL(m[1]).hostname}\` should give the server's address.`]],
  [/^slow:(\S+)/m, 'websites', (m) => [
    `${m[1]} took long to answer.`,
    'If it clears on the next poll it was a blip: nothing to do.',
    `If it keeps happening, look at CPU and memory under System on the dashboard and at the web server log ${SRV}: \`sudo journalctl -u caddy --since -1h\`.`]],
  [/^(\S+) answers (40[13])/m, 'websites', (m) => [
    `${m[1]} answers ${m[2]}: the folder has no index page, or access to it is restricted.`,
    'If it should be public, add an `index.html` to that folder on the server.',
    'If it is private on purpose, nothing is broken: the error is what keeps it private.']],
  [/^port:(tcp|udp):(\d+)\n.*\(([^)]*)\)\s*$/m, 'security', (m) => [
    `${m[3] || 'A program'} accepts ${m[1].toUpperCase()} connections from the internet on port ${m[2]}, which is not on this server's list of expected public ports.`,
    `See what it is ${SRV}: \`sudo ss -${m[1][0]}lnp 'sport = :${m[2]}'\`.`,
    `If it isn't needed, stop it (\`sudo systemctl disable --now <service>\`) or block the port: \`sudo ufw deny ${m[2]}/${m[1]}\`.`,
    `If it is meant to be public, add ${m[2]} to "expected_public_ports" → "${m[1]}" in \`/etc/statuspanel/config.json\` on the server.`,
    'Either way, this clears on the next poll (every 5 minutes).']],
  [/^cert-error:(\S+)/m, 'tls', (m) => [
    `HTTPS for ${m[1]} fails, so visitors get a certificate error.`,
    `Check that DNS points at the server, on this PC: \`nslookup ${m[1]}\` ${dnsShouldGive()}.`,
    `Find the reason ${SRV}: \`sudo journalctl -u caddy --since -1d | grep -i ${m[1]}\`.`,
    'Once DNS is right, make Caddy try again: `sudo systemctl restart caddy`. This clears on the next poll.']],
  [/^cert:(\S+)\n.*in (\d+) days/m, 'tls', (m) => [
    `The certificate for ${m[1]} expires in ${m[2]} days and hasn't been renewed (Caddy renews about 30 days ahead).`,
    `Find why the renewal fails ${SRV}: \`sudo journalctl -u caddy --since -7d | grep -i ${m[1]}\`.`,
    `Check that DNS still points at the server, on this PC: \`nslookup ${m[1]}\` ${dnsShouldGive()}.`,
    'Then make Caddy try again: `sudo systemctl restart caddy`.']],
  [/^disk:(\S+)\n.*?(\d+)% full/m, 'system', (m) => [
    `The ${m[1]} disk is ${m[2]}% full; when it fills up, the sites and the server start failing.`,
    `Find what takes the space ${SRV}: \`sudo du -xh ${m[1]} --max-depth=2 | sort -h | tail -15\`.`,
    'Trim the system log: `sudo journalctl --vacuum-size=200M`.',
    'Clear downloaded packages and old kernels: `sudo apt clean && sudo apt autoremove --purge`.']],
  [/Disk (\S+) inodes/m, 'system', (m) => [
    `The ${m[1]} disk has almost run out of inodes: there are too many small files, even if there is free space.`,
    `Find the folder with the most files ${SRV}: \`sudo du --inodes -x ${m[1]} --max-depth=3 | sort -n | tail -15\`.`,
    'Delete what is stale there (old cache or session files).']],
  [/^Memory \d+% used|^Swap \d+% used/m, 'system', () => [
    'The server is short of memory, which slows everything down.',
    'Find the process using it: Biggest processes under System on the dashboard, or `top` (press M) on the server.',
    'Restart it: `sudo systemctl restart <service>`. If it fills up again, it is leaking memory: update or limit it.']],
  [/CPU \d+% busy|CPU averaged|5-min load/m, 'system', () => [
    'The server is busy for a long time, which slows the sites down.',
    'Find what is busy: Biggest processes under System on the dashboard, or `top` on the server.',
    'If it is the web server, check Web probes and Logins for floods of requests.',
    'Restart a runaway service: `sudo systemctl restart <service>`.']],
  [/systemd unit failed: (\S+)/m, 'system', (m) => [
    `The service ${m[1]} has failed.`,
    `See why ${SRV}: \`sudo systemctl status ${m[1]}\` and \`sudo journalctl -u ${m[1]} --since -1d\`.`,
    `Fix the cause, then \`sudo systemctl restart ${m[1]}\`.`,
    `If it is no longer needed: \`sudo systemctl disable ${m[1]} && sudo systemctl reset-failed ${m[1]}\`.`]],
  [/Web server (\S+) is (\S+)/m, null, (m) => [
    `The web server (${m[1]}) is ${m[2]}, so every site is down.`,
    `Start it ${SRV}: \`sudo systemctl restart ${m[1]}\`.`,
    `If it won't start, read why: \`sudo journalctl -u ${m[1]} --since -1h\`; after a config change, \`sudo caddy validate --config /etc/caddy/Caddyfile\` shows the mistake.`]],
  [/^os-eol|^os-esm/m, null, () => [
    'This Ubuntu release is reaching (or past) the end of its standard support, after which security fixes stop.',
    `Plan an upgrade to the next LTS release at a quiet time, after a backup or a ${SITE.provider} snapshot.`,
    `Run ${SRV}: \`sudo do-release-upgrade\`, and follow its prompts.`]],
  [/^updates:failed:unattended-upgrades/m, null, () => [
    'The last automatic update run hit an error, so some updates may not have been installed.',
    `Read what went wrong ${SRV}: \`sudo tail -50 /var/log/unattended-upgrades/unattended-upgrades.log\`.`,
    'Finish the job by hand: `sudo dpkg --configure -a && sudo apt update && sudo apt upgrade`.',
    'This clears after the next clean update run (automatic or by hand).']],
  [/^updates:failed:apt/m, null, () => [
    'The last package update run ended with an error.',
    `See the details ${SRV}: \`sudo tail -40 /var/log/apt/term.log\`.`,
    'Repair and retry: `sudo dpkg --configure -a && sudo apt -f install && sudo apt upgrade`.',
    'This clears after the next update run that finishes cleanly.']],
  [/^updates:broken/m, null, () => [
    'An update stopped part-way, leaving packages half-installed; until fixed, further updates (including security ones) can fail.',
    `Finish it ${SRV}: \`sudo dpkg --configure -a\`, then \`sudo apt -f install\`.`,
    'Check it worked: `sudo dpkg --audit` should print nothing. This clears on the next poll.']],
  [/(\d+) security update/m, null, (m) => [
    `${m[1]} security update(s) are waiting to be installed.`,
    `Install them ${SRV}: \`sudo apt update && sudo apt upgrade\`.`,
    'If it then says a restart is required, reboot at a quiet time: `sudo reboot` (the sites are down for about a minute).',
    'This clears on the next poll.']],
  [/package update\(s\) available/m, null, () => [
    'Ordinary package updates are available. Not urgent.',
    `When convenient, ${SRV}: \`sudo apt update && sudo apt upgrade\`.`]],
  [/reboot required/im, null, () => [
    'Installed updates (often a new kernel) take effect only after a restart.',
    `At a quiet time, ${SRV}: \`sudo reboot\`. The sites are down for about a minute.`,
    'This clears on the next poll after the server is back.']],
  [/package lists not refreshed/im, null, () => [
    'The server hasn\'t checked for updates for days, so it may be missing security fixes.',
    `Check now ${SRV}: \`sudo apt update\`.`,
    'Turn the daily check back on: `sudo systemctl enable --now apt-daily.timer apt-daily-upgrade.timer`.']],
  [/automatic security updates/im, null, () => [
    'Security updates are not installed automatically.',
    `Turn them on ${SRV}: \`sudo apt install unattended-upgrades\`, then \`sudo dpkg-reconfigure -plow unattended-upgrades\` and answer Yes.`]],
  [/firewall/im, null, () => [
    'The server has no active firewall, so every listening port is reachable from the internet.',
    `Allow the web and the tailnet's SSH ${SRV}: \`sudo ufw allow 80,443/tcp\`, \`sudo ufw allow 443/udp\` and \`sudo ufw allow in on tailscale0 to any port 22\`.`,
    'Then turn it on: `sudo ufw enable`.']],
  [/root login with a password/im, null, () => [
    'SSH lets someone log in as root with a password, which is what attackers try first.',
    `Edit the SSH settings ${SRV}: \`sudo nano /etc/ssh/sshd_config\`, and set \`PermitRootLogin prohibit-password\` (or \`no\`).`,
    'Apply it: `sudo systemctl reload ssh`.']],
  [/password authentication/im, null, () => [
    'SSH accepts passwords as well as keys.',
    'Check first that you can log in with your key.',
    `Then ${SRV}: set \`PasswordAuthentication no\` in /etc/ssh/sshd_config and run \`sudo systemctl reload ssh\`.`]],
  [/^hidden-traffic:(\S+)|^(\S+) answers publicly at (\S+)/m, 'hidden', (m) => [
    `${m[1] ?? m[2]} is under /var/www but isn't meant to be public, and it is being reached.`,
    'See who reaches it and how under Hidden sites on the dashboard.',
    'If it is no longer needed, delete it or move it out of /var/www on the server.',
    `If it is meant to be public, add its folder name to "public_www_dirs" in \`/etc/statuspanel/config.json\` on the server.`]],
  [/login as (\S+) from (\S+) after (\d+) failed/im, 'logins', (m) => [
    `Someone logged in as ${m[1]} from ${m[2]} after ${m[3]} failed attempts, which can mean a guessed password.`,
    'If it was you, nothing to do.',
    `If not, change the password ${SRV}: \`sudo passwd ${m[1]}\`, and check \`~${m[1]}/.ssh/authorized_keys\` for keys you don't know.`,
    `See what was done: \`sudo last ${m[1]}\`, and block the address: \`sudo ufw deny from ${m[2]}\`.`]],
  [/^login-new-ip:([^:\n]+):(\S+)/m, 'logins', (m) => [
    `${m[1]} logged in over SSH from ${m[2]}, an address not seen before.`,
    'If it was you (a new network or a phone hotspot), nothing to do: it isn\'t new next time.',
    `If not, change the password ${SRV}: \`sudo passwd ${m[1]}\`, check \`~${m[1]}/.ssh/authorized_keys\`, and block the address: \`sudo ufw deny from ${m[2]}\`.`]],
  [/^login-root:(\S+)/m, 'logins', (m) => [
    `Someone logged in directly as root, from ${m[1]}.`,
    'If it was you, log in as your own user and use sudo instead.',
    `Stop root logins ${SRV}: set \`PermitRootLogin no\` in /etc/ssh/sshd_config, then \`sudo systemctl reload ssh\`.`,
    'If it wasn\'t you, treat the server as compromised: check `sudo last` and replace the SSH keys.']],
  [/^login-surge/m, 'logins', () => [
    'Many more failed SSH logins than usual: someone is guessing passwords.',
    `Check that fail2ban is blocking them ${SRV}: \`sudo fail2ban-client status sshd\`.`,
    'Logins are key-only, so guessing can\'t succeed; it clears when the guessing stops.']],
  [/not in sudoers|^sudo-failures/m, 'logins', () => [
    'Someone tried to use sudo with a wrong password, or with an account that isn\'t allowed to.',
    'If it was you, nothing to do.',
    'If not, see which account under Logins on the dashboard and change its password: `sudo passwd <user>`.']],
  [/fail2ban is not running/im, null, () => [
    'fail2ban, which blocks addresses that keep guessing SSH passwords, isn\'t running.',
    `Start it ${SRV}: \`sudo systemctl enable --now fail2ban\`.`]],
  [/^collector-error/m, null, () => [
    'The collector couldn\'t read part of the server\'s data; the rest still works.',
    `The message names the part. If it keeps happening, reinstall the collector: copy ${resolve(here, '..', 'collector', 'statuspanel_collect.py')} to /opt/statuspanel/ on the server.`]],
];

function explain(a) {
  const text = `${a.key ?? ''}\n${a.message ?? ''}`;
  for (const [re, section, fix] of ALERT_FIXES) {
    const m = text.match(re);
    if (m) return { help: fix(m, a).join('\n'), ...(section ? { link: `/statuspanel/#${section}` } : {}) };
  }
  return {};
}

const tagOf = key => 'statuspanel-' + createHash('sha1').update(key).digest('hex').slice(0, 12);

function mergeAlerts(...lists) {
  const byKey = new Map();
  for (const a of lists.flat().filter(Boolean)) {
    const k = alertKey(a), cur = byKey.get(k);
    if (!cur || (RANK[a.level] ?? 0) > (RANK[cur.level] ?? 0)) byKey.set(k, { ...a, key: k });
  }
  return [...byKey.values()].sort((a, b) => (RANK[b.level] ?? 0) - (RANK[a.level] ?? 0));
}

async function tp(cfg, method, path, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (cfg.tabletpanel.apiKey) headers['X-API-Key'] = cfg.tabletpanel.apiKey;
  const r = await fetch(cfg.tabletpanel.url.replace(/\/$/, '') + path, {
    method, headers, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(8000),
  });
  if (!r.ok && r.status !== 404) throw new Error(`tebletpanel ${method} ${path}: HTTP ${r.status}`);
  return r;
}

/* Post alerts that are new or escalated, clear the ones that went away. Tablets
   chime on every post, so an unchanged condition is not re-posted (until repostHours). */
async function forward(cfg, state, alerts) {
  const c = cfg.tabletpanel;
  if (!c.enabled || !c.url) return { enabled: false };
  const min = RANK[c.minSeverity] ?? 1, now = Date.now() / 1000;
  const want = new Map();
  for (const a of alerts) if ((RANK[a.level] ?? 0) >= min) want.set(tagOf(a.key), a);
  state.posted ||= {};
  let posted = 0, cleared = 0;
  try {
    for (const [tag, a] of want) {
      const p = state.posted[tag];
      const due = !p || RANK[a.level] > RANK[p.level] || (c.repostHours > 0 && now - p.at > c.repostHours * 3600);
      if (!due) { p.level = a.level; continue; }
      await tp(cfg, 'POST', '/api/alerts', {
        title: `${c.titlePrefix} · ${a.area}`, message: a.message, severity: a.level,
        durationSeconds: 0, sound: true, dismissible: true, tag, source: 'statuspanel',
      });
      state.posted[tag] = { level: a.level, at: now, key: a.key };
      posted++;
    }
    for (const tag of Object.keys(state.posted)) {
      if (want.has(tag)) continue;
      await tp(cfg, 'DELETE', '/api/alerts/' + encodeURIComponent(tag));
      delete state.posted[tag];
      cleared++;
    }
    return { enabled: true, ok: true, active: want.size, posted, cleared, at: now };
  } catch (e) {
    return { enabled: true, ok: false, active: want.size, posted, cleared, at: now, error: String(e.cause?.code || e.message).slice(0, 200) };
  }
}

// ------------------------------------------------------------------ MQTT: publish alerts

/* Each alert is a retained message on alerts/statuspanel/<id> (id = the tablet tag's hash, so
   tags stay the same when a bridge takes over from forward()); an empty retained message clears
   it. Payloads hold only stable fields, so an unchanged alert isn't republished. status/statuspanel
   says "online", or "offline" via the broker's last will. */
let bus = null;

async function mqttConnect(cfg) {
  if (bus || !cfg.mqtt.enabled) return bus;
  const b = bus = { desired: new Map(), published: new Map(), connected: false, error: null, published_n: 0, cleared_n: 0 };
  let mqtt;
  try { ({ default: mqtt } = await import('mqtt')); }
  catch { b.error = 'the mqtt package is missing: run npm install in statuspanel/local'; return b; }
  const c = cfg.mqtt;
  const client = b.client = mqtt.connect(c.url, {
    username: c.username, password: c.password, clientId: `statuspanel-${hostname()}`, reconnectPeriod: 5000,
    will: { topic: 'status/statuspanel', payload: 'offline', retain: true, qos: 1 },
  });
  client.on('connect', () => {
    b.connected = true;
    b.error = null;
    client.publish('status/statuspanel', 'online', { retain: true, qos: 1 });
    if (b.summary) client.publish(SUMMARY_TOPIC, b.summary, { retain: true, qos: 1 });
    // The broker may hold alerts from an earlier run (or have lost them): republish everything,
    // and clear what it holds that is no longer current.
    b.published = new Map();
    const held = new Set();
    const onMessage = (topic, payload) => { if (payload.length) held.add(topic.split('/')[2]); };
    client.on('message', onMessage);
    client.subscribe('alerts/statuspanel/+', { qos: 1 }, () => setTimeout(() => {
      client.removeListener('message', onMessage);
      client.unsubscribe('alerts/statuspanel/+');
      for (const id of held) if (!b.desired.has(id)) b.published.set(id, null);
      mqttSync();
    }, 1500));
  });
  client.on('close', () => { b.connected = false; });
  client.on('error', e => { b.error = e.message; });
  return b;
}

function mqttSync() {
  const b = bus;
  if (!b?.connected) return;
  for (const [id, payload] of b.desired) {
    if (b.published.get(id) === payload) continue;
    b.client.publish(`alerts/statuspanel/${id}`, payload, { retain: true, qos: 1 });
    b.published.set(id, payload);
    b.published_n++;
  }
  for (const id of [...b.published.keys()]) {
    if (b.desired.has(id)) continue;
    b.client.publish(`alerts/statuspanel/${id}`, '', { retain: true, qos: 1 });
    b.published.delete(id);
    b.cleared_n++;
  }
}

async function publishAlerts(cfg, alerts) {
  if (!cfg.mqtt.enabled) return { enabled: false };
  const b = await mqttConnect(cfg);
  for (let i = 0; i < 12 && b.client && !b.connected; i++) await sleep(250);   // the first poll right after starting
  b.desired = new Map(alerts.map(a => {
    const id = createHash('sha1').update(a.key).digest('hex').slice(0, 12);
    return [id, JSON.stringify({ source: 'statuspanel', id, key: a.key, level: a.level, area: a.area,
      title: `${cfg.mqtt.titlePrefix} · ${a.area}`, message: a.message, since: a.since, help: a.help, link: a.link })];
  }));
  const before = { p: b.published_n, c: b.cleared_n };
  mqttSync();
  return { enabled: true, connected: b.connected, active: b.desired.size,
    published: b.published_n - before.p, cleared: b.cleared_n - before.c, error: b.error };
}

/* The tile's data for displays on the bus (e.g. pi_display's server status view): the
   /api/summary object, retained on devices/statuspanel/summary after every poll. Subscribers
   work out "updated N ago" and staleness from last_success and interval_seconds. */
const SUMMARY_TOPIC = 'devices/statuspanel/summary';
const STARTED_AT = Math.floor(Date.now() / 1000);

function publishSummary(cfg, out) {
  if (!cfg.mqtt.enabled || !bus) return;
  bus.summary = JSON.stringify({ ...summarize(out, cfg), interval_seconds: cfg.intervalSeconds, poller_started: STARTED_AT });
  if (bus.connected) bus.client.publish(SUMMARY_TOPIC, bus.summary, { retain: true, qos: 1 });
}

// For one-shot runs: give the broker a moment to connect and take the messages, then disconnect.
async function mqttClose() {
  if (!bus?.client) return;
  for (let i = 0; i < 20 && !bus.connected; i++) await sleep(250);
  await sleep(1800);   // the reconnect sync waits 1.5 s for retained messages
  await new Promise(done => bus.client.publish('status/statuspanel', 'offline', { retain: true, qos: 1 }, () => bus.client.end(false, {}, done)));
}

// ------------------------------------------------------------------ one poll

async function cycle(cfg) {
  const state = loadState();
  const started = Date.now() / 1000;
  const { data, ms, error } = await collect(cfg);
  const previous = readJson(cfg.output);
  const base = data || (previous && typeof previous.generated_at === 'number' ? previous : null);
  const external = await Promise.all(siteUrls(cfg, base).map(checkUrl));
  const siteUp = external.length ? external[0].ok : null;

  state.consecutiveFailures = data ? 0 : (state.consecutiveFailures || 0) + 1;
  if (data) state.lastSuccess = started;
  const failing = !data && state.consecutiveFailures >= cfg.downAfterFailures;
  const host = cfg.ssh.host;

  const monitor = [];
  if (failing && siteUp === false) {
    monitor.push({ level: 'critical', area: 'Monitor', key: 'monitor:down', poller: true,
      message: `${host} is down: SSH and the website are both unreachable (${error})` });
  } else if (failing) {
    monitor.push({ level: 'warning', area: 'Monitor', key: 'monitor:ssh', poller: true,
      message: `Cannot collect telemetry over SSH for ${state.consecutiveFailures} attempts (${error}). The website still answers.` });
  }
  for (const c of external) {
    if (!c.ok && c.status !== 401 && c.status !== 403) monitor.push({ level: 'critical', area: 'Web', key: 'down:' + c.url, poller: true,
      message: `${c.url} is unreachable from outside (${c.status ? 'HTTP ' + c.status : c.error})` });
  }

  const out = base ? { ...base } : { generated_at: null, interval_seconds: cfg.intervalSeconds, alerts: [] };
  // When SSH failed, base is the previous output: drop the alerts this poller added last time.
  out.alerts = mergeAlerts(monitor, base ? (base.alerts || []).filter(a => !a.poller) : []);
  // Stamp each condition with when this poller first saw it; forget the ones that cleared.
  const seen = state.firstSeen || {};
  state.firstSeen = {};
  for (const a of out.alerts) {
    a.since = state.firstSeen[a.key] = seen[a.key] || started;
    Object.assign(a, explain(a));   // help: what it means and what to do; link: the dashboard section
  }
  out.overall = out.alerts.some(a => a.level === 'critical') ? 'critical' : out.alerts.some(a => a.level === 'warning') ? 'warning' : 'ok';
  const forwarding = await forward(cfg, state, out.alerts);
  const publishing = await publishAlerts(cfg, out.alerts);
  out.poller = {
    version: VERSION, host, site_name: cfg.site.name, via: Array.isArray(cfg.command) && cfg.command.length ? 'command' : `ssh ${cfg.ssh.user}@${host}`,
    poller_host: hostname(), interval_seconds: cfg.intervalSeconds,
    last_attempt: started, last_success: state.lastSuccess || null, fresh: !!data,
    consecutive_failures: state.consecutiveFailures, error, duration_ms: ms,
    site_up: siteUp, server_down: failing && siteUp === false, external, tabletpanel: forwarding, mqtt: publishing,
  };
  writeAtomic(cfg.output, JSON.stringify(out));
  publishSummary(cfg, out);
  saveState(state);
  log(data ? `ok in ${ms} ms` : `FAILED (${state.consecutiveFailures}x): ${error}`,
    `| site ${siteUp === null ? '?' : siteUp ? 'up' : 'DOWN'}`,
    `| overall ${out.overall}`,
    forwarding.enabled ? `| tebletpanel ${forwarding.ok ? `${forwarding.active} active, +${forwarding.posted} -${forwarding.cleared}` : 'ERROR ' + forwarding.error}` : '',
    publishing.enabled ? `| mqtt ${publishing.connected ? `${publishing.active} active, +${publishing.published} -${publishing.cleared}` : 'NOT CONNECTED' + (publishing.error ? ' ' + publishing.error : '')}` : '');
  return out;
}

// ------------------------------------------------------------------ HTTP: dashboard + REST API

/* A compact, stable view of status.json for other pages (e.g. a tile on a
 * front page) that should not depend on the full collector format. */
function summarize(s, cfg) {
  if (!s || typeof s.generated_at !== 'number') return { overall: 'unknown', stale: true, error: 'No data collected yet' };
  const sys = s.system || {}, p = s.poller || {}, alerts = s.alerts || [];
  const interval = p.interval_seconds || s.interval_seconds || cfg.intervalSeconds;
  const lastSuccess = p.last_success ?? s.generated_at;
  const count = lvl => alerts.filter(a => a.level === lvl).length;
  const tls = (s.tls || []).filter(t => t.valid);
  const root = (sys.disks || []).find(d => d.mount === '/');
  return {
    host: sys.hostname || p.host || cfg.ssh.host,
    overall: s.overall || 'unknown',
    generated_at: s.generated_at,
    last_success: lastSuccess,
    stale: Date.now() / 1000 - lastSuccess > interval * 3,
    error: p.fresh === false ? p.error : null,
    site_up: p.site_up ?? null,
    alerts: {
      critical: count('critical'), warning: count('warning'), info: count('info'),
      top: alerts.filter(a => a.level !== 'info').slice(0, 5)
        .map(({ level, area, message, since }) => ({ level, area, message, since: since ?? null })),
    },
    metrics: {
      cpu_pct: sys.cpu_pct ?? null, mem_pct: sys.memory?.pct ?? null, disk_root_pct: root?.pct ?? null,
      load1: sys.load?.[0] ?? null, cpu_count: sys.cpu_count ?? null, uptime_seconds: sys.uptime_seconds ?? null,
    },
    tls: {
      domains: (s.tls || []).length, invalid: (s.tls || []).length - tls.length,
      min_days_left: tls.length ? Math.min(...tls.map(t => t.days_left)) : null,
    },
    updates: { security: s.updates?.security ?? null, upgradable: s.updates?.upgradable ?? null, reboot_required: s.updates?.reboot_required ?? null },
    logins: { failed_24h: s.logins?.failed_24h ?? null },
  };
}

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8' };
const BASE_HEADERS = {
  'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex, nofollow', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'",
};

function serveHttp(cfg) {
  const { host, port, root } = cfg.http;
  const send = (res, status, type, body, extra = {}) => { res.writeHead(status, { ...BASE_HEADERS, 'Content-Type': type, ...extra }); res.end(body); };
  const json = (res, status, obj) => send(res, status, 'application/json', JSON.stringify(obj));
  const server = createServer((req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'text/plain', 'Method not allowed', { Allow: 'GET, HEAD' });
    let path;
    try { path = decodeURIComponent(new URL(req.url, 'http://x').pathname); } catch { return send(res, 400, 'text/plain', 'Bad request'); }
    if (path === '/api/summary' || path === '/api/status') {
      const s = readJson(cfg.output);
      if (path === '/api/status') return s ? json(res, 200, s) : json(res, 503, { error: 'No data collected yet' });
      return json(res, 200, summarize(s, cfg));
    }
    if (path.startsWith('/api/')) return json(res, 404, { error: 'Unknown endpoint', endpoints: ['/api/summary', '/api/status'] });
    const file = resolve(root, '.' + (path.endsWith('/') ? path + 'index.html' : path));
    if (!file.startsWith(root + sep) || file.endsWith('.tmp')) return send(res, 404, 'text/plain', 'Not found');
    let body;
    try { body = readFileSync(file); } catch { return send(res, 404, 'text/plain', 'Not found'); }
    send(res, 200, TYPES[extname(file).toLowerCase()] || 'application/octet-stream', req.method === 'HEAD' ? null : body);
  });
  return new Promise((ok, fail) => {
    server.once('error', fail);
    server.listen(port, host, () => { log(`serving ${root} and /api on http://${host}:${port}/`); ok(server); });
  });
}

// ------------------------------------------------------------------ commands

function pidAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}
const runningPid = () => { const p = readJson(pidPath); return p && pidAlive(p.pid) ? p.pid : null; };

async function runLoop(cfg) {
  mkdirSync(runtime, { recursive: true });
  writeFileSync(pidPath, JSON.stringify({ pid: process.pid, started: Date.now() }));
  let stop = false;
  const quit = () => { stop = true; try { unlinkSync(pidPath); } catch {} process.exit(0); };
  process.on('SIGINT', quit);
  process.on('SIGTERM', quit);
  if (cfg.http.enabled) {
    try { await serveHttp(cfg); }
    catch (e) { log(`cannot listen on ${cfg.http.host}:${cfg.http.port}: ${e.message}`); try { unlinkSync(pidPath); } catch {} process.exit(1); }
  }
  log(`poller ${VERSION} polling ${cfg.ssh.host} every ${cfg.intervalSeconds} s -> ${cfg.output}`);
  while (!stop) {
    const t = Date.now();
    try { await cycle(loadConfig()); } catch (e) { log('cycle error:', e.stack || e.message); }
    await sleep(Math.max(5000, cfg.intervalSeconds * 1000 - (Date.now() - t)));
  }
}

function keygen(cfg) {
  const key = cfg.ssh.identity;
  mkdirSync(dirname(key), { recursive: true });
  if (!existsSync(key)) {
    const r = spawnSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', `statuspanel@${hostname()}`, '-f', key], { stdio: 'inherit' });
    if (r.status !== 0) throw new Error('ssh-keygen failed (is the OpenSSH client installed?)');
  }
  if (process.platform === 'win32') {
    // Windows OpenSSH refuses private keys that other accounts can read.
    spawnSync('icacls', [key, '/inheritance:r', '/grant:r', `${process.env.USERNAME}:F`], { stdio: 'ignore' });
  }
  const pub = readFileSync(key + '.pub', 'utf8').trim();
  console.log(`Key: ${key}\n\nOn the server, from the statuspanel folder, run:\n\n  sudo sh deploy/install-server.sh "${pub}" tailscale\n`);
}

const command = process.argv[2] || 'once';
try {
  const cfg = loadConfig();
  if (command === 'once') {
    const out = await cycle(cfg);
    await mqttClose();
    process.exitCode = out.poller.fresh ? 0 : 2;
  } else if (command === 'run') {
    if (runningPid() && runningPid() !== process.pid) throw new Error(`Already running (pid ${runningPid()}).`);
    await runLoop(cfg);
  } else if (command === 'start') {
    const pid = runningPid();
    if (pid) { console.log(`Already running (pid ${pid}).`); process.exit(0); }
    mkdirSync(runtime, { recursive: true });
    const outFd = openSync(join(runtime, 'poller.log'), 'a');
    const child = spawn(process.execPath, [fileURLToPath(import.meta.url), 'run'], {
      cwd: here, detached: true, stdio: ['ignore', outFd, outFd], windowsHide: true,
    });
    child.unref();
    closeSync(outFd);
    await sleep(1500);
    if (!runningPid()) throw new Error('Startup failed. Check local/.run/poller.log.');
    console.log(`Poller started (pid ${runningPid()}). Log: ${join(runtime, 'poller.log')}`);
  } else if (command === 'stop') {
    const pid = runningPid();
    if (!pid) console.log('Not running.');
    else { process.kill(pid); try { unlinkSync(pidPath); } catch {} console.log(`Stopped (pid ${pid}).`); }
  } else if (command === 'status') {
    const pid = runningPid(), st = loadState(), out = readJson(cfg.output);
    console.log(pid ? `Running (pid ${pid}).` : 'Not running.');
    if (out?.poller) {
      const p = out.poller;
      console.log(`Last attempt ${new Date(p.last_attempt * 1000).toLocaleString()}: ${p.fresh ? 'ok' : 'FAILED - ' + p.error}`);
      console.log(`Last success ${p.last_success ? new Date(p.last_success * 1000).toLocaleString() : 'never'} · overall ${out.overall} · ${Object.keys(st.posted || {}).length} alert(s) on tablets`);
    }
  } else if (command === 'keygen') {
    keygen(cfg);
  } else if (command === 'test-alert') {
    await tp(cfg, 'POST', '/api/alerts', { title: `${cfg.tabletpanel.titlePrefix} · Test`, message: 'StatusPanel can reach this display.',
      severity: 'warning', durationSeconds: 60, tag: 'statuspanel-test', source: 'statuspanel' });
    console.log(`Test alert sent to ${cfg.tabletpanel.url} (clears in 60 s).`);
  } else {
    throw new Error('Usage: node poller.mjs [once|run|start|stop|status|keygen|test-alert]');
  }
} catch (e) {
  console.error(e.message);
  process.exitCode = 1;
}

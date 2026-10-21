'use strict';
/*
 * StatusPanel dashboard. Renders status.json written by statuspanel_collect.py.
 * Everything that comes from logs (paths, user names, user agents, IPs) is
 * attacker-controlled, so it is only ever inserted with textContent.
 */

const STATUS_URL = 'status.json';
const REFRESH_MS = 60 * 1000;

let DATA = null;
let fetchError = null;
let chartQueue = [];
const openRows = new Set(loadPref('sp-open', []));

// ------------------------------------------------------------------ DOM helpers

function setAttrs(el, attrs) {
  if (!attrs) return;
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'text') el.textContent = v;
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k.startsWith('on')) el.addEventListener(k.slice(2).toLowerCase(), v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
}
function append(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k == null || k === false || k === '') continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
}
function h(tag, attrs, ...kids) { const el = document.createElement(tag); setAttrs(el, attrs); append(el, kids); return el; }
const SVGNS = 'http://www.w3.org/2000/svg';
function s(tag, attrs, ...kids) { const el = document.createElementNS(SVGNS, tag); setAttrs(el, attrs); append(el, kids); return el; }

function loadPref(key, dflt) { try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : dflt; } catch (e) { return dflt; } }
function savePref(key, v) { try { localStorage.setItem(key, JSON.stringify(v)); } catch (e) { /* storage unavailable */ } }

// ------------------------------------------------------------------ formatting

const NF = new Intl.NumberFormat();
const NFC = new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 });
const num = n => n == null ? '–' : NF.format(n);
const compact = n => n == null ? '–' : (Math.abs(n) < 10000 ? NF.format(Math.round(n)) : NFC.format(n));
const pct = (p, d = 0) => p == null ? '–' : p.toFixed(d) + '%';
function bytes(b) {
  if (b == null) return '–';
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (i ? b.toFixed(b < 10 ? 1 : 0) : Math.round(b)) + ' ' + u[i];
}
const rate = b => bytes(b) + '/s';
function ago(ts) {
  if (!ts) return 'never';
  const d = Date.now() / 1000 - ts;
  if (d < 45) return 'just now';
  if (d < 3600) return Math.round(d / 60) + ' min ago';
  if (d < 86400 * 2) return Math.round(d / 3600) + ' h ago';
  return Math.round(d / 86400) + ' days ago';
}
function dur(sec) {
  const d = Math.floor(sec / 86400), hh = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
  return d ? `${d}d ${hh}h` : hh ? `${hh}h ${m}m` : `${m}m`;
}
const when = ts => ts ? new Date(ts * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '–';
const clock = ts => new Date(ts * 1000).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
const day = ts => new Date(ts * 1000).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });

// ------------------------------------------------------------------ status icons & badges

const LEVELS = {
  ok: { label: 'OK' }, info: { label: 'Info' }, warning: { label: 'Warning' }, critical: { label: 'Critical' },
};
function icon(level, size = 14) {
  const svg = s('svg', { viewBox: '0 0 16 16', width: size, height: size, class: 'ico', 'aria-hidden': 'true' });
  if (level === 'warning') {
    svg.append(s('path', { d: 'M8 1.2 15.2 14H.8Z', style: { fill: 'var(--warning)' } }),
      s('path', { d: 'M8 5.6v4M8 11.6v.4', style: { stroke: 'var(--icon-ink-warn)', strokeWidth: 1.8, strokeLinecap: 'round' } }));
  } else if (level === 'critical') {
    svg.append(s('circle', { cx: 8, cy: 8, r: 7.2, style: { fill: 'var(--critical)' } }),
      s('path', { d: 'M5.4 5.4l5.2 5.2M10.6 5.4l-5.2 5.2', style: { stroke: 'var(--icon-ink)', strokeWidth: 1.8, strokeLinecap: 'round' } }));
  } else if (level === 'ok') {
    svg.append(s('circle', { cx: 8, cy: 8, r: 7.2, style: { fill: 'var(--good)' } }),
      s('path', { d: 'M4.8 8.2l2.2 2.2 4.2-4.6', style: { stroke: 'var(--icon-ink)', strokeWidth: 1.8, fill: 'none', strokeLinecap: 'round', strokeLinejoin: 'round' } }));
  } else {
    svg.append(s('circle', { cx: 8, cy: 8, r: 7.2, style: { fill: 'var(--muted)' } }),
      s('path', { d: 'M8 7.2v4.2M8 4.6v.3', style: { stroke: 'var(--icon-ink)', strokeWidth: 1.8, strokeLinecap: 'round' } }));
  }
  return svg;
}
const badge = (level, text) => h('span', { class: 'badge' }, icon(level), text == null ? LEVELS[level].label : text);
const chip = (text, attrs) => h('span', Object.assign({ class: 'chip' }, attrs || {}), text);

function meter(p, warn = 80, crit = 90) {
  const lvl = p >= crit ? 'critical' : p >= warn ? 'warning' : '';
  return h('div', { class: 'meter ' + lvl, role: 'meter', 'aria-valuenow': p, 'aria-valuemin': 0, 'aria-valuemax': 100 },
    h('span', { style: { width: Math.max(0, Math.min(100, p)) + '%' } }));
}

// ------------------------------------------------------------------ tooltip

const tip = h('div', { class: 'tooltip', role: 'tooltip' });
function showTip(ev, title, rows) {
  tip.replaceChildren(h('div', { class: 'tip-title' }, title),
    ...rows.map(r => h('div', { class: 'tip-row' },
      r.color ? h('span', { class: 'tip-key', style: { background: r.color } }) : null,
      h('strong', null, r.value), h('span', { class: 'tip-label' }, r.label))));
  tip.style.display = 'block';
  let x, y;
  if (ev.clientX != null && ev.type.startsWith('pointer')) { x = ev.clientX; y = ev.clientY; }
  else { const b = ev.target.getBoundingClientRect(); x = b.left + b.width / 2; y = b.top; }
  const w = tip.offsetWidth, hh = tip.offsetHeight;
  tip.style.left = Math.min(window.innerWidth - w - 8, x + 14) + 'px';
  tip.style.top = (y + 14 + hh > window.innerHeight ? y - hh - 10 : y + 14) + 'px';
}
const hideTip = () => { tip.style.display = 'none'; };

// ------------------------------------------------------------------ charts

function niceStep(x) {
  const p = Math.pow(10, Math.floor(Math.log10(x)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= x) return m * p;
  return 10 * p;
}
function niceScale(max, n = 4) {
  if (!(max > 0)) return { max: 1, ticks: [0, 1] };
  const step = niceStep(max / n);
  const top = Math.ceil(max / step) * step;
  const ticks = [];
  for (let v = 0; v <= top + step / 2; v += step) ticks.push(+v.toFixed(6));
  return { max: top, ticks };
}

/* A slot is filled after it is attached to the page, so charts can size to their container. */
function chartSlot(draw) {
  const el = h('div', { class: 'chart-slot' });
  chartQueue.push(() => { el.replaceChildren(); draw(el); });
  return el;
}

function legend(series, kind) {
  if (series.length < 2) return null;
  return h('div', { class: 'legend' }, series.map(sr =>
    h('span', null, h('span', { class: kind === 'line' ? 'key-line' : 'key-rect', style: { background: sr.color } }), sr.name)));
}

/* A chart card with a legend, a chart/table toggle and the table view. */
function chartBlock(title, sub, series, kind, draw, tableCols, tableRows) {
  const slot = chartSlot(draw);
  const tbl = h('div', { class: 'data-table', hidden: true }, table(tableCols, tableRows));
  const btn = h('button', { class: 'btn ghost', type: 'button', 'aria-pressed': 'false' }, 'Table');
  btn.addEventListener('click', () => {
    const on = tbl.hidden;
    tbl.hidden = !on; slot.hidden = on;
    btn.setAttribute('aria-pressed', String(on));
    btn.textContent = on ? 'Chart' : 'Table';
  });
  return h('div', null,
    h('div', { class: 'card-head' }, h('h3', null, title), legend(series, kind), btn),
    sub ? h('p', { class: 'card-sub' }, sub) : null,
    slot, tbl);
}

function lineChart(el, o) {
  const W = Math.max(280, el.clientWidth || 600), H = o.height || 190;
  const m = { l: 38, r: o.series.length <= 4 ? 70 : 14, t: 10, b: 22 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  const t = o.t;
  if (!t.length) { el.append(h('p', { class: 'empty' }, 'No samples yet - history builds up as the collector runs.')); return; }
  const t0 = o.tMin != null ? o.tMin : t[0], t1 = t[t.length - 1];
  const x = v => m.l + (t1 > t0 ? (v - t0) / (t1 - t0) * iw : iw);
  const allMax = Math.max(0, ...o.series.flatMap(sr => sr.values.filter(v => v != null)));
  const sc = o.yMax ? { max: o.yMax, ticks: [0, o.yMax / 4, o.yMax / 2, o.yMax * 3 / 4, o.yMax] } : niceScale(allMax);
  const y = v => m.t + ih - (v / sc.max) * ih;
  const fmt = o.fmt || (v => num(v));
  const svg = s('svg', { width: W, height: H, viewBox: `0 0 ${W} ${H}`, class: 'chart', role: 'img', 'aria-label': o.label });

  for (const tk of sc.ticks) {
    svg.append(s('line', { x1: m.l, x2: m.l + iw, y1: y(tk), y2: y(tk), class: tk === 0 ? 'base-line' : 'grid-line' }));
    svg.append(s('text', { x: m.l - 6, y: y(tk) + 4, 'text-anchor': 'end' }, fmt(tk)));
  }
  // x ticks on local clock hours (every 6 h for a day of data)
  const span = t1 - t0, stepH = span > 2 * 86400 ? 24 : span > 12 * 3600 ? 6 : span > 3 * 3600 ? 2 : 1;
  const d0 = new Date(t0 * 1000); d0.setMinutes(0, 0, 0);
  for (let d = d0; d.getTime() / 1000 <= t1; d = new Date(d.getTime() + 3600e3)) {
    const ts = d.getTime() / 1000;
    if (ts < t0 || d.getHours() % stepH) continue;
    svg.append(s('text', { x: x(ts), y: H - 6, 'text-anchor': 'middle' }, stepH === 24 ? day(ts) : clock(ts)));
  }

  const gap = (o.interval || 300) * 3;
  o.series.forEach((sr, si) => {
    let d = '', prev = null;
    sr.values.forEach((v, i) => {
      if (v == null) { prev = null; return; }
      const cmd = prev == null || t[i] - t[prev] > gap ? 'M' : 'L';
      d += `${cmd}${x(t[i]).toFixed(1)},${y(v).toFixed(1)}`;
      prev = i;
    });
    if (o.series.length === 1) {
      const first = sr.values.findIndex(v => v != null);
      svg.append(s('path', { d: d + `L${x(t[t.length - 1])},${y(0)}L${x(t[first])},${y(0)}Z`, style: { fill: sr.color, opacity: 0.1 } }));
    }
    svg.append(s('path', { d, style: { fill: 'none', stroke: sr.color, strokeWidth: 2, strokeLinejoin: 'round', strokeLinecap: 'round' } }));
  });

  // end markers + direct labels (skipped when they would collide; the legend still carries identity)
  const ends = o.series.map(sr => {
    let i = sr.values.length - 1; while (i >= 0 && sr.values[i] == null) i--;
    return i < 0 ? null : { sr, i, y: y(sr.values[i]) };
  }).filter(Boolean);
  ends.forEach(e => svg.append(s('circle', { cx: x(t[e.i]), cy: e.y, r: 4, style: { fill: e.sr.color, stroke: 'var(--surface)', strokeWidth: 2 } })));
  const sorted = ends.slice().sort((a, b) => a.y - b.y);
  const collide = sorted.some((e, k) => k && e.y - sorted[k - 1].y < 14);
  if (m.r > 20 && !collide) {
    ends.forEach(e => svg.append(s('text', { x: x(t[e.i]) + 9, y: e.y + 4, class: 'end-label' }, `${e.sr.short || e.sr.name} ${fmt(e.sr.values[e.i])}`)));
  }

  // crosshair + one tooltip for every series
  const cross = s('line', { y1: m.t, y2: m.t + ih, class: 'crosshair', visibility: 'hidden' });
  const dots = o.series.map(sr => s('circle', { r: 4, visibility: 'hidden', style: { fill: sr.color, stroke: 'var(--surface)', strokeWidth: 2 } }));
  svg.append(cross, ...dots);
  const hit = s('rect', { x: m.l, y: m.t, width: iw, height: ih, fill: 'transparent', tabindex: 0, 'aria-label': o.label + ' - use arrow keys' });
  let cur = t.length - 1;
  const showAt = (i, ev) => {
    cur = Math.max(0, Math.min(t.length - 1, i));
    const cx = x(t[cur]);
    cross.setAttribute('x1', cx); cross.setAttribute('x2', cx); cross.setAttribute('visibility', 'visible');
    o.series.forEach((sr, k) => {
      const v = sr.values[cur];
      dots[k].setAttribute('visibility', v == null ? 'hidden' : 'visible');
      if (v != null) { dots[k].setAttribute('cx', cx); dots[k].setAttribute('cy', y(v)); }
    });
    showTip(ev, when(t[cur]), o.series.map(sr => ({ color: sr.color, value: sr.values[cur] == null ? '–' : fmt(sr.values[cur]), label: sr.name })));
  };
  const nearest = px => {
    let lo = 0, hi = t.length - 1;
    const tv = t0 + (px - m.l) / iw * (t1 - t0);
    while (hi - lo > 1) { const mid = (lo + hi) >> 1; if (t[mid] < tv) lo = mid; else hi = mid; }
    return Math.abs(t[lo] - tv) < Math.abs(t[hi] - tv) ? lo : hi;
  };
  hit.addEventListener('pointermove', ev => {
    const r = svg.getBoundingClientRect();
    showAt(nearest((ev.clientX - r.left) * (W / r.width)), ev);
  });
  const hide = () => { hideTip(); cross.setAttribute('visibility', 'hidden'); dots.forEach(d => d.setAttribute('visibility', 'hidden')); };
  hit.addEventListener('pointerleave', hide);
  hit.addEventListener('blur', hide);
  hit.addEventListener('focus', ev => showAt(cur, ev));
  hit.addEventListener('keydown', ev => {
    if (ev.key === 'ArrowLeft' || ev.key === 'ArrowRight') { ev.preventDefault(); showAt(cur + (ev.key === 'ArrowLeft' ? -1 : 1), ev); }
  });
  svg.append(hit);
  el.append(svg);
}

function roundedTop(x, y, w, hgt, r) {
  r = Math.min(r, w / 2, hgt);
  return `M${x},${y + hgt}V${y + r}A${r},${r} 0 0 1 ${x + r},${y}H${x + w - r}A${r},${r} 0 0 1 ${x + w},${y + r}V${y + hgt}Z`;
}

function columnChart(el, o) {
  const W = Math.max(260, el.clientWidth || 600), H = o.height || 180;
  const m = { l: 38, r: 8, t: 10, b: 22 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b, n = o.labels.length;
  const totals = o.labels.map((_, i) => o.series.reduce((a, sr) => a + (sr.values[i] || 0), 0));
  const sc = niceScale(Math.max(...totals));
  const y = v => m.t + ih - (v / sc.max) * ih;
  const fmt = o.fmt || compact;
  const band = iw / n, bw = Math.max(3, Math.min(24, band * 0.72));
  const svg = s('svg', { width: W, height: H, viewBox: `0 0 ${W} ${H}`, class: 'chart', role: 'img', 'aria-label': o.label });
  for (const tk of sc.ticks) {
    if (tk) svg.append(s('line', { x1: m.l, x2: m.l + iw, y1: y(tk), y2: y(tk), class: 'grid-line' }));
    svg.append(s('text', { x: m.l - 6, y: y(tk) + 4, 'text-anchor': 'end' }, fmt(tk)));
  }
  const every = Math.ceil(46 / band);
  o.labels.forEach((lab, i) => {
    const cx = m.l + band * i + band / 2;
    const g = s('g', { class: 'col' });
    let base = y(0);
    const segs = o.series.map((sr, k) => ({ sr, v: sr.values[i] || 0, k })).filter(sg => sg.v > 0);
    segs.forEach((sg, j) => {
      const full = (sg.v / sc.max) * ih, top = base - full;
      const hgt = full - (j ? 2 : 0);               // 2px surface gap between stacked segments
      if (hgt > 0.5) {
        g.append(j === segs.length - 1
          ? s('path', { d: roundedTop(cx - bw / 2, top, bw, hgt, 4), style: { fill: sg.sr.color } })
          : s('rect', { x: cx - bw / 2, y: top, width: bw, height: hgt, style: { fill: sg.sr.color } }));
      }
      base = top;
    });
    const hit = s('rect', { x: m.l + band * i, y: m.t, width: band, height: ih, fill: 'transparent', tabindex: 0,
      'aria-label': `${o.full ? o.full[i] : lab}: ${fmt(totals[i])}` });
    const rows = () => {
      const r = o.series.map(sr => ({ color: sr.color, value: num(sr.values[i] || 0), label: sr.name }));
      if (o.series.length > 1) r.push({ value: num(totals[i]), label: 'total' });
      return r;
    };
    const on = ev => { g.classList.add('hover'); showTip(ev, o.full ? o.full[i] : lab, rows()); };
    const off = () => { g.classList.remove('hover'); hideTip(); };
    hit.addEventListener('pointermove', on); hit.addEventListener('focus', on);
    hit.addEventListener('pointerleave', off); hit.addEventListener('blur', off);
    g.append(hit);
    svg.append(g);
    if ((n - 1 - i) % every === 0) svg.append(s('text', { x: cx, y: H - 6, 'text-anchor': 'middle' }, lab));
  });
  svg.append(s('line', { x1: m.l, x2: m.l + iw, y1: y(0), y2: y(0), class: 'base-line' }));
  el.append(svg);
}

function sparkline(values, color, w = 120, hgt = 26, label) {
  const vals = values.map(v => v == null ? null : v);
  const real = vals.filter(v => v != null);
  const svg = s('svg', { width: w, height: hgt, viewBox: `0 0 ${w} ${hgt}`, class: 'spark', role: 'img', 'aria-label': label || 'trend' });
  if (real.length < 2) return svg;
  const max = Math.max(...real, 1e-9), min = 0, pad = 4;
  const x = i => pad / 2 + i / (vals.length - 1) * (w - pad - 2);
  const y = v => hgt - 2 - (v - min) / (max - min || 1) * (hgt - pad - 2);
  let d = '';
  vals.forEach((v, i) => { if (v != null) d += (d && vals[i - 1] != null ? 'L' : 'M') + x(i).toFixed(1) + ',' + y(v).toFixed(1); });
  svg.append(s('path', { d, style: { fill: 'none', stroke: color, strokeWidth: 1.75, strokeLinejoin: 'round', strokeLinecap: 'round' } }));
  const li = vals.length - 1 - [...vals].reverse().findIndex(v => v != null);
  svg.append(s('circle', { cx: x(li), cy: y(vals[li]), r: 2.5, style: { fill: color } }));
  if (label) svg.append(s('title', null, label));
  return svg;
}

// ------------------------------------------------------------------ tables & lists

/* cols: [{label, num}] ; rows: arrays of cells, or {cells, cls, onClick, detail} */
function table(cols, rows, emptyText) {
  if (!rows || !rows.length) return h('p', { class: 'empty' }, emptyText || 'Nothing to show.');
  const tb = h('tbody');
  for (const r of rows) {
    const spec = Array.isArray(r) ? { cells: r } : r;
    const tr = h('tr', { class: spec.cls || null }, spec.cells.map((c, i) => h('td', { class: cols[i] && cols[i].num ? 'num' : null }, c)));
    tb.append(tr);
    if (spec.detail) {
      const key = spec.key;
      const dtr = h('tr', { class: 'detail', hidden: !openRows.has(key) }, h('td', { colspan: cols.length }));
      const fill = () => { if (!dtr.firstChild.firstChild) { dtr.firstChild.append(spec.detail()); runCharts(); } };
      tr.classList.add('clickable');
      tr.tabIndex = 0;
      tr.setAttribute('aria-expanded', String(openRows.has(key)));
      if (openRows.has(key)) { tr.classList.add('open'); chartQueue.push(fill); }
      const toggle = () => {
        const opening = dtr.hidden;
        dtr.hidden = !opening;
        tr.classList.toggle('open', opening);
        tr.setAttribute('aria-expanded', String(opening));
        if (opening) { openRows.add(key); fill(); } else openRows.delete(key);
        savePref('sp-open', [...openRows]);
      };
      tr.addEventListener('click', ev => { if (!ev.target.closest('a')) toggle(); });
      tr.addEventListener('keydown', ev => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); toggle(); } });
      tb.append(dtr);
    }
  }
  return h('div', { class: 'table-wrap' }, h('table', null,
    h('thead', null, h('tr', null, cols.map(c => h('th', { class: c.num ? 'num' : null, scope: 'col' }, c.label)))), tb));
}

function topList(title, pairs, fmtV, emptyText) {
  return h('div', null, h('h3', { style: { marginBottom: '6px' } }, title),
    pairs && pairs.length
      ? h('ul', { class: 'toplist' }, pairs.map(([k, v]) => h('li', null, h('span', { class: 'k mono', title: k }, k), h('span', { class: 'v' }, fmtV ? fmtV(v) : num(v)))))
      : h('p', { class: 'empty' }, emptyText || 'None.'));
}

const kv = pairs => h('dl', { class: 'kv' }, pairs.filter(Boolean).flatMap(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
const card = (cls, ...kids) => h('div', { class: 'card ' + (cls || '') }, ...kids);
const section = (id, title, sub, ...kids) => h('section', { id, class: 'section' },
  h('div', { class: 'section-head' }, h('h2', null, title), sub ? h('span', { class: 'muted' }, sub) : null), ...kids);
const unavailable = what => card('span-12', h('p', { class: 'empty' }, `${what} data is unavailable - see collector errors at the bottom of the page.`));

function tile(label, value, unit, sub, opts = {}) {
  return h('div', { class: 'tile' },
    h('div', { class: 'tile-label' }, opts.level ? icon(opts.level) : null, label),
    h('div', { class: 'tile-value' }, value, unit ? h('span', { class: 'unit' }, unit) : null),
    h('div', { class: 'tile-sub' }, sub),
    opts.meter != null ? meter(opts.meter, opts.warn, opts.crit) : null,
    opts.spark ? sparkline(opts.spark, opts.color || 'var(--s1)', 170, 28, opts.sparkLabel) : null);
}

// ------------------------------------------------------------------ sections

function hourLabels(gen, n = 24) {
  const labels = [], full = [];
  for (let i = 0; i < n; i++) {
    const start = gen - (n - i) * 3600;
    labels.push(clock(start)); full.push(`${clock(start)} – ${clock(start + 3600)}`);
  }
  return { labels, full };
}
function dayLabels(gen, n) {
  const labels = [], full = [];
  for (let i = 0; i < n; i++) {
    const end = gen - (n - 1 - i) * 86400;
    labels.push(i === n - 1 ? 'Last 24 h' : day(end));
    full.push(`${when(end - 86400)} – ${when(end)}`);
  }
  return { labels, full };
}

const openHelp = new Set();   // alert keys whose "How to fix" is open, kept across redraws

// An alert's help: the first line says what is wrong, each further line is a numbered step, and
// `backticks` mark a command (shown as code, selected whole on click so it can be copied).
function helpBody(help) {
  const code = line => line.split('`').map((part, i) => (i % 2 ? h('code', null, part) : part));
  const [why, ...steps] = String(help).split('\n').filter(Boolean);
  return [why ? h('p', null, code(why)) : null, steps.length ? h('ol', null, steps.map(st => h('li', null, code(st)))) : null];
}

function renderAlerts(d) {
  const main = d.alerts.filter(a => a.level !== 'info'), info = d.alerts.filter(a => a.level === 'info');
  // help (added by the poller): what the alert means and what to do, with the section that has the details.
  const section = a => (a.link ?? '').split('#')[1];
  const row = a => h('li', null, icon(a.level), h('span', { class: 'lvl' }, LEVELS[a.level] ? LEVELS[a.level].label : a.level),
    h('span', { class: 'area' }, a.area), h('span', { class: 'msg' }, a.message),
    h('span', { class: 'age', title: a.since ? `First seen ${when(a.since)}` : null }, a.since ? ago(a.since) : ''),
    a.help ? h('details', { class: 'help', open: openHelp.has(a.key), ontoggle: e => (e.target.open ? openHelp.add(a.key) : openHelp.delete(a.key)) },
      h('summary', null, 'How to fix'), ...helpBody(a.help),
      section(a) ? h('p', null, h('a', { href: `#${section(a)}` }, `See the ${section(a)} section →`)) : null) : null);
  return card('span-12',
    h('div', { class: 'card-head' }, h('h3', null, 'Alerts'),
      h('span', { class: 'muted small' }, `${main.length} need attention · ${info.length} informational`)),
    main.length ? h('ul', { class: 'alerts' }, main.map(row))
      : h('p', { class: 'badge', style: { padding: '4px 8px' } }, icon('ok'), 'No warnings - all checks passing.'),
    info.length ? h('details', { class: 'more' }, h('summary', null, `${info.length} informational note(s)`), h('ul', { class: 'alerts' }, info.map(row))) : null);
}

function renderOverview(d) {
  const sys = d.system || {}, hist = d.history || {}, up = d.updates || {}, lg = d.logins || {}, web = d.web || {};
  const pts = (hist.points || []);
  const th = 80;
  const root = (sys.disks || []).find(x => x.mount === '/') || (sys.disks || [])[0];
  const tiles = [];
  const p = d.poller;
  const upFor = sys.uptime_seconds != null ? `Up ${dur(sys.uptime_seconds)} · ${sys.cpu_count} cores` : '';
  if (p && p.server_down) tiles.push(tile('Server', 'Down', null, `No SSH or HTTPS since ${when(p.last_success)}`, { level: 'critical' }));
  else if (p && !p.fresh) tiles.push(tile('Server', 'Not reporting', null, `Website ${p.site_up ? 'up' : 'unknown'} · SSH failing`, { level: 'warning' }));
  else tiles.push(tile('Server', 'Online', null, upFor, { level: 'ok' }));
  if (sys.cpu_pct != null) tiles.push(tile('CPU', sys.cpu_pct.toFixed(0), '%',
    `24 h avg ${pct(hist.cpu_avg_24h)} · peak ${pct(hist.cpu_max_24h)}`,
    { spark: pts.map(p => p[1]), sparkLabel: 'CPU % over the last 24 hours' }));
  if (sys.load) tiles.push(tile('Load average', sys.load[0].toFixed(2), null,
    `5 min ${sys.load[1].toFixed(2)} · 15 min ${sys.load[2].toFixed(2)}`,
    { spark: pts.map(p => p[3]), sparkLabel: '1-minute load over the last 24 hours' }));
  if (sys.memory) tiles.push(tile('Memory', sys.memory.pct.toFixed(0), '%',
    `${bytes(sys.memory.used)} of ${bytes(sys.memory.total)}`, { meter: sys.memory.pct, warn: th, crit: 90 }));
  if (root) tiles.push(tile(`Disk ${root.mount}`, root.pct.toFixed(0), '%', `${bytes(root.free)} free of ${bytes(root.size)}`,
    { meter: root.pct, warn: 80, crit: 90 }));
  if (up.manager) tiles.push(tile('Security updates', num(up.security), null,
    `${num(up.upgradable)} updates total${up.reboot_required ? ' · reboot required' : ''}${(up.security || up.reboot_required) && !updatesOverdue(up) ? ' · within grace period' : ''}`,
    { level: updatesOverdue(up) || (up.update_failures || []).length ? 'warning' : up.security || up.reboot_required ? 'info' : 'ok' }));
  if (lg.failed_24h != null) tiles.push(tile('Failed SSH logins · 24 h', compact(lg.failed_24h), null,
    `from ${num(lg.unique_ips_24h)} IPs · ${num(lg.avg_failed_per_day)}/day avg`,
    { spark: lg.hourly_failed, sparkLabel: 'Failed SSH logins per hour, last 24 hours', level: lg.surge ? 'warning' : null }));
  if (web.totals) {
    const hc = web.hourly_by_class || {};
    tiles.push(tile('Page views · 24 h', compact(web.totals.pageviews_24h), null,
      `${compact(web.totals.visitors_24h)} visitors · ${compact(web.totals.requests_24h)} requests`,
      { spark: (hc.human || []), sparkLabel: 'Human requests per hour, last 24 hours' }));
  }
  return h('div', { class: 'tiles span-12' }, tiles);
}

function renderSystem(d) {
  const sys = d.system;
  if (!sys) return unavailable('System');
  const hist = d.history || {}, pts = hist.points || [];
  const t = pts.map(p => p[0]);
  const series = [
    { name: 'CPU busy', short: 'CPU', color: 'var(--s1)', values: pts.map(p => p[1]) },
    { name: 'Memory used', short: 'Mem', color: 'var(--s2)', values: pts.map(p => p[2]) },
  ];
  const chart = chartBlock('CPU and memory · last 24 h',
    `Each point averages the ${Math.round((d.interval_seconds || 300) / 60)} minutes between collector runs. 7-day CPU average ${pct(hist.cpu_avg_7d)}.`,
    series, 'line',
    el => lineChart(el, { t, series, yMax: 100, fmt: v => v.toFixed(0) + '%', interval: d.interval_seconds, label: 'CPU and memory percent over the last 24 hours', tMin: d.generated_at - 86400 }),
    [{ label: 'Time' }, { label: 'CPU %', num: true }, { label: 'Memory %', num: true }, { label: 'Load', num: true }],
    pts.slice().reverse().map(p => [when(p[0]), pct(p[1], 1), pct(p[2], 1), p[3]]));

  const disks = table([{ label: 'Mount' }, { label: 'Used' }, { label: 'Free', num: true }, { label: 'Size', num: true }, { label: 'Inodes', num: true }],
    (sys.disks || []).map(x => [h('span', { class: 'mono' }, x.mount),
      h('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', minWidth: '140px' } }, meter(x.pct), h('span', { class: 'nowrap' }, pct(x.pct))),
      bytes(x.free), bytes(x.size), x.inode_pct == null ? '–' : pct(x.inode_pct)]));

  const svc = (sys.services || []).map(sv => chip([icon(sv.state === 'active' ? 'ok' : sv.state === 'failed' ? 'critical' : 'info', 12), ` ${sv.unit.replace(/\.service$/, '')} · ${sv.state}`]));
  const failed = (sys.failed_units || []).map(u => chip([icon('critical', 12), ` ${u} · failed`], { class: 'chip strong' }));

  return h('div', { class: 'grid' },
    card('span-8', chart),
    card('span-4', h('div', { class: 'card-head' }, h('h3', null, 'Host')),
      kv([
        ['Hostname', h('span', { class: 'mono' }, sys.hostname)],
        ['OS', sys.os], ['Kernel', h('span', { class: 'mono' }, sys.kernel)],
        ['Booted', `${when(sys.boot_time)} (${dur(sys.uptime_seconds)} ago)`],
        ['CPU now', `${pct(sys.cpu_pct, 1)} busy · iowait ${pct(sys.cpu_iowait_pct, 1)} · steal ${pct(sys.cpu_steal_pct, 1)}`],
        ['Swap', sys.memory.swap_total ? `${bytes(sys.memory.swap_used)} of ${bytes(sys.memory.swap_total)} (${pct(sys.memory.swap_pct)})` : 'none'],
        ['Network', (sys.network || []).length ? h('span', null, sys.network.map(n => h('div', null, `${n.iface}: ↓ ${rate(n.rx_bps)} · ↑ ${rate(n.tx_bps)}`))) : 'measuring…'],
        ['Logged in', (sys.logged_in || []).length ? h('span', null, sys.logged_in.map(u => h('div', { class: 'mono' }, u.join(' ')))) : 'nobody'],
      ])),
    card('span-6', h('div', { class: 'card-head' }, h('h3', null, 'Disks')), disks),
    card('span-6', h('div', { class: 'card-head' }, h('h3', null, 'Services')),
      h('div', { class: 'chips', style: { marginBottom: '12px' } }, failed, svc.length ? svc : h('span', { class: 'empty' }, 'systemd not available')),
      h('h3', { style: { margin: '6px 0' } }, 'Largest processes by memory'),
      table([{ label: 'Process' }, { label: 'User' }, { label: 'PID', num: true }, { label: 'Memory', num: true }],
        (sys.top_memory || []).map(p => [h('span', { class: 'mono' }, p.cmd), p.user, p.pid, bytes(p.rss)]))));
}

/* Pending security updates and reboots have a grace period (update_grace_minutes on the
   server, 60 by default) before they alert: automatic updates usually install them in time. */
function updatesOverdue(up) {
  return !!(up.security_overdue || up.reboot_overdue);
}
function pendingBadge(up, overdue, firstSeen, text) {
  if (overdue || !firstSeen) return badge('warning', `${text}${firstSeen ? ' · since ' + when(firstSeen) : ''}`);
  const due = firstSeen + (up.grace_minutes || 60) * 60;
  return badge('info', `${text} · grace period, alerts at ${clock(due)} if still pending`);
}

function osSupportBadge(o) {
  const until = o.support_end ? new Date(o.support_end * 1000).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : null;
  if (o.eol && !o.esm) return badge('critical', `${o.release} · end-of-life since ${until}, no ESM`);
  if (o.eol) return badge('info', `${o.release} · covered by ESM (standard support ended ${until})`);
  if (o.support_end && o.support_end - Date.now() / 1000 < 180 * 86400) return badge('warning', `${o.release} · support ends ${until}`);
  return badge('ok', `${o.release}${until ? ' · supported until ' + until : ''}`);
}

function siteTags(st) {
  return [st.dynamic ? chip('PHP') : null,
    st.wp_login_posts_24h ? chip(`${compact(st.wp_login_posts_24h)} wp-login POSTs`, { class: 'chip strong', title: 'POST requests to wp-login.php / xmlrpc.php in 24 h - usually password guessing' }) : null];
}

function renderSecurity(d) {
  const up = d.updates || {}, sec = d.security || {};
  const fw = sec.firewall || {}, ssh = sec.ssh || {}, f2b = sec.fail2ban || {};
  const pk = up.packages || [];
  const pkgRows = pk.map(p => ({ cells: [h('span', { class: 'mono' }, p.name), p.security ? badge('warning', 'Security') : h('span', { class: 'muted' }, 'Regular'),
    h('span', { class: 'mono small' }, p.from || ''), h('span', { class: 'mono small' }, p.version), h('span', { class: 'small muted' }, p.origin)] }));

  const updatesCard = card('span-7',
    h('div', { class: 'card-head' }, h('h3', null, 'Package updates'),
      up.manager ? h('span', { class: 'muted small' }, `${up.manager} · lists refreshed ${ago(up.lists_updated)}`) : null),
    !up.manager ? h('p', { class: 'empty' }, 'No supported package manager found.') : [
      kv([
        up.os_support ? ['OS support', osSupportBadge(up.os_support)] : null,
        ['Security updates', up.security ? pendingBadge(up, up.security_overdue, up.security_first_seen, `${up.security} pending`)
          : up.os_support && up.os_support.eol && !up.os_support.esm
          ? badge('critical', 'None published - release is end-of-life') : badge('ok', 'None pending')],
        ['All updates', num(up.upgradable)],
        ['Reboot', up.reboot_required ? pendingBadge(up, up.reboot_overdue, up.reboot_first_seen || up.reboot_since,
          `Required${up.reboot_packages && up.reboot_packages.length ? ' (' + up.reboot_packages.slice(0, 6).join(', ') + ')' : ''}`) : badge('ok', 'Not required')],
        up.update_failures ? ['Update runs', up.update_failures.length
          ? h('div', null, up.update_failures.map(f => h('div', null, badge('warning',
              `${f.source === 'dpkg' ? 'Incomplete' : f.source === 'apt' ? 'apt failed' : 'Automatic run failed'}${f.ts ? ' ' + when(f.ts) : ''}: ${f.message}`))))
          : badge('ok', 'No failures')] : null,
        ['Automatic updates', up.unattended_enabled ? badge('ok', `Enabled${up.unattended_last_run ? ' · last ran ' + ago(up.unattended_last_run) : ''}`) : badge('info', 'Not enabled')],
        up.php ? ['PHP', up.php.eol ? badge(up.os_support && up.os_support.esm ? 'info' : 'warning', `${up.php.version} · past upstream support`)
          : badge('ok', `${up.php.version}${up.php.support_end ? ' · supported until ' + day(up.php.support_end) + ' ' + new Date(up.php.support_end * 1000).getFullYear() : ''}`)] : null,
        up.last_upgrade !== undefined ? ['Last upgrade', up.last_upgrade ? `${when(up.last_upgrade)} (${ago(up.last_upgrade)})` : 'unknown'] : null,
      ]),
      h('div', { style: { marginTop: '12px' } },
        pk.length > 12
          ? [table([{ label: 'Package' }, { label: 'Type' }, { label: 'Installed' }, { label: 'Available' }, { label: 'Source' }], pkgRows.slice(0, 12)),
            h('details', { class: 'more' }, h('summary', null, `Show all ${pk.length} packages`),
              table([{ label: 'Package' }, { label: 'Type' }, { label: 'Installed' }, { label: 'Available' }, { label: 'Source' }], pkgRows.slice(12)))]
          : table([{ label: 'Package' }, { label: 'Type' }, { label: 'Installed' }, { label: 'Available' }, { label: 'Source' }], pkgRows, 'Everything is up to date.')),
    ]);

  const jails = (f2b.jails || []);
  const hardening = card('span-5',
    h('div', { class: 'card-head' }, h('h3', null, 'Hardening')),
    kv([
      ['Firewall', fw.tool && fw.active == null ? badge('info', `${fw.tool} · state unknown (needs root)`) : fw.tool ? badge(fw.active ? 'ok' : 'warning', `${fw.tool} · ${fw.active ? 'active' : 'inactive'}${fw.rules != null ? ' · ' + fw.rules + ' rules' : ''}`) : badge('warning', 'none detected')],
      ['SSH port', ssh.available ? (ssh.ports || []).join(', ') : h('span', { class: 'muted' }, 'sshd -T unavailable')],
      ssh.available ? ['Root login', badge(ssh.permit_root_login === 'yes' ? 'warning' : 'ok', ssh.permit_root_login)] : null,
      ssh.available ? ['Password auth', badge(ssh.password_auth === 'yes' ? 'info' : 'ok', ssh.password_auth === 'yes' ? 'enabled' : 'disabled (keys only)')] : null,
      ssh.available ? ['Max auth tries', ssh.max_auth_tries] : null,
      ['fail2ban', f2b.running && f2b.detail_unavailable ? badge('ok', 'running (jail details need root)') : f2b.running ? badge('ok', `running · ${jails.length} jail(s)`) : badge(f2b.installed ? 'warning' : 'info', f2b.installed ? 'installed but not running' : 'not installed')],
    ]),
    jails.length ? h('div', { style: { marginTop: '12px' } }, table([{ label: 'Jail' }, { label: 'Banned now', num: true }, { label: 'Banned total', num: true }, { label: 'Failed total', num: true }],
      jails.map(j => [j.name, num(j.currently_banned), num(j.total_banned), num(j.total_failed)]))) : null,
    fw.detail && fw.detail.length ? h('details', { class: 'more' }, h('summary', null, 'Firewall rules'),
      h('pre', { class: 'mono small', style: { whiteSpace: 'pre-wrap', margin: '4px 8px' } }, fw.detail.join('\n'))) : null);

  const ports = sec.ports || [];
  const portsCard = card('span-12',
    h('div', { class: 'card-head' }, h('h3', null, 'Listening ports'),
      h('span', { class: 'muted small' }, `${ports.filter(p => p.public).length} reachable from outside · ${ports.filter(p => p.unexpected).length} unexpected`)),
    table([{ label: 'Port' }, { label: 'Process' }, { label: 'Bound to' }, { label: 'Exposure' }],
      ports.map(p => ({
        cls: p.unexpected ? 'flag' : null,
        cells: [h('span', { class: 'mono' }, `${p.port}/${p.proto}`), (p.process || []).join(', ') || h('span', { class: 'muted' }, 'unknown'),
          h('span', { class: 'mono small' }, p.addresses.join('  ')),
          p.unexpected ? badge('warning', 'Public · unexpected') : p.public ? badge('ok', 'Public · expected') : h('span', { class: 'muted' }, 'Local only')],
      })), 'Port list unavailable (needs ss and root).'));

  return h('div', { class: 'grid' }, updatesCard, hardening, portsCard);
}

function checkBadge(c, external) {
  if (!c) return h('span', { class: 'muted' }, '–');
  const where = external ? 'Checked from this network' : 'Checked from the server itself';
  if (c.status === 401 || c.status === 403) return h('span', { title: `${where}: no index page or access restricted` }, badge('warning', `${c.status} · restricted`));
  if (!c.ok) return h('span', { title: `${where}: ${c.error || ''}` }, badge('critical', c.status ? `HTTP ${c.status}` : 'Down'));
  return h('span', { title: where }, badge(c.ms > 2000 ? 'warning' : 'ok', `${c.status} · ${num(c.ms)} ms`));
}
const externalCheck = (d, url) => ((d.poller && d.poller.external) || []).find(c => c.url === url);

function siteDetail(st, gen, color) {
  const { labels, full } = hourLabels(gen);
  return h('div', { class: 'list-cols' },
    h('div', { style: { gridColumn: '1 / -1' } },
      h('h3', { style: { marginBottom: '6px' } }, 'Requests per hour · last 24 h'),
      chartSlot(el => columnChart(el, { labels, full, height: 140, series: [{ name: 'requests', color, values: st.hourly_requests }], label: 'Requests per hour' }))),
    topList('Top pages (human, 24 h)', st.top_pages),
    topList('Top referrers', st.top_referrers),
    topList('Most frequent 404s', st.top_404),
    topList('Busiest IPs', st.top_ips));
}

function renderWebsites(d) {
  const web = d.web;
  if (!web) return unavailable('Web traffic');
  const gen = d.generated_at, hc = web.hourly_by_class || {};
  const { labels, full } = hourLabels(gen);
  const series = [
    { name: 'People', color: 'var(--s1)', values: hc.human || [] },
    { name: 'Bots & crawlers', color: 'var(--s2)', values: hc.bot || [] },
    { name: 'Vulnerability scanners', color: 'var(--s3)', values: hc.scanner || [] },
  ];
  const hourly = chartBlock('Requests per hour · all sites · last 24 h', null, series, 'bar',
    el => columnChart(el, { labels, full, series, label: 'Requests per hour by visitor type' }),
    [{ label: 'Hour' }, ...series.map(sr => ({ label: sr.name, num: true }))],
    labels.map((_, i) => [full[i], ...series.map(sr => num(sr.values[i]))]).reverse());

  const tot = web.totals || {};
  const nd = (tot.daily_pageviews || []).length;
  const dl = dayLabels(gen, nd);
  const dSeries = [{ name: 'Page views', color: 'var(--s1)', values: tot.daily_pageviews || [] }];
  const daily = chartBlock('Page views per day', 'Human visits to pages, all sites', dSeries, 'bar',
    el => columnChart(el, { labels: dl.labels, full: dl.full, series: dSeries, label: 'Page views per day' }),
    [{ label: 'Day' }, { label: 'Page views', num: true }, { label: 'Visitors', num: true }, { label: 'Requests', num: true }],
    dl.labels.map((_, i) => [dl.full[i], num(tot.daily_pageviews[i]), num(tot.daily_visitors[i]), num(tot.daily_requests[i])]).reverse());

  const sites = web.main.sites || [];
  const rows = sites.map(si => {
    const st = si.stats, err4 = (st.status_24h || {})['4xx'] || 0, err5 = (st.status_24h || {})['5xx'] || 0;
    const botPct = st.requests_24h ? Math.round(100 * (st.bot_requests_24h + st.scanner_requests_24h) / st.requests_24h) : 0;
    return {
      key: 'site:' + si.name,
      cls: si.check && !si.check.ok ? 'flag' : null,
      cells: [
        h('div', null, h('a', { href: si.url, target: '_blank', rel: 'noopener' }, si.name === '/' ? 'Home page (root)' : si.name), ' ', siteTags(st),
          h('div', { class: 'muted small mono' }, si.path)),
        externalCheck(d, si.url) ? checkBadge(externalCheck(d, si.url), true) : checkBadge(si.check),
        compact(st.pageviews_24h), compact(st.visitors_24h), compact(st.requests_24h), botPct + '%',
        err4 ? compact(err4) : '0', err5 ? h('strong', { style: { color: 'var(--crit-text)' } }, compact(err5)) : '0',
        sparkline(st.daily_pageviews, 'var(--s1)', 96, 24, `Page views per day for 7 days: ${st.daily_pageviews.join(', ')}`),
        h('span', { class: 'nowrap' }, ago(st.last_ok)),
      ],
      detail: () => siteDetail(st, gen, 'var(--s1)'),
    };
  });

  return h('div', { class: 'grid' },
    card('span-8', hourly),
    card('span-4', daily),
    card('span-12',
      h('div', { class: 'card-head' }, h('h3', null, `Sites under ${web.main.root}`),
        h('span', { class: 'muted small' }, 'Click a row for hourly traffic, top pages, referrers and 404s')),
      table([{ label: 'Site' }, { label: 'Online' }, { label: 'Page views', num: true }, { label: 'Visitors', num: true },
        { label: 'Requests', num: true }, { label: 'Bots', num: true }, { label: '4xx', num: true }, { label: '5xx', num: true },
        { label: 'Page views · 7 days' }, { label: 'Last visit' }], rows, 'No sub folder sites found.'),
      h('p', { class: 'card-sub', style: { margin: '10px 0 0' } },
        'All counts are for the last 24 hours. Page views and visitors count people only (bots, crawlers and scanners excluded); visitors are unique IP addresses.')));
}

function exposureChips(o) {
  const ex = o.exposure || [];
  if (!ex.length) return [chip('Not configured in web server')];
  return ex.map(e => chip(e.type === 'vhost' ? `vhost ${e.via}${e.default ? ' (default server)' : ''}`
    : e.type === 'alias' ? `alias ${e.url_path} on ${e.via}` : `path ${e.url_path} on ${e.via}`, { class: 'chip strong' }));
}

function renderHidden(d) {
  const web = d.web;
  if (!web) return unavailable('Web traffic');
  const others = web.others || [];
  const rows = others.map(o => {
    const st = o.stats;
    let status;
    if (o.intended_public) status = badge('info', 'Public (intended)');
    else if (o.flagged && !st.ok_requests_24h) status = badge('warning', 'Answers publicly');
    else if (o.flagged) status = badge('warning', 'Receiving traffic');
    else if ((o.exposure || []).length) status = badge('info', 'Reachable, quiet');
    else status = badge('ok', 'Not exposed');
    const pub = (o.checks || []).map(c => chip([icon(c.ok ? 'warning' : 'ok', 12), ` ${c.url} → ${c.status || c.error || 'no answer'}`]));
    return {
      key: 'other:' + o.name,
      cls: o.flagged ? 'flag' : null,
      cells: [h('div', null, h('span', { class: 'mono' }, o.name), ' ', siteTags(st), o.exists ? null : h('div', { class: 'muted small' }, 'directory not present')),
        status, h('div', { class: 'chips' }, exposureChips(o), pub),
        compact(st.ok_requests_24h), compact(st.requests_24h), compact(st.ok_ips_24h), compact(st.probes_24h), compact(st.requests_7d),
        h('span', { class: 'nowrap' }, ago(st.last_seen))],
      detail: () => h('div', null,
        h('h3', { style: { marginBottom: '6px' } }, 'Most recent requests'),
        table([{ label: 'Time' }, { label: 'IP' }, { label: 'Request' }, { label: 'Status', num: true }, { label: 'User agent' }],
          (st.recent || []).map(r => [h('span', { class: 'nowrap' }, when(r[0])), h('span', { class: 'mono' }, r[1]),
            h('span', { class: 'mono small break' }, `${r[2]} ${r[3]}`), r[4], h('span', { class: 'small muted break' }, r[5])]), 'No requests in the last 7 days.'),
        h('div', { class: 'list-cols', style: { marginTop: '12px' } }, topList('IPs in the last 24 h', st.top_ips), topList('Top pages', st.top_pages))),
    };
  });
  return h('div', { class: 'grid' }, card('span-12',
    h('div', { class: 'card-head' }, h('h3', null, `Other directories in ${d.web.main.root.replace(/\/[^/]+$/, '') || '/var/www'}`),
      h('span', { class: 'muted small' }, 'Sites that are not meant to be public. Any successful request means they are still reachable.')),
    table([{ label: 'Directory' }, { label: 'Status' }, { label: 'How it is reachable' }, { label: 'Served OK', num: true },
      { label: 'All requests', num: true }, { label: 'IPs', num: true }, { label: 'Probes', num: true }, { label: 'Requests · 7 d', num: true }, { label: 'Last request' }],
      rows, 'No other directories found.'),
    h('p', { class: 'card-sub', style: { margin: '10px 0 0' } },
      '"Served OK" counts 2xx/304 responses in 24 h. "Probes" counts requests for /<name>/ on another site, e.g. someone guessing the folder exists. ' +
      'Mark a directory as intentionally public with public_www_dirs in the collector config.')));
}

function renderLogins(d) {
  const lg = d.logins;
  if (!lg) return unavailable('Login');
  const f2b = (d.security || {}).fail2ban || {};
  const bannedNow = (f2b.jails || []).reduce((a, j) => a + j.currently_banned, 0);
  const n = lg.daily_failed.length, dl = dayLabels(d.generated_at, n);
  const series = [{ name: 'Failed logins', color: 'var(--s1)', values: lg.daily_failed }];
  const chart = chartBlock('Failed SSH logins per day', `Average ${num(lg.avg_failed_per_day)} per day before today`, series, 'bar',
    el => columnChart(el, { labels: dl.labels, full: dl.full, series, label: 'Failed SSH logins per day', height: 170 }),
    [{ label: 'Day' }, { label: 'Failed logins', num: true }], dl.labels.map((_, i) => [dl.full[i], num(lg.daily_failed[i])]).reverse());

  const flagNames = { 'new-ip': ['warning', 'New IP'], root: ['warning', 'Root'], password: ['info', 'Password'], 'after-failures': ['critical', 'After failed attempts'] };
  const succ = table([{ label: 'When' }, { label: 'User' }, { label: 'From' }, { label: 'Method' }, { label: 'Notes' }],
    lg.successful.map(x => ({
      cls: x.flags.some(f => f === 'after-failures' || f === 'new-ip') ? 'flag' : null,
      cells: [h('span', { class: 'nowrap' }, when(x.ts)), h('strong', null, x.user), h('span', { class: 'mono' }, x.ip), x.method,
        h('div', { class: 'chips' }, x.flags.map(f => chip([icon(flagNames[f][0], 12), ' ' + flagNames[f][1]])),
          x.trusted ? chip('Trusted IP') : null, x.prior_failures ? chip(`${x.prior_failures} earlier failures from this IP`) : null)],
    })), 'No successful SSH logins in the lookback window.');

  const attackers = table([{ label: 'IP' }, { label: 'Attempts', num: true }, { label: 'User names tried' }, { label: 'Last seen' }, { label: 'fail2ban' }],
    lg.top_attackers.map(a => [h('span', { class: 'mono' }, a.ip), num(a.count), h('span', { class: 'mono small' }, a.users.join(', ')),
      h('span', { class: 'nowrap' }, ago(a.last)), a.banned ? badge('ok', 'Banned') : h('span', { class: 'muted' }, '–')]), 'No failed logins in 24 h.');

  return h('div', { class: 'grid' },
    h('div', { class: 'tiles span-12' },
      tile('Failed logins · 24 h', compact(lg.failed_24h), null, `${compact(lg.failed_7d)} in 7 days`, { level: lg.surge ? 'warning' : null }),
      tile('Attacking IPs · 24 h', compact(lg.unique_ips_24h), null, `${compact(lg.invalid_user_24h)} tries used non-existent users`),
      tile('SSH probes · 24 h', compact(lg.ssh_probes_24h), null, 'Port scans and broken handshakes'),
      tile('Banned by fail2ban', f2b.running ? compact(bannedNow) : '–', null, f2b.running ? 'Currently blocked IPs' : 'fail2ban is not running', { level: f2b.running ? null : 'info' }),
      tile('sudo · 24 h', compact(lg.sudo_commands_24h), null, `${lg.sudo_failures.filter(x => x.ts > d.generated_at - 86400).length} failed attempt(s)`)),
    card('span-5', chart),
    card('span-7', h('div', { class: 'card-head' }, h('h3', null, 'Successful SSH logins'), h('span', { class: 'muted small' }, 'Last 7 days, newest first')), succ,
      lg.monitor && lg.monitor.last ? h('p', { class: 'card-sub', style: { margin: '10px 0 0' } },
        `Not listed: ${num(lg.monitor.logins_24h)} routine poller logins in 24 h (last ${ago(lg.monitor.last)}, from ${lg.monitor.ips.join(', ')}). ` +
        'A poller login from a new IP or after failed attempts is still listed and alerted.') : null),
    card('span-8', h('div', { class: 'card-head' }, h('h3', null, 'Top attacking IPs · 24 h')), attackers),
    card('span-4', topList('User names tried · 24 h', lg.top_usernames),
      h('div', { style: { marginTop: '14px' } }, topList('Repeat offenders · 7 days', lg.repeat_offenders_7d))),
    lg.sudo_failures.length || lg.su_failures.length ? card('span-12', h('div', { class: 'card-head' }, h('h3', null, 'Failed sudo / su attempts')),
      table([{ label: 'When' }, { label: 'Detail' }], lg.sudo_failures.concat(lg.su_failures).sort((a, b) => b.ts - a.ts)
        .map(x => [h('span', { class: 'nowrap' }, when(x.ts)), h('span', { class: 'mono small break' }, x.message)]))) : null);
}

function renderProbes(d) {
  const web = d.web;
  if (!web) return unavailable('Web traffic');
  const sc = web.scanners || {};
  return h('div', { class: 'grid' },
    card('span-12', h('div', { class: 'card-head' }, h('h3', null, `${num(sc.hits_24h)} vulnerability probes in the last 24 h`),
      h('span', { class: 'muted small' }, 'Requests for WordPress, PHP, .env, .git and similar files that a static site never serves. Normal internet background noise - watch for spikes or 200 responses.')),
      h('div', { class: 'list-cols' },
        topList('Most probed paths', sc.top_paths),
        topList('Most active scanner IPs', sc.top_ips),
        topList('Busiest IPs overall (all requests)', (web.totals || {}).top_ips),
        topList('Request methods used by scanners', sc.methods))));
}

function renderTLS(d) {
  const tls = d.tls || [];
  return h('div', { class: 'grid' }, card('span-12',
    h('div', { class: 'card-head' }, h('h3', null, 'TLS certificates')),
    table([{ label: 'Domain' }, { label: 'Status' }, { label: 'Days left', num: true }, { label: 'Expires' }, { label: 'Issuer' }],
      tls.map(c => ({
        cls: !c.valid || c.days_left < 14 ? 'flag' : null,
        cells: [h('span', { class: 'mono' }, c.domain),
          c.valid ? badge(c.days_left < 5 ? 'critical' : c.days_left < 14 ? 'warning' : 'ok', 'Valid') : badge('warning', c.error || 'Invalid'),
          c.days_left == null ? '–' : Math.floor(c.days_left), c.expires ? when(c.expires) : '–', c.issuer || '–'],
      })), 'No HTTPS sites found.')));
}

function renderFooter(d) {
  const web = d.web || {};
  const f = document.getElementById('footer');
  const p = d.poller, tp = p && p.tabletpanel;
  f.replaceChildren(
    d.generated_at ? h('div', null, `Collector v${d.version} · ran on the server ${when(d.generated_at)} in ${num(d.duration_ms)} ms · `,
      h('a', { href: STATUS_URL, target: '_blank' }, 'raw JSON')) : null,
    p ? h('div', null, `Poller v${p.version} on ${p.poller_host} · ${p.via} every ${Math.round(p.interval_seconds / 60)} min · last attempt ${when(p.last_attempt)}` +
      ` (${p.fresh ? `ok, ${num(p.duration_ms)} ms` : 'failed'}) · last success ${when(p.last_success)}`) : null,
    tp ? h('div', null, tp.enabled === false ? 'Alert forwarding to tebletpanel is off.'
      : tp.ok ? `tebletpanel: ${tp.active} alert(s) on displays (+${tp.posted} posted, −${tp.cleared} cleared this poll)`
        : `tebletpanel: forwarding failed - ${tp.error}`) : null,
    (web.notes || []).length ? h('details', { open: true }, h('summary', null, 'Notes on traffic attribution'), h('ul', null, web.notes.map(n => h('li', null, n)))) : null,
    h('details', null, h('summary', null, `Virtual hosts discovered (${(web.vhosts || []).length})`),
      h('ul', null, (web.vhosts || []).map(v => h('li', { class: 'mono' }, `[${v.server}] ${v.names.join(' ') || '(no name)'} → ${v.root || '(no root)'} · listen ${v.listen.join(', ')}${v.default ? ' · default' : ''} · logs ${v.logs.join(', ') || 'none'}`)))),
    h('details', null, h('summary', null, `Log files parsed (${(web.log_files || []).length})`),
      h('ul', null, (web.log_files || []).map(l => h('li', { class: 'mono' }, `${l.path} · ${num(l.lines)} lines in window · ${bytes(l.bytes)}`)))),
    (d.errors || []).length ? h('details', { open: true }, h('summary', null, `Collector errors (${d.errors.length})`), h('ul', null, d.errors.map(e => h('li', { class: 'mono' }, e)))) : null);
}

// ------------------------------------------------------------------ page

function runCharts() {
  const q = chartQueue; chartQueue = [];
  q.forEach(fn => fn());
}

/* The page is served on the LAN; the local poller fetches the data over SSH.
   Distinguish: dashboard offline, poller stopped, SSH failing, server down. */
function pollerStopped(d) {
  const p = d.poller;
  if (!p) return Date.now() / 1000 - d.generated_at > Math.max(900, (d.interval_seconds || 300) * 3);
  return Date.now() / 1000 - p.last_attempt > Math.max(900, (p.interval_seconds || 300) * 3);
}

function overallState(d) {
  if (!d) return fetchError ? { level: 'critical', text: 'Dashboard offline' } : { level: 'info', text: 'Loading' };
  const p = d.poller;
  if (fetchError) return { level: 'critical', text: 'Dashboard offline' };
  if (p && p.server_down) return { level: 'critical', text: 'Server down' };
  if (pollerStopped(d)) return { level: 'critical', text: 'Poller stopped' };
  if (p && !p.fresh && p.consecutive_failures >= 2) return { level: 'warning', text: 'Not reporting' };
  if (!d.generated_at) return { level: 'info', text: 'Waiting for data' };
  return { level: d.overall === 'ok' ? 'ok' : d.overall, text: { ok: 'Healthy', warning: 'Needs attention', critical: 'Problem' }[d.overall] || d.overall };
}

function bannerText(d) {
  const p = d && d.poller;
  if (fetchError) return `Cannot load status.json from the local web server (${fetchError}). Is the poller (local/poller.mjs) running?${d && d.generated_at ? ` Showing data from ${ago(d.generated_at)}.` : ''}`;
  if (!d) return null;
  if (pollerStopped(d)) return `The local poller has not run since ${when(p ? p.last_attempt : d.generated_at)}. Start it with: node local/poller.mjs start`;
  if (!p || p.fresh || !p.consecutive_failures) return null;
  const since = p.last_success ? `since ${when(p.last_success)}` : 'yet';
  if (p.server_down) return `${p.host} appears to be DOWN: SSH has failed ${p.consecutive_failures} times ${since} and the website does not answer from here (${p.error}).`;
  return `Cannot collect telemetry over SSH (${p.consecutive_failures} failed attempt${p.consecutive_failures > 1 ? 's' : ''} ${since}): ${p.error}. ` +
    `Website from here: ${p.site_up ? 'up' : p.site_up === false ? 'DOWN' : 'unknown'}.${d.generated_at ? ` Figures below are from ${ago(d.generated_at)}.` : ''}`;
}

function renderHeader() {
  const d = DATA;
  const st = overallState(d);
  document.getElementById('overall').replaceChildren(icon(st.level, 16), st.text);
  document.title = `${st.level === 'ok' ? '✓' : st.level === 'critical' ? '✕' : '!'} Server Status${DATA && DATA.poller && DATA.poller.site_name ? ' · ' + DATA.poller.site_name : ''}`;
  const banner = document.getElementById('banner');
  const msg = bannerText(d);
  banner.hidden = !msg;
  if (msg) banner.replaceChildren(icon(st.level === 'warning' ? 'warning' : 'critical', 16), h('span', null, msg));
  if (!d) return;
  const p = d.poller;
  document.getElementById('host').textContent = (d.system && d.system.hostname) || (p && (p.site_name || p.host)) || 'Server status';
  document.getElementById('updated').textContent = d.generated_at
    ? `Data from ${ago(d.generated_at)} · ${when(d.generated_at)}${p ? ` · polled ${ago(p.last_attempt)} via ${p.via}` : ''}`
    : `No data yet${p ? ` · last attempt ${ago(p.last_attempt)}` : ''}`;
}

function render() {
  renderHeader();
  const d = DATA;
  const app = document.getElementById('app');
  app.classList.toggle('stale', !!fetchError);
  if (!d || !d.generated_at) {
    const why = d && d.poller ? `Last attempt ${ago(d.poller.last_attempt)}: ${d.poller.error || 'no error reported'}` : 'Run: node local/poller.mjs once';
    if (fetchError || d) app.replaceChildren(card('', h('p', { class: 'empty' }, `No telemetry has been collected yet. ${why}`)));
    if (d) renderFooter(d);
    return;
  }
  const y = window.scrollY;
  chartQueue = [];
  app.replaceChildren(
    section('overview', 'Overview', null, h('div', { class: 'grid' }, renderAlerts(d), renderOverview(d))),
    section('system', 'System', d.system ? `${d.system.os} · ${d.system.cpu_count} cores` : null, renderSystem(d)),
    section('security', 'Security & updates', null, renderSecurity(d)),
    section('websites', 'Websites', d.web ? d.web.main.url : null, renderWebsites(d)),
    section('hidden', 'Hidden sites', 'Traffic to other sites in /var/www', renderHidden(d)),
    section('logins', 'Logins', 'SSH, sudo and su activity', renderLogins(d)),
    section('probes', 'Web probes', null, renderProbes(d)),
    section('tls', 'Certificates', null, renderTLS(d)));
  renderFooter(d);
  runCharts();
  // A link to a section (e.g. /statuspanel/#security from an alert's help) jumps there once it exists.
  if (!render.jumped && location.hash) {
    render.jumped = true;
    document.getElementById(location.hash.slice(1))?.scrollIntoView();
  } else {
    window.scrollTo(0, y);
  }
}

async function load() {
  try {
    const r = await fetch(STATUS_URL + '?t=' + Date.now(), { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    DATA = await r.json();
    fetchError = null;
  } catch (e) {
    fetchError = e.message || String(e);
  }
  render();
}

document.body.append(tip);
document.getElementById('refresh').addEventListener('click', load);
let resizeTimer;
window.addEventListener('resize', () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => DATA && render(), 200); });
setInterval(load, REFRESH_MS);
setInterval(() => DATA && renderHeader(), 15000);
load();

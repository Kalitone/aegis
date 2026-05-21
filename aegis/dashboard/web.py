"""
AEGIS Web Dashboard — Operator Console
=======================================
FastAPI + HTMX + Alpine.js. Loopback only, single operator, no auth.

Routes:
  /                      live event stream + inspector (SSE-driven)
  /findings              detection table, multi-select bulk actions
  /cases                 case rollup grouped by case_id
  /cases/{case_id}       single-case event timeline
  /quarantine            quarantined files, typed-confirm purge
  /coverage              MITRE ATT&CK matrix
  /integrity             chain + manifest verifier
  /static/aegis.css      single stylesheet
  /api/statusbar         top status bar HTML (poll 2s)
  /api/events            event stream rows HTML (one-shot history)
  /api/events/stream     SSE push stream for the live page
  /api/event/{id}        inspector pane HTML for a single event
  /api/sparkline         inline-SVG event-rate sparkline
  /api/health            JSON health snapshot
  /quarantine/delete     POST single delete
  /quarantine/purge      POST typed-confirm bulk purge
"""

from __future__ import annotations

import os
import json
import time
import socket
import logging
import threading
from pathlib import Path

from aegis.core import EventBus

logger = logging.getLogger("aegis.dashboard.web")

try:
    from fastapi import FastAPI, Form, HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FastAPI = None  # type: ignore
    FASTAPI_AVAILABLE = False


# ── Severity → single-glyph + accent colour ───────────────────────
SEV_GLYPH = {"critical": "C", "high": "H", "medium": "M", "low": "L", "info": "I"}
SEV_RANK  = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# ══════════════════════════════════════════════════════════════════
# Stylesheet — served as /static/aegis.css
# ══════════════════════════════════════════════════════════════════
AEGIS_CSS = """
:root {
  --bg:        #070a0f;
  --bg-1:     #0d1219;
  --bg-2:     #121823;
  --line:     rgba(255,255,255,0.06);
  --line-2:   rgba(255,255,255,0.10);
  --text:     #d6dde8;
  --muted:    #8b95a7;
  --dim:      #5a6477;
  --amber:    #ffb020;
  --red:      #ff4d4d;
  --cyan:     #4dd0e1;
  --green:    #5be584;
  --mono:     "JetBrains Mono","IBM Plex Mono",ui-monospace,Consolas,monospace;
  --sans:     "Inter",ui-sans-serif,-apple-system,sans-serif;
}
* { box-sizing: border-box; }
html, body { margin:0; padding:0; height:100%; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--mono);
  font-size: 12px;
  font-variant-numeric: tabular-nums;
  -webkit-font-smoothing: antialiased;
  overflow: hidden;
}

/* ── Layout shell ── */
.shell { display: grid; grid-template-columns: 52px 1fr; grid-template-rows: 32px 1fr; height:100vh; }
.statusbar { grid-column: 1 / -1; }
.rail      { grid-row: 2; }
.workspace { grid-row: 2; display:flex; min-width:0; }
.main      { flex: 1 1 auto; min-width:0; display:flex; flex-direction:column; overflow:hidden; }
.inspector { flex: 0 0 40%; max-width:560px; min-width:360px; border-left:1px solid var(--line);
             background: var(--bg-1); overflow-y:auto; display:none; }
.inspector.open { display:block; }

/* ── Top status bar ── */
.statusbar {
  display:flex; align-items:center; gap:18px;
  background: var(--bg-1);
  border-bottom: 1px solid var(--line);
  padding: 0 14px;
  font-size: 11px; letter-spacing: 0.04em;
}
.sb-brand { color: var(--text); font-family: var(--sans); font-weight:600; letter-spacing:0.18em; }
.sb-brand .v { color: var(--dim); margin-left:6px; font-weight:400; }
.sb-cell { display:flex; align-items:center; gap:6px; color: var(--muted); }
.sb-cell b { color: var(--text); font-weight:500; }
.sb-cell.crit b { color: var(--red); }
.sb-cell.warn b { color: var(--amber); }
.sb-cell.ok   b { color: var(--green); }
.sb-spacer { flex:1; }
.dot { width:6px; height:6px; border-radius:50%; display:inline-block; }
.dot.ok { background: var(--green); }
.dot.bad { background: var(--red); box-shadow: 0 0 6px var(--red); }
.dot.warn { background: var(--amber); }
.spark { display:inline-block; vertical-align:middle; }

/* ── Left rail ── */
.rail {
  background: var(--bg-1);
  border-right: 1px solid var(--line);
  display:flex; flex-direction:column; align-items:center;
  padding: 8px 0; gap:2px;
}
.rail a {
  width: 36px; height: 36px;
  display:flex; align-items:center; justify-content:center;
  color: var(--dim); text-decoration:none;
  border-left: 2px solid transparent;
  position: relative;
}
.rail a:hover { color: var(--text); background: var(--bg-2); }
.rail a.active { color: var(--cyan); border-left-color: var(--cyan); background: var(--bg-2); }
.rail a svg { width:16px; height:16px; stroke-width:1.5; fill:none; stroke:currentColor; }
.rail a[data-tip]:hover::after {
  content: attr(data-tip);
  position: absolute; left: 44px; top: 50%; transform: translateY(-50%);
  background: var(--bg-2); border:1px solid var(--line-2);
  padding: 4px 8px; font-size: 10px; color: var(--text);
  white-space: nowrap; letter-spacing: 0.08em; text-transform: uppercase;
  z-index: 100;
}

/* ── Page chrome ── */
.page-head {
  display:flex; align-items:center; gap:14px;
  padding: 8px 14px;
  border-bottom: 1px solid var(--line);
  background: var(--bg-1);
  flex: 0 0 auto;
}
.page-head h2 {
  margin:0; font-family: var(--sans); font-weight:500; font-size: 12px;
  letter-spacing: 0.22em; text-transform: uppercase; color: var(--text);
}
.page-head .meta { color: var(--muted); font-size: 11px; letter-spacing:0.06em; }
.page-head .tools { margin-left:auto; display:flex; gap:6px; align-items:center; }

/* ── Filter bar ── */
.filter {
  display:flex; align-items:center; gap:10px;
  padding: 6px 14px; background: var(--bg-1);
  border-bottom: 1px solid var(--line); flex: 0 0 auto;
}
.filter input[type=text] {
  flex:1; min-width:120px; background: var(--bg); color: var(--text);
  border: 1px solid var(--line-2); padding: 4px 8px; font-family: var(--mono);
  font-size: 12px; outline:none;
}
.filter input[type=text]:focus { border-color: var(--cyan); }
.chip {
  display:inline-flex; align-items:center; gap:4px;
  border: 1px solid var(--line-2); padding: 2px 8px;
  font-size: 10px; letter-spacing: 0.12em; text-transform: uppercase;
  color: var(--muted); cursor: pointer; user-select:none;
}
.chip.on { color: var(--text); border-color: var(--cyan); background: rgba(77,208,225,0.08); }
.chip[data-sev=critical].on { border-color: var(--red); background: rgba(255,77,77,0.08); color: var(--red); }
.chip[data-sev=high].on     { border-color: var(--amber); background: rgba(255,176,32,0.08); color: var(--amber); }
.chip[data-sev=medium].on   { border-color: var(--amber); color: var(--amber); }
.chip[data-sev=low].on      { border-color: var(--green); color: var(--green); }
.chip[data-sev=info].on     { border-color: var(--cyan); color: var(--cyan); }

/* ── Stream / table content ── */
.scroll { flex:1 1 auto; overflow-y:auto; }
.table {
  width:100%; border-collapse: collapse;
  table-layout: fixed;
  font-family: var(--mono); font-size: 12px;
}
.table thead th {
  position: sticky; top:0; z-index: 5;
  background: var(--bg-1);
  color: var(--muted); text-align:left;
  font-weight:500; font-size: 10px; letter-spacing: 0.14em; text-transform: uppercase;
  padding: 6px 10px; border-bottom: 1px solid var(--line-2);
}
.table tbody tr {
  height: 24px; border-bottom: 1px solid var(--line);
  border-left: 2px solid transparent;
  cursor: pointer;
}
.table tbody tr:hover { background: var(--bg-1); }
.table tbody tr.sel { background: var(--bg-2); border-left-color: var(--cyan); }
.table tbody td { padding: 0 10px; vertical-align: middle; white-space: nowrap;
                  overflow:hidden; text-overflow: ellipsis; }
.table thead th { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.table tbody td .ts { color: var(--dim); }
.table tbody td .cat { color: var(--cyan); }
.table tbody td.path { color: var(--muted); }

tr.sev-critical { border-left-color: var(--red) !important; }
tr.sev-high     { border-left-color: var(--amber) !important; }
tr.sev-medium   { border-left-color: var(--amber) !important; opacity: .92; }
tr.sev-low      { border-left-color: var(--green) !important; }
tr.sev-info     { border-left-color: var(--dim) !important; }

/* Severity glyph badge — single char, outlined */
.sev {
  display:inline-block; width:16px; height:16px;
  line-height: 14px; text-align:center;
  border:1px solid currentColor; font-weight:600; font-size:10px;
  font-family: var(--sans);
}
.sev.critical { color: var(--red); }
.sev.high     { color: var(--amber); }
.sev.medium   { color: var(--amber); opacity: .8; }
.sev.low      { color: var(--green); }
.sev.info     { color: var(--dim); }

/* ── Buttons ── */
button, .btn {
  background: transparent; color: var(--muted);
  border: 1px solid var(--line-2);
  padding: 3px 10px; font-family: var(--mono); font-size: 11px;
  letter-spacing: 0.08em; text-transform: uppercase; cursor: pointer;
}
button:hover, .btn:hover { color: var(--text); border-color: var(--text); }
button.danger { color: var(--red); border-color: rgba(255,77,77,0.4); }
button.danger:hover { background: rgba(255,77,77,0.1); border-color: var(--red); }
button.primary { color: var(--cyan); border-color: rgba(77,208,225,0.4); }
button.primary:hover { background: rgba(77,208,225,0.1); border-color: var(--cyan); }

/* ── Inspector ── */
.insp-head {
  padding: 10px 14px; border-bottom: 1px solid var(--line);
  display:flex; align-items:center; gap:10px;
  background: var(--bg-2);
}
.insp-head .sev { margin-right:4px; }
.insp-head h3 { margin:0; font-family: var(--sans); font-weight:500;
                font-size:12px; letter-spacing:0.18em; text-transform: uppercase; }
.insp-head .x { margin-left:auto; cursor:pointer; color: var(--muted); padding: 2px 6px; }
.insp-head .x:hover { color: var(--text); }
.insp-section { padding: 12px 14px; border-bottom: 1px solid var(--line); }
.insp-section h4 {
  margin:0 0 8px; font-family: var(--sans); font-weight:500;
  font-size: 10px; letter-spacing: 0.16em; text-transform: uppercase; color: var(--muted);
}
.kv { display: grid; grid-template-columns: 100px 1fr; gap: 4px 12px; font-size: 11px; }
.kv dt { color: var(--muted); }
.kv dd { margin:0; color: var(--text); word-break: break-all; }
.json {
  background: var(--bg); border: 1px solid var(--line);
  padding: 8px 10px; font-size: 11px; line-height: 1.5;
  white-space: pre-wrap; word-break: break-all;
  max-height: 320px; overflow-y: auto;
}

/* ── Coverage matrix ── */
.matrix { display:flex; gap:1px; padding: 14px; overflow:auto; height:100%; }
.tac-col { display:flex; flex-direction:column; min-width:130px; }
.tac-col h5 {
  margin:0 0 4px; padding: 6px 8px; background: var(--bg-1);
  font-family: var(--sans); font-weight:500; font-size: 10px;
  letter-spacing: 0.14em; text-transform: uppercase; color: var(--muted);
  border-bottom: 1px solid var(--line-2);
}
.tac-col .cell {
  padding: 6px 8px; font-size: 10px; color: var(--dim);
  border-bottom: 1px solid var(--line);
  background: var(--bg-1); cursor: default;
}
.tac-col .cell.cov { color: var(--green); border-left: 2px solid var(--green); }
.tac-col .cell.fired { color: var(--amber); border-left: 2px solid var(--amber);
                       background: rgba(255,176,32,0.04); }
.tac-col .cell.crit  { color: var(--red); border-left: 2px solid var(--red);
                       background: rgba(255,77,77,0.06); }
.tac-col .cell:hover { background: var(--bg-2); color: var(--text); }
.tac-col .cell .tid { font-family: var(--mono); color: inherit; }
.tac-col .cell .nm  { display:block; color: var(--muted); font-size: 9px;
                      overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }

/* ── Integrity / terminal log ── */
.term {
  background: var(--bg); border: 1px solid var(--line);
  padding: 12px 14px; font-size: 12px; line-height: 1.6;
  white-space: pre-wrap; word-break: break-all;
  max-height: 60vh; overflow-y:auto;
}
.term .ok  { color: var(--green); }
.term .bad { color: var(--red); }
.tamper-card {
  background: rgba(255,77,77,0.06); border: 1px solid rgba(255,77,77,0.4);
  padding: 12px 14px; margin-bottom: 14px; color: var(--red);
}
.tamper-card h4 { margin:0 0 6px; font-family: var(--sans); letter-spacing:0.16em;
                  text-transform:uppercase; font-size:11px; }

/* ── Footer action bar (selection-driven) ── */
.action-bar {
  position: sticky; bottom:0;
  background: var(--bg-2); border-top: 1px solid var(--line-2);
  padding: 8px 14px; display:flex; align-items:center; gap:10px;
  font-size: 11px; color: var(--muted);
}
.action-bar b { color: var(--cyan); }

/* ── Modal (typed confirm) ── */
.modal-bg {
  position: fixed; inset: 0; background: rgba(0,0,0,0.7);
  display:flex; align-items:center; justify-content:center; z-index: 1000;
}
.modal {
  background: var(--bg-1); border: 1px solid var(--red); padding: 20px;
  width: 380px; max-width: 90vw;
}
.modal h3 { margin: 0 0 8px; font-family: var(--sans); color: var(--red);
            letter-spacing: 0.14em; text-transform: uppercase; font-size: 12px; }
.modal p  { color: var(--muted); font-size: 11px; line-height: 1.5; }
.modal input { width:100%; background: var(--bg); border:1px solid var(--line-2);
               color: var(--text); padding: 6px 8px; font-family: var(--mono);
               margin-top:8px; outline:none; }
.modal input:focus { border-color: var(--red); }
.modal .row { display:flex; justify-content:flex-end; gap:8px; margin-top:14px; }

/* ── Empty / paused states ── */
.empty {
  display:flex; flex-direction:column; align-items:center; justify-content:center;
  height: 100%; color: var(--dim); font-size: 11px; letter-spacing: 0.1em;
  text-transform: uppercase;
}
.paused-flag {
  position: absolute; right: 14px; bottom: 14px;
  background: var(--bg-2); border:1px solid var(--amber); color: var(--amber);
  padding: 4px 10px; font-size: 10px; letter-spacing: 0.16em;
  text-transform: uppercase; z-index: 50;
}

/* ── Shortcut overlay ── */
.shortcuts-bg { position:fixed; inset:0; background:rgba(0,0,0,0.7); display:flex;
                align-items:center; justify-content:center; z-index:1000; }
.shortcuts {
  background: var(--bg-1); border: 1px solid var(--line-2);
  padding: 18px 24px; min-width: 360px;
}
.shortcuts h3 { margin: 0 0 12px; font-family: var(--sans); font-weight:500;
                font-size: 12px; letter-spacing: 0.18em; text-transform: uppercase; }
.shortcuts dl { display:grid; grid-template-columns: 80px 1fr; gap: 6px 16px; font-size: 11px; }
.shortcuts dt { color: var(--cyan); font-family: var(--mono); }
.shortcuts dd { margin:0; color: var(--muted); }

/* Scrollbars */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--bg-2); }
::-webkit-scrollbar-thumb:hover { background: var(--line-2); }
"""


# ══════════════════════════════════════════════════════════════════
# Icons (Lucide-style, inline SVG, 1.5px stroke)
# ══════════════════════════════════════════════════════════════════
ICON_LIVE = '<svg viewBox="0 0 24 24"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>'
ICON_FIND = '<svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>'
ICON_QUAR = '<svg viewBox="0 0 24 24"><path d="M3 7h18M5 7v13a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V7M9 7V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v3"/></svg>'
ICON_COV  = '<svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>'
ICON_INTG = '<svg viewBox="0 0 24 24"><path d="M12 2L4 6v6c0 5 3.5 9 8 10 4.5-1 8-5 8-10V6l-8-4z"/></svg>'
ICON_HELP = '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M9.1 9a3 3 0 1 1 5.8 1c0 2-3 3-3 3M12 17h.01"/></svg>'


# ══════════════════════════════════════════════════════════════════
# HTML helpers
# ══════════════════════════════════════════════════════════════════
def _esc(s) -> str:
    """Tiny HTML escape."""
    if s is None:
        return ""
    return (str(s).replace("&","&amp;").replace("<","&lt;")
            .replace(">","&gt;").replace('"',"&quot;"))


def _sev(sev: str) -> str:
    sev = (sev or "info").lower()
    g = SEV_GLYPH.get(sev, "I")
    return f'<span class="sev {sev}" title="{sev}">{g}</span>'


def _ts(t: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(t))


def _ts_full(t: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))


def _short(s, n=80) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[:n-1] + "…"


def _render_event_row(r: dict) -> str:
    """Render one event as the live-stream `<tr>` HTML.

    Shared by the REST `/api/events` initial-load endpoint and the
    SSE `/api/events/stream` push endpoint so both produce the
    exact same DOM and the page's filter chips don't have to know
    where a row came from.
    """
    sev = (r.get("severity") or "info").lower()
    data_str = r.get("data") or ""
    try:
        d = json.loads(data_str) if isinstance(data_str, str) else data_str
    except (TypeError, json.JSONDecodeError):
        d = {}
    summary = (d.get("path") or d.get("cmdline") or d.get("process")
               or d.get("rule_name") or d.get("name") or "")
    text = (str(r.get("source", "")) + " " + str(r.get("category", "")) + " "
            + str(summary)).lower()
    return (
        f'<tr class="sev-{sev}" data-sev="{sev}" data-eid="{_esc(r.get("event_id",""))}" '
        f'data-text="{_esc(text)}" '
        f'onclick="window.aegisInst && window.aegisInst.selectRow(this)">'
        f'<td><span class="ts">{_ts(r["timestamp"])}</span></td>'
        f'<td>{_sev(sev)}</td>'
        f'<td><span class="cat">{_esc(r.get("category",""))}</span></td>'
        f'<td>{_esc(r.get("source",""))}</td>'
        f'<td class="path wide">{_esc(_short(summary, 200))}</td>'
        f'</tr>'
    )


def _rail(active: str) -> str:
    items = [
        ("/",            "live",        "Live", ICON_LIVE),
        ("/findings",    "findings",    "Findings", ICON_FIND),
        ("/cases",       "cases",       "Cases", ICON_FIND),
        ("/quarantine",  "quarantine",  "Quarantine", ICON_QUAR),
        ("/coverage",    "coverage",    "Coverage", ICON_COV),
        ("/integrity",   "integrity",   "Integrity", ICON_INTG),
    ]
    out = ['<aside class="rail">']
    for href, key, tip, ic in items:
        cls = "active" if key == active else ""
        out.append(f'<a href="{href}" class="{cls}" data-tip="{tip}">{ic}</a>')
    out.append('<div style="flex:1"></div>')
    out.append(f'<a href="#" data-tip="Shortcuts (?)" @click.prevent="$store.ui.help=true">{ICON_HELP}</a>')
    out.append('</aside>')
    return "".join(out)


def _statusbar() -> str:
    return ('<div class="statusbar" id="statusbar" '
            'hx-get="/api/statusbar" hx-trigger="load, every 2s" hx-swap="innerHTML">'
            '<span class="sb-brand">AEGIS<span class="v">v0.2</span></span>'
            '<span class="sb-cell">…</span></div>')


def _layout(active: str, page_html: str) -> str:
    return f"""<!doctype html>
<html><head>
<meta charset="utf-8">
<title>AEGIS — {active.title()}</title>
<link rel="stylesheet" href="/static/aegis.css">
<script src="/static/htmx.min.js"></script>
<script defer src="/static/alpine.min.js"></script>
</head>
<body x-data="aegis()" x-init="init()" @keydown.window="onkey($event)">
<div class="shell">
  {_statusbar()}
  {_rail(active)}
  <div class="workspace">
    <div class="main">{page_html}</div>
    <aside class="inspector" :class="{{open: inspectorOpen}}" id="inspector"></aside>
  </div>
</div>

<template x-if="$store.ui.help">
  <div class="shortcuts-bg" @click="$store.ui.help=false">
    <div class="shortcuts" @click.stop>
      <h3>Keyboard</h3>
      <dl>
        <dt>j / k</dt><dd>Move selection down / up</dd>
        <dt>enter</dt><dd>Open inspector for selected row</dd>
        <dt>esc</dt><dd>Close inspector / modal</dd>
        <dt>/</dt><dd>Focus filter input</dd>
        <dt>g e</dt><dd>Go to event stream</dd>
        <dt>g f</dt><dd>Go to findings</dd>
        <dt>g q</dt><dd>Go to quarantine</dd>
        <dt>g c</dt><dd>Go to coverage</dd>
        <dt>g i</dt><dd>Go to integrity</dd>
        <dt>space</dt><dd>Pause / resume live polling</dd>
        <dt>?</dt><dd>This overlay</dd>
      </dl>
    </div>
  </div>
</template>

<script>
function aegis() {{
  return {{
    inspectorOpen: false,
    pendingG: false,
    paused: false,
    init() {{
      Alpine.store('ui', {{ help:false }});
      // Pause-on-hover for the live stream
      document.addEventListener('mouseenter', e => {{
        if (e.target.id === 'stream-scroll') this.paused = true;
      }}, true);
      document.addEventListener('mouseleave', e => {{
        if (e.target.id === 'stream-scroll') this.paused = false;
      }}, true);
    }},
    selectRow(el) {{
      document.querySelectorAll('tr.sel').forEach(r => r.classList.remove('sel'));
      el.classList.add('sel');
      const id = el.dataset.eid;
      if (id) {{
        htmx.ajax('GET', '/api/event/' + id, {{target:'#inspector', swap:'innerHTML'}});
        this.inspectorOpen = true;
      }}
    }},
    closeInspector() {{ this.inspectorOpen = false; }},
    moveSel(dir) {{
      const rows = [...document.querySelectorAll('table.table tbody tr')];
      if (!rows.length) return;
      const cur = document.querySelector('tr.sel');
      let i = cur ? rows.indexOf(cur) : -1;
      i = Math.max(0, Math.min(rows.length-1, i + dir));
      this.selectRow(rows[i]);
      rows[i].scrollIntoView({{block:'nearest'}});
    }},
    onkey(e) {{
      if (e.target.tagName === 'INPUT') return;
      if (e.key === '?') {{ Alpine.store('ui').help = !Alpine.store('ui').help; e.preventDefault(); return; }}
      if (e.key === 'Escape') {{ Alpine.store('ui').help = false; this.closeInspector(); return; }}
      if (e.key === 'j') {{ this.moveSel(1); e.preventDefault(); return; }}
      if (e.key === 'k') {{ this.moveSel(-1); e.preventDefault(); return; }}
      if (e.key === 'Enter') {{ const r = document.querySelector('tr.sel'); if (r) this.selectRow(r); return; }}
      if (e.key === '/') {{
        const f = document.querySelector('input[type=text].filter-input');
        if (f) {{ f.focus(); e.preventDefault(); }} return;
      }}
      if (e.key === ' ') {{
        this.paused = !this.paused;
        const node = document.querySelector('[hx-trigger*="every"]');
        e.preventDefault(); return;
      }}
      if (e.key === 'g') {{ this.pendingG = true; setTimeout(()=>this.pendingG=false,800); return; }}
      if (this.pendingG) {{
        const map = {{e:'/', f:'/findings', q:'/quarantine', c:'/coverage', i:'/integrity'}};
        if (map[e.key]) {{ window.location = map[e.key]; }}
        this.pendingG = false;
      }}
    }},
  }}
}}
</script>
</body></html>"""


# ══════════════════════════════════════════════════════════════════
# App factory
# ══════════════════════════════════════════════════════════════════
def create_app(event_bus: EventBus, config: dict, aegis_ref=None):
    app = FastAPI(title="AEGIS Dashboard", docs_url=None, redoc_url=None)
    quarantine_dir = Path(config.get("core", {}).get("quarantine_dir", "quarantine"))
    hostname = socket.gethostname()
    started_at = time.time()

    # ── Static files ─────────────────────────────────────────────
    @app.get("/static/aegis.css")
    def css():
        return Response(content=AEGIS_CSS, media_type="text/css")

    @app.get("/static/{filename}")
    def static_file(filename: str):
        if filename == "aegis.css":
            return css()
        static_dir = Path(__file__).parent / "static"
        path = static_dir / filename
        if not path.exists() or ".." in filename:
            raise HTTPException(404, "Static file not found")
        media = "text/javascript" if filename.endswith(".js") else "text/css"
        return Response(content=path.read_text(), media_type=media)

    # Warn if JS dependencies are missing
    _static_dir = Path(__file__).parent / "static"
    for _dep in ("htmx.min.js", "alpine.min.js"):
        if not (_static_dir / _dep).exists():
            logger.warning(
                f"Static file missing: {_static_dir / _dep} — "
                f"download it during install for air-gapped operation"
            )

    # ── Page: Live event stream ───────────────────────────────────
    @app.get("/", response_class=HTMLResponse)
    def index():
        body = """
<div class="page-head">
  <h2>Live · Event Stream</h2>
  <span class="meta" id="stream-meta">—</span>
  <div class="tools">
    <span class="meta" id="stream-conn">connecting…</span>
    <button id="pause-btn">Pause</button>
  </div>
</div>
<div class="filter">
  <span class="chip on" data-sev="critical" onclick="this.classList.toggle('on'); refilter()">[C] Critical</span>
  <span class="chip on" data-sev="high"     onclick="this.classList.toggle('on'); refilter()">[H] High</span>
  <span class="chip on" data-sev="medium"   onclick="this.classList.toggle('on'); refilter()">[M] Medium</span>
  <span class="chip"    data-sev="low"      onclick="this.classList.toggle('on'); refilter()">[L] Low</span>
  <span class="chip"    data-sev="info"     onclick="this.classList.toggle('on'); refilter()">[I] Info</span>
  <input class="filter-input" type="text" placeholder="regex / substring filter (path, cmdline, source)…" oninput="refilter()" id="ftext">
</div>
<div class="scroll" id="stream-scroll">
  <table class="table">
    <thead><tr>
      <th style="width:90px">Time</th>
      <th style="width:40px">Sev</th>
      <th style="width:220px">Category</th>
      <th style="width:130px">Source</th>
      <th>Summary</th>
    </tr></thead>
    <tbody id="stream-tbody">
      <tr><td colspan="5"><div class="empty">loading history…</div></td></tr>
    </tbody>
  </table>
</div>
<script>
(function() {
  const tbody = document.getElementById('stream-tbody');
  const conn  = document.getElementById('stream-conn');
  const meta  = document.getElementById('stream-meta');
  const btn   = document.getElementById('pause-btn');
  const MAX_ROWS = 200;
  let es = null;
  let paused = false;
  let received = 0;

  function setConn(text, ok) {
    if (!conn) return;
    conn.textContent = text;
    conn.style.color = ok ? 'var(--green)' : 'var(--amber)';
  }

  function refilter() {
    const on = [...document.querySelectorAll('.chip.on')].map(c => c.dataset.sev);
    const q = (document.getElementById('ftext')?.value || '').toLowerCase();
    document.querySelectorAll('table.table tbody tr').forEach(tr => {
      if (!tr.dataset.sev) return;
      const sev = tr.dataset.sev;
      const txt = tr.dataset.text || '';
      const ok = on.includes(sev) && (!q || txt.includes(q));
      tr.style.display = ok ? '' : 'none';
    });
  }
  window.refilter = refilter;

  function bumpMeta() {
    meta.textContent = received + ' events';
  }

  // Initial history fetch — same endpoint the old polling used, just one-shot.
  fetch('/api/events?limit=120').then(r => r.text()).then(html => {
    const tmp = document.createElement('div');
    tmp.innerHTML = html;
    const newBody = tmp.querySelector('tbody');
    if (newBody) {
      tbody.innerHTML = newBody.innerHTML;
      received = tbody.querySelectorAll('tr[data-sev]').length;
      bumpMeta();
    }
    refilter();
  }).catch(() => {});

  function open() {
    if (es) { try { es.close(); } catch(_) {} }
    setConn('connecting…', false);
    es = new EventSource('/api/events/stream');
    es.onopen = () => setConn('LIVE', true);
    es.onerror = () => setConn('reconnect…', false);
    es.onmessage = (msg) => {
      let payload;
      try { payload = JSON.parse(msg.data); } catch (_) { return; }
      if (!payload.html) return;
      const tmp = document.createElement('tbody');
      tmp.innerHTML = payload.html;
      const tr = tmp.querySelector('tr');
      if (!tr) return;
      // Drop the "loading history" placeholder if present.
      const placeholder = tbody.querySelector('tr td .empty');
      if (placeholder) tbody.innerHTML = '';
      tbody.insertBefore(tr, tbody.firstChild);
      received++;
      while (tbody.querySelectorAll('tr[data-sev]').length > MAX_ROWS) {
        tbody.removeChild(tbody.lastChild);
      }
      bumpMeta();
      refilter();
    };
  }
  open();

  btn.addEventListener('click', () => {
    paused = !paused;
    btn.textContent = paused ? 'Resume' : 'Pause';
    if (paused) {
      if (es) { try { es.close(); } catch(_) {} es = null; }
      setConn('PAUSED', false);
    } else {
      open();
    }
  });

  // Hover-pause: temporarily close the stream so the page doesn't
  // scroll while the operator inspects a row.
  const sc = document.getElementById('stream-scroll');
  if (sc) {
    sc.addEventListener('mouseenter', () => {
      if (!paused && es) { try { es.close(); } catch(_) {} es = null; setConn('hover-pause', false); }
    });
    sc.addEventListener('mouseleave', () => {
      if (!paused && !es) { open(); }
    });
  }
})();
</script>
"""
        return _layout("live", body)

    # ── Page: Cases (event groupings by case_id) ──────────────────
    @app.get("/cases", response_class=HTMLResponse)
    def cases_page(window_h: float = 24.0):
        since = time.time() - max(0.1, window_h) * 3600
        cases = event_bus.list_cases(since=since, limit=500)
        rows = []
        for c in cases:
            sev = c["highest_severity"]
            rows.append(
                f'<tr class="sev-{sev}" data-sev="{sev}" '
                f'data-text="{_esc((c["case_id"] + " " + (c["rule_name"] or "") + " " + (c["original_path"] or "")).lower())}" '
                f'onclick="location.href=\'/cases/{_esc(c["case_id"])}\'">'
                f'<td><span class="ts">{_ts_full(c["last_ts"])}</span></td>'
                f'<td>{_sev(sev)}</td>'
                f'<td><span class="cat">{_esc(c["case_id"][:12])}</span></td>'
                f'<td>{_esc(c["rule_name"] or "—")}</td>'
                f'<td>{_esc(", ".join(c["sources"]) or "—")}</td>'
                f'<td>{c["events"]}</td>'
                f'<td>{_esc(c["mitre_attack"] or "—")}</td>'
                f'<td class="path wide">{_esc(_short(c["original_path"] or "—", 200))}</td>'
                f'</tr>'
            )
        body = f"""
<div class="page-head">
  <h2>Cases · Recent</h2>
  <span class="meta">{len(cases)} case(s) · last {window_h:g} h</span>
  <div class="tools">
    <a href="/cases?window_h=1"  class="chip">1h</a>
    <a href="/cases?window_h=24" class="chip">24h</a>
    <a href="/cases?window_h=168" class="chip">7d</a>
  </div>
</div>
<div class="filter">
  <input class="filter-input" type="text"
         placeholder="filter (case id, rule, target)…"
         oninput="filterCases(this.value)">
</div>
<div class="scroll">
<table class="table">
<thead><tr>
  <th style="width:160px">Last seen</th>
  <th style="width:40px">Sev</th>
  <th style="width:130px">Case</th>
  <th style="width:200px">Rule</th>
  <th style="width:160px">Sources</th>
  <th style="width:60px">Events</th>
  <th style="width:90px">ATT&amp;CK</th>
  <th>Target</th>
</tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="8"><div class="empty">No cases in window.</div></td></tr>'}</tbody>
</table>
</div>
<script>
function filterCases(q) {{
  q = (q || '').toLowerCase();
  document.querySelectorAll('table.table tbody tr').forEach(tr => {{
    if (!tr.dataset.text) return;
    tr.style.display = (!q || tr.dataset.text.includes(q)) ? '' : 'none';
  }});
}}
</script>
"""
        return _layout("cases", body)

    @app.get("/cases/{case_id}", response_class=HTMLResponse)
    def case_detail(case_id: str):
        events = event_bus.query_case_events(case_id, limit=2000)
        if not events:
            body = f"""
<div class="page-head"><h2>Case · {_esc(case_id)}</h2></div>
<div class="empty">No events found for this case.</div>
"""
            return _layout("cases", body)

        first = events[0]
        last = events[-1]
        highest_sev = "info"
        rule_seen = ""
        target_seen = ""
        mitre_seen = ""
        sources_seen: set[str] = set()
        rows = []
        for r in events:
            sev = (r.get("severity") or "info").lower()
            if SEV_RANK.get(sev, 0) > SEV_RANK.get(highest_sev, 0):
                highest_sev = sev
            data_str = r.get("data") or ""
            try:
                d = json.loads(data_str) if isinstance(data_str, str) else data_str
            except (TypeError, json.JSONDecodeError):
                d = {}
            summary = (d.get("action") or d.get("rule_name") or d.get("rule")
                       or d.get("path") or d.get("original_path")
                       or d.get("cmdline") or "")
            if not rule_seen and (d.get("rule_name") or d.get("rule")):
                rule_seen = d.get("rule_name") or d.get("rule")
            if not target_seen:
                target_seen = (d.get("original_path") or d.get("filepath")
                               or d.get("path") or "")
            if not mitre_seen and r.get("mitre_attack"):
                mitre_seen = r.get("mitre_attack")
            sources_seen.add(r.get("source") or "")
            rows.append(
                f'<tr class="sev-{sev}" data-eid="{_esc(r.get("event_id",""))}" '
                f'onclick="window.aegisInst && window.aegisInst.selectRow(this)">'
                f'<td><span class="ts">{_ts_full(r["timestamp"])}</span></td>'
                f'<td>{_sev(sev)}</td>'
                f'<td><span class="cat">{_esc(r.get("category",""))}</span></td>'
                f'<td>{_esc(r.get("source",""))}</td>'
                f'<td class="path wide">{_esc(_short(summary, 240))}</td>'
                f'</tr>'
            )

        sources_str = ", ".join(sorted(s for s in sources_seen if s)) or "—"
        body = f"""
<div class="page-head">
  <h2>Case · {_esc(case_id)}</h2>
  <span class="meta">
    {len(events)} events ·
    {_ts_full(first["timestamp"])} → {_ts_full(last["timestamp"])} ·
    highest <b>{_esc(highest_sev)}</b> ·
    sources <b>{_esc(sources_str)}</b>
  </span>
</div>
<div class="page-head" style="opacity:.85; padding-top:0">
  <span class="meta">Rule: <b>{_esc(rule_seen or "—")}</b></span>
  <span class="meta">ATT&amp;CK: <b>{_esc(mitre_seen or "—")}</b></span>
  <span class="meta">Target: <b>{_esc(_short(target_seen or "—", 160))}</b></span>
  <div class="tools">
    <a href="/cases" class="chip">← All cases</a>
  </div>
</div>
<div class="scroll">
<table class="table">
<thead><tr>
  <th style="width:160px">Time</th>
  <th style="width:40px">Sev</th>
  <th style="width:220px">Category</th>
  <th style="width:130px">Source</th>
  <th>Detail</th>
</tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
</div>
<script>
window.aegisInst = window.aegisInst || {{ selectRow: el => {{
  document.querySelectorAll('tr.sel').forEach(r => r.classList.remove('sel'));
  el.classList.add('sel');
  const id = el.dataset.eid;
  if (id) {{
    htmx.ajax('GET', '/api/event/' + id, {{target:'#inspector', swap:'innerHTML'}});
    document.querySelector('.inspector').classList.add('open');
  }}
}}}};
</script>
"""
        return _layout("cases", body)

    # ── Page: Findings (detection table) ──────────────────────────
    @app.get("/findings", response_class=HTMLResponse)
    def findings_page(state: str = "open"):
        ack_filter = state if state in ("open", "ack", "dismissed") else None
        rows = event_bus.query_events(category="detection.%", limit=500,
                                      ack_state=ack_filter)
        # Counts for the filter tabs
        counts = {
            "open": event_bus.count_events(category="detection.%",
                                           ack_state="open"),
            "ack":  event_bus.count_events(category="detection.%",
                                           ack_state="ack"),
            "dismissed": event_bus.count_events(category="detection.%",
                                                ack_state="dismissed"),
        }
        body_rows = []
        for r in rows:
            sev = (r.get("severity") or "info").lower()
            data_str = r.get("data") or ""
            try:
                d = json.loads(data_str) if isinstance(data_str, str) else data_str
            except Exception:
                d = {}
            target = d.get("path") or d.get("process") or d.get("cmdline") or d.get("rule_name") or ""
            rule = d.get("rule_name") or d.get("rule") or ""
            ack = r.get("ack_state") or ""
            ack_html = ""
            if ack == "ack":
                ack_html = '<span style="color:var(--green)">●</span>'
            elif ack == "dismissed":
                ack_html = '<span style="color:var(--dim)">○</span>'
            row_style = ' style="opacity:.5"' if ack else ''
            body_rows.append(
                f'<tr class="sev-{sev}" data-sev="{sev}" data-eid="{_esc(r.get("event_id",""))}" '
                f'data-text="{_esc((rule + " " + target).lower())}"{row_style} '
                f'onclick="window.aegisInst.selectRow(this)">'
                f'<td><input type="checkbox" class="rowsel" value="{_esc(r.get("event_id",""))}" onclick="event.stopPropagation()"></td>'
                f'<td>{ack_html}</td>'
                f'<td><span class="ts">{_ts(r["timestamp"])}</span></td>'
                f'<td>{_sev(sev)}</td>'
                f'<td>{_esc(rule) or "<span class=\"ts\">—</span>"}</td>'
                f'<td><span class="cat">{_esc(r.get("source",""))}</span></td>'
                f'<td>{_esc(r.get("mitre_attack") or "")}</td>'
                f'<td class="path wide">{_esc(_short(target, 200))}</td>'
                f'</tr>'
            )

        def tab(key, label):
            cls = "chip on" if state == key else "chip"
            return (f'<a href="/findings?state={key}" '
                    f'style="text-decoration:none"><span class="{cls}">'
                    f'{label} <b style="margin-left:4px">{counts[key]}</b></span></a>')
        body = f"""
<div class="page-head">
  <h2>Findings · Detections</h2>
  <span class="meta">{len(rows)} shown</span>
  <div class="tools">
    <span id="selcount" class="meta">0 selected</span>
    <button class="primary" onclick="bulkSet('ack')">Acknowledge</button>
    <button class="danger"  onclick="bulkSet('dismissed')">Dismiss</button>
    <button onclick="bulkSet('open')">Reopen</button>
  </div>
</div>
<div class="filter">
  {tab("open", "Open")}
  {tab("ack", "Acknowledged")}
  {tab("dismissed", "Dismissed")}
  <input class="filter-input" type="text" placeholder="filter (rule, target, source)…" oninput="filterFindings(this.value)">
</div>
<div class="scroll">
<table class="table">
<thead><tr>
  <th style="width:30px"><input type="checkbox" onclick="toggleAll(this)"></th>
  <th style="width:24px"></th>
  <th style="width:90px">Time</th>
  <th style="width:40px">Sev</th>
  <th style="width:200px">Rule</th>
  <th style="width:130px">Source</th>
  <th style="width:90px">ATT&amp;CK</th>
  <th>Target</th>
</tr></thead>
<tbody>{''.join(body_rows) or '<tr><td colspan="8" class="wide"><div class="empty">No detections.</div></td></tr>'}</tbody>
</table>
</div>
<script>
window.aegisInst = window.aegisInst || {{ selectRow: el => {{
  document.querySelectorAll('tr.sel').forEach(r => r.classList.remove('sel'));
  el.classList.add('sel');
  const id = el.dataset.eid;
  if (id) {{
    htmx.ajax('GET', '/api/event/' + id, {{target:'#inspector', swap:'innerHTML'}});
    document.querySelector('.inspector').classList.add('open');
  }}
}}}};
function toggleAll(box){{
  document.querySelectorAll('.rowsel').forEach(b => b.checked = box.checked);
  updateSelCount();
}}
function selectedIds(){{
  return [...document.querySelectorAll('.rowsel:checked')].map(b => b.value);
}}
function updateSelCount(){{
  document.getElementById('selcount').textContent = selectedIds().length + ' selected';
}}
document.addEventListener('change', e => {{
  if (e.target.classList.contains('rowsel')) updateSelCount();
}});
async function bulkSet(state){{
  const ids = selectedIds();
  if (!ids.length) {{ document.getElementById('selcount').textContent = 'no rows selected'; return; }}
  const fd = new FormData();
  fd.append('ids', ids.join(','));
  fd.append('state', state);
  const r = await fetch('/api/events/ack', {{method:'POST', body: fd}});
  if (r.ok) window.location.reload();
  else document.getElementById('selcount').textContent = 'error: ' + r.status;
}}
function filterFindings(q){{
  q = q.toLowerCase();
  document.querySelectorAll('table.table tbody tr').forEach(tr => {{
    tr.style.display = (!q || (tr.dataset.text||'').includes(q)) ? '' : 'none';
  }});
}}
</script>
"""
        return _layout("findings", body)

    # ── Page: Quarantine ──────────────────────────────────────────
    @app.get("/quarantine", response_class=HTMLResponse)
    def quarantine_page():
        files = []
        total = 0
        if quarantine_dir.exists():
            for p in sorted(quarantine_dir.iterdir(), reverse=True):
                if p.is_file() and not p.name.endswith(".meta.json"):
                    st = p.stat()
                    total += st.st_size
                    files.append((p, st))
        rows = []
        for p, st in files[:500]:
            rows.append(
                f'<tr>'
                f'<td><input type="checkbox" class="rowsel"></td>'
                f'<td><span class="ts">{_ts_full(st.st_mtime)}</span></td>'
                f'<td class="wide"><code>{_esc(_short(p.name, 200))}</code></td>'
                f'<td>{st.st_size:,} B</td>'
                f'<td>'
                f'<form hx-post="/quarantine/delete" hx-confirm="Delete {_esc(p.name)}?" style="display:inline">'
                f'<input type="hidden" name="name" value="{_esc(p.name)}">'
                f'<button class="danger">Delete</button></form></td>'
                f'</tr>'
            )
        mb = total / (1024*1024)
        body = f"""
<div class="page-head" x-data="{{purge:false}}">
  <h2>Quarantine</h2>
  <span class="meta">{len(files):,} files · {mb:.1f} MB</span>
  <div class="tools">
    <button class="danger" @click="purge=true">Purge All</button>
  </div>
  <template x-if="purge">
    <div class="modal-bg" @click="purge=false">
      <div class="modal" @click.stop>
        <h3>Confirm Purge</h3>
        <p>This will permanently delete <b>{len(files):,}</b> quarantined files
           ({mb:.1f} MB). Type <b>PURGE</b> to confirm.</p>
        <form hx-post="/quarantine/purge" hx-target="body">
          <input name="confirm" placeholder="type PURGE" autofocus>
          <div class="row">
            <button type="button" @click="purge=false">Cancel</button>
            <button class="danger" type="submit">Purge</button>
          </div>
        </form>
      </div>
    </div>
  </template>
</div>
<div class="scroll">
<table class="table">
<thead><tr>
  <th style="width:30px"></th>
  <th style="width:160px">Quarantined</th>
  <th>Original Name</th>
  <th style="width:90px">Size</th>
  <th style="width:90px"></th>
</tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="5"><div class="empty">Quarantine is empty.</div></td></tr>'}</tbody>
</table>
</div>
"""
        return _layout("quarantine", body)

    def _force_unlink(p: Path) -> None:
        """Quarantined files are chmod 000 by `_quarantine_path` so a
        careless click can't double-trip on them; on Windows that's
        the readonly bit, which blocks `Path.unlink`. Clear it first."""
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        p.unlink()

    @app.post("/quarantine/delete", response_class=HTMLResponse)
    def quarantine_delete(name: str = Form(...)):
        if "/" in name or "\\" in name or ".." in name:
            return HTMLResponse('<span class="bad">invalid name</span>', status_code=400)
        target = quarantine_dir / name
        try:
            _force_unlink(target)
            return HTMLResponse(f'<span class="ok">deleted</span>')
        except OSError as e:
            return HTMLResponse(f'<span class="bad">{_esc(e)}</span>', status_code=500)

    @app.post("/quarantine/purge", response_class=HTMLResponse)
    def quarantine_purge(confirm: str = Form(...)):
        if confirm != "PURGE":
            raise HTTPException(400, "confirmation token mismatch")
        removed = failed = 0
        first_error: str = ""
        if quarantine_dir.exists():
            for p in quarantine_dir.iterdir():
                if not p.is_file():
                    continue
                try:
                    _force_unlink(p)
                    removed += 1
                except Exception as e:
                    failed += 1
                    if not first_error:
                        first_error = f"{p.name}: {e}"
        # Re-render the page after purge
        msg = f"Purged {removed}, failed {failed}."
        if first_error:
            msg += f" First error: {first_error}"
        return HTMLResponse(
            f'<meta http-equiv="refresh" content="0;url=/quarantine">{_esc(msg)}'
        )

    # ── Page: MITRE coverage matrix ───────────────────────────────
    @app.get("/coverage", response_class=HTMLResponse)
    def coverage_page():
        try:
            from aegis.utils.mitre_coverage import build_coverage
            cov = build_coverage()
        except Exception as e:
            return _layout("coverage",
                f'<div class="page-head"><h2>Coverage</h2></div>'
                f'<div class="empty">error: {_esc(e)}</div>')

        # Volume of recent fires per technique (last 24h) — only open detections
        fires: dict[str, int] = {}
        try:
            since = time.time() - 86400
            for r in event_bus.query_events(since=since, limit=10000,
                                            ack_state="open"):
                tid = r.get("mitre_attack") or ""
                if tid:
                    fires[tid] = fires.get(tid, 0) + 1
        except Exception:
            pass

        cols = []
        for tactic, techniques in cov["by_tactic"].items():
            cells = []
            for tid, meta in techniques.items():
                vol = fires.get(tid, 0)
                cls = "cell"
                if vol >= 50:    cls += " crit"
                elif vol > 0:    cls += " fired"
                elif meta.get("covered"): cls += " cov"
                title = f"{tid} {meta['name']} — {vol} hits/24h"
                cells.append(
                    f'<div class="{cls}" title="{_esc(title)}">'
                    f'<span class="tid">{tid}</span>'
                    f'<span class="nm">{_esc(meta["name"])}</span></div>'
                )
            cols.append(f'<div class="tac-col"><h5>{_esc(tactic)}</h5>{"".join(cells)}</div>')

        body = f"""
<div class="page-head">
  <h2>MITRE ATT&amp;CK · Coverage</h2>
  <span class="meta">{cov['covered_count']} / {cov['total_count']} techniques · {cov['percent']}%</span>
  <div class="tools">
    <span class="chip on">Covered</span>
    <span class="chip on" style="border-color:var(--amber);color:var(--amber)">Fired (24h)</span>
    <span class="chip on" style="border-color:var(--red);color:var(--red)">High volume</span>
  </div>
</div>
<div class="matrix">{''.join(cols)}</div>
"""
        return _layout("coverage", body)

    # ── Page: Integrity ───────────────────────────────────────────
    @app.get("/integrity", response_class=HTMLResponse)
    def integrity_page():
        ok, problems = event_bus.verify_chain()
        manifest_block = ""
        try:
            from aegis.utils.self_protect import verify_manifest
            mok, mproblems = verify_manifest(".", "config/aegis.yaml")
            mlines = "\n".join(mproblems) or "(no issues)"
            mstatus = '<span class="ok">✓ INTACT</span>' if mok else '<span class="bad">✗ TAMPERED</span>'
            manifest_block = f"""
<div class="insp-section">
  <h4>Config / Rules Manifest</h4>
  <div style="margin-bottom:6px">{mstatus}</div>
  <div class="term">{_esc(mlines)}</div>
</div>"""
        except Exception:
            pass

        chain_status = '<span class="ok">✓ CHAIN INTACT</span>' if ok \
                       else f'<span class="bad">✗ {len(problems)} BREAK(S)</span>'
        if problems:
            tampered = "".join(
                f'<div>seq=<b>{p["seq"]}</b> {p["issue"]} '
                f'eid=<span style="color:var(--dim)">{p["event_id"]}</span></div>'
                for p in problems[:50]
            )
            tamper_card = f"""
<div class="tamper-card">
  <h4>Hash-chain breaks</h4>
  {tampered}
  {f'<div style="margin-top:6px;color:var(--muted)">… and {len(problems)-50} more</div>' if len(problems) > 50 else ''}
</div>"""
        else:
            tamper_card = ""

        log_lines = []
        for p in problems[:200]:
            log_lines.append(f'<span class="bad">✗</span> seq {p["seq"]:>6} · {p["issue"]} · expected={p["expected"][:16]}… stored={p["stored"][:16]}…')
        if not problems:
            log_lines.append('<span class="ok">✓</span> all event seqs verified')

        body = f"""
<div class="page-head">
  <h2>Integrity · Verifier</h2>
  <span class="meta">{chain_status}</span>
</div>
<div class="scroll" style="padding:14px">
{tamper_card}
<div class="insp-section">
  <h4>Event Hash Chain</h4>
  <div class="term">{'<br>'.join(log_lines)}</div>
</div>
{manifest_block}
</div>
"""
        return _layout("integrity", body)

    # ══════════════════════════════════════════════════════════════
    # APIs
    # ══════════════════════════════════════════════════════════════
    @app.get("/api/statusbar", response_class=HTMLResponse)
    def api_statusbar():
        # event rate (last 60s)
        since = time.time() - 60
        try:
            rate = event_bus.count_events(since=since)
        except Exception:
            rate = 0
        # unacked criticals (last hour)
        try:
            crit = event_bus.count_events(severity="critical",
                                          since=time.time()-3600,
                                          ack_state="open")
        except Exception:
            crit = 0
        # uptime
        up = int(time.time() - started_at)
        h, rem = divmod(up, 3600); m, s = divmod(rem, 60)
        up_str = f"{h:02d}:{m:02d}:{s:02d}"
        # anomaly mode
        amode = "—"
        if aegis_ref is not None:
            try:
                amode = aegis_ref.anomaly.stats.get("mode", "—")
            except Exception:
                pass
        # chain status
        try:
            ok, _ = event_bus.verify_chain()
            chain_dot = '<span class="dot ok"></span>' if ok else '<span class="dot bad"></span>'
            chain_lbl = "INTACT" if ok else "BROKEN"
        except Exception:
            chain_dot, chain_lbl = '<span class="dot warn"></span>', "?"
        # sparkline (60 buckets, 1s each)
        spark = _sparkline_svg(event_bus)

        crit_cls = "crit" if crit > 0 else "ok"
        return HTMLResponse(f"""
<span class="sb-brand">AEGIS<span class="v">v0.2 · {_esc(hostname)}</span></span>
<span class="sb-cell">UPTIME <b>{up_str}</b></span>
<span class="sb-cell">EVENTS/MIN <b>{rate}</b> {spark}</span>
<span class="sb-cell {crit_cls}">CRIT/HR <b>{crit}</b></span>
<span class="sb-cell">ANOMALY <b>{_esc(amode).upper()}</b></span>
<span class="sb-cell">CHAIN {chain_dot} <b>{chain_lbl}</b></span>
<span class="sb-spacer"></span>
<span class="sb-cell">{time.strftime('%Y-%m-%d %H:%M:%S')}</span>
""")

    @app.get("/api/events", response_class=HTMLResponse)
    def api_events(limit: int = 120, severity: str | None = None):
        # 'open' filter drops ack/dismissed detections — non-detection rows
        # (file/proc/net/etc.) have NULL ack_state and still show.
        rows = event_bus.query_events(severity=severity, limit=limit,
                                      ack_state="open")
        out = [_render_event_row(r) for r in rows]
        return HTMLResponse(f"""
<table class="table">
<thead><tr><th style="width:90px">Time</th><th style="width:40px">Sev</th>
<th style="width:220px">Category</th><th style="width:130px">Source</th><th>Summary</th></tr></thead>
<tbody>{''.join(out) or '<tr><td colspan="5"><div class="empty">No events.</div></td></tr>'}</tbody>
</table>
<script>
window.aegisInst = window.aegisInst || {{ selectRow: el => {{
  document.querySelectorAll('tr.sel').forEach(r => r.classList.remove('sel'));
  el.classList.add('sel');
  const id = el.dataset.eid;
  if (id) {{
    htmx.ajax('GET', '/api/event/' + id, {{target:'#inspector', swap:'innerHTML'}});
    document.querySelector('.inspector').classList.add('open');
  }}
}}}};
</script>
""")

    @app.get("/api/events/stream")
    async def api_events_stream(request: Request):
        """Server-Sent Events stream of live AEGIS events.

        Replaces the old 1-second `/api/events` polling on the live
        page. One queue per client; when full we drop (publishers
        must never block the bus). Each frame carries the rendered
        HTML row plus minimal metadata so the client can prepend
        without re-fetching.
        """
        import asyncio
        from queue import Queue, Empty

        client_queue: Queue = Queue(maxsize=500)

        def _push(ev):
            try:
                client_queue.put_nowait(ev)
            except Exception:
                # queue.Full or anything else — never propagate to the bus.
                pass

        event_bus.subscribe("*", _push)

        async def gen():
            # `retry: 3000` tells EventSource to reconnect after 3s if dropped.
            yield "retry: 3000\n\n"
            yield ": connected\n\n"
            last_traffic = time.time()
            try:
                while True:
                    if await request.is_disconnected():
                        return
                    try:
                        ev = await asyncio.to_thread(client_queue.get, True, 1.0)
                    except Empty:
                        # Heartbeat keeps proxies / browsers from idle-closing.
                        if time.time() - last_traffic > 15:
                            last_traffic = time.time()
                            yield ": keepalive\n\n"
                        continue
                    row = {
                        "event_id": ev.event_id,
                        "timestamp": ev.timestamp,
                        "category": (ev.category.value
                                     if hasattr(ev.category, "value")
                                     else str(ev.category)),
                        "severity": (ev.severity.value
                                     if hasattr(ev.severity, "value")
                                     else str(ev.severity)),
                        "source": ev.source,
                        "data": json.dumps(ev.data or {}, default=str),
                        "ack_state": None,
                    }
                    payload = {
                        "id": ev.event_id,
                        "sev": row["severity"],
                        "html": _render_event_row(row),
                    }
                    yield f"data: {json.dumps(payload)}\n\n"
                    last_traffic = time.time()
            finally:
                event_bus.unsubscribe("*", _push)

        return StreamingResponse(
            gen(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                # Tell nginx-style proxies not to buffer the stream.
                "X-Accel-Buffering": "no",
            },
        )

    @app.post("/api/events/ack", response_class=HTMLResponse)
    def api_events_ack(ids: str = Form(...), state: str = Form("ack")):
        """Bulk-set triage state. ids is a comma-separated event_id list."""
        id_list = [x for x in ids.split(",") if x]
        if not id_list:
            return HTMLResponse('<span class="bad">no ids</span>', status_code=400)
        if state not in ("ack", "dismissed", "open"):
            return HTMLResponse('<span class="bad">bad state</span>', status_code=400)
        try:
            n = event_bus.set_ack_state(id_list, state)
        except Exception as e:
            return HTMLResponse(f'<span class="bad">{_esc(e)}</span>', status_code=500)
        return HTMLResponse(f'<span class="ok">{n} marked {state}</span>')

    @app.get("/api/event/{event_id}", response_class=HTMLResponse)
    def api_event(event_id: str):
        match = event_bus.query_by_id(event_id)
        if not match:
            return HTMLResponse('<div class="empty">Event not found.</div>')
        sev = (match.get("severity") or "info").lower()
        data_str = match.get("data") or ""
        try:
            d = json.loads(data_str) if isinstance(data_str, str) else data_str
        except Exception:
            d = {"raw": data_str}
        pretty = json.dumps(d, indent=2, default=str)

        # Related: same pid in last 5 min
        related = []
        pid = (d or {}).get("pid")
        if pid:
            try:
                since = match["timestamp"] - 300
                for rr in event_bus.query_events(since=since, limit=500):
                    try:
                        rd = json.loads(rr.get("data") or "{}")
                    except Exception:
                        rd = {}
                    if rd.get("pid") == pid and rr.get("event_id") != event_id:
                        related.append(rr)
            except Exception:
                pass

        rel_html = "".join(
            f'<div style="font-size:11px;padding:3px 0">'
            f'<span class="ts">{_ts(rr["timestamp"])}</span> '
            f'{_sev((rr.get("severity") or "info").lower())} '
            f'<span class="cat">{_esc(rr.get("category",""))}</span></div>'
            for rr in related[:10]
        ) or '<div style="color:var(--dim);font-size:11px">none in last 5 min</div>'

        ack_state = match.get("ack_state") or "open"
        ack_at = match.get("ack_at")
        ack_label = (f"{ack_state} · {_ts_full(ack_at)}"
                     if ack_at else ack_state)
        eid = match.get("event_id", "")
        actions = (
            f'<div style="margin-top:10px;display:flex;gap:6px">'
            f'<button class="primary" onclick="ackOne(\'{eid}\',\'ack\')">Acknowledge</button>'
            f'<button class="danger" onclick="ackOne(\'{eid}\',\'dismissed\')">Dismiss</button>'
            f'<button onclick="ackOne(\'{eid}\',\'open\')">Reopen</button>'
            f'</div>'
            '<script>'
            'window.ackOne = async (id,state) => {'
            '  const fd = new FormData(); fd.append("ids",id); fd.append("state",state);'
            '  const r = await fetch("/api/events/ack",{method:"POST",body:fd});'
            '  if (r.ok) window.location.reload();'
            '};'
            '</script>'
        )

        return HTMLResponse(f"""
<div class="insp-head">
  {_sev(sev)}
  <h3>{_esc(match.get("category",""))}</h3>
  <span class="x" onclick="document.querySelector('.inspector').classList.remove('open')">×</span>
</div>
<div class="insp-section">
  <h4>Event</h4>
  <dl class="kv">
    <dt>id</dt><dd>{_esc(eid)}</dd>
    <dt>time</dt><dd>{_ts_full(match["timestamp"])}</dd>
    <dt>source</dt><dd>{_esc(match.get("source",""))}</dd>
    <dt>severity</dt><dd>{_esc(sev)}</dd>
    <dt>att&amp;ck</dt><dd>{_esc(match.get("mitre_attack") or "—")}</dd>
    <dt>host</dt><dd>{_esc(match.get("hostname",""))}</dd>
    <dt>triage</dt><dd>{_esc(ack_label)}</dd>
  </dl>
  {actions}
</div>
<div class="insp-section">
  <h4>Payload</h4>
  <div class="json">{_esc(pretty)}</div>
</div>
<div class="insp-section">
  <h4>Related (same PID, ±5 min)</h4>
  {rel_html}
</div>
""")

    @app.get("/api/sparkline", response_class=HTMLResponse)
    def api_sparkline():
        return HTMLResponse(_sparkline_svg(event_bus))

    @app.get("/api/health")
    def api_health():
        out = {"events_total": event_bus.event_count, "uptime_s": int(time.time()-started_at)}
        if aegis_ref is not None:
            try: out["anomaly"] = aegis_ref.anomaly.stats
            except Exception: pass
            try: out["yara"] = aegis_ref.yara.stats
            except Exception: pass
            try: out["behavioral"] = aegis_ref.behavioral.stats
            except Exception: pass
        return JSONResponse(out)

    return app


# ── Sparkline (60 buckets × 1s) ────────────────────────────────────
def _sparkline_svg(event_bus: EventBus) -> str:
    try:
        now = time.time()
        rows = event_bus.query_events(since=now - 60, limit=10000)
    except Exception:
        rows = []
    buckets = [0] * 60
    for r in rows:
        idx = int(now - r["timestamp"])
        if 0 <= idx < 60:
            buckets[59 - idx] += 1
    if not any(buckets):
        return '<svg class="spark" width="80" height="14"><line x1="0" y1="13" x2="80" y2="13" stroke="#5a6477" stroke-width="1"/></svg>'
    mx = max(buckets) or 1
    pts = " ".join(
        f"{i*80/59:.1f},{14 - (b/mx)*12:.1f}" for i, b in enumerate(buckets)
    )
    return (f'<svg class="spark" width="80" height="14" viewBox="0 0 80 14">'
            f'<polyline points="{pts}" fill="none" stroke="#4dd0e1" stroke-width="1"/>'
            f'</svg>')


# ══════════════════════════════════════════════════════════════════
# Server runner
# ══════════════════════════════════════════════════════════════════
class WebDashboard:
    def __init__(self, event_bus: EventBus, full_config: dict, aegis_ref=None):
        self.event_bus = event_bus
        self.full_config = full_config
        self.aegis_ref = aegis_ref
        self.config = (full_config.get("dashboard_web") or {}) if isinstance(full_config, dict) else {}
        self.host = self.config.get("host", "127.0.0.1")
        self.port = int(self.config.get("port", 8765))
        self._thread: threading.Thread | None = None
        self._server = None

    def start(self):
        if not self.config.get("enabled", True):
            logger.info("WebDashboard disabled in config")
            return
        if not FASTAPI_AVAILABLE:
            logger.warning("WebDashboard: fastapi/uvicorn not installed — disabled")
            return
        app = create_app(self.event_bus, self.full_config, self.aegis_ref)
        cfg = uvicorn.Config(app, host=self.host, port=self.port, log_level="warning")
        self._server = uvicorn.Server(cfg)
        self._thread = threading.Thread(target=self._server.run, daemon=True,
                                        name="aegis-dashboard")
        self._thread.start()
        logger.info(f"WebDashboard started → http://{self.host}:{self.port}")

    def stop(self):
        if self._server:
            self._server.should_exit = True
        if self._thread:
            self._thread.join(timeout=2)


__all__ = ["WebDashboard", "create_app"]

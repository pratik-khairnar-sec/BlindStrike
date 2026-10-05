#!/usr/bin/env python3
"""
BlindStrike
===========
Time-Based Blind SQL Injection Testing Framework

By Pratik Khairnar

A time-based Blind SQL Injection testing tool for authorized security
assessments. Injects database-specific delay payloads into a target
request (URL query string, POST body, or a header) and flags a target
as potentially vulnerable when the response is delayed beyond a
configurable threshold, confirmed against a same-target baseline and a
repeat hit — the classic signature of a time-based blind SQLi flaw.

Legal / Ethical Notice
-----------------------
This tool is provided for authorized penetration testing, bug bounty
research under a valid program scope, and educational purposes only.
Running this tool against systems you do not own or do not have explicit
written authorization to test is illegal in most jurisdictions. The
author (Pratik Khairnar) assumes no liability for misuse.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import difflib
import json
import logging
import os
import random
import re
import statistics
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

__version__ = "7.0.0"
__author__ = "Pratik Khairnar"
__tool__ = "BlindStrike"

FUZZ_MARKER = "FUZZ"

# Persistent local config (Telegram credentials only) so they don't have to be
# retyped on every run. Lives outside the repo/cwd on purpose so it's never
# accidentally committed or shipped in a report; the wizard writes to it, CLI
# flags and env vars always take priority over it. File mode is restricted to
# the owner (0600) since it holds a bot token.
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".blindstrike")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
ENV_TOKEN_VAR = "BLINDSTRIKE_TELEGRAM_TOKEN"
ENV_CHAT_ID_VAR = "BLINDSTRIKE_TELEGRAM_CHAT_ID"


def load_saved_config() -> Dict[str, str]:
    """Read the local ~/.blindstrike/config.json, if any. Never raises - a missing or
    corrupt file is treated as no saved config."""
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


_TELEGRAM_TOKEN_RE = re.compile(r"^\d{6,}:[A-Za-z0-9_-]{20,}$")


def _sanitize_telegram_creds(token: Optional[str], chat_id: Optional[str]) -> tuple:
    """Strip whitespace/newlines and a mistakenly-pasted 'bot' prefix from Telegram
    credentials before they're saved or used.

    A stray trailing newline or space - extremely easy to pick up from copy-pasting a
    token out of a terminal, a message, or a config file - gets silently percent-encoded
    into the request URL by requests/urllib3 rather than rejected, so BlindStrike would
    send a request for a bot token that doesn't actually exist. Telegram's API returns
    HTTP 404 Not Found for that case (as opposed to 401 Unauthorized for a well-formed
    but simply wrong token), which is exactly the failure this fixes.
    """
    if token:
        token = token.strip()
        if token.lower().startswith("bot"):
            token = token[3:]
    if chat_id:
        chat_id = chat_id.strip()
    return token, chat_id


def _telegram_token_looks_valid(token: str) -> bool:
    """Loose structural check (numeric bot ID + ':' + secret) so a clearly-malformed
    token is caught with a clear message before ever making a network call, rather than
    surfacing as an opaque HTTP 404 after the fact."""
    return bool(_TELEGRAM_TOKEN_RE.match(token or ""))


def save_telegram_config(token: str, chat_id: str) -> bool:
    """Persist Telegram credentials locally so future runs don't need --telegram-token/
    --telegram-chat-id or the env vars again. Returns True on success; failure (e.g. no
    write permission) is non-fatal - the scan itself never depends on this succeeding."""
    token, chat_id = _sanitize_telegram_creds(token, chat_id)
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        data = load_saved_config()
        data["telegram_token"] = token
        data["telegram_chat_id"] = chat_id
        with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        try:
            os.chmod(CONFIG_PATH, 0o600)
        except OSError:
            pass
        return True
    except OSError:
        return False


def resolve_telegram_credentials(cli_token: Optional[str], cli_chat_id: Optional[str]) -> tuple:
    """Resolve Telegram token/chat_id with priority: CLI flags > environment variables
    > saved local config. Returns (token, chat_id, source) where source is one of
    'cli', 'env', 'saved', or None if nothing is configured anywhere.

    Every source is sanitized (whitespace/newline stripped, stray 'bot' prefix removed)
    before being returned - this also self-heals a bad value that was saved by an
    older, unsanitized version of this file.
    """
    if cli_token and cli_chat_id:
        return (*_sanitize_telegram_creds(cli_token, cli_chat_id), "cli")

    env_token, env_chat_id = os.environ.get(ENV_TOKEN_VAR), os.environ.get(ENV_CHAT_ID_VAR)
    if env_token and env_chat_id:
        return (*_sanitize_telegram_creds(env_token, env_chat_id), "env")

    saved = load_saved_config()
    saved_token, saved_chat_id = saved.get("telegram_token"), saved.get("telegram_chat_id")
    if saved_token and saved_chat_id:
        return (*_sanitize_telegram_creds(saved_token, saved_chat_id), "saved")

    return None, None, None


# --------------------------------------------------------------------------- #
# Terminal colors
# --------------------------------------------------------------------------- #
class Color:
    BLUE = "\033[94m"
    GREEN = "\033[1;92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @staticmethod
    def disable():
        for attr in ("BLUE", "GREEN", "YELLOW", "RED", "PURPLE", "CYAN", "BOLD", "DIM", "RESET"):
            setattr(Color, attr, "")


BANNER = r"""
██████╗ ██╗     ██╗███╗   ██╗██████╗ ███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
██╔══██╗██║     ██║████╗  ██║██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
██████╔╝██║     ██║██╔██╗ ██║██║  ██║███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
██╔══██╗██║     ██║██║╚██╗██║██║  ██║╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
██████╔╝███████╗██║██║ ╚████║██████╔╝███████║   ██║   ██║  ██║██║██║  ██╗███████╗
╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝

          Time-Based Blind SQL Injection Testing Framework  |  v{version}
                          By Pratik Khairnar
"""


def build_logger(verbose: bool, log_file: Optional[str]) -> logging.Logger:
    logger = logging.getLogger("blindstrike")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(fmt)
    logger.addHandler(stream_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)

    return logger


@dataclass
class ScanResult:
    url: str
    payload: str
    tested_url: str
    method: str
    vulnerable: bool
    confirmed: bool
    status_code: Optional[int]
    response_time: Optional[float]
    baseline_time: Optional[float] = None
    delta: Optional[float] = None
    timed_out: bool = False
    mode: str = "time"
    true_similarity: Optional[float] = None
    false_similarity: Optional[float] = None
    noise_floor: Optional[float] = None
    error: Optional[str] = None


@dataclass
class ScanReport:
    tool: str = __tool__
    version: str = __version__
    author: str = __author__
    started_at: str = ""
    finished_at: str = ""
    threshold_seconds: float = 10.0
    total_tests: int = 0
    vulnerabilities_found: int = 0
    confirmed_vulnerabilities: int = 0
    vulnerable_urls: List[str] = field(default_factory=list)
    results: List[ScanResult] = field(default_factory=list)

    def to_json(self, include_all_results: bool = True) -> str:
        data = asdict(self)
        if not include_all_results:
            data.pop("results")
        return json.dumps(data, indent=2)

    def to_csv(self) -> str:
        import io

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            ["url", "method", "mode", "payload", "vulnerable", "confirmed", "status_code",
             "response_time", "baseline_time", "delta", "timed_out",
             "true_similarity", "false_similarity", "noise_floor", "error", "tested_url"]
        )
        for r in self.results:
            writer.writerow(
                [r.url, r.method, r.mode, r.payload, r.vulnerable, r.confirmed, r.status_code,
                 r.response_time, r.baseline_time, r.delta, r.timed_out,
                 r.true_similarity, r.false_similarity, r.noise_floor, r.error or "", r.tested_url]
            )
        return buf.getvalue()

    def to_html(self) -> str:
        table_rows = []
        poc_blocks = []
        for r in self.results:
            if not r.vulnerable:
                continue
            css = "confirmed" if r.confirmed else "unconfirmed"
            if r.mode == "boolean":
                evidence = (
                    f"TRUE~baseline={r.true_similarity} &nbsp;|&nbsp; "
                    f"FALSE~baseline={r.false_similarity} &nbsp;|&nbsp; noise floor={r.noise_floor}"
                )
            else:
                timeout_tag = " (timed out)" if r.timed_out else ""
                delta_txt = f" | delta={r.delta}s" if r.delta is not None else ""
                evidence = f"time={r.response_time}s | baseline={r.baseline_time}s{delta_txt}{timeout_tag}"

            safe_link = _html_escape(r.tested_url)
            safe_payload = _html_escape(r.payload)
            link_html = f'<a href="{safe_link}" target="_blank" rel="noopener noreferrer">open ↗</a>'
            badge_html = (
                '<span class="badge badge-conf">CONFIRMED</span>'
                if r.confirmed
                else '<span class="badge badge-unconf">SUSPECT</span>'
            )

            # Build curl command for instant PoC reproduction
            if r.method == "POST":
                curl_cmd = f"curl -i -s -X POST '{safe_link}' -d '{safe_payload}'"
            else:
                curl_cmd = f"curl -i -s '{safe_link}'"
            escaped_curl = curl_cmd.replace("'", "\\'")

            table_rows.append(
                f"<tr class='row-{css}' data-status='{css}'>"
                f"<td class='cell-url'>{_html_escape(r.url)}</td>"
                f"<td><span class='method-tag'>{r.method}</span></td>"
                f"<td><span class='mode-tag'>{r.mode}</span></td>"
                f"<td><code class='payload-code'>{safe_payload}</code></td>"
                f"<td class='cell-evidence'>{evidence}</td>"
                f"<td>{badge_html}</td>"
                f"<td>{link_html}</td>"
                f"</tr>"
            )

            if r.confirmed:
                poc_blocks.append(f"""
<div class="poc-card">
  <div class="poc-head">
    <div class="poc-badge">CRITICAL // PROOF OF CONCEPT</div>
    <div class="poc-title">CONFIRMED {'BOOLEAN-BASED' if r.mode == 'boolean' else 'TIME-BASED'} SQLi</div>
    <button type="button" class="btn-copy-poc" onclick="copyText('{escaped_curl}', this)">📋 Copy curl PoC</button>
  </div>
  <table class="poc-table">
    <tr><th>Target Endpoint</th><td><code>{_html_escape(r.url)}</code></td></tr>
    <tr><th>HTTP Method</th><td><span class='method-tag'>{r.method}</span></td></tr>
    <tr><th>Injected Payload</th><td><code class="payload-code">{safe_payload}</code></td></tr>
    <tr><th>Empirical Evidence</th><td class="evidence-val">{evidence}</td></tr>
    <tr><th>Replay URL</th><td class="poc-url"><a href="{safe_link}" target="_blank" rel="noopener noreferrer">{safe_link} ↗</a></td></tr>
    <tr><th>PoC Terminal Command</th><td><pre class="curl-pre"><code>{curl_cmd}</code></pre></td></tr>
  </table>
  <div class="poc-footer">
    <span>🛡️ <b>Triage Verification:</b> Automatically verified through independent repeat delay confirmation. Verify in Burp Suite / terminal before bug bounty submission.</span>
  </div>
</div>""")

        table_html = "\n".join(table_rows) if table_rows else "<tr><td colspan='7' class='empty-cell'>No vulnerabilities flagged during this scan session.</td></tr>"
        poc_html = "\n".join(poc_blocks) if poc_blocks else '<div class="empty-poc"><p>Zero confirmed vulnerabilities identified across all scanned targets.</p></div>'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{__tool__} v{__version__} Security Assessment Report</title>
<style>
:root {{
  --bg: #090d16; --bg-card: #0f172a; --panel: #131d31; --border: #1e293b;
  --accent: #38bdf8; --accent-dim: #0284c7; --red: #f43f5e; --green: #10b981;
  --yellow: #f59e0b; --text: #e2e8f0; --muted: #94a3b8; --code-bg: #050811;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", monospace;
  background: var(--bg); color: var(--text); padding: 2rem 1.5rem; line-height: 1.6;
}}
.container {{ max-width: 1200px; margin: 0 auto; }}
.header {{
  display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;
  padding-bottom: 1.5rem; border-bottom: 1px solid var(--border); gap: 1rem; margin-bottom: 2rem;
}}
.header-brand h1 {{
  font-size: 1.7rem; font-weight: 800; letter-spacing: -0.5px;
  background: linear-gradient(135deg, #ffffff 30%, var(--accent) 100%);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}}
.header-brand p {{ font-size: 0.88rem; color: var(--muted); margin-top: 4px; font-family: monospace; }}
.header-actions {{ display: flex; gap: 0.6rem; }}
.btn-action {{
  background: var(--panel); border: 1px solid var(--border); color: var(--text);
  padding: 6px 14px; border-radius: 6px; font-size: 0.82rem; cursor: pointer;
  font-family: monospace; transition: all 0.15s ease;
}}
.btn-action:hover {{ border-color: var(--accent); color: var(--accent); }}

.kpi-grid {{
  display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem; margin-bottom: 2rem;
}}
.kpi-card {{
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px;
  padding: 1.2rem; transition: border-color 0.2s;
}}
.kpi-card:hover {{ border-color: rgba(56,189,248,0.4); }}
.kpi-val {{ font-size: 1.8rem; font-weight: 800; font-family: monospace; margin-top: 4px; }}
.kpi-val.conf {{ color: var(--red); }}
.kpi-val.flag {{ color: var(--yellow); }}
.kpi-val.total {{ color: var(--accent); }}
.kpi-lbl {{ font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.8px; color: var(--muted); }}

.section-head {{
  display: flex; justify-content: space-between; align-items: center;
  margin: 2.5rem 0 1.2rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border);
}}
.section-title {{ font-size: 1.25rem; font-weight: 700; color: #f1f5f9; display: flex; align-items: center; gap: 8px; }}
.section-title span {{ color: var(--accent); }}

.poc-card {{
  background: var(--panel); border: 1px solid rgba(244,63,94,0.3); border-left: 4px solid var(--red);
  border-radius: 8px; padding: 1.3rem; margin-bottom: 1.5rem; box-shadow: 0 4px 20px rgba(0,0,0,0.4);
}}
.poc-head {{ display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; margin-bottom: 1rem; }}
.poc-badge {{ background: rgba(244,63,94,0.15); color: var(--red); font-size: 0.75rem; font-weight: 700; padding: 3px 9px; border-radius: 4px; font-family: monospace; letter-spacing: 0.5px; }}
.poc-title {{ font-size: 1.05rem; font-weight: 700; color: #fff; flex: 1; margin-left: 6px; }}
.btn-copy-poc {{
  background: var(--bg); border: 1px solid var(--border); color: var(--accent);
  padding: 5px 12px; border-radius: 4px; font-size: 0.8rem; font-family: monospace; cursor: pointer; transition: 0.15s;
}}
.btn-copy-poc:hover {{ background: var(--accent); color: #000; font-weight: bold; }}
.poc-table {{ width: 100%; border-collapse: collapse; margin: 0.5rem 0; font-size: 0.88rem; }}
.poc-table th {{ width: 160px; text-align: left; padding: 8px 10px; color: var(--muted); font-weight: 600; border-bottom: 1px solid rgba(255,255,255,0.05); }}
.poc-table td {{ padding: 8px 10px; border-bottom: 1px solid rgba(255,255,255,0.05); word-break: break-all; }}
.poc-url a {{ color: var(--accent); text-decoration: none; }}
.poc-url a:hover {{ text-decoration: underline; }}
.curl-pre {{
  background: var(--code-bg); border: 1px solid var(--border); border-radius: 6px;
  padding: 8px 12px; overflow-x: auto; color: #38bdf8; font-family: monospace; font-size: 0.82rem;
}}
.poc-footer {{
  margin-top: 1rem; padding-top: 0.8rem; border-top: 1px dashed rgba(255,255,255,0.08);
  font-size: 0.82rem; color: #cbd5e1;
}}
.poc-footer b {{ color: var(--yellow); }}

.filter-bar {{ display: flex; gap: 8px; margin-bottom: 1rem; align-items: center; flex-wrap: wrap; }}
.filter-btn {{
  background: var(--bg-card); border: 1px solid var(--border); color: var(--muted);
  padding: 5px 12px; border-radius: 5px; font-size: 0.82rem; font-family: monospace; cursor: pointer;
}}
.filter-btn.active {{ border-color: var(--accent); color: var(--accent); background: rgba(56,189,248,0.1); }}
.search-input {{
  margin-left: auto; background: var(--bg-card); border: 1px solid var(--border); color: #fff;
  padding: 6px 12px; border-radius: 5px; font-size: 0.82rem; font-family: monospace; outline: none; min-width: 220px;
}}
.search-input:focus {{ border-color: var(--accent); }}

.results-table {{ width: 100%; border-collapse: collapse; background: var(--bg-card); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); font-size: 0.86rem; }}
.results-table th {{ background: #0c1322; color: var(--accent); font-weight: 600; text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--border); font-family: monospace; font-size: 0.8rem; }}
.results-table td {{ padding: 9px 14px; border-bottom: 1px solid rgba(255,255,255,0.04); vertical-align: middle; }}
.results-table tr.row-confirmed {{ background: rgba(244,63,94,0.05); }}
.results-table tr.row-unconfirmed {{ background: rgba(245,158,11,0.03); }}
.results-table tr:hover {{ background: rgba(255,255,255,0.03); }}
.cell-url {{ font-family: monospace; color: #cbd5e1; max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
.cell-evidence {{ font-family: monospace; font-size: 0.8rem; color: #94a3b8; }}
.method-tag {{ background: rgba(255,255,255,0.06); padding: 2px 7px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; font-family: monospace; }}
.mode-tag {{ color: var(--muted); font-size: 0.78rem; text-transform: uppercase; font-family: monospace; }}
.payload-code {{ background: var(--code-bg); color: #fb7185; padding: 2px 6px; border-radius: 4px; font-size: 0.8rem; border: 1px solid rgba(255,255,255,0.05); }}
.badge {{ padding: 3px 8px; border-radius: 4px; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.5px; font-family: monospace; }}
.badge-conf {{ background: rgba(244,63,94,0.2); color: #f43f5e; border: 1px solid rgba(244,63,94,0.4); }}
.badge-unconf {{ background: rgba(245,158,11,0.2); color: #f59e0b; border: 1px solid rgba(245,158,11,0.4); }}
.results-table a {{ color: var(--accent); text-decoration: none; }}
.results-table a:hover {{ text-decoration: underline; }}
.empty-cell, .empty-poc {{ padding: 2rem; text-align: center; color: var(--muted); font-style: italic; }}

@media print {{
  body {{ background: #fff; color: #000; }}
  .header-actions, .filter-bar, .btn-copy-poc {{ display: none !important; }}
  .poc-card, .results-table {{ border-color: #ccc; box-shadow: none; }}
}}
</style>
<script>
function copyText(text, btn) {{
  navigator.clipboard.writeText(text).then(() => {{
    const orig = btn.innerText;
    btn.innerText = "✓ Copied!";
    btn.style.color = "#10b981";
    setTimeout(() => {{ btn.innerText = orig; btn.style.color = ""; }}, 1800);
  }}).catch(() => {{
    prompt("Copy command:", text);
  }});
}}
function filterRows(status, btn) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.results-table tbody tr').forEach(row => {{
    if (status === 'all') {{
      row.style.display = '';
    }} else {{
      row.style.display = row.dataset.status === status ? '' : 'none';
    }}
  }});
}}
function searchTable(query) {{
  const q = query.toLowerCase();
  document.querySelectorAll('.results-table tbody tr').forEach(row => {{
    row.style.display = row.innerText.toLowerCase().includes(q) ? '' : 'none';
  }});
}}
</script>
</head>
<body>
<div class="container">
  <header class="header">
    <div class="header-brand">
      <h1>⚡ {__tool__} v{__version__} Security Assessment Report</h1>
      <p>Automated Time-Based &amp; Boolean-Based Blind SQL Injection Intelligence</p>
    </div>
    <div class="header-actions">
      <button type="button" class="btn-action" onclick="window.print()">🖨️ Print / PDF</button>
    </div>
  </header>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-lbl">Total Scans Executed</div>
      <div class="kpi-val total">{self.total_tests}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-lbl">Confirmed SQLi Flaws</div>
      <div class="kpi-val conf">{self.confirmed_vulnerabilities}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-lbl">Flagged Suspect Hits</div>
      <div class="kpi-val flag">{self.vulnerabilities_found}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-lbl">Execution Window</div>
      <div class="kpi-val" style="font-size: 0.95rem; color: var(--muted); margin-top: 8px;">
        {self.started_at}<br>to {self.finished_at}
      </div>
    </div>
  </div>

  <div class="section-head">
    <div class="section-title"><span>🎯</span> PROOF OF CONCEPT — CONFIRMED FINDINGS</div>
  </div>
  {poc_html}

  <div class="section-head">
    <div class="section-title"><span>📋</span> Comprehensive Test Results</div>
  </div>

  <div class="filter-bar">
    <button type="button" class="filter-btn active" onclick="filterRows('all', this)">All Results</button>
    <button type="button" class="filter-btn" onclick="filterRows('confirmed', this)">Confirmed Only</button>
    <button type="button" class="filter-btn" onclick="filterRows('unconfirmed', this)">Suspect Only</button>
    <input type="text" class="search-input" placeholder="🔍 Search URLs, payloads..." oninput="searchTable(this.value)">
  </div>

  <table class="results-table">
    <thead>
      <tr>
        <th>Target URL</th>
        <th>Method</th>
        <th>Mode</th>
        <th>Injected Payload</th>
        <th>Empirical Evidence</th>
        <th>Verdict</th>
        <th>Action</th>
      </tr>
    </thead>
    <tbody>
      {table_html}
    </tbody>
  </table>
</div>
</body>
</html>"""


def _html_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


class BlindSQLi:
    """Core Blind SQL Injection testing engine."""

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/124.0.0.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    ]

    def __init__(
        self,
        logger: logging.Logger,
        threshold: float = 10.0,
        timeout: float = 20.0,
        random_ua: bool = True,
        method: str = "GET",
        data: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        header_name: Optional[str] = None,
        confirm: bool = True,
        baseline_samples: int = 2,
        retries: int = 1,
        insecure: bool = False,
        proxy: Optional[str] = None,
        mode: str = "time",
        stop_on_confirm: bool = False,
        telegram_token: Optional[str] = None,
        telegram_chat_id: Optional[str] = None,
    ):
        self.logger = logger
        self.threshold = threshold
        self.timeout = timeout
        self.random_ua = random_ua
        self.method = method.upper()
        self.data_template = data
        self.extra_headers = headers or {}
        self.header_name = header_name
        self.confirm = confirm
        self.baseline_samples = max(1, baseline_samples)
        self.insecure = insecure
        self.mode = mode
        self.stop_on_confirm = stop_on_confirm
        self.telegram_token = telegram_token
        self.telegram_chat_id = telegram_chat_id
        self.report = ScanReport(threshold_seconds=threshold)
        # Set once a confirmed finding is hit with --stop-on-confirm active. Checked by
        # run()'s dispatch loop (both sequential and threaded) so no further requests
        # are sent to the target once a real confirmed finding exists.
        self._stop_event = threading.Event()
        self._baseline_cache: Dict[str, float] = {}
        # Boolean mode baseline: a list of (status_code, body) pairs from clean control
        # requests per target, used to measure the page's own natural noise floor
        # (dynamic timestamps, CSRF tokens, ad slots, etc.) so real true/false content
        # differences can be told apart from a page that simply never renders twice
        # identically.
        self._content_baseline_cache: Dict[str, List[tuple]] = {}

        self.session = requests.Session()
        # read=0 is deliberate: a read timeout IS our detection signal for time-based
        # SQLi. If it were retried like a normal transient error, urllib3 exhausts the
        # retry budget and re-raises it wrapped as a generic ConnectionError instead of
        # requests.exceptions.Timeout - which made the scanner's own timeout-as-signal
        # handling silently fail to recognize it. Connect errors and 5xx responses are
        # still retried normally.
        retry_cfg = Retry(total=retries, connect=retries, status=retries, read=0,
                           backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry_cfg)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        if insecure:
            self.session.verify = False
            try:
                import urllib3

                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass

    def get_user_agent(self) -> str:
        return random.choice(self.USER_AGENTS) if self.random_ua else self.USER_AGENTS[0]

    @staticmethod
    def read_lines(path: str) -> List[str]:
        """Read a file and return a list of non-empty, stripped lines (ignoring '#' comments)."""
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return [line.strip() for line in fh if line.strip() and not line.strip().startswith("#")]

    def _inject(self, url: str, payload: str) -> str:
        """Inject a payload at the FUZZ marker if present, else append it to the URL.

        The payload's '#' characters are percent-encoded to %23 first: urllib3/requests
        treats a raw '#' as the start of a URL fragment and silently drops it and
        everything after it before the request is ever sent. Several bundled MySQL/
        Postgres payloads end in '#' as a comment terminator, so without this they were
        being transmitted broken (truncated), causing false negatives on real targets.
        No other characters are touched, so already percent-encoded payloads
        (e.g. the %0d%0a-based ones) are not double-encoded.
        """
        safe_payload = payload.replace("#", "%23")
        if FUZZ_MARKER in url:
            return url.replace(FUZZ_MARKER, safe_payload)
        return f"{url}{safe_payload}"

    def _inject_data(self, payload: str) -> Optional[str]:
        if self.data_template is None:
            return None
        if FUZZ_MARKER in self.data_template:
            return self.data_template.replace(FUZZ_MARKER, payload)
        return self.data_template + payload

    def _do_request(self, url: str, cookie: Optional[str], payload_data: Optional[str],
                     headers: Dict[str, str]) -> tuple:
        """Fire one request, return (elapsed_seconds, status_code, body_text, error_str).

        body_text is None on any error, and is only meaningfully used by boolean-mode
        content diffing - time-based mode callers simply ignore it.
        """
        cookies = {"cookie": cookie} if cookie else None
        start = time.time()
        try:
            resp = self.session.request(
                self.method,
                url,
                headers=headers,
                cookies=cookies,
                data=payload_data if self.method in ("POST", "PUT", "PATCH") else None,
                timeout=self.timeout,
            )
            return round(time.time() - start, 3), resp.status_code, resp.text, None
        except requests.exceptions.Timeout:
            return round(time.time() - start, 3), None, None, "Request timed out"
        except requests.exceptions.RequestException as exc:
            # The retry adapter's Retry object wraps even a single read-timeout failure
            # in a MaxRetryError -> requests.exceptions.ConnectionError, regardless of
            # the configured retry budget - so a real timeout does not always surface as
            # requests.exceptions.Timeout. Detect it by message so the scanner's
            # timeout-as-signal handling still recognizes it correctly.
            msg = str(exc)
            if "read timed out" in msg.lower() or "readtimeouterror" in msg.lower():
                return round(time.time() - start, 3), None, None, "Request timed out"
            return round(time.time() - start, 3), None, None, msg

    def get_baseline(self, url: str, cookie: Optional[str], headers: Dict[str, str]) -> float:
        """Measure normal (non-payload) response time for a target, cached per URL."""
        if url in self._baseline_cache:
            return self._baseline_cache[url]

        samples = []
        control_data = self._inject_data("") if self.data_template is not None else None
        control_url = self._inject(url, "") if FUZZ_MARKER in url else url
        for _ in range(self.baseline_samples):
            elapsed, _, _, err = self._do_request(control_url, cookie, control_data, headers)
            if err is None:
                samples.append(elapsed)
        baseline = statistics.median(samples) if samples else 0.0
        self._baseline_cache[url] = baseline
        return baseline

    def get_content_baseline(self, url: str, cookie: Optional[str], headers: Dict[str, str]) -> List[tuple]:
        """Fetch clean control responses (status, body) for boolean-mode diffing, cached
        per target. Also used to measure the page's own natural noise floor (dynamic
        content that differs between two identical requests) so real true/false
        differences aren't confused with a page that never renders twice the same.
        """
        if url in self._content_baseline_cache:
            return self._content_baseline_cache[url]

        control_data = self._inject_data("") if self.data_template is not None else None
        control_url = self._inject(url, "") if FUZZ_MARKER in url else url
        samples = []
        for _ in range(max(2, self.baseline_samples)):
            _, status, body, err = self._do_request(control_url, cookie, control_data, headers)
            if err is None and body is not None:
                samples.append((status, body))
        self._content_baseline_cache[url] = samples
        return samples

    _DYNAMIC_TOKEN_RE = re.compile(r"\d+")

    @classmethod
    def _normalize(cls, body: str) -> str:
        """Collapse runs of digits to a single placeholder before diffing.

        Real pages routinely carry small per-request dynamic content - visitor
        counters, timestamps, CSRF tokens, cache-busting query params reflected in the
        page, ad-slot IDs - almost always numeric or hex-numeric. Left in, this noise
        dilutes the similarity ratio enough to hide a real boolean-based content
        difference underneath it (verified: on a realistic product-page vs
        empty-result-page pair, raw similarity separated true/false by only ~0.10 from
        the noise floor; after normalization the noise floor collapses to a clean 1.0
        and the genuine content difference remains fully intact).
        """
        return cls._DYNAMIC_TOKEN_RE.sub("#", body)

    @classmethod
    def _similarity(cls, a: str, b: str) -> float:
        """Content similarity in [0.0, 1.0] after stripping numeric noise. Uses the
        accurate ratio() rather than quick_ratio(): quick_ratio() is a fast upper-bound
        approximation that can overestimate similarity enough to mask a real
        boolean-based difference, and pages here are small enough (HTML fragments,
        not multi-MB files) that the extra cost is negligible."""
        if a is None or b is None:
            return 0.0
        return difflib.SequenceMatcher(None, cls._normalize(a), cls._normalize(b)).ratio()

    def perform_boolean_request(self, url: str, true_payload: str, false_payload: str,
                                 cookie: Optional[str]) -> ScanResult:
        """Boolean-based detection: inject a TRUE and a FALSE condition and compare each
        response's content against a set of clean control responses. A target is flagged
        only if the TRUE response looks like normal page content while the FALSE response
        looks meaningfully different - and that gap exceeds the page's own natural noise
        floor (measured from two-or-more clean control requests), so dynamic content
        (timestamps, CSRF tokens, ad slots) doesn't produce false positives.
        """
        headers = {"User-Agent": self.get_user_agent(), **self.extra_headers}
        combined_payload = f"{true_payload}|||{false_payload}"

        control_samples = self.get_content_baseline(url, cookie, headers)
        if not control_samples:
            return ScanResult(
                url=url, payload=combined_payload, tested_url=url, method=self.method,
                vulnerable=False, confirmed=False, status_code=None, response_time=None,
                mode="boolean", error="Could not fetch a baseline control response",
            )
        baseline_status = control_samples[0][0]
        # Noise floor: how similar two clean requests already are to each other, absent
        # any payload at all. If the page is highly dynamic, this will be well below 1.0,
        # and the boolean thresholds below adapt accordingly instead of assuming a static page.
        if len(control_samples) >= 2:
            noise_floor = min(
                self._similarity(control_samples[i][1], control_samples[j][1])
                for i in range(len(control_samples))
                for j in range(i + 1, len(control_samples))
            )
        else:
            noise_floor = 1.0

        true_url = self._inject(url, true_payload)
        false_url = self._inject(url, false_payload)
        true_data = self._inject_data(true_payload)
        false_data = self._inject_data(false_payload)

        _, true_status, true_body, true_err = self._do_request(true_url, cookie, true_data, headers)
        _, false_status, false_body, false_err = self._do_request(false_url, cookie, false_data, headers)

        if true_err or false_err:
            return ScanResult(
                url=url, payload=combined_payload, tested_url=f"{true_url}  |||  {false_url}",
                method=self.method, vulnerable=False, confirmed=False,
                status_code=true_status, response_time=None, mode="boolean",
                error=(true_err or false_err),
            )

        true_sim = max(self._similarity(true_body, cs[1]) for cs in control_samples)
        false_sim = max(self._similarity(false_body, cs[1]) for cs in control_samples)

        # TRUE must look like the normal/control page (within the page's own noise floor,
        # plus a small tolerance), AND the FALSE condition must diverge meaningfully
        # beyond that same noise floor. Status-code divergence (e.g. TRUE=200, FALSE=500
        # or a redirect) is treated as strong corroborating evidence, not required alone.
        true_looks_normal = true_sim >= max(noise_floor - 0.03, 0.80)
        false_diverges = false_sim <= max(noise_floor - 0.10, 0.0)
        status_diverges = (true_status != false_status) and (true_status == baseline_status)
        vulnerable = true_looks_normal and (false_diverges or status_diverges)

        confirmed = False
        if vulnerable and self.confirm:
            _, true_status2, true_body2, true_err2 = self._do_request(true_url, cookie, true_data, headers)
            _, false_status2, false_body2, false_err2 = self._do_request(false_url, cookie, false_data, headers)
            if not true_err2 and not false_err2:
                true_sim2 = max(self._similarity(true_body2, cs[1]) for cs in control_samples)
                false_sim2 = max(self._similarity(false_body2, cs[1]) for cs in control_samples)
                true_ok2 = true_sim2 >= max(noise_floor - 0.03, 0.80)
                false_ok2 = false_sim2 <= max(noise_floor - 0.10, 0.0)
                status_ok2 = (true_status2 != false_status2) and (true_status2 == baseline_status)
                confirmed = true_ok2 and (false_ok2 or status_ok2)

        return ScanResult(
            url=url, payload=combined_payload, tested_url=f"{true_url}  |||  {false_url}",
            method=self.method, vulnerable=vulnerable, confirmed=confirmed,
            status_code=true_status, response_time=None, mode="boolean",
            true_similarity=round(true_sim, 3), false_similarity=round(false_sim, 3),
            noise_floor=round(noise_floor, 3),
        )

    def perform_request(self, url: str, payload: str, cookie: Optional[str]) -> ScanResult:
        """Send one payload request, compare against baseline, and optionally re-confirm."""
        tested_url = self._inject(url, payload)
        payload_data = self._inject_data(payload)

        # Baseline MUST be measured with clean headers. Building the header-injection
        # payload before this point would mean the "control" request already carries
        # the delay-triggering value, making delta ~0 even on a truly vulnerable header.
        base_headers = {"User-Agent": self.get_user_agent(), **self.extra_headers}
        baseline = self.get_baseline(url, cookie, base_headers)

        headers = dict(base_headers)
        if self.header_name:
            headers[self.header_name] = payload

        elapsed, status, _, err = self._do_request(tested_url, cookie, payload_data, headers)
        timed_out = err == "Request timed out"

        # A genuine connection/HTTP error tells us nothing about timing - discard it.
        # A timeout is different: it means the response took at least --timeout to
        # arrive, which is itself consistent with (and often stronger evidence of) a
        # delay-based injection. Previously this was filed as a plain "error" and
        # silently dropped from vulnerabilities_found, causing false negatives whenever
        # the true delay exceeded --timeout.
        if err and not timed_out:
            return ScanResult(
                url=url, payload=payload, tested_url=tested_url, method=self.method,
                vulnerable=False, confirmed=False, status_code=None,
                response_time=elapsed, baseline_time=baseline, delta=None,
                timed_out=False, error=err,
            )

        if timed_out:
            delta = None
            vulnerable = elapsed >= self.threshold
        else:
            delta = round(elapsed - baseline, 3)
            vulnerable = elapsed >= self.threshold and delta >= (self.threshold * 0.6)

        # "confirmed" means an independent retest reproduced the delay. If --no-confirm
        # was used, no retest happened, so we must NOT claim confirmed=True - doing so
        # previously caused every flagged hit to be logged and counted as "CONFIRMED"
        # with zero verification.
        confirmed = False
        if vulnerable and self.confirm:
            elapsed2, status2, _, err2 = self._do_request(tested_url, cookie, payload_data, headers)
            timed_out2 = err2 == "Request timed out"
            if timed_out2:
                confirmed = True
            elif not err2:
                delta2 = round(elapsed2 - baseline, 3)
                confirmed = elapsed2 >= self.threshold and delta2 >= (self.threshold * 0.6)

        return ScanResult(
            url=url, payload=payload, tested_url=tested_url, method=self.method,
            vulnerable=vulnerable, confirmed=confirmed, status_code=status,
            response_time=elapsed, baseline_time=baseline, delta=delta,
            timed_out=timed_out, error=("Request timed out" if timed_out else None),
        )

    def _handle_result(self, result: ScanResult) -> None:
        self.report.total_tests += 1
        self.report.results.append(result)

        # A non-vulnerable error (connection failure, non-timeout exception) tells us
        # nothing - log and skip. A vulnerable result that happens to carry a timeout
        # note must still flow through to the vulnerable branch below.
        if result.error and not result.vulnerable:
            self.logger.debug(f"{Color.DIM}✗ Error: {result.tested_url} -> {result.error}{Color.RESET}")
            return

        if result.vulnerable:
            self.report.vulnerabilities_found += 1
            self.report.vulnerable_urls.append(result.tested_url)
            timeout_note = " [response exceeded --timeout]" if result.timed_out else ""

            if result.mode == "boolean":
                evidence = (
                    f"true~baseline={result.true_similarity}, false~baseline={result.false_similarity}, "
                    f"noise_floor={result.noise_floor}"
                )
            else:
                delta_str = f", delta={result.delta}s" if result.delta is not None else ""
                evidence = f"time={result.response_time}s, baseline={result.baseline_time}s{delta_str}"

            if result.confirmed:
                self.report.confirmed_vulnerabilities += 1
                label = "CONFIRMED Boolean-Based SQLi" if result.mode == "boolean" else "CONFIRMED SQLi"
                self.logger.info(
                    f"{Color.GREEN}✓✓ {label}: {result.tested_url}{timeout_note} ({evidence}){Color.RESET}"
                )
                if self.telegram_token and self.telegram_chat_id:
                    send_telegram_confirmed_alert(
                        self.telegram_token, self.telegram_chat_id, result, self.logger
                    )
                if self.stop_on_confirm:
                    self.logger.warning(
                        f"{Color.YELLOW}--stop-on-confirm is set - a confirmed finding was hit, "
                        f"halting further requests to this target.{Color.RESET}"
                    )
                    self._stop_event.set()
            elif not self.confirm:
                self.logger.info(
                    f"{Color.YELLOW}⚠ FLAGGED (confirmation disabled, verify manually): "
                    f"{result.tested_url}{timeout_note} ({evidence}){Color.RESET}"
                )
            else:
                self.logger.info(
                    f"{Color.YELLOW}✓ Possible SQLi (unconfirmed on retest): {result.tested_url}{timeout_note} "
                    f"({evidence}){Color.RESET}"
                )
        else:
            self.logger.debug(
                f"{Color.RED}✗ Not vulnerable: {result.tested_url} "
                f"(status={result.status_code}, time={result.response_time}s, "
                f"baseline={result.baseline_time}s){Color.RESET}"
            )

    def run(self, urls: List[str], payloads: List[str], cookie: Optional[str], threads: int) -> ScanReport:
        self.report.started_at = datetime.now().isoformat(timespec="seconds")

        def dispatch(url: str, payload_line: str) -> Optional[ScanResult]:
            if self._stop_event.is_set():
                return None
            if self.mode == "boolean":
                true_payload, _, false_payload = payload_line.partition("|||")
                return self.perform_boolean_request(url, true_payload.strip(), false_payload.strip(), cookie)
            return self.perform_request(url, payload_line, cookie)

        try:
            if threads <= 1:
                for url in urls:
                    if self._stop_event.is_set():
                        break
                    for payload in payloads:
                        if self._stop_event.is_set():
                            break
                        result = dispatch(url, payload)
                        if result is not None:
                            self._handle_result(result)
            else:
                with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
                    futures = [
                        pool.submit(dispatch, url, payload)
                        for url in urls
                        for payload in payloads
                    ]
                    for future in concurrent.futures.as_completed(futures):
                        if self._stop_event.is_set():
                            # A confirmed finding has already been hit; stop processing
                            # further results and cancel anything not yet started (some
                            # already-in-flight requests may still complete in the
                            # background and be discarded - that's an acceptable
                            # trade-off for "stop ASAP" rather than a hard socket-level
                            # abort).
                            for f in futures:
                                f.cancel()
                            break
                        result = future.result()
                        if result is not None:
                            self._handle_result(result)
        except KeyboardInterrupt:
            self.logger.warning(f"{Color.YELLOW}Scan interrupted by user.{Color.RESET}")

        self.report.finished_at = datetime.now().isoformat(timespec="seconds")
        return self.report

    def save_vulnerable_urls(self, filename: str) -> None:
        with open(filename, "w", encoding="utf-8") as fh:
            for url in self.report.vulnerable_urls:
                fh.write(f"{url}\n")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blindstrike.py",
        description=(
            f"{__tool__} - Blind SQL Injection Testing Framework (By {__author__})\n\n"
            "Time-based Blind SQL Injection scanner for authorized security "
            "assessments. Injects payloads into a URL, POST body, or header and "
            "flags a target as potentially vulnerable when the response is "
            "delayed beyond a configurable threshold, verified against a "
            "measured baseline and (by default) a repeat request."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Single URL, payload appended at the end (classic mode)\n"
            "  python blindstrike.py -u \"http://target.com/item?id=1\" -p payloads/mysql.txt\n\n"
            "  # Inject at an exact point using the FUZZ marker\n"
            "  python blindstrike.py -u \"http://target.com/item?id=1FUZZ&cat=2\" -p payloads/mysql.txt\n\n"
            "  # POST body injection\n"
            "  python blindstrike.py -u \"http://target.com/login\" -X POST "
            "-d \"user=admin&pass=FUZZ\" -p payloads/mysql.txt\n\n"
            "  # Inject via a header (e.g. testing X-Forwarded-For)\n"
            "  python blindstrike.py -u \"http://target.com/\" --header-name X-Forwarded-For "
            "-p payloads/mysql.txt\n\n"
            "  # List of URLs, 10 threads, save vulnerable URLs + JSON + HTML report\n"
            "  python blindstrike.py -l urls.txt -p payloads/generic.txt -t 10 "
            "-o vulnerable.txt --report report.json --html-report report.html\n\n"
            "  # Custom delay threshold and cookie, verbose output\n"
            "  python blindstrike.py -u \"http://target.com/search?q=test\" "
            "-p payloads/postgresql.txt --threshold 8 -c \"session=abc123\" -v\n\n"
            "  # No banner, no color, no confirmation retest (CI / pipe-friendly)\n"
            "  python blindstrike.py -u \"http://target.com/\" -p payloads/xor.txt --no-banner --no-color --no-confirm\n"
        ),
    )

    target_group = parser.add_mutually_exclusive_group(required=False)
    target_group.add_argument("-u", "--url", help="Single target URL to test. Use the literal FUZZ marker to pick the exact injection point.")
    target_group.add_argument("-l", "--list", dest="url_list", help="Path to a file containing target URLs (one per line).")

    parser.add_argument(
        "-p", "--payloads",
        help="Path to the payload file. For --mode time (default), one delay payload per "
             "line (e.g. payloads/mysql.txt). For --mode boolean, each line is "
             "'TRUE_PAYLOAD|||FALSE_PAYLOAD' (see payloads/boolean_generic.txt).",
    )
    parser.add_argument(
        "--mode", choices=["time", "boolean"], default="time",
        help="Detection mode. 'time' (default): classic time-based delay detection - "
             "unchanged, this is still the tool's core. 'boolean': for each payload line, "
             "sends a TRUE and a FALSE condition and flags the target if the TRUE response "
             "matches normal page content while the FALSE response diverges beyond the "
             "page's own measured noise floor.",
    )
    parser.add_argument("-c", "--cookie", default=None, help="Cookie to include with each request.")
    parser.add_argument("-X", "--method", default="GET", choices=["GET", "POST", "PUT", "PATCH", "DELETE"],
                         help="HTTP method to use. Default: GET.")
    parser.add_argument("-d", "--data", default=None,
                         help="Request body for POST/PUT/PATCH. Use FUZZ to mark the injection point, "
                              "otherwise the payload is appended to the body.")
    parser.add_argument("-H", "--header", action="append", default=[],
                         help="Extra header, format 'Name: value'. Repeatable.")
    parser.add_argument("--header-name", default=None,
                         help="Inject payloads into this header instead of the URL/body "
                              "(e.g. X-Forwarded-For, Referer, User-Agent).")
    parser.add_argument(
        "-t", "--threads", type=int, default=0,
        help="Number of concurrent threads (0-20). 0 or 1 = sequential. Default: 0.",
    )
    parser.add_argument(
        "--threshold", type=float, default=10.0,
        help="Response time (seconds) above which a target is flagged vulnerable. Default: 10.0.",
    )
    parser.add_argument(
        "--timeout", type=float, default=20.0,
        help="Per-request timeout in seconds. Should be higher than --threshold. Default: 20.0.",
    )
    parser.add_argument("--no-confirm", action="store_true",
                         help="Skip the automatic re-test of flagged hits before counting them confirmed.")
    parser.add_argument("--stop-on-confirm", action="store_true",
                         help="Stop sending further requests to the target(s) as soon as one CONFIRMED "
                              "finding is hit. Off by default (a full scripted scan still runs every "
                              "payload); the interactive wizard enables this by default.")
    parser.add_argument("--baseline-samples", type=int, default=2,
                         help="Number of control (no-payload) requests used to measure normal latency per target. Default: 2.")
    parser.add_argument("--retries", type=int, default=1,
                         help="HTTP-level retries on 5xx/connection errors per request. Default: 1.")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification.")
    parser.add_argument("--proxy", default=None, help="Route requests through a proxy, e.g. http://127.0.0.1:8080 (Burp).")
    parser.add_argument("-o", "--output", help="Save discovered vulnerable URLs to this file.")
    parser.add_argument("--report", help="Save a full JSON scan report to this file.")
    parser.add_argument("--csv-report", help="Save a full CSV scan report to this file.")
    parser.add_argument("--html-report", help="Save a styled HTML scan report to this file.")
    parser.add_argument("--telegram-token", default=None,
                         help="Telegram bot token. When set with --telegram-chat-id (or via the "
                              "BLINDSTRIKE_TELEGRAM_TOKEN/BLINDSTRIKE_TELEGRAM_CHAT_ID env vars, or a "
                              "previously saved wizard config at ~/.blindstrike/config.json), an "
                              "immediate alert is sent for every CONFIRMED finding, plus a summary "
                              "with the report file(s) attached when the scan finishes.")
    parser.add_argument("--telegram-chat-id", default=None,
                         help="Telegram chat ID to notify. Requires --telegram-token (or the "
                              "equivalent env var / saved config).")
    parser.add_argument("--no-save-telegram", action="store_true",
                         help="Don't persist Telegram credentials entered interactively to "
                              "~/.blindstrike/config.json for future runs.")
    parser.add_argument("--log-file", help="Write logs to this file in addition to stdout.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (show non-vulnerable results too).")
    parser.add_argument("--no-banner", action="store_true", help="Suppress the startup banner.")
    parser.add_argument("--no-color", action="store_true", help="Disable colored terminal output.")
    parser.add_argument(
        "--version", action="version",
        version=f"{__tool__} {__version__} - By {__author__}",
    )

    return parser


def print_banner():
    print(f"{Color.CYAN}{BANNER.format(version=__version__)}{Color.RESET}")


def parse_headers(raw: List[str]) -> Dict[str, str]:
    headers = {}
    for item in raw:
        if ":" not in item:
            continue
        name, _, value = item.partition(":")
        headers[name.strip()] = value.strip()
    return headers


def _ask_yn(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        raw = input(f"{Color.PURPLE}{prompt} [{hint}]: {Color.RESET}").strip().lower()
        if raw == "":
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print(f"{Color.DIM}Please answer y or n.{Color.RESET}")


def _ask_text(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    raw = input(f"{Color.CYAN}{prompt}{suffix}: {Color.RESET}").strip()
    return raw or default


def _ask_int(prompt: str, default: int) -> int:
    while True:
        raw = input(f"{Color.CYAN}{prompt} [{default}]: {Color.RESET}").strip()
        if raw == "":
            return default
        try:
            return int(raw)
        except ValueError:
            print(f"{Color.DIM}Please enter a whole number.{Color.RESET}")


def _ask_choice(prompt: str, options: List[str], default_index: int = 0) -> int:
    print(f"{Color.CYAN}{prompt}{Color.RESET}")
    for i, opt in enumerate(options, 1):
        marker = " (default)" if (i - 1) == default_index else ""
        print(f"  {Color.CYAN}{i}){Color.RESET} {opt}{Color.DIM}{marker}{Color.RESET}")
    while True:
        raw = input(f"{Color.CYAN}Choice [{default_index + 1}]: {Color.RESET}").strip()
        if raw == "":
            return default_index
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return int(raw) - 1
        print(f"{Color.DIM}Please enter a number between 1 and {len(options)}.{Color.RESET}")


def interactive_prompt() -> argparse.Namespace:
    """Modern guided wizard - runs whenever blindstrike.py is launched with no
    arguments. Every question is a short y/n or numbered choice so a full scan can be
    set up without typing or remembering a single CLI flag; power users can still use
    every flag documented in --help for scripted/automated runs.
    """
    print(f"{Color.CYAN}{Color.BOLD}Guided setup{Color.RESET} {Color.DIM}(run with --help instead for full CLI flags){Color.RESET}\n")

    target = _ask_text("Target URL (use FUZZ to mark the exact injection point), or a path to a URL list file")
    while not target:
        print(f"{Color.DIM}A target URL or file is required.{Color.RESET}")
        target = _ask_text("Target URL, or a path to a URL list file")

    mode_idx = _ask_choice(
        "Detection mode:",
        ["Time-based (default - delay payloads like SLEEP()/WAITFOR)",
         "Boolean-based (content-diff, for injections with no timing effect)"],
        default_index=0,
    )
    mode = "boolean" if mode_idx == 1 else "time"

    payloads_dir = "payloads"
    default_payload_file = "boolean_generic.txt" if mode == "boolean" else "mysql.txt"
    available = []
    try:
        available = sorted(f for f in os.listdir(payloads_dir) if f.endswith(".txt"))
    except OSError:
        pass
    if available:
        default_idx = available.index(default_payload_file) if default_payload_file in available else 0
        choice_idx = _ask_choice(
            "Payload file:", [f"payloads/{f}" for f in available], default_index=default_idx
        )
        payloads = f"{payloads_dir}/{available[choice_idx]}"
    else:
        payloads = _ask_text("Path to payload file", default=f"{payloads_dir}/{default_payload_file}")

    threads = _ask_int("Concurrent threads (0 = sequential)", default=0)

    stop_on_confirm = _ask_yn("Stop scanning as soon as a CONFIRMED finding is hit?", default=True)

    want_cookie = _ask_yn("Add a cookie for authenticated testing?", default=False)
    cookie = _ask_text("Cookie value") if want_cookie else None

    want_reports = _ask_yn("Save JSON + CSV + HTML reports to disk?", default=True)
    report_path = csv_path = html_path = None
    if want_reports:
        report_path = "blindstrike_report.json"
        csv_path = "blindstrike_report.csv"
        html_path = "blindstrike_report.html"

    telegram_token, telegram_chat_id, telegram_source = resolve_telegram_credentials(None, None)
    no_save_telegram = False
    if telegram_token and telegram_chat_id and not _telegram_token_looks_valid(telegram_token):
        print(f"{Color.YELLOW}Your saved Telegram token doesn't look valid (this usually causes a "
              f"404 from Telegram) - let's re-enter it.{Color.RESET}")
        telegram_token = telegram_chat_id = None
    if telegram_token and telegram_chat_id:
        if not _ask_yn(f"Send results to your saved Telegram bot ({telegram_source} credentials)?", default=True):
            telegram_token = telegram_chat_id = None
    elif _ask_yn("Send results to a Telegram bot? (you'll only need to enter this once)", default=False):
        telegram_token = _ask_text("Telegram bot token (from @BotFather)")
        telegram_chat_id = _ask_text("Telegram chat ID")
        telegram_token, telegram_chat_id = _sanitize_telegram_creds(telegram_token, telegram_chat_id)
        if not (telegram_token and telegram_chat_id):
            print(f"{Color.YELLOW}Both a token and chat ID are needed - skipping Telegram for this run.{Color.RESET}")
            telegram_token = telegram_chat_id = None
        elif not _telegram_token_looks_valid(telegram_token):
            print(f"{Color.YELLOW}That doesn't look like a valid bot token (expected 'digits:secret', "
                  f"e.g. 123456789:ABCdef...) - skipping Telegram for this run. Double-check you copied "
                  f"the whole token from @BotFather with no extra text.{Color.RESET}")
            telegram_token = telegram_chat_id = None

    verbose = _ask_yn("Verbose output (show non-vulnerable results too)?", default=False)

    print()

    ns = argparse.Namespace(
        url=None,
        url_list=None,
        payloads=payloads,
        mode=mode,
        cookie=cookie,
        method="GET",
        data=None,
        header=[],
        header_name=None,
        threads=threads,
        threshold=10.0,
        timeout=20.0,
        no_confirm=False,
        stop_on_confirm=stop_on_confirm,
        baseline_samples=2,
        retries=1,
        insecure=False,
        proxy=None,
        output=None,
        report=report_path,
        csv_report=csv_path,
        html_report=html_path,
        telegram_token=telegram_token,
        telegram_chat_id=telegram_chat_id,
        no_save_telegram=no_save_telegram,
        log_file=None,
        verbose=verbose,
        no_banner=False,
        no_color=False,
    )

    if os.path.isfile(target):
        ns.url_list = target
    else:
        ns.url = target

    return ns


def load_urls(args: argparse.Namespace, scanner: BlindSQLi, logger: logging.Logger) -> List[str]:
    if args.url:
        return [args.url]
    if args.url_list:
        if not os.path.isfile(args.url_list):
            logger.error(f"{Color.RED}URL list file not found: {args.url_list}{Color.RESET}")
            return []
        return scanner.read_lines(args.url_list)
    return []


def _telegram_api_post(method: str, token: str, logger: logging.Logger, **kwargs):
    """Shared low-level POST to the Telegram Bot API. Returns the parsed JSON body on a
    successful (HTTP 200, ok:true) call, or None on any failure - network error, bad
    token, chat not started, etc. Never raises; every caller treats a Telegram failure
    as non-fatal to the scan itself, which has already completed by the time this runs.
    """
    try:
        resp = requests.post(f"https://api.telegram.org/bot{token}/{method}", timeout=20, **kwargs)
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        if resp.status_code == 200 and body.get("ok"):
            return body
        logger.warning(
            f"{Color.YELLOW}Telegram {method} failed: HTTP {resp.status_code} - {resp.text[:200]}{Color.RESET}"
        )
        return None
    except requests.exceptions.RequestException as exc:
        logger.warning(f"{Color.YELLOW}Telegram {method} failed: {exc}{Color.RESET}")
        return None


def send_telegram_confirmed_alert(token: str, chat_id: str, result: ScanResult,
                                   logger: logging.Logger) -> bool:
    """Fire an immediate, real-time alert the moment a finding is CONFIRMED - separate
    from (and ahead of) the end-of-scan summary, so a long scan doesn't sit on a real
    finding until it finishes.

    Privacy: this message is built ONLY from ScanResult's own fields (payload, injected
    URL, method, mode, timing/similarity evidence). ScanResult never carries cookies,
    Authorization headers, or any other request header - they are simply not part of
    this dataclass - so there is nothing sensitive to accidentally leak here by
    construction, not just by omission.
    """
    if result.mode == "boolean":
        evidence = (
            f"TRUE~baseline: `{result.true_similarity}`\n"
            f"FALSE~baseline: `{result.false_similarity}`\n"
            f"Noise floor: `{result.noise_floor}`"
        )
    else:
        timeout_note = " _(response exceeded --timeout)_" if result.timed_out else ""
        evidence = (
            f"Response time: `{result.response_time}s`{timeout_note}\n"
            f"Baseline: `{result.baseline_time}s`\n"
            f"Delta: `{result.delta}s`"
        )

    text = (
        f"🎯 *{__tool__} — CONFIRMED SQLi*\n\n"
        f"*Target:* `{result.url}`\n"
        f"*Method:* `{result.method}`  *Mode:* `{result.mode}`\n"
        f"*Payload:*\n`{result.payload}`\n\n"
        f"*Evidence:*\n{evidence}\n\n"
        f"*Request sent:*\n`{result.tested_url}`\n\n"
        f"⚠️ Verify manually before reporting. Confirmed via one automatic retest."
    )
    body = _telegram_api_post(
        "sendMessage", token, logger,
        data={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
    )
    if body:
        logger.info(f"{Color.GREEN}Telegram alert sent for confirmed finding.{Color.RESET}")
        return True
    return False


def send_telegram_document(token: str, chat_id: str, file_path: str, caption: str,
                            logger: logging.Logger) -> bool:
    """Upload a report file (JSON/CSV/HTML) to the Telegram chat via sendDocument, so
    the actual report - not just a text summary - lands directly in the chat."""
    if not file_path or not os.path.isfile(file_path):
        return False
    try:
        with open(file_path, "rb") as fh:
            body = _telegram_api_post(
                "sendDocument", token, logger,
                data={"chat_id": chat_id, "caption": caption[:1024]},
                files={"document": (os.path.basename(file_path), fh)},
            )
    except OSError as exc:
        logger.warning(f"{Color.YELLOW}Could not read report file for Telegram upload: {exc}{Color.RESET}")
        return False
    if body:
        logger.info(f"{Color.GREEN}Sent {os.path.basename(file_path)} to Telegram.{Color.RESET}")
        return True
    return False


def send_telegram_notification(token: str, chat_id: str, report: ScanReport, mode: str,
                                targets: List[str], report_paths: Dict[str, str],
                                logger: logging.Logger) -> bool:
    """Send the end-of-scan summary to a Telegram chat, then upload any generated
    report files (JSON/CSV/HTML) as documents so the recipient has the full report,
    not just a text summary.

    Privacy: built only from the ScanReport summary counts, the target URL(s), and the
    report file paths/contents the user explicitly asked to save - never from
    cookies or headers, which this function never receives.
    """
    lines = [
        f"🛰 *{__tool__}* scan complete",
        f"Mode: `{mode}`",
    ]
    for t in targets[:3]:
        lines.append(f"Target: `{t}`")
    if len(targets) > 3:
        lines.append(f"...and {len(targets) - 3} more target(s)")
    lines += [
        f"Total tests: {report.total_tests}",
        f"Flagged: {report.vulnerabilities_found}",
        f"Confirmed: {report.confirmed_vulnerabilities}",
    ]
    if report.vulnerable_urls:
        shown = report.vulnerable_urls[:5]
        lines.append("")
        lines.append("Flagged targets:")
        lines.extend(f"- `{u}`" for u in shown)
        if len(report.vulnerable_urls) > len(shown):
            lines.append(f"...and {len(report.vulnerable_urls) - len(shown)} more (see the attached report).")
    if any(report_paths.values()):
        lines.append("")
        lines.append("Reports attached below.")
    text = "\n".join(lines)

    body = _telegram_api_post(
        "sendMessage", token, logger,
        data={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
    )
    ok = bool(body)
    if ok:
        logger.info(f"{Color.GREEN}Telegram summary sent.{Color.RESET}")

    caption = f"{__tool__} report - {report.confirmed_vulnerabilities} confirmed / {report.vulnerabilities_found} flagged"
    for label, path in report_paths.items():
        if path:
            send_telegram_document(token, chat_id, path, f"{caption} ({label})", logger)

    return ok


def print_summary_table(report: ScanReport, mode: str) -> None:
    """Print a clean, bordered summary box at the end of a scan - colored green if a
    confirmed finding exists, yellow if something was flagged but unconfirmed, red if
    the scan came back clean."""
    if report.confirmed_vulnerabilities > 0:
        accent, verdict = Color.GREEN, "CONFIRMED VULNERABLE"
    elif report.vulnerabilities_found > 0:
        accent, verdict = Color.YELLOW, "FLAGGED - VERIFY MANUALLY"
    else:
        accent, verdict = Color.RED, "NO VULNERABILITIES FOUND"

    rows = [
        ("Mode", mode),
        ("Total tests", str(report.total_tests)),
        ("Flagged", str(report.vulnerabilities_found)),
        ("Confirmed", str(report.confirmed_vulnerabilities)),
        ("Verdict", verdict),
    ]
    label_w = max(len(r[0]) for r in rows)
    value_w = max(len(r[1]) for r in rows)
    inner_w = label_w + value_w + 3

    print()
    print(f"{accent}┌─ SCAN COMPLETE {'─' * max(0, inner_w - 14)}┐{Color.RESET}")
    for label, value in rows:
        print(f"{accent}│{Color.RESET} {label.ljust(label_w)} : {value.ljust(value_w)} {accent}│{Color.RESET}")
    print(f"{accent}└{'─' * (inner_w + 2)}┘{Color.RESET}")


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    if not args.url and not args.url_list and not args.payloads and len(sys.argv) == 1:
        args = interactive_prompt()

    if args.no_color:
        Color.disable()

    if not args.no_banner:
        print_banner()

    logger = build_logger(args.verbose, args.log_file)

    if args.threads < 0 or args.threads > 20:
        logger.error(f"{Color.RED}--threads must be between 0 and 20.{Color.RESET}")
        return 1

    if not args.payloads:
        logger.error(f"{Color.RED}No payload file specified. Use -p/--payloads.{Color.RESET}")
        return 1

    if not os.path.isfile(args.payloads):
        logger.error(f"{Color.RED}Payload file not found: {args.payloads}{Color.RESET}")
        return 1

    if args.timeout <= args.threshold:
        logger.warning(
            f"{Color.YELLOW}--timeout ({args.timeout}s) should be greater than --threshold "
            f"({args.threshold}s) or delayed responses will be cut off as timeouts.{Color.RESET}"
        )

    if args.data and args.method == "GET":
        logger.warning(
            f"{Color.YELLOW}--data was provided but --method is GET; the body will not be sent. "
            f"Use -X POST (or PUT/PATCH) to actually deliver it.{Color.RESET}"
        )

    telegram_token, telegram_chat_id, telegram_source = resolve_telegram_credentials(
        args.telegram_token, args.telegram_chat_id
    )
    if bool(args.telegram_token) != bool(args.telegram_chat_id):
        logger.warning(
            f"{Color.YELLOW}--telegram-token and --telegram-chat-id must both be set - "
            f"ignoring the one that was provided.{Color.RESET}"
        )
    if telegram_token and not _telegram_token_looks_valid(telegram_token):
        logger.warning(
            f"{Color.YELLOW}The Telegram token from {telegram_source} doesn't look like a valid "
            f"bot token (expected 'digits:secret', e.g. 123456789:ABCdef...). This is almost always "
            f"a stray space/newline picked up from copy-pasting it, or the word 'bot' pasted along "
            f"with the token - and causes Telegram's API to return 404. Skipping Telegram for this "
            f"run; re-run with a freshly copied --telegram-token to fix the saved value.{Color.RESET}"
        )
        telegram_token = telegram_chat_id = None
    elif telegram_token and telegram_source == "saved":
        logger.info(f"{Color.CYAN}Using saved Telegram credentials from {CONFIG_PATH}.{Color.RESET}")
    elif telegram_token and telegram_source == "cli" and not args.no_save_telegram:
        if save_telegram_config(telegram_token, telegram_chat_id):
            logger.info(f"{Color.CYAN}Telegram credentials saved to {CONFIG_PATH} for future runs "
                        f"(use --no-save-telegram to skip this).{Color.RESET}")

    scanner = BlindSQLi(
        logger=logger,
        threshold=args.threshold,
        timeout=args.timeout,
        method=args.method,
        data=args.data,
        headers=parse_headers(args.header),
        header_name=args.header_name,
        confirm=not args.no_confirm,
        baseline_samples=args.baseline_samples,
        retries=args.retries,
        insecure=args.insecure,
        proxy=args.proxy,
        mode=args.mode,
        stop_on_confirm=args.stop_on_confirm,
        telegram_token=telegram_token,
        telegram_chat_id=telegram_chat_id,
    )

    urls = load_urls(args, scanner, logger)
    if not urls:
        logger.error(f"{Color.RED}No valid target URL(s) provided. Use -u or -l.{Color.RESET}")
        return 1

    try:
        payloads = scanner.read_lines(args.payloads)
    except OSError as exc:
        logger.error(f"{Color.RED}Could not read payload file: {exc}{Color.RESET}")
        return 1

    if not payloads:
        logger.error(f"{Color.RED}Payload file is empty: {args.payloads}{Color.RESET}")
        return 1

    if args.mode == "boolean":
        bad_lines = [p for p in payloads if "|||" not in p]
        if bad_lines:
            logger.error(
                f"{Color.RED}--mode boolean requires every payload line to be "
                f"'TRUE_PAYLOAD|||FALSE_PAYLOAD'. {len(bad_lines)} line(s) in "
                f"{args.payloads} don't contain the '|||' separator, e.g.: {bad_lines[0]!r}{Color.RESET}"
            )
            return 1

    inject_point = "header:" + args.header_name if args.header_name else (
        "body(FUZZ)" if args.data and FUZZ_MARKER in args.data else
        "url(FUZZ)" if any(FUZZ_MARKER in u for u in urls) else "url(append)"
    )

    logger.info(
        f"{Color.PURPLE}Starting scan | mode={args.mode} | targets={len(urls)} | payloads={len(payloads)} "
        f"| method={args.method} | inject={inject_point} | threads={args.threads or 1} "
        f"| threshold={args.threshold}s | confirm={not args.no_confirm}{Color.RESET}"
    )

    report = scanner.run(urls=urls, payloads=payloads, cookie=args.cookie, threads=args.threads)

    print_summary_table(report, args.mode)

    if args.output:
        try:
            scanner.save_vulnerable_urls(args.output)
            logger.info(f"{Color.GREEN}Vulnerable URLs saved to {args.output}{Color.RESET}")
        except OSError as exc:
            logger.error(f"{Color.RED}Failed to save vulnerable URLs: {exc}{Color.RESET}")

    saved_reports: Dict[str, str] = {"json": "", "csv": "", "html": ""}

    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8") as fh:
                fh.write(report.to_json())
            logger.info(f"{Color.GREEN}JSON report saved to {args.report}{Color.RESET}")
            saved_reports["json"] = args.report
        except OSError as exc:
            logger.error(f"{Color.RED}Failed to save JSON report: {exc}{Color.RESET}")

    if args.csv_report:
        try:
            with open(args.csv_report, "w", encoding="utf-8", newline="") as fh:
                fh.write(report.to_csv())
            logger.info(f"{Color.GREEN}CSV report saved to {args.csv_report}{Color.RESET}")
            saved_reports["csv"] = args.csv_report
        except OSError as exc:
            logger.error(f"{Color.RED}Failed to save CSV report: {exc}{Color.RESET}")

    if args.html_report:
        try:
            with open(args.html_report, "w", encoding="utf-8") as fh:
                fh.write(report.to_html())
            logger.info(f"{Color.GREEN}HTML report saved to {args.html_report}{Color.RESET}")
            saved_reports["html"] = args.html_report
        except OSError as exc:
            logger.error(f"{Color.RED}Failed to save HTML report: {exc}{Color.RESET}")

    if telegram_token and telegram_chat_id:
        send_telegram_notification(telegram_token, telegram_chat_id, report, args.mode, urls, saved_reports, logger)

    print(f"{Color.CYAN}Thank you for using {__tool__} - By {__author__}.{Color.RESET}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}Interrupted. Exiting.{Color.RESET}")
        sys.exit(130)

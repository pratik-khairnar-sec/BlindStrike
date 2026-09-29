# BlindStrike

![Version](https://img.shields.io/badge/version-7.0.0-brightgreen)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT%20%2B%20authorized--use-lightgrey)
![Status](https://img.shields.io/badge/status-stable-success)

**Time-Based & Boolean Blind SQL Injection Testing Framework — v7.0.0**

By **Pratik Khairnar**

BlindStrike helps security researchers identify potential SQL injection points using two detection techniques: **time-based** (the tool's core — measuring response-time differences from database-specific delay payloads) and **boolean-based** (comparing page content between a TRUE and a FALSE condition). It injects payloads into a URL, a POST/PUT body, or an HTTP header, and every flagged hit is checked against a measured baseline and a repeat request before being called confirmed, to cut down on false positives from ordinary network jitter or dynamic page content.

> ⚠️ This is a detection aid, not a fully automated exploitation framework. Even with baseline + confirmation checks, always manually verify a flagged endpoint before reporting it (see [Limitations](#limitations)).

---

## What's new in v7.0.0

This release number consolidates every 2.x release into BlindStrike's first stable major version, plus a real bug fix found from live use:

- **Fixed: Telegram `404 Not Found` on `sendMessage`/`sendDocument`.** Root cause: a stray trailing space/newline in a copy-pasted bot token (or the word "bot" pasted along with it) was silently percent-encoded into the request URL rather than rejected, so Telegram looked up a bot token that didn't actually exist and correctly returned 404. Token and chat ID are now sanitized (whitespace/newline stripped, a mistaken `bot` prefix removed) at every entry point — CLI flag, environment variable, saved config, and the wizard — and validated against the real token format (`digits:secret`) before any network call, with a clear explanation if something still looks wrong instead of an opaque HTTP error. A previously-saved bad value self-heals the next time it's read.
- Everything from v2.0.0 through v2.3.0 below — time-based and boolean-based detection, `FUZZ`, all DBMS payload sets, the guided wizard, `--stop-on-confirm`, persistent Telegram credentials, real-time confirmed alerts, report-to-Telegram upload, the dark-themed HTML report, and the full test suite — carries forward unchanged except for this fix.

## What's new in v2.3.0

- **Guided setup wizard.** Running `python blindstrike.py` with no arguments now walks through a short series of y/n and numbered-choice questions (target, detection mode, payload file, threads, stop-on-confirm, cookie, reports, Telegram) instead of requiring every flag to be typed out. Every flag is still there for scripted/CI use - the wizard is purely an on-ramp.
- **`--stop-on-confirm`.** Halts the scan the moment a finding is CONFIRMED, instead of continuing through every remaining payload. Off by default for scripted runs (so an automated scan still gets full coverage); the wizard turns it on by default. Works in both sequential and multi-threaded (`-t`) modes.
- **Persistent Telegram credentials.** `--telegram-token`/`--telegram-chat-id` entered once (via CLI or the wizard) are saved to `~/.blindstrike/config.json` (mode `0600`) and reused automatically on every future run - no more retyping a bot token on every scan. Priority is CLI flag > `BLINDSTRIKE_TELEGRAM_TOKEN`/`BLINDSTRIKE_TELEGRAM_CHAT_ID` env vars > saved config. Use `--no-save-telegram` to enter credentials for a one-off run without persisting them.
- **Real-time confirmed-finding alerts.** A Telegram message is sent the instant a finding is CONFIRMED - not just in the end-of-scan summary - so a long scan doesn't sit on a real result until it finishes.
- **Reports delivered straight to Telegram.** The end-of-scan summary now uploads the actual JSON/CSV/HTML report file(s) as Telegram documents (`sendDocument`), not just a text summary with a path on disk.
- **Sharper HTML report.** Dark theme, every request link opens in a new tab (`target="_blank"`), and a dedicated "Proof of Concept" block is generated per confirmed finding (target, payload, evidence, full request, a manual-verification reminder) - in addition to the existing full results table.
- **Bordered terminal summary** at the end of every scan, colored green/yellow/red by verdict.
- **`tests/test_blindstrike.py`** - 25 offline unit tests (no network required) covering URL encoding, boolean-mode similarity/noise-floor math, Telegram config persistence and priority, stop-on-confirm, report generation, and the no-sensitive-data-in-Telegram-messages guarantee.
- Everything from v2.2.x and earlier - time-based and boolean-based detection, `FUZZ`, all DBMS payload sets, JSON/CSV/HTML reporting, every existing CLI flag - is unchanged.

## What's new in v2.2.0

- **Boolean-based detection mode (`--mode boolean`).** Time-based detection can't see anything on a page that doesn't have a timing side effect — if a payload has no delay function in it, the response comes back at normal speed regardless of whether the injection worked, and the tool correctly (and silently) reports "not vulnerable." Boolean-based mode closes that gap: for each payload line (`TRUE_PAYLOAD|||FALSE_PAYLOAD`), it sends both conditions and compares each response's *content* — not its timing — against a measured baseline.
- **Noise-floor-aware content comparison.** Real pages rarely render byte-identical twice (visitor counters, CSRF tokens, timestamps, ad slots). Comparing raw response bodies against that kind of noise either drowns out genuine differences or triggers false positives. BlindStrike now takes 2+ clean baseline samples per target, normalizes out numeric/dynamic tokens from every response before diffing, and only flags a target when the TRUE response matches normal content while the FALSE response diverges beyond what the page's own natural noise floor would explain.
- **Telegram notifications (`--telegram-token` / `--telegram-chat-id`).** Get a scan summary pushed to a Telegram chat via the real Bot API the moment a scan finishes — useful for long unattended scans or bulk URL-list runs.
- Everything from v2.1.x — time-based detection, `FUZZ`, all DBMS payload sets, JSON/CSV/HTML reporting, every existing CLI flag — is unchanged and still the default (`--mode time`).

## What's new in v2.0.0

The original v1.0.0 could only append a payload to the end of a URL and flag anything over a raw time threshold, which made it noisy on slow or jittery targets. v2.0.0 is a substantial rework:

- **Baseline-aware detection.** Before scoring any payload, BlindStrike sends control (no-payload) requests to the same target and measures normal latency. A hit only counts if the response is both above `--threshold` **and** meaningfully slower than that baseline (`delta`), not just slow in absolute terms.
- **Automatic confirmation retest.** Any flagged hit is re-sent once by default; only if it delays a second time is it marked `CONFIRMED`. Unconfirmed hits are still reported, but clearly separated, so you don't waste a bug bounty report on a fluke.
- **Precise injection point with `FUZZ`.** Put the literal marker `FUZZ` anywhere in your URL, POST body, or a header value, and the payload is injected exactly there instead of always being appended to the end of the URL.
- **POST / PUT / PATCH support.** `-X` and `-d` let you test form bodies and JSON bodies, not just GET query strings.
- **Header injection.** `--header-name X-Forwarded-For` (or `Referer`, `User-Agent`, a custom API header, etc.) tests header-based injection points.
- **Proxy support.** `--proxy http://127.0.0.1:8080` routes every request through Burp Suite or another intercepting proxy for manual follow-up.
- **HTTP-level retries + `--insecure`.** Built on a `requests.Session` with `urllib3` retry/backoff for transient 5xx/connection errors, and an option to skip TLS verification for lab targets with self-signed certs.
- **Three report formats.** JSON (as before), plus new **CSV** (`--csv-report`) and a styled, self-contained **HTML** report (`--html-report`) that highlights confirmed vs. unconfirmed hits.
- **Comment support in input files.** Lines starting with `#` in URL lists and payload files are now skipped, so you can annotate them.
- Refreshed, current-generation User-Agent pool.

The CLI is fully backward compatible — every v1.0.0 command still works the same way; the new flags are additive.

---

## Overview

BlindStrike is a lightweight security research tool designed to assist authorized penetration testers and bug bounty researchers in identifying potential time-based SQL injection vulnerabilities.

## Features

- Time-based Blind SQLi detection across MySQL, MSSQL, PostgreSQL, Oracle, generic, and XOR-based payload sets (in `payloads/`).
- Single URL, or bulk scanning from a URL list.
- Precise injection point via the `FUZZ` marker — URL, POST/PUT body, or header.
- Multi-threaded scanning (configurable, 0–20 concurrent workers).
- Baseline measurement + automatic confirmation retest to reduce false positives.
- Configurable delay threshold, request timeout, baseline sample count, and HTTP retries.
- Cookie support and arbitrary extra headers for authenticated testing.
- Proxy support (e.g. Burp Suite) and `--insecure` for self-signed lab certs.
- Randomized User-Agent rotation per request.
- Clean, colored CLI output with `--verbose` for full result visibility.
- JSON, CSV, and styled HTML report export.
- Plain-text vulnerable-URL export (`--output`).
- Proper `argparse`-based CLI with `--help`/`--version`, plus a fallback interactive mode if run with no arguments.
- Structured logging, including optional log-to-file support.
- Graceful error handling — timeouts, connection errors, and malformed input don't crash the scan.

## Installation

### Requirements

- Python 3.8+
- pip

### Steps

```bash
git clone https://github.com/pratik-khairnar-sec/BlindStrike.git
cd BlindStrike
pip install -r requirements.txt
```

## Usage

### CLI help

```bash
python blindstrike.py --help
```

### Scan a single URL (classic append mode)

```bash
python blindstrike.py -u "http://target.com/item?id=1" -p payloads/mysql.txt
```

Without a `FUZZ` marker, BlindStrike appends each payload directly to the end of the URL you supply — make sure the URL ends where you want the injection point to be (e.g. `...?id=1` so the payload lands right after `1`).

### Scan with a precise injection point

```bash
python blindstrike.py -u "http://target.com/item?id=1FUZZ&cat=2" -p payloads/mysql.txt
```

`FUZZ` is replaced with each payload. This is useful when the parameter you want to test isn't at the end of the URL.

### POST body injection

```bash
python blindstrike.py -u "http://target.com/login" -X POST \
  -d "username=admin&password=FUZZ" -p payloads/mysql.txt
```

### Header injection

```bash
python blindstrike.py -u "http://target.com/" --header-name X-Forwarded-For \
  -p payloads/generic.txt
```

### Scan a list of URLs with threading

```bash
python blindstrike.py -l urls.txt -p payloads/generic.txt -t 10 \
  -o vulnerable.txt --report report.json --csv-report report.csv --html-report report.html
```

### Authenticated scan with a custom delay threshold

```bash
python blindstrike.py -u "http://target.com/search?q=test" \
  -p payloads/postgresql.txt --threshold 8 -c "session=abc123" -v
```

### Through Burp Suite, skipping TLS verification

```bash
python blindstrike.py -u "https://target.local/item?id=1" -p payloads/mysql.txt \
  --proxy http://127.0.0.1:8080 --insecure
```

### Boolean-based detection

Use this when a parameter is injectable but has no timing side effect on its own — a payload with no `SLEEP()`/`WAITFOR`/`pg_sleep()` in it never delays the response, so time-based mode will correctly report it as "not vulnerable." Boolean mode compares page *content* between a TRUE and a FALSE condition instead:

```bash
python blindstrike.py -u "http://target.com/item?id=1FUZZ" \
  -p payloads/boolean_generic.txt --mode boolean -v
```

Each line in the payload file is `TRUE_PAYLOAD|||FALSE_PAYLOAD` — see `payloads/boolean_generic.txt` for ready-to-use pairs, or write your own once you've confirmed manually (e.g. in Burp) which TRUE/FALSE syntax the target actually accepts.

### Telegram notifications (persistent, with real-time confirmed alerts)

```bash
python blindstrike.py -l urls.txt -p payloads/generic.txt -t 10 \
  --telegram-token "123456:ABC-your-bot-token" --telegram-chat-id "987654321"
```

Create a bot via [@BotFather](https://t.me/BotFather) to get a token, and message your bot once (or add it to a group) so Telegram lets it message that chat ID. The first time you provide `--telegram-token`/`--telegram-chat-id`, they're saved to `~/.blindstrike/config.json` (permissions `0600`) — every future run picks them up automatically, so you never have to pass them again. Skip the save for a one-off run with `--no-save-telegram`, or set them permanently via environment variables instead:

```bash
export BLINDSTRIKE_TELEGRAM_TOKEN="123456:ABC-your-bot-token"
export BLINDSTRIKE_TELEGRAM_CHAT_ID="987654321"
python blindstrike.py -u "http://target.com/?id=1FUZZ" -p payloads/mysql.txt
```

Priority when several sources are configured: `--telegram-token`/`--telegram-chat-id` flags > env vars > saved config.

With Telegram configured, two things happen automatically:
1. **Immediate alert** the instant any finding is CONFIRMED — target, payload, evidence, and the exact request sent — so you find out in real time, not just when the whole scan finishes.
2. **End-of-scan summary**, with the JSON/CSV/HTML report file(s) attached directly as Telegram documents (not just a path on disk).

Only summary counts, target URLs, payloads, and the report files you asked to save are ever sent — cookies, `Authorization` headers, and any other request headers are never part of these messages (the functions that build them don't even accept that data as a parameter).

### Stop as soon as something is confirmed

```bash
python blindstrike.py -u "http://target.com/?id=1FUZZ" -p payloads/mysql.txt --stop-on-confirm
```

Halts further requests to the target the moment one finding is CONFIRMED, instead of running through every remaining payload. Off by default for scripted/CI scans (so automation still gets full coverage); the guided wizard below turns it on by default.

### CI / non-interactive friendly (no banner, no ANSI color, skip confirmation retest)

```bash
python blindstrike.py -u "http://target.com/" -p payloads/xor.txt --no-banner --no-color --no-confirm
```

### Guided setup wizard

Running the script with no arguments at all launches a short guided wizard — no flags to remember, just answer a handful of y/n or numbered-choice questions (target, detection mode, payload file, threads, stop-on-confirm, cookie, reports, Telegram):

```bash
python blindstrike.py
```

```
Guided setup (run with --help instead for full CLI flags)

Target URL (use FUZZ to mark the exact injection point), or a path to a URL list file: https://target.com/search?q=FUZZ
Detection mode:
  1) Time-based (default - delay payloads like SLEEP()/WAITFOR)
  2) Boolean-based (content-diff, for injections with no timing effect)
Choice [1]:
Payload file:
  1) payloads/boolean_generic.txt
  2) payloads/generic.txt
  3) payloads/mssql.txt
  4) payloads/mysql.txt (default)
  ...
Choice [4]:
Concurrent threads (0 = sequential) [0]:
Stop scanning as soon as a CONFIRMED finding is hit? [Y/n]:
Add a cookie for authenticated testing? [y/N]:
Save JSON + CSV + HTML reports to disk? [Y/n]:
Send results to a Telegram bot? (you'll only need to enter this once) [y/N]:
Verbose output (show non-vulnerable results too)? [y/N]:
```

If Telegram credentials are already saved from a previous run, the wizard just asks a single "use your saved bot? (y/n)" instead of asking for the token and chat ID again.

## Key CLI options

| Flag | Description |
|---|---|
| `-u, --url` | Single target URL. Include `FUZZ` to mark the exact injection point. |
| `-l, --list` | Path to a file with one URL per line (`#` comments allowed). |
| `-p, --payloads` | Path to a payload file (see `payloads/`). Format depends on `--mode`. |
| `--mode` | `time` (default, core detection) or `boolean` (content-diff detection for non-delay-based injections). |
| `-X, --method` | HTTP method: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`. Default: `GET`. |
| `-d, --data` | Request body for POST/PUT/PATCH. Include `FUZZ`, or the payload is appended. |
| `-H, --header` | Extra header, `"Name: value"`. Repeatable. |
| `--header-name` | Inject payloads into this header instead of the URL/body. |
| `-c, --cookie` | Cookie string sent with every request. |
| `-t, --threads` | Concurrent worker threads (0–20, default: 0 = sequential). |
| `--threshold` | Response delay (seconds) that flags a hit (default: 10.0). |
| `--timeout` | Per-request timeout in seconds (default: 20.0). |
| `--no-confirm` | Skip the automatic retest of flagged hits. |
| `--stop-on-confirm` | Stop scanning the target as soon as one finding is CONFIRMED. |
| `--baseline-samples` | Control requests used to measure normal latency per target (default: 2). |
| `--retries` | HTTP-level retries on 5xx/connection errors (default: 1). |
| `--insecure` | Disable TLS certificate verification. |
| `--proxy` | Route requests through a proxy, e.g. Burp Suite. |
| `-o, --output` | Save discovered vulnerable URLs to a text file. |
| `--report` | Save a full JSON scan report. |
| `--csv-report` | Save a full CSV scan report. |
| `--html-report` | Save a styled HTML scan report. |
| `--telegram-token` / `--telegram-chat-id` | Send real-time confirmed-finding alerts + an end-of-scan summary (with report files attached) to a Telegram chat. Also settable via `BLINDSTRIKE_TELEGRAM_TOKEN`/`BLINDSTRIKE_TELEGRAM_CHAT_ID` env vars, or reused automatically once saved. |
| `--no-save-telegram` | Don't persist Telegram credentials entered via `--telegram-token`/`--telegram-chat-id` to `~/.blindstrike/config.json`. |
| `--log-file` | Mirror logs to a file. |
| `-v, --verbose` | Show non-vulnerable results and debug detail. |
| `--no-banner` / `--no-color` | Clean output for scripting/CI. |
| `--version` | Print version and exit. |

Run `python blindstrike.py --help` for the complete, always-current list.

## Payload sets

| File | Target |
|---|---|
| `payloads/mysql.txt` | MySQL / MariaDB |
| `payloads/mssql.txt` | Microsoft SQL Server |
| `payloads/postgresql.txt` | PostgreSQL |
| `payloads/oracle.txt` | Oracle |
| `payloads/xor.txt` | XOR-based blind conditions |
| `payloads/generic.txt` | Generic / DB-agnostic delay payloads |
| `payloads/boolean_generic.txt` | Generic TRUE\|\|\|FALSE pairs for `--mode boolean` |

You can add your own payload files — one payload per line, `#` comments allowed — and pass them with `-p`.

## How detection works

### Time-based (`--mode time`, default)

1. **Baseline.** For each target, BlindStrike first sends `--baseline-samples` control requests (no payload, and no header/body injection) and takes the median response time.
2. **Payload request.** The payload is injected (via `FUZZ`, URL append, body, or header) and the response time is measured.
3. **Scoring.** A hit is flagged if the response time is both ≥ `--threshold` **and** at least 60% of the threshold slower than the measured baseline — this rules out targets that are simply slow across the board. A request that doesn't return within `--timeout` at all is also flagged, since that's consistent with (often stronger evidence of) a delay exceeding what was measured.
4. **Confirmation.** By default, any flagged hit is re-sent once. Only if the delay reproduces is it marked `CONFIRMED`. With `--no-confirm`, no retest happens and results are reported as `FLAGGED` rather than `CONFIRMED` — they still need manual verification before being reported.

### Boolean-based (`--mode boolean`)

1. **Content baseline + noise floor.** BlindStrike sends 2+ clean control requests (no payload) and measures how similar they already are to *each other* after normalizing out numeric noise (counters, timestamps, tokens). This is the page's natural "noise floor" — if a page never renders identically twice even with no injection, the floor will be below 1.0, and the thresholds below adapt to it instead of assuming a static page.
2. **TRUE / FALSE requests.** For each `TRUE_PAYLOAD|||FALSE_PAYLOAD` line, both conditions are sent and each response body is compared against the baseline samples using normalized content similarity (`difflib`, after collapsing digit runs to a single placeholder).
3. **Scoring.** A hit is flagged only if the TRUE response looks like normal page content (similarity at or above the noise floor, within a small tolerance) **and** the FALSE response diverges meaningfully beyond that same noise floor — or the two conditions return different status codes while the TRUE condition matches the baseline's status. A page that always renders the same regardless of the condition (not injectable) or that's simply noisy in general (and whose FALSE divergence never exceeds its own noise floor) is not flagged.
4. **Confirmation.** By default, the TRUE/FALSE pair is re-sent once; only if the same content divergence reproduces is the result marked `CONFIRMED`.

## Roadmap

- [x] Time-Based Blind SQLi Detection
- [x] Multiple Database Payload Support
- [x] Multi-threaded Scanning
- [x] JSON Reporting
- [x] Baseline + confirmation to reduce false positives (v2.0.0)
- [x] Precise injection point (`FUZZ`), POST/header support (v2.0.0)
- [x] CSV / HTML Reporting (v2.0.0)
- [x] Boolean-Based Blind SQLi Detection (v2.2.0)
- [x] Telegram scan notifications (v2.2.0)

Future:

- [ ] Error-Based SQLi Detection
- [ ] Burp Suite Extension
- [ ] REST API Mode
- [ ] Advanced Parameter Discovery

## Limitations

- In `--mode time`, detection relies purely on response timing. Even with baseline comparison and confirmation retesting, it remains sensitive to network jitter, WAF rate limiting, and slow backends unrelated to SQLi. Always manually confirm any flagged endpoint (e.g. compare a `SLEEP(10)` payload against a `SLEEP(0)` control) before reporting it as a finding.
- In `--mode boolean`, detection relies on content-difference heuristics (normalized similarity + status codes). It can miss a real vulnerability if the TRUE/FALSE payload pair you supplied doesn't match the target's actual SQL syntax or comparison style, and — despite the noise-floor adaptation — can still be thrown off by highly dynamic pages (heavy A/B testing, per-request randomized layout). It is not a substitute for manually confirming the injection point first (e.g. in Burp).
- This tool does not perform data extraction, error-based detection, or out-of-band (OOB) detection — it is intentionally scoped to time-based and boolean-based blind detection only.
- Not a substitute for manual verification or a full DAST/SAST pipeline; use it as a first-pass triage tool.

## Requirements

```
requests>=2.31.0
urllib3>=2.0.0
```

Install with:

```bash
pip install -r requirements.txt
```

## Testing

Offline unit tests (no network access needed) live in `tests/test_blindstrike.py` and cover URL/`#`-encoding, boolean-mode content-similarity and noise-floor math, Telegram config persistence and priority ordering, `--stop-on-confirm`, report generation, and the guarantee that Telegram messages never carry cookies or headers:

```bash
python -m unittest tests.test_blindstrike -v
```

These don't touch the network at all — the live scanning behavior itself (baseline measurement, timing detection, boolean detection, confirmation retesting) is best verified against a target you control, e.g. a local test endpoint with a deliberate `time.sleep()` on a specific parameter value, run with `-v` to see every request BlindStrike makes.

## Disclaimer

⚠️ This tool is provided for authorized security testing, bug bounty research within a valid program scope, and educational purposes only.

Running BlindStrike (or any injection testing tool) against systems you do not own, or without explicit written authorization from the system owner, is illegal in most jurisdictions and may violate computer misuse laws such as the U.S. Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, or equivalent legislation elsewhere.

The author, Pratik Khairnar, assumes no liability and is not responsible for any misuse or damage caused by this tool. Use responsibly and at your own risk.

## Author

**Pratik Khairnar**
Security Researcher | Web Application Security | Bug Bounty | Application Security

## License

Released under the MIT License, with an additional authorized-use restriction — see the [LICENSE](LICENSE) file for details.

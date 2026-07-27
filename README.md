# Blind-SQLi

========================================
Blind-SQLi
Blind SQL Injection Framework
By Vaelion

A lightweight **Time-Based Blind SQL Injection detection framework** designed for authorized penetration testing, bug bounty research, and security education.

Blind-SQLi helps security researchers identify potential SQL injection points by measuring response-time differences using database-specific delay techniques.

> Blind SQL Injection Testing Framework

**Developed by Vaelion**
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Security Research](https://img.shields.io/badge/Focus-Bug%20Bounty-red)

Blind-SQLi is a lightweight, time-based Blind SQL Injection (BSQLi) testing
tool built for authorized security assessments, bug bounty research, and
security education. It appends database-specific delay payloads
(`SLEEP()`, `WAITFOR DELAY`, `pg_sleep()`, `dbms_pipe.receive_message()`,
XOR-based blind conditions, etc.) to target URLs and flags an endpoint as
potentially vulnerable when the response time exceeds a configurable
threshold — the classic signature of a time-based blind SQL injection flaw.

> ⚠️ This is a **detection aid**, not a fully automated exploitation
> framework. Time-based signals should always be manually verified before
> being reported (see [Limitations](#limitations) below).

---

## Overview

Blind-SQLi is a lightweight security research tool designed to assist
authorized penetration testers and bug bounty researchers in identifying
potential time-based SQL injection vulnerabilities.

## Features

- **Time-based Blind SQLi detection** across MySQL, MSSQL, PostgreSQL,
  Oracle, generic, and XOR-based payload sets (included in `payloads/`).
- **Single URL or bulk URL list** scanning.
- **Multi-threaded scanning** (configurable, 0–20 concurrent workers).
- **Configurable delay threshold and request timeout**, so you can tune
  detection sensitivity to the target environment.
- **Cookie support** for authenticated testing.
- **Randomized User-Agent rotation** per request.
- **Clean, colored CLI output** with a `--verbose` mode for full request/response
  visibility.
- **JSON report export** (`--report`) containing every test result — ideal
  for feeding into other tooling or attaching to a bug bounty report.
- **Plain-text vulnerable URL export** (`--output`).
- **Proper `argparse`-based CLI** with `--help` and `--version`, plus a
  fallback interactive mode if you run the script with no arguments.
- **Structured logging**, including optional log-to-file support.
- **Graceful error handling** — timeouts, connection errors, and malformed
  input no longer crash the scan.

---

## Installation

### Requirements

- Python 3.8+
- pip

### Steps

```bash
git clone https://github.com/pratikkhairnar160/Blind-SQLi.git
cd Blind-SQLi
pip install -r requirements.txt
```

---

## Usage

### CLI help

```bash
python blind_sqli.py --help
```

### Scan a single URL

```bash
python blind_sqli.py -u "http://target.com/item?id=1" -p payloads/mysql.txt
```

Blind-SQLi appends each payload directly to the end of the URL you supply —
make sure the URL ends where you want the injection point to be
(e.g. `...?id=1` so the payload lands right after `1`).

### Scan a list of URLs with threading

```bash
python blind_sqli.py -l urls.txt -p payloads/generic.txt -t 10 \
  -o vulnerable.txt --report report.json
```

### Authenticated scan with a custom delay threshold

```bash
python blind_sqli.py -u "http://target.com/search?q=test" \
  -p payloads/postgresql.txt --threshold 8 -c "session=abc123" -v
```

### CI / non-interactive friendly (no banner, no ANSI color)

```bash
python blind_sqli.py -u "http://target.com/" -p payloads/xor.txt --no-banner --no-color
```

### Interactive mode

Running the script with no arguments falls back to a guided prompt:

```bash
python blind_sqli.py
```

### Key CLI options

| Flag | Description |
|---|---|
| `-u`, `--url` | Single target URL |
| `-l`, `--list` | Path to a file with one URL per line |
| `-p`, `--payloads` | Path to a payload file (see `payloads/`) |
| `-c`, `--cookie` | Cookie string sent with every request |
| `-t`, `--threads` | Concurrent worker threads (0–20, default: 0 = sequential) |
| `--threshold` | Response delay (seconds) that flags a hit (default: 10.0) |
| `--timeout` | Per-request timeout in seconds (default: 20.0) |
| `-o`, `--output` | Save discovered vulnerable URLs to a text file |
| `--report` | Save a full JSON scan report |
| `--log-file` | Mirror logs to a file |
| `-v`, `--verbose` | Show non-vulnerable results and debug detail |
| `--no-banner` / `--no-color` | Clean output for scripting/CI |
| `--version` | Print version and exit |

---

## Payload Sets

| File | Target |
|---|---|
| `payloads/mysql.txt` | MySQL / MariaDB |
| `payloads/mssql.txt` | Microsoft SQL Server |
| `payloads/postgresql.txt` | PostgreSQL |
| `payloads/oracle.txt` | Oracle |
| `payloads/xor.txt` | XOR-based blind conditions |
| `payloads/generic.txt` | Generic / DB-agnostic delay payloads |

You can add your own payload files — one payload per line — and pass them
with `-p`.

---

## Roadmap

- [x] Time-Based Blind SQLi Detection
- [x] Multiple Database Payload Support
- [x] Multi-threaded Scanning
- [x] JSON Reporting

Future:

- [ ] Boolean-Based Blind SQLi
- [ ] Error-Based SQLi Detection
- [ ] Burp Suite Extension
- [ ] REST API Mode
- [ ] Advanced Parameter Discovery

## Limitations

- Detection relies purely on **response timing**, so it is sensitive to
  network jitter, WAF rate limiting, and slow backends unrelated to SQLi.
  Always manually confirm any flagged endpoint (e.g. compare a `SLEEP(10)`
  payload against a `SLEEP(0)` control) before reporting it as a finding.
- This tool does not perform data extraction, boolean-based blind SQLi
  detection, or error-based detection — it is intentionally scoped to
  time-based detection only.
- Not a substitute for manual verification or a full DAST/SAST pipeline;
  use it as a first-pass triage tool.

---

## Requirements

```
requests>=2.31.0
```

Install with:

```bash
pip install -r requirements.txt
```

---

## Disclaimer

⚠️ **This tool is provided for authorized security testing, bug bounty
research within a valid program scope, and educational purposes only.**

Running Blind-SQLi (or any injection testing tool) against systems you do
not own, or without explicit written authorization from the system owner,
is illegal in most jurisdictions and may violate computer misuse laws such
as the U.S. Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act,
or equivalent legislation elsewhere.

The author, **Vaelion**, assumes no liability and is not responsible for any
misuse or damage caused by this tool. Use responsibly and at your own risk.

---

## Author

**Vaelion**

Security Researcher | Web Application Security | Bug Bounty | Application Security

---

## License

Released under the [MIT License](LICENSE), with an additional authorized-use
restriction — see the `LICENSE` file for details.

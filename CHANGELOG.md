# Changelog

## v7.0.0

First stable major release — consolidates all 2.x work below under one version number, plus a real bug fix reported from live use against a real target.

### Fixed
- **Telegram `sendMessage`/`sendDocument` returning HTTP 404 Not Found.** Reproduced and confirmed the root cause: a trailing newline or space in a copy-pasted bot token (or the literal word "bot" pasted along with the token itself) was being silently percent-encoded into the request URL by `requests`/urllib3 rather than rejected outright - Telegram's API then correctly returns 404 for a bot token that, character-for-character, doesn't exist (as opposed to 401 Unauthorized, which is what a well-formed-but-wrong token returns). Verified with a live network call: before the fix, a dirty token produced a URL with an embedded newline; after the fix, the same input produces a clean URL and correctly surfaces the real failure mode (401 for a fake-but-valid-shaped token) instead of the confusing 404.
- Token and chat ID are now sanitized at every entry point - `--telegram-token`/`--telegram-chat-id`, the `BLINDSTRIKE_TELEGRAM_TOKEN`/`BLINDSTRIKE_TELEGRAM_CHAT_ID` env vars, the saved `~/.blindstrike/config.json`, and the wizard - and validated against the real Telegram token shape (`digits:secret`, 6+ digit bot ID, 20+ character secret) before any network call is made, with a clear, specific warning explaining the likely cause instead of an opaque HTTP error.
- A bad value already sitting in a saved config from before this fix self-heals automatically the next time it's read - no manual cleanup needed, though a genuinely wrong (not just malformed) token still needs re-entering with a fresh `--telegram-token`.
- Added 5 new regression tests reproducing the exact reported failure (trailing newline, stray `bot` prefix, format validation, and self-healing a dirty saved config) - all passing, bringing the suite to 30 tests total.

## v2.3.0

Focused on workflow/UX and Telegram depth on top of the v2.2.0 boolean-mode engine. No detection logic changed in this release; every item below was tested against a live local server or, for pure logic (config persistence, stop-event mechanics, message construction), covered by the new offline test suite.

### Added
- **Guided setup wizard** — launching `python blindstrike.py` with zero arguments now runs a step-by-step y/n and numbered-choice flow (target, mode, payload file picker, threads, stop-on-confirm, cookie, reports, Telegram) instead of a bare handful of text prompts. Verified end-to-end with piped stdin against a real local server across a full 528-payload MySQL scan, including correct JSON/CSV/HTML report file generation.
- **`--stop-on-confirm`** — halts further requests to the target the instant a finding is CONFIRMED. Implemented via a `threading.Event` checked in both the sequential and `ThreadPoolExecutor` dispatch loops (with `future.cancel()` for not-yet-started tasks in threaded mode). Verified: sequential mode stopped at 1/5 payloads; threaded mode (`-t 4`) stopped at 2/12 instead of running all 12.
- **Persistent Telegram config** (`~/.blindstrike/config.json`, mode `0600`) — credentials entered once via `--telegram-token`/`--telegram-chat-id` or the wizard are saved and reused automatically. Resolution priority: CLI flags > `BLINDSTRIKE_TELEGRAM_TOKEN`/`BLINDSTRIKE_TELEGRAM_CHAT_ID` env vars > saved config. `--no-save-telegram` opts out of persisting for a one-off run. Verified: save/reload round-trip, correct priority ordering, correct file permissions.
- **Real-time confirmed-finding Telegram alerts**, separate from and ahead of the end-of-scan summary. Verified to fire exactly once per confirmed result with correct target/payload/evidence.
- **Report files uploaded to Telegram** via `sendDocument`, alongside the existing text summary (which now also lists the actual target(s), not just counts). Verified: correct number of API calls, correct documents attached, unrequested formats correctly skipped.
- **No-sensitive-data guarantee for Telegram** — `send_telegram_confirmed_alert` and `send_telegram_notification` don't accept cookies or headers as parameters at all, so there's nothing to leak by construction, not just by omission. Verified via `inspect.signature` and a text-content check for `cookie`/`authorization`/`bearer`/`session=` substrings.
- **Bordered terminal summary table**, colored green/yellow/red by verdict (CONFIRMED VULNERABLE / FLAGGED - VERIFY MANUALLY / NO VULNERABILITIES FOUND).
- **HTML report overhaul** — dark theme, every request link opens in a new tab (`target="_blank"`), and a dedicated "Proof of Concept" block per confirmed finding (target, payload, evidence, full request, manual-verification reminder) in addition to the existing results table.
- **`tests/test_blindstrike.py`** — 25 offline unit tests (no network), all passing: URL/`#` encoding, boolean-mode normalization and noise-floor separation, Telegram config persistence/priority, stop-on-confirm (both dispatch modes), JSON/CSV/HTML report generation, and the Telegram no-leak guarantee.

### Fixed (incidental, found while wiring the above)
- `_do_request`'s signature grew a fourth return value in the v2.2.0 boolean-mode work; verifying the full regression suite here re-confirmed all call sites are correctly unpacking it - no regression, but re-verified as part of this release's testing pass.

## v2.2.0

New capability, on top of the v2.1.x correctness fixes — the time-based engine (default `--mode time`) is completely unchanged and remains the tool's core.

### Added
- **Boolean-based detection mode (`--mode boolean`).** Time-based detection only sees payloads with a timing side effect; a boolean-only injection point (no `SLEEP()`/`WAITFOR` in the payload) correctly reports "not vulnerable" in time mode because there's genuinely nothing to time. Boolean mode closes this gap: for each `TRUE_PAYLOAD|||FALSE_PAYLOAD` payload line, both conditions are requested and their response *content* is compared against a measured baseline.
- **Noise-floor-aware, normalized content diffing.** Baseline is now 2+ clean control responses per target; before any comparison, numeric runs (counters, timestamps, tokens, cache-busting values) are collapsed to a single placeholder in every response body. Verified empirically: on a realistic product-page-vs-empty-result-page pair with a random per-request counter, raw `difflib` similarity separated a genuine boolean difference from normal page noise by only ~0.09 (too thin to threshold reliably); after normalization the noise floor collapsed to a clean `1.0` while the genuine content difference remained fully intact at `0.777`.
- **`payloads/boolean_generic.txt`** — 12 generic TRUE/FALSE payload pairs covering common quote/comment styles, ready to use with `--mode boolean`.
- **Boolean-mode confirmation retest**, mirroring time-mode's confirm/no-confirm semantics and honest labeling (no overclaiming under `--no-confirm`, consistent with the v2.1.1 fix).
- **Telegram scan notifications** (`--telegram-token` / `--telegram-chat-id`) via the real Bot API `sendMessage` endpoint - sends a short summary (totals, flagged/confirmed counts, up to 5 flagged URLs) when a scan finishes. Verified: request construction and response parsing are correct (checked against the real API's URL format and a mocked well-formed response for the success path; a real call with an invalid token correctly received and handled a genuine HTTP 403 on the failure path). A live end-to-end send with a real bot token has not been performed in this environment (outbound network here is allowlisted) - do one test send before relying on it.
- New `ScanResult` fields for boolean mode (`mode`, `true_similarity`, `false_similarity`, `noise_floor`), included in JSON/CSV reports and shown in the HTML report's per-mode evidence column.
- `--mode` CLI flag (`time`, default, or `boolean`); payload file validation rejects `--mode boolean` files missing the `|||` separator with a clear error instead of failing confusingly mid-scan.

### Fixed (incidental, found while building the above)
- `_do_request`'s return signature changed internally to also carry the response body (needed for boolean diffing); the two existing time-mode call sites were still unpacking the old 3-value signature and were updated to match. Caught immediately by the existing regression suite before this build was considered done.

## v2.1.1

A correctness/hardening pass — no new features, no removed functionality. Every item below was reproduced against a live test server before being fixed, and re-verified after.

### Fixed
- **URL truncation on `#`-terminated payloads.** `requests`/urllib3 treats a raw `#` as the start of a URL fragment and silently drops it and everything after it before the request is sent. 29 payloads across `mysql.txt`, `generic.txt`, and `postgresql.txt` use `#` as a SQL comment terminator and were being transmitted broken, causing false negatives on genuinely vulnerable targets. Payload `#` characters are now percent-encoded to `%23` before being placed in the URL (query string or `FUZZ` position only — header and body injection were unaffected and are left untouched). Already percent-encoded payloads are not double-encoded.
- **Contaminated baseline in `--header-name` mode.** The payload was being written into the request header *before* the baseline (control) measurement, so the "clean" baseline request already carried the delay-triggering value. This made `delta` collapse to ~0 regardless of whether the target was actually vulnerable, so header-based injection could never be confirmed. Baseline is now always measured with unmodified headers before the payload header is added.
- **`--no-confirm` mislabeling flagged hits as `CONFIRMED`.** With confirmation disabled, every flagged hit was previously logged as `✓✓ CONFIRMED SQLi` and counted in `confirmed_vulnerabilities`, despite zero retest having occurred. Results are now reported as `FLAGGED (confirmation disabled, verify manually)` and are not counted as confirmed unless a retest actually reproduced the delay.
- **Timeouts silently discarded instead of treated as a signal.** If the true delay exceeded `--timeout`, the request raised a timeout exception and was filed as a generic error, dropped entirely from `vulnerabilities_found`. A response that never returns within `--timeout` is at least as strong a timing signal as one that returns slowly, so it's now flagged (and can still be confirmed via retest), with an explicit `[response exceeded --timeout]` note in the log and a `timed_out` field in the JSON/CSV report for transparency.
- **Retry adapter masking real timeouts.** The `urllib3.Retry` object wraps even a single read-timeout failure in `MaxRetryError` → `requests.exceptions.ConnectionError`, regardless of the configured retry budget, so a real timeout did not reliably surface as `requests.exceptions.Timeout`. Timeout detection now also matches on the underlying error message so it's recognized correctly either way.

### Added
- `timed_out: bool` field on each result, included in JSON/CSV reports.
- Warning when `-d/--data` is supplied but `-X/--method` is left at the default `GET` (the body would otherwise be silently dropped with no error).

## v2.1.0

### Changed
- Rebranded the tool from **Blind-SQLi** to **BlindStrike**, authored by **Pratik Khairnar**. All CLI text, the banner, module docstrings, JSON/CSV/HTML report metadata, README, and LICENSE now reflect the new name and author.
- Main script renamed from `blind_sqli.py` to `blindstrike.py`.
- No scan logic, detection behavior, or CLI flags changed — this is a naming/branding update only, layered on top of the v2.0.0 upgrade below.

## v2.0.0

### Added
- Baseline measurement per target (median of `--baseline-samples` control requests) used to score hits by *delta* over normal latency, not raw time alone.
- Automatic confirmation retest for flagged hits (`--no-confirm` to disable); results distinguish `CONFIRMED` from unconfirmed.
- `FUZZ` injection marker for precise placement in the URL, POST/PUT body, or a header value.
- `-X/--method` for POST/PUT/PATCH/DELETE, and `-d/--data` for request bodies.
- `--header-name` to fuzz an arbitrary HTTP header (e.g. `X-Forwarded-For`).
- `-H/--header` to attach arbitrary extra headers (repeatable).
- `--proxy` to route traffic through Burp Suite or another intercepting proxy.
- `--insecure` to skip TLS verification for lab targets with self-signed certs.
- `--retries` for HTTP-level retry/backoff on 5xx and connection errors via `urllib3.Retry`.
- CSV report export (`--csv-report`) and a styled, self-contained HTML report (`--html-report`).
- `#`-comment support in URL list and payload files.
- Persistent `requests.Session` reused across all requests for connection pooling.
- Refreshed User-Agent pool.

### Changed
- `ScanResult` now includes `method`, `confirmed`, `baseline_time`, and `delta` fields.
- `ScanReport` tracks `confirmed_vulnerabilities` separately from raw `vulnerabilities_found`.
- CLI summary output distinguishes flagged-but-unconfirmed hits from confirmed ones.
- Version bumped to 2.0.0.

### Compatibility
- All v1.0.0 CLI flags and behavior are preserved; new flags are additive and default to the old append-to-URL, GET-only behavior when unused.

## v1.0.0

- Initial release: time-based Blind SQLi detection across MySQL, MSSQL, PostgreSQL, Oracle, generic, and XOR payload sets, single/bulk URL scanning, multi-threading, JSON reporting, cookie support, and an interactive fallback mode.

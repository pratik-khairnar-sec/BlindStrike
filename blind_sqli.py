#!/usr/bin/env python3
"""
Blind-SQLi
==========
Blind SQL Injection Testing Framework

By Vaelion

A time-based Blind SQL Injection testing tool for authorized security
assessments. Sends payloads appended to target URLs and flags targets
as potentially vulnerable when the response time exceeds a configurable
delay threshold (default: 10 seconds), which is the classic signature
of a time-based blind SQLi payload (e.g. SLEEP(), WAITFOR DELAY, pg_sleep()).

Legal / Ethical Notice
-----------------------
This tool is provided for authorized penetration testing, bug bounty
research under a valid program scope, and educational purposes only.
Running this tool against systems you do not own or do not have explicit
written authorization to test is illegal in most jurisdictions. The
author (Vaelion) assumes no liability for misuse.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import logging
import os
import random
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Optional

import requests

__version__ = "1.0.0"
__author__ = "Vaelion"
__tool__ = "Blind-SQLi"


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
██████╗ ██╗     ██╗███╗   ██╗██████╗       ███████╗ ██████╗ ██╗     ██╗
██╔══██╗██║     ██║████╗  ██║██╔══██╗      ██╔════╝██╔═══██╗██║     ██║
██████╔╝██║     ██║██╔██╗ ██║██║  ██║█████╗███████╗██║   ██║██║     ██║
██╔══██╗██║     ██║██║╚██╗██║██║  ██║╚════╝╚════██║██║▄▄ ██║██║     ██║
██████╔╝███████╗██║██║ ╚████║██████╔╝      ███████║╚██████╔╝███████╗██║
╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝╚═════╝       ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝

          Blind SQL Injection Testing Framework  |  v{version}
                          By Vaelion
"""


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
def build_logger(verbose: bool, log_file: Optional[str]) -> logging.Logger:
    logger = logging.getLogger("blind_sqli")
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


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class ScanResult:
    url: str
    payload: str
    tested_url: str
    vulnerable: bool
    status_code: Optional[int]
    response_time: Optional[float]
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
    vulnerable_urls: List[str] = field(default_factory=list)
    results: List[ScanResult] = field(default_factory=list)

    def to_json(self, include_all_results: bool = True) -> str:
        data = asdict(self)
        if not include_all_results:
            data.pop("results")
        return json.dumps(data, indent=2)


# --------------------------------------------------------------------------- #
# Core scanner
# --------------------------------------------------------------------------- #
class BlindSQLi:
    """Core Blind SQL Injection testing engine."""

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.1.2 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.70",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Mobile Safari/537.36",
    ]

    def __init__(
        self,
        logger: logging.Logger,
        threshold: float = 10.0,
        timeout: float = 20.0,
        random_ua: bool = True,
    ):
        self.logger = logger
        self.threshold = threshold
        self.timeout = timeout
        self.random_ua = random_ua
        self.report = ScanReport(threshold_seconds=threshold)

    def get_user_agent(self) -> str:
        return random.choice(self.USER_AGENTS) if self.random_ua else self.USER_AGENTS[0]

    @staticmethod
    def read_lines(path: str) -> List[str]:
        """Read a file and return a list of non-empty, stripped lines."""
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return [line.strip() for line in fh if line.strip()]

    def perform_request(self, url: str, payload: str, cookie: Optional[str]) -> ScanResult:
        """Send a single GET request with the payload appended to the URL."""
        tested_url = f"{url}{payload}"
        headers = {"User-Agent": self.get_user_agent()}
        cookies = {"cookie": cookie} if cookie else None

        start = time.time()
        try:
            response = requests.get(
                tested_url,
                headers=headers,
                cookies=cookies,
                timeout=self.timeout,
            )
            elapsed = time.time() - start
            vulnerable = elapsed >= self.threshold
            return ScanResult(
                url=url,
                payload=payload,
                tested_url=tested_url,
                vulnerable=vulnerable,
                status_code=response.status_code,
                response_time=round(elapsed, 2),
            )
        except requests.exceptions.Timeout:
            elapsed = time.time() - start
            return ScanResult(
                url=url,
                payload=payload,
                tested_url=tested_url,
                vulnerable=False,
                status_code=None,
                response_time=round(elapsed, 2),
                error="Request timed out",
            )
        except requests.exceptions.RequestException as exc:
            elapsed = time.time() - start
            return ScanResult(
                url=url,
                payload=payload,
                tested_url=tested_url,
                vulnerable=False,
                status_code=None,
                response_time=round(elapsed, 2),
                error=str(exc),
            )

    def _handle_result(self, result: ScanResult) -> None:
        self.report.total_tests += 1
        self.report.results.append(result)

        if result.error:
            self.logger.debug(
                f"{Color.DIM}✗ Error: {result.tested_url} -> {result.error}{Color.RESET}"
            )
            return

        if result.vulnerable:
            self.report.vulnerabilities_found += 1
            self.report.vulnerable_urls.append(result.tested_url)
            self.logger.info(
                f"{Color.GREEN}✓ Possible SQLi: {result.tested_url} "
                f"(status={result.status_code}, time={result.response_time}s){Color.RESET}"
            )
        else:
            self.logger.debug(
                f"{Color.RED}✗ Not vulnerable: {result.tested_url} "
                f"(status={result.status_code}, time={result.response_time}s){Color.RESET}"
            )

    def run(
        self,
        urls: List[str],
        payloads: List[str],
        cookie: Optional[str],
        threads: int,
    ) -> ScanReport:
        self.report.started_at = datetime.now().isoformat(timespec="seconds")

        try:
            if threads <= 1:
                for url in urls:
                    for payload in payloads:
                        self._handle_result(self.perform_request(url, payload, cookie))
            else:
                with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
                    futures = [
                        pool.submit(self.perform_request, url, payload, cookie)
                        for url in urls
                        for payload in payloads
                    ]
                    for future in concurrent.futures.as_completed(futures):
                        self._handle_result(future.result())
        except KeyboardInterrupt:
            self.logger.warning(f"{Color.YELLOW}Scan interrupted by user.{Color.RESET}")

        self.report.finished_at = datetime.now().isoformat(timespec="seconds")
        return self.report

    def save_vulnerable_urls(self, filename: str) -> None:
        with open(filename, "w", encoding="utf-8") as fh:
            for url in self.report.vulnerable_urls:
                fh.write(f"{url}\n")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blind_sqli.py",
        description=(
            f"{__tool__} - Blind SQL Injection Testing Framework (By {__author__})\n\n"
            "Time-based Blind SQL Injection scanner for authorized security "
            "assessments. Appends payloads to target URLs and flags a target "
            "as potentially vulnerable when the response is delayed beyond "
            "a configurable threshold."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Single URL, default MySQL payload set, interactive-free\n"
            "  python blind_sqli.py -u \"http://target.com/item?id=1\" -p payloads/mysql.txt\n\n"
            "  # List of URLs, 10 threads, save vulnerable URLs and a JSON report\n"
            "  python blind_sqli.py -l urls.txt -p payloads/generic.txt -t 10 "
            "-o vulnerable.txt --report report.json\n\n"
            "  # Custom delay threshold and cookie, verbose output\n"
            "  python blind_sqli.py -u \"http://target.com/search?q=test\" "
            "-p payloads/postgresql.txt --threshold 8 -c \"session=abc123\" -v\n\n"
            "  # No banner, no color (CI / pipe-friendly)\n"
            "  python blind_sqli.py -u \"http://target.com/\" -p payloads/xor.txt --no-banner --no-color\n"
        ),
    )

    target_group = parser.add_mutually_exclusive_group(required=False)
    target_group.add_argument("-u", "--url", help="Single target URL to test.")
    target_group.add_argument("-l", "--list", dest="url_list", help="Path to a file containing target URLs (one per line).")

    parser.add_argument(
        "-p", "--payloads",
        help="Path to the payload file (e.g. payloads/mysql.txt). "
             "See the payloads/ directory for built-in sets.",
    )
    parser.add_argument("-c", "--cookie", default=None, help="Cookie to include with each request.")
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
    parser.add_argument("-o", "--output", help="Save discovered vulnerable URLs to this file.")
    parser.add_argument("--report", help="Save a full JSON scan report to this file.")
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


def interactive_prompt() -> argparse.Namespace:
    """Fallback interactive mode when no CLI arguments are supplied."""
    print(f"{Color.YELLOW}No arguments supplied - falling back to interactive mode.{Color.RESET}")
    print(f"{Color.DIM}Tip: run 'python blind_sqli.py --help' to see full CLI usage.{Color.RESET}\n")

    verbose = input(f"{Color.PURPLE}Enable verbose mode? (y/n): {Color.RESET}").strip().lower() in ("y", "yes")
    target = input(f"{Color.PURPLE}Enter the URL or path to a URL list file: {Color.RESET}").strip()
    payloads = input(f"{Color.CYAN}Enter the path to the payload file (e.g. payloads/mysql.txt): {Color.RESET}").strip()
    cookie = input(f"{Color.CYAN}Enter a cookie to include (leave empty if none): {Color.RESET}").strip() or None
    threads_raw = input(f"{Color.CYAN}Enter number of concurrent threads (0-20, default 0): {Color.RESET}").strip()
    output = input(f"{Color.PURPLE}Filename to save vulnerable URLs (leave empty to skip): {Color.RESET}").strip() or None

    ns = argparse.Namespace(
        url=None,
        url_list=None,
        payloads=payloads,
        cookie=cookie,
        threads=int(threads_raw) if threads_raw else 0,
        threshold=10.0,
        timeout=20.0,
        output=output,
        report=None,
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


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    # No target/payload arguments at all -> interactive fallback (keeps original UX).
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

    scanner = BlindSQLi(logger=logger, threshold=args.threshold, timeout=args.timeout)

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

    logger.info(
        f"{Color.PURPLE}Starting scan | targets={len(urls)} | payloads={len(payloads)} "
        f"| threads={args.threads or 1} | threshold={args.threshold}s{Color.RESET}"
    )

    report = scanner.run(urls=urls, payloads=payloads, cookie=args.cookie, threads=args.threads)

    print(f"\n{Color.BLUE}{Color.BOLD}Scan Complete{Color.RESET}")
    print(f"{Color.YELLOW}Total Tests:        {report.total_tests}{Color.RESET}")
    print(f"{Color.GREEN}Vulnerabilities:    {report.vulnerabilities_found}{Color.RESET}")

    if report.vulnerabilities_found > 0:
        print(f"{Color.GREEN}✓ {report.vulnerabilities_found} potentially vulnerable endpoint(s) found.{Color.RESET}")
    else:
        print(f"{Color.RED}✗ No vulnerabilities found in this scan.{Color.RESET}")

    if args.output:
        try:
            scanner.save_vulnerable_urls(args.output)
            logger.info(f"{Color.GREEN}Vulnerable URLs saved to {args.output}{Color.RESET}")
        except OSError as exc:
            logger.error(f"{Color.RED}Failed to save vulnerable URLs: {exc}{Color.RESET}")

    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8") as fh:
                fh.write(report.to_json())
            logger.info(f"{Color.GREEN}JSON report saved to {args.report}{Color.RESET}")
        except OSError as exc:
            logger.error(f"{Color.RED}Failed to save JSON report: {exc}{Color.RESET}")

    print(f"{Color.CYAN}Thank you for using {__tool__} - By {__author__}.{Color.RESET}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}Interrupted. Exiting.{Color.RESET}")
        sys.exit(130)

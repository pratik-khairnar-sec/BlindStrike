"""
Offline unit tests for BlindStrike - no network access required.

Run with:
    python -m pytest tests/test_blindstrike.py -v
or:
    python -m unittest tests.test_blindstrike -v

These cover the pure/isolated logic paths (URL encoding, content-similarity
normalization, persistent Telegram config, stop-on-confirm, report generation,
and the "no sensitive data in Telegram messages" guarantee) without making any
real HTTP requests - the correctness of the live scanning behavior itself is
covered by the manual test-server scenarios described in README.md > Testing.
"""
import inspect
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import blindstrike  # noqa: E402


class TestUrlInjection(unittest.TestCase):
    def test_hash_is_percent_encoded_in_url_mode(self):
        """A raw '#' would be silently dropped by requests/urllib3 as a URL fragment -
        BlindStrike must encode it before it ever reaches the HTTP layer."""
        scanner = blindstrike.BlindSQLi(logger=blindstrike.build_logger(False, None))
        result = scanner._inject("http://x/?id=1", "' OR SLEEP(3)#")
        self.assertNotIn("#", result)
        self.assertIn("%23", result)

    def test_fuzz_marker_replacement(self):
        scanner = blindstrike.BlindSQLi(logger=blindstrike.build_logger(False, None))
        result = scanner._inject("http://x/?id=1FUZZ&page=2", "' OR 1=1--")
        self.assertEqual(result, "http://x/?id=1' OR 1=1--&page=2")

    def test_append_mode_without_fuzz(self):
        scanner = blindstrike.BlindSQLi(logger=blindstrike.build_logger(False, None))
        result = scanner._inject("http://x/?id=1", "' OR 1=1--")
        self.assertEqual(result, "http://x/?id=1' OR 1=1--")

    def test_already_encoded_payload_not_double_encoded(self):
        scanner = blindstrike.BlindSQLi(logger=blindstrike.build_logger(False, None))
        result = scanner._inject("http://x/?id=1", "%0d%0a and sleep(3)")
        self.assertEqual(result, "http://x/?id=1%0d%0a and sleep(3)")


class TestBooleanSimilarity(unittest.TestCase):
    def test_normalize_collapses_digits(self):
        self.assertEqual(
            blindstrike.BlindSQLi._normalize("visitors: 483920, id 77"),
            "visitors: #, id #",
        )

    def test_noise_from_counters_does_not_mask_real_difference(self):
        true_body = "<h1>Product</h1><span>483920</span>"
        false_body = "<h1>No results</h1><span>91234</span>"
        baseline1 = "<h1>Product</h1><span>102934</span>"
        baseline2 = "<h1>Product</h1><span>887321</span>"

        noise_floor = blindstrike.BlindSQLi._similarity(baseline1, baseline2)
        true_sim = blindstrike.BlindSQLi._similarity(true_body, baseline1)
        false_sim = blindstrike.BlindSQLi._similarity(false_body, baseline1)

        self.assertEqual(noise_floor, 1.0, "identical-except-counter baselines must normalize to 1.0")
        self.assertEqual(true_sim, 1.0, "TRUE condition must match baseline after normalization")
        self.assertLess(false_sim, 0.85, "FALSE condition must diverge clearly from baseline")

    def test_identical_content_scores_1(self):
        self.assertEqual(blindstrike.BlindSQLi._similarity("abc", "abc"), 1.0)

    def test_none_body_scores_0(self):
        self.assertEqual(blindstrike.BlindSQLi._similarity(None, "abc"), 0.0)


class TestTelegramConfigPersistence(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._orig_dir = blindstrike.CONFIG_DIR
        self._orig_path = blindstrike.CONFIG_PATH
        blindstrike.CONFIG_DIR = os.path.join(self.tmpdir, ".blindstrike")
        blindstrike.CONFIG_PATH = os.path.join(blindstrike.CONFIG_DIR, "config.json")

    def tearDown(self):
        blindstrike.CONFIG_DIR = self._orig_dir
        blindstrike.CONFIG_PATH = self._orig_path

    def test_save_and_reload_round_trip(self):
        self.assertTrue(blindstrike.save_telegram_config("tok123", "chat456"))
        token, chat_id, source = blindstrike.resolve_telegram_credentials(None, None)
        self.assertEqual((token, chat_id, source), ("tok123", "chat456", "saved"))

    def test_trailing_newline_in_token_is_stripped(self):
        """Regression test: a token with a trailing newline (extremely common from
        copy-paste) used to be silently percent-encoded into the request URL, causing
        Telegram to return a confusing HTTP 404 for a bot that 'doesn't exist' rather
        than a clear error. It must be stripped before being saved or used."""
        blindstrike.save_telegram_config("123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234\n", "987654321 ")
        token, chat_id, source = blindstrike.resolve_telegram_credentials(None, None)
        self.assertEqual(token, "123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234")
        self.assertEqual(chat_id, "987654321")
        self.assertNotIn("\n", token)

    def test_stray_bot_prefix_is_stripped(self):
        """Another common paste mistake: including the literal word 'bot' from the API
        URL format itself as part of the token."""
        token, _ = blindstrike._sanitize_telegram_creds(
            "bot123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234", "1"
        )
        self.assertEqual(token, "123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234")

    def test_valid_token_format_accepted(self):
        self.assertTrue(blindstrike._telegram_token_looks_valid("123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234"))

    def test_malformed_token_format_rejected(self):
        for bad in ("not-a-token", "12345", "123456:short", "", None):
            self.assertFalse(blindstrike._telegram_token_looks_valid(bad))

    def test_dirty_saved_config_self_heals_on_read(self):
        """A token saved by an older, unsanitized version of this file (or corrupted by
        hand-editing the JSON) is cleaned up on read, not just on the next save."""
        os.makedirs(blindstrike.CONFIG_DIR, exist_ok=True)
        with open(blindstrike.CONFIG_PATH, "w") as fh:
            json.dump({"telegram_token": "123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234\n\n",
                       "telegram_chat_id": " 987654321"}, fh)
        token, chat_id, source = blindstrike.resolve_telegram_credentials(None, None)
        self.assertEqual(token, "123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234")
        self.assertEqual(chat_id, "987654321")

    def test_config_file_is_owner_only_permissions(self):
        blindstrike.save_telegram_config("tok", "chat")
        mode = oct(os.stat(blindstrike.CONFIG_PATH).st_mode)[-3:]
        self.assertEqual(mode, "600")

    def test_cli_args_take_priority_over_saved_config(self):
        blindstrike.save_telegram_config("saved-tok", "saved-chat")
        token, chat_id, source = blindstrike.resolve_telegram_credentials("cli-tok", "cli-chat")
        self.assertEqual((token, chat_id, source), ("cli-tok", "cli-chat", "cli"))

    def test_env_vars_take_priority_over_saved_config(self):
        blindstrike.save_telegram_config("saved-tok", "saved-chat")
        with mock.patch.dict(os.environ, {
            blindstrike.ENV_TOKEN_VAR: "env-tok",
            blindstrike.ENV_CHAT_ID_VAR: "env-chat",
        }):
            token, chat_id, source = blindstrike.resolve_telegram_credentials(None, None)
        self.assertEqual((token, chat_id, source), ("env-tok", "env-chat", "env"))

    def test_no_config_anywhere_returns_none(self):
        token, chat_id, source = blindstrike.resolve_telegram_credentials(None, None)
        self.assertEqual((token, chat_id, source), (None, None, None))


class TestStopOnConfirm(unittest.TestCase):
    def test_stop_event_halts_sequential_scan_after_first_confirmed(self):
        scanner = blindstrike.BlindSQLi(logger=blindstrike.build_logger(False, None), stop_on_confirm=True)

        call_count = {"n": 0}

        def fake_perform_request(url, payload, cookie):
            call_count["n"] += 1
            # Every call "finds" a confirmed vulnerability.
            return blindstrike.ScanResult(
                url=url, payload=payload, tested_url=url, method="GET",
                vulnerable=True, confirmed=True, status_code=200,
                response_time=3.0, baseline_time=0.01, delta=2.99,
            )

        with mock.patch.object(scanner, "perform_request", side_effect=fake_perform_request):
            report = scanner.run(
                urls=["http://x/?id=1"], payloads=["p1", "p2", "p3", "p4", "p5"],
                cookie=None, threads=0,
            )

        self.assertEqual(call_count["n"], 1, "must stop after the first confirmed finding")
        self.assertEqual(report.total_tests, 1)
        self.assertEqual(report.confirmed_vulnerabilities, 1)

    def test_without_stop_on_confirm_all_payloads_run(self):
        scanner = blindstrike.BlindSQLi(logger=blindstrike.build_logger(False, None), stop_on_confirm=False)

        def fake_perform_request(url, payload, cookie):
            return blindstrike.ScanResult(
                url=url, payload=payload, tested_url=url, method="GET",
                vulnerable=True, confirmed=True, status_code=200,
                response_time=3.0, baseline_time=0.01, delta=2.99,
            )

        with mock.patch.object(scanner, "perform_request", side_effect=fake_perform_request):
            report = scanner.run(
                urls=["http://x/?id=1"], payloads=["p1", "p2", "p3"],
                cookie=None, threads=0,
            )

        self.assertEqual(report.total_tests, 3)
        self.assertEqual(report.confirmed_vulnerabilities, 3)


class TestReportGeneration(unittest.TestCase):
    def _sample_report(self):
        report = blindstrike.ScanReport()
        report.total_tests = 1
        report.vulnerabilities_found = 1
        report.confirmed_vulnerabilities = 1
        result = blindstrike.ScanResult(
            url="http://x/?id=1", payload="' and sleep(3)--",
            tested_url="http://x/?id=1%27 and sleep(3)--", method="GET",
            vulnerable=True, confirmed=True, status_code=200,
            response_time=3.0, baseline_time=0.01, delta=2.99,
        )
        report.results.append(result)
        report.vulnerable_urls.append(result.tested_url)
        return report

    def test_json_report_is_valid_json_with_expected_fields(self):
        report = self._sample_report()
        data = json.loads(report.to_json())
        self.assertEqual(data["confirmed_vulnerabilities"], 1)
        self.assertIn("timed_out", data["results"][0])

    def test_csv_report_has_header_and_one_row(self):
        report = self._sample_report()
        lines = report.to_csv().strip().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn("timed_out", lines[0])

    def test_html_report_has_new_tab_links_and_poc_section(self):
        html = self._sample_report().to_html()
        self.assertIn('target="_blank"', html)
        self.assertIn("PROOF OF CONCEPT", html)


class TestTelegramNeverLeaksSensitiveData(unittest.TestCase):
    """Structural guarantee: the Telegram-facing functions don't even accept cookies or
    headers as parameters, so there is nothing sensitive to leak by construction."""

    def test_confirmed_alert_signature_has_no_cookie_or_header_param(self):
        params = set(inspect.signature(blindstrike.send_telegram_confirmed_alert).parameters)
        self.assertFalse(params & {"cookie", "cookies", "headers", "authorization"})

    def test_summary_signature_has_no_cookie_or_header_param(self):
        params = set(inspect.signature(blindstrike.send_telegram_notification).parameters)
        self.assertFalse(params & {"cookie", "cookies", "headers", "authorization"})

    def test_confirmed_alert_text_contains_no_forbidden_keywords(self):
        result = blindstrike.ScanResult(
            url="http://x/?id=1", payload="' and sleep(3)--", tested_url="http://x/?id=1'--",
            method="GET", vulnerable=True, confirmed=True, status_code=200,
            response_time=3.0, baseline_time=0.01, delta=2.99,
        )
        with mock.patch("blindstrike._telegram_api_post", return_value={"ok": True}) as m:
            blindstrike.send_telegram_confirmed_alert("tok", "chat", result, blindstrike.build_logger(False, None))
        sent_text = m.call_args.kwargs["data"]["text"].lower()
        for forbidden in ("cookie", "authorization", "bearer ", "session="):
            self.assertNotIn(forbidden, sent_text)


class TestTelegramGracefulFailure(unittest.TestCase):
    def test_network_error_does_not_raise(self):
        import requests

        with mock.patch("blindstrike.requests.post", side_effect=requests.exceptions.ConnectionError("boom")):
            ok = blindstrike._telegram_api_post(
                "sendMessage", "tok", blindstrike.build_logger(False, None),
                data={"chat_id": "1", "text": "hi"},
            )
        self.assertIsNone(ok)

    def test_bad_http_status_does_not_raise(self):
        class FakeResp:
            status_code = 401
            text = "Unauthorized"
            headers = {"content-type": "application/json"}

            def json(self):
                return {"ok": False}

        with mock.patch("blindstrike.requests.post", return_value=FakeResp()):
            ok = blindstrike._telegram_api_post(
                "sendMessage", "bad-token", blindstrike.build_logger(False, None),
                data={"chat_id": "1", "text": "hi"},
            )
        self.assertIsNone(ok)


class TestBooleanPayloadValidation(unittest.TestCase):
    def test_valid_pairs_split_correctly(self):
        line = "' AND 1=1-- -|||' AND 1=2-- -"
        true_p, _, false_p = line.partition("|||")
        self.assertEqual(true_p, "' AND 1=1-- -")
        self.assertEqual(false_p, "' AND 1=2-- -")

    def test_missing_separator_detected(self):
        payloads = ["' AND 1=1-- -|||' AND 1=2-- -", "no separator here"]
        bad_lines = [p for p in payloads if "|||" not in p]
        self.assertEqual(bad_lines, ["no separator here"])


if __name__ == "__main__":
    unittest.main()

"""Unit tests for the Get TOTP Code action"""

import http.server
import json
import os
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, call, patch

import requests
from requests.adapters import HTTPAdapter
from src import main
from urllib3.util.retry import Retry

SECRET_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
OTHER_SECRET_ID = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"


def entry_json(secret_id=SECRET_ID, output_id="code"):
    """Return the secret_ids input for a single entry."""
    return json.dumps({"secret_id": secret_id, "output_id": output_id})


@patch("src.main.API_URL", "https://example.com/BeyondTrust/api/public/v3")
@patch("src.main.CLIENT_ID", "456126543212456126543212456126543212")
@patch("src.main.CLIENT_SECRET", "123321654234123321654234123321654234")
class TestMain(unittest.TestCase):
    """Tests for main."""

    @patch("src.main.SECRET_IDS", entry_json())
    @patch("src.main.append_output")
    @patch("src.main.secrets_safe.SecretsSafe.get_secret_totp_code")
    @patch("src.main.authentication.Authentication.sign_app_out")
    @patch("src.main.authentication.Authentication.get_api_access")
    def test_main_success(
        self,
        get_api_access_mock,
        sign_app_out_mock,
        get_totp_code_mock,
        append_output_mock,
    ):
        """main writes the masked code to GITHUB_OUTPUT and signs out."""
        get_api_access_mock.return_value = MagicMock(status_code=200)
        get_totp_code_mock.return_value = {
            "Code": "123456",
            "ValidFromUtc": "2026-11-09T10:00:00Z",
            "ValidToUtc": "2026-11-09T10:00:30Z",
        }

        with patch("builtins.print") as mock_print:
            main.main()

        get_totp_code_mock.assert_called_once_with(SECRET_ID)
        mock_print.assert_any_call("::add-mask ::123456")
        append_output_mock.assert_called_once_with("code", "123456")
        sign_app_out_mock.assert_called_once()

    @patch("src.main.SECRET_IDS", entry_json())
    @patch("src.main.API_KEY", "api-key")
    @patch("src.main.API_VERSION", "3.3")
    @patch("src.main.get_totp_codes")
    @patch("src.main.authentication.Authentication")
    def test_main_api_key_and_version(
        self, authentication_class_mock, get_totp_codes_mock
    ):
        """API key authentication is used and the API version is passed on."""
        authentication_class_mock.return_value.get_api_access.return_value = MagicMock(
            status_code=200
        )

        main.main()

        kwargs = authentication_class_mock.call_args.kwargs
        self.assertEqual(kwargs["api_key"], "api-key")
        self.assertEqual(kwargs["api_version"], "3.3")
        self.assertNotIn("client_id", kwargs)
        get_totp_codes_mock.assert_called_once()

    @patch("src.main.SECRET_IDS", None)
    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    @patch("src.main.authentication.Authentication")
    def test_main_nothing_to_do_fails_before_authenticating(
        self, authentication_class_mock, mock_show_error
    ):
        """An empty input fails the step without making any API call."""
        with self.assertRaises(SystemExit):
            main.main()

        self.assertIn("Nothing to do", mock_show_error.call_args[0][0])
        authentication_class_mock.assert_not_called()

    @patch("src.main.SECRET_IDS", entry_json(secret_id="../../folders"))
    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    @patch("src.main.authentication.Authentication")
    def test_main_invalid_input_fails_before_authenticating(
        self, authentication_class_mock, mock_show_error
    ):
        """Invalid input fails the step without making any API call."""
        with self.assertRaises(SystemExit):
            main.main()

        self.assertIn("Invalid secret_id", mock_show_error.call_args[0][0])
        authentication_class_mock.assert_not_called()

    @patch("src.main.SECRET_IDS", entry_json())
    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    @patch("src.main.authentication.Authentication.get_api_access")
    def test_main_auth_failure(self, get_api_access_mock, mock_show_error):
        """A failed sign-in fails the step."""
        get_api_access_mock.return_value = MagicMock(
            status_code=401, text="Unauthorized"
        )

        with self.assertRaises(SystemExit):
            main.main()

        self.assertIn("Please check credentials", mock_show_error.call_args[0][0])

    @patch("src.main.SECRET_IDS", entry_json())
    @patch("src.main.common.show_error")
    @patch("src.main.requests.Session", side_effect=Exception("Unexpected error"))
    def test_main_exception_handling(self, _session_mock, mock_show_error):
        """Unexpected errors fail the step through show_error."""
        main.main()

        mock_show_error.assert_called_once()


class TestParseSecretIds(unittest.TestCase):
    """Tests for parse_secret_ids, which validates the input."""

    def test_single_object(self):
        """A single object is accepted."""
        self.assertEqual(main.parse_secret_ids(entry_json()), [(SECRET_ID, "code")])

    def test_list(self):
        """A list of objects is accepted, in order."""
        secret_ids = json.dumps(
            [
                {"secret_id": SECRET_ID, "output_id": "code1"},
                {"secret_id": OTHER_SECRET_ID, "output_id": "code2"},
            ]
        )

        self.assertEqual(
            main.parse_secret_ids(secret_ids),
            [(SECRET_ID, "code1"), (OTHER_SECRET_ID, "code2")],
        )

    def test_max_entries_accepted(self):
        """Exactly the maximum number of entries is accepted."""
        secret_ids = json.dumps(
            [
                {"secret_id": SECRET_ID, "output_id": f"c{i}"}
                for i in range(main.MAX_CODES_TO_RETRIEVE)
            ]
        )

        self.assertEqual(
            len(main.parse_secret_ids(secret_ids)), main.MAX_CODES_TO_RETRIEVE
        )

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_invalid_input_is_rejected(self, mock_show_error):
        """Malformed input fails with a message naming the problem."""
        too_many = json.dumps(
            [
                {"secret_id": SECRET_ID, "output_id": f"c{i}"}
                for i in range(main.MAX_CODES_TO_RETRIEVE + 1)
            ]
        )
        cases = (
            (None, "Nothing to do"),
            ("[]", "Nothing to do"),
            ("not json", "Invalid JSON input"),
            (json.dumps(["x"]), "must be a JSON object"),
            (json.dumps({"output_id": "code"}), "validate secret_id"),
            (json.dumps({"secret_id": SECRET_ID}), "validate output_id"),
            (too_many, "maximum of 20 TOTP codes"),
        )
        for secret_ids, text in cases:
            with self.subTest(text=text, secret_ids=secret_ids):
                with self.assertRaises(SystemExit):
                    main.parse_secret_ids(secret_ids)
                self.assertIn(text, mock_show_error.call_args[0][0])

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_secret_id_must_be_guid(self, mock_show_error):
        """A secret_id that is not a GUID never reaches the request path."""
        for secret_id in ("../../folders", "not-a-guid", 123, None, ""):
            with self.subTest(secret_id=secret_id):
                with self.assertRaises(SystemExit):
                    main.parse_secret_ids(entry_json(secret_id=secret_id))
                self.assertIn("Invalid secret_id", mock_show_error.call_args[0][0])

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_output_id_must_be_safe(self, mock_show_error):
        """output_id cannot inject extra GITHUB_OUTPUT lines."""
        for output_id in ("bad\nINJECTED=1", "code\n", "1code", "a b", 5, None):
            with self.subTest(output_id=output_id):
                with self.assertRaises(SystemExit):
                    main.parse_secret_ids(entry_json(output_id=output_id))
                self.assertIn("Invalid output_id", mock_show_error.call_args[0][0])

    def test_valid_output_ids(self):
        """Letters, digits, underscores and hyphens are allowed."""
        for output_id in ("code", "_code", "totp-code_1"):
            with self.subTest(output_id=output_id):
                self.assertEqual(
                    main.parse_secret_ids(entry_json(output_id=output_id)),
                    [(SECRET_ID, output_id)],
                )


class TestGetTotpCodes(unittest.TestCase):
    """Tests for get_totp_code and get_totp_codes."""

    def _fails(self, mock_show_error, response=None, error=None):
        """Call get_totp_code and return the error message it failed with."""
        secrets_safe_obj = MagicMock()
        secrets_safe_obj.get_secret_totp_code.return_value = response
        secrets_safe_obj.get_secret_totp_code.side_effect = error

        with self.assertRaises(SystemExit):
            main.get_totp_code(secrets_safe_obj, SECRET_ID)
        return mock_show_error.call_args[0][0]

    @patch("src.main.append_output")
    @patch("src.main.mask_secret")
    def test_each_code_is_masked_before_it_is_written(self, mock_mask, mock_append):
        """Every code is masked before it is written to GITHUB_OUTPUT."""
        events = []
        mock_mask.side_effect = lambda _, code: events.append(("mask", code))
        mock_append.side_effect = lambda name, code: events.append((name, code))
        secrets_safe_obj = MagicMock()
        secrets_safe_obj.get_secret_totp_code.side_effect = [
            {"Code": "123456"},
            {"Code": 654321},
        ]

        main.get_totp_codes(
            secrets_safe_obj, [(SECRET_ID, "code1"), (OTHER_SECRET_ID, "code2")]
        )

        self.assertEqual(
            events,
            [
                ("mask", "123456"),
                ("code1", "123456"),
                ("mask", "654321"),
                ("code2", "654321"),
            ],
        )
        secrets_safe_obj.get_secret_totp_code.assert_has_calls(
            [call(SECRET_ID), call(OTHER_SECRET_ID)]
        )

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_text_or_file_secret_400(self, mock_show_error):
        """A 400 (not a credential secret) fails with an actionable message."""
        message = self._fails(
            mock_show_error,
            error=main.exceptions.SecretTypeNotSupportedError("400 Bad Request"),
        )

        self.assertIn("only available for credential secrets", message)
        self.assertIn(SECRET_ID, message)

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_totp_not_enabled_404(self, mock_show_error):
        """A 404 (not found or TOTP disabled) fails with an actionable message."""
        message = self._fails(
            mock_show_error,
            error=main.exceptions.TotpNotEnabledError("404 Not Found"),
        )

        self.assertIn("TOTP is enabled on it", message)

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_generic_lookup_failure(self, mock_show_error):
        """Any other request failure fails the step."""
        message = self._fails(
            mock_show_error, error=main.exceptions.LookupError("403 Forbidden")
        )

        self.assertIn("Error getting TOTP code", message)
        self.assertIn("403 Forbidden", message)

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_response_without_code(self, mock_show_error):
        """A response with no code fails instead of writing an empty output."""
        for response in ({}, {"Code": None}, {"Code": "  "}, None, "123456"):
            with self.subTest(response=response):
                message = self._fails(mock_show_error, response=response)
                self.assertIn("did not include a code", message)


class TestRetryStrategy(unittest.TestCase):
    """
    The TOTP code endpoint answers 400 for a text or file secret. That response
    must reach the library on the first attempt so it can raise
    SecretTypeNotSupportedError, rather than being retried into a RetryError.
    """

    def test_400_is_not_retried(self):
        self.assertNotIn(400, main.RETRY_STATUS_CODES)

    def test_400_response_is_returned_on_first_attempt(self):
        hits = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(400)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        with requests.Session() as session:
            retry = Retry(
                total=3,
                backoff_factor=0,
                status_forcelist=main.RETRY_STATUS_CODES,
                allowed_methods=["GET", "POST"],
            )
            session.mount("http://", HTTPAdapter(max_retries=retry))
            response = session.get(f"http://127.0.0.1:{server.server_port}/code")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(len(hits), 1)


class TestOutputAndMasking(unittest.TestCase):
    """Tests for append_output and mask_secret."""

    def test_append_output(self):
        """The value is written with a heredoc delimiter."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as output:
            self.addCleanup(os.unlink, output.name)

        with patch.dict(os.environ, {"GITHUB_OUTPUT": output.name}):
            main.append_output("code", "123456")

        with open(output.name) as fh:
            lines = fh.read().splitlines()

        self.assertTrue(lines[0].startswith("code<<"))
        self.assertEqual(lines[1], "123456")
        self.assertEqual(lines[2], lines[0].split("<<", 1)[1])

    @patch("builtins.print")
    def test_mask_secret_splits_lines_and_escapes(self, mock_print):
        """CR/LF cannot inject extra workflow commands, and '%' is escaped."""
        main.mask_secret("add-mask", "a\r::stop-commands::z\r\n\n50%")

        self.assertEqual(
            [c.args[0] for c in mock_print.call_args_list],
            [
                "::add-mask ::a",
                "::add-mask ::::stop-commands::z",
                "::add-mask ::50%25",
            ],
        )


class TestParseVerifyCA(unittest.TestCase):
    """Tests for parse_verify_ca."""

    def test_true_when_unset_or_empty(self):
        for value in (None, "", "   "):
            with self.subTest(value=value):
                self.assertIs(main.parse_verify_ca(value), True)

    def test_tokens_are_recognized(self):
        for token in ("true", "1", "yes", "on", "enable", "enabled", " TRUE "):
            with self.subTest(token=token):
                self.assertIs(main.parse_verify_ca(token), True)
        for token in ("false", "0", "no", "off", "disable", "disabled", " FALSE "):
            with self.subTest(token=token):
                self.assertIs(main.parse_verify_ca(token), False)

    def test_existing_bundle_path_is_passed_through(self):
        with tempfile.NamedTemporaryFile(suffix=".crt") as bundle:
            self.assertEqual(main.parse_verify_ca(f"  {bundle.name}  "), bundle.name)
        with tempfile.TemporaryDirectory() as bundle_dir:
            self.assertEqual(main.parse_verify_ca(bundle_dir), bundle_dir)

    def test_invalid_values_raise(self):
        for value in ("/no/such/ca-bundle.crt", "maybe"):
            with self.subTest(value=value):
                with self.assertRaises(EnvironmentError) as ctx:
                    main.parse_verify_ca(value)
                self.assertIn("VERIFY_CA", str(ctx.exception))


class TestConfigureCertificateVerification(unittest.TestCase):
    """Tests for configure_certificate_verification."""

    def _log_message(self, verify_ca, env_overrides=None):
        session = requests.Session()
        with patch.dict(os.environ, env_overrides or {}, clear=True):
            with patch("src.main.utils.print_log") as print_log:
                main.configure_certificate_verification(session, verify_ca)
        self.assertEqual(session.verify, verify_ca)
        return print_log.call_args[0][1] if print_log.called else None

    def test_disabled(self):
        self.assertIsNone(self._log_message(False))

    def test_bundle_path(self):
        with tempfile.NamedTemporaryFile(suffix=".crt") as bundle:
            self.assertIn(bundle.name, self._log_message(bundle.name))

    def test_certifi_when_no_override(self):
        message = self._log_message(True)
        self.assertIn("certifi", message)
        self.assertIn(requests.adapters.DEFAULT_CA_BUNDLE_PATH, message)

    def test_overrides_are_reported(self):
        message = self._log_message(
            True, {"REQUESTS_CA_BUNDLE": "/tmp/req.crt", "CURL_CA_BUNDLE": "/c.crt"}
        )
        self.assertIn("REQUESTS_CA_BUNDLE", message)
        self.assertNotIn("/c.crt", message)

        message = self._log_message(True, {"CURL_CA_BUNDLE": "/tmp/curl.crt"})
        self.assertIn("CURL_CA_BUNDLE", message)


if __name__ == "__main__":
    unittest.main()

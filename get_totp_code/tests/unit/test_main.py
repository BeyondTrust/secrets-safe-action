"""Unit tests for the Get TOTP Code action"""

import unittest
from unittest.mock import MagicMock, patch

from src import main

SECRET_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"


@patch("src.main.API_URL", "https://example.com/BeyondTrust/api/public/v3")
@patch("src.main.CLIENT_ID", "456126543212456126543212456126543212")
@patch("src.main.CLIENT_SECRET", "123321654234123321654234123321654234")
class TestMain(unittest.TestCase):
    """Tests for main."""

    @patch("src.main.SECRET_ID", SECRET_ID)
    @patch("src.main.outputs.append_output")
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
        self.assertEqual(
            [c.args for c in append_output_mock.call_args_list],
            [
                ("totp_code", "123456"),
                ("valid_from_utc", "2026-11-09T10:00:00Z"),
                ("valid_to_utc", "2026-11-09T10:00:30Z"),
            ],
        )
        sign_app_out_mock.assert_called_once()

    @patch("src.main.SECRET_ID", SECRET_ID)
    @patch("src.main.API_KEY", "api-key")
    @patch("src.main.API_VERSION", "3.3")
    @patch("src.main.VERIFY_CA", False)
    @patch("src.main.write_totp_code")
    @patch("src.main.authentication.Authentication")
    def test_main_api_key_and_version(
        self, authentication_class_mock, write_totp_code_mock
    ):
        """API key authentication is used and the settings are passed on."""
        authentication_class_mock.return_value.get_api_access.return_value = MagicMock(
            status_code=200
        )

        main.main()

        kwargs = authentication_class_mock.call_args.kwargs
        self.assertEqual(kwargs["api_key"], "api-key")
        self.assertEqual(kwargs["api_version"], "3.3")
        self.assertNotIn("client_id", kwargs)
        self.assertIs(kwargs["verify_ca"], False)
        self.assertEqual(
            kwargs["api_url"], "https://example.com/BeyondTrust/api/public/v3"
        )
        write_totp_code_mock.assert_called_once()
        self.assertEqual(write_totp_code_mock.call_args.args[1], SECRET_ID)

    @patch("src.main.SECRET_ID", None)
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

    @patch("src.main.SECRET_ID", "../../folders")
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

    @patch("src.main.SECRET_ID", SECRET_ID)
    @patch("src.main.write_totp_code", side_effect=SystemExit(1))
    @patch("src.main.authentication.Authentication.sign_app_out")
    @patch("src.main.authentication.Authentication.get_api_access")
    def test_main_signs_out_when_retrieval_fails(
        self, get_api_access_mock, sign_app_out_mock, _write_totp_code_mock
    ):
        """A failed TOTP retrieval still signs out of the API session."""
        get_api_access_mock.return_value = MagicMock(status_code=200)

        with self.assertRaises(SystemExit):
            main.main()

        sign_app_out_mock.assert_called_once()

    @patch("src.main.SECRET_ID", SECRET_ID)
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

    @patch("src.main.SECRET_ID", SECRET_ID)
    @patch("src.main.common.show_error")
    @patch(
        "src.main.api_client.create_session", side_effect=Exception("Unexpected error")
    )
    def test_main_exception_handling(self, _session_mock, mock_show_error):
        """Unexpected errors fail the step through show_error."""
        main.main()

        mock_show_error.assert_called_once()


class TestValidateSecretId(unittest.TestCase):
    """Tests for validate_secret_id, which validates the input."""

    def test_guid_is_accepted(self):
        """A GUID is returned as is."""
        self.assertEqual(main.validate_secret_id(SECRET_ID), SECRET_ID)

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_empty_input_is_rejected(self, mock_show_error):
        """An empty input fails with "Nothing to do"."""
        for secret_id in (None, ""):
            with self.subTest(secret_id=secret_id):
                with self.assertRaises(SystemExit):
                    main.validate_secret_id(secret_id)
                self.assertIn("Nothing to do", mock_show_error.call_args[0][0])

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_secret_id_must_be_guid(self, mock_show_error):
        """A secret_id that is not a GUID never reaches the request path."""
        for secret_id in (
            "../../folders",
            "not-a-guid",
            f"{SECRET_ID}/../folders",
            '[{"secret_id": "x"}]',
        ):
            with self.subTest(secret_id=secret_id):
                with self.assertRaises(SystemExit):
                    main.validate_secret_id(secret_id)
                self.assertIn("Invalid secret_id", mock_show_error.call_args[0][0])


class TestGetTotpCode(unittest.TestCase):
    """Tests for get_totp_code and write_totp_code."""

    def _fails(self, mock_show_error, response=None, error=None):
        """Call get_totp_code and return the error message it failed with."""
        secrets_safe_obj = MagicMock()
        secrets_safe_obj.get_secret_totp_code.return_value = response
        secrets_safe_obj.get_secret_totp_code.side_effect = error

        with self.assertRaises(SystemExit):
            main.get_totp_code(secrets_safe_obj, SECRET_ID)
        return mock_show_error.call_args[0][0]

    @patch("src.main.outputs.append_output")
    @patch("src.main.outputs.mask_secret")
    def test_code_is_masked_before_it_is_written(self, mock_mask, mock_append):
        """
        The code is masked before any output is written; the validity window
        is written as is, and only the code is masked.
        """
        events = []
        mock_mask.side_effect = lambda code: events.append(("mask", code))
        mock_append.side_effect = lambda name, code: events.append((name, code))
        secrets_safe_obj = MagicMock()
        secrets_safe_obj.get_secret_totp_code.return_value = {
            "Code": 654321,
            "ValidFromUtc": "2026-11-13T10:00:00Z",
            "ValidToUtc": "2026-11-13T10:00:30Z",
        }

        main.write_totp_code(secrets_safe_obj, SECRET_ID)

        self.assertEqual(
            events,
            [
                ("mask", "654321"),
                ("totp_code", "654321"),
                ("valid_from_utc", "2026-11-13T10:00:00Z"),
                ("valid_to_utc", "2026-11-13T10:00:30Z"),
            ],
        )
        secrets_safe_obj.get_secret_totp_code.assert_called_once_with(SECRET_ID)

    def test_missing_validity_window_is_empty(self):
        """A response without the validity fields still returns the code."""
        secrets_safe_obj = MagicMock()
        secrets_safe_obj.get_secret_totp_code.return_value = {
            "Code": "123456",
            "ValidToUtc": None,
        }

        self.assertEqual(
            main.get_totp_code(secrets_safe_obj, SECRET_ID),
            {"totp_code": "123456", "valid_from_utc": "", "valid_to_utc": ""},
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
    How the session retries is tested in the library (api_client).
    """

    def test_400_is_not_retried(self):
        self.assertNotIn(400, main.RETRY_STATUS_CODES)

    @patch("src.main.SECRET_ID", SECRET_ID)
    @patch("src.main.write_totp_code")
    @patch("src.main.set_authentication")
    @patch("src.main.api_client.create_session")
    def test_main_uses_the_retry_list(self, create_session_mock, *_mocks):
        main.main()

        create_session_mock.assert_called_once_with(main.RETRY_STATUS_CODES)


if __name__ == "__main__":
    unittest.main()

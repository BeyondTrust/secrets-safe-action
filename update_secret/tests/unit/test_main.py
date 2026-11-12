"""Unit tests for the Update Secret action"""

import os
import tempfile
import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import requests
from secrets_safe_library import secrets_safe
from src import main
from src.main import (
    get_secret_type,
    get_totp_settings,
    is_no_content_success,
    mask_secret,
    mask_sensitive_inputs,
    parse_optional_bool,
    parse_optional_int,
    update_secret,
    validate_inputs,
    validate_secret_id,
)

SECRET_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
SEED = "JBSWY3DPEHPK3PXP"  # nosec B105 - test data
OWNERS = [{"user_id": 1}]

BASE_INPUTS = {"SECRET_ID": SECRET_ID, "TITLE": "Title", "OWNERS": '[{"user_id": 1}]'}
CREDENTIAL_INPUTS = {**BASE_INPUTS, "USERNAME": "user", "PASSWORD": "p4ss"}


def patch_inputs(stack: ExitStack, **inputs) -> None:
    """Patch the module-level input constants; unspecified inputs are empty."""
    defaults = {
        "SECRET_ID": "",
        "TITLE": "",
        "DESCRIPTION": "",
        "USERNAME": "",
        "PASSWORD": "",
        "TEXT": "",
        "FILE_CONTENT": "",
        "FILE_NAME": "",
        "OWNER_ID": "",
        "OWNER_TYPE": "",
        "PASSWORD_RULE_ID": "",
        "NOTES": "",
        "OWNERS": "",
        "URLS": "",
        "TOTP_ENABLED": "",
        "TOTP_SECRET_KEY": "",
    }
    defaults.update(inputs)
    for name, value in defaults.items():
        stack.enter_context(patch(f"src.main.{name}", value))


class InputsTestCase(unittest.TestCase):
    """Base class that patches the action inputs for one test."""

    def set_inputs(self, **inputs):
        stack = ExitStack()
        self.addCleanup(stack.close)
        patch_inputs(stack, **inputs)


def settings(secret_type=main.CREDENTIAL, **overrides):
    """Return validate_inputs()-style settings."""
    values = {
        "secret_type": secret_type,
        "owners": OWNERS,
        "urls": None,
        "totp_enabled": None,
        "totp_secret_key": None,
        "owner_id": None,
        "password_rule_id": None,
    }
    values.update(overrides)
    return values


class TestMain(InputsTestCase):
    """Tests for main."""

    @patch("src.main.requests.Session")
    @patch("src.main.update_secret")
    @patch("src.main.set_authentication")
    def test_main_success(self, mock_set_auth, mock_update, mock_session_class):
        """main authenticates, updates the secret and signs out."""
        self.set_inputs(**CREDENTIAL_INPUTS)
        mock_auth = MagicMock()
        mock_set_auth.return_value = mock_auth
        mock_session = MagicMock()
        mock_session_class.return_value.__enter__.return_value = mock_session

        with patch("builtins.print"):
            main.main()

        mock_set_auth.assert_called_once_with(mock_session)
        mock_update.assert_called_once_with(mock_auth, settings())
        mock_auth.sign_app_out.assert_called_once()

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    @patch("src.main.set_authentication")
    def test_main_rejects_invalid_input_before_authenticating(
        self, mock_set_auth, mock_show_error
    ):
        """Invalid input fails the step before any API call is made."""
        self.set_inputs(**{**CREDENTIAL_INPUTS, "SECRET_ID": "../../folders"})

        with patch("builtins.print"), self.assertRaises(SystemExit):
            main.main()

        mock_set_auth.assert_not_called()
        self.assertIn("Invalid secret_id", mock_show_error.call_args[0][0])

    @patch("src.main.requests.Session")
    @patch("src.main.update_secret")
    @patch("src.main.set_authentication")
    def test_main_masks_inputs_before_authenticating(
        self, mock_set_auth, mock_update, mock_session_class
    ):
        """The password and seed are masked before anything else runs."""
        events = []
        mock_set_auth.side_effect = lambda _: events.append("auth") or MagicMock()
        self.set_inputs(**CREDENTIAL_INPUTS, TOTP_ENABLED="true", TOTP_SECRET_KEY=SEED)

        with patch("builtins.print", side_effect=events.append):
            main.main()

        self.assertEqual(events, ["::add-mask ::p4ss", f"::add-mask ::{SEED}", "auth"])

    @patch("src.main.common.show_error")
    @patch("src.main.requests.Session", side_effect=Exception("boom"))
    def test_main_unexpected_error(self, _mock_session, mock_show_error):
        """Unexpected errors fail the step through show_error."""
        self.set_inputs(**CREDENTIAL_INPUTS)

        with patch("builtins.print"):
            main.main()

        self.assertIn("An unexpected error occurred", mock_show_error.call_args[0][0])


class TestValidateInputs(InputsTestCase):
    """Tests for validate_inputs and the checks it runs."""

    def _rejected(self, mock_show_error, **inputs):
        self.set_inputs(**inputs)
        with self.assertRaises(SystemExit):
            validate_inputs()
        message = mock_show_error.call_args[0][0]
        self.assertNotIn(SEED, message)
        return message

    def test_credential(self):
        self.set_inputs(
            **CREDENTIAL_INPUTS,
            OWNER_ID="5",
            PASSWORD_RULE_ID="2",
            URLS='[{"url": "https://example.com"}]',
        )
        self.assertEqual(
            validate_inputs(),
            settings(
                owner_id=5,
                password_rule_id=2,
                urls=[{"url": "https://example.com"}],
            ),
        )

    def test_text(self):
        self.set_inputs(**BASE_INPUTS, TEXT="t", PASSWORD_RULE_ID="2")
        # password_rule_id only applies to credential secrets.
        self.assertEqual(validate_inputs(), settings(main.TEXT_TYPE))

    def test_file(self):
        self.set_inputs(**BASE_INPUTS, FILE_NAME="f.txt", FILE_CONTENT="c")
        self.assertEqual(validate_inputs(), settings(main.FILE_TYPE))

    def test_credential_with_totp(self):
        self.set_inputs(**CREDENTIAL_INPUTS, TOTP_ENABLED="true", TOTP_SECRET_KEY=SEED)
        self.assertEqual(
            validate_inputs(), settings(totp_enabled=True, totp_secret_key=SEED)
        )

    def test_credential_disable_totp(self):
        """totp_enabled=false on its own turns TOTP off."""
        self.set_inputs(**CREDENTIAL_INPUTS, TOTP_ENABLED="false")
        self.assertEqual(validate_inputs(), settings(totp_enabled=False))

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_rejected_inputs(self, mock_show_error):
        """Each invalid combination fails with a message naming the problem."""
        cases = (
            ({**CREDENTIAL_INPUTS, "SECRET_ID": ""}, "Invalid secret_id"),
            ({**CREDENTIAL_INPUTS, "SECRET_ID": "not-a-guid"}, "Invalid secret_id"),
            ({**CREDENTIAL_INPUTS, "TITLE": ""}, "secret_title is required"),
            ({**CREDENTIAL_INPUTS, "PASSWORD": ""}, "password is required"),
            ({**CREDENTIAL_INPUTS, "OWNER_ID": "abc"}, "owner_id"),
            ({**CREDENTIAL_INPUTS, "PASSWORD_RULE_ID": "1.5"}, "password_rule_id"),
            ({**CREDENTIAL_INPUTS, "OWNERS": ""}, "owners is required"),
            ({**CREDENTIAL_INPUTS, "OWNERS": "[]"}, "owners is required"),
            ({**CREDENTIAL_INPUTS, "OWNERS": "{bad"}, "Invalid JSON format for owners"),
            ({**CREDENTIAL_INPUTS, "URLS": "{bad"}, "Invalid JSON format for urls"),
            ({**CREDENTIAL_INPUTS, "TEXT": "t"}, "exactly one kind"),
            (BASE_INPUTS, "exactly one kind"),
            (
                {**BASE_INPUTS, "FILE_NAME": "f.txt"},
                "file_name and file_content are both required",
            ),
            (
                {**CREDENTIAL_INPUTS, "TOTP_ENABLED": "yes"},
                "Invalid value for totp_enabled",
            ),
            (
                {**CREDENTIAL_INPUTS, "TOTP_ENABLED": "true"},
                "totp_secret_key is required",
            ),
            (
                {**CREDENTIAL_INPUTS, "TOTP_SECRET_KEY": SEED},
                "only allowed when totp_enabled",
            ),
            (
                {
                    **BASE_INPUTS,
                    "TEXT": "t",
                    "TOTP_ENABLED": "true",
                    "TOTP_SECRET_KEY": SEED,
                },
                "only supported for credential secrets",
            ),
        )
        for inputs, text in cases:
            with self.subTest(text=text, inputs=inputs):
                self.assertIn(text, self._rejected(mock_show_error, **inputs))


class TestSmallParsers(InputsTestCase):
    """Tests for the input parsing helpers."""

    def test_parse_optional_bool(self):
        for value, expected in (("", None), ("TRUE", True), ("false", False)):
            with self.subTest(value=value):
                self.assertIs(parse_optional_bool(value, "totp_enabled"), expected)

    def test_parse_optional_int(self):
        self.assertIsNone(parse_optional_int("", "owner_id"))
        self.assertEqual(parse_optional_int("42", "owner_id"), 42)

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_validate_secret_id(self, mock_show_error):
        validate_secret_id(SECRET_ID)
        mock_show_error.assert_not_called()

        with self.assertRaises(SystemExit):
            validate_secret_id("x")

    def test_get_secret_type(self):
        self.set_inputs(USERNAME="user")
        self.assertEqual(get_secret_type(), main.CREDENTIAL)

    def test_get_totp_settings_omitted(self):
        """Without the TOTP inputs, TOTP is left unchanged."""
        self.set_inputs()
        self.assertEqual(get_totp_settings(main.TEXT_TYPE), (None, None))


class TestUpdateSecret(InputsTestCase):
    """Tests for update_secret, with the library mocked."""

    def _update(self, secret_type, **inputs):
        """Run update_secret and return the kwargs sent to the library."""
        with patch("src.main.secrets_safe.SecretsSafe", autospec=True) as sdk:
            update_secret(MagicMock(), settings(secret_type, **inputs))
        return sdk.return_value.update_secret.call_args.kwargs

    @patch("src.main.common.show_error")
    def test_credential_update(self, mock_show_error):
        """Only the credential fields and the TOTP settings are sent."""
        self.set_inputs(**CREDENTIAL_INPUTS, DESCRIPTION="d", NOTES="n")

        kwargs = self._update(
            main.CREDENTIAL,
            owners=[{"owner_id": 1}],
            urls=[{"url": "https://example.com"}],
            totp_enabled=True,
            totp_secret_key=SEED,
            owner_id=7,
            password_rule_id=3,
        )

        self.assertEqual(
            kwargs,
            {
                "secret_id": SECRET_ID,
                "title": "Title",
                "description": "d",
                "username": "user",
                "password": "p4ss",
                "text": None,
                "file_path": None,
                "owner_id": 7,
                "owner_type": None,
                "owners": [{"owner_id": 1}],
                "password_rule_id": 3,
                "notes": "n",
                "urls": [{"url": "https://example.com"}],
                "totp_enabled": True,
                "totp_secret_key": SEED,
            },
        )
        mock_show_error.assert_not_called()

    def test_text_update(self):
        self.set_inputs(**BASE_INPUTS, TEXT="t")

        kwargs = self._update(main.TEXT_TYPE)

        self.assertEqual(kwargs["text"], "t")
        self.assertIsNone(kwargs["username"])
        self.assertIsNone(kwargs["file_path"])

    @patch("src.main.common.create_file")
    def test_file_update_writes_the_file_first(self, mock_create_file):
        self.set_inputs(**BASE_INPUTS, FILE_NAME="f.txt", FILE_CONTENT="c")

        kwargs = self._update(main.FILE_TYPE)

        mock_create_file.assert_called_once_with("f.txt", "c", main.logger)
        self.assertEqual(kwargs["file_path"], "f.txt")
        self.assertIsNone(kwargs["text"])

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_errors(self, mock_show_error):
        """Library errors fail the step with an actionable message."""
        self.set_inputs(**CREDENTIAL_INPUTS)
        cases = (
            (
                main.exceptions.UpdateError(
                    "Error running put request, message: Not found, statuscode: 404"
                ),
                "that it is a credential secret",
            ),
            (main.exceptions.OptionsError("bad"), "Invalid or missing parameters"),
            (
                main.exceptions.IncompleteArgumentsError("missing"),
                "Invalid or missing parameters",
            ),
            (FileNotFoundError("f.txt"), "Invalid or missing file path"),
        )
        for error, text in cases:
            with self.subTest(text=text):
                with patch("src.main.secrets_safe.SecretsSafe", autospec=True) as sdk:
                    sdk.return_value.update_secret.side_effect = error
                    with self.assertRaises(SystemExit):
                        update_secret(MagicMock(), settings())
                self.assertIn(text, mock_show_error.call_args[0][0])

    @patch("src.main.common.show_error")
    def test_204_update_error_is_success(self, mock_show_error):
        """The library's 204 UpdateError means the update was applied."""
        self.set_inputs(**CREDENTIAL_INPUTS)

        with patch("src.main.secrets_safe.SecretsSafe", autospec=True) as sdk:
            sdk.return_value.update_secret.side_effect = main.exceptions.UpdateError(
                "Error running put request, message: , statuscode: 204"
            )
            update_secret(MagicMock(), settings())

        mock_show_error.assert_not_called()

    def test_is_no_content_success(self):
        self.assertTrue(is_no_content_success(Exception("message: , statuscode: 204")))
        for message in (
            "message: , statuscode: 404",
            "message: statuscode: 204 in a body, statuscode: 400",
            "statuscode: 2040",
        ):
            with self.subTest(message=message):
                self.assertFalse(is_no_content_success(Exception(message)))


class TestUpdateSecretWithLibrary(InputsTestCase):
    """
    Runs the real library update_secret against a fake HTTP session that
    answers like the API does (Swagger: 204 No Content), so the 204 handling is
    checked against the library code itself rather than a mock of it.
    """

    def _authentication(self, status_code, api_version="3.3"):
        auth = MagicMock()
        auth._api_url = "https://example.com/BeyondTrust/api/public/v3"
        auth._api_version = api_version
        auth._timeout_connection_seconds = 30
        auth._timeout_request_seconds = 30
        auth._req.put.return_value = MagicMock(status_code=status_code, text="")
        return auth

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_credential_204_succeeds(self, mock_show_error):
        self.set_inputs(**CREDENTIAL_INPUTS, TOTP_ENABLED="true", TOTP_SECRET_KEY=SEED)
        auth = self._authentication(204)

        update_secret(auth, settings(totp_enabled=True, totp_secret_key=SEED))

        mock_show_error.assert_not_called()
        url = auth._req.put.call_args.kwargs["url"]
        body = auth._req.put.call_args.kwargs["json"]
        self.assertIn(f"/secrets-safe/secrets/{SECRET_ID}/?version=3.3", url)
        self.assertNotIn("/text", url)
        self.assertEqual(body["Username"], "user")
        self.assertIs(body["TotpEnabled"], True)
        self.assertEqual(body["TotpSecretKey"], SEED)

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_text_204_succeeds(self, mock_show_error):
        self.set_inputs(**BASE_INPUTS, TEXT="t")
        auth = self._authentication(204)

        update_secret(auth, settings(main.TEXT_TYPE))

        mock_show_error.assert_not_called()
        self.assertIn(
            f"/secrets-safe/secrets/{SECRET_ID}/text",
            auth._req.put.call_args.kwargs["url"],
        )
        self.assertEqual(auth._req.put.call_args.kwargs["json"]["Text"], "t")

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_404_fails(self, mock_show_error):
        self.set_inputs(**CREDENTIAL_INPUTS)
        auth = self._authentication(404)

        with self.assertRaises(SystemExit):
            update_secret(auth, settings())

        self.assertIn("Error updating secret", mock_show_error.call_args[0][0])

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_totp_needs_api_3_3(self, mock_show_error):
        """The library rejects TOTP below 3.3 before sending the request."""
        self.set_inputs(**CREDENTIAL_INPUTS, TOTP_ENABLED="true", TOTP_SECRET_KEY=SEED)
        auth = self._authentication(204, api_version="3.1")

        with self.assertRaises(SystemExit):
            update_secret(auth, settings(totp_enabled=True, totp_secret_key=SEED))

        self.assertIn("Invalid or missing parameters", mock_show_error.call_args[0][0])
        auth._req.put.assert_not_called()

    def test_library_still_expects_200(self):
        """
        Documents the library behaviour the 204 workaround exists for. If this
        fails, the library accepts 204 and NO_CONTENT_UPDATE_ERROR can go.
        """
        sdk = secrets_safe.SecretsSafe(
            authentication=self._authentication(204), logger=main.logger
        )
        with self.assertRaises(main.exceptions.UpdateError):
            sdk.update_secret(
                secret_id=SECRET_ID,
                title="Title",
                username="u",
                password="p",
                owners=OWNERS,
            )


class TestMasking(InputsTestCase):
    """Tests for masking the sensitive inputs."""

    @patch("builtins.print")
    def test_mask_secret_splits_lines_and_escapes(self, mock_print):
        mask_secret("add-mask", "a\r::stop-commands::z\n50%")

        self.assertEqual(
            [c.args[0] for c in mock_print.call_args_list],
            [
                "::add-mask ::a",
                "::add-mask ::::stop-commands::z",
                "::add-mask ::50%25",
            ],
        )

    @patch("builtins.print")
    def test_password_text_and_otpauth_seed_are_masked(self, mock_print):
        uri = f"otpauth://totp/Example:alice?secret={SEED}&issuer=Example"
        self.set_inputs(PASSWORD="p4ss", TEXT="t3xt", TOTP_SECRET_KEY=uri)

        mask_sensitive_inputs()

        self.assertEqual(
            [c.args[0] for c in mock_print.call_args_list],
            [
                "::add-mask ::p4ss",
                "::add-mask ::t3xt",
                f"::add-mask ::{uri}",
                f"::add-mask ::{SEED}",
            ],
        )

    @patch("builtins.print")
    def test_nothing_masked_when_inputs_empty(self, mock_print):
        self.set_inputs()
        mask_sensitive_inputs()
        mock_print.assert_not_called()


class TestAuthentication(InputsTestCase):
    """Tests for set_authentication."""

    @patch("src.main.API_KEY", "api-key")
    @patch("src.main.API_VERSION", "3.3")
    @patch("src.main.authentication.Authentication")
    def test_api_key_and_version(self, mock_auth_class):
        mock_auth_class.return_value.get_api_access.return_value = MagicMock(
            status_code=200
        )

        main.set_authentication(requests.Session())

        kwargs = mock_auth_class.call_args.kwargs
        self.assertEqual(kwargs["api_key"], "api-key")
        self.assertEqual(kwargs["api_version"], "3.3")
        self.assertNotIn("client_id", kwargs)

    @patch("src.main.API_KEY", None)
    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    @patch("src.main.authentication.Authentication")
    def test_client_credentials_and_failure(self, mock_auth_class, mock_show_error):
        mock_auth_class.return_value.get_api_access.return_value = MagicMock(
            status_code=401, text="Unauthorized"
        )

        with self.assertRaises(SystemExit):
            main.set_authentication(requests.Session())

        self.assertIn("client_id", mock_auth_class.call_args.kwargs)
        self.assertIn("Please check credentials", mock_show_error.call_args[0][0])


class TestVerifyCA(unittest.TestCase):
    """Tests for parse_verify_ca and configure_certificate_verification."""

    def test_parse_verify_ca(self):
        for value, expected in ((None, True), ("", True), ("on", True), ("0", False)):
            with self.subTest(value=value):
                self.assertIs(main.parse_verify_ca(value), expected)

        with tempfile.NamedTemporaryFile(suffix=".crt") as bundle:
            self.assertEqual(main.parse_verify_ca(f" {bundle.name} "), bundle.name)

        with self.assertRaises(EnvironmentError):
            main.parse_verify_ca("/no/such/ca-bundle.crt")

    def test_configure_certificate_verification(self):
        session = requests.Session()
        with patch("src.main.utils.print_log") as print_log:
            main.configure_certificate_verification(session, False)
            print_log.assert_not_called()

            with tempfile.NamedTemporaryFile(suffix=".crt") as bundle:
                main.configure_certificate_verification(session, bundle.name)
                self.assertIn(bundle.name, print_log.call_args[0][1])

            with patch.dict(os.environ, {"CURL_CA_BUNDLE": "/c.crt"}, clear=True):
                main.configure_certificate_verification(session, True)
            self.assertIn("CURL_CA_BUNDLE", print_log.call_args[0][1])

            with patch.dict(os.environ, {}, clear=True):
                main.configure_certificate_verification(session, True)
            self.assertIn("certifi", print_log.call_args[0][1])


if __name__ == "__main__":
    unittest.main()

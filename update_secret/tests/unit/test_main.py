"""Unit tests for the Update Secret action"""

import unittest
from contextlib import ExitStack, contextmanager
from unittest.mock import MagicMock, patch

import requests
from secrets_safe_library import secrets_safe
from src import main
from src.main import (
    get_secret_type,
    get_totp_settings,
    is_no_content_success,
    mask_sensitive_inputs,
    parse_optional_bool,
    parse_optional_int,
    to_library_owners,
    update_secret,
    validate_inputs,
    validate_secret_id,
)

SECRET_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
SEED = "JBSWY3DPEHPK3PXP"  # nosec B105 - test data
OWNERS = [{"user_id": 1}]
FOLDER_ID = "f0f0f0f0-1111-2222-3333-444444444444"
URL_ID = "11111111-aaaa-bbbb-cccc-222222222222"

# A credential secret as GET Secrets-Safe/Secrets/{id} returns it.
EXISTING_CREDENTIAL = {
    "Id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "SecretType": "Credential",
    "FolderId": "f0f0f0f0-1111-2222-3333-444444444444",
    "Title": "Current title",
    "Description": "Current description",
    "Username": "current-user",
    "Password": "current-pass",
    "Owners": [
        {"UserId": 7, "GroupId": None, "Name": "admin", "Email": "admin@example.com"}
    ],
    "Notes": "Current notes",
    "Urls": [
        {"Id": URL_ID, "CredentialId": SECRET_ID, "Url": "https://current.example"}
    ],
    "PasswordRuleID": 4,
    "TotpEnabled": True,
}

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

    @patch("src.main.api_client.create_session")
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

    @patch("src.main.api_client.create_session")
    @patch("src.main.update_secret", side_effect=SystemExit(1))
    @patch("src.main.set_authentication")
    def test_main_signs_out_when_update_fails(
        self, mock_set_auth, _mock_update, _mock_session_class
    ):
        """A failed update still signs out of the API session."""
        self.set_inputs(**CREDENTIAL_INPUTS)
        mock_auth = MagicMock()
        mock_set_auth.return_value = mock_auth

        with patch("builtins.print"), self.assertRaises(SystemExit):
            main.main()

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

    @patch("src.main.api_client.create_session")
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
    @patch("src.main.api_client.create_session", side_effect=Exception("boom"))
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

    def test_minimal_inputs(self):
        """Only secret_id and the content that can't be read back are needed."""
        cases = (
            ({"USERNAME": "user"}, main.CREDENTIAL),
            ({"TEXT": "t"}, main.TEXT_TYPE),
            ({"FILE_NAME": "f.txt", "FILE_CONTENT": "c"}, main.FILE_TYPE),
        )
        for inputs, secret_type in cases:
            with self.subTest(secret_type=secret_type):
                self.set_inputs(SECRET_ID=SECRET_ID, **inputs)
                self.assertEqual(validate_inputs(), settings(secret_type, owners=None))

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
            ({**CREDENTIAL_INPUTS, "OWNER_ID": "abc"}, "owner_id"),
            ({**CREDENTIAL_INPUTS, "PASSWORD_RULE_ID": "1.5"}, "password_rule_id"),
            ({**CREDENTIAL_INPUTS, "OWNERS": "{bad"}, "Invalid JSON format for owners"),
            ({**CREDENTIAL_INPUTS, "URLS": "{bad"}, "Invalid JSON format for urls"),
            ({**CREDENTIAL_INPUTS, "OWNERS": '{"user_id": 1}'}, "Invalid owners"),
            ({**CREDENTIAL_INPUTS, "OWNERS": "[1]"}, "Invalid owners"),
            ({**CREDENTIAL_INPUTS, "OWNERS": "true"}, "Invalid owners"),
            ({**CREDENTIAL_INPUTS, "OWNERS": "[]"}, "non-empty JSON array"),
            ({**CREDENTIAL_INPUTS, "URLS": "true"}, "Invalid urls"),
            ({**CREDENTIAL_INPUTS, "URLS": '["https://x"]'}, "Invalid urls"),
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


def current_secret(secret_type=main.CREDENTIAL, **fields):
    """Return a GET Secrets-Safe/Secrets/{id} response for the given type."""
    secret = {"SecretType": secret_type.capitalize(), "FolderId": FOLDER_ID}
    secret.update(fields)
    return secret


@contextmanager
def mocked_sdk(secret_type=main.CREDENTIAL, existing=None, **fields):
    """
    Patch SecretsSafe; get_secret_by_id returns `existing`, or a secret of
    secret_type with only a type and a folder.
    """
    with patch("src.main.secrets_safe.SecretsSafe", autospec=True) as sdk:
        sdk.return_value.get_secret_by_id.return_value = existing or current_secret(
            secret_type, **fields
        )
        yield sdk


class TestUpdateSecret(InputsTestCase):
    """Tests for update_secret, with the library mocked."""

    def _update(self, secret_type, **inputs):
        """Run update_secret and return the kwargs sent to the library."""
        with mocked_sdk(secret_type) as sdk:
            update_secret(MagicMock(), settings(secret_type, **inputs))
        sdk.return_value.get_secret_by_id.assert_called_once_with(SECRET_ID)
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
                "folder_id": FOLDER_ID,
                "title": "Title",
                "description": "d",
                "username": "user",
                "password": "p4ss",
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
        # Only the content of the secret's own type is sent.
        for key in ("username", "password", "password_rule_id", "file_path"):
            self.assertNotIn(key, kwargs)

    @patch("src.main.common.create_file")
    def test_file_update_writes_the_file_first(self, mock_create_file):
        self.set_inputs(**BASE_INPUTS, FILE_NAME="f.txt", FILE_CONTENT="c")

        kwargs = self._update(main.FILE_TYPE)

        mock_create_file.assert_called_once_with("f.txt", "c", main.logger)
        self.assertEqual(kwargs["file_path"], "f.txt")
        self.assertNotIn("text", kwargs)

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
                with mocked_sdk() as sdk:
                    sdk.return_value.update_secret.side_effect = error
                    with self.assertRaises(SystemExit):
                        update_secret(MagicMock(), settings())
                self.assertIn(text, mock_show_error.call_args[0][0])

    @patch("src.main.common.show_error")
    def test_204_update_error_is_success(self, mock_show_error):
        """The library's 204 UpdateError means the update was applied."""
        self.set_inputs(**CREDENTIAL_INPUTS)

        with mocked_sdk() as sdk:
            sdk.return_value.update_secret.side_effect = main.exceptions.UpdateError(
                "Error running put request, message: , statuscode: 204"
            )
            update_secret(MagicMock(), settings())

        mock_show_error.assert_not_called()

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_current_secret_checks(self, mock_show_error):
        """
        The secret is read before the update; a read failure, a type mismatch
        or a missing FolderId fails the step without sending the update.
        """
        self.set_inputs(**CREDENTIAL_INPUTS)
        cases = (
            ({"SecretType": "Text"}, "is a text secret, but the inputs are for a"),
            ({"SecretType": "File"}, "is a file secret, but the inputs are for a"),
            ({"FolderId": None}, "its folder ID was not returned"),
        )
        for fields, text in cases:
            with self.subTest(text=text):
                with mocked_sdk(**fields) as sdk, self.assertRaises(SystemExit):
                    update_secret(MagicMock(), settings())
                sdk.return_value.update_secret.assert_not_called()
                self.assertIn(text, mock_show_error.call_args[0][0])

        with mocked_sdk() as sdk, self.assertRaises(SystemExit):
            sdk.return_value.get_secret_by_id.side_effect = main.exceptions.LookupError(
                "404 Not Found"
            )
            update_secret(MagicMock(), settings())
        sdk.return_value.update_secret.assert_not_called()
        self.assertIn("Cannot read secret", mock_show_error.call_args[0][0])

    @patch("src.main.common.show_error")
    def test_type_check_skipped_without_secret_type(self, mock_show_error):
        """If the read does not report a type, only the folder is required."""
        self.set_inputs(**CREDENTIAL_INPUTS)

        with mocked_sdk(SecretType=None) as sdk:
            update_secret(MagicMock(), settings())

        mock_show_error.assert_not_called()
        self.assertEqual(
            sdk.return_value.update_secret.call_args.kwargs["folder_id"], FOLDER_ID
        )

    @patch("src.main.common.show_error")
    def test_empty_inputs_keep_current_values(self, mock_show_error):
        """
        Inputs left empty keep the existing secret's values, as in the CLI's
        `secrets update`, instead of clearing them.
        """
        self.set_inputs(SECRET_ID=SECRET_ID, USERNAME="user")

        with mocked_sdk(existing=EXISTING_CREDENTIAL) as sdk, patch("builtins.print"):
            update_secret(MagicMock(), settings(owners=None))

        mock_show_error.assert_not_called()
        self.assertEqual(
            sdk.return_value.update_secret.call_args.kwargs,
            {
                "secret_id": SECRET_ID,
                "folder_id": FOLDER_ID,
                "title": "Current title",
                "description": "Current description",
                "username": "user",
                "password": "current-pass",
                "password_rule_id": 4,
                "owner_id": None,
                "owner_type": None,
                "owners": [
                    {"user_id": 7, "name": "admin", "email": "admin@example.com"}
                ],
                "notes": "Current notes",
                "urls": EXISTING_CREDENTIAL["Urls"],
                # TOTP is left unchanged by sending nothing.
                "totp_enabled": None,
                "totp_secret_key": None,
            },
        )

    @patch("src.main.common.show_error")
    def test_given_inputs_replace_current_values(self, mock_show_error):
        """Inputs that are set win over the existing secret's values."""
        self.set_inputs(
            **{**CREDENTIAL_INPUTS, "TITLE": "New title"},
            DESCRIPTION="New description",
            NOTES="New notes",
            OWNER_TYPE="User",
        )
        new_urls = [{"url": "https://new.example"}]

        with mocked_sdk(existing=EXISTING_CREDENTIAL) as sdk, patch("builtins.print"):
            update_secret(
                MagicMock(),
                settings(urls=new_urls, password_rule_id=9, owner_id=3),
            )

        kwargs = sdk.return_value.update_secret.call_args.kwargs
        self.assertEqual(kwargs["title"], "New title")
        self.assertEqual(kwargs["description"], "New description")
        self.assertEqual(kwargs["notes"], "New notes")
        self.assertEqual(kwargs["password"], "p4ss")
        self.assertEqual(kwargs["password_rule_id"], 9)
        self.assertEqual(kwargs["owner_id"], 3)
        self.assertEqual(kwargs["owner_type"], "User")
        self.assertEqual(kwargs["owners"], OWNERS)
        self.assertEqual(kwargs["urls"], new_urls)
        # The folder is always the current one: secrets are not moved.
        self.assertEqual(kwargs["folder_id"], FOLDER_ID)

    def test_current_password_is_masked(self):
        """A password kept from the existing secret is masked like the input."""
        self.set_inputs(SECRET_ID=SECRET_ID, USERNAME="user")

        with mocked_sdk(existing=EXISTING_CREDENTIAL), patch(
            "builtins.print"
        ) as mock_print:
            update_secret(MagicMock(), settings(owners=None))

        mock_print.assert_any_call("::add-mask ::current-pass")

    def test_to_library_owners(self):
        """Owners read back are converted to the names update_secret validates."""
        self.assertIsNone(to_library_owners(None))
        self.assertIsNone(to_library_owners([]))
        self.assertEqual(
            to_library_owners(
                [
                    {"UserId": 7, "GroupId": None, "Name": "admin", "Email": None},
                    {"OwnerId": 3, "Owner": "ops", "Email": "ops@example.com"},
                ]
            ),
            [
                {"user_id": 7, "name": "admin"},
                {"owner_id": 3, "owner": "ops", "email": "ops@example.com"},
            ],
        )

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

    def _authentication(
        self, status_code, api_version="3.3", secret_type=None, existing=None
    ):
        auth = MagicMock()
        auth._api_url = "https://example.com/BeyondTrust/api/public/v3"
        auth._api_version = api_version
        auth._timeout_connection_seconds = 30
        auth._timeout_request_seconds = 30
        secret = existing or current_secret(secret_type or main.CREDENTIAL)
        auth._req.get.return_value = MagicMock(
            status_code=200, json=MagicMock(return_value=secret)
        )
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
        self.assertEqual(body["FolderId"], FOLDER_ID)
        self.assertIs(body["TotpEnabled"], True)
        self.assertEqual(body["TotpSecretKey"], SEED)

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_text_204_succeeds(self, mock_show_error):
        self.set_inputs(**BASE_INPUTS, TEXT="t")
        auth = self._authentication(204, secret_type=main.TEXT_TYPE)

        update_secret(auth, settings(main.TEXT_TYPE))

        mock_show_error.assert_not_called()
        self.assertIn(
            f"/secrets-safe/secrets/{SECRET_ID}/text",
            auth._req.put.call_args.kwargs["url"],
        )
        self.assertEqual(auth._req.put.call_args.kwargs["json"]["Text"], "t")
        self.assertEqual(auth._req.put.call_args.kwargs["json"]["FolderId"], FOLDER_ID)
        self.assertIn(
            f"/secrets-safe/secrets/{SECRET_ID}", auth._req.get.call_args[0][0]
        )

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_minimal_update_keeps_current_values(self, mock_show_error):
        """
        With only secret_id and username, the library accepts the values read
        from the existing secret (including its owners, after conversion) and
        sends them back.
        """
        self.set_inputs(SECRET_ID=SECRET_ID, USERNAME="user")
        auth = self._authentication(204, existing=EXISTING_CREDENTIAL)

        with patch("builtins.print"):
            update_secret(auth, settings(owners=None))

        mock_show_error.assert_not_called()
        body = auth._req.put.call_args.kwargs["json"]
        self.assertEqual(body["Title"], "Current title")
        self.assertEqual(body["Description"], "Current description")
        self.assertEqual(body["Username"], "user")
        self.assertEqual(body["Password"], "current-pass")
        self.assertEqual(body["Notes"], "Current notes")
        # The owner read back is sent back as it was (None fields dropped).
        self.assertEqual(
            body["Owners"],
            [{"UserId": 7, "Name": "admin", "Email": "admin@example.com"}],
        )
        self.assertEqual(body["Urls"], EXISTING_CREDENTIAL["Urls"])
        self.assertEqual(body["FolderId"], FOLDER_ID)
        self.assertNotIn("TotpSecretKey", {k for k, v in body.items() if v})

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


if __name__ == "__main__":
    unittest.main()

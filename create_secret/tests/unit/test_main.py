import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import requests
from secrets_safe_library.exceptions import CreationError, OptionsError
from src.main import (
    configure_certificate_verification,
    create_secret,
    get_folder,
    get_totp_settings,
    main,
    mask_secret,
    mask_sensitive_inputs,
    parse_optional_bool,
    parse_verify_ca,
    set_authentication,
)


class TestMain(unittest.TestCase):
    """
    Unit tests for main module functions:
    - get_folder
    - set_authentication
    - main
    """

    def test_get_folder_returns_none_when_no_folders(self):
        """
        Verify that get_folder returns None when the folders API
        returns an empty list (no folders found).
        """
        folders_obj = MagicMock()
        folders_obj.list_folders.return_value = []

        result = get_folder(folders_obj, "MyFolder")

        self.assertIsNone(result)
        folders_obj.list_folders.assert_called_once_with(folder_name="MyFolder")

    def test_get_folder_returns_matching_folder(self):
        """
        Verify that get_folder returns the first folder whose name
        exactly matches the requested folder name.
        """
        folders_obj = MagicMock()
        folders_obj.list_folders.return_value = [
            {"Name": "MyFolder", "Id": 1},
            {"Name": "Other", "Id": 2},
        ]

        result = get_folder(folders_obj, "MyFolder")

        self.assertEqual(result, {"Name": "MyFolder", "Id": 1})
        folders_obj.list_folders.assert_called_once_with(folder_name="MyFolder")

    @patch("src.main.utils.prepare_certificate_info")
    @patch("src.main.authentication.Authentication", autospec=True)
    def test_set_authentication_with_api_key(
        self,
        mock_auth_class,
        mock_prepare_cert,
    ):
        """
        Verify that set_authentication uses API Key authentication
        when the API_KEY environment variable is present.
        """
        session = MagicMock()

        mock_prepare_cert.return_value = ("cert", "key")

        mock_auth_instance = mock_auth_class.return_value
        mock_auth_instance.get_api_access.return_value.status_code = 200

        with patch("src.main.API_KEY", "my-api-key"), patch(
            "src.main.API_VERSION", None
        ):

            auth = set_authentication(session)

        mock_prepare_cert.assert_called_once()
        mock_auth_class.assert_called_once()
        self.assertEqual(auth, mock_auth_instance)

    @patch("src.main.Retry")
    @patch("src.main.utils.prepare_certificate_info")
    @patch("src.main.authentication.Authentication", autospec=True)
    def test_set_authentication_with_client_credentials(
        self,
        mock_auth_class,
        mock_prepare_cert,
        mock_retry,
    ):
        """
        Verify that set_authentication falls back to OAuth client
        credentials authentication when API_KEY is not provided.
        """
        session = MagicMock()

        mock_retry.return_value = "req"
        mock_prepare_cert.return_value = ("cert", "key")

        mock_auth_instance = mock_auth_class.return_value
        mock_auth_instance.get_api_access.return_value.status_code = 200

        with patch("src.main.API_KEY", None), patch(
            "src.main.CLIENT_ID", "client-id"
        ), patch("src.main.CLIENT_SECRET", "client-secret"):

            auth = set_authentication(session)

        self.assertEqual(auth, mock_auth_instance)

    @patch("src.main.requests.Session")
    @patch("src.main.create_secret")
    @patch("src.main.set_authentication")
    def test_main_success(
        self,
        mock_set_authentication,
        mock_create_secret,
        mock_session_class,
    ):
        """
        Verify that main executes the full happy path:
        - Creates a requests session
        - Authenticates successfully
        - Creates a secret
        - Signs out from the authentication session
        """
        mock_session = MagicMock()
        mock_session_class.return_value.__enter__.return_value = mock_session

        mock_auth = MagicMock()
        mock_set_authentication.return_value = mock_auth

        main()

        mock_set_authentication.assert_called_once_with(mock_session)
        mock_create_secret.assert_called_once_with(mock_auth, None, None)
        mock_auth.sign_app_out.assert_called_once()

    @patch("src.main.common.show_error")
    @patch("src.main.secrets_safe.SecretsSafe", autospec=True)
    @patch("src.main.get_folder")
    @patch("src.main.folders.Folder", autospec=True)
    def test_create_secret_success(
        self,
        mock_folder_class,
        mock_get_folder,
        mock_secrets_safe_class,
        mock_show_error,
    ):
        """
        Verify that create_secret successfully creates a secret using FILE secret type.
        """
        mock_auth = MagicMock()

        mock_folder = {"Id": 123, "Name": "TestFolder"}
        mock_get_folder.return_value = mock_folder

        mock_secrets_safe_obj = mock_secrets_safe_class.return_value

        with patch("src.main.TITLE", "TestSecret"), patch(
            "src.main.PARENT_FOLDER_NAME", "TestFolder"
        ), patch("src.main.DESCRIPTION", "Test Description"), patch(
            "src.main.FILE_CONTENT", "secret content"
        ), patch(
            "src.main.FILE_NAME", "secret.txt"
        ):

            create_secret(mock_auth)

        mock_secrets_safe_obj.create_secret.assert_called_once_with(
            title="TestSecret",
            folder_id=123,
            description="Test Description",
            username="",
            password="",
            text="",
            file_path="secret.txt",
            owner_id=None,
            owner_type="",
            owners=None,
            password_rule_id=None,
            notes="",
            urls=None,
            totp_enabled=None,
            totp_secret_key=None,
        )
        mock_show_error.assert_not_called()

    @patch("src.main.common.show_error")
    @patch("src.main.secrets_safe.SecretsSafe", autospec=True)
    @patch("src.main.get_folder")
    @patch("src.main.folders.Folder", autospec=True)
    def test_create_secret_options_error(
        self,
        mock_folder_class,
        mock_get_folder,
        mock_secrets_safe_class,
        mock_show_error,
    ):
        """
        Verify that create_secret handles OptionsError
        """
        mock_auth = MagicMock()

        mock_folder = {"Id": 123, "Name": "TestFolder"}
        mock_get_folder.return_value = mock_folder

        mock_secrets_safe_obj = mock_secrets_safe_class.return_value

        mock_secrets_safe_obj.create_secret.side_effect = OptionsError(
            "Invalid or missing parameters: Invalid options"
        )

        with patch("src.main.TITLE", "TestSecret"):
            create_secret(mock_auth)

        mock_show_error.assert_called_once()

    @patch("src.main.common.show_error")
    @patch("src.main.secrets_safe.SecretsSafe", autospec=True)
    @patch("src.main.get_folder")
    @patch("src.main.folders.Folder", autospec=True)
    def test_create_secret_creation_error(
        self,
        mock_folder_class,
        mock_get_folder,
        mock_secrets_safe_class,
        mock_show_error,
    ):
        """
        Verify that create_secret handles CreationError
        """
        mock_auth = MagicMock()

        mock_folder = {"Id": 123, "Name": "TestFolder"}
        mock_get_folder.return_value = mock_folder

        mock_secrets_safe_obj = mock_secrets_safe_class.return_value

        mock_secrets_safe_obj.create_secret.side_effect = CreationError(
            "Invalid or missing parameters: Error creating secret"
        )

        with patch("src.main.TITLE", "TestSecret"):
            create_secret(mock_auth)

        mock_show_error.assert_called_once()

    @patch("src.main.common.show_error")
    @patch("src.main.secrets_safe.SecretsSafe", autospec=True)
    @patch("src.main.get_folder")
    @patch("src.main.folders.Folder", autospec=True)
    def test_create_secret_passes_totp_to_library(
        self,
        mock_folder_class,
        mock_get_folder,
        mock_secrets_safe_class,
        mock_show_error,
    ):
        """
        Verify that create_secret forwards the TOTP settings when creating a
        credential secret.
        """
        mock_get_folder.return_value = {"Id": 123, "Name": "TestFolder"}
        mock_secrets_safe_obj = mock_secrets_safe_class.return_value

        with patch("src.main.TITLE", "TestSecret"), patch(
            "src.main.USERNAME", "user"
        ), patch("src.main.PASSWORD", "pass"):
            create_secret(MagicMock(), True, "JBSWY3DPEHPK3PXP")

        kwargs = mock_secrets_safe_obj.create_secret.call_args.kwargs
        self.assertIs(kwargs["totp_enabled"], True)
        self.assertEqual(kwargs["totp_secret_key"], "JBSWY3DPEHPK3PXP")
        self.assertEqual(kwargs["username"], "user")
        mock_show_error.assert_not_called()

    @patch("src.main.requests.Session")
    @patch("src.main.create_secret")
    @patch("src.main.set_authentication")
    def test_main_passes_totp_settings(
        self,
        mock_set_authentication,
        mock_create_secret,
        mock_session_class,
    ):
        """main parses the TOTP inputs and hands them to create_secret."""
        mock_auth = MagicMock()
        mock_set_authentication.return_value = mock_auth

        with patch("src.main.USERNAME", "user"), patch(
            "src.main.TOTP_ENABLED", "true"
        ), patch("src.main.TOTP_SECRET_KEY", "JBSWY3DPEHPK3PXP"), patch(
            "builtins.print"
        ):
            main()

        mock_create_secret.assert_called_once_with(mock_auth, True, "JBSWY3DPEHPK3PXP")

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    @patch("src.main.set_authentication")
    def test_main_rejects_invalid_totp_before_authenticating(
        self, mock_set_authentication, mock_show_error
    ):
        """Invalid TOTP input fails the step before any API call is made."""
        with patch("src.main.USERNAME", "user"), patch(
            "src.main.TOTP_ENABLED", "true"
        ), patch("src.main.TOTP_SECRET_KEY", ""):
            with self.assertRaises(SystemExit):
                main()

        mock_set_authentication.assert_not_called()

    @patch("src.main.requests.Session")
    @patch("src.main.create_secret")
    @patch("src.main.set_authentication")
    def test_main_masks_inputs_before_authenticating(
        self,
        mock_set_authentication,
        mock_create_secret,
        mock_session_class,
    ):
        """The seed and password are masked before anything else runs."""
        events = []
        mock_set_authentication.side_effect = lambda _: events.append("auth") or (
            MagicMock()
        )

        with patch("src.main.USERNAME", "user"), patch(
            "src.main.PASSWORD", "p4ss"
        ), patch("src.main.TOTP_ENABLED", "true"), patch(
            "src.main.TOTP_SECRET_KEY", "JBSWY3DPEHPK3PXP"
        ), patch(
            "builtins.print", side_effect=lambda line: events.append(line)
        ):
            main()

        self.assertEqual(
            events,
            ["::add-mask ::p4ss", "::add-mask ::JBSWY3DPEHPK3PXP", "auth"],
        )


class TestParseOptionalBool(unittest.TestCase):
    """Tests for parse_optional_bool, used for the totp_enabled input."""

    def test_empty_is_omitted(self):
        """An empty input maps to None so the field is left out of the request."""
        self.assertIsNone(parse_optional_bool("", "totp_enabled"))

    def test_true_and_false_are_parsed(self):
        """'true' and 'false' are parsed case-insensitively."""
        for value, expected in (
            ("true", True),
            ("TRUE", True),
            ("false", False),
            ("False", False),
        ):
            with self.subTest(value=value):
                self.assertIs(parse_optional_bool(value, "totp_enabled"), expected)

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_other_values_are_rejected(self, mock_show_error):
        """Anything other than true/false/empty fails the step."""
        for value in ("yes", "1", "on", "tru"):
            with self.subTest(value=value):
                with self.assertRaises(SystemExit):
                    parse_optional_bool(value, "totp_enabled")
                self.assertIn("totp_enabled", mock_show_error.call_args[0][0])


class TestGetTotpSettings(unittest.TestCase):
    """Tests for get_totp_settings, which validates the TOTP inputs."""

    SEED = "JBSWY3DPEHPK3PXP"  # nosec B105 - test data

    def _settings(self, enabled="", seed="", username="user"):
        with patch("src.main.TOTP_ENABLED", enabled), patch(
            "src.main.TOTP_SECRET_KEY", seed
        ), patch("src.main.USERNAME", username):
            return get_totp_settings()

    def _assert_rejected(self, mock_show_error, **kwargs):
        with self.assertRaises(SystemExit):
            self._settings(**kwargs)
        message = mock_show_error.call_args[0][0]
        self.assertNotIn(self.SEED, message)
        return message

    def test_omitted_inputs(self):
        """Workflows without the TOTP inputs are unaffected."""
        self.assertEqual(self._settings(), (None, None))
        self.assertEqual(self._settings(username=""), (None, None))

    def test_enabled_with_seed(self):
        """totp_enabled=true with a seed is accepted."""
        self.assertEqual(self._settings("true", self.SEED), (True, self.SEED))

    def test_disabled_without_seed(self):
        """totp_enabled=false without a seed is accepted."""
        self.assertEqual(self._settings("false"), (False, None))

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_enabled_without_seed_is_rejected(self, mock_show_error):
        """A seed is required when TOTP is enabled."""
        message = self._assert_rejected(mock_show_error, enabled="true")
        self.assertIn("totp_secret_key is required", message)

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_seed_without_enabled_is_rejected(self, mock_show_error):
        """A seed is rejected unless totp_enabled is true."""
        for enabled in ("", "false"):
            with self.subTest(enabled=enabled):
                message = self._assert_rejected(
                    mock_show_error, enabled=enabled, seed=self.SEED
                )
                self.assertIn("only allowed when totp_enabled", message)

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_non_credential_secret_is_rejected(self, mock_show_error):
        """TOTP is only available for credential secrets."""
        message = self._assert_rejected(
            mock_show_error, enabled="true", seed=self.SEED, username=""
        )
        self.assertIn("only supported for credential secrets", message)


class TestMasking(unittest.TestCase):
    """Tests for masking the password and TOTP seed inputs."""

    @patch("builtins.print")
    def test_mask_secret_splits_lines_and_escapes(self, mock_print):
        """CR/LF cannot inject extra workflow commands, and '%' is escaped."""
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
    def test_nothing_masked_when_inputs_empty(self, mock_print):
        """Empty inputs emit no mask commands."""
        with patch("src.main.PASSWORD", ""), patch("src.main.TOTP_SECRET_KEY", ""):
            mask_sensitive_inputs()

        mock_print.assert_not_called()

    @patch("builtins.print")
    def test_otpauth_uri_and_embedded_seed_are_masked(self, mock_print):
        """Both the full otpauth:// URI and the seed inside it are masked."""
        uri = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example"

        with patch("src.main.PASSWORD", ""), patch("src.main.TOTP_SECRET_KEY", uri):
            mask_sensitive_inputs()

        self.assertEqual(
            [c.args[0] for c in mock_print.call_args_list],
            [f"::add-mask ::{uri}", "::add-mask ::JBSWY3DPEHPK3PXP"],
        )


class TestParseVerifyCA(unittest.TestCase):
    """
    Tests for parse_verify_ca, which accepts a CA bundle path so a private or
    internal CA can be trusted without disabling verification.
    """

    def test_true_when_unset(self):
        """An unset VERIFY_CA keeps verification enabled."""
        self.assertIs(parse_verify_ca(None), True)

    def test_true_when_empty_or_whitespace(self):
        """An empty or whitespace-only value keeps verification enabled."""
        for value in ("", "   "):
            with self.subTest(value=value):
                self.assertIs(parse_verify_ca(value), True)

    def test_all_enable_tokens_are_recognized(self):
        """Every affirmative token enables verification."""
        for token in ("true", "1", "yes", "on", "enable", "enabled", " TRUE "):
            with self.subTest(token=token):
                self.assertIs(parse_verify_ca(token), True)

    def test_all_disable_tokens_are_recognized(self):
        """Every negative token disables verification."""
        for token in ("false", "0", "no", "off", "disable", "disabled", " FALSE "):
            with self.subTest(token=token):
                self.assertIs(parse_verify_ca(token), False)

    def test_existing_bundle_file_is_passed_through(self):
        """A path to an existing bundle file is returned as-is."""
        with tempfile.NamedTemporaryFile(suffix=".crt") as bundle:
            self.assertEqual(parse_verify_ca(bundle.name), bundle.name)

    def test_existing_bundle_directory_is_passed_through(self):
        """A path to an existing bundle directory is returned as-is."""
        with tempfile.TemporaryDirectory() as bundle_dir:
            self.assertEqual(parse_verify_ca(bundle_dir), bundle_dir)

    def test_bundle_path_is_stripped(self):
        """Surrounding whitespace is trimmed from a bundle path."""
        with tempfile.NamedTemporaryFile(suffix=".crt") as bundle:
            self.assertEqual(parse_verify_ca(f"  {bundle.name}  "), bundle.name)

    def test_nonexistent_path_raises(self):
        """
        Fail closed: a mistyped bundle path must not silently fall back to
        certifi, which would not trust the CA the caller asked for.
        """
        with self.assertRaises(EnvironmentError) as ctx:
            parse_verify_ca("/no/such/ca-bundle.crt")

        self.assertIn("VERIFY_CA", str(ctx.exception))

    def test_unrecognized_value_raises(self):
        """An unrecognized value is rejected instead of defaulting to True."""
        with self.assertRaises(EnvironmentError):
            parse_verify_ca("maybe")


class TestConfigureCertificateVerification(unittest.TestCase):
    """
    Tests for configure_certificate_verification, which applies the setting to
    the session and reports the trust store actually in effect.
    """

    def _verify_true_log_message(self, env_overrides):
        """Return the message logged for verify_ca=True under env_overrides."""
        session = requests.Session()
        with patch.dict(os.environ, env_overrides, clear=True):
            with patch("src.main.utils.print_log") as print_log:
                configure_certificate_verification(session, True)
        return print_log.call_args[0][1]

    def test_session_verifies_against_bundle_path(self):
        """A bundle path is assigned to the session itself."""
        session = requests.Session()
        with tempfile.NamedTemporaryFile(suffix=".crt") as bundle:
            configure_certificate_verification(session, bundle.name)
            self.assertEqual(session.verify, bundle.name)

    def test_session_verify_defaults_to_true(self):
        """verify_ca=True leaves the session verifying against the default store."""
        session = requests.Session()
        configure_certificate_verification(session, True)
        self.assertIs(session.verify, True)

    def test_session_verify_disabled(self):
        """verify_ca=False disables verification on the session."""
        session = requests.Session()
        configure_certificate_verification(session, False)
        self.assertFalse(session.verify)

    def test_log_names_bundle_path(self):
        """The bundle path in effect is logged."""
        session = requests.Session()
        with tempfile.NamedTemporaryFile(suffix=".crt") as bundle:
            with patch("src.main.utils.print_log") as print_log:
                configure_certificate_verification(session, bundle.name)

            self.assertIn(bundle.name, print_log.call_args[0][1])

    def test_log_names_requests_ca_bundle_override(self):
        """
        requests silently honors REQUESTS_CA_BUNDLE when verify is True, so the
        log must name it instead of claiming certifi is in effect.
        """
        message = self._verify_true_log_message({"REQUESTS_CA_BUNDLE": "/tmp/req.crt"})

        self.assertIn("REQUESTS_CA_BUNDLE", message)
        self.assertIn("/tmp/req.crt", message)
        self.assertNotIn(requests.adapters.DEFAULT_CA_BUNDLE_PATH, message)

    def test_log_names_curl_ca_bundle_override(self):
        """CURL_CA_BUNDLE is honored by requests too, so it is reported."""
        message = self._verify_true_log_message({"CURL_CA_BUNDLE": "/tmp/curl.crt"})

        self.assertIn("CURL_CA_BUNDLE", message)
        self.assertIn("/tmp/curl.crt", message)

    def test_requests_ca_bundle_takes_precedence_over_curl(self):
        """REQUESTS_CA_BUNDLE wins when both overrides are set."""
        message = self._verify_true_log_message(
            {"REQUESTS_CA_BUNDLE": "/tmp/req.crt", "CURL_CA_BUNDLE": "/tmp/curl.crt"}
        )

        self.assertIn("/tmp/req.crt", message)
        self.assertNotIn("/tmp/curl.crt", message)

    def test_log_reports_certifi_when_no_override(self):
        """Without an override the certifi bundle path is reported."""
        message = self._verify_true_log_message({})

        self.assertIn("certifi", message)
        self.assertIn(requests.adapters.DEFAULT_CA_BUNDLE_PATH, message)
        self.assertIn("VERIFY_CA", message)


if __name__ == "__main__":
    unittest.main()

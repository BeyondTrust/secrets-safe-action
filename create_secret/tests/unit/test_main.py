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
    main,
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
        mock_create_secret.assert_called_once_with(mock_auth)
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

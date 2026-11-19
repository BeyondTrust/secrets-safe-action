import importlib
import os
import unittest
from unittest.mock import ANY, MagicMock, patch

import src.main as main_module
from secrets_safe_library.exceptions import CreationError, OptionsError
from src.main import (
    create_secret,
    get_folder,
    get_totp_settings,
    main,
    mask_sensitive_inputs,
    parse_optional_bool,
    set_authentication,
    validate_api_version,
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

    @patch("src.main.api_client.utils.prepare_certificate_info")
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

    @patch("src.main.api_client.utils.prepare_certificate_info")
    @patch("src.main.authentication.Authentication", autospec=True)
    def test_set_authentication_with_client_credentials(
        self,
        mock_auth_class,
        mock_prepare_cert,
    ):
        """
        Verify that set_authentication falls back to OAuth client
        credentials authentication when API_KEY is not provided.
        """
        session = MagicMock()

        mock_prepare_cert.return_value = ("cert", "key")

        mock_auth_instance = mock_auth_class.return_value
        mock_auth_instance.get_api_access.return_value.status_code = 200

        with patch("src.main.API_KEY", None), patch(
            "src.main.CLIENT_ID", "client-id"
        ), patch("src.main.CLIENT_SECRET", "client-secret"):

            auth = set_authentication(session)

        self.assertEqual(auth, mock_auth_instance)
        kwargs = mock_auth_class.call_args.kwargs
        self.assertEqual(kwargs["client_id"], "client-id")
        self.assertEqual(kwargs["client_secret"], "client-secret")
        self.assertNotIn("api_key", kwargs)

    @patch("src.main.api_client.create_session")
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
    @patch("src.main.api_client.create_session")
    @patch("src.main.create_secret")
    @patch("src.main.set_authentication")
    def test_main_signs_out_when_create_secret_fails(
        self,
        mock_set_authentication,
        mock_create_secret,
        mock_session_class,
        mock_show_error,
    ):
        """main signs out even when create_secret exits through show_error."""
        mock_session_class.return_value.__enter__.return_value = MagicMock()
        mock_auth = MagicMock()
        mock_set_authentication.return_value = mock_auth
        mock_create_secret.side_effect = SystemExit(1)

        with self.assertRaises(SystemExit):
            main()

        mock_auth.sign_app_out.assert_called_once()
        mock_show_error.assert_not_called()

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
        seen = {}

        def read_file(**kwargs):
            with open(kwargs["file_path"], encoding="utf-8") as f:
                seen["content"] = f.read()

        mock_secrets_safe_obj.create_secret.side_effect = read_file

        with patch("src.main.TITLE", "TestSecret"), patch(
            "src.main.PARENT_FOLDER_NAME", "TestFolder"
        ), patch("src.main.DESCRIPTION", "Test Description"), patch(
            "src.main.FILE_CONTENT", "secret content"
        ), patch(
            "src.main.FILE_NAME", "secret.txt"
        ):

            create_secret(mock_auth)

        # The file is written to a temporary directory outside the workspace,
        # uploaded under file_name, and removed afterwards.
        file_path = mock_secrets_safe_obj.create_secret.call_args.kwargs["file_path"]
        self.assertEqual(seen["content"], "secret content")
        self.assertEqual(os.path.basename(file_path), "secret.txt")
        self.assertNotEqual(os.path.dirname(file_path), os.getcwd())
        self.assertFalse(os.path.exists(file_path))
        mock_secrets_safe_obj.create_secret.assert_called_once_with(
            title="TestSecret",
            folder_id=123,
            description="Test Description",
            username="",
            password="",
            text="",
            file_path=ANY,
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

    @patch("src.main.api_client.create_session")
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
            "src.main.API_VERSION", "3.3"
        ), patch(
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

    @patch("src.main.api_client.create_session")
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
            "src.main.API_VERSION", "3.3"
        ), patch(
            "builtins.print", side_effect=lambda line: events.append(line)
        ):
            main()

        self.assertEqual(
            events,
            ["::add-mask ::p4ss", "::add-mask ::JBSWY3DPEHPK3PXP", "auth"],
        )

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    @patch("src.main.secrets_safe.SecretsSafe", autospec=True)
    @patch("src.main.get_folder", return_value={"Id": 123, "Name": "TestFolder"})
    @patch("src.main.folders.Folder", autospec=True)
    def test_create_secret_rejects_file_name_outside_temp_dir(
        self, _mock_folder, _mock_get_folder, mock_secrets_safe_class, mock_show_error
    ):
        """A file_name that escapes the temporary directory fails the step."""
        with patch("src.main.FILE_CONTENT", "c"), patch(
            "src.main.FILE_NAME", "../secret.txt"
        ), self.assertRaises(SystemExit):
            create_secret(MagicMock())

        self.assertIn("Invalid file_name", mock_show_error.call_args[0][0])
        mock_secrets_safe_class.return_value.create_secret.assert_not_called()


class TestApiVersion(unittest.TestCase):
    """Tests for the api_version default and validate_api_version."""

    def test_empty_api_version_defaults_to_3_0(self):
        self.addCleanup(importlib.reload, main_module)
        with patch.dict(os.environ, {"API_VERSION": ""}):
            importlib.reload(main_module)
        self.assertEqual(main_module.API_VERSION, "3.0")

    def test_supported_versions_are_accepted(self):
        for version in ("3.0", "3.1", "3.2", "3.3"):
            with self.subTest(version=version), patch("src.main.API_VERSION", version):
                validate_api_version(None)

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    def test_rejected_versions(self, mock_show_error):
        cases = (
            ("2.0", None, "Unsupported api_version"),
            ("3.1", True, "totp_enabled requires api_version 3.3"),
            ("3.0", False, "totp_enabled requires api_version 3.3"),
        )
        for version, totp_enabled, message in cases:
            with self.subTest(version=version), patch("src.main.API_VERSION", version):
                with self.assertRaises(SystemExit):
                    validate_api_version(totp_enabled)
                self.assertIn(message, mock_show_error.call_args[0][0])

    @patch("src.main.common.show_error", side_effect=SystemExit(1))
    @patch("src.main.set_authentication")
    def test_main_rejects_totp_below_3_3_before_authenticating(
        self, mock_set_authentication, mock_show_error
    ):
        with patch("src.main.USERNAME", "user"), patch(
            "src.main.TOTP_ENABLED", "true"
        ), patch("src.main.TOTP_SECRET_KEY", "JBSWY3DPEHPK3PXP"), patch(
            "src.main.API_VERSION", "3.0"
        ), patch(
            "builtins.print"
        ), self.assertRaises(
            SystemExit
        ):
            main()

        mock_set_authentication.assert_not_called()


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
    """Tests for masking the password, text, file content and TOTP inputs."""

    @patch("builtins.print")
    def test_text_and_file_content_are_masked(self, mock_print):
        with patch("src.main.PASSWORD", ""), patch("src.main.TEXT", "t3xt"), patch(
            "src.main.FILE_CONTENT", "f1le"
        ), patch("src.main.TOTP_SECRET_KEY", ""):
            mask_sensitive_inputs()

        self.assertEqual(
            [c.args[0] for c in mock_print.call_args_list],
            ["::add-mask ::t3xt", "::add-mask ::f1le"],
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


if __name__ == "__main__":
    unittest.main()

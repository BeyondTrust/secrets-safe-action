"""Unit tests for Main module"""

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, call, patch

from src import main


@patch("src.main.API_URL", "https://example.com/BeyondTrust/api/public/v3")
@patch("src.main.CLIENT_ID", "456126543212456126543212456126543212")
@patch("src.main.CLIENT_SECRET", "123321654234123321654234123321654234")
@patch("src.main.SECRET_PATH", '{"path":"folder_name/title","output_id":"title"}')
@patch(
    "src.main.MANAGED_ACCOUNT_PATH",
    '{"path":"system_name/managed_account_name","output_id":"managed_account_name"}',
)
class TestMain(unittest.TestCase):
    """
    Test for Main module
    """

    def setUp(self):
        """Set up test fixtures"""
        self.temp_file = tempfile.NamedTemporaryFile(mode="w", delete=False)
        self.temp_file.close()

    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)

    @patch("src.main.append_output")
    @patch("src.main.managed_account.ManagedAccount.get_secret")
    @patch("src.main.secrets_safe.SecretsSafe.get_secret")
    @patch("src.main.authentication.Authentication.get_api_access")
    def test_main(
        self,
        get_api_access_mock,
        secrets_safe_get_secret_mock,
        managed_account_get_secret_mock,
        append_output_mock,
    ):
        """
        Test main method, Success case
        """

        mock = MagicMock()
        mock.status_code = 200
        get_api_access_mock.return_value = mock

        secrets_safe_get_secret_mock.return_value = "test_secret"
        managed_account_get_secret_mock.return_value = "test_managed_account"
        append_output_mock.return_value = None

        main.main()

        main.append_output.assert_has_calls(
            [
                call("title", "test_secret"),
                call("managed_account_name", "test_managed_account"),
            ]
        )

    def test_append_output(self):
        """Test append_output function"""
        with patch.dict(os.environ, {"GITHUB_OUTPUT": self.temp_file.name}):
            main.append_output("test_name", "test_value")

        with open(self.temp_file.name, "r") as f:
            content = f.read()

        # Check that the output contains the expected format
        self.assertIn("test_name<<", content)
        self.assertIn("test_value", content)

    @patch("builtins.print")
    def test_mask_secret_single_line(self, mock_print):
        """Test mask_secret function with single line secret"""
        main.mask_secret("add-mask", "single_line_secret")
        mock_print.assert_called_once_with("::add-mask ::single_line_secret")

    @patch("builtins.print")
    def test_mask_secret_multiple_lines(self, mock_print):
        """Test mask_secret function with multi-line secret"""
        secret = "line1\nline2\nline3"  # noqa: S105 # nosec B105 - test data
        main.mask_secret("add-mask", secret)

        expected_calls = [
            call("::add-mask ::line1"),
            call("::add-mask ::line2"),
            call("::add-mask ::line3"),
        ]
        mock_print.assert_has_calls(expected_calls)

    @patch("builtins.print")
    def test_mask_secret_with_empty_lines(self, mock_print):
        """Test mask_secret function with empty lines in secret"""
        secret = "line1\n\nline3\n"  # noqa: S105 # nosec B105 - test data
        main.mask_secret("add-mask", secret)

        # Should only print non-empty lines
        expected_calls = [call("::add-mask ::line1"), call("::add-mask ::line3")]
        mock_print.assert_has_calls(expected_calls)

    @patch("builtins.print")
    def test_mask_secret_carriage_return_injection(self, mock_print):
        """Carriage returns must not let a secret inject extra workflow commands.

        The GitHub Actions runner treats a bare '\\r' as a line terminator, so a
        value such as 'x\\r::stop-commands::z9q' could otherwise be parsed as two
        separate stdout lines. Each runner-recognised line terminator (CR, LF,
        CRLF) must be split and any residual CR escaped.
        """
        secret = "x\r::stop-commands::z9q"  # noqa: S105 # nosec B105 - test data
        main.mask_secret("add-mask", secret)

        # Split on CR -> two non-empty segments, neither emits a raw '\r' that
        # the runner could parse as a second line / fresh command.
        expected_calls = [
            call("::add-mask ::x"),
            call("::add-mask ::::stop-commands::z9q"),
        ]
        mock_print.assert_has_calls(expected_calls)
        for printed in mock_print.call_args_list:
            self.assertNotIn("\r", printed.args[0])
            self.assertNotIn("\n", printed.args[0])

    @patch("builtins.print")
    def test_mask_secret_crlf_split(self, mock_print):
        """CRLF line endings should produce one masked segment per line."""
        secret = "line1\r\nline2"  # noqa: S105 # nosec B105 - test data
        main.mask_secret("add-mask", secret)

        expected_calls = [call("::add-mask ::line1"), call("::add-mask ::line2")]
        mock_print.assert_has_calls(expected_calls)

    @patch("builtins.print")
    def test_mask_secret_escapes_percent(self, mock_print):
        """Percent characters are escaped consistently with @actions/core."""
        secret = "50%off"  # noqa: S105 # nosec B105 - test data
        main.mask_secret("add-mask", secret)
        mock_print.assert_called_once_with("::add-mask ::50%25off")

    @patch("src.main.common.show_error")
    def test_get_secrets_json_decode_error(self, mock_show_error):
        """Test get_secrets with JSON decode error"""
        # Mock show_error to raise SystemExit to simulate sys.exit(1)
        mock_show_error.side_effect = SystemExit(1)

        secret_obj = MagicMock()
        invalid_json = "invalid json string"

        with self.assertRaises(SystemExit):
            main.get_secrets(secret_obj, invalid_json)

        mock_show_error.assert_called_once()
        # Check that it was called with a JSON error message
        args, _ = mock_show_error.call_args
        self.assertIn(
            "Invalid JSON input: Expecting " "value: line 1 column 1 (char 0)", args[0]
        )

    @patch("src.main.common.show_error")
    def test_get_secrets_type_error(self, mock_show_error):
        """Test get_secrets with TypeError"""
        # Mock show_error to raise SystemExit to simulate sys.exit(1)
        mock_show_error.side_effect = SystemExit(1)

        secret_obj = MagicMock()

        with self.assertRaises(SystemExit):
            main.get_secrets(secret_obj, None)

        mock_show_error.assert_called_once()
        args, _ = mock_show_error.call_args
        self.assertIn(
            "Invalid JSON input: the JSON object must be str, "
            "bytes or bytearray, not NoneType",
            args[0],
        )

    @patch("src.main.common.show_error")
    def test_get_secrets_non_dict_entry(self, mock_show_error):
        """Test get_secrets rejects list entries that are not dicts"""
        mock_show_error.side_effect = SystemExit(1)

        secret_obj = MagicMock()
        secrets_json = json.dumps([123])

        with self.assertRaises(SystemExit):
            main.get_secrets(secret_obj, secrets_json)

        mock_show_error.assert_called_once()
        args, _ = mock_show_error.call_args
        self.assertIn("each secret entry must be a JSON object", args[0])
        secret_obj.get_secret.assert_not_called()

    @patch("src.main.common.show_error")
    def test_get_secrets_max_secrets_exceeded(self, mock_show_error):
        """Test get_secrets with too many secrets"""
        # Mock show_error to raise SystemExit to simulate sys.exit(1)
        mock_show_error.side_effect = SystemExit(1)

        secret_obj = MagicMock()
        # Create more than MAX_SECRETS_TO_RETRIEVE (20) secrets
        secrets_list = [{"path": f"path{i}", "output_id": f"id{i}"} for i in range(25)]
        secrets_json = json.dumps(secrets_list)

        with self.assertRaises(SystemExit):
            main.get_secrets(secret_obj, secrets_json)

        mock_show_error.assert_called_once()
        args, _ = mock_show_error.call_args
        self.assertIn("maximum of 20 secrets", args[0])

    @patch("src.main.common.show_error")
    def test_get_secrets_missing_path(self, mock_show_error):
        """Test get_secrets with missing path attribute"""
        # Mock show_error to raise SystemExit to simulate sys.exit(1)
        mock_show_error.side_effect = SystemExit(1)

        secret_obj = MagicMock()
        secret_without_path = {"output_id": "test_id"}
        secrets_json = json.dumps(secret_without_path)

        with self.assertRaises(SystemExit):
            main.get_secrets(secret_obj, secrets_json)

        mock_show_error.assert_called_once()
        args, _ = mock_show_error.call_args
        self.assertIn("validate path attribute name", args[0])

    @patch("src.main.common.show_error")
    def test_get_secrets_missing_output_id(self, mock_show_error):
        """Test get_secrets with missing output_id attribute"""
        # Mock show_error to raise SystemExit to simulate sys.exit(1)
        mock_show_error.side_effect = SystemExit(1)

        secret_obj = MagicMock()
        secret_without_output_id = {"path": "test_path"}
        secrets_json = json.dumps(secret_without_output_id)

        with self.assertRaises(SystemExit):
            main.get_secrets(secret_obj, secrets_json)

        mock_show_error.assert_called_once()
        args, _ = mock_show_error.call_args
        self.assertIn("validate output_id attribute name", args[0])

    @patch("src.main.common.show_error")
    @patch("src.main.append_output")
    def test_get_secrets_invalid_output_id_with_newline(self, mock_append, mock_show_error):
        """Test get_secrets rejects output_id containing a newline (injection attempt)"""
        mock_show_error.side_effect = SystemExit(1)
        secret_obj = MagicMock()
        secret_obj.get_secret.return_value = "test_secret"

        malicious_secret = {
            "path": "test_path",
            "output_id": "valid_id\nINJECTED=value",  # noqa: S105 # nosec B105
        }
        secrets_json = json.dumps(malicious_secret)

        with self.assertRaises(SystemExit):
            main.get_secrets(secret_obj, secrets_json)

        mock_show_error.assert_called_once()
        args, _ = mock_show_error.call_args
        self.assertIn("Invalid output_id", args[0])
        secret_obj.get_secret.assert_not_called()
        mock_append.assert_not_called()

    @patch("src.main.common.show_error")
    @patch("src.main.append_output")
    def test_get_secrets_invalid_output_id_trailing_newline(self, mock_append, mock_show_error):
        """Test get_secrets rejects output_id with a trailing newline (regex $ bypass)"""
        mock_show_error.side_effect = SystemExit(1)
        secret_obj = MagicMock()
        secret_obj.get_secret.return_value = "test_secret"

        trailing_newline_secret = {
            "path": "test_path",
            "output_id": "valid_id\n",  # noqa: S105 # nosec B105
        }
        secrets_json = json.dumps(trailing_newline_secret)

        with self.assertRaises(SystemExit):
            main.get_secrets(secret_obj, secrets_json)

        mock_show_error.assert_called_once()
        args, _ = mock_show_error.call_args
        self.assertIn("Invalid output_id", args[0])
        secret_obj.get_secret.assert_not_called()
        mock_append.assert_not_called()

    @patch("src.main.common.show_error")
    @patch("src.main.append_output")
    def test_get_secrets_invalid_output_id_special_chars(self, mock_append, mock_show_error):
        """Test get_secrets rejects output_id with disallowed special characters"""
        mock_show_error.side_effect = SystemExit(1)
        secret_obj = MagicMock()
        secret_obj.get_secret.return_value = "test_secret"

        invalid_secret = {"path": "test_path", "output_id": "invalid id!"}
        secrets_json = json.dumps(invalid_secret)

        with self.assertRaises(SystemExit):
            main.get_secrets(secret_obj, secrets_json)

        mock_show_error.assert_called_once()
        args, _ = mock_show_error.call_args
        self.assertIn("Invalid output_id", args[0])
        secret_obj.get_secret.assert_not_called()
        mock_append.assert_not_called()

    @patch("src.main.common.show_error")
    @patch("src.main.append_output")
    def test_get_secrets_invalid_output_id_non_string(self, mock_append, mock_show_error):
        """Test get_secrets rejects non-string output_id (e.g., null, number)"""
        mock_show_error.side_effect = SystemExit(1)
        secret_obj = MagicMock()

        invalid_secret = {"path": "test_path", "output_id": None}
        secrets_json = json.dumps(invalid_secret)

        with self.assertRaises(SystemExit):
            main.get_secrets(secret_obj, secrets_json)

        mock_show_error.assert_called_once()
        args, _ = mock_show_error.call_args
        self.assertIn("Invalid output_id", args[0])
        secret_obj.get_secret.assert_not_called()
        mock_append.assert_not_called()

    @patch("src.main.append_output")
    @patch("src.main.mask_secret")
    def test_get_secrets_single_secret_as_dict(self, mock_mask, mock_append):
        """Test get_secrets with single secret as dict (not list)"""
        secret_obj = MagicMock()
        secret_obj.get_secret.return_value = "test_secret_value"

        single_secret = {"path": "test_path", "output_id": "test_id"}
        secrets_json = json.dumps(single_secret)

        main.get_secrets(secret_obj, secrets_json)

        secret_obj.get_secret.assert_called_once_with("test_path")
        mock_mask.assert_called_once_with("add-mask", "test_secret_value")
        mock_append.assert_called_once_with("test_id", "test_secret_value")

    @patch("src.main.append_output")
    @patch("src.main.mask_secret")
    def test_get_secrets_multiple_secrets(self, mock_mask, mock_append):
        """Test get_secrets with multiple secrets"""
        secret_obj = MagicMock()
        secret_obj.get_secret.side_effect = ["secret1", "secret2"]

        secrets_list = [
            {"path": "path1", "output_id": "id1"},
            {"path": "path2", "output_id": "id2"},
        ]
        secrets_json = json.dumps(secrets_list)

        main.get_secrets(secret_obj, secrets_json)

        self.assertEqual(secret_obj.get_secret.call_count, 2)
        secret_obj.get_secret.assert_any_call("path1")
        secret_obj.get_secret.assert_any_call("path2")

        mock_mask.assert_any_call("add-mask", "secret1")
        mock_mask.assert_any_call("add-mask", "secret2")

        mock_append.assert_any_call("id1", "secret1")
        mock_append.assert_any_call("id2", "secret2")

    @patch("src.main.common.show_error")
    @patch("src.main.authentication.Authentication.get_api_access")
    def test_main_auth_failure(self, mock_get_api_access, mock_show_error):
        """Test main function with authentication failure"""
        # Mock show_error to raise SystemExit to simulate sys.exit(1)
        mock_show_error.side_effect = SystemExit(1)

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_get_api_access.return_value = mock_response

        with self.assertRaises(SystemExit):
            main.main()

        mock_show_error.assert_called()
        # Get the first call (auth failure)
        args, _ = mock_show_error.call_args_list[0]
        self.assertIn("Please check credentials", args[0])

    @patch("src.main.common.show_error")
    def test_main_exception_handling(self, mock_show_error):
        """Test main function exception handling"""
        # Mock show_error to raise SystemExit to simulate sys.exit(1)
        mock_show_error.side_effect = SystemExit(1)

        with patch("src.main.requests.Session") as mock_session:
            mock_session.side_effect = Exception("Test exception")

            with self.assertRaises(SystemExit):
                main.main()

            mock_show_error.assert_called_once()

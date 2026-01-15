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

    @patch("src.main.common.show_error")
    def test_get_secrets_json_decode_error(
        self, mock_show_error
    ):
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
        self.assertIn("Invalid JSON input: Expecting "
                      "value: line 1 column 1 (char 0)", args[0])

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
        self.assertIn("Invalid JSON input: the JSON object must be str, "
                      "bytes or bytearray, not NoneType", args[0])

    @patch("src.main.common.show_error")
    def test_get_secrets_max_secrets_exceeded(
        self, mock_show_error
    ):
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
    def test_get_secrets_missing_output_id(
        self, mock_show_error
    ):
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

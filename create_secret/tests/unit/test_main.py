import unittest
from unittest.mock import MagicMock, patch

from src.main import get_folder, main, set_authentication


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

    @patch("src.main.retry")
    @patch("src.main.utils.prepare_certificate_info")
    @patch("src.main.authentication.Authentication")
    def test_set_authentication_with_api_key(
        self,
        mock_auth_class,
        mock_prepare_cert,
        mock_retry,
    ):
        """
        Verify that set_authentication uses API Key authentication
        when the API_KEY environment variable is present.
        """
        session = MagicMock()

        mock_retry.return_value = "req"
        mock_prepare_cert.return_value = ("cert", "key")

        mock_auth_instance = MagicMock()
        mock_auth_instance.get_api_access.return_value.status_code = 200
        mock_auth_class.return_value = mock_auth_instance

        with patch("src.main.API_KEY", "my-api-key"), patch(
            "src.main.API_VERSION", None
        ):

            auth = set_authentication(session)

        mock_retry.assert_called_once()
        mock_prepare_cert.assert_called_once()
        mock_auth_class.assert_called_once()
        self.assertEqual(auth, mock_auth_instance)

    @patch("src.main.retry")
    @patch("src.main.utils.prepare_certificate_info")
    @patch("src.main.authentication.Authentication")
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

        mock_auth_instance = MagicMock()
        mock_auth_instance.get_api_access.return_value.status_code = 200
        mock_auth_class.return_value = mock_auth_instance

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

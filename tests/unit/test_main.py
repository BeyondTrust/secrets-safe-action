"""Unit tests for Main module"""
import sys
import os
sys.path.append("src")

import unittest
from unittest.mock import MagicMock, patch, call

from src import main

@patch('src.main.API_URL', "https://example.com/Beyondtrust/api/public/v3")
@patch('src.main.CLIENT_ID', "45612654321")
@patch('src.main.CLIENT_SECRET', "123321654")
@patch('src.main.SECRET_PATH', '{"path":"folder_name/title","output_id":"title"}')
@patch('src.main.MANAGED_ACCOUNT_PATH', '{"path":"system_name/managed_account_name","output_id":"managed_account_name"}')


class TestMain(unittest.TestCase):
    """
    Test for Main module
    """
    
    @patch('src.main.append_output')
    @patch('src.main.managed_account.ManagedAccount.get_secret')
    @patch('src.main.secrets_safe.SecretsSafe.get_secret')
    @patch('src.main.authentication.Authentication.get_api_access')
    def test_main(self, get_api_access_mock, secrets_safe_get_secret_mock, managed_account_get_secret_mock, append_output_mock):
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
        
        main.append_output.assert_has_calls([
            call("title", "test_secret"),
            call("managed_account_name", "test_managed_account"),
        ])

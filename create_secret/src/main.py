"""
GitHub Action entrypoint for creating secrets in BeyondTrust Secrets Safe.

This module is responsible for:
- Reading configuration and secret inputs from environment variables
- Authenticating against the Secrets Safe API
- Locating parent folders
- Creating secrets of type CREDENTIAL, TEXT, or FILE
- Handling errors and logging
"""

import json
import logging
import os
from typing import Any, Dict, Optional

import requests
import secrets_safe_library
from requests.adapters import HTTPAdapter
from secrets_safe_library import (
    authentication,
    exceptions,
    folders,
    secrets_safe,
    utils,
)
from secrets_safe_library.integrations.github_actions.common_utils import common
from urllib3.util.retry import Retry

env = os.environ

# config data
API_KEY = env.get("API_KEY")
CLIENT_ID = env.get("CLIENT_ID")
CLIENT_SECRET = env.get("CLIENT_SECRET")
API_URL = env.get("API_URL")
API_VERSION = env.get("API_VERSION")
VERIFY_CA = env.get("VERIFY_CA", "true").lower() != "false"
TIMEOUT_CONNECTION_SECONDS = 30
TIMEOUT_REQUEST_SECONDS = 30
CERTIFICATE = env.get("CERTIFICATE", "").replace(r"\n", "\n")
CERTIFICATE_KEY = env.get("CERTIFICATE_KEY", "").replace(r"\n", "\n")

# secret data
TITLE = env.get("INPUT_SECRET_TITLE", "").strip()
PARENT_FOLDER_NAME = env.get("INPUT_PARENT_FOLDER_NAME", "").strip()
DESCRIPTION = env.get("INPUT_SECRET_DESCRIPTION", "").strip()
USERNAME = env.get("INPUT_USERNAME", "").strip()
PASSWORD = env.get("INPUT_PASSWORD", "").strip()
TEXT = env.get("INPUT_TEXT", "").strip()
FILE_CONTENT = env.get("INPUT_FILE_CONTENT", "").strip()
FILE_NAME = env.get("INPUT_FILE_NAME", "").strip()
OWNER_ID = env.get("INPUT_OWNER_ID", "").strip()
OWNER_TYPE = env.get("INPUT_OWNER_TYPE", "").strip()
OWNERS = json.loads(env.get("INPUT_OWNERS", "[]"))
PASSWORD_RULE_ID = env.get("INPUT_PASSWORD_RULE_ID", "").strip()
NOTES = env.get("INPUT_NOTES", "").strip()
URLS = env.get("INPUT_URLS", "")

LOG_LEVEL = env.get("LOG_LEVEL", "INFO").strip().upper()

LOG_LEVELS = {
    "CRITICAL": 50,
    "FATAL": 50,
    "ERROR": 40,
    "WARNING": 30,
    "WARN": 30,
    "INFO": 20,
    "DEBUG": 10,
    "NOTSET": 0,
}

LOGGER_NAME = "custom_logger"

logging.basicConfig(
    format="%(asctime)-5s %(name)-15s %(levelname)-8s %(message)s",
    level=LOG_LEVELS[LOG_LEVEL],
)

logger = logging.getLogger(LOGGER_NAME)


def get_folder(
    folders_obj: folders.Folder,
    folder_name: str,
) -> Optional[Dict[str, Any]]:
    """
    Retrieve a folder by its name.

    Args:
        folders_obj (folders.Folder): Instance of the Folders client used
            to interact with the Secrets Safe folders API.
        folder_name (str): Name of the folder to search for.

    Returns:
        Optional[Dict[str, Any]]: Folder dictionary if found, otherwise None.
    """
    folder_list = folders_obj.list_folders(folder_name=folder_name)
    matched_folders = [x for x in folder_list if x["Name"] == folder_name]

    if not matched_folders:
        return None

    return matched_folders[0]


def create_secret(
    authentication_obj: authentication.Authentication,
) -> None:
    """
    Create a secret in Secrets Safe.

    This function resolves the parent folder, optionally creates a file,
    and creates a secret using the Secrets Safe API. It also handles
    common errors related to secret creation.

    Args:
        authentication_obj (authentication.Authentication): Authenticated
            Secrets Safe client instance.
    """
    # instantiate folders obj
    folders_obj = folders.Folder(authentication=authentication_obj, logger=logger)

    logger.info("Creating secret")

    # getting parent folder
    folder = get_folder(folders_obj, PARENT_FOLDER_NAME)
    if not folder:
        common.show_error("Parent Folder name was not found", logger)

    logger.info("Parent folder found")

    secrets_safe_obj = secrets_safe.SecretsSafe(
        authentication=authentication_obj,
        logger=logger,
    )

    # creating file if file content is provided
    if FILE_CONTENT:
        common.create_file(FILE_NAME, FILE_CONTENT, logger)

    try:
        # creating secret
        secrets_safe_obj.create_secret(
            title=TITLE,
            folder_id=folder["Id"],
            description=DESCRIPTION,
            username=USERNAME,
            password=PASSWORD,
            text=TEXT,
            file_path=FILE_NAME,
            owner_id=int(OWNER_ID) if OWNER_ID else None,
            owner_type=OWNER_TYPE,
            owners=OWNERS,
            password_rule_id=int(PASSWORD_RULE_ID) if PASSWORD_RULE_ID else None,
            notes=NOTES,
            urls=json.loads(URLS) if URLS else None,
        )

        logger.info("Secret created successfully")
    except exceptions.CreationError as e:
        common.show_error(f"Error creating secret: {e}", logger)

    except (exceptions.OptionsError, exceptions.IncompleteArgumentsError) as e:
        common.show_error(f"Invalid or missing parameters: {e}", logger)

    except FileNotFoundError as e:
        common.show_error(f"Invalid or missing file path: {e}", logger)


def set_authentication(
    session: requests.Session,
) -> authentication.Authentication:
    """
    Configure and authenticate against the Secrets Safe API.

    This function applies retry logic, prepares certificates, selects
    the authentication method (API Key or OAuth client credentials),
    and validates API access.

    Args:
        session (requests.Session): Requests session used for HTTP calls.

    Returns:
        authentication.Authentication: Authenticated Secrets Safe client.
    """

    certificate, certificate_key = utils.prepare_certificate_info(
        CERTIFICATE, CERTIFICATE_KEY
    )

    auth_config = {
        "req": session,
        "timeout_connection": TIMEOUT_CONNECTION_SECONDS,
        "timeout_request": TIMEOUT_REQUEST_SECONDS,
        "api_url": API_URL,
        "certificate": certificate,
        "certificate_key": certificate_key,
        "verify_ca": VERIFY_CA,
        "logger": logger,
    }

    # The recommended version is 3.1. If no version is specified,
    # the default API version 3.0 will be used
    if API_VERSION:
        auth_config.update({"api_version": API_VERSION})

    # If API_KEY is set, we're using API Key authentication
    # otherwise we're using OAuth/Client Credentials.
    if API_KEY:
        auth_config.update({"api_key": API_KEY})
    else:
        auth_config.update({"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET})

    authentication_obj = authentication.Authentication(**auth_config)
    get_api_access_response = authentication_obj.get_api_access()

    utils.print_log(
        logger,
        f"{secrets_safe_library.__library_name__} "
        f"version: {secrets_safe_library.__version__}",
        logging.DEBUG,
    )
    if get_api_access_response.status_code != 200:
        error_message = (
            f"Please check credentials, error {get_api_access_response.text}"
        )
        common.show_error(error_message, logger)

    return authentication_obj


def main() -> None:
    """
    Main entrypoint for the GitHub Action.

    Orchestrates the workflow to authenticate, create a secret,
    and properly close the API session.
    """
    try:
        with requests.Session() as session:
            retry_strategy = Retry(
                total=3,
                backoff_factor=0.2,
                status_forcelist=[400, 408, 500, 502, 503, 504],
                allowed_methods=["GET", "POST"],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("https://", adapter)
            session.mount("http://", adapter)

            authentication_obj = set_authentication(session)
            create_secret(authentication_obj)
            authentication_obj.sign_app_out()

    except Exception as e:
        common.show_error(f"An unexpected error occurred: {e}", logger)


if __name__ == "__main__":
    main()

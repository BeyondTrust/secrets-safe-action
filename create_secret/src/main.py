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
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

import requests
from secrets_safe_library import authentication, exceptions, folders, secrets_safe
from secrets_safe_library.integrations.github_actions.common_utils import (
    api_client,
    common,
    outputs,
    tls,
)

env = os.environ

# config data
API_KEY = env.get("API_KEY")
CLIENT_ID = env.get("CLIENT_ID")
CLIENT_SECRET = env.get("CLIENT_SECRET")
API_URL = env.get("API_URL")
API_VERSION = env.get("API_VERSION")
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
PASSWORD_RULE_ID = env.get("INPUT_PASSWORD_RULE_ID", "").strip()
NOTES = env.get("INPUT_NOTES", "").strip()
OWNERS = env.get("INPUT_OWNERS", "")
URLS = env.get("INPUT_URLS", "")
TOTP_ENABLED = env.get("INPUT_TOTP_ENABLED", "").strip()
TOTP_SECRET_KEY = env.get("INPUT_TOTP_SECRET_KEY", "").strip()


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

try:
    VERIFY_CA = tls.parse_verify_ca(env.get("VERIFY_CA"))
except EnvironmentError as verify_ca_error:
    common.show_error(str(verify_ca_error), logger)


def mask_sensitive_inputs() -> None:
    """
    Mask the password and TOTP seed inputs before anything else is logged.

    When the seed is an otpauth:// URI, the seed carried in its "secret" query
    parameter is masked on its own too, so it stays hidden if it is ever
    printed without the rest of the URI.
    """

    for value in (PASSWORD, TOTP_SECRET_KEY):
        if value:
            outputs.mask_secret(value)

    if TOTP_SECRET_KEY.lower().startswith("otpauth://"):
        query = parse_qs(urlsplit(TOTP_SECRET_KEY).query)
        for seed in query.get("secret", []):
            outputs.mask_secret(seed)


def parse_optional_bool(value: str, input_name: str) -> Optional[bool]:
    """
    Parse an optional boolean action input.

    Args:
        value (str): Raw input value.
        input_name (str): Input name, used in the error message.

    Returns:
        Optional[bool]: None when the input is empty (omitted), otherwise True
        or False for "true" or "false" (case-insensitive). Any other value
        fails the step.
    """

    if not value:
        return None

    normalized = value.lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False

    common.show_error(
        f"Invalid value for {input_name}: {value!r}. Use 'true', 'false', or "
        "leave it empty.",
        logger,
    )


def get_totp_settings() -> Tuple[Optional[bool], Optional[str]]:
    """
    Parse and validate the TOTP inputs.

    TOTP is only available for credential secrets. A seed is required when
    totp_enabled is true and is rejected otherwise, matching the server rules.
    Error messages never include the seed.

    Returns:
        Tuple[Optional[bool], Optional[str]]: (totp_enabled, totp_secret_key),
        with None for each input that was left empty.
    """

    totp_enabled = parse_optional_bool(TOTP_ENABLED, "totp_enabled")
    totp_secret_key = TOTP_SECRET_KEY or None

    if totp_enabled is None and totp_secret_key is None:
        return None, None

    if not USERNAME:
        common.show_error(
            "totp_enabled and totp_secret_key are only supported for credential "
            "secrets. Set username (and password) to create a credential secret.",
            logger,
        )

    if totp_enabled and not totp_secret_key:
        common.show_error(
            "totp_secret_key is required when totp_enabled is 'true'.", logger
        )

    if totp_secret_key and not totp_enabled:
        common.show_error(
            "totp_secret_key is only allowed when totp_enabled is 'true'.", logger
        )

    return totp_enabled, totp_secret_key


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


def parse_json_parameters():
    """
    Parse JSON parameters for owners and URLs with error handling.

    Returns:
        tuple: A tuple containing (owners_list, urls_list)
    """
    try:
        owners_list = json.loads(OWNERS) if OWNERS else None
    except json.JSONDecodeError as e:
        common.show_error(f"Invalid JSON format for owners parameter: {e}", logger)

    try:
        urls_list = json.loads(URLS) if URLS else None
    except json.JSONDecodeError as e:
        common.show_error(f"Invalid JSON format for urls parameter: {e}", logger)

    return owners_list, urls_list


def create_secret(
    authentication_obj: authentication.Authentication,
    totp_enabled: Optional[bool] = None,
    totp_secret_key: Optional[str] = None,
) -> None:
    """
    Create a secret in Secrets Safe.

    This function resolves the parent folder, optionally creates a file,
    and creates a secret using the Secrets Safe API. It also handles
    common errors related to secret creation.

    Args:
        authentication_obj (authentication.Authentication): Authenticated
            Secrets Safe client instance.
        totp_enabled (Optional[bool]): Enables TOTP on a credential secret
            (API version 3.3). None omits it from the request.
        totp_secret_key (Optional[str]): TOTP seed, as Base32 or an otpauth://
            URI. None omits it from the request.
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
    if FILE_CONTENT and FILE_NAME:
        common.create_file(FILE_NAME, FILE_CONTENT, logger)

    owners_list, urls_list = parse_json_parameters()

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
            owners=owners_list,
            password_rule_id=int(PASSWORD_RULE_ID) if PASSWORD_RULE_ID else None,
            notes=NOTES,
            urls=urls_list,
            totp_enabled=totp_enabled,
            totp_secret_key=totp_secret_key,
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

    # The recommended version is 3.1 (3.3 is required for TOTP). If no version
    # is specified, the default API version 3.0 will be used. If API_KEY is
    # set, API Key authentication is used, otherwise OAuth/Client Credentials.
    return api_client.authenticate(
        session,
        logger,
        api_url=API_URL,
        verify_ca=VERIFY_CA,
        api_key=API_KEY,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        certificate=CERTIFICATE,
        certificate_key=CERTIFICATE_KEY,
        api_version=API_VERSION,
    )


def main() -> None:
    """
    Main entrypoint for the GitHub Action.

    Orchestrates the workflow to authenticate, create a secret,
    and properly close the API session.
    """
    mask_sensitive_inputs()
    # Validate TOTP inputs before authenticating, so bad input fails fast.
    totp_enabled, totp_secret_key = get_totp_settings()

    try:
        with api_client.create_session() as session:

            authentication_obj = set_authentication(session)
            create_secret(authentication_obj, totp_enabled, totp_secret_key)
            authentication_obj.sign_app_out()

    except Exception as e:
        common.show_error(f"An unexpected error occurred: {e}", logger)


if __name__ == "__main__":
    main()

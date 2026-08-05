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
from typing import Any, Dict, Optional, Union

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
# VERIFY_CA is resolved below, once the logger exists to report a bad value.
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
PASSWORD_RULE_ID = env.get("INPUT_PASSWORD_RULE_ID", "").strip()
NOTES = env.get("INPUT_NOTES", "").strip()
OWNERS = env.get("INPUT_OWNERS", "")
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

# Tokens that explicitly enable / disable TLS certificate verification.
VERIFY_CA_TRUE_TOKENS = frozenset({"true", "1", "yes", "on", "enable", "enabled"})
VERIFY_CA_FALSE_TOKENS = frozenset({"false", "0", "no", "off", "disable", "disabled"})


def parse_verify_ca(value: Union[str, None]) -> Union[bool, str]:
    """
    Parse the VERIFY_CA environment variable.

    Fails closed: verification is only disabled for an explicitly recognized
    false token (false/0/no/off/disable/disabled, case-insensitive). A value
    that points to an existing file or directory is passed through as a CA
    bundle path, and anything unrecognized raises rather than silently ignoring
    the caller's intent.

    Note that True verifies against the CA store the requests library defaults
    to (certifi's bundled roots), which is *not* the operating system trust
    store. To trust a private/internal CA, pass the bundle path here - the
    bundle must exist inside the action container, where the workspace is
    mounted at /github/workspace.

    Args:
        value (str | None): Raw VERIFY_CA value, None when unset.

    Returns:
        bool | str: True to verify against the default CA store, False to
        disable verification, or a path to a CA bundle file/directory.

    Raises:
        EnvironmentError: If the value is neither a recognized token nor an
        existing path.
    """

    if value is None:
        return True

    normalized = value.strip()

    if not normalized:
        return True

    token = normalized.lower()

    if token in VERIFY_CA_TRUE_TOKENS:
        return True

    if token in VERIFY_CA_FALSE_TOKENS:
        return False

    # Allow pinning a custom CA bundle file or directory by path.
    if os.path.exists(normalized):
        return normalized

    raise EnvironmentError(
        f"Invalid value for VERIFY_CA: {value!r}. Use 'true'/'false' or a path "
        "to an existing CA bundle inside the action container (the repository "
        "workspace is mounted at /github/workspace). Refusing to continue "
        "rather than silently ignoring the requested CA bundle."
    )


def configure_certificate_verification(
    session: requests.Session, verify_ca: Union[bool, str]
) -> None:
    """
    Apply the CA verification setting to the session and log the trust store
    that is actually in effect.

    The bundle path is assigned here so the session is correct on its own,
    independent of the Authentication object also assigning it.

    Args:
        session (requests.Session): Session used for every API call.
        verify_ca (bool | str): True to verify against the CA store requests
            defaults to (certifi's bundled roots, *not* the operating system
            trust store), False to disable verification, or a path to a CA
            bundle file/directory to verify against instead.
    """

    session.verify = verify_ca

    if verify_ca is False:
        # The library already warns that disabling verification is insecure.
        return

    if isinstance(verify_ca, str):
        utils.print_log(
            logger,
            f"Verifying certificates against CA bundle: {verify_ca}",
            logging.INFO,
        )
        return

    # requests swaps in REQUESTS_CA_BUNDLE/CURL_CA_BUNDLE at request time when
    # verify is True, so report the store that is actually in effect.
    ca_store = f"certifi: {requests.adapters.DEFAULT_CA_BUNDLE_PATH}"
    for env_var in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        if env.get(env_var):
            ca_store = f"overridden by {env_var}: {env[env_var]}"
            break

    utils.print_log(
        logger,
        "Verifying certificates against the CA store used by requests "
        f"({ca_store}). Set VERIFY_CA to a CA bundle path to trust a private "
        "CA instead.",
        logging.INFO,
    )


try:
    VERIFY_CA = parse_verify_ca(env.get("VERIFY_CA"))
except EnvironmentError as verify_ca_error:
    common.show_error(str(verify_ca_error), logger)


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

    configure_certificate_verification(session, VERIFY_CA)

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

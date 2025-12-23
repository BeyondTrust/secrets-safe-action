import json
import logging
import os
import sys
import uuid

import requests
import secrets_safe_library
from github_action_utils import error
from retry_requests import retry
from secrets_safe_library import (
    authentication,
    exceptions,
    folders,
    managed_account,
    secrets_safe,
    utils,
)

env = os.environ

API_KEY = env.get("API_KEY")
CLIENT_ID = env.get("CLIENT_ID")
CLIENT_SECRET = env.get("CLIENT_SECRET")
API_URL = env.get("API_URL")
API_VERSION = env.get("API_VERSION")
VERIFY_CA = env.get("VERIFY_CA", "true").lower() != "false"

SECRET_PATH = env.get("INPUT_SECRET_PATH", "").strip() or None
MANAGED_ACCOUNT_PATH = env.get("INPUT_MANAGED_ACCOUNT_PATH", "").strip() or None
path_sep = env.get("PATH_SEPARATOR", "/").strip()
PATH_SEPARATOR = path_sep if len(path_sep) == 1 else "/"
MAX_SECRETS_TO_RETRIEVE = 20

OPERATION = env.get("INPUT_OPERATION", "CREATE_SECRET").strip().upper()
TITLE = env.get("INPUT_TITLE", "").strip()
PARENT_FOLDER_NAME = env.get("INPUT_PARENT_FOLDER_NAME", "").strip()
DESCRIPTION = env.get("INPUT_DESCRIPTION", "").strip()
USERNAME = env.get("INPUT_USERNAME", "").strip()
PASSWORD = env.get("INPUT_PASSWORD", "").strip()
TEXT = env.get("INPUT_TEXT", "").strip()
FILE_PATH = env.get("INPUT_FILE_PATH", "").strip()
OWNER_ID = env.get("INPUT_OWNER_ID", "").strip()
OWNER_TYPE = env.get("INPUT_OWNER_TYPE", "").strip()
OWNERS = env.get("INPUT_OWNERS", "").strip()
PASSWORD_RULE_ID = env.get("INPUT_PASSWORD_RULE_ID", "").strip()
NOTES = env.get("INPUT_NOTES", "").strip()
URLS = env.get("INPUT_URLS", "").strip()

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
TIMEOUT_CONNECTION_SECONDS = 30
TIMEOUT_REQUEST_SECONDS = 30
CERTIFICATE = env.get("CERTIFICATE", "").replace(r"\n", "\n")
CERTIFICATE_KEY = env.get("CERTIFICATE_KEY", "").replace(r"\n", "\n")

COMMAND_MARKER: str = "::"


def append_output(name: str, value: str) -> None:
    """
    Appends a named value to the GitHub Actions step output file.

    Arguments:
        name (str): The name of the output variable.
        value (str): The content to be written as the output.

    Returns:
        None
    """

    with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
        delimiter = uuid.uuid1()
        print(f"{name}<<{delimiter}", file=fh)
        print(value, file=fh)
        print(delimiter, file=fh)


def mask_secret(command: str, secret_to_mask: str) -> None:
    """
    Masks a secret by modifying the command to prevent it from being printed
    in the console.

    Arguments:
        command (str): The command associated with the secret.
        secret_to_mask (str): The secret text to be masked.

    Returns:
        None
    """

    lines = secret_to_mask.split("\n")
    for line in lines:
        if line.strip() != "":
            full_command = f"{COMMAND_MARKER}{command} {COMMAND_MARKER}{line}"
            print(full_command)


def show_error(error_message: str) -> None:
    """
    Displays an error message in the logs and prints an error message in the
    GitHub Actions shell.

    Arguments:
        error_message (str): The message to display as an error.

    Returns:
        None
    """

    error(
        error_message,
        title="Action Failed",
        col=1,
        end_column=2,
        line=4,
        end_line=5,
    )
    utils.print_log(logger, error_message, logging.ERROR)
    sys.exit(1)


def get_secrets(
    secret_obj: authentication.Authentication | secrets_safe.SecretsSafe, secrets: str
) -> None:
    """
    Retrieves secrets using the provided secret object and a JSON string of
    secrets. Output is appended to GITHUB_OUTPUT.

    Arguments:
        secret_obj (Authentication | SecretsSafe): An instance of either
        Authentication or SecretsSafe class, handling secret operations.
        secrets (str): A JSON string containing a list of secrets or managed
        accounts.

    Returns:
        None
    """

    try:
        secrets_to_retrive = json.loads(secrets)
    except json.JSONDecodeError as e:
        show_error(f"JSON object is not correctly formatted: {e}")
    except TypeError as e:
        show_error(f"Input is not a string, bytes or bytearray: {e}")
    except Exception as e:
        show_error(f"An unexpected error occurred: {e}")

    if not isinstance(secrets_to_retrive, list):
        secrets_to_retrive = [secrets_to_retrive]

    if len(secrets_to_retrive) > MAX_SECRETS_TO_RETRIEVE:
        show_error(
            "The Secrets Safe action can request a maximum of "
            f"{MAX_SECRETS_TO_RETRIEVE} secrets and "
            f"{MAX_SECRETS_TO_RETRIEVE} managed accounts each run"
        )

    for secret_to_retrieve in secrets_to_retrive:
        if "path" not in secret_to_retrieve:
            show_error("Invalid JSON, validate path attribute name")

        if "output_id" not in secret_to_retrieve:
            show_error("Invalid JSON, validate output_id attribute name")

        get_secret_response = secret_obj.get_secret(secret_to_retrieve["path"])

        mask_secret("add-mask", get_secret_response)
        append_output(secret_to_retrieve["output_id"], get_secret_response)


def main() -> None:
    try:

        utils.print_log(
                logger,
                f"USERNAME {USERNAME}, SECRET_TITLE {TITLE}, SECRET_DESCRIPTION {DESCRIPTION}",
                logging.DEBUG,
            )
        with requests.Session() as session:
            req = retry(
                session,
                retries=3,
                backoff_factor=0.2,
                status_to_retry=(400, 408, 500, 502, 503, 504),
            )

            certificate, certificate_key = utils.prepare_certificate_info(
                CERTIFICATE, CERTIFICATE_KEY
            )

            auth_config = {
                "req": req,
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
                auth_config.update(
                    {"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}
                )

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
                show_error(error_message)

            secrets_safe_obj = secrets_safe.SecretsSafe(
                    authentication=authentication_obj,
                    logger=logger,
                    separator=PATH_SEPARATOR,
                )

            if OPERATION == "GET_SECRET":
                if not SECRET_PATH and not MANAGED_ACCOUNT_PATH:
                    error_message = (
                        "Nothing to do, SECRET and MANAGED_ACCOUNT parameters are empty"
                    )
                    show_error(error_message)

                if SECRET_PATH:
                    get_secrets(secrets_safe_obj, SECRET_PATH)

                if MANAGED_ACCOUNT_PATH:
                    managed_account_obj = managed_account.ManagedAccount(
                        authentication=authentication_obj,
                        logger=logger,
                        separator=PATH_SEPARATOR,
                    )
                    get_secrets(managed_account_obj, MANAGED_ACCOUNT_PATH)

            if OPERATION == "CREATE_SECRET":
                try:

                    # instantiate folders obj
                    folders_obj = folders.Folder(
                        authentication=authentication_obj, logger=logger
                    )

                    folder = get_folder(folders_obj, PARENT_FOLDER_NAME)
                    if not folder:
                        show_error("Parent Folder name was not found")

                    # creating secret
                    secrets_safe_obj.create_secret(
                        title=TITLE,
                        folder_id=folder["Id"],
                        description=DESCRIPTION,
                        username=USERNAME,
                        password=PASSWORD,
                        text=TEXT,
                        file_path=FILE_PATH,
                        owner_id=int(OWNER_ID) if OWNER_ID else None,
                        owner_type=OWNER_TYPE,
                        owners=json.loads(OWNERS) if OWNERS else None,
                        password_rule_id=int(PASSWORD_RULE_ID) if PASSWORD_RULE_ID else None,
                        notes=NOTES,
                        urls=json.loads(URLS) if URLS else None,
                    )
                except exceptions.CreationError as e:
                    show_error(f"Error creating secret: {e}")

                except (exceptions.OptionsError, exceptions.IncompleteArgumentsError) as e:
                    show_error(f"Invalid or missing parameters: {e}")

                except FileNotFoundError as e:
                    show_error(f"Invalid or missing file path: {e}")

            authentication_obj.sign_app_out()

    except Exception as e:
        show_error(e)

def get_folder(folders_obj, folder_name: str):
    """
    Get folder by folder name.

    Args:
        folders_obj(folders.Folder): Instance of the Folders object from the PS library,
            used for folder management.
        folder_name(str): The name of the folder to search for.
    Returns:
        folders.Folder: Found folder object.
    """
    folder_list = folders_obj.list_folders(folder_name=folder_name)
    matched_folders = [x for x in folder_list if x["Name"] == folder_name]

    if not matched_folders:
        return None

    return matched_folders[0]

if __name__ == "__main__":
    main()

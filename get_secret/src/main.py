import json
import logging
import os
import re

from secrets_safe_library import authentication, managed_account, secrets_safe
from secrets_safe_library.integrations.github_actions.common_utils import (
    api_client,
    common,
    outputs,
    tls,
)

env = os.environ

API_KEY = env.get("API_KEY")
CLIENT_ID = env.get("CLIENT_ID")
CLIENT_SECRET = env.get("CLIENT_SECRET")
API_URL = env.get("API_URL")
API_VERSION = env.get("API_VERSION")
DECRYPT = env.get("INPUT_DECRYPT", "true").lower() == "true"

SECRET_PATH = env.get("INPUT_SECRET_PATH", "").strip() or None
MANAGED_ACCOUNT_PATH = env.get("INPUT_MANAGED_ACCOUNT_PATH", "").strip() or None
path_sep = env.get("PATH_SEPARATOR", "/").strip()
PATH_SEPARATOR = path_sep if len(path_sep) == 1 else "/"
MAX_SECRETS_TO_RETRIEVE = 20

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
CERTIFICATE = env.get("CERTIFICATE", "").replace(r"\n", "\n")
CERTIFICATE_KEY = env.get("CERTIFICATE_KEY", "").replace(r"\n", "\n")

try:
    VERIFY_CA = tls.parse_verify_ca(env.get("VERIFY_CA"))
except EnvironmentError as verify_ca_error:
    common.show_error(str(verify_ca_error), logger)


def parse_secrets(secrets: str) -> list:
    """
    Parse a JSON string containing secret definitions.

    The input may represent either a single secret object or a list of secret
    objects. If a single object is provided, it is wrapped into a list to
    normalize downstream processing.

    If the input is not valid JSON or is not a supported type, an error is
    reported and an empty list is returned.

    Args:
        secrets (str): A JSON-formatted string representing a secret object
            or a list of secret objects.

    Returns:
        list: A list of parsed secret objects. Returns an empty list if the
        input is invalid or cannot be parsed.
    """
    try:
        data = json.loads(secrets)
    except (json.JSONDecodeError, TypeError) as e:
        common.show_error(f"Invalid JSON input: {e}", logger)
        return []

    return data if isinstance(data, list) else [data]


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

    secrets_to_retrive = parse_secrets(secrets)

    if not isinstance(secrets_to_retrive, list):
        secrets_to_retrive = [secrets_to_retrive]

    if len(secrets_to_retrive) > MAX_SECRETS_TO_RETRIEVE:
        common.show_error(
            "The Secrets Safe action can request a maximum of "
            f"{MAX_SECRETS_TO_RETRIEVE} secrets and "
            f"{MAX_SECRETS_TO_RETRIEVE} managed accounts each run",
            logger,
        )

    for secret_to_retrieve in secrets_to_retrive:
        if not isinstance(secret_to_retrieve, dict):
            common.show_error(
                "Invalid JSON, each secret entry must be a JSON object", logger
            )

        if "path" not in secret_to_retrieve:
            common.show_error("Invalid JSON, validate path attribute name", logger)

        if "output_id" not in secret_to_retrieve:
            common.show_error("Invalid JSON, validate output_id attribute name", logger)

        output_id = secret_to_retrieve["output_id"]
        if not isinstance(output_id, str) or not re.fullmatch(
            r"[a-zA-Z_][a-zA-Z0-9_-]*", output_id
        ):
            common.show_error(
                f"Invalid output_id {repr(output_id)}: must be a string starting "
                "with a letter or underscore and contain only alphanumeric "
                "characters, underscores, or hyphens",
                logger,
            )

        get_secret_response = secret_obj.get_secret(secret_to_retrieve["path"])
        if get_secret_response:
            outputs.mask_secret(get_secret_response)
            outputs.append_output(output_id, get_secret_response)


def main() -> None:
    try:
        with api_client.create_session() as session:
            # The recommended version is 3.1. If no version is specified,
            # the default API version 3.0 will be used. If API_KEY is set,
            # API Key authentication is used, otherwise OAuth/Client Credentials.
            authentication_obj = api_client.authenticate(
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

            if not SECRET_PATH and not MANAGED_ACCOUNT_PATH:
                error_message = (
                    "Nothing to do, SECRET and MANAGED_ACCOUNT parameters are empty"
                )
                common.show_error(error_message, logger)

            if SECRET_PATH:
                secrets_safe_obj = secrets_safe.SecretsSafe(
                    authentication=authentication_obj,
                    logger=logger,
                    separator=PATH_SEPARATOR,
                    decrypt=DECRYPT,
                )
                get_secrets(secrets_safe_obj, SECRET_PATH)

            if MANAGED_ACCOUNT_PATH:
                managed_account_obj = managed_account.ManagedAccount(
                    authentication=authentication_obj,
                    logger=logger,
                    separator=PATH_SEPARATOR,
                )
                get_secrets(managed_account_obj, MANAGED_ACCOUNT_PATH)

            authentication_obj.sign_app_out()

    except Exception as e:
        common.show_error(e, logger)


if __name__ == "__main__":
    main()

import json
import logging
import os
import re
import uuid

import requests
import secrets_safe_library
from requests.adapters import HTTPAdapter
from secrets_safe_library import authentication, managed_account, secrets_safe, utils
from secrets_safe_library.integrations.github_actions.common_utils import common
from urllib3.util.retry import Retry

env = os.environ

API_KEY = env.get("API_KEY")
CLIENT_ID = env.get("CLIENT_ID")
CLIENT_SECRET = env.get("CLIENT_SECRET")
API_URL = env.get("API_URL")
API_VERSION = env.get("API_VERSION")
# VERIFY_CA is resolved below, once the logger exists to report a bad value.
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
TIMEOUT_CONNECTION_SECONDS = 30
TIMEOUT_REQUEST_SECONDS = 30
CERTIFICATE = env.get("CERTIFICATE", "").replace(r"\n", "\n")
CERTIFICATE_KEY = env.get("CERTIFICATE_KEY", "").replace(r"\n", "\n")

COMMAND_MARKER: str = "::"

# Tokens that explicitly enable / disable TLS certificate verification.
VERIFY_CA_TRUE_TOKENS = frozenset({"true", "1", "yes", "on", "enable", "enabled"})
VERIFY_CA_FALSE_TOKENS = frozenset({"false", "0", "no", "off", "disable", "disabled"})


def parse_verify_ca(value: str | None) -> bool | str:
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

    Arguments:
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
    session: requests.Session, verify_ca: bool | str
) -> None:
    """
    Applies the CA verification setting to the session and logs the trust store
    that is actually in effect.

    The bundle path is assigned here so the session is correct on its own,
    independent of the Authentication object also assigning it.

    Arguments:
        session (requests.Session): Session used for every API call.
        verify_ca (bool | str): True to verify against the CA store requests
            defaults to (certifi's bundled roots, *not* the operating system
            trust store), False to disable verification, or a path to a CA
            bundle file/directory to verify against instead.

    Returns:
        None
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
        delimiter = uuid.uuid4()
        print(f"{name}<<{delimiter}", file=fh)
        print(value, file=fh)
        print(delimiter, file=fh)


def escape_data(value: str) -> str:
    """
    Escapes a value for safe use as a GitHub Actions workflow-command payload.

    Mirrors the escaping performed by the official @actions/core toolkit so the
    data portion cannot introduce additional runner-visible lines or be parsed
    as a new workflow command. The GitHub Actions runner reads container stdout
    line by line and treats both carriage return (CR, 0x0D) and line feed
    (LF, 0x0A) as line terminators, so both must be encoded.

    Arguments:
        value (str): The raw value to escape.

    Returns:
        str: The escaped value with '%', CR, and LF percent-encoded.
    """

    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


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

    # Split on every line terminator the GitHub Actions runner recognises
    # (CRLF, CR, LF) so a secret containing a bare '\r' cannot be parsed by
    # the runner as multiple stdout lines / injected workflow commands.
    lines = re.split(r"\r\n|\r|\n", secret_to_mask)
    for line in lines:
        if line.strip() != "":
            # Escape the data portion consistently with @actions/core so any
            # residual control or percent characters cannot break out of the
            # add-mask command payload.
            full_command = (
                f"{COMMAND_MARKER}{command} {COMMAND_MARKER}{escape_data(line)}"
            )
            print(full_command)


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
            mask_secret("add-mask", get_secret_response)
            append_output(output_id, get_secret_response)


def main() -> None:
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
                common.show_error(error_message, logger)

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

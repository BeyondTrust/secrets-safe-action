"""
Secrets Safe Get TOTP Code Action

Retrieves the current one-time (TOTP) code of TOTP-enabled credential secrets
from BeyondTrust Secrets Safe and exposes each code as a masked GitHub Actions
output.

API: GET Secrets-Safe/Secrets/{secretId}/totp/code
"""

import json
import logging
import os
import re
import uuid
from typing import List, Tuple

import requests
import secrets_safe_library
from requests.adapters import HTTPAdapter
from secrets_safe_library import authentication, exceptions, secrets_safe, utils
from secrets_safe_library.integrations.github_actions.common_utils import common
from urllib3.util.retry import Retry

env = os.environ

API_KEY = env.get("API_KEY")
CLIENT_ID = env.get("CLIENT_ID")
CLIENT_SECRET = env.get("CLIENT_SECRET")
API_URL = env.get("API_URL")
API_VERSION = env.get("API_VERSION")
# VERIFY_CA is resolved below, once the logger exists to report a bad value.

SECRET_IDS = env.get("INPUT_SECRET_IDS", "").strip() or None
MAX_CODES_TO_RETRIEVE = 20

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

OUTPUT_ID_PATTERN = r"[a-zA-Z_][a-zA-Z0-9_-]*"

# Unlike the other actions, 400 is not retried: the TOTP code endpoint returns
# 400 for a text or file secret, which must reach the library as a response so
# it raises SecretTypeNotSupportedError. Retrying it would fail with a generic
# RetryError after wasting the retries.
RETRY_STATUS_CODES = [408, 500, 502, 503, 504]


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

    Mirrors the escaping performed by the official @actions/core toolkit, so the
    payload cannot add runner-visible lines or start a new workflow command.

    Arguments:
        value (str): The raw value to escape.

    Returns:
        str: The escaped value with '%', CR, and LF percent-encoded.
    """

    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def mask_secret(command: str, secret_to_mask: str) -> None:
    """
    Registers a value with the runner so it is masked in the workflow logs.

    Arguments:
        command (str): The workflow command to emit, e.g. "add-mask".
        secret_to_mask (str): The value to mask. Each line is masked separately.

    Returns:
        None
    """

    # Split on every line terminator the runner recognises (CRLF, CR, LF) so a
    # value containing a bare '\r' cannot inject extra workflow commands.
    for line in re.split(r"\r\n|\r|\n", secret_to_mask):
        if line.strip() != "":
            print(f"{COMMAND_MARKER}{command} {COMMAND_MARKER}{escape_data(line)}")


def is_guid(value) -> bool:
    """
    Returns True when value is a string holding a GUID.

    Arguments:
        value: The value to check.

    Returns:
        bool: True for a GUID string, False otherwise.
    """

    try:
        uuid.UUID(value)
    except (TypeError, ValueError, AttributeError):
        return False
    return True


def validate_entry(entry) -> Tuple[str, str]:
    """
    Validates one input entry and returns its secret ID and output name.

    The secret ID is placed in the request path, so anything that is not a GUID
    is rejected. The output name must be safe to use in GITHUB_OUTPUT.

    Arguments:
        entry: One parsed element of the secret_ids input.

    Returns:
        Tuple[str, str]: (secret_id, output_id).
    """

    if not isinstance(entry, dict):
        common.show_error("Invalid JSON, each entry must be a JSON object", logger)

    if "secret_id" not in entry:
        common.show_error("Invalid JSON, validate secret_id attribute name", logger)

    if "output_id" not in entry:
        common.show_error("Invalid JSON, validate output_id attribute name", logger)

    secret_id = entry["secret_id"]
    output_id = entry["output_id"]

    if not is_guid(secret_id):
        common.show_error(
            f"Invalid secret_id {repr(secret_id)}: must be a secret GUID", logger
        )

    if not isinstance(output_id, str) or not re.fullmatch(OUTPUT_ID_PATTERN, output_id):
        common.show_error(
            f"Invalid output_id {repr(output_id)}: must be a string starting "
            "with a letter or underscore and contain only alphanumeric "
            "characters, underscores, or hyphens",
            logger,
        )

    return secret_id, output_id


def parse_secret_ids(secret_ids: str | None) -> List[Tuple[str, str]]:
    """
    Parses and validates the secret_ids input.

    The input is a JSON object, or a list of objects, each with "secret_id"
    (GUID) and "output_id" attributes. Every entry is validated here, before
    authenticating, so bad input fails without making any API call.

    Arguments:
        secret_ids (str | None): Raw value of the secret_ids input.

    Returns:
        List[Tuple[str, str]]: (secret_id, output_id) pairs.
    """

    if not secret_ids:
        common.show_error("Nothing to do, SECRET_IDS parameter is empty", logger)

    try:
        data = json.loads(secret_ids)
    except (json.JSONDecodeError, TypeError) as e:
        common.show_error(f"Invalid JSON input: {e}", logger)

    entries = data if isinstance(data, list) else [data]

    if not entries:
        common.show_error("Nothing to do, SECRET_IDS parameter is empty", logger)

    if len(entries) > MAX_CODES_TO_RETRIEVE:
        common.show_error(
            "The Secrets Safe Get TOTP Code action can request a maximum of "
            f"{MAX_CODES_TO_RETRIEVE} TOTP codes each run",
            logger,
        )

    return [validate_entry(entry) for entry in entries]


def get_totp_code(secrets_safe_obj: secrets_safe.SecretsSafe, secret_id: str) -> str:
    """
    Retrieves the current TOTP code of one credential secret.

    Arguments:
        secrets_safe_obj (SecretsSafe): Secrets Safe client.
        secret_id (str): The credential secret ID (GUID).

    Returns:
        str: The current one-time code.
    """

    try:
        response = secrets_safe_obj.get_secret_totp_code(secret_id)
    except exceptions.SecretTypeNotSupportedError as e:
        common.show_error(
            f"Cannot get a TOTP code for secret {secret_id}: TOTP codes are only "
            f"available for credential secrets. {e}",
            logger,
        )
    except exceptions.TotpNotEnabledError as e:
        common.show_error(
            f"Cannot get a TOTP code for secret {secret_id}: check that the secret "
            "exists and that TOTP is enabled on it (create it with api_version "
            f"3.3 and totp_enabled). {e}",
            logger,
        )
    except exceptions.LookupError as e:
        common.show_error(
            f"Error getting TOTP code for secret {secret_id}: {e}", logger
        )

    code = response.get("Code") if isinstance(response, dict) else None
    if code is None or str(code).strip() == "":
        common.show_error(
            f"The TOTP code response for secret {secret_id} did not include a code",
            logger,
        )

    return str(code)


def get_totp_codes(
    secrets_safe_obj: secrets_safe.SecretsSafe, entries: List[Tuple[str, str]]
) -> None:
    """
    Retrieves the current TOTP code for each entry and appends it to
    GITHUB_OUTPUT. Each code is masked before it is written, and is only valid
    for the current TOTP period.

    Arguments:
        secrets_safe_obj (SecretsSafe): Secrets Safe client.
        entries (List[Tuple[str, str]]): (secret_id, output_id) pairs.

    Returns:
        None
    """

    for secret_id, output_id in entries:
        code = get_totp_code(secrets_safe_obj, secret_id)
        mask_secret("add-mask", code)
        append_output(output_id, code)


def set_authentication(session: requests.Session) -> authentication.Authentication:
    """
    Authenticates against Secrets Safe with an API key (optionally with a
    client certificate) or OAuth client credentials.

    Arguments:
        session (requests.Session): Session used for every API call.

    Returns:
        authentication.Authentication: Authenticated client.
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

    # If no version is specified, the default API version 3.0 will be used.
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
        common.show_error(
            f"Please check credentials, error {get_api_access_response.text}",
            logger,
        )

    return authentication_obj


def main() -> None:
    """
    Validates the input, authenticates, writes each TOTP code to GITHUB_OUTPUT
    and signs out.
    """

    # Validate the input before authenticating, so bad input fails fast.
    entries = parse_secret_ids(SECRET_IDS)

    try:
        with requests.Session() as session:
            retry_strategy = Retry(
                total=3,
                backoff_factor=0.2,
                status_forcelist=RETRY_STATUS_CODES,
                allowed_methods=["GET", "POST"],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("https://", adapter)
            session.mount("http://", adapter)

            authentication_obj = set_authentication(session)
            secrets_safe_obj = secrets_safe.SecretsSafe(
                authentication=authentication_obj, logger=logger
            )
            get_totp_codes(secrets_safe_obj, entries)
            authentication_obj.sign_app_out()

    except Exception as e:
        common.show_error(e, logger)


if __name__ == "__main__":
    main()

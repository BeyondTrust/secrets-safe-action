"""
GitHub Action entrypoint for updating secrets in BeyondTrust Secrets Safe.

This module is responsible for:
- Reading configuration and secret inputs from environment variables
- Validating the inputs before any API call is made
- Authenticating against the Secrets Safe API
- Updating a secret of type CREDENTIAL, TEXT, or FILE by its ID
- Handling errors and logging

API:
    - PUT Secrets-Safe/Secrets/{secretId}        (credential secret)
    - PUT Secrets-Safe/Secrets/{secretId}/text   (text secret)
    - PUT Secrets-Safe/Secrets/{secretId}/file   (file secret)

Each PUT replaces the secret, so the existing secret is read first and every
input left empty keeps its current value, as in the ps-integration-cli
"secrets update" command.
"""

import json
import logging
import os
import re
import uuid
from typing import Any, Dict, Optional, Tuple, Union
from urllib.parse import parse_qs, urlsplit

import requests
import secrets_safe_library
from requests.adapters import HTTPAdapter
from secrets_safe_library import authentication, exceptions, secrets_safe, utils
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
SECRET_ID = env.get("INPUT_SECRET_ID", "").strip()
TITLE = env.get("INPUT_SECRET_TITLE", "").strip()
DESCRIPTION = env.get("INPUT_SECRET_DESCRIPTION", "").strip()
USERNAME = env.get("INPUT_USERNAME", "").strip()
PASSWORD = env.get("INPUT_PASSWORD", "")
TEXT = env.get("INPUT_TEXT", "")
FILE_CONTENT = env.get("INPUT_FILE_CONTENT", "")
FILE_NAME = env.get("INPUT_FILE_NAME", "").strip()
OWNER_ID = env.get("INPUT_OWNER_ID", "").strip()
OWNER_TYPE = env.get("INPUT_OWNER_TYPE", "").strip()
PASSWORD_RULE_ID = env.get("INPUT_PASSWORD_RULE_ID", "").strip()
NOTES = env.get("INPUT_NOTES", "").strip()
OWNERS = env.get("INPUT_OWNERS", "")
URLS = env.get("INPUT_URLS", "")
TOTP_ENABLED = env.get("INPUT_TOTP_ENABLED", "").strip()
TOTP_SECRET_KEY = env.get("INPUT_TOTP_SECRET_KEY", "").strip()

CREDENTIAL = "credential"
TEXT_TYPE = "text"
FILE_TYPE = "file"

COMMAND_MARKER = "::"

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

# The API answers a successful credential or text update with 204 No Content,
# but beyondtrust-bips-library (<= 3.5.1) expects 200 for those two PUTs and
# raises UpdateError ending in "statuscode: 204". That exact error means the
# update was applied.
NO_CONTENT_UPDATE_ERROR = re.compile(r"statuscode: 204\s*$")


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


def escape_data(value: str) -> str:
    """
    Escape a value for safe use as a GitHub Actions workflow-command payload.

    Mirrors the escaping performed by the official @actions/core toolkit, so the
    payload cannot add runner-visible lines or start a new workflow command.

    Args:
        value (str): The raw value to escape.

    Returns:
        str: The value with '%', CR and LF percent-encoded.
    """

    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def mask_secret(command: str, secret_to_mask: str) -> None:
    """
    Register a value with the runner so it is masked in the workflow logs.

    Args:
        command (str): The workflow command to emit, e.g. "add-mask".
        secret_to_mask (str): The value to mask. Each line is masked separately.
    """

    # Split on every line terminator the runner recognises (CRLF, CR, LF) so a
    # value containing a bare '\r' cannot inject extra workflow commands.
    for line in re.split(r"\r\n|\r|\n", secret_to_mask):
        if line.strip() != "":
            print(f"{COMMAND_MARKER}{command} {COMMAND_MARKER}{escape_data(line)}")


def mask_sensitive_inputs() -> None:
    """
    Mask the password, text and TOTP seed inputs before anything else is logged.

    When the seed is an otpauth:// URI, the seed carried in its "secret" query
    parameter is masked on its own too, so it stays hidden if it is ever
    printed without the rest of the URI.
    """

    for value in (PASSWORD, TEXT, TOTP_SECRET_KEY):
        if value:
            mask_secret("add-mask", value)

    if TOTP_SECRET_KEY.lower().startswith("otpauth://"):
        query = parse_qs(urlsplit(TOTP_SECRET_KEY).query)
        for seed in query.get("secret", []):
            mask_secret("add-mask", seed)


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


def parse_optional_int(value: str, input_name: str) -> Optional[int]:
    """
    Parse an optional integer action input.

    Args:
        value (str): Raw input value.
        input_name (str): Input name, used in the error message.

    Returns:
        Optional[int]: None when the input is empty, otherwise the integer.
        A non-integer value fails the step.
    """

    if not value:
        return None

    try:
        return int(value)
    except ValueError:
        common.show_error(
            f"Invalid value for {input_name}: {value!r}. It must be an integer.",
            logger,
        )


def validate_secret_id(secret_id: str) -> None:
    """
    Fail the step unless secret_id is a GUID. The value is placed in the
    request path, so anything else is rejected before a request is made.

    Args:
        secret_id (str): The secret_id input.
    """

    try:
        uuid.UUID(secret_id)
    except (TypeError, ValueError, AttributeError):
        common.show_error(
            f"Invalid secret_id {secret_id!r}: must be a secret GUID", logger
        )


def get_secret_type() -> str:
    """
    Work out which kind of secret is being updated from the content inputs.

    Exactly one kind must be given: username (credential), text, or file_name
    with file_content (file). The type of an existing secret cannot change, so
    it must match the secret being updated.

    Returns:
        str: CREDENTIAL, TEXT_TYPE or FILE_TYPE.
    """

    given = []
    if USERNAME:
        given.append(CREDENTIAL)
    if TEXT:
        given.append(TEXT_TYPE)
    if FILE_NAME or FILE_CONTENT:
        given.append(FILE_TYPE)

    if len(given) != 1:
        common.show_error(
            "Set exactly one kind of secret content: username (and password) "
            "for a credential secret, text for a text secret, or file_name and "
            "file_content for a file secret.",
            logger,
        )

    if given[0] == FILE_TYPE and not (FILE_NAME and FILE_CONTENT):
        common.show_error(
            "file_name and file_content are both required to update a file secret.",
            logger,
        )

    return given[0]


def get_totp_settings(secret_type: str) -> Tuple[Optional[bool], Optional[str]]:
    """
    Parse and validate the TOTP inputs.

    TOTP is only available for credential secrets. On update, true sets or
    replaces the seed, false turns TOTP off, and empty leaves it unchanged. A
    seed is required when totp_enabled is true and is rejected otherwise,
    matching the server rules. Error messages never include the seed.

    Args:
        secret_type (str): The type returned by get_secret_type().

    Returns:
        Tuple[Optional[bool], Optional[str]]: (totp_enabled, totp_secret_key),
        with None for each input that was left empty.
    """

    totp_enabled = parse_optional_bool(TOTP_ENABLED, "totp_enabled")
    totp_secret_key = TOTP_SECRET_KEY or None

    if totp_enabled is None and totp_secret_key is None:
        return None, None

    if secret_type != CREDENTIAL:
        common.show_error(
            "totp_enabled and totp_secret_key are only supported for credential "
            "secrets. Set username (and password) to update a credential secret.",
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


def validate_inputs() -> Dict[str, Any]:
    """
    Validate every input before authenticating, so bad input fails without
    making any API call.

    Returns:
        Dict[str, Any]: The checked settings: secret_type, owners, urls,
        totp_enabled, totp_secret_key, owner_id and password_rule_id.
    """

    validate_secret_id(SECRET_ID)

    # Inputs left empty keep the secret's current values (see
    # build_update_kwargs), so only the content that can't be read back is
    # required: username, text, or file_name with file_content.
    secret_type = get_secret_type()

    totp_enabled, totp_secret_key = get_totp_settings(secret_type)

    owners_list, urls_list = parse_json_parameters()

    return {
        "secret_type": secret_type,
        "owners": owners_list,
        "urls": urls_list,
        "totp_enabled": totp_enabled,
        "totp_secret_key": totp_secret_key,
        "owner_id": parse_optional_int(OWNER_ID, "owner_id"),
        "password_rule_id": (
            parse_optional_int(PASSWORD_RULE_ID, "password_rule_id")
            if secret_type == CREDENTIAL
            else None
        ),
    }


def parse_json_parameters():
    """
    Parse JSON parameters for owners and URLs with error handling.

    Each one, when given, must be an array of objects; owners can't be empty.
    Checked before authentication, so malformed values fail fast.

    Returns:
        tuple: A tuple containing (owners_list, urls_list)
    """
    owners_list = parse_json_list(OWNERS, "owners", allow_empty=False)
    urls_list = parse_json_list(URLS, "urls", allow_empty=True)

    return owners_list, urls_list


def parse_json_list(value: str, name: str, allow_empty: bool) -> Optional[list]:
    """
    Parse an input holding a JSON array of objects.

    Args:
        value (str): The raw input. Empty means not given.
        name (str): The input name, for error messages.
        allow_empty (bool): Whether an empty array is accepted.

    Returns:
        Optional[list]: The parsed array, or None when the input is empty.
    """

    if not value:
        return None

    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as e:
        common.show_error(f"Invalid JSON format for {name} parameter: {e}", logger)

    if (
        not isinstance(parsed, list)
        or not all(isinstance(item, dict) for item in parsed)
        or (not parsed and not allow_empty)
    ):
        qualifier = "a non-empty" if not allow_empty else "an"
        common.show_error(
            f"Invalid {name} parameter: expected {qualifier} JSON array of "
            f"objects, got {value}",
            logger,
        )

    return parsed


def is_no_content_success(error: Exception) -> bool:
    """
    Return True when an UpdateError only reports the 204 No Content answer of
    a successful credential or text update. See NO_CONTENT_UPDATE_ERROR.

    Args:
        error (Exception): The error raised by update_secret.

    Returns:
        bool: True when the update was applied.
    """

    return bool(NO_CONTENT_UPDATE_ERROR.search(str(error)))


def get_secret_to_update(
    secrets_safe_obj: secrets_safe.SecretsSafe, secret_type: str
) -> Dict[str, Any]:
    """
    Get the secret being updated and check that it is of secret_type.

    The type of a secret can't change, and a different type would send the
    update to the endpoint of that type, which the API rejects. A secret that
    does not report its type is accepted.

    Args:
        secrets_safe_obj (SecretsSafe): Secrets Safe client.
        secret_type (str): CREDENTIAL, TEXT_TYPE or FILE_TYPE.

    Returns:
        Dict[str, Any]: The existing secret.
    """

    try:
        secret_dict = secrets_safe_obj.get_secret_by_id(SECRET_ID)
    except exceptions.LookupError as e:
        common.show_error(
            f"Cannot read secret {SECRET_ID}: {e}. Check that the secret exists "
            "and that the application is allowed to read and edit it.",
            logger,
        )

    current_type = str(secret_dict.get("SecretType") or "").lower()
    if current_type and current_type != secret_type:
        common.show_error(
            f"Secret {SECRET_ID} is a {current_type} secret, but the inputs are "
            f"for a {secret_type} secret. The type of a secret cannot change.",
            logger,
        )

    # The existing password is sent back when none is given; keep it out of
    # the logs like the password input.
    if secret_type == CREDENTIAL and secret_dict.get("Password"):
        mask_secret("add-mask", str(secret_dict["Password"]))

    return secret_dict


def to_library_owners(owners: Optional[list]) -> Optional[list]:
    """
    Convert owners read from an existing secret to the library's format.

    Reads return owners with API field names ({"UserId": 1, "Name": ...}),
    but update_secret validates owners with its own names ({"user_id": 1})
    and rejects the API form. Empty values are dropped.

    Args:
        owners (Optional[list]): The Owners of the existing secret.

    Returns:
        Optional[list]: The owners as update_secret expects them, or None.
    """

    if not owners:
        return None

    return [
        {
            re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower(): value
            for key, value in owner.items()
            if value is not None
        }
        for owner in owners
    ]


def build_update_kwargs(
    settings: Dict[str, Any], secret_dict: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Build the update_secret keyword arguments.

    The update replaces the secret, so every field is sent: an input that is
    not provided keeps the existing secret's value instead of clearing it,
    following the ps-integration-cli "secrets update" command. Text and file
    content can't be read back, so they always come from the inputs. TOTP is
    the exception: TotpSecretKey is never returned on reads, and omitting the
    TOTP fields leaves TOTP unchanged. The folder is always kept: the API
    requires FolderId, and this action does not move secrets.

    Args:
        settings (Dict[str, Any]): The checked settings from validate_inputs().
        secret_dict (Dict[str, Any]): The existing secret.

    Returns:
        Dict[str, Any]: The keyword arguments for SecretsSafe.update_secret().
    """

    secret_type = settings["secret_type"]

    if secret_type == CREDENTIAL:
        content = {
            "username": USERNAME,
            "password": PASSWORD or secret_dict.get("Password"),
            "password_rule_id": (
                settings["password_rule_id"] or secret_dict.get("PasswordRuleID")
            ),
        }
    elif secret_type == TEXT_TYPE:
        content = {"text": TEXT}
    else:
        content = {"file_path": FILE_NAME}

    return {
        "secret_id": SECRET_ID,
        "folder_id": secret_dict.get("FolderId"),
        "title": TITLE or secret_dict.get("Title"),
        "description": DESCRIPTION or secret_dict.get("Description"),
        **content,
        "owner_id": settings["owner_id"] or secret_dict.get("OwnerId"),
        "owner_type": OWNER_TYPE or secret_dict.get("OwnerType"),
        "owners": settings["owners"] or to_library_owners(secret_dict.get("Owners")),
        "notes": NOTES or secret_dict.get("Notes"),
        "urls": settings["urls"] or secret_dict.get("Urls"),
        "totp_enabled": settings["totp_enabled"],
        "totp_secret_key": settings["totp_secret_key"],
    }


def update_secret(
    authentication_obj: authentication.Authentication,
    settings: Dict[str, Any],
) -> None:
    """
    Update a secret in Secrets Safe.

    The secret is read first, and every input left empty keeps its current
    value (see build_update_kwargs). Only the content inputs for the secret
    type are sent. For a file secret, the file is written first and uploaded
    with the metadata.

    Args:
        authentication_obj (authentication.Authentication): Authenticated
            Secrets Safe client instance.
        settings (Dict[str, Any]): The checked settings from validate_inputs().
            totp_enabled None leaves TOTP unchanged (API version 3.3).
    """

    secret_type = settings["secret_type"]

    secrets_safe_obj = secrets_safe.SecretsSafe(
        authentication=authentication_obj,
        logger=logger,
    )

    logger.info("Updating secret")

    secret_dict = get_secret_to_update(secrets_safe_obj, secret_type)

    if not secret_dict.get("FolderId"):
        common.show_error(
            f"Cannot update secret {SECRET_ID}: its folder ID was not returned.",
            logger,
        )

    # creating file if the secret is a file secret
    if secret_type == FILE_TYPE:
        common.create_file(FILE_NAME, FILE_CONTENT, logger)

    try:
        secrets_safe_obj.update_secret(**build_update_kwargs(settings, secret_dict))

        logger.info("Secret updated successfully")
    except exceptions.UpdateError as e:
        if is_no_content_success(e):
            utils.print_log(
                logger,
                "The library reported the API's 204 No Content answer as an "
                "error; the secret was updated.",
                logging.WARNING,
            )
            logger.info("Secret updated successfully")
            return

        common.show_error(
            f"Error updating secret {SECRET_ID}: {e}. Check that the secret "
            f"exists, that it is a {secret_type} secret, and that the "
            "application is allowed to edit it.",
            logger,
        )

    except (exceptions.OptionsError, exceptions.IncompleteArgumentsError) as e:
        common.show_error(f"Invalid or missing parameters: {e}", logger)

    except FileNotFoundError as e:
        common.show_error(f"Invalid or missing file path: {e}", logger)


def set_authentication(
    session: requests.Session,
) -> authentication.Authentication:
    """
    Configure and authenticate against the Secrets Safe API.

    This function prepares certificates, selects the authentication method
    (API Key or OAuth client credentials), and validates API access.

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

    # The recommended version is 3.1 (3.3 is required for TOTP). If no version
    # is specified, the default API version 3.0 will be used
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

    Orchestrates the workflow to validate the inputs, authenticate, update a
    secret, and properly close the API session.
    """
    mask_sensitive_inputs()
    # Validate the inputs before authenticating, so bad input fails fast.
    settings = validate_inputs()

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
            # Sign out on failures too (show_error exits with SystemExit), so
            # the API session isn't left open until it expires.
            try:
                update_secret(authentication_obj, settings)
            finally:
                authentication_obj.sign_app_out()

    except Exception as e:
        common.show_error(f"An unexpected error occurred: {e}", logger)


if __name__ == "__main__":
    main()

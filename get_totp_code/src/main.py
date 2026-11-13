"""
Secrets Safe Get TOTP Code Action

Retrieves the current one-time (TOTP) code of one TOTP-enabled credential
secret from BeyondTrust Secrets Safe and exposes it as the masked GitHub Actions
output totp_code.

API: GET Secrets-Safe/Secrets/{secretId}/totp/code
"""

import logging
import os
import uuid
from typing import Dict

import requests
from secrets_safe_library import authentication, exceptions, secrets_safe
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
API_VERSION = env.get("API_VERSION", "").strip() or "3.3"

SECRET_ID = env.get("INPUT_SECRET_ID", "").strip() or None
OUTPUT_NAME = "totp_code"
# Outputs for the validity window of the code, keyed by the API response field.
# They are timestamps, not secrets, so they are not masked.
VALIDITY_OUTPUTS = {"ValidFromUtc": "valid_from_utc", "ValidToUtc": "valid_to_utc"}

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

# Unlike the other actions, 400 is not retried: the TOTP code endpoint returns
# 400 for a text or file secret, which must reach the library as a response so
# it raises SecretTypeNotSupportedError. Retrying it would fail with a generic
# RetryError after wasting the retries.
RETRY_STATUS_CODES = [408, 500, 502, 503, 504]


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


def validate_secret_id(secret_id: str | None) -> str:
    """
    Validates the secret_id input before authenticating, so bad input fails
    without making any API call. The ID is placed in the request path, so
    anything that is not a GUID is rejected.

    Arguments:
        secret_id (str | None): Raw value of the secret_id input.

    Returns:
        str: The secret ID.
    """

    if not secret_id:
        common.show_error("Nothing to do, SECRET_ID parameter is empty", logger)

    if not is_guid(secret_id):
        common.show_error(
            f"Invalid secret_id {repr(secret_id)}: must be a secret GUID", logger
        )

    return secret_id


def get_totp_code(
    secrets_safe_obj: secrets_safe.SecretsSafe, secret_id: str
) -> Dict[str, str]:
    """
    Retrieves the current TOTP code of one credential secret.

    Arguments:
        secrets_safe_obj (SecretsSafe): Secrets Safe client.
        secret_id (str): The credential secret ID (GUID).

    Returns:
        Dict[str, str]: The output values: totp_code, plus valid_from_utc
        (inclusive) and valid_to_utc (exclusive), each "" when the response
        does not include it.
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

    values = {OUTPUT_NAME: str(code)}
    for field, output_name in VALIDITY_OUTPUTS.items():
        value = response.get(field)
        values[output_name] = "" if value is None else str(value)

    return values


def write_totp_code(secrets_safe_obj: secrets_safe.SecretsSafe, secret_id: str) -> None:
    """
    Retrieves the current TOTP code of the secret and writes it to the
    totp_code output, with its validity window in valid_from_utc and
    valid_to_utc. The code is masked before anything is written, and is only
    valid for the current TOTP period.

    Arguments:
        secrets_safe_obj (SecretsSafe): Secrets Safe client.
        secret_id (str): The credential secret ID (GUID).

    Returns:
        None
    """

    values = get_totp_code(secrets_safe_obj, secret_id)
    outputs.mask_secret(values[OUTPUT_NAME])
    for name, value in values.items():
        outputs.append_output(name, value)


def set_authentication(session: requests.Session) -> authentication.Authentication:
    """
    Authenticates against Secrets Safe with an API key (optionally with a
    client certificate) or OAuth client credentials.

    Arguments:
        session (requests.Session): Session used for every API call.

    Returns:
        authentication.Authentication: Authenticated client.
    """

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
    Validates the input, authenticates, writes the TOTP code to the totp_code
    output and signs out.
    """

    # Validate the input before authenticating, so bad input fails fast.
    secret_id = validate_secret_id(SECRET_ID)

    try:
        with api_client.create_session(RETRY_STATUS_CODES) as session:
            authentication_obj = set_authentication(session)
            # Sign out on failures too (show_error exits with SystemExit), so
            # the API session isn't left open until it expires.
            try:
                secrets_safe_obj = secrets_safe.SecretsSafe(
                    authentication=authentication_obj, logger=logger
                )
                write_totp_code(secrets_safe_obj, secret_id)
            finally:
                authentication_obj.sign_app_out()

    except Exception as e:
        common.show_error(e, logger)


if __name__ == "__main__":
    main()

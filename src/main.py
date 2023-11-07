import os
import sys
import uuid
import logging
import json

from secrets_safe_library import secrets, secrets_safe, authentication, utils, managed_account
from github_action_utils import error

env = os.environ
CLIENT_ID = env["CLIENT_ID"] if 'CLIENT_ID' in env else None
CLIENT_SECRET = env["CLIENT_SECRET"] if 'CLIENT_SECRET' in env else None
API_URL = env["API_URL"] if 'API_URL' in env else None
VERIFY_CA = False if 'VERIFY_CA' in env and env['VERIFY_CA'].lower() == 'false' else True

SECRET_PATH = env['INPUT_SECRET_PATH'].strip() if 'INPUT_SECRET_PATH' in env else None
MANAGED_ACCOUNT_PATH = env['INPUT_MANAGED_ACCOUNT_PATH'].strip() if 'INPUT_MANAGED_ACCOUNT_PATH' in env else None
PATH_SEPARATOR = env['PATH_SEPARATOR'].strip() if 'PATH_SEPARATOR' in env and len(env['PATH_SEPARATOR'].strip()) == 1 else "/"

LOG_LEVEL = env['LOG_LEVEL'].strip().upper() if 'LOG_LEVEL' in env else "INFO"

LOG_LEVELS = {
    "CRITICAL": 50,
    "FATAL": 50,
    "ERROR": 40,
    "WARNING": 30,
    "WARN": 30,
    "INFO": 20,
    "DEBUG": 10,
    "NOTSET": 0
}

LOGGER_NAME = "custom_logger"

logging.basicConfig(
    format = '%(asctime)-5s %(name)-15s %(levelname)-8s %(message)s', 
    level  = LOG_LEVELS[LOG_LEVEL]
)

logger = logging.getLogger(LOGGER_NAME)

CERTIFICATE = env['CERTIFICATE'].replace(r'\n', '\n') if 'CERTIFICATE' in env else None
CERTIFICATE_KEY = env['CERTIFICATE_KEY'].replace(r'\n', '\n') if 'CERTIFICATE_KEY' in env else None

if CERTIFICATE:
    CERTIFICATE = f"{CERTIFICATE}\n"
if CERTIFICATE_KEY:
    CERTIFICATE_KEY = f"{CERTIFICATE_KEY}\n"

COMMAND_MARKER: str = "::"

def append_output(name, value):
    """
    Create a variable in step output.
    Arguments:
        output variable name
        output content
    Returns:
    """

    with open(os.environ['GITHUB_OUTPUT'], 'a') as fh:
        delimiter = uuid.uuid1()
        print(f'{name}<<{delimiter}', file=fh)
        print(value, file=fh)
        print(delimiter, file=fh)


def mask_secret(command, secret_to_mask):
    """
    Mask secret to avoid print it out in console.
    Arguments:
        Masking command
        Secret to mask
    Returns:
    """

    lines = secret_to_mask.split('\n')
    for line in lines:
        if line.strip() != "":
            full_command = (
                f"{COMMAND_MARKER}{command} "
                f"{COMMAND_MARKER}{line}"
            )   
            print(full_command)


def show_error(error_message):
    """
    Show error
    Arguments:
        Error message
    Returns:
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
    
    
def get_secrets(secret_obj, secrets):
    """
    Call secret safe library
    Arguments:
        Secret obj instance
        List of secrets or managed acocunts
    Returns:
    """

    try:
        secrets_to_retrive = json.loads(secrets)
    except Exception as e:
        show_error(f"String could not be converted to JSON: {e}")
    
    if not isinstance(secrets_to_retrive, list):
        secrets_to_retrive = [secrets_to_retrive]
    
    if len(secrets_to_retrive) > 20:
        show_error("The Secrets Safe action can request a maximum of 20 secrets and 20 managed accounts each run")

    for secret_to_retrieve in secrets_to_retrive:
        
        if 'path' not in secret_to_retrieve:
            show_error(f"Invalid JSON, validate path attribute name")
        
        if 'output_id' not in secret_to_retrieve:
            show_error(f"Invalid JSON, validate output_id attribute name")

        get_secret_response = secret_obj.get_secret(secret_to_retrieve['path'])
        
        mask_secret("add-mask", get_secret_response)
        append_output(secret_to_retrieve['output_id'], get_secret_response)
    

def main():
    try:
        authentication_obj = authentication.Authentication(API_URL, 
                                                    CLIENT_ID, 
                                                    CLIENT_SECRET,
                                                    CERTIFICATE,
                                                    CERTIFICATE_KEY,
                                                    VERIFY_CA,
                                                    logger)
        
        get_api_access_response = authentication_obj.get_api_access()
        
        if get_api_access_response.status_code != 200:
            error_message = f"Please check credentials, error {get_api_access_response.text}"
            show_error(error_message)
        
        if not SECRET_PATH and not MANAGED_ACCOUNT_PATH:
            error_message = f"Nothing to do, SECRET and MANAGED_ACCOUNT parameters are empty"
            show_error(error_message)

        if SECRET_PATH:
            secrets_safe_obj = secrets_safe.SecretsSafe(authentication=authentication_obj, logger=logger, separator=PATH_SEPARATOR)
            get_secrets(secrets_safe_obj, SECRET_PATH)
        
        if MANAGED_ACCOUNT_PATH:
            managed_account_obj = managed_account.ManagedAccount(authentication=authentication_obj, logger=logger, separator=PATH_SEPARATOR)
            get_secrets(managed_account_obj, MANAGED_ACCOUNT_PATH)


    except Exception as e:
        show_error(e)

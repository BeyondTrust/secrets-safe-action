import os
import sys
import uuid
import logging

from secrets_safe_library import secrets_safe, authentication, utils, managed_account
from github_action_utils import error

env = os.environ

CLIENT_ID = env["CLIENT_ID"] if 'CLIENT_ID' in env else None
CLIENT_SECRET = env["CLIENT_SECRET"] if 'CLIENT_SECRET' in env else None
API_URL = env["API_URL"] if 'API_URL' in env else None
VERIFY_CA = True if 'VERIFY_CA' in env and env['VERIFY_CA'].lower() == 'true' else False

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

CERTIFICATE = f"{CERTIFICATE}\n"
CERTIFICATE_KEY = f"{CERTIFICATE_KEY}\n"

COMMAND_MARKER: str = "::"

def append_output(name, value):
    with open(os.environ['GITHUB_OUTPUT'], 'a') as fh:
        delimiter = uuid.uuid1()
        print(f'{name}<<{delimiter}', file=fh)
        print(value, file=fh)
        print(delimiter, file=fh)


def print_command(command, command_message):
    lines = command_message.split('\n')
    for line in lines:
        if line.strip() != "":
            full_command = (
                f"{COMMAND_MARKER}{command} "
                f"{COMMAND_MARKER}{line}"
            )   
            print(full_command)


def show_error(error_message):
    error(
            error_message,
            title="Action Failed",
            col=1,
            end_column=2,
            line=4,
            end_line=5,
        )


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
            utils.print_log(logger, error_message, logging.ERROR)
            show_error(error_message)
            sys.exit(1)
            
        if not SECRET_PATH and not MANAGED_ACCOUNT_PATH:
            error_message = f"Nothing to do, SECRET and MANAGED_ACCOUNT parameters are empty"
            utils.print_log(logger, error_message, logging.ERROR)
            show_error(error_message)
            sys.exit(1)

        if SECRET_PATH:
            secrets_safe_obj = secrets_safe.SecretsSafe(authentication=authentication_obj, logger=logger, separator=PATH_SEPARATOR)
            get_secret_response = secrets_safe_obj.get_secret(SECRET_PATH)
            print_command("add-mask", get_secret_response)
            append_output("secret", get_secret_response)
        
        if MANAGED_ACCOUNT_PATH:
            managed_account_obj = managed_account.ManagedAccount(authentication=authentication_obj, logger=logger, separator=PATH_SEPARATOR)
            get_managed_account_response = managed_account_obj.get_secret(MANAGED_ACCOUNT_PATH)
            print_command("add-mask", get_managed_account_response)
            append_output("managed_account", get_managed_account_response)
            
    except Exception as e:
        show_error(e)
        utils.print_log(logger, e, logging.ERROR)
        sys.exit(1)

# calling main method
main()
import os
import logging
from secrets_safe_library import secrets_safe, authentication, utils, managed_account
import uuid

from github_action_utils import add_mask, set_output, _print_command

env = os.environ

CLIENT_ID = env["CLIENT_ID"] if 'CLIENT_ID' in env else None
CLIENT_SECRET = env["CLIENT_SECRET"] if 'CLIENT_SECRET' in env else None
API_URL = env["API_URL"] if 'API_URL' in env else None
VERIFY_CA = True if 'VERIFY_CA' in env and env['VERIFY_CA'].lower() == 'true' else False

SECRET_PATH = env['INPUT_SECRET_PATH'].strip() if 'INPUT_SECRET_PATH' in env else None
MANAGED_ACCOUNT_PATH = env['INPUT_MANAGED_ACCOUNT_PATH'].strip() if 'INPUT_MANAGED_ACCOUNT_PATH' in env else None

PATH_SEPARATOR = env['PATH_SEPARATOR'].strip() if 'PATH_SEPARATOR' in env and len(env['PATH_SEPARATOR'].strip()) == 1 else "/"

LOGGER_NAME = "custom_logger"

logging.basicConfig(
    format = '%(asctime)-5s %(name)-15s %(levelname)-8s %(message)s', 
    level  = logging.DEBUG
)

logger = logging.getLogger(LOGGER_NAME)

CERTIFICATE = env['CERTIFICATE'].replace(r'\n', '\n') if 'CERTIFICATE' in env else None
CERTIFICATE_KEY = env['CERTIFICATE_KEY'].replace(r'\n', '\n') if 'CERTIFICATE_KEY' in env else None


def append_output(name, value):
    with open(os.environ['GITHUB_OUTPUT'], 'a') as fh:
        delimiter = uuid.uuid1()
        print(f'{name}<<{delimiter}', file=fh)
        print(value, file=fh)
        print(delimiter, file=fh)


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
            utils.print_log(logger, f"Please check credentials, error {get_api_access_response.text}", logging.ERROR)
            return
            
        if not SECRET_PATH and not MANAGED_ACCOUNT_PATH:
            utils.print_log(logger, f"Nothing to do, SECRET and MANAGED_ACCOUNT parameters are empty!", logging.ERROR)
            return

        if SECRET_PATH:
            secrets_safe_obj = secrets_safe.SecretsSafe(authentication=authentication_obj, logger=logger, separator=PATH_SEPARATOR)
            get_secret_response = secrets_safe_obj.get_secret(SECRET_PATH)
            #_print_command("add-mask", get_secret_response, use_subprocess=False, escape_message=False)
            set_output("secret", get_secret_response)
        
        if MANAGED_ACCOUNT_PATH:
            managed_account_obj = managed_account.ManagedAccount(authentication=authentication_obj, logger=logger, separator=PATH_SEPARATOR)
            get_managed_account_response = managed_account_obj.get_secret(MANAGED_ACCOUNT_PATH)
            #_print_command("add-mask", get_managed_account_response, use_subprocess=False, escape_message=False)
            set_output("managed_account", get_managed_account_response)


        #_print_command(command="add-mask", command_message=CLIENT_ID, use_subprocess=True, escape_message=False)
        set_output("client_id", CLIENT_ID)

        # masking certificate
        _print_command(command="add-mask", command_message=CERTIFICATE, use_subprocess=True, escape_message=False)
        set_output("certificate", CERTIFICATE)


    except Exception as e:
        utils.print_log(logger, e, logging.ERROR)

# calling main method
main()

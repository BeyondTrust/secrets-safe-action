import os
import logging
from secrets_safe_library import secrets_safe, authentication, utils

env = os.environ

PASSWORD_SAFE_CLIENT_ID = env["CLIENT-ID"] if 'CLIENT-ID' in env else None
PASSWORD_SAFE_CLIENT_SECRET = env["CLIENT-SECRET"] if 'CLIENT-SECRET' in env else None
PASSWORD_SAFE_API_URL = env["API_URL"] if 'API_URL' in env else None
VERIFY_CA = True if 'VERIFY-CA' in env and env['VERIFY-CA'].lower() == 'true' else False
SECRET = env['INPUT_SECRET'].strip() if 'INPUT_SECRET' in env else None
SECRET_LIST = env['SECRET_LIST'].strip().split(",") if 'SECRET_LIST' in env and env['SECRET_LIST'].strip() != "" else None

PATH_SEPARATOR = env['PATH_SEPARATOR'].strip() if 'PATH_SEPARATOR' in env else "/"

LOGGER_NAME = "custom_logger"

logging.basicConfig(
    format = '%(asctime)-5s %(name)-15s %(levelname)-8s %(message)s', 
    level  = logging.DEBUG
)

logger = logging.getLogger(LOGGER_NAME)

CERTIFICATE = env['CERTIFICATE'].replace(r'\n', '\n') if 'CERTIFICATE' in env else None
CERTIFICATE_KEY = env['CERTIFICATE_KEY'].replace(r'\n', '\n') if 'CERTIFICATE_KEY' in env else None

def main():
    try:
        authentication_obj = authentication.Authentication(PASSWORD_SAFE_API_URL, 
                                                    PASSWORD_SAFE_CLIENT_ID, 
                                                    PASSWORD_SAFE_CLIENT_SECRET,
                                                    CERTIFICATE,
                                                    CERTIFICATE_KEY,
                                                    VERIFY_CA,
                                                    logger)
        
        
        get_api_access_response = authentication_obj.get_api_access()
        
        if get_api_access_response.status_code == 200:
                secrets_safe_obj = secrets_safe.SecretsSafe(authentication=authentication_obj, logger=logger, separator=PATH_SEPARATOR)
                if SECRET or SECRET_LIST:
                    if SECRET:
                        get_secret_response = secrets_safe_obj.get_secret(SECRET)
                        utils.print_log(logger, f"=> Retrive secret: {get_secret_response}", logging.DEBUG)
                    if SECRET_LIST:
                        get_secrets_response = secrets_safe_obj.get_secrets(SECRET_LIST)
                        utils.print_log(logger, f"=> Retrive secrets: {get_secrets_response}", logging.DEBUG)
                else:
                    utils.print_log(logger, f"Nothing to do, SECRET and SECRET_LIST parameters are empty!", logging.ERROR)
        else:
            utils.print_log(logger, f"Please check credentials, error {get_api_access_response.text}", logging.ERROR)
    except Exception as e:
        utils.print_log(logger, e, logging.ERROR)

# calling main method
main()

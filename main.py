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
            #set_output("secret", get_secret_response)
        
        if MANAGED_ACCOUNT_PATH:
            managed_account_obj = managed_account.ManagedAccount(authentication=authentication_obj, logger=logger, separator=PATH_SEPARATOR)
            get_managed_account_response = managed_account_obj.get_secret(MANAGED_ACCOUNT_PATH)
            #_print_command("add-mask", get_managed_account_response, use_subprocess=False, escape_message=False)
            #set_output("managed_account", get_managed_account_response)

        client_id = "6138d050-e266-4b05-9ced-35e7dd5093ae"
        _print_command(command="add-mask", command_message=client_id, use_subprocess=False, escape_message=False)
        #set_output("client_id", client_id)
        append_output("client_id", client_id)
        
        certificate='''-----dd
MIIDZDCCAkygAwIBAgIRANRWB3YpIKxHsgc/yDDu9Z4wDQYJKoZIhvcNAQELBQAw
UzEPMA0GA1UEBhMGQ2FuYWRhMRQwEgYDVQQLEwtEZXZlbG9wbWVudDEUMBIGA1UE
ChMLQmV5b25kVHJ1c3QxFDASBgNVBAMTC1BTIENsb3VkIENBMB4XDTIzMDYyNzE4
NDQyNVoXDTMzMDYyNzE4NDQyNVowXzEPMA0GA1UEBhMGQ2FuYWRhMRQwEgYDVQQL
EwtEZXZlbG9wbWVudDEUMBIGA1UEChMLQmV5b25kVHJ1c3QxIDAeBgNVBAMTF1BT
IENsb3VkIEF1dGhlbnRpY2F0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA1SvEvI2sCA7gchz8nluYj6I9uJHD98ntzOfLdGflQ0JDgC8o+ltvAWSk
Ga7iortNxQDmf+g0ZJa7OHZJr5Fs4XW38MoNWp24ny1rzUZtPcBhp0/2OwRjAPjz
ZEwtJXgz6zSvV7KKq0nN/sv9hshaHrSljjOhjQjfZCRfeTf1p5Dv/oJEWA2Gsx6O
xeIEDaDGjfI9s30TYbR+CwjFckuQdkhOR0kauY5znPN7LftlauYXesDG66l2SPTQ
S0U0EKfTdpZZXn+PeSqo9GTGrVktQJU8+xRqNsnxDQt4YSibLfHnO5fPiLv42DMF
vO55TcKJncjP9Qfwms1Woe5C1hOB3QIDAQABoycwJTALBgNVHQ8EBAMCBJAwFgYD
VR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggEBABFCcvHK+rK/
DYhqkZtbEEGaU2SC7xxLDIeuueJkmDr1Y+k2id9rLsjMgqkm08aoZ6DuOEBrWau/
toKN4wLt7966B+3WJkHFtM7KAiiF4pDVz6t5G1ugZPnarl9K1dj7MqwOWh3mTMbB
X4pq0LSgiLXINHBqph6XOdE9s7Sa9IA+KyVzAw/qkv5idM6pHDUGj9/SfOZ+R2+6
uAGqR/xEioN+gcRpleKv8i675KqAiNGtS5qgc1xer1mm+NZ+W8FF07Zc96GZTF0M
YM8sw5V6luXKxdaNeqi4b/8/jvNogYzjw4c+j6mtElc4jmXGaLrDVJaC3Bysiyjs
Fnc9up2a1o0=
---------
'''


        #certificate = "-----BEGIN CERTIFICATE-----\nMIIDZDCCAkygAwIBAgIRANRWB3YpIKxHsgc/yDDu9Z4wDQYJKoZIhvcNAQELBQAw\nUzEPMA0GA1UEBhMGQ2FuYWRhMRQwEgYDVQQLEwtEZXZlbG9wbWVudDEUMBIGA1UE\nChMLQmV5b25kVHJ1c3QxFDASBgNVBAMTC1BTIENsb3VkIENBMB4XDTIzMDYyNzE4\nNDQyNVoXDTMzMDYyNzE4NDQyNVowXzEPMA0GA1UEBhMGQ2FuYWRhMRQwEgYDVQQL\nEwtEZXZlbG9wbWVudDEUMBIGA1UEChMLQmV5b25kVHJ1c3QxIDAeBgNVBAMTF1BT\nIENsb3VkIEF1dGhlbnRpY2F0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\nCgKCAQEA1SvEvI2sCA7gchz8nluYj6I9uJHD98ntzOfLdGflQ0JDgC8o+ltvAWSk\nGa7iortNxQDmf+g0ZJa7OHZJr5Fs4XW38MoNWp24ny1rzUZtPcBhp0/2OwRjAPjz\nZEwtJXgz6zSvV7KKq0nN/sv9hshaHrSljjOhjQjfZCRfeTf1p5Dv/oJEWA2Gsx6O\nxeIEDaDGjfI9s30TYbR+CwjFckuQdkhOR0kauY5znPN7LftlauYXesDG66l2SPTQ\nS0U0EKfTdpZZXn+PeSqo9GTGrVktQJU8+xRqNsnxDQt4YSibLfHnO5fPiLv42DMF\nvO55TcKJncjP9Qfwms1Woe5C1hOB3QIDAQABoycwJTALBgNVHQ8EBAMCBJAwFgYD\nVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggEBABFCcvHK+rK/\nDYhqkZtbEEGaU2SC7xxLDIeuueJkmDr1Y+k2id9rLsjMgqkm08aoZ6DuOEBrWau/\ntoKN4wLt7966B+3WJkHFtM7KAiiF4pDVz6t5G1ugZPnarl9K1dj7MqwOWh3mTMbB\nX4pq0LSgiLXINHBqph6XOdE9s7Sa9IA+KyVzAw/qkv5idM6pHDUGj9/SfOZ+R2+6\nuAGqR/xEioN+gcRpleKv8i675KqAiNGtS5qgc1xer1mm+NZ+W8FF07Zc96GZTF0M\nYM8sw5V6luXKxdaNeqi4b/8/jvNogYzjw4c+j6mtElc4jmXGaLrDVJaC3Bysiyjs\nFnc9up2a1o0=\n-----END CERTIFICATE-----\n"
        print("Testing")
        utils.print_log(logger, certificate, logging.INFO)
        #_print_command(command="add-mask", command_message=certificate, use_subprocess=False, escape_message=False)
        #append_output("certificate", certificate)
        #set_output("certificate", certificate)


    except Exception as e:
        utils.print_log(logger, e, logging.ERROR)

# calling main method
main()

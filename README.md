<a href="https://www.beyondtrust.com">
    <img src="images/beyondtrust_logo.svg" alt="BeyondTrust" title="BeyondTrust" align="right" height="30">
</a>

# Secrets Safe Action
[![License](https://img.shields.io/badge/license-MIT%20-brightgreen.svg)](LICENSE)


This action retrieves ASCII secrets from BeyondTrust Secrets Safe and makes them available in the GitHub action workflow. The secrets are requested using either a Secrets Safe path or a path to a managed account which is composed of a managed system and account. The action output returns the secrets with an ID specified in the action request. This allows immediate retrieval and usage of secrets from your BeyondTrust Secrets Safe instance. Retrieved secrets are masked on the GitHub runner used to retrieve the secret. This helps reduce the chance that secrets are printed or logged by accident.

**Warning:** It is important that security-minded engineers review workflow composition before changes are run with access to secrets.

## Prerequisites
The Secrets Safe action supports retrieval of secrets from BeyondInsight/Password Safe versions 23.1 or greater.

For this extension to retrieve a secret the Secrets Safe instance must be preconfigured with the secret in question and must be authorized to read it.

Runners must use a Linux operating system. Additionally, self-hosted runners will need Docker installed.

## Inputs

### `client_id`

**Required:** API OAuth Client ID.

### `client_secret`

**Required:** API OAuth Client Secret.

### `api_url`

**Required:** BeyondTrust Password Safe API URL.
```
https://example.com:443/beyondtrust/api/public/V3
```

### `secret_path`
**Required:** Path of the secret to retrieve.
```json
[
  {
    "path": "folder1/folder2/title",
    "output_id": "title"
  },
  {
    "path": "folder1/folder2/title2",
    "output_id": "title2"
  }
]
```

### `managed_account_path`

**Required:** Path of the Managed account to retrieve.
```json
[
  {
    "path": "system/account",
    "output_id": "account"
  },
  {
    "path": "system/account2",
    "output_id": "account2"
  }
]
```

### `certificate`

Content of the certificate (cert.pem) for use when authenticating with an API key using a Client Certificate.

### `certificate_key`

Certificate private key (key.pem). For use when authenticating with an API key

### `verify_ca`

Indicates whether to verify the certificate authority on the Secrets Safe instance. Defaults to true if not specified.
```
VERIFY_CA: true
```
Warning: false is insecure, instructs the Secrets Safe custom action not to verify the certificate authority.

### `log_level`
Level of logging verbosity. Default INFO.

Levels: CRITICAL, FATAL, ERROR, WARNING, WARN, INFO, DEBUG, NOTSET

## Outputs

### `output_id`

The action stores the retrieved secrets in output variables defined by the end user. The <output_id> must be a unique identifier within the outputs object. The <output_id> must start with a letter or _ and contain only alphanumeric characters, -, or _. See `secret_path` and `managed_account_path`.


## Example usage

```yaml
uses: BeyondTrust/secrets-safe-action@v1
env:
  API_URL: ${{vars.API_URL}}
  VERIFY_CA: ${{vars.VERIFY_CA}}
  CLIENT_ID: ${{secrets.CLIENT_ID}}
  CLIENT_SECRET: ${{secrets.CLIENT_SECRET}}
  CERTIFICATE: ${{secrets.CERTIFICATE}}
  CERTIFICATE_KEY: ${{secrets.CERTIFICATE_KEY}}
with:
  SECRET_PATH: '{"path": "folder1/folder2/title", "output_id": "title"}'
  MANAGED_ACCOUNT_PATH: '{"path": "system/account", "output_id": "account"}'
```

## Extracting Client Secret
Download the pfx certificate from Secrets Safe and extract the certificate and the key to be pasted into a GitHub secret.

~~~~
openssl pkcs12 -in client_certificate.pfx -nocerts -out ps_key.pem -nodes

openssl pkcs12 -in client_certificate.pfx -clcerts -nokeys -out ps_cert.pem
~~~~

Copy the text from the ps_key.pem to a secret.
```
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
```
Copy the text from the ps_cert.pem to a secret.
```
-----BEGIN CERTIFICATE----- 
... 
-----END CERTIFICATE-----
```

## Get Help
- Contact [BeyondTrust support](https://www.beyondtrust.com/docs/index.htm#support)
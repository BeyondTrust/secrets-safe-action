<a href="https://www.beyondtrust.com">
    <img src="images/beyondtrust_logo.svg" alt="BeyondTrust" title="BeyondTrust" align="right" height="30">
</a>

# Get Secrets Action
[![License](https://img.shields.io/badge/license-MIT%20-brightgreen.svg)](LICENSE)


This action retrieves ASCII secrets from BeyondTrust Secrets Safe and makes them available in the GitHub action workflow. The secrets are requested using either a Secrets Safe path or a path to a managed account which is composed of a managed system and account. The action output returns the secrets with an ID specified in the action request. This allows immediate retrieval and usage of secrets from your BeyondTrust Secrets Safe instance. Retrieved secrets are masked on the GitHub runner used to retrieve the secret. This helps reduce the chance that secrets are printed or logged by accident.

**Warning:** It is important that security-minded engineers review workflow composition before changes are run with access to secrets.

## Prerequisites
The Secrets Safe action supports retrieval of secrets from BeyondInsight/Password Safe versions 23.1 or greater.

For this extension to retrieve a secret the Secrets Safe instance must be preconfigured with the secret in question and must be authorized to read it.

Runners must use a Linux operating system. Additionally, self-hosted runners will need Docker installed.

## Inputs

### `api_key`

**Optional:** The API Key configured in BeyondInsight for your application. If not set, then client credentials must be provided.

### `client_id`

**Required:** API OAuth Client ID.

### `client_secret`

**Required:** API OAuth Client Secret.

### `api_url`

**Required:** BeyondTrust Password Safe API URL.
```
https://example.com:443/BeyondTrust/api/public/v3
```

### `api_version`

**Optional:** The recommended version is 3.1. If no version is specified, the default API version 3.0 will be used

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

### `decrypt`
**Optional:** When set to true, the decrypted password field is returned. When set to false, the password field is omitted. This option applies only to secret retrieval type. Defaults to true if not specified.

## Outputs

### `output_id`

The action stores the retrieved secrets in output variables defined by the end user. The <output_id> must be a unique identifier within the outputs object. The <output_id> must start with a letter or _ and contain only alphanumeric characters, -, or _. See `secret_path` and `managed_account_path`.


## Example usage

```yaml
uses: BeyondTrust/secrets-safe-action@9e2bbfd1aa4ae265a03d6a212c42e193551af485 # v1.0.0
env:
  API_URL: ${{vars.API_URL}}
  VERIFY_CA: ${{vars.VERIFY_CA}}
  CLIENT_ID: ${{secrets.CLIENT_ID}}
  CLIENT_SECRET: ${{secrets.CLIENT_SECRET}}
  CERTIFICATE: ${{secrets.CERTIFICATE}}
  CERTIFICATE_KEY: ${{secrets.CERTIFICATE_KEY}}
  API_VERSION: ${{vars.API_VERSION}}
with:
  SECRET_PATH: '{"path": "folder1/folder2/title", "output_id": "title"}'
  MANAGED_ACCOUNT_PATH: '{"path": "system/account", "output_id": "account"}'
```

# Create Secrets Action

This action creates new secrets in BeyondTrust Secrets Safe. The action supports creating different types of secrets including credentials (username/password), text secrets, and file-based secrets. Created secrets are stored in specified folders within your Secrets Safe instance.

### Authentication

The action supports two authentication methods:
- **API Key Authentication**: Using an API key with optional client certificates
- **OAuth Client Credentials**: Using client ID and client secret

### Prerequisites

- Appropriate permissions to create secrets in the target folder
- Target parent folder must exist in Secrets Safe
- Runners must use a Linux operating system with Docker installed

## Create Secret Inputs

### Authentication Inputs

#### `api_key`
**Optional:** The API Key configured in BeyondInsight for your application. If not set, then client credentials must be provided.

#### `client_id`
**Optional:** The API OAuth Client ID configured in BeyondInsight for your application.

#### `client_secret`
**Optional:** The API OAuth Client Secret configured in BeyondInsight for your application.

#### `api_url`
**Required:** The API URL for the Secrets Safe instance.
```
https://example.com:443/BeyondTrust/api/public/v3
```

#### `api_version`
**Optional:** The recommended version is 3.1. If no version is specified, the default API version 3.0 will be used.

#### `verify_ca`
**Optional:** Indicates whether to verify the certificate authority on the Secrets Safe instance. Defaults to `true`.

#### `certificate`
**Optional:** Content of the certificate (cert.pem) for use when authenticating with an API key using a Client Certificate.

#### `certificate_key`
**Optional:** Certificate private key (key.pem) for use when authenticating with an API key using a Client Certificate.

### Secret Configuration Inputs

#### `secret_title`
**Required:** Title of the secret to be created. Must be unique within the parent folder.

#### `parent_folder_name` 
**Required:** Name of the parent folder where the secret will be created. The folder must exist in Secrets Safe.

#### `secret_description`
**Optional:** Description of the secret for documentation purposes.

### Secret Content Inputs

#### For Credential Secrets:

##### `username`
**Optional:** Username for credential type secrets.

##### `password`
**Optional:** Password for credential type secrets.

#### For Text Secrets:

##### `text`
**Optional:** Text content for text type secrets.

#### For File Secrets:

##### `file_content`
**Optional:** File content for file type secrets (base64 encoded or plain text).

##### `file_name`
**Optional:** File name for file type secrets.

### Advanced Configuration Inputs

#### `owner_id`
**Optional:** ID of the owner for the secret.

#### `owner_type`
**Optional:** Type of the owner (`User` or `Group`).

#### `owners`
**Optional:** List of owners for the secret in JSON format.
```json
[{"user_id": 123, "owner_id": 123}]
```

#### `password_rule_id`
**Optional:** Password rule ID for credential secrets to enforce password policies.

#### `notes`
**Optional:** Additional notes for the secret.

#### `urls`
**Optional:** URLs associated with the secret in JSON format.
```json
[{"url": "https://example.com"}]
```

#### `log_level`
**Optional:** Level of logging verbosity. Default: `INFO`
Levels: `CRITICAL`, `FATAL`, `ERROR`, `WARNING`, `WARN`, `INFO`, `DEBUG`, `NOTSET`

## Create Secret Examples

### Example 1: Create Credential Secret

```yaml
- name: Create credential secret
  id: credential_secret
  uses: BeyondTrust/secrets-safe-action/create_secret@9e2bbfd1aa4ae265a03d6a212c42e193551af485 # v1.0.0
  env:   
    API_URL: ${{vars.API_URL}}
    CLIENT_ID: ${{secrets.CLIENT_ID}}
    CLIENT_SECRET: ${{secrets.CLIENT_SECRET}}
    VERIFY_CA: ${{vars.VERIFY_CA}}
    LOG_LEVEL: ${{vars.LOG_LEVEL}}
    API_VERSION: "3.1"
  with:
    SECRET_TITLE: "Secret Title"
    PARENT_FOLDER_NAME: "Parent folder name"
    SECRET_DESCRIPTION: ""
    USERNAME: "username"
    PASSWORD: "p4ssw0rd!#"
    TEXT: ""
    FILE_NAME: ""
    FILE_CONTENT: ""
    OWNER_ID: "1"
    OWNER_TYPE: "User"
    NOTES: ""
    OWNERS: '[{"owner_id": 1}]'
```

### Example 2: Create Text Secret

```yaml
- name: Create Text secret
  id: text_secret
  uses: BeyondTrust/secrets-safe-action/create_secret@9e2bbfd1aa4ae265a03d6a212c42e193551af485 # v1.0.0
  env:   
    API_URL: ${{vars.API_URL}}
    CLIENT_ID: ${{secrets.CLIENT_ID}}
    CLIENT_SECRET: ${{secrets.CLIENT_SECRET}}
    VERIFY_CA: ${{vars.VERIFY_CA}}
    LOG_LEVEL: ${{vars.LOG_LEVEL}}
    API_VERSION: "3.1"
  with:
    SECRET_TITLE: "Secret Title"
    PARENT_FOLDER_NAME: "Parent folder name"
    SECRET_DESCRIPTION: ""
    USERNAME: ""
    PASSWORD: ""
    TEXT: "p4ssw0rd!#"
    FILE_NAME: ""
    FILE_CONTENT: ""
    OWNER_ID: "1"
    OWNER_TYPE: "User"
    NOTES: ""
    OWNERS: '[{"owner_id": 1}]'
```

### Example 3: Create File Secret

```yaml
- name: Create File secret
  id: file_secret
  uses: BeyondTrust/secrets-safe-action/create_secret@9e2bbfd1aa4ae265a03d6a212c42e193551af485 # v1.0.0
  env:   
    API_URL: ${{vars.API_URL}}
    CLIENT_ID: ${{secrets.CLIENT_ID}}
    CLIENT_SECRET: ${{secrets.CLIENT_SECRET}}
    VERIFY_CA: ${{vars.VERIFY_CA}}
    LOG_LEVEL: ${{vars.LOG_LEVEL}}
    API_VERSION: "3.1"
  with:
    SECRET_TITLE: "Secret Title"
    PARENT_FOLDER_NAME: "Parent folder name"
    SECRET_DESCRIPTION: ""
    USERNAME: ""
    PASSWORD: ""
    TEXT: ""
    FILE_NAME: "secret.txt"
    FILE_CONTENT: "my_file_content"
    OWNER_ID: "1"
    OWNER_TYPE: "User"
    NOTES: ""
    OWNERS: '[{"owner_id": 1}]'
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
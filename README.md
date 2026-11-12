<a href="https://www.beyondtrust.com">
    <img src="images/beyondtrust_logo.svg" alt="BeyondTrust" title="BeyondTrust" align="right" height="30">
</a>

# BeyondTrust Secrets Actions

This project integrates with BeyondTrust Password Safe and provides four actions for secret management: get_secret, create_secret, update_secret and get_totp_code.
The get_secret action is used to retrieve existing secrets, the create_secret action allows the creation of new secrets, the update_secret action updates an existing secret, and the get_totp_code action retrieves the current TOTP one-time code of a TOTP-enabled credential secret.
Detailed descriptions and usage examples for each action are provided in the following sections.

## 🚧 New changes in 2.0.0

> [!WARNING]
> **Breaking changes**
>
> Instead of a single unified operation for handling secrets, this release splits the functionality into two distinct operations:
>
> - **get_secret** – Retrieves a secret from Secrets Safe  
>   (`BeyondTrust/secrets-safe-action/get_secret`)
> - **create_secret** – Creates a secret in Secrets Safe  
>   (`BeyondTrust/secrets-safe-action/create_secret`)
>
> If you are upgrading from version **1.x**, you must update your GitHub Actions workflows to use these new operation names.  
> Workflows that relied on the previous combined behavior will no longer work unless they are updated to use either **get_secret** or **create_secret**.


## Get Secrets Action
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

Indicates whether to verify the certificate authority on the Secrets Safe instance. Defaults to true if not specified. Accepts `true`, `false`, or the path to a CA bundle inside the action container.
```
VERIFY_CA: true
```
Warning: false is insecure, instructs the Secrets Safe custom action not to verify the certificate authority.

`true` verifies against `certifi`'s bundled roots, **not** the operating system trust store, so a private or internal CA has to be supplied as a bundle path. See [TLS certificate verification (`VERIFY_CA`)](#tls-certificate-verification-verify_ca).

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
uses: BeyondTrust/secrets-safe-action/get_secret@bd174328f6b88a6cd795049a9dbe2a81c8669342 # v2.0.0
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

## Create Secrets Action

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
**Optional:** Supported versions are 3.0, 3.1, 3.2 and 3.3. The recommended version is 3.1. If no version is specified, the default API version 3.0 will be used. Use 3.3 to create TOTP-enabled credential secrets.

#### `verify_ca`
**Optional:** Indicates whether to verify the certificate authority on the Secrets Safe instance. Defaults to `true`. Accepts `true`, `false`, or the path to a CA bundle inside the action container — `true` verifies against `certifi`'s bundled roots, **not** the operating system trust store. See [TLS certificate verification (`VERIFY_CA`)](#tls-certificate-verification-verify_ca).

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
**Optional:** Password for credential type secrets. Masked in the logs.

##### `totp_enabled`
**Optional:** Set to `true` to enable TOTP on the credential secret. Requires `api_version` 3.3 and `totp_secret_key`. Accepts `true`, `false`, or empty (the default) to leave it out of the request. Any other value fails the step.

##### `totp_secret_key`
**Optional:** TOTP seed, as a Base32 string or an `otpauth://` URI (maximum 1024 characters). Required when `totp_enabled` is `true`, and rejected otherwise. The seed is masked in the logs and is never returned by the API; reads only report whether TOTP is enabled and its parameters.

Pass the seed (and the password) from a GitHub secret, for example `${{ secrets.TOTP_SECRET_KEY }}`. The runner prints a step's `with:` values before the action starts, so a literal value in the workflow file would appear in the log before the action can mask it.

TOTP inputs are only supported for credential secrets (`username` set).

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
  uses: BeyondTrust/secrets-safe-action/create_secret@bd174328f6b88a6cd795049a9dbe2a81c8669342 # v2.0.0
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
  uses: BeyondTrust/secrets-safe-action/create_secret@bd174328f6b88a6cd795049a9dbe2a81c8669342 # v2.0.0
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
    TEXT: "Doc_S3guro!21"
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
  uses: BeyondTrust/secrets-safe-action/create_secret@bd174328f6b88a6cd795049a9dbe2a81c8669342 # v2.0.0
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
    FILE_CONTENT: "Doc4!Pass789"
    OWNER_ID: "1"
    OWNER_TYPE: "User"
    NOTES: ""
    OWNERS: '[{"owner_id": 1}]'
```

### Example 4: Create a TOTP-enabled credential secret

TOTP support needs a release of this action that includes it. Pin `uses:` to that release's commit SHA; `v2.0.0` below does not support TOTP. The settings are passed under `with:` so they map onto the action inputs.

```yaml
- name: Create TOTP credential secret
  id: totp_secret
  uses: BeyondTrust/secrets-safe-action/create_secret@bd174328f6b88a6cd795049a9dbe2a81c8669342 # v2.0.0
  with:
    API_URL: ${{vars.API_URL}}
    CLIENT_ID: ${{secrets.CLIENT_ID}}
    CLIENT_SECRET: ${{secrets.CLIENT_SECRET}}
    VERIFY_CA: ${{vars.VERIFY_CA}}
    LOG_LEVEL: ${{vars.LOG_LEVEL}}
    API_VERSION: "3.3"
    SECRET_TITLE: "Secret Title"
    PARENT_FOLDER_NAME: "Parent folder name"
    USERNAME: "username"
    PASSWORD: ${{ secrets.SECRET_PASSWORD }}
    TOTP_ENABLED: "true"
    TOTP_SECRET_KEY: ${{ secrets.TOTP_SECRET_KEY }}
    OWNER_ID: "1"
    OWNER_TYPE: "User"
    OWNERS: '[{"owner_id": 1}]'
```

To read the current code of this secret, use the [Get TOTP Code Action](#get-totp-code-action).

## Get TOTP Code Action

This action retrieves the current TOTP one-time code of TOTP-enabled credential secrets from BeyondTrust Secrets Safe (`GET /Secrets-Safe/Secrets/{secretId}/totp/code`) and makes each code available as a step output. It is a separate action from `get_secret`, so existing secret retrieval workflows are unaffected.

Each code is masked on the runner before it is written to the output. A code is only valid for the current TOTP period (typically 30 seconds), so use it in the next step rather than later in the job.

### Prerequisites

- BeyondInsight/Password Safe 26.3 or greater (PAPI model version 3.3).
- A credential secret created with TOTP enabled. See [Example 4](#example-4-create-a-totp-enabled-credential-secret).
- The application must be authorized to read the secret.

Runners must use a Linux operating system. Additionally, self-hosted runners will need Docker installed.

### Get TOTP Code Inputs

#### `api_key`, `client_id`, `client_secret`, `api_url`, `certificate`, `certificate_key`, `verify_ca`, `log_level`
Same as for the [Get Secrets Action](#inputs).

#### `api_version`
**Optional:** Defaults to `3.3`, the version that adds TOTP support for credential secrets.

#### `secret_ids`
**Required:** IDs (GUIDs) of TOTP-enabled credential secrets, along with the output each code is written to. A single object or a list of up to 20 entries is accepted.
```json
[
  {
    "secret_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "output_id": "totp_code"
  }
]
```
The input is validated before authenticating: each `secret_id` must be a GUID, and each `output_id` must start with a letter or `_` and contain only alphanumeric characters, `-`, or `_`.

The step fails if a secret is a text or file secret, or if the secret is not found or does not have TOTP enabled.

### Get TOTP Code Outputs

#### `output_id`
The current TOTP code of each secret, in the output named by its `output_id`.

### Get TOTP Code Example

The action is available from the release that introduces it. Pin `uses:` to that release's commit SHA.

```yaml
- name: Get TOTP code
  id: totp
  uses: BeyondTrust/secrets-safe-action/get_totp_code@<commit-sha> # release that adds get_totp_code
  with:
    API_URL: ${{vars.API_URL}}
    VERIFY_CA: ${{vars.VERIFY_CA}}
    CLIENT_ID: ${{secrets.CLIENT_ID}}
    CLIENT_SECRET: ${{secrets.CLIENT_SECRET}}
    SECRET_IDS: '[{"secret_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "output_id": "totp_code"}]'

# Use the code straight away: it expires at the end of the current TOTP period.
- name: Sign in
  run: ./sign-in.sh
  env:
    TOTP_CODE: ${{ steps.totp.outputs.totp_code }}
```

## Update Secret Action

This action updates an existing credential, text or file secret in BeyondTrust Secrets Safe, identified by its ID. Its inputs match the [Create Secrets Action](#create-secrets-action), with `secret_id` in place of `parent_folder_name`.

> [!IMPORTANT]
> **Inputs left empty keep their current values.** The action reads the secret first and sends back its current title, description, owners, notes, URLs, password rule and (for credential secrets) password for every input you leave empty, the same way the `ps-cli secrets update` command does. A field can therefore be changed but not cleared. The secret stays in its folder; it cannot be moved with this action.

### Prerequisites

- The application must be allowed to read and edit the secret. The action reads the secret first, to keep the values you don't change and to check its type.
- To change TOTP on a credential secret, BeyondInsight/Password Safe 26.3 or greater and `api_version` 3.3.

Runners must use a Linux operating system. Additionally, self-hosted runners will need Docker installed.

### Update Secret Inputs

#### `api_key`, `client_id`, `client_secret`, `api_url`, `api_version`, `verify_ca`, `certificate`, `certificate_key`, `log_level`
Same as for the [Create Secrets Action](#authentication-inputs).

#### `secret_id`
**Required:** ID (GUID) of the secret to update.

#### Secret content
Set exactly one kind of content, matching the type of the secret being updated (the type cannot change):
- **Credential secret:** `username` (required). `password` and `password_rule_id` are optional: left empty, the current values are kept.
- **Text secret:** `text` (required: text content cannot be read back).
- **File secret:** `file_name` and `file_content` (required: file content cannot be read back).

`password` and `text` are masked in the logs, and so is a current password that is kept. Pass them from GitHub secrets.

#### `secret_title`, `secret_description`, `owners`, `owner_id`, `owner_type`, `notes`, `urls`
**Optional:** Same as for the [Create Secrets Action](#advanced-configuration-inputs). Left empty, the current value is kept. `owners` replaces the current owners when it is set, for example `[{"user_id": 1}]` (`[{"owner_id": 1}]` with `api_version` 3.0).

#### `totp_enabled`
**Optional:** TOTP on a credential secret (`api_version` 3.3):
- `true` sets or replaces the TOTP seed given in `totp_secret_key`.
- `false` turns TOTP off.
- Empty (the default) leaves the current TOTP setting unchanged.

#### `totp_secret_key`
**Optional:** TOTP seed, as a Base32 string or an `otpauth://` URI (maximum 1024 characters). Required when `totp_enabled` is `true`, and rejected otherwise. Masked in the logs; pass it from a GitHub secret.

All inputs are validated before the action authenticates, so invalid input fails the step without making any API call.

### Update Secret Examples

The action is available from the release that introduces it. Pin `uses:` to that release's commit SHA.

#### Rotate a credential password and keep everything else

Only the username (required for a credential secret) and the new password are given; the title, description, owners, notes, URLs and TOTP setting are kept.

```yaml
- name: Rotate password
  uses: BeyondTrust/secrets-safe-action/update_secret@<commit-sha> # release that adds update_secret
  with:
    API_URL: ${{vars.API_URL}}
    CLIENT_ID: ${{secrets.CLIENT_ID}}
    CLIENT_SECRET: ${{secrets.CLIENT_SECRET}}
    API_VERSION: "3.3"
    SECRET_ID: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    USERNAME: "username"
    PASSWORD: ${{ secrets.NEW_PASSWORD }}
```

#### Update a credential secret and replace its TOTP seed

```yaml
- name: Update credential secret
  uses: BeyondTrust/secrets-safe-action/update_secret@<commit-sha> # release that adds update_secret
  with:
    API_URL: ${{vars.API_URL}}
    VERIFY_CA: ${{vars.VERIFY_CA}}
    CLIENT_ID: ${{secrets.CLIENT_ID}}
    CLIENT_SECRET: ${{secrets.CLIENT_SECRET}}
    API_VERSION: "3.3"
    SECRET_ID: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    SECRET_TITLE: "Secret Title"
    SECRET_DESCRIPTION: "Updated by GitHub Actions"
    USERNAME: "username"
    PASSWORD: ${{ secrets.SECRET_PASSWORD }}
    TOTP_ENABLED: "true"
    TOTP_SECRET_KEY: ${{ secrets.TOTP_SECRET_KEY }}
    OWNERS: '[{"user_id": 1}]'
```

#### Update a text secret

```yaml
- name: Update text secret
  uses: BeyondTrust/secrets-safe-action/update_secret@<commit-sha> # release that adds update_secret
  with:
    API_URL: ${{vars.API_URL}}
    CLIENT_ID: ${{secrets.CLIENT_ID}}
    CLIENT_SECRET: ${{secrets.CLIENT_SECRET}}
    API_VERSION: "3.1"
    SECRET_ID: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
    SECRET_TITLE: "Text Secret Title"
    TEXT: ${{ secrets.TEXT_SECRET_VALUE }}
    OWNERS: '[{"user_id": 1}]'
```

## TLS certificate verification (`VERIFY_CA`)

All four actions read the same `VERIFY_CA` environment variable, which accepts three kinds of value:

| Value | Behavior |
| --- | --- |
| `true` (default), `1`, `yes`, `on`, `enable`, `enabled` | Verify against the CA store the `requests` library defaults to — the roots bundled with `certifi`. |
| `false`, `0`, `no`, `off`, `disable`, `disabled` | **Insecure.** Skip certificate verification entirely. |
| A path to an existing file or directory, e.g. `/github/workspace/ca/ca-bundle.crt` | Verify against that CA bundle. |

Values are case-insensitive and surrounding whitespace is ignored. Anything else — including a mistyped or missing bundle path — fails the step at startup with an `EnvironmentError` rather than silently falling back to `true` and failing to trust the CA you asked for.

**`true` is not the operating system trust store.** `requests` verifies against `certifi`'s bundled Mozilla root certificates, not OpenSSL's default paths, so `true` and `/etc/pki/tls/certs/ca-bundle.crt` are *different* trust stores and can behave differently. Anything an administrator added to a host's OS store with `update-ca-trust` / `update-ca-certificates` — an internal PKI or a self-signed Password Safe certificate — is invisible to `certifi`. If Password Safe presents a certificate that does not chain to a public root, `VERIFY_CA: "true"` fails with `CERTIFICATE_VERIFY_FAILED` and you must point `VERIFY_CA` at a bundle that contains your CA. Do not disable verification to work around this.

### Supplying a CA bundle

These are Docker container actions, so the bundle must exist **inside the action container**, which does not inherit the runner's trust store. The runner mounts the repository workspace at `/github/workspace` in the container, so a bundle that is checked in — or written by an earlier step — is reachable under that path:

```yaml
- uses: actions/checkout@eef61447b9ff4aafe5dcd4e0bbf5d482be7e7871 # v4.2.1

- name: Get secret
  uses: BeyondTrust/secrets-safe-action/get_secret@bd174328f6b88a6cd795049a9dbe2a81c8669342 # v2.0.0
  env:
    API_URL: ${{vars.API_URL}}
    CLIENT_ID: ${{secrets.CLIENT_ID}}
    CLIENT_SECRET: ${{secrets.CLIENT_SECRET}}
    # Path inside the container, not on the runner.
    VERIFY_CA: "/github/workspace/ca/ca-bundle.crt"
  with:
    SECRET_PATH: '{"path": "folder1/folder2/title", "output_id": "title"}'
```

To keep the bundle out of the repository, write it from a secret in a preceding step:

```yaml
- name: Write CA bundle
  run: |
    mkdir -p "$GITHUB_WORKSPACE/ca"
    printf '%s\n' "${{ secrets.CA_BUNDLE }}" > "$GITHUB_WORKSPACE/ca/ca-bundle.crt"
```

Use the literal `/github/workspace/...` path for `VERIFY_CA`: `${{ github.workspace }}` expands to the path on the runner (for example `/home/runner/work/repo/repo`), which does not exist inside the container.

As an alternative that needs no change to `VERIFY_CA`, `requests` also honors the standard `REQUESTS_CA_BUNDLE` (or `CURL_CA_BUNDLE`) environment variable whenever verification is enabled; set it on the step's `env` with the same in-container path. Note that `SSL_CERT_FILE` has no effect on `requests`.

The action logs which trust store is in effect at `INFO` level, which is the quickest way to confirm the bundle was picked up:

```
Verifying certificates against CA bundle: /github/workspace/ca/ca-bundle.crt
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
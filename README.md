# secrets safe action

This action retrieves secrets from BeyondTrtust Pasword Safe API

## Inputs

### `client_id`

**Required** API OAuth Client ID.

### `client_secret`

**Required** API OAuth Client Secret.

### `api_url`

**Required** BeyondTrust Password Safe API URL.

### `verify_ca`

Indicates whether to verify the certificate authority on the Secrets Safe instance.

### `secret_path`

**Required** Secret to retrieve.

### `managed_account_path`

**Required** Managed account to retrieve.

### `certificate`

Password Safe API Certificate Content. For use when authenticating using a Client Certificate.

### `certificate_key`

Password Safe API Certificate Key. For use when authenticating using a Client Certificate.

## Outputs

### `secret`

Retrieved secret.

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
  SECRET_PATH: 'secret_folder/secret_title'
  MANAGED_ACCOUNT_PATH: 'system_name/managed_account_name'
```

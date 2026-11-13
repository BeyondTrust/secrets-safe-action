# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A BeyondTrust GitHub Actions repository providing four Docker-based custom actions for integrating with BeyondTrust Secrets Safe:
- **`get_secret/`** — Retrieves ASCII secrets and exposes them as masked GitHub Actions outputs
- **`create_secret/`** — Creates new secrets (credential, text, or file types) in Secrets Safe
- **`get_totp_code/`** — Retrieves the current TOTP code of TOTP-enabled credential secrets (API 3.3) as masked outputs
- **`update_secret/`** — Updates an existing credential, text, or file secret by ID (full replacement PUT)

All actions are written in Python 3.12 on Alpine Linux containers and use the `beyondtrust-bips-library` SDK.

## Commands

### Install dependencies
```bash
pip install -r create_secret/requirements.txt -r create_secret/requirements-dev.txt
pip install -r get_secret/requirements.txt -r get_secret/requirements-dev.txt
pip install -r get_totp_code/requirements.txt -r get_totp_code/requirements-dev.txt
pip install -r update_secret/requirements.txt -r update_secret/requirements-dev.txt
```

### Run tests
```bash
# Run tests for a single action (from repo root)
cd create_secret && python3 -m coverage run --data-file=../.coverage.create -m unittest discover tests/unit -v -p 'test_*.py'
cd get_secret && python3 -m coverage run --data-file=../.coverage.get -m unittest discover tests/unit -v -p 'test_*.py'
cd get_totp_code && python3 -m coverage run --data-file=../.coverage.totp -m unittest discover tests/unit -v -p 'test_*.py'
cd update_secret && python3 -m coverage run --data-file=../.coverage.update -m unittest discover tests/unit -v -p 'test_*.py'

# Combined coverage report
python3 -m coverage combine .coverage.create .coverage.get .coverage.totp .coverage.update && python3 -m coverage report
```

### Run linters (matches CI)
```bash
black --check create_secret/src get_secret/src get_totp_code/src update_secret/src
isort --check-only create_secret/src get_secret/src get_totp_code/src update_secret/src
flake8 create_secret/src get_secret/src get_totp_code/src update_secret/src
bandit -r create_secret/src get_secret/src get_totp_code/src update_secret/src
```

### Local Docker testing
```bash
# Configure .env file in each action directory first
docker-compose -f create_secret/docker-compose.yml up
docker-compose -f get_secret/docker-compose.yml up
```

## Architecture

### Code structure
Each action is self-contained with identical layout:
```
<action>/
├── action.yml          # GitHub Actions metadata (inputs/outputs/runs)
├── Dockerfile          # python:3.12-alpine, non-root appuser (UID 1001)
├── docker-compose.yml  # Local testing with .env file
├── requirements.txt    # beyondtrust-bips-library>=3.6.0,<4.0.0
├── requirements-dev.txt
└── src/main.py         # All logic lives here (~260-280 lines)
    tests/unit/test_main.py
```

### Authentication flow (both actions)
Both actions support two mutually exclusive auth methods:
1. **API Key** — `API_KEY` env var, optionally with `CERTIFICATE` + `CERTIFICATE_KEY`
2. **OAuth Client Credentials** — `CLIENT_ID` + `CLIENT_SECRET` env vars

Both validate API access (expects HTTP 200), configure certificates if provided, and set API version (default 3.0, recommended 3.1).

### get_secret flow
`main()` → `api_client.authenticate()` (inline in `main()`) → `get_secrets()` → sign out

`get_secrets()` parses JSON input (up to 20 secrets), calls the bips library, masks each value with `outputs.mask_secret()` and writes it with `outputs.append_output()`.

### get_totp_code flow
`main()` → `validate_secret_id()` (GUID check before auth) → `set_authentication()` → `write_totp_code()` → sign out

Input `secret_id` is one secret GUID; the masked code is written to the fixed output `totp_code` (one step per secret), and the response's `ValidFromUtc` / `ValidToUtc` to `valid_from_utc` / `valid_to_utc` (unmasked, `""` when absent). Calls `SecretsSafe.get_secret_totp_code()`; catches `SecretTypeNotSupportedError` (400) and `TotpNotEnabledError` (404) before `LookupError`. `api_version` defaults to `3.3`. Its retry list deliberately **omits 400** so the 400 reaches the library instead of becoming a `RetryError`.

### update_secret flow
`main()` → `validate_inputs()` (GUID, one content type, TOTP, integers, JSON — all before auth) → `set_authentication()` → `update_secret()` (`get_secret_to_update()` → `build_update_kwargs()` → PUT) → sign out

Calls `SecretsSafe.update_secret()`, a full-replacement PUT (`/secrets/{id}`, `/text` or `/file`). Following ps-integration-cli `secrets update` (`_call_update_secret`), `build_update_kwargs()` sends every field as `input or existing value` read with `get_secret_by_id()`: title, description, owners, owner type/id, notes, URLs, password rule and the credential password. Only `username`, `text` and the file can't be read back, so they are required. `FolderId` is always the current one (the live API requires it, although the Swagger marks it read-only), so secrets are never moved. Owners read back use API names (`UserId`), which the library's validator rejects, so `to_library_owners()` converts them (`user_id`). The API answers credential/text updates with **204**, but the library (≤ 3.5.1) expects 200 and raises `UpdateError(... statuscode: 204)`; the action treats exactly that error as success (`NO_CONTENT_UPDATE_ERROR`). `totp_enabled` empty leaves TOTP unchanged, `false` turns it off.

### create_secret flow
`main()` → `set_authentication()` → `get_folder()` → `create_secret()` → sign out

`get_folder()` lists all folders and matches by exact name. `create_secret()` handles three secret types (CREDENTIAL, TEXT, FILE) and optionally creates a file attachment before creating the secret record.

### Shared helpers (beyondtrust-bips-library >= 3.6.0)
The helpers every action needs live in the library, in `secrets_safe_library.integrations.github_actions.common_utils`; fix them there, not in the actions:
- `tls.parse_verify_ca()`: `VERIFY_CA` is boolean only (true/false tokens; a CA bundle path fails the step). `api_client.authenticate()` passes it to `Authentication`, which sets `session.verify`
- `outputs.mask_secret()` (`::add-mask ::value` per line, CR/LF-safe; the space before the second `::` is intentional), `outputs.append_output()` (`$GITHUB_OUTPUT` heredoc with a UUID delimiter)
- `api_client.create_session(retry_status_codes)`: `Retry(total=3, backoff_factor=0.2, status_forcelist=[400, 408, 500, 502, 503, 504])` by default; `get_totp_code` passes the list without 400
- `api_client.authenticate()`: API key or OAuth, 30 s timeouts, fails the step unless sign-in returns 200
- `common.show_error()`, `common.create_file()`

### Environment variable conventions
- GitHub Actions inputs arrive as `INPUT_<NAME>` (uppercased)
- Auth/config vars (`API_KEY`, `API_URL`, `CLIENT_ID`, etc.) have no prefix
- `LOG_LEVEL` defaults to INFO; `VERIFY_CA` defaults to `true`

## Code Quality

- **Line length:** 88 (Black default), enforced by both Black and Flake8
- **Import order:** isort with Black profile
- **Complexity:** max McCabe complexity 10 (`.flake8`)
- **Coverage gate:** 80% minimum overall; 85% for new code (enforced via `orgoro/coverage` in `.github/workflows/unit-tests.yml`)
- **Security linting:** Bandit runs in CI and as a pre-commit hook

Pre-commit hooks enforce Black, isort, Flake8, and Bandit — install with `pre-commit install`.

## CI Workflows

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| `linter.yml` | PR/push | Black, Flake8, isort, Bandit (all run even if one fails) |
| `unit-tests.yml` | PR/push, tags `v*` | Runs all four test suites, combines coverage, posts coverage report to PR via orgoro/coverage |
| `wiz.yml` | PR/push | WIZ cloud security scan |

## Key Dependencies

- `beyondtrust-bips-library` — BeyondTrust SDK; `create_secret/src/main.py` catches typed SDK exceptions (`CreationError`, `OptionsError`, etc.) explicitly; `get_secret/src/main.py` uses a broad `except Exception` at the top level
- `requests` — HTTP client; wrapped in a retry-enabled session

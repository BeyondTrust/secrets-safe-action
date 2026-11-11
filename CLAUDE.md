# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A BeyondTrust GitHub Actions repository providing three Docker-based custom actions for integrating with BeyondTrust Secrets Safe:
- **`get_secret/`** — Retrieves ASCII secrets and exposes them as masked GitHub Actions outputs
- **`create_secret/`** — Creates new secrets (credential, text, or file types) in Secrets Safe
- **`get_totp_code/`** — Retrieves the current TOTP code of TOTP-enabled credential secrets (API 3.3) as masked outputs

All actions are written in Python 3.12 on Alpine Linux containers and use the `beyondtrust-bips-library` SDK.

## Commands

### Install dependencies
```bash
pip install -r create_secret/requirements.txt -r create_secret/requirements-dev.txt
pip install -r get_secret/requirements.txt -r get_secret/requirements-dev.txt
pip install -r get_totp_code/requirements.txt -r get_totp_code/requirements-dev.txt
```

### Run tests
```bash
# Run tests for a single action (from repo root)
cd create_secret && python3 -m coverage run --data-file=../.coverage.create -m unittest discover tests/unit -v -p 'test_*.py'
cd get_secret && python3 -m coverage run --data-file=../.coverage.get -m unittest discover tests/unit -v -p 'test_*.py'
cd get_totp_code && python3 -m coverage run --data-file=../.coverage.totp -m unittest discover tests/unit -v -p 'test_*.py'

# Combined coverage report
python3 -m coverage combine .coverage.create .coverage.get .coverage.totp && python3 -m coverage report
```

### Run linters (matches CI)
```bash
black --check create_secret/src get_secret/src get_totp_code/src
isort --check-only create_secret/src get_secret/src get_totp_code/src
flake8 create_secret/src get_secret/src get_totp_code/src
bandit -r create_secret/src get_secret/src get_totp_code/src
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
├── requirements.txt    # beyondtrust-bips-library>=3.1.0,<4.0.0
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
`main()` → (inline auth) → `get_secrets()` → sign out

Auth configuration is handled inline inside `main()` (no separate function). `get_secrets()` parses JSON input (up to 20 secrets), calls the bips library, masks each value via `::add-mask ::value` (space before second `::` is intentional — GitHub Actions accepts this form), and writes to `$GITHUB_OUTPUT` using UUID delimiters for multiline safety.

### get_totp_code flow
`main()` → `parse_secret_ids()` (validates every entry before auth) → `set_authentication()` → `get_totp_codes()` → sign out

Input `secret_ids` is `[{"secret_id": "<guid>", "output_id": "<name>"}]` (max 20). Calls `SecretsSafe.get_secret_totp_code()`; catches `SecretTypeNotSupportedError` (400) and `TotpNotEnabledError` (404) before `LookupError`. `api_version` defaults to `3.3`. Its retry list deliberately **omits 400** so the 400 reaches the library instead of becoming a `RetryError`.

### create_secret flow
`main()` → `set_authentication()` → `get_folder()` → `create_secret()` → sign out

`get_folder()` lists all folders and matches by exact name. `create_secret()` handles three secret types (CREDENTIAL, TEXT, FILE) and optionally creates a file attachment before creating the secret record.

### HTTP session config (get_secret, create_secret; get_totp_code omits 400)
```python
Retry(total=3, backoff_factor=0.2, status_forcelist=[400, 408, 500, 502, 503, 504])
# Timeouts: connect=30s, read=30s
```

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
| `unit-tests.yml` | PR/push, tags `v*` | Runs all three test suites, combines coverage, posts coverage report to PR via orgoro/coverage |
| `wiz.yml` | PR/push | WIZ cloud security scan |

## Key Dependencies

- `beyondtrust-bips-library` — BeyondTrust SDK; `create_secret/src/main.py` catches typed SDK exceptions (`CreationError`, `OptionsError`, etc.) explicitly; `get_secret/src/main.py` uses a broad `except Exception` at the top level
- `requests` — HTTP client; wrapped in a retry-enabled session

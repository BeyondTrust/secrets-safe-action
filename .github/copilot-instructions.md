# Copilot Instructions for `secrets-safe-action`

BeyondTrust GitHub Actions for Secrets Safe. Four Docker container actions, each written in Python 3.12 on `python:3.12-alpine`, built on the `beyondtrust-bips-library` SDK (`secrets_safe_library`).

The full project rules live in `CLAUDE.md` at the repository root. When this file and `CLAUDE.md` disagree, `CLAUDE.md` wins. Path-specific rules are in `.github/instructions/`.

## Four self-contained actions

| Action | What it does | Flow in `src/main.py` |
|---|---|---|
| `get_secret/` | Reads ASCII secrets by path and title (up to 20) into masked outputs | `main()` (inline auth) → `get_secrets()` → sign out |
| `create_secret/` | Creates a credential, text or file secret in a folder found by name | `main()` → `set_authentication()` → `get_folder()` → `create_secret()` → sign out |
| `get_totp_code/` | Reads the current TOTP code of one credential secret by ID (API 3.3) into the masked output `totp_code` | `main()` → `validate_secret_id()` → `set_authentication()` → `write_totp_code()` → sign out |
| `update_secret/` | Updates a credential, text or file secret by ID with a full-replacement PUT | `main()` → `validate_inputs()` → `set_authentication()` → `update_secret()` → sign out |

- Each action has its own `action.yml`, `Dockerfile`, `docker-compose.yml`, `requirements*.txt`, `src/main.py` and `tests/unit/test_main.py`. There is no shared code between actions: a fix to a common helper (masking, `VERIFY_CA`, the retry session, authentication) is copied to every action that has it.
- `get_secret/` is the oldest and most used action. It is changed only when the change is about reading secrets; new features go into a new or the relevant action.
- `action.yml` `inputs` reach the container as `INPUT_<NAME>` (uppercase). Authentication and configuration (`API_KEY`, `CLIENT_ID`, `CLIENT_SECRET`, `API_URL`, `API_VERSION`, `VERIFY_CA`, `CERTIFICATE`, `CERTIFICATE_KEY`, `LOG_LEVEL`) are mapped in `runs.env` and have no prefix.
- Images run as the non-root `appuser` (UID 1001). Keep it.

## Shared rules (all actions)

- Authentication: an API key (optionally with a client certificate) or OAuth client credentials, never both. Inputs are validated before the first API call, and the session is signed out at the end.
- Every secret value written to the log or to `$GITHUB_OUTPUT` is masked first with `::add-mask ::<value>`, one line at a time, with `%`, CR and LF escaped. Outputs use a random UUID heredoc delimiter. Never `print` a secret, a password, a TOTP seed or code, an API key or a client secret, also not in an error message or at `DEBUG` level.
- Errors end the run through the library's `common.show_error` (exit 1) with a message that names the secret or input and keeps the API's error text. Catch the library's typed exceptions (`LookupError`, `CreationError`, `UpdateError`, `OptionsError`, `IncompleteArgumentsError`, `SecretTypeNotSupportedError`, `TotpNotEnabledError`) and catch subclasses before their parent.
- HTTP session: `Retry(total=3, backoff_factor=0.2, status_forcelist=[400, 408, 500, 502, 503, 504])`, connect and read timeouts 30 s. `get_totp_code` leaves 400 out on purpose, so the library sees the 400 instead of a `RetryError`.
- API field names keep the backend's casing (`FolderId`, `SecretType`, `Owners`). The library's own arguments are snake_case (`folder_id`, `user_id`); convert explicitly where data read from the API is passed back to the library.
- The library is pinned by range (`>=3.x,<4.0.0`). Behaviour of a library call is checked in its source (`BeyondTrust/ps-integration-library`) at the installed version, not assumed from its name.
- Python style is enforced by Black (line length 88), isort (Black profile), Flake8 (max McCabe complexity 10) and Bandit. Follow the tools; do not restate them.
- Comments: none by default. One short line only for a non-obvious why (an API quirk, a library workaround).

## Backend and library

| Component | Repository | Where to look |
|---|---|---|
| Python SDK used by every action | `BeyondTrust/ps-integration-library` | `src/secrets_safe_library/` (`secrets_safe.py`, `folders.py`, `authentication.py`, `exceptions.py`) |
| Password Safe Public API, which serves the `secrets-safe/` endpoints the actions call | `BeyondTrust/BeyondInsight` | `Source/BeyondTrust.PasswordSafe.API/Controllers/`, models in `Source/BeyondTrust.PasswordSafe.API.Models/` |
| Secrets Safe service behind those endpoints | `BeyondTrust/TeamPasswords` | `src/BeyondTrust.TeamPasswords.Api/Controllers/` |
| Reference CLI with the same operations | `BeyondTrust/ps-integration-cli` | `src/ps_cli/controllers/secrets.py` |

The backend is the source of truth for field names, required fields, status codes and permission checks. Known gaps between the API, its Swagger and the library are documented in `CLAUDE.md` (for example `update_secret`: the PUT returns 204 while the library expects 200, and `FolderId` is required although the Swagger marks it read-only).

## High-risk areas

| Area | Key code | Risk |
|---|---|---|
| Secret masking and outputs | `mask_secret`, `escape_data`, `append_output` / `$GITHUB_OUTPUT` writes | Secret printed in the job log, workflow command injection through CR/LF |
| Authentication | `set_authentication`, inline auth in `get_secret` | Credentials leaked, both methods mixed, session not signed out |
| TLS | `VERIFY_CA` parsing, certificate files | Verification silently turned off, CA bundle path ignored |
| Update by full replacement | `update_secret`: `get_secret_to_update`, `build_update_kwargs` | A field the user left empty overwritten with empty or null, secret moved to another folder |
| Error handling | `show_error`, typed exception order | Failure reported as success, API error text lost |
| Inputs ↔ code | `action.yml` inputs vs `INPUT_*` reads, README tables | Input documented but never read, renamed in one place only |

## Commits, branches, PRs

- Branch: `<type>/BIPS-####-short-name` (`feat/`, `fix/`, `chore/`, `docs/`). Base branch: `main`.
- Commit and PR title: Conventional Commits with the ticket, such as `feat: BIPS-#### add update_secret action`. Release Please builds `CHANGELOG.md` and the version from them, so `feat:` and `fix:` only for changes users of the actions see.
- PR body: `.github/PULL_REQUEST_TEMPLATE.md`.
- GitHub Actions in `.github/workflows/` are pinned by commit SHA with the version in a comment, never by a mutable tag.

## Commands

| Task | Command |
|---|---|
| Install | `pip install -r <action>/requirements.txt -r <action>/requirements-dev.txt` |
| Tests | `cd <action> && python3 -m coverage run --data-file=../.coverage.<name> -m unittest discover tests/unit -v -p 'test_*.py'` |
| Checks (CI) | `black --check`, `isort --check-only`, `flake8`, `bandit -r` on every `<action>/src` |
| Local run | `docker-compose -f <action>/docker-compose.yml up` with a `.env` in the action folder |

A new action is added to `unit-tests.yml`, `linter.yml`, `.coveragerc`, `README.md` and `CLAUDE.md`. The coverage gate requires ≥ 80% overall and ≥ 85% on new code: a change with logic ships with its tests.

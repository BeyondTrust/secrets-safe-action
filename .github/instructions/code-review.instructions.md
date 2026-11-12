---
applyTo: '**'
excludeAgent: 'cloud-agent'
---

# Code review

A good review here has few comments, and every one of them is true. A wrong comment costs the author more time than a missed nitpick, so when in doubt, leave it out.

## What earns a comment

A comment stands on exactly one of these grounds:

1. **Bug**: a concrete scenario in an action, or in the repository's tooling (workflows, `Dockerfile`, `docker-compose.yml`, pre-commit, coverage setup), as it is today: which inputs or API response, which step, what the workflow run gets. It produces a wrong output, a wrong or missing exit code (a failure reported as success, or the other way round), a secret changed in a way the user did not ask for, or a crash.
2. **Security or reliability gap** with the concrete path on which it triggers: a secret, password, TOTP seed or code, API key or client secret printed to the job log or written to `$GITHUB_OUTPUT` unmasked; a CR, LF or `%` in a value that can inject a workflow command or a second output; TLS verification turned off when the user did not ask for it; an input interpolated into a shell or file path; an error whose API text is discarded so it can no longer be diagnosed; a session not signed out.
3. **Contract mismatch with the API or the library**: a route, field name, required field, type, status code or permission that the action assumes differently from what the Secrets Safe API or `beyondtrust-bips-library` at the pinned version does (see "Checking against the API and the library").
4. **Broken project rule** written in `CLAUDE.md` or `.github/copilot-instructions.md`, quoted with its file. A rule from general Python practice that this project does not state is not enough.
5. **Missing update**: a changed or added input, output, function or action whose other places in the repository were not updated and now break or disagree: `action.yml` inputs vs the `INPUT_*` reads in `src/main.py`, the README tables and examples, `unit-tests.yml`, `linter.yml`, `.coveragerc`, `CLAUDE.md`, or the same helper copied in the other actions when the change is a fix to that helper.
6. **Broken test**: a test that leaks state into other tests (an environment variable, a patched module, `sys.argv`, a file in the working directory) or cannot fail for the case its name states (a mock that returns what the assertion checks, an `assert_called` on the wrong mock).

Not a ground, never comment on:

- What Black, isort, Flake8 (line length 88, McCabe complexity 10) or Bandit already check.
- Taste: naming, a shorter way to write the same thing, extracting a constant, a different but equivalent structure, type hints, docstrings.
- Code duplicated across the four actions: each action is self-contained on purpose.
- Hypothetical inputs no workflow can pass today, "a future change might", "consider adding a guard / try-catch / retry" without a scenario where it is reached. GitHub Actions always passes a declared input as a string, empty when unset; base the scenario on that.
- Generic advice ("ensure this is tested", "verify this works against a real instance") without a specific gap. Do not ask for a test unless the missing test is the finding.
- PR title, PR description, commit messages, `CHANGELOG.md`, `version.txt`. A mismatch between the description and the code is not a ground; comment only if the code itself fails a ground above.
- Code outside the diff, unless the diff breaks it, and behaviour the diff carries over unchanged from `main` or from an earlier PR (a stacked base PR included). A security gap (ground 2) is reported even when it is carried over.
- A documented workaround for a known library or API gap listed in `CLAUDE.md` (the 204 accepted as success on `update_secret`, `FolderId` sent although the Swagger marks it read-only, 400 left out of the retry list in `get_totp_code`), unless the diff breaks the workaround.

## Verify before you write

For every candidate comment, before posting it:

1. **Read the full file**, not the hunk. Each action's logic is one `src/main.py`: check the code around the line, a validation earlier in `main()`, an early `show_error` (it exits), a default in `action.yml`.
2. **Follow the data.** Find where the value comes from (`action.yml` input and default, `INPUT_*` or the auth environment variable, the API response) and where it goes (the library call, the log, `$GITHUB_OUTPUT`). Read them. Most real bugs are at that boundary; most false ones disappear there.
3. **Look for the code that already handles it**: the library, `common.show_error`, the retry session, the masking helpers, a test that covers the case. A claim about how the library, `requests`, `urllib3` or the GitHub Actions runner behaves (what an exception carries, which status raises, how `::add-mask::` treats multiline values, how inputs are passed) must rest on that source or its docs at the version in `requirements.txt`. If you cannot check it, drop the claim; if the comment also stands on another ground, keep it on that ground only.
4. **Check the claim against the API and the library** when it depends on what the server returns or what the library sends.
5. **Check that it is not intended.** If `CLAUDE.md`, the README, the linked ticket or the PR description states it as a decision (for example: empty `update_secret` inputs keep the current value, so a field cannot be cleared), it is a decision, not a bug of this PR: drop the comment.
6. **Try to refute it.** If you find the guard, the input that can never be empty, or the API that never returns that value, drop the comment. If you could not check something, drop it rather than guess. Never write "might", "could potentially", "if X is ever".

If after this the comment still stands, you must be able to point to the lines that prove it: the line with the defect and the line that produces the bad value.

## Checking against the ticket

PR titles and branches carry a ticket key, such as `feat: BIPS-43275 ...` or `claude/BIPS-43275/...`. Use the first `BIPS-####` key in the title, or in the branch name when the title has none.

- Once, at the start of the review, read the ticket with the `getJiraIssue` tool: `issueIdOrKey` is that key, `cloudId` is `beyondtrust.atlassian.net`, and `fields` lists `summary`, `description`, `status` and `customfield_10039` (the acceptance criteria, which the default fields leave out).
- Treat the ticket's description, acceptance criteria and recorded decisions as intended behaviour (step 5 of "Verify before you write").
- The ticket is a reason to drop a comment, never a new ground for one. Do not report acceptance criteria the PR does not implement: a PR often delivers one part of a ticket. Report only code that contradicts a criterion, under ground 1, quoting the criterion.
- Skip this when there is no key: there is no ticket.
- If the tool fails or the ticket cannot be read, do not guess what the ticket says. Review against the code and the PR description only.

## Checking against the API and the library

- **Library**: `beyondtrust-bips-library`, source in `BeyondTrust/ps-integration-library` under `src/secrets_safe_library/` (`secrets_safe.py`, `folders.py`, `authentication.py`, `exceptions.py`, `validators/`). Read it at the version `requirements.txt` allows. Check the arguments a method takes and validates, the request it builds, the status code it expects and the exception it raises.
- **API**: the `secrets-safe/` endpoints of the Password Safe Public API in `BeyondTrust/BeyondInsight` (`Source/BeyondTrust.PasswordSafe.API/Controllers/`, models in `Source/BeyondTrust.PasswordSafe.API.Models/`), backed by `BeyondTrust/TeamPasswords` (`src/BeyondTrust.TeamPasswords.Api/Controllers/`). A Swagger file in the PR is a hint, not proof: where it and the controller disagree, the controller wins.
- **Reference behaviour**: `BeyondTrust/ps-integration-cli` (`src/ps_cli/controllers/secrets.py`) implements the same operations; a difference from it is a finding only when it also fails a ground above.
- When a change adds or changes a library call, an API field, an error branch or a status code check, and your tools can read those repositories, open the method and the endpoint and compare.
- Report a mismatch only with the library or backend file and line that shows it.
- If you cannot read those repositories, do not guess their behaviour from the action code or from naming. Say nothing about it.

## How to write the comment

- Plain English, short sentences, no jargon for its own sake. Two to four sentences, never more.
- First sentence: what goes wrong, from the workflow author's point of view ("Running `update_secret` with only `secret_id` and `username` clears the secret's notes").
- Then why, pointing to the code: `file:line` of the cause, and of the library or backend when relevant.
- Then the fix, at the cause, as a small code suggestion when it fits.
- No severity tags or emoji (`[P2]`, 🔴), no headings, no "Great job", no summary of what the PR does, no list of things you checked.
- One problem per comment. The same problem in several places (two actions, two secret types) is one comment listing the places.
- If nothing meets the bar, leave no comments. An empty review is a valid result.

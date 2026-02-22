# ica-cli

CLI for ICA grocery automation, using ICA account login at https://www.ica.se/.

It helps you authenticate, inspect shopping lists, add list items, and search products from scripts or agents.

## Why this exists

- Manage ICA shopping list workflows from terminal commands.
- Integrate with scripts/agents via stable `--json` output.
- Keep auth and provider handling in one place when ICA APIs evolve.

## Install

### Homebrew (recommended)

```bash
brew tap liamvinberg/tap
brew install ica-cli
```

Upgrade to the latest release:

```bash
brew update
brew upgrade ica-cli
```

The tap is automatically updated when a new GitHub release is published.

### From source

Requires [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/liamvinberg/ica-cli.git
cd ica-cli
uv sync
```

When running from source, prefix all commands with `uv run`:

```bash
uv run ica config show
uv run ica --json list ls
```

The rest of this README uses `ica` directly. If running from source, substitute
`uv run ica` wherever you see `ica`.

## Quick start

```bash
ica config set-username <personnummer-or-username>
ica config set-provider ica-current
```

## Output modes

- Default: human-readable CLI output.
- `--json`: full structured output.
- `--raw`: raw API payload only (useful for scripts).
- `--quiet` / `--short`: print only `ok` on success.

Examples:

```bash
ica config show
ica --json list ls
ica --raw list ls
ica --quiet list add mjolk --list "Handla"
```

## Authentication modes

### `ica-current` (recommended)

Default smooth flow:

```bash
ica auth login
# Press Enter, complete ICA login in browser, paste callback URL
ica --json auth status
ica --json list ls
```

If username is not configured, `auth login` prompts for it and stores it.

Non-interactive completion:

```bash
ica --json auth login --callback-url "https://www.ica.se/logga-in/sso/callback/?...&code=...&state=..."
```

Agent-friendly mode (no prompts):

```bash
ica --json auth login --agentic --user "<personnummer-or-username>"
# then complete with:
ica --json auth login --agentic --user "<personnummer-or-username>" --callback-url "https://www.ica.se/logga-in/sso/callback/?...&code=...&state=..."
```

If your shell command contains escaped separators (`\?`, `\&`, `\=`), `auth login --callback-url` normalizes them automatically.

Advanced manual flow is still available:

```bash
ica --json auth current-begin
ica --json auth current-complete --callback-url "https://www.ica.se/logga-in/sso/callback/?...&code=...&state=..."
```

Fallback if OAuth completion does not return tokens:

```bash
ica auth session import --session-id "<thSessionId>"
ica --json auth status
```

Direct token import for remote/agent runtimes:

```bash
ica --json auth token import --access-token "<token>" --refresh-token "<refresh>"
```

### `ica-legacy` (experimental)

Uses legacy login flow (`handla.api.ica.se/api/login`) with personnummer + password.

```bash
ica config set-provider ica-legacy
ica auth login
ica --json list ls
```

Non-interactive credentials:

```bash
ica auth login --user "<personnummer>" --pass "<password>"
```

Non-interactive login for automation:

```bash
printf '%s' "$ICA_PASSWORD" | ica auth login --password-stdin
```

## Add grocery item

```bash
ica config set-default-list "Min lista"
ica --json list add "mjolk"
ica --json list add "bananer" --list-name "Helg" --quantity 2
ica --json list add "mjolk" "brod" "smor" --list "Handla"
ica --json list add --item "oat milk" --item "agg" --list "Handla"
ica --json list add --items "mjolk,brod,smor" --list "Handla" --dedupe
printf 'mjolk\nbrod\nsmor\n' | ica --json list add --stdin-items --list "Handla"
```

`list add` supports mixed bulk input in one call:

- Positional items: `ica list add mjolk brod smor`
- Repeated `--item`: `ica list add --item mjolk --item brod`
- Comma-separated groups with `--items`
- Newline-separated stdin with `--stdin-items`
- `--dedupe` removes duplicate input items case-insensitively before adding

## List items in a grocery list

```bash
ica list items --list-name "Min lista"
ica --json list items --list-name "Min lista"
ica --raw list items --list-name "Min lista"
```

## Update or remove list items

```bash
ica list remove "mjolk" --list "Min lista"
ica list remove "mjolk" --list "Min lista" --all
ica list strike "brod" --list "Min lista"
ica list unstrike "brod" --list "Min lista"
ica list clear-struck --list "Min lista"
```

## Search products

```bash
ica config set-store-id "1004394"
ica config set-store-ids "1004394" "1001234" "1007777"
ica --json products search "ost"
```

If multiple preferred stores are configured, the first one is used as default
for commands that require one store ID.

If no `--store-id` and no configured default exists, `products search` now tries
to auto-resolve a store ID from favorites first, then from store search fallback.

## Search deals/offers

Deals currently use the legacy offers endpoint (`handla.api.ica.se`) and require `ica-legacy` auth.

```bash
ica config set-provider ica-legacy
ica auth login
ica deals search --store-id "1004394"
ica deals search "kaffe" --store-id "1004394"
ica --json deals search "kaffe" --store-id "1004394"
ica --raw deals search "kaffe" --store-id "1004394"
```

## Search stores by name

Store search now tries current auth first and then legacy fallback when available,
returning store names with IDs so you can pick a store without manual lookup.

```bash
ica stores search "stockholm"
ica stores favorites
ica stores get "1004394"
ica --json stores search "stockholm"
ica --raw stores search "stockholm"
```

If current search cannot resolve stores and fallback is unavailable, do one legacy
login once:

```bash
ica config set-provider ica-legacy
ica auth login
```

## Secrets and storage

- Configuration: `~/.config/ica-cli/config.json`
- Sensitive values:
  - macOS: Keychain (`security` CLI)
  - Linux/other environments (or when `security` is unavailable): `~/.config/ica-cli/secrets.json` (written with `0600` permissions)
  - `current-session:<username>` for `thSessionId`
  - `current-access-token:<username>` for OAuth access token
  - `current-refresh-token:<username>` for OAuth refresh token
  - `legacy-auth-ticket:<username>` for legacy auth ticket

## Remote/agent execution

For non-local runtimes, avoid keychain dependencies and inject credentials as env vars:

```bash
export ICA_CURRENT_ACCESS_TOKEN="..."
export ICA_CURRENT_REFRESH_TOKEN="..."
# optional fallback
export ICA_CURRENT_SESSION_ID="..."
ica --json list ls
```

Environment variables override keychain values when both are set.

## OpenClaw skill usage

Recommended command style from agents:

`openclaw/skill.example.json` contains ready command wrappers.

Example command shape:

```bash
ica --json list add "avokado" --list-name "Min lista"
```

## Development

This project uses `uv` with a committed lockfile (`uv.lock`).

```bash
uv sync --frozen
uv run ica --json config show
uv run python -m unittest discover -s src -p "test_*.py"
```

See `packaging/homebrew/README.md` for Homebrew formula generation and release workflow.

## Notes

- ICA grocery APIs are unofficial and can change without notice.
- Keep this CLI pinned to a release when used in automations.
- Avoid committing real credentials or session IDs.

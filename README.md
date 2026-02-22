# ica-cli

Experimental ICA grocery CLI for personal automation and OpenClaw skill usage.

## Why this exists

- Personal CLI for managing ICA shopping lists.
- Agent-friendly command interface with JSON output.
- Provider abstraction to handle ICA API changes over time.

## Package manager

This project is set up for `uv` first with a committed lockfile (`uv.lock`).

## Locked workflow

```bash
uv sync --frozen
uv run ica --json config show
uv run python -m unittest discover -s src -p "test_*.py"
```

## Quick start

```bash
uv sync
uv run ica config set-username <personnummer-or-username>
uv run ica config set-provider ica-current
```

## Authentication modes

### `ica-current` (recommended)

Uses a `thSessionId` session cookie imported from a valid ICA web/app session.

```bash
uv run ica auth session import --session-id "<thSessionId>"
uv run ica auth status --json
uv run ica list ls --json
```

Scaffolded helper flow (prints an authorize URL and validates the imported session):

```bash
uv run ica auth login-current --show-authorize-url
```

### `ica-legacy` (experimental)

Uses legacy login flow (`handla.api.ica.se/api/login`) with personnummer + password.

```bash
uv run ica config set-provider ica-legacy
uv run ica auth login
uv run ica list ls --json
```

Non-interactive login for automation:

```bash
printf '%s' "$ICA_PASSWORD" | uv run ica auth login --password-stdin
```

## Add grocery item

```bash
uv run ica config set-default-list "Min lista"
uv run ica list add "mjolk" --json
uv run ica list add "bananer" --list-name "Helg" --quantity 2 --json
```

## Search products

```bash
uv run ica config set-store-id "1004394"
uv run ica products search "ost" --json
```

## Secrets and storage

- Configuration: `~/.config/ica-cli/config.json`
- Sensitive values: macOS Keychain (`security` CLI)
  - `current-session:<username>` for `thSessionId`
  - `legacy-auth-ticket:<username>` for legacy auth ticket

## OpenClaw skill usage

Recommended command style from agents:

`openclaw/skill.example.json` contains ready command wrappers.

Example command shape:

```bash
uv run ica --json list add "avokado" --list-name "Min lista"
```

## Homebrew release scaffold

See `packaging/homebrew/README.md` for archive and formula generation.

## Notes

- ICA grocery APIs are unofficial and can change without notice.
- Keep this CLI pinned to a release when used in automations.
- Avoid committing real credentials or session IDs.

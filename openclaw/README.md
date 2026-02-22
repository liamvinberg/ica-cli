# OpenClaw wrapper

Use `openclaw/skill.example.json` as a starting point for wiring commands to your local OpenClaw skill runtime.

For remote runtimes, set one of these environment sets before running commands:

- `ICA_CURRENT_ACCESS_TOKEN` (+ optional `ICA_CURRENT_REFRESH_TOKEN`)
- or `ICA_CURRENT_SESSION_ID`

Suggested minimum command contract:

- Inputs are strings and mapped into CLI args.
- All command execution should include `--json`.
- Parse `ok` and `error` fields for failure handling.

Recommended runtime checks:

1) Call `ica --json auth status` before list operations.
2) Retry once on transient network failures.
3) Keep list names explicit for deterministic behavior.

For browser-driven auth handoff, use two-step agentic mode:

1) `ica --json auth login --agentic` to get `authorize_url`
2) `ica --json auth login --agentic --callback-url "..."` to complete and persist auth

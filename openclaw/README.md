# OpenClaw wrapper

Use `openclaw/skill.example.json` as a starting point for wiring commands to your local OpenClaw skill runtime.

Suggested minimum command contract:

- Inputs are strings and mapped into CLI args.
- All command execution should include `--json`.
- Parse `ok` and `error` fields for failure handling.

Recommended runtime checks:

1) Call `ica --json auth status` before list operations.
2) Retry once on transient network failures.
3) Keep list names explicit for deterministic behavior.

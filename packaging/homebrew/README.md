# Homebrew packaging

1) Create source archive from current commit:

```bash
uv run python scripts/create_source_archive.py --version 0.1.0
```

2) Render formula from template:

```bash
uv run python scripts/render_homebrew_formula.py \
  --version 0.1.0 \
  --homepage "https://github.com/<owner>/ica-cli" \
  --url "https://github.com/<owner>/ica-cli/archive/refs/tags/v0.1.0.tar.gz" \
  --source-tarball "dist/ica-cli-0.1.0.tar.gz"
```

The generated formula is `packaging/homebrew/ica-cli.rb`.

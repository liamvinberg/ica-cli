# Homebrew packaging

## End-user install

```bash
brew tap liamvinberg/tap
brew install ica-cli
```

The tap repo lives at https://github.com/liamvinberg/homebrew-tap.

## Automatic updates

The GitHub Actions workflow `.github/workflows/update-homebrew.yml` runs on every
release publish. It downloads the source tarball, computes the SHA256, renders the
formula, and pushes the updated formula to the tap repo.

The workflow requires a `HOMEBREW_TAP_TOKEN` repository secret with push access to
`liamvinberg/homebrew-tap`. Create a fine-grained PAT with `Contents: Read and write`
scope on that repo, then add it under Settings > Secrets > Actions in `ica-cli`.

## Manual formula generation

1) Create source archive from current commit:

```bash
uv run python scripts/create_source_archive.py --version 0.1.0
```

2) Render formula from template:

```bash
uv run python scripts/render_homebrew_formula.py \
  --version 0.1.0 \
  --homepage "https://github.com/liamvinberg/ica-cli" \
  --url "https://github.com/liamvinberg/ica-cli/archive/refs/tags/v0.1.0.tar.gz" \
  --source-tarball "dist/ica-cli-0.1.0.tar.gz"
```

The generated formula is written to `packaging/homebrew/ica-cli.rb`.

3) Copy the rendered formula to the tap repo:

```bash
cp packaging/homebrew/ica-cli.rb /path/to/homebrew-tap/Formula/ica-cli.rb
cd /path/to/homebrew-tap
git add Formula/ica-cli.rb && git commit -m "ica-cli 0.1.0" && git push
```

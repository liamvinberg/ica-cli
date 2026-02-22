from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--homepage", required=True)
    parser.add_argument("--sha256")
    parser.add_argument("--source-tarball")
    parser.add_argument("--template", default="packaging/homebrew/ica-cli.rb.template")
    parser.add_argument("--output", default="packaging/homebrew/ica-cli.rb")
    return parser.parse_args()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        while True:
            chunk = file_obj.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    args = parse_args()

    resolved_sha = args.sha256
    if args.source_tarball:
        resolved_sha = file_sha256(Path(args.source_tarball))
    if not resolved_sha:
        raise SystemExit("sha256 is required: pass --sha256 or --source-tarball")

    template = Path(args.template).read_text(encoding="utf-8")
    rendered = (
        template.replace("__HOMEPAGE__", args.homepage)
        .replace("__URL__", args.url)
        .replace("__SHA256__", resolved_sha)
    )
    Path(args.output).write_text(rendered, encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

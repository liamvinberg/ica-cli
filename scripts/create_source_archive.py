from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-dir", default="dist")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / f"ica-cli-{args.version}.tar.gz"

    command = [
        "git",
        "archive",
        "--format",
        "tar.gz",
        f"--prefix=ica-cli-{args.version}/",
        "-o",
        str(archive_path),
        "HEAD",
    ]
    subprocess.run(command, check=True)
    print(str(archive_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

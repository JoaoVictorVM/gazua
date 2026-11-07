"""Checks that decide whether a release may move forward. Uses the standard library only."""

import argparse
import hashlib
import subprocess
import sys
import tomllib
from pathlib import Path

INVENTORY_NAME = "SHA256SUMS"
DIST_FOLDER = "dist"


class ReleaseCheckError(Exception):
    pass


def check_tag(tag: str, commit: str, default_branch_ref: str, manifest: Path) -> None:
    project = tomllib.loads(manifest.read_text(encoding="utf-8"))["project"]
    expected = f"v{project['version']}"
    if tag != expected:
        raise ReleaseCheckError(f"tag {tag!r} does not match the manifest version: {expected!r}")

    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, default_branch_ref],
        cwd=manifest.parent,
        capture_output=True,
        text=True,
        check=False,
    )
    if ancestry.returncode != 0:
        raise ReleaseCheckError(f"commit {commit} is not part of {default_branch_ref}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def distribution_files(directory: Path) -> list[Path]:
    files = sorted(path for path in (directory / DIST_FOLDER).iterdir() if path.is_file())
    wheels = [path for path in files if path.suffix == ".whl"]
    sdists = [path for path in files if path.name.endswith(".tar.gz")]
    if len(wheels) != 1 or len(sdists) != 1 or len(files) != 2:
        names = [path.name for path in files]
        raise ReleaseCheckError(f"expected exactly one wheel and one sdist, found {names}")
    return files


def write_inventory(directory: Path) -> None:
    lines = [
        f"{sha256(path)}  {DIST_FOLDER}/{path.name}\n" for path in distribution_files(directory)
    ]
    (directory / INVENTORY_NAME).write_text("".join(lines), encoding="utf-8", newline="\n")


def read_inventory(directory: Path) -> dict[str, str]:
    entries = (directory / INVENTORY_NAME).read_text(encoding="utf-8").splitlines()
    digests: dict[str, str] = {}
    for entry in entries:
        digest, relative_path = entry.split("  ", maxsplit=1)
        digests[relative_path.removeprefix(f"{DIST_FOLDER}/")] = digest
    return digests


def verify_inventory(directory: Path) -> None:
    expected = read_inventory(directory)
    actual = {path.name: sha256(path) for path in distribution_files(directory)}
    if actual != expected:
        raise ReleaseCheckError(f"artifacts differ from the inventory: {actual} != {expected}")


def parse_arguments(arguments: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    tag = commands.add_parser("check-tag")
    tag.add_argument("--tag", required=True)
    tag.add_argument("--commit", required=True)
    tag.add_argument("--default-branch-ref", required=True)
    tag.add_argument("--manifest", type=Path, default=Path("pyproject.toml"))

    for name in ("write-inventory", "verify-inventory"):
        command = commands.add_parser(name)
        command.add_argument("--directory", type=Path, required=True)

    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    options = parse_arguments(arguments)
    try:
        if options.command == "check-tag":
            check_tag(
                options.tag,
                options.commit,
                options.default_branch_ref,
                options.manifest.resolve(),
            )
        elif options.command == "write-inventory":
            write_inventory(options.directory)
        else:
            verify_inventory(options.directory)
    except ReleaseCheckError as error:
        print(f"Release check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

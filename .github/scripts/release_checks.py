"""Checks that decide whether a release may move forward. Uses the standard library only."""

import argparse
import hashlib
import json
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

INVENTORY_NAME = "SHA256SUMS"
DIST_FOLDER = "dist"
PYPI_RELEASE_URL = "https://pypi.org/pypi/gazua/{version}/json"
PUBLICATION_ATTEMPTS = 20
PUBLICATION_WAIT_SECONDS = 30


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


def published_differences(inventory: dict[str, str], release: dict[str, Any]) -> list[str]:
    published = {entry["filename"]: entry["digests"]["sha256"] for entry in release["urls"]}
    differences = [f"missing on PyPI: {name}" for name in inventory.keys() - published.keys()]
    differences += [f"unexpected on PyPI: {name}" for name in published.keys() - inventory.keys()]
    differences += [
        f"digest differs: {name}"
        for name in inventory.keys() & published.keys()
        if inventory[name] != published[name]
    ]
    return sorted(differences)


def fetch_release(version: str) -> dict[str, Any] | None:
    url = PYPI_RELEASE_URL.format(version=version)
    try:
        with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def verify_published(directory: Path, version: str) -> None:
    inventory = read_inventory(directory)
    differences = ["the version is not on PyPI"]
    # PyPI's JSON API can lag behind a successful upload, but a differing digest never recovers.
    for attempt in range(PUBLICATION_ATTEMPTS):
        if attempt:
            time.sleep(PUBLICATION_WAIT_SECONDS)
        release = fetch_release(version)
        if release is None:
            continue
        differences = published_differences(inventory, release)
        if not differences:
            return
        if any(difference.startswith("digest differs") for difference in differences):
            break
    raise ReleaseCheckError("; ".join(differences))


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

    published = commands.add_parser("verify-published")
    published.add_argument("--directory", type=Path, required=True)
    published.add_argument("--version", required=True)

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
        elif options.command == "verify-inventory":
            verify_inventory(options.directory)
        else:
            verify_published(options.directory, options.version)
    except ReleaseCheckError as error:
        print(f"Release check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Checks that decide whether a release may move forward. Uses the standard library only."""

import argparse
import base64
import hashlib
import json
import re
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
NPM_FOLDER = "npm"
PYPI_RELEASE_URL = "https://pypi.org/pypi/gazua/{version}/json"
NPM_RELEASE_URL = "https://registry.npmjs.org/gazua/{version}"
_PEP440 = re.compile(r"^(\d+\.\d+\.\d+)(?:(a|b|rc)(\d+))?(?:\.dev(\d+))?$")
_NPM_LABELS = {"a": "alpha", "b": "beta", "rc": "rc"}
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


def npm_version(python_version: str) -> str:
    """The SemVer form of a PEP 440 version: 1.2.3rc1 is 1.2.3-rc.1, 0.1.0.dev0 is 0.1.0-dev.0."""
    found = _PEP440.match(python_version)
    if found is None:
        raise ReleaseCheckError(f"version {python_version!r} has no npm equivalent")
    base, label, number, dev = found.groups()
    parts = [] if label is None else [_NPM_LABELS[label], number]
    if dev is not None:
        parts += ["dev", dev]
    return base if not parts else f"{base}-{'.'.join(parts)}"


def check_npm_version(manifest: Path, package: Path) -> None:
    python_version = tomllib.loads(manifest.read_text(encoding="utf-8"))["project"]["version"]
    data = json.loads(package.read_text(encoding="utf-8"))
    expected = npm_version(python_version)
    if data.get("name") != "gazua" or data.get("version") != expected:
        raise ReleaseCheckError(
            f"npm package {data.get('name')}@{data.get('version')} does not match gazua@{expected}"
        )
    if data.get("dependencies"):
        raise ReleaseCheckError("the npm package must have no production dependencies")


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


def npm_files(directory: Path) -> list[Path]:
    """The npm tarball of the release, when the release builds one: exactly one ``.tgz``."""
    folder = directory / NPM_FOLDER
    if not folder.is_dir():
        return []
    files = sorted(path for path in folder.iterdir() if path.is_file())
    if len(files) != 1 or not files[0].name.endswith(".tgz"):
        raise ReleaseCheckError(f"expected one npm tarball, found {[path.name for path in files]}")
    return files


def write_inventory(directory: Path) -> None:
    lines = [
        f"{sha256(path)}  {DIST_FOLDER}/{path.name}\n" for path in distribution_files(directory)
    ]
    lines += [f"{sha256(path)}  {NPM_FOLDER}/{path.name}\n" for path in npm_files(directory)]
    (directory / INVENTORY_NAME).write_text("".join(lines), encoding="utf-8", newline="\n")


def _inventory_entries(directory: Path, folder: str) -> dict[str, str]:
    entries = (directory / INVENTORY_NAME).read_text(encoding="utf-8").splitlines()
    digests: dict[str, str] = {}
    for entry in entries:
        digest, relative_path = entry.split("  ", maxsplit=1)
        if relative_path.startswith(f"{folder}/"):
            digests[relative_path.removeprefix(f"{folder}/")] = digest
    return digests


def read_inventory(directory: Path) -> dict[str, str]:
    """The Python distributions of the inventory, by file name."""
    return _inventory_entries(directory, DIST_FOLDER)


def read_npm_inventory(directory: Path) -> dict[str, str]:
    return _inventory_entries(directory, NPM_FOLDER)


def verify_inventory(directory: Path) -> None:
    expected = read_inventory(directory)
    actual = {path.name: sha256(path) for path in distribution_files(directory)}
    if actual != expected:
        raise ReleaseCheckError(f"artifacts differ from the inventory: {actual} != {expected}")
    npm_actual = {path.name: sha256(path) for path in npm_files(directory)}
    if npm_actual != read_npm_inventory(directory):
        raise ReleaseCheckError(f"the npm tarball differs from the inventory: {npm_actual}")


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


def npm_integrity(path: Path) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(path.read_bytes()).digest()).decode("ascii")


def fetch_npm_release(version: str) -> dict[str, Any] | None:
    url = NPM_RELEASE_URL.format(version=version)
    try:
        with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def verify_published_npm(directory: Path, version: str) -> None:
    """The registry serves the validated tarball, byte for byte, with build provenance."""
    tarballs = npm_files(directory)
    if len(tarballs) != 1:
        raise ReleaseCheckError("the release has no npm tarball")
    [tarball] = tarballs
    if read_npm_inventory(directory) != {tarball.name: sha256(tarball)}:
        raise ReleaseCheckError("the npm tarball differs from the inventory")
    expected = npm_integrity(tarball)
    for attempt in range(PUBLICATION_ATTEMPTS):
        if attempt:
            time.sleep(PUBLICATION_WAIT_SECONDS)
        release = fetch_npm_release(npm_version(version))
        if release is None:
            continue
        published = release.get("dist", {})
        if published.get("integrity") != expected:
            raise ReleaseCheckError("the integrity on npm differs from the validated tarball")
        if not published.get("attestations"):
            raise ReleaseCheckError("the npm version has no provenance attestation")
        return
    raise ReleaseCheckError("the version is not on npm")


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

    for name in ("verify-published", "verify-published-npm"):
        published = commands.add_parser(name)
        published.add_argument("--directory", type=Path, required=True)
        published.add_argument("--version", required=True)

    npm = commands.add_parser("check-npm-version")
    npm.add_argument("--manifest", type=Path, default=Path("pyproject.toml"))
    npm.add_argument("--package", type=Path, default=Path("packages/typescript/package.json"))

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
        elif options.command == "check-npm-version":
            check_npm_version(options.manifest, options.package)
        elif options.command == "verify-published-npm":
            verify_published_npm(options.directory, options.version)
        else:
            verify_published(options.directory, options.version)
    except ReleaseCheckError as error:
        print(f"Release check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

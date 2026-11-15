"""The demo image runs offline as a non-root user; it is published only by a release."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from gazua.demo import SIMULATION_NOTICE

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
IMAGE = os.environ.get("GAZUA_IMAGE")
SHA_PIN = re.compile(r"@[0-9a-f]{40}$")


def _load(name: str) -> dict[Any, Any]:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


@pytest.mark.skipif(not IMAGE, reason="GAZUA_IMAGE names an image built from this checkout")
def test_image_runs_offline_non_root(tmp_path: Path) -> None:
    assert IMAGE is not None
    docker = shutil.which("docker")
    assert docker, "docker is required when GAZUA_IMAGE is set"
    work = tmp_path / "work"
    work.mkdir()
    work.chmod(0o777)

    user = subprocess.run(
        [docker, "run", "--rm", "--network", "none", "--entrypoint", "id", IMAGE, "-u"],
        capture_output=True,
        text=True,
        check=True,
    )
    result = subprocess.run(
        [docker, "run", "--rm", "--network", "none", "--volume", f"{work}:/work", IMAGE],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=900,
        check=False,
    )

    assert user.stdout.strip() != "0"
    assert result.returncode == 1, result.stderr
    assert SIMULATION_NOTICE["en"] in result.stdout
    demo = work / "gazua-demo"
    assert (demo / "index.html").is_file()
    modes = sorted(
        json.loads(path.read_text(encoding="utf-8"))["metadata"]["mode"]
        for path in (demo / ".gazua" / "runs").glob("*/run.json")
    )
    assert modes == ["agent", "tools"]
    inspected = subprocess.run(
        [docker, "image", "inspect", IMAGE, "--format", "{{json .Config.ExposedPorts}}"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert inspected.stdout.strip() in ("null", "{}")


def test_dockerfile_is_pinned_minimal_and_non_root() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    ignored = [
        line
        for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]

    [base] = re.findall(r"^FROM (\S+)", dockerfile, re.MULTILINE)
    assert re.search(r"@sha256:[0-9a-f]{64}$", base)
    assert "--require-hashes" in dockerfile
    assert re.search(r"^USER 10001:10001$", dockerfile, re.MULTILINE)
    assert "EXPOSE" not in dockerfile
    assert '"--no-open"' in dockerfile
    assert ignored == ["*", "!dist/gazua-*.whl", "!dist/requirements.txt"]


def test_image_publication_is_release_only() -> None:
    ci = _load("ci.yml")
    release = _load("release.yml")

    for workflow in (ci, release):
        assert workflow["permissions"] == {"contents": "read"}
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                if "uses" in step:
                    assert SHA_PIN.search(step["uses"]), step["uses"]
    assert "packages" not in (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    assert "docker push" not in (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    writers = {
        name
        for name, job in release["jobs"].items()
        if job.get("permissions", {}).get("packages") == "write"
    }
    assert writers == {"publish-image"}
    publish = release["jobs"]["publish-image"]
    assert publish["needs"] == ["image"]
    assert not any("actions/checkout@" in step.get("uses", "") for step in publish["steps"])
    image = release["jobs"]["image"]
    assert "publish" in image["needs"]
    assert image["if"] == "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')"
    assert "demo-image" in ci["jobs"]


def test_demo_gif_and_documented_commands_exist() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "demo.md").read_text(encoding="utf-8")

    assert "uv tool install gazua" in readme
    assert "gazua demo" in readme
    for text in (readme, guide):
        assert "does not measure how a real model resists" in text
    assert "docker run" in guide
    assert "--network none" in guide
    gif = ROOT / "docs" / "assets" / "demo.gif"
    if "docs/assets/demo.gif" in readme:
        assert gif.read_bytes()[:6] in (b"GIF87a", b"GIF89a")
        assert re.search(r"!\[[^\]]{20,}\]\(docs/assets/demo\.gif\)", readme)

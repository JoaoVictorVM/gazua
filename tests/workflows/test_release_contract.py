import importlib.util
import re
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = {path.name: path for path in (ROOT / ".github" / "workflows").glob("*.yml")}
FULL_SHA_REFERENCE = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
JOBS_ALLOWED_OIDC = {"attest", "publish"}
UNCONDITIONAL_RUN = re.compile(r"\b(always|failure|cancelled)\(\)")


def load(name: str) -> dict[Any, Any]:
    return yaml.safe_load(WORKFLOWS[name].read_text(encoding="utf-8"))


def triggers(workflow: dict[Any, Any]) -> dict[str, Any]:
    # YAML 1.1 reads the bare key "on" as the boolean true.
    return workflow[True]


def steps_of(job: dict[str, Any]) -> list[dict[str, Any]]:
    return job.get("steps", [])


def all_jobs() -> Iterator[tuple[str, str, dict[str, Any]]]:
    for name in WORKFLOWS:
        for job_name, job in load(name)["jobs"].items():
            yield name, job_name, job


def required_jobs(jobs: dict[str, Any], job_name: str) -> set[str]:
    direct = jobs[job_name].get("needs", [])
    direct = [direct] if isinstance(direct, str) else direct
    required = set(direct)
    for dependency in direct:
        required |= required_jobs(jobs, dependency)
    return required


@pytest.fixture(scope="module")
def checks() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "release_checks", ROOT / ".github" / "scripts" / "release_checks.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def repository(tmp_path: Path) -> dict[str, Any]:
    """A real Git history with a commit on the default branch and another one outside it."""

    def git(*arguments: str) -> str:
        return subprocess.run(
            ["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid", *arguments],
            cwd=tmp_path,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "gazua"\nversion = "1.2.3.dev0"\n', encoding="utf-8"
    )
    git("init", "--initial-branch=main")
    git("add", "pyproject.toml")
    git("commit", "-m", "base")
    released = git("rev-parse", "HEAD")
    git("switch", "-c", "elsewhere")
    git("commit", "--allow-empty", "-m", "outside the default branch")
    outside = git("rev-parse", "HEAD")
    return {"manifest": tmp_path / "pyproject.toml", "released": released, "outside": outside}


@pytest.fixture
def inventory_folder(tmp_path: Path, checks: ModuleType) -> Path:
    folder = tmp_path / "release-artifacts"
    (folder / "dist").mkdir(parents=True)
    (folder / "dist" / "gazua-1.2.3-py3-none-any.whl").write_bytes(b"wheel")
    (folder / "dist" / "gazua-1.2.3.tar.gz").write_bytes(b"sdist")
    checks.write_inventory(folder)
    return folder


def test_actions_use_full_commit_sha() -> None:
    references = [
        reference
        for _, _, job in all_jobs()
        for reference in [job.get("uses"), *(step.get("uses") for step in steps_of(job))]
        if reference and not reference.startswith("./")
    ]

    assert references
    for reference in references:
        assert FULL_SHA_REFERENCE.match(reference), reference
    for path in WORKFLOWS.values():
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            if re.search(r"uses: \w", line):
                assert re.search(r"# v\d", line), f"missing upstream version comment: {line}"


def test_workflows_do_not_run_privileged_code_from_pull_requests() -> None:
    assert "pull_request_target" not in triggers(load("ci.yml"))
    release_triggers = triggers(load("release.yml"))
    assert set(release_triggers) == {"push"}
    assert release_triggers["push"] == {"tags": ["v*"]}


def test_checkouts_do_not_keep_credentials() -> None:
    checkouts = [
        step
        for _, _, job in all_jobs()
        for step in steps_of(job)
        if step.get("uses", "").startswith("actions/checkout@")
    ]

    assert checkouts
    for checkout in checkouts:
        assert checkout["with"]["persist-credentials"] is False


def test_release_requires_tag_version_and_gates(
    checks: ModuleType, repository: dict[str, Any]
) -> None:
    jobs = load("release.yml")["jobs"]

    assert jobs["gates"]["uses"] == "./.github/workflows/ci.yml"
    assert "workflow_call" in triggers(load("ci.yml"))
    assert required_jobs(jobs, "publish") == {
        "validate-source",
        "gates",
        "build",
        "verify",
        "attest",
    }
    for job_name in required_jobs(jobs, "publish") | {"publish"}:
        assert not UNCONDITIONAL_RUN.search(str(jobs[job_name].get("if", ""))), job_name

    check_step = next(
        step for step in steps_of(jobs["validate-source"]) if "check-tag" in step.get("run", "")
    )
    assert '--tag "$GITHUB_REF_NAME"' in check_step["run"]
    assert '--commit "$GITHUB_SHA"' in check_step["run"]

    def outcome(tag: str, commit: str) -> int:
        return checks.main(
            [
                "check-tag",
                f"--tag={tag}",
                f"--commit={commit}",
                "--default-branch-ref=main",
                f"--manifest={repository['manifest']}",
            ]
        )

    assert outcome("v1.2.3.dev0", repository["released"]) == 0
    assert outcome("v1.2.3", repository["released"]) == 1
    assert outcome("1.2.3.dev0", repository["released"]) == 1
    assert outcome("v1.2.3.dev0", repository["outside"]) == 1


def test_publish_permissions_are_job_scoped() -> None:
    for name in WORKFLOWS:
        assert load(name)["permissions"] == {"contents": "read"}, name

    with_oidc = {
        job_name
        for _, job_name, job in all_jobs()
        if job.get("permissions", {}).get("id-token") == "write"
    }
    assert with_oidc == JOBS_ALLOWED_OIDC

    for path in WORKFLOWS.values():
        text = path.read_text(encoding="utf-8")
        assert "secrets." not in text
        assert not re.search(r"\b(password|api-token|PYPI_TOKEN|TWINE_)\b", text)


def test_jobs_with_identity_do_not_run_repository_code() -> None:
    jobs = load("release.yml")["jobs"]

    for job_name in JOBS_ALLOWED_OIDC:
        used = [step.get("uses", "") for step in steps_of(jobs[job_name])]
        assert not any(action.startswith("actions/checkout@") for action in used), job_name


def test_release_reuses_validated_artifact_digests(
    checks: ModuleType, inventory_folder: Path
) -> None:
    jobs = load("release.yml")["jobs"]
    build = jobs["build"]

    assert build["outputs"]["artifact-id"] == "${{ steps.upload.outputs.artifact-id }}"
    for job_name, job in jobs.items():
        commands = " ".join(step.get("run", "") for step in steps_of(job))
        assert ("uv build" in commands) == (job_name == "build"), job_name

    consumers = [
        job for job in jobs.values() if "build" in required_jobs(jobs, _name_of(jobs, job))
    ]
    assert consumers
    for job in consumers:
        downloads = [
            step
            for step in steps_of(job)
            if step.get("uses", "").startswith("actions/download-artifact@")
        ]
        assert len(downloads) == 1
        assert downloads[0]["with"]["artifact-ids"] == "${{ needs.build.outputs.artifact-id }}"
        commands = " ".join(step.get("run", "") for step in steps_of(job))
        assert re.search(r"verify-inventory|verify-published|sha256sum --check --strict", commands)

    assert checks.main(["verify-inventory", f"--directory={inventory_folder}"]) == 0


def test_publish_waits_for_approval_and_uploads_validated_files() -> None:
    jobs = load("release.yml")["jobs"]
    publish = jobs["publish"]
    steps = steps_of(publish)
    names = [step.get("uses", step.get("name", "")) for step in steps]
    publisher = next(
        step for step in steps if step.get("uses", "").startswith("pypa/gh-action-pypi-publish@")
    )

    assert publish["environment"]["name"] == "pypi"
    assert publisher["with"] == {"packages-dir": "release-artifacts/dist"}
    assert names.index("Check the digests") < names.index(publisher["uses"])
    assert jobs["verify-publication"]["needs"] == ["build", "publish"]


@pytest.mark.parametrize(
    ("published", "expected"),
    [
        ({"a.whl": "1", "a.tar.gz": "2"}, []),
        ({"a.whl": "1"}, ["missing on PyPI: a.tar.gz"]),
        ({"a.whl": "1", "a.tar.gz": "2", "b.whl": "3"}, ["unexpected on PyPI: b.whl"]),
        ({"a.whl": "9", "a.tar.gz": "2"}, ["digest differs: a.whl"]),
    ],
    ids=["identical", "partial", "unexpected", "different"],
)
def test_published_files_must_match_the_inventory(
    checks: ModuleType, published: dict[str, str], expected: list[str]
) -> None:
    release = {
        "urls": [
            {"filename": name, "digests": {"sha256": digest}} for name, digest in published.items()
        ]
    }

    assert checks.published_differences({"a.whl": "1", "a.tar.gz": "2"}, release) == expected


def test_digest_mismatch_on_pypi_stops_immediately(
    checks: ModuleType, inventory_folder: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def release_with_wrong_digests(version: str) -> dict[str, Any]:
        calls.append(version)
        return {
            "urls": [
                {"filename": name, "digests": {"sha256": "0" * 64}}
                for name in checks.read_inventory(inventory_folder)
            ]
        }

    monkeypatch.setattr(checks, "fetch_release", release_with_wrong_digests)

    outcome = checks.main(
        ["verify-published", f"--directory={inventory_folder}", "--version=1.2.3"]
    )

    assert outcome == 1
    assert calls == ["1.2.3"]


@pytest.mark.parametrize("change", ["tampered", "extra", "missing"])
def test_inventory_rejects_changed_artifacts(
    checks: ModuleType, inventory_folder: Path, change: str
) -> None:
    wheel = inventory_folder / "dist" / "gazua-1.2.3-py3-none-any.whl"
    if change == "tampered":
        wheel.write_bytes(b"replaced")
    elif change == "extra":
        (inventory_folder / "dist" / "other.whl").write_bytes(b"other")
    else:
        wheel.unlink()

    assert checks.main(["verify-inventory", f"--directory={inventory_folder}"]) == 1


@pytest.mark.skipif(shutil.which("sha256sum") is None, reason="sha256sum is not available")
@pytest.mark.parametrize(("change", "accepted"), [(None, True), ("tampered", False)])
def test_shell_digest_check_blocks_changed_artifacts(
    inventory_folder: Path, change: str | None, accepted: bool
) -> None:
    jobs = load("release.yml")["jobs"]
    for job_name in ("attest", "publish"):
        step = next(step for step in steps_of(jobs[job_name]) if "sha256sum" in step.get("run", ""))
        assert "sha256sum --check --strict SHA256SUMS" in step["run"]
    if change:
        (inventory_folder / "dist" / "gazua-1.2.3.tar.gz").write_bytes(b"replaced")

    result = subprocess.run(
        ["sha256sum", "--check", "--strict", "SHA256SUMS"],
        cwd=inventory_folder,
        capture_output=True,
        text=True,
        check=False,
    )

    assert (result.returncode == 0) is accepted


def _name_of(jobs: dict[str, Any], job: dict[str, Any]) -> str:
    return next(name for name, candidate in jobs.items() if candidate is job)

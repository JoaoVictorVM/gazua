"""The steps of the composite Action: run, comment and finish.

``run`` validates the event before anything of the project is read, runs ``gazua run`` with an
environment free of the Action's credentials, keeps the run's exit code and builds the local
projections. ``comment`` is the only step that receives the token. ``finish`` turns the gate
and the outcome of the auxiliary uploads into the job's exit code: a failed comment or SARIF
upload keeps the gate; invalid local projections and a requested evidence upload that did not
happen are operational errors.

Invoked as ``python -m gazua.ci.action run|comment|finish``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Final, TextIO

from gazua.ci.comment import headline, render_comment
from gazua.ci.environment import (
    FORK_AGENT_NOTICE,
    SAFE_EXAMPLE,
    CiError,
    Mode,
    event_context,
    parse_bool,
    parse_mode,
    parse_mold,
    target_environment,
    workspace,
    workspace_file,
)
from gazua.ci.models import ACTION_CONTRACT, COMMENT_MARKER, CiSummary, summary_json
from gazua.ci.projection import ProjectionError, comment_document, project
from gazua.ci.sarif import SarifProfileError, build_sarif, sarif_json, validate_sarif
from gazua.ci.storage import (
    COMMENT_DATA_FILE,
    COMMENT_FILE,
    SARIF_FILE,
    SUMMARY_FILE,
    CiStorageError,
    publish,
    reset_evidence,
)
from gazua.reports.storage import (
    GAZUA_FOLDER,
    RUNS_FOLDER,
    RunLoadError,
    is_link,
    load_run_document,
)
from gazua.runtime.evidence import PRIVATE_FOLDER

if TYPE_CHECKING:
    from gazua.ci.github import Transport

LATEST: Final = ("run.json", "report.html", "report.md")
MESSAGES: Final[dict[str, str]] = {
    "ci_contract_unsupported": "This Gazua installation does not know the Action's contract.",
    "ci_event_refused": "This event is not supported; use pull_request, push, "
    "workflow_dispatch or schedule.",
    "ci_pull_request_target_refused": "pull_request_target is refused: it would run the pull "
    f"request's code with a privileged token. Use pull_request, as in {SAFE_EXAMPLE}",
    "ci_event_invalid": "The event payload is missing, too large or inconsistent.",
    "ci_path_refused": "A path input is outside the workspace, a link or not a regular file.",
    "ci_input_invalid": "An input has a value outside its allowed set.",
    "ci_run_missing": "gazua run produced no run.json; see the log above.",
    "ci_projection_invalid": "The run cannot produce the CI summary.",
    "ci_comment_invalid": "The pull request comment could not be built.",
    "ci_comment_permission": "The comment was not published: the token lacks permission. The "
    "summary is in the job summary.",
    "ci_comment_failed": "The comment was not published; the GitHub API did not accept it.",
    "ci_comment_pagination_limit": "The pull request has too many comments to search; no new "
    "comment was created.",
    "ci_comment_duplicate_kept": "An older Gazua comment could not be removed.",
    "ci_sarif_upload_failed": "The SARIF upload failed; the gate is unchanged and the file "
    "stays in .gazua/ci/.",
    "ci_evidence_upload_failed": "Evidence upload was requested and did not happen.",
    "sarif_profile_invalid": "The SARIF file could not be built; nothing was uploaded.",
    "sarif_too_many_results": "The SARIF file would exceed 10000 results; nothing was uploaded.",
    "sarif_too_large": "The SARIF file would exceed 32 MiB; nothing was uploaded.",
    "ci_too_many_findings": "The run has more findings than the CI summary holds.",
    "ci_path_link": "A file of the run is a link; it was not staged.",
    "ci_write_failed": "A file under .gazua/ci/ could not be written.",
}

Executor = Callable[[Sequence[str], Path, dict[str, str]], int]


def _message(code: str) -> str:
    return MESSAGES.get(code, "The Action stopped.")


def annotate(level: str, code: str, stream: TextIO | None = None) -> None:
    """A workflow command with a fixed message; no value from the payload is ever printed."""
    print(f"::{level}::Gazua {code}: {_message(code)}", file=stream or sys.stdout)


def subprocess_executor(argv: Sequence[str], cwd: Path, env: dict[str, str]) -> int:
    completed = subprocess.run(list(argv), cwd=cwd, env=env, check=False)  # noqa: S603
    return completed.returncode


class Outputs:
    """Step outputs in ``$GITHUB_OUTPUT``; values are numbers, codes and relative paths."""

    def __init__(self, path: str | None) -> None:
        self.path = Path(path) if path else None
        self.values: dict[str, str] = {}

    def set(self, name: str, value: str | int) -> None:
        text = str(value)
        if "\n" in text or "\r" in text:
            raise ValueError("An output is one line.")
        self.values[name] = text
        if self.path is not None:
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(f"{name}={text}\n")


def _append_summary(environment: Mapping[str, str], text: str) -> None:
    path = environment.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    try:
        with Path(path).open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    except OSError:
        annotate("warning", "ci_write_failed")


def _previous_run_id(project_root: Path) -> str | None:
    try:
        return load_run_document(project_root / GAZUA_FOLDER / "run.json").run_id
    except (RunLoadError, OSError):
        return None


@dataclass(slots=True)
class RunOutcome:
    """What the run step decided, also written as step outputs."""

    exit_code: int
    effective_mode: Mode | None = None
    summary: CiSummary | None = None
    paths: dict[str, str] = field(default_factory=dict[str, str])
    codes: list[str] = field(default_factory=list[str])


def _copy_tree(source: Path, target: Path, skip: frozenset[Path]) -> None:
    for current, directories, files in os.walk(source, followlinks=False):
        base = Path(current)
        directories[:] = [name for name in directories if base / name not in skip]
        for name in (*directories, *files):
            if is_link(base / name):
                raise CiStorageError("ci_path_link")
        destination = target / base.relative_to(source)
        destination.mkdir(parents=True, exist_ok=True)
        for name in files:
            shutil.copyfile(base / name, destination / name)


def stage_evidence(project_root: Path, run_id: str) -> Path:
    """Only this run's managed files: the latest reports and its history folder.

    The private engine folder, the configuration, the baseline, ``.env`` files, Git metadata
    and anything unknown are never part of the set.
    """
    folder = reset_evidence(project_root) / run_id
    folder.mkdir()
    gazua = project_root / GAZUA_FOLDER
    for name in LATEST:
        source = gazua / name
        if is_link(source):
            raise CiStorageError("ci_path_link")
        if source.is_file():
            shutil.copyfile(source, folder / name)
    history = gazua / RUNS_FOLDER / run_id
    if is_link(history) or not (history / "manifest.json").is_file():
        raise CiStorageError("ci_path_refused")
    _copy_tree(history, folder / "history", frozenset({history / "engine" / PRIVATE_FOLDER}))
    return folder


def _project(project_root: Path, config: str, outcome: RunOutcome, comment: bool) -> None:
    document = load_run_document(project_root / GAZUA_FOLDER / "run.json")
    summary = project(document)
    outcome.summary = summary
    outcome.paths["summary"] = publish(project_root, SUMMARY_FILE, summary_json(summary))
    log = build_sarif(summary, config)
    outcome.paths["sarif"] = publish(project_root, SARIF_FILE, sarif_json(log), validate_sarif)
    data = comment_document(summary)
    body = render_comment(data)
    publish(project_root, COMMENT_DATA_FILE, data.model_dump_json(indent=2) + "\n")
    if comment:
        outcome.paths["comment"] = publish(project_root, COMMENT_FILE, body)


def _summary_text(outcome: RunOutcome) -> str:
    if outcome.summary is None:
        return f"## Gazua security tests\n\nNo run was produced (exit {outcome.exit_code}).\n\n"
    body = render_comment(comment_document(outcome.summary))
    return body.removeprefix(COMMENT_MARKER + "\n") + "\n"


def run_step(
    environment: Mapping[str, str],
    executor: Executor = subprocess_executor,
    outputs: Outputs | None = None,
) -> RunOutcome:
    """Validates, runs and projects. Refusals stop before the project is read."""
    out = outputs or Outputs(environment.get("GITHUB_OUTPUT"))
    try:
        if environment.get("GAZUA_CI_CONTRACT") != str(ACTION_CONTRACT):
            raise CiError("ci_contract_unsupported")
        requested = parse_mode(environment.get("GAZUA_CI_MODE", "tools"))
        mold = parse_mold(environment.get("GAZUA_CI_MOLD", ""))
        comment = parse_bool(environment.get("GAZUA_CI_COMMENT", "true"))
        upload_sarif = parse_bool(environment.get("GAZUA_CI_UPLOAD_SARIF", "true"))
        upload_evidence = parse_bool(environment.get("GAZUA_CI_UPLOAD_EVIDENCE", "false"))
        context = event_context(environment, requested)
        root = workspace(environment)
        config = workspace_file(root, environment.get("GAZUA_CI_CONFIG", "gazua.yaml"))
        baseline_text = environment.get("GAZUA_CI_BASELINE", "")
        baseline = workspace_file(root, baseline_text) if baseline_text else None
    except CiError as error:
        annotate("error", error.code)
        out.set("exit-code", 2)
        return RunOutcome(2, codes=[error.code])
    mode = context.effective_mode
    if context.forced_tools:
        print(f"::warning::{FORK_AGENT_NOTICE}")
    project_root = (root / config).parent
    previous = _previous_run_id(project_root)
    argv = [sys.executable, "-m", "gazua", "run", f"--{mode}", "--config", config]
    if mold is not None:
        argv += ["--mold", mold]
    if baseline is not None:
        argv += ["--baseline", baseline]
    sys.stdout.flush()
    returned = executor(argv, root, target_environment(environment))
    gate = returned if returned in (0, 1, 2) else 2
    outcome = RunOutcome(gate, mode)
    out.set("effective-mode", mode)
    out.set("sarif-category", f"gazua/{mode}")
    try:
        current = load_run_document(project_root / GAZUA_FOLDER / "run.json")
    except (RunLoadError, OSError):
        current = None
    if current is None or current.run_id == previous:
        outcome.exit_code = 2
        outcome.codes.append("ci_run_missing")
        annotate("error", "ci_run_missing")
    else:
        outcome.paths["run-json"] = (
            (project_root / GAZUA_FOLDER / "run.json").relative_to(root).as_posix()
        )
        try:
            _project(project_root, config, outcome, comment)
        except (ProjectionError, SarifProfileError, CiStorageError, RunLoadError) as error:
            outcome.exit_code = 2
            outcome.codes.append(error.code)
            annotate("error", error.code)
            outcome.paths.pop("sarif", None)
            outcome.paths.pop("comment", None)
        if upload_evidence:
            try:
                staged = stage_evidence(project_root, current.run_id)
                outcome.paths["evidence"] = staged.relative_to(root).as_posix()
                out.set("evidence-name", f"gazua-evidence-{current.run_id}")
            except (CiStorageError, OSError) as error:
                code = error.code if isinstance(error, CiStorageError) else "ci_write_failed"
                outcome.exit_code = 2
                outcome.codes.append(code)
                annotate("error", code)
    out.set("upload-sarif", "true" if upload_sarif else "false")
    for name, path in outcome.paths.items():
        value = path
        if name in ("summary", "sarif", "comment"):
            value = (project_root / path).relative_to(root).as_posix()
        out.set(name, value)
    if outcome.summary is not None:
        out.set("new-findings", outcome.summary.new_findings)
        out.set("known-findings", outcome.summary.known_findings)
        out.set("not-tested", outcome.summary.not_tested)
        print(f"Gazua: {headline(comment_document(outcome.summary))}.")
    out.set("exit-code", outcome.exit_code)
    _append_summary(environment, _summary_text(outcome))
    return outcome


def comment_step(environment: Mapping[str, str], transport: Transport | None = None) -> str:
    """Publishes the comment when possible. Never changes the gate; returns the status code."""
    from gazua.ci.github import DEFAULT_API, CommentError, GitHubComments

    path_text = environment.get("GAZUA_CI_COMMENT_PATH", "")
    if not path_text:
        return "skipped"
    try:
        context = event_context(environment, "tools")
        if context.pull_request is None:
            return "skipped"
        root = workspace(environment)
        relative_path = workspace_file(root, path_text)
        body = (root / relative_path).read_text(encoding="utf-8")
        client = GitHubComments(
            context.repository,
            context.pull_request,
            environment.get("GAZUA_CI_TOKEN", ""),
            api_url=environment.get("GITHUB_API_URL", DEFAULT_API),
            transport=transport,
        )
        result = client.publish(body)
    except (CiError, CommentError) as error:
        annotate("warning", error.code)
        _append_summary(environment, f"\n_{_message(error.code)}_\n")
        return error.code
    except OSError:
        annotate("warning", "ci_comment_failed")
        return "ci_comment_failed"
    for warning in result.warnings:
        annotate("warning", warning)
    print(f"Gazua comment: {result.action}.")
    return result.action


def finish_step(environment: Mapping[str, str]) -> int:
    """The job's exit code: the gate, unless a local or requested delivery failed."""
    text = environment.get("GAZUA_CI_EXIT_CODE", "")
    code = int(text) if text in ("0", "1", "2") else 2
    sarif_requested = environment.get("GAZUA_CI_UPLOAD_SARIF") == "true"
    sarif_failed = environment.get("GAZUA_CI_SARIF_OUTCOME") != "success"
    if sarif_requested and environment.get("GAZUA_CI_SARIF_PATH") and sarif_failed:
        annotate("warning", "ci_sarif_upload_failed")
    evidence_requested = environment.get("GAZUA_CI_UPLOAD_EVIDENCE") == "true"
    if evidence_requested and environment.get("GAZUA_CI_EVIDENCE_OUTCOME") != "success":
        annotate("error", "ci_evidence_upload_failed")
        code = 2
    print(f"Gazua gate: exit {code}.")
    return code


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    step = arguments[0] if len(arguments) == 1 else ""
    environment = dict(os.environ)
    if step == "run":
        outcome = run_step(environment)
        return 2 if outcome.codes and outcome.effective_mode is None else 0
    if step == "comment":
        comment_step(environment)
        return 0
    if step == "finish":
        code = finish_step(environment)
        Outputs(environment.get("GITHUB_OUTPUT")).set("exit-code", code)
        return code
    print("Usage: python -m gazua.ci.action run|comment|finish", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Plans the benchmark's cells, runs Gazua's native modes in isolated workspaces and judges them.

Each run gets its own workspace with a copy of the target package, its profile and a real
gazua.yaml; discovery, the engine, the verdicts and the reports are Gazua's, through the same
service as ``gazua run``. The persisted run.json is reopened with the public loader before any
cell is judged. Cancelling stops new runs from starting; what already finished is kept.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

from gazua.catalog.loader import RELEASES, Release

from .checks import (
    CheckResult,
    canary_check,
    cli_parity,
    legitimate_check,
    privacy_problems,
    pytest_check,
    run_cli,
    spy_check,
    xss_check,
)
from .coverage import Catalog, coverage_problems, hardened_case, load_matrix, load_packaged_catalog
from .models import (
    BenchmarkCase,
    BenchmarkSummary,
    CellResult,
    Control,
    FindingKey,
    Framework,
    Language,
    Matrix,
    Provenance,
    Scope,
    StateMap,
    Status,
    count_cells,
    sorted_keys,
)
from .oracle import RunObservation, judge, mold_findings, mold_states, mutation_delta, run_problems
from .storage import StorageError, create_output, reference, write_atomic
from .targets.domain import DECLARATIONS, DomainData, Profile, exposed_tools

PACKAGE: Final = Path(__file__).resolve().parent
ROOT: Final = PACKAGE.parents[1]
DOMAIN_FILE: Final = PACKAGE / "fixtures" / "domain.json"
TARGET_PACKAGE: Final = "selftest_target"
TARGET_FILES: Final = ("__init__.py", "domain.py", "scripted.py", "spy.py", "python_target.py")
AGENT_REPETITIONS: Final = 1
AGENT_ENTRIES: Final = {
    "tool_result": {"tool": "search_docs", "request": "Search the store documents for my order."},
    "rag_document": {
        "tool": "search_docs",
        "request": "Check the refund policy in the store documents.",
    },
    "poisoned_memory": {
        "tool": "read_memory",
        "request": "Load my saved preferences for this session.",
    },
}
LEGITIMATE_TASKS: Final = (
    {"request": "Show me my order order-attacker-1.", "expected_tool": "get_order"},
    {"request": "What is the refund policy?", "expected_tool": "search_docs"},
)
RUN_CONCURRENCY: Final = 4
SUMMARY_FILE: Final = "benchmark.json"
REPORT_FILE: Final = "summary.md"

Say = Callable[[str], None]


class BenchmarkOptions(BaseModel):
    """What a contributor chose. Validation happens before any workspace is created."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    profile: Literal["release", "full", "real"] = "release"
    release: Release | None = None
    frameworks: list[Framework] = Field(default_factory=list[Framework])
    molds: list[Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]*$")]] = Field(
        default_factory=list[str]
    )
    output: str | None = None
    max_cost: Annotated[Decimal, Field(gt=0)] | None = None
    max_runs: Annotated[int, Field(ge=1)] | None = None
    real_config: str | None = None


class OptionsError(Exception):
    """The options cannot run; ``message`` is safe to show."""


@dataclass(frozen=True, slots=True)
class RunSpec:
    label: str
    mode: Literal["tools", "agent"]
    framework: Framework
    variant: Literal["vulnerable", "hardened", "no-tools", "mutant"]
    language: Language
    molds: tuple[str, ...]
    disabled_control: str | None = None

    def profile(self) -> Profile:
        return Profile.build(self.variant, self.disabled_control, self.mode)


@dataclass(slots=True)
class Plan:
    scope: Scope
    catalog_release: str
    runs: list[RunSpec] = field(default_factory=list[RunSpec])
    targets: list[tuple[BenchmarkCase, Language, RunSpec]] = field(
        default_factory=list[tuple[BenchmarkCase, Language, RunSpec]]
    )
    pending: list[CellResult] = field(default_factory=list[CellResult])
    controls: list[Control] = field(default_factory=list[Control])
    isolated: tuple[str, ...] = ()
    full_molds: tuple[str, ...] = ()
    checks: bool = False
    gaps: list[str] = field(default_factory=list[str])


@dataclass(frozen=True, slots=True)
class BenchmarkOutcome:
    summary: BenchmarkSummary
    exit_code: Literal[0, 1, 2]
    folder: Path


def _label(*parts: str | None) -> str:
    return "-".join(part for part in parts if part)


def plan_benchmark(options: BenchmarkOptions, matrix: Matrix, catalog: Catalog) -> Plan:
    """Every cell of the selection, with the runs that observe them. Unknown ids raise."""
    known = {entry.id for entry in catalog.entries}
    unknown = sorted(set(options.molds) - known)
    if unknown:
        raise OptionsError(f"Unknown mold: {', '.join(unknown)}.")
    full = options.profile == "full"
    release: Release = options.release or catalog.default_release
    in_scope = {entry.id for entry in (catalog.entries if full else catalog.in_release(release))}
    selected_molds = set(options.molds) or in_scope
    outside = sorted(set(options.molds) - in_scope)
    if outside:
        raise OptionsError(f"Not in the selected release: {', '.join(outside)}.")
    frameworks = set(options.frameworks)
    narrowed = bool(options.molds or options.frameworks)
    plan = Plan(
        scope="selection" if narrowed else ("full" if full else "release"),
        catalog_release="all" if full else release,
    )
    cases = [
        case
        for case in matrix.cases
        if case.mold_id in selected_molds and (not frameworks or case.framework in frameworks)
    ]
    runs: dict[str, RunSpec] = {}
    tools_molds = tuple(
        entry.id
        for entry in catalog.entries
        if entry.id in selected_molds and "tools" in entry.mold.supported_modes
    )
    agent_molds = tuple(
        entry.id
        for entry in catalog.entries
        if any(
            case.mold_id == entry.id and case.mode == "agent" and case.availability == "ready"
            for case in cases
        )
    )
    for case in cases:
        support = matrix.framework(case.framework)
        pending = case.dependency
        if support is not None and support.availability != "ready":
            pending = support.requirement
        for language in case.languages:
            if case.availability != "ready" or pending is not None:
                plan.pending.append(_pending_cell(case, language, pending or "pending"))
                continue
            molds = tools_molds if case.mode == "tools" else agent_molds
            label = _label(case.mode, case.framework, case.variant, language)
            spec = runs.setdefault(
                label,
                RunSpec(label, case.mode, case.framework, case.variant, language, molds),
            )
            plan.targets.append((case, language, spec))
    if full:
        for support in matrix.frameworks:
            if support.availability != "ready" and (not frameworks or support.id in frameworks):
                plan.pending.append(_pending_framework(support.id, support.requirement or ""))
    else:
        plan.gaps.extend(
            f"{support.id}: {support.requirement}"
            for support in matrix.frameworks
            if support.availability != "ready"
        )
    reference_python = not frameworks or "python" in frameworks
    if tools_molds and reference_python:
        representatives = sorted({control.representative.mold_id for control in matrix.controls})
        plan.isolated = tuple(mold for mold in representatives if mold in in_scope)
        plan.full_molds = tools_molds
        for control in matrix.controls:
            if control.representative.mold_id not in plan.isolated:
                continue
            if options.molds and control.representative.mold_id not in selected_molds:
                continue
            plan.controls.append(control)
            for kind, molds in (("isolated", plan.isolated), ("full", plan.full_molds)):
                label = _label("tools", "python", "mutant", control.id, kind)
                runs[label] = RunSpec(
                    label, "tools", "python", "mutant", "en", molds, disabled_control=control.id
                )
        baseline = _label("tools", "python", "hardened", "en")
        if plan.controls and baseline not in runs:
            runs[baseline] = RunSpec(baseline, "tools", "python", "hardened", "en", tools_molds)
    plan.checks = not narrowed and reference_python and bool(tools_molds)
    plan.runs = list(runs.values())
    return plan


def _pending_cell(case: BenchmarkCase, language: Language, dependency: str) -> CellResult:
    return CellResult(
        case_id=case.case_id,
        kind="target",
        mold_id=case.mold_id,
        mode=case.mode,
        language=language,
        framework=case.framework,
        variant=case.variant,
        fixture_id=case.fixture_id,
        disabled_control=None,
        outcome="pending",
        dependency=dependency,
    )


def _pending_framework(framework: Framework, requirement: str) -> CellResult:
    return CellResult(
        case_id=f"framework-{framework}",
        kind="target",
        mold_id=None,
        mode=None,
        language=None,
        framework=framework,
        variant=None,
        fixture_id=None,
        disabled_control=None,
        outcome="pending",
        dependency=requirement,
    )


def config_document(data: DomainData, profile: Profile) -> dict[str, Any]:
    """The gazua.yaml a user of this store would write for the profile."""
    tools = exposed_tools(profile)
    records = [record for record in data.victim_records() if record["tool"] in tools]
    victim: dict[str, Any] = {"id": data.victim}
    if records:
        victim["records"] = records
    document: dict[str, Any] = {
        "schema_version": 1,
        "entrypoint": f"{TARGET_PACKAGE}.python_target:entrypoint",
        "tools": {name: DECLARATIONS[name] for name in tools},
        "limits": {"concurrency": RUN_CONCURRENCY},
        "fixtures": {"attacker": {"id": data.attacker}, "victim": victim},
        "canaries": [data.canary],
        "output_sink": f"{TARGET_PACKAGE}.python_target:sink",
    }
    if profile.mode == "agent":
        document["agent_entries"] = {
            entry: declared
            for entry, declared in AGENT_ENTRIES.items()
            if declared["tool"] in tools
        }
        document["legit_tasks"] = [
            task for task in LEGITIMATE_TASKS if task["expected_tool"] in tools
        ]
    return document


def prepare_workspace(root: Path, profile: Profile, data: DomainData) -> Path:
    """A new project folder with the target package, its profile and its gazua.yaml."""
    package = root / TARGET_PACKAGE
    package.mkdir(parents=True)
    for name in TARGET_FILES:
        shutil.copyfile(PACKAGE / "targets" / name, package / name)
    shutil.copyfile(DOMAIN_FILE, package / "domain.json")
    (root / "profile.json").write_text(json.dumps(profile.document()), encoding="utf-8")
    # JSON is valid YAML, so Gazua's own loader reads this file.
    document = config_document(data, profile)
    (root / "gazua.yaml").write_text(json.dumps(document, indent=2), encoding="utf-8")
    return root


class _Quiet:
    def __init__(self) -> None:
        self.warnings: list[str] = []

    def say(self, line: str) -> None:
        return None

    def lines(self, lines: Sequence[str]) -> None:
        return None

    def warn(self, line: str) -> None:
        self.warnings.append(line)


def execute_run(
    spec: RunSpec,
    workspace: Path,
    folder: Path,
    cancel: threading.Event | None = None,
) -> RunObservation:
    """Runs one native mode with its reports and reopens what it persisted."""
    from gazua.catalog.loader import load_catalog
    from gazua.config.diagnostics import ConfigError
    from gazua.config.loader import load_config
    from gazua.modes.agent_models import AgentOptions
    from gazua.modes.tools_models import ToolsOptions
    from gazua.reports.execution import ReportOutput, execute_mode
    from gazua.reports.lifecycle import LifecycleLock, LockBusy
    from gazua.reports.storage import RunLoadError, load_run_document

    quiet = _Quiet()
    output = ReportOutput(say=quiet.say, lines=quiet.lines, warn=quiet.warn)
    try:
        config = load_config(workspace / "gazua.yaml").config
        loaded = load_catalog(config, config_dir=workspace, release=RELEASES[-1])
        entries = tuple(entry for entry in loaded.entries if entry.id in spec.molds)
        options: ToolsOptions | AgentOptions = (
            ToolsOptions(language=spec.language)
            if spec.mode == "tools"
            else AgentOptions(language=spec.language, repetitions=AGENT_REPETITIONS)
        )
        with LifecycleLock(workspace):
            outcome = execute_mode(
                spec.mode, config, entries, options, workspace, output, locked=True, cancel=cancel
            )
    except ConfigError:
        return RunObservation(spec.label, 2, error="configuration_error")
    except (LockBusy, OSError):
        return RunObservation(spec.label, 2, error="workspace_unavailable")
    native = outcome.native
    states = (
        {result.attack_key: result.state for result in native.verdicts.results}
        if native is not None
        else {}
    )
    operational = tuple(
        sorted({item.code for item in getattr(native, "diagnostics", ())})
        if outcome.exit_code == 2
        else ()
    )
    if outcome.interrupted or "archive" not in outcome.paths:
        code = "interrupted" if outcome.interrupted else "report_not_saved"
        return RunObservation(
            spec.label, 2, native_states=states, operational=operational, error=code
        )
    path = workspace / outcome.paths["archive"]
    try:
        document = load_run_document(path)
    except RunLoadError:
        return RunObservation(spec.label, 2, native_states=states, error="run_document_invalid")
    return RunObservation(
        label=spec.label,
        exit_code=outcome.exit_code,
        run_document=reference(folder, path),
        document=document,
        native_states=states,
        operational=operational,
    )


def _expected_for(matrix: Matrix, control: Control, mold_id: str) -> StateMap | None:
    if mold_id in control.changes:
        return control.changes[mold_id]
    base = hardened_case(matrix, mold_id, "tools")
    return None if base is None else base.expected_states


def _mutation_cells(
    matrix: Matrix,
    catalog: Catalog,
    plan: Plan,
    observations: Mapping[str, RunObservation],
) -> list[CellResult]:
    cells: list[CellResult] = []
    baseline = observations.get(_label("tools", "python", "hardened", "en"))
    for control in plan.controls:
        for kind, molds in (("isolated", plan.isolated), ("full", plan.full_molds)):
            observation = observations.get(_label("tools", "python", "mutant", control.id, kind))
            diagnostics: list[str] = []
            observed: list[FindingKey] = []
            ids: list[str] = []
            outcome: Literal["passed", "failed", "error"] = "passed"
            if observation is None:
                outcome, diagnostics = "error", ["interrupted"]
            else:
                problems = run_problems(observation)
                for mold_id in molds:
                    mold = catalog.mold(mold_id)
                    expected = _expected_for(matrix, control, mold_id)
                    if mold is None or expected is None:
                        continue
                    verdict = judge(expected, observation, matrix, mold, "tools", problems)
                    if verdict.outcome == "error":
                        outcome = "error"
                    elif verdict.outcome == "failed" and outcome == "passed":
                        outcome = "failed"
                    diagnostics.extend(verdict.diagnostics)
                    observed.extend(verdict.observed_findings)
                    ids.extend(verdict.finding_ids)
            selected = set(molds)
            if kind == "isolated":
                expected_keys = [control.representative]
                base_keys = _baseline_keys(matrix, catalog, baseline, molds)
                if base_keys is None:
                    outcome, diagnostics = "error", [*diagnostics, "baseline_unavailable"]
                elif outcome != "error" and mutation_delta(observed, base_keys) != expected_keys:
                    outcome, diagnostics = "failed", [*diagnostics, "mutation_delta_mismatch"]
            else:
                expected_keys = [key for key in control.full_scan if key.mold_id in selected]
                if outcome != "error" and sorted_keys(observed) != sorted_keys(expected_keys):
                    outcome, diagnostics = "failed", [*diagnostics, "full_scan_mismatch"]
            cells.append(
                CellResult(
                    case_id=f"mutation-{control.id}-{kind}",
                    kind="mutation",
                    mold_id=control.representative.mold_id if kind == "isolated" else None,
                    mode="tools",
                    language="en",
                    framework="python",
                    variant="mutant",
                    fixture_id=control.fixture_id,
                    disabled_control=control.id,
                    outcome=outcome,
                    expected_findings=sorted_keys(expected_keys),
                    observed_findings=sorted_keys(observed),
                    finding_ids=sorted(set(ids)),
                    run_document=None if observation is None else observation.run_document,
                    diagnostics=sorted(set(diagnostics)),
                )
            )
    return cells


def _baseline_keys(
    matrix: Matrix, catalog: Catalog, baseline: RunObservation | None, molds: Sequence[str]
) -> list[FindingKey] | None:
    if baseline is None or baseline.document is None or baseline.exit_code == 2:
        return None
    keys: list[FindingKey] = []
    for mold_id in molds:
        mold = catalog.mold(mold_id)
        if mold is not None:
            keys.extend(mold_findings(baseline.document, matrix, mold)[0])
    return sorted_keys(keys)


def _target_cells(
    matrix: Matrix, catalog: Catalog, plan: Plan, observations: Mapping[str, RunObservation]
) -> list[CellResult]:
    cells: list[CellResult] = []
    problems = {label: run_problems(item) for label, item in observations.items()}
    for spec in plan.runs:
        observation = observations.get(spec.label)
        if spec.mode == "agent" and observation is not None and observation.document is not None:
            problems[spec.label] = [
                *problems[spec.label],
                *legitimate_problems(observation.document, spec.variant),
            ]
    for case, language, spec in plan.targets:
        mold = catalog.mold(case.mold_id)
        observation = observations.get(spec.label)
        if mold is None:
            continue
        base: dict[str, Any] = {
            "case_id": case.case_id,
            "kind": "target",
            "mold_id": case.mold_id,
            "mode": case.mode,
            "language": language,
            "framework": case.framework,
            "variant": case.variant,
            "fixture_id": case.fixture_id,
            "disabled_control": None,
        }
        if observation is None:
            cells.append(CellResult(**base, outcome="error", diagnostics=["interrupted"]))
            continue
        verdict = judge(
            case.expected_states, observation, matrix, mold, case.mode, problems[spec.label]
        )
        positive = bool(verdict.expected_findings)
        cells.append(
            CellResult(
                **base,
                outcome=verdict.outcome,
                positive=positive,
                negative=not positive and "resisted" in case.expected_states.values(),
                observed_states=verdict.observed_states,
                expected_findings=verdict.expected_findings,
                observed_findings=verdict.observed_findings,
                finding_ids=verdict.finding_ids,
                run_document=observation.run_document,
                diagnostics=verdict.diagnostics,
            )
        )
    return cells


def legitimate_problems(document: Any, variant: str) -> list[str]:
    """A target with tools must keep serving its declared tasks; refusing everything fails."""
    use = document.legitimate_use
    if variant == "no-tools":
        return []
    if use is None or use.planned == 0 or use.succeeded != use.planned:
        return ["legitimate_task_failed"]
    return []


def _projection(document: Any) -> dict[str, object]:
    states: dict[str, str] = {}
    for scenario in document.scenarios:
        found, _ = mold_states(document, scenario.mold_id)
        for key, state in found.items():
            states[f"{scenario.mold_id}/{key}"] = state
    findings = sorted(f"{item.mold_id}/{item.tool_name}" for item in document.findings)
    return {"states": states, "findings": findings}


def _check_cells(
    matrix: Matrix,
    plan: Plan,
    folder: Path,
    data: DomainData,
    observations: Mapping[str, RunObservation],
    targets: Sequence[CellResult],
    say: Say,
) -> list[CellResult]:
    from gazua.reports.storage import RunLoadError, load_run_document

    runs = folder / "runs"
    vulnerable = [
        runs / spec.label
        for spec in plan.runs
        if spec.mode == "tools" and spec.variant == "vulnerable"
    ]
    others = [
        runs / spec.label
        for spec in plan.runs
        if spec.mode == "tools" and spec.variant != "vulnerable"
    ]
    results: dict[str, CheckResult] = {}
    say("Checking the dry-run spy, the canary and the report HTML.")
    results["dry-run-spy"] = spy_check(vulnerable, others)
    detected = any(
        cell.outcome == "passed"
        and any(key.signal == "canary_in_response" for key in cell.observed_findings)
        for cell in targets
    )
    results["canary-redaction"] = canary_check(vulnerable, data.canary, detected)
    results["report-xss"] = xss_check(vulnerable)
    say("Checking legitimate tasks on the hardened target.")
    checks_root = folder / "checks"
    legit = prepare_workspace(checks_root / "legitimate", Profile.build("hardened"), data)
    results["legitimate-tasks"] = legitimate_check(legit)
    say("Comparing the command line with the programmatic runs.")
    problems: list[str] = []
    parity_runs: tuple[tuple[Literal["vulnerable", "no-tools"], int], ...] = (
        ("vulnerable", 1),
        ("no-tools", 0),
    )
    for variant, expected_exit in parity_runs:
        label = _label("tools", "python", variant, "en")
        observation = observations.get(label)
        workspace = prepare_workspace(checks_root / f"cli-{variant}", Profile.build(variant), data)
        code = run_cli(workspace, "--tools", "--language", "en")
        if observation is None or observation.document is None:
            problems.append("programmatic_run_missing")
            continue
        try:
            command_line = load_run_document(workspace / ".gazua" / "run.json")
        except RunLoadError:
            problems.append("cli_report_missing")
            continue
        parity = cli_parity(
            {"exit": observation.exit_code, **_projection(observation.document)},
            {"exit": code, **_projection(command_line)},
        )
        problems.extend(parity.diagnostics)
        if code != expected_exit:
            problems.append("cli_exit_unexpected")
    results["cli-parity"] = CheckResult.of(problems)
    builtin = results
    results = {}
    for check in matrix.checks:
        if check.kind == "pytest":
            say(f"Running the selected tests of {check.id}.")
            results[check.id] = pytest_check(ROOT, check.tests)
        else:
            results[check.id] = builtin.get(check.id, CheckResult("failed", ("unknown_check",)))
    return [
        CellResult(
            case_id=f"check-{name}",
            kind="check",
            mold_id=None,
            mode=None,
            language=None,
            framework="python",
            variant=None,
            fixture_id=None,
            disabled_control=None,
            outcome="passed" if result.outcome == "passed" else "failed",
            diagnostics=list(result.diagnostics),
        )
        for name, result in sorted(results.items())
    ]


def provenance(matrix: Matrix, matrix_digest: str, catalog: Catalog) -> Provenance:
    from gazua.reports.execution import installed_version

    commit: str | None = None
    dirty: bool | None = None
    reason: str | None = "git_unavailable"
    git = shutil.which("git")
    if git is not None:
        head = subprocess.run(  # noqa: S603
            [git, "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False
        )
        status = subprocess.run(  # noqa: S603
            [git, "status", "--porcelain", "--untracked-files=no"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if head.returncode == 0 and len(head.stdout.strip()) == 40:
            commit, reason = head.stdout.strip(), None
            dirty = status.returncode != 0 or bool(status.stdout.strip())
    return Provenance(
        commit=commit,
        commit_unavailable=reason,
        dirty=dirty,
        gazua_version=installed_version(),
        matrix_revision=matrix.revision,
        matrix_digest=matrix_digest,
        catalog_digest=catalog.digest,
        runtime=f"{platform.python_implementation()} {platform.python_version()}",
    )


def decide(cells: Sequence[CellResult], interrupted: bool) -> tuple[Status, Literal[0, 1, 2]]:
    """An operational error or a pending cell wins over a mismatch."""
    outcomes = {cell.outcome for cell in cells}
    if interrupted or outcomes & {"error", "pending"}:
        return "incomplete", 2
    if "failed" in outcomes:
        return "failed", 1
    return "passed", 0


def run_benchmark(
    options: BenchmarkOptions,
    *,
    root: Path,
    say: Say,
    cancel: threading.Event | None = None,
    write_summary: Callable[[Path, BenchmarkSummary], list[str]] | None = None,
    matrix_path: Path | None = None,
) -> BenchmarkOutcome:
    """Runs the selection and writes ``benchmark.json``. Invalid input raises first.

    ``write_summary`` writes the extra artifacts and returns their relative paths;
    ``matrix_path`` replaces the reviewed matrix, for tests that break it on purpose.
    """
    matrix, digest = load_matrix() if matrix_path is None else load_matrix(matrix_path)
    catalog = load_packaged_catalog()
    problems = coverage_problems(matrix, catalog)
    if problems:
        from .coverage import MatrixError

        raise MatrixError(problems)
    plan = plan_benchmark(options, matrix, catalog)
    data = DomainData.load(DOMAIN_FILE)
    folder = create_output(Path(options.output) if options.output else None, root)
    observations: dict[str, RunObservation] = {}
    interrupted = False
    for index, spec in enumerate(plan.runs, start=1):
        if cancel is not None and cancel.is_set():
            interrupted = True
            break
        say(f"[{index}/{len(plan.runs)}] {spec.label}")
        workspace = prepare_workspace(folder / "runs" / spec.label, spec.profile(), data)
        observations[spec.label] = execute_run(spec, workspace, folder, cancel)
        if cancel is not None and cancel.is_set():
            interrupted = True
            break
    targets = _target_cells(matrix, catalog, plan, observations)
    cells = [*targets, *_mutation_cells(matrix, catalog, plan, observations), *plan.pending]
    if plan.checks and not interrupted:
        cells.extend(_check_cells(matrix, plan, folder, data, observations, targets, say))
    cells.sort(key=CellResult.sort_key)
    status, code = decide(cells, interrupted)
    summary = BenchmarkSummary(
        schema_version=1,
        profile=options.profile,
        status=status,
        scope=plan.scope,
        simulated=True,
        catalog_release=plan.catalog_release,
        provenance=provenance(matrix, digest, catalog),
        counts=count_cells(cells),
        cells=cells,
        gaps=plan.gaps,
        artifacts=[],
    )
    artifacts = write_summary(folder, summary) if write_summary is not None else []
    summary = summary.model_copy(update={"artifacts": artifacts})
    text = summary.model_dump_json(indent=2) + "\n"
    if privacy_problems(text, data.canary):
        raise StorageError("summary_not_private")
    write_atomic(folder, SUMMARY_FILE, text)
    return BenchmarkOutcome(summary, code, folder)


__all__ = [
    "BenchmarkOptions",
    "BenchmarkOutcome",
    "OptionsError",
    "Plan",
    "RunSpec",
    "config_document",
    "decide",
    "execute_run",
    "plan_benchmark",
    "prepare_workspace",
    "run_benchmark",
]

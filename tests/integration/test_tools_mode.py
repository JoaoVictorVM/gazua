import json
import sys
from pathlib import Path
from typing import Any

from conftest import FAKE_CREDENTIALS, SPY, build_clean_environment, run_process
from gazua.modes.tools import HTTP_REFUSAL, NO_TOOL_CAN_RUN

PROVIDER_TRAP = (
    "import json, os\n"
    "os.makedirs('effects', exist_ok=True)\n"
    "with open(os.path.join('effects', f'{os.getpid()}.jsonl'), 'a') as handle:\n"
    "    handle.write(json.dumps({'kind': 'provider_imported', 'name': __name__}) + '\\n')\n"
)


def kinds(project: Any) -> set[str]:
    return {item["kind"] for item in project.effects()}


def spied_cli(project: Any, *arguments: str) -> dict[str, Any]:
    report_path = project.root.parent / "spy-report.json"
    run_process(
        [sys.executable, SPY, report_path, "cli", "run", *arguments],
        cwd=project.root,
        env={**build_clean_environment(), **FAKE_CREDENTIALS},
    )
    return json.loads(report_path.read_text(encoding="utf-8"))


def test_cli_needs_no_key_and_never_calls_model(tools_project: Any) -> None:
    for name in ("openai", "anthropic"):
        (tools_project.root / f"{name}.py").write_text(PROVIDER_TRAP, encoding="utf-8")
    environment = {**build_clean_environment(), **FAKE_CREDENTIALS}
    control = run_process(
        [
            sys.executable,
            "-c",
            "import tools_target, openai, os; os.environ['OPENAI_API_KEY']; "
            "import socket; socket.getaddrinfo('localhost', 9)",
        ],
        cwd=tools_project.root,
        env=environment,
    )
    assert control.returncode == 0, control.stderr
    assert {"provider_imported", "credential_read", "network"} <= kinds(tools_project)
    tools_project.clear_effects()

    result = tools_project.cli("--tools", env=environment)

    assert result.returncode == 1, result.stderr
    seen = kinds(tools_project)
    assert "get_order" in seen
    assert not seen & {"provider_imported", "credential_read", "network", "entrypoint_called"}
    report = spied_cli(tools_project, "--tools", "--mold", "idor-01")
    assert report["exit_code"] == 1
    assert report["network"] == []
    assert report["credential_reads"] == []
    assert report["environment_listed"] is False


def normalized(result: Any) -> dict[str, Any]:
    def proof(item: Any) -> dict[str, Any]:
        return item.model_dump(exclude={"execution_id", "reference"})

    return {
        "exit": result.exit_code,
        "order": result.result_order,
        "results": [
            {
                **item.model_dump(exclude={"proof"}),
                "proof": [proof(entry) for entry in item.proof],
            }
            for item in result.verdicts.results
        ],
        "counts": result.engine.counts,
        "statuses": sorted(
            (record.request_key, record.status, record.reason, record.attempt)
            for record in result.engine.records
        ),
        "diagnostics": [item.model_dump() for item in result.diagnostics],
    }


def test_twenty_runs_have_identical_normalized_results(tools_project: Any) -> None:
    document = tools_project.document()
    tools = {
        name: document["tools"][name]
        for name in ("get_order", "refund", "delete_account", "send_email")
    }
    tools_project.write(tools=tools, target={"reset": "tools_target:reset"}, output_sink=None)

    # A finding, a proven inapplicability, a skipped unsafe tool and a canary probe: every
    # state path of the mode, kept small so that twenty full commands stay fast.
    molds = ("idor-01", "idor-04", "permission-03", "secret-01")
    first = normalized(tools_project.run(molds=molds))
    assert first["exit"] == 1
    assert sorted((item["mold_id"], item["state"]) for item in first["results"]) == [
        ("idor-01", "finding"),
        ("idor-04", "not_applicable"),
        ("permission-03", "finding"),
        ("permission-03", "not_tested"),
        ("secret-01", "finding"),
    ]
    for _ in range(19):
        assert normalized(tools_project.run(molds=molds)) == first


def test_http_target_is_refused_without_request(tools_project: Any) -> None:
    tools_project.write(entrypoint="https://agent.example.com/chat")

    result = tools_project.cli("--tools")
    report = spied_cli(tools_project, "--tools")

    assert result.returncode == 2
    assert HTTP_REFUSAL in result.stderr
    assert "Traceback" not in result.stderr
    assert report["exit_code"] == 2
    assert report["network"] == []
    assert not (tools_project.root / "effects").exists()
    assert not (tools_project.root / ".gazua").exists()


def test_exit_codes_zero_one_two(tools_project: Any) -> None:
    vulnerable = tools_project.cli("--tools", "--mold", "idor-01")
    assert vulnerable.returncode == 1
    assert "Reproduce: gazua run --tools --config gazua.yaml --mold idor-01" in vulnerable.stdout

    tools_project.harden()
    hardened = tools_project.cli("--tools", "--mold", "idor-01")
    assert hardened.returncode == 0, hardened.stdout
    tools_project.harden(False)

    (tools_project.root / "slow").write_text("x", encoding="utf-8")
    mixed = tools_project.cli("--tools", "--timeout", "3", "--concurrency", "4")
    assert mixed.returncode == 2
    assert "Gate: " in mixed.stdout
    assert "Gate: no finding" not in mixed.stdout
    assert "attack timeout" in mixed.stdout or "attack_timeout" in mixed.stdout
    (tools_project.root / "slow").unlink()

    tools_project.clear_effects()
    usage = [
        ("--tools", "--mode", "agent"),
        ("--tools", "--mold", "permission-10"),
        ("--tools", "--mold", "does-not-exist"),
        ("--tools", "--max-runs", "0"),
        ("--tools", "--timeout", "-1"),
        ("--tools", "--config", "missing.yaml"),
        (),
    ]
    for arguments in usage:
        refused = tools_project.cli(*arguments)
        assert refused.returncode == 2, arguments
        assert "Traceback" not in refused.stderr
    assert not (tools_project.root / "effects").exists()

    document = tools_project.document()
    for tool in document["tools"].values():
        tool.pop("safe", None)
    tools_project.write(tools=document["tools"])
    nothing = tools_project.cli("--tools")
    assert nothing.returncode == 2
    assert NO_TOOL_CAN_RUN in nothing.stdout
    assert "get_order: not tested, missing safe: true" in nothing.stdout
    assert not kinds(tools_project) - {"as_user", "as_user_async"}


def test_listing_remains_read_only(tools_project: Any, workdir: Path) -> None:
    listing = tools_project.cli("--list")
    tools_only = tools_project.cli("--tools", "--list")
    one = tools_project.cli("--list", "--tools", "--mold", "idor-01")
    flags = tools_project.cli("--list", "--max-runs", "3")
    elsewhere = run_process([sys.executable, "-m", "gazua", "run", "--list"], cwd=workdir)

    assert listing.returncode == tools_only.returncode == one.returncode == 0
    assert "mode: tools" in tools_only.stdout
    assert "mode: agent" not in tools_only.stdout
    assert "idor-01" in one.stdout
    assert "idor-02" not in one.stdout
    assert flags.returncode == 2
    assert elsewhere.returncode == 0
    assert not (tools_project.root / "effects").exists()
    assert not (tools_project.root / ".gazua").exists()
    assert list(workdir.iterdir()) == []

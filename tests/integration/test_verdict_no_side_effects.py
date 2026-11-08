from typing import Any

Spy = Any


def test_import_and_evaluation_need_no_provider_or_network(run_spied: Spy) -> None:
    report = run_spied("verdict")
    control = run_spied("control")

    assert report["exit_code"] == 0
    assert report["verdicts_on_import"] == []
    assert report["states"] == ["finding", "finding", "finding"]
    assert report["targets_imported"] == []
    assert report["network"] == []
    assert report["credential_reads"] == []
    assert report["environment_listed"] is False
    assert not [path for path in report["opened_paths"] if path.endswith((".env", ".pem", ".key"))]
    assert control["network"]
    assert control["credential_reads"]

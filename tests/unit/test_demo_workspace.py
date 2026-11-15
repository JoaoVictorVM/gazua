"""The demo folder is created once, recognized by its manifest and never overwritten."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from gazua.config.loader import load_config
from gazua.demo import ENTRYPOINT
from gazua.demo import workspace as module
from gazua.demo.workspace import (
    CONFIG_NAME,
    CONFLICT,
    MANIFEST_NAME,
    UNSAFE,
    DemoError,
    packaged_config,
    prepare_workspace,
    sha256,
)
from gazua.reports.lifecycle import gitignore_covers


def test_materialized_config_validates(tmp_path: Path) -> None:
    created = prepare_workspace(tmp_path / "demo")

    config = load_config(created.config_path).config
    manifest = json.loads((created.root / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert created.created is True
    assert config.entrypoint == ENTRYPOINT
    assert config.limits.concurrency == 1
    assert config.limits.cost_per_run == 0
    assert created.config_path.read_bytes() == packaged_config()
    assert manifest == {
        "schema_version": 1,
        "profile": "gazua-store-demo",
        "profile_version": 1,
        "config_sha256": sha256(packaged_config()),
    }
    assert gitignore_covers(created.root)
    again = prepare_workspace(tmp_path / "demo")
    assert again.created is False
    assert again.root == created.root


def test_empty_existing_folder_is_filled(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()

    assert prepare_workspace(tmp_path / "empty").created is True


def test_existing_foreign_directory_is_preserved(tmp_path: Path) -> None:
    folder = tmp_path / "project"
    folder.mkdir()
    (folder / "notes.txt").write_text("mine", encoding="utf-8")
    (folder / CONFIG_NAME).write_text("schema_version: 1\n", encoding="utf-8")

    with pytest.raises(DemoError) as raised:
        prepare_workspace(folder)

    assert raised.value.code == CONFLICT
    assert "choose another folder" in raised.value.message
    assert sorted(item.name for item in folder.iterdir()) == ["gazua.yaml", "notes.txt"]
    assert (folder / CONFIG_NAME).read_text(encoding="utf-8") == "schema_version: 1\n"


def test_changed_config_is_refused(tmp_path: Path) -> None:
    created = prepare_workspace(tmp_path / "demo")
    changed = created.config_path.read_bytes().replace(b"concurrency: 1", b"concurrency: 4")
    created.config_path.write_bytes(changed)
    (created.root / "extra.txt").write_text("unknown", encoding="utf-8")

    with pytest.raises(DemoError) as raised:
        prepare_workspace(created.root)

    assert raised.value.code == CONFLICT
    assert created.config_path.read_bytes() == changed
    assert (created.root / "extra.txt").read_text(encoding="utf-8") == "unknown"


def test_incompatible_manifest_is_refused(tmp_path: Path) -> None:
    created = prepare_workspace(tmp_path / "demo")
    manifest = created.root / MANIFEST_NAME
    document = json.loads(manifest.read_text(encoding="utf-8"))
    manifest.write_text(json.dumps({**document, "profile_version": 2}), encoding="utf-8")

    with pytest.raises(DemoError) as raised:
        prepare_workspace(created.root)

    assert raised.value.code == CONFLICT


def _link(source: Path, link: Path) -> None:
    try:
        link.symlink_to(source, target_is_directory=True)
        return
    except OSError:
        pass
    if os.name != "nt":
        pytest.skip("this system does not allow creating symlinks")
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(source)],
        capture_output=True,
        check=False,
    )
    if created.returncode != 0:
        pytest.skip("this system does not allow creating links or junctions")


def test_links_are_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "linked"
    _link(real, link)

    with pytest.raises(DemoError) as raised:
        prepare_workspace(link)

    assert raised.value.code == UNSAFE
    assert list(real.iterdir()) == []


def test_managed_link_inside_workspace_is_refused(tmp_path: Path) -> None:
    created = prepare_workspace(tmp_path / "demo")
    outside = tmp_path / "outside"
    outside.mkdir()
    _link(outside, created.root / ".gazua")

    with pytest.raises(DemoError) as raised:
        prepare_workspace(created.root)

    assert raised.value.code == UNSAFE


def test_concurrent_creation_does_not_overwrite(tmp_path: Path) -> None:
    folder = tmp_path / "raced"
    folder.mkdir()
    (folder / CONFIG_NAME).write_bytes(b"theirs")

    with pytest.raises(DemoError) as raised:
        module._create(folder / CONFIG_NAME, b"ours")  # pyright: ignore[reportPrivateUsage]

    assert raised.value.code == CONFLICT
    assert (folder / CONFIG_NAME).read_bytes() == b"theirs"
    assert [item.name for item in folder.iterdir()] == [CONFIG_NAME]


def test_parallel_preparations_agree_on_one_workspace(tmp_path: Path) -> None:
    target = tmp_path / "shared"
    errors: list[str] = []
    barrier = threading.Barrier(4)

    def prepare() -> None:
        barrier.wait()
        try:
            prepare_workspace(target)
        except DemoError as error:
            errors.append(error.code)

    threads = [threading.Thread(target=prepare) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert set(errors) <= {CONFLICT}
    assert len(errors) < 4
    assert (target / CONFIG_NAME).read_bytes() == packaged_config()
    assert not [item for item in target.iterdir() if item.name.endswith(".tmp")]


def test_workspace_module_does_not_import_the_target() -> None:
    code = (
        "import sys; from gazua.demo.workspace import prepare_workspace; "
        "print('gazua.demo.target' in sys.modules)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )

    assert result.stdout.strip() == "False"

from pathlib import Path

import pytest

from contrace.artifacts import ArtifactLayout
from contrace.errors import ContraceError


def test_create_temp_layout_and_cleanup() -> None:
    layout = ArtifactLayout.create(None, keep_workdir=False)
    root = layout.root
    assert root.exists()
    layout.cleanup()
    assert not root.exists()


def test_explicit_workdir_must_be_empty(tmp_path: Path) -> None:
    workdir = tmp_path / "occupied"
    workdir.mkdir()
    (workdir / "marker.txt").write_text("x", encoding="utf-8")

    with pytest.raises(ContraceError):
        ArtifactLayout.create(workdir, keep_workdir=True)

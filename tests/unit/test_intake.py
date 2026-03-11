import tarfile
import zipfile
from pathlib import Path

from contrace.artifacts import ArtifactLayout
from contrace.intake import prepare_input


def _make_source_tree(root: Path) -> Path:
    challenge = root / "challenge"
    challenge.mkdir()
    (challenge / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (challenge / "contrace.yml").write_text("version: 1\n", encoding="utf-8")
    return challenge


def test_prepare_directory_input(tmp_path: Path) -> None:
    source = _make_source_tree(tmp_path)
    layout = ArtifactLayout.create(tmp_path / "workdir", keep_workdir=True)

    prepared = prepare_input(source, layout)

    assert prepared.extracted is False
    assert prepared.source_root == layout.source_dir
    assert prepared.dockerfile_path.exists()
    assert prepared.detected_config_path is not None


def test_prepare_archive_input(tmp_path: Path) -> None:
    source = _make_source_tree(tmp_path)
    archive = tmp_path / "challenge.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        handle.add(source, arcname="challenge")

    layout = ArtifactLayout.create(tmp_path / "archive-workdir", keep_workdir=True)
    prepared = prepare_input(archive, layout)

    assert prepared.extracted is True
    assert prepared.source_root.name == "challenge"
    assert prepared.dockerfile_path.exists()


def test_prepare_zip_input(tmp_path: Path) -> None:
    source = _make_source_tree(tmp_path)
    archive = tmp_path / "challenge.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        for path in source.rglob("*"):
            if path.is_file():
                handle.write(path, arcname=str(path.relative_to(tmp_path)))

    layout = ArtifactLayout.create(tmp_path / "zip-workdir", keep_workdir=True)
    prepared = prepare_input(archive, layout)

    assert prepared.extracted is True
    assert prepared.source_root.name == "challenge"
    assert prepared.dockerfile_path.exists()

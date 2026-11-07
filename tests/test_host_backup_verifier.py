"""Native host handoff verification rejects false success without an archive."""
from __future__ import annotations

import hashlib
import io
import json
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

PS = shutil.which("pwsh") or shutil.which("powershell.exe")
ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(PS is None, reason="Native PowerShell is not installed")


def verify(directory):
    return subprocess.run(
        [PS, "-NoProfile", "-NonInteractive", "-File",
         str(ROOT/"scripts/verify_collection_backup.ps1"), "-Directory", str(directory)],
        capture_output=True, text=True, check=False,
    )


def checksums(directory):
    (directory/"checksums.sha256").write_text("".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
        for p in sorted(directory.iterdir()) if p.name != "checksums.sha256"
    ), encoding="utf-8")


def valid_backup(directory):
    directory.mkdir()
    archive = directory/"collection-20261107T120000Z.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        data = b"synthetic transfer verifier fixture only"
        info = tarfile.TarInfo("fixture.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    metadata = {
        "git-commit.txt": "a"*40,
        "source-tag.txt": "collection-v4.0.0-candidate.1",
        "source-tag-object.txt": "b"*40,
        "source-url.txt": "https://github.com/lethinhlord/Repo.git",
    }
    for name, content in metadata.items():
        (directory/name).write_text(content+"\n", encoding="utf-8")
    (directory/"restore-report.json").write_text(json.dumps({
        "status": "BACKUP_RESTORED_AND_VALIDATED",
        "archive": archive.name,
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "validated_runs": ["SYNTHETIC-RUN"],
        "candidate": {"commit": "a"*40, "tag": metadata["source-tag.txt"],
                      "tag_object": "b"*40, "origin": metadata["source-url.txt"]},
    }), encoding="utf-8")
    checksums(directory)


def test_empty_inventory_never_prints_pass(tmp_path):
    (tmp_path/"checksums.sha256").write_text("")
    result = verify(tmp_path)
    assert result.returncode != 0
    assert "HOST_BACKUP_VERIFY=PASS" not in result.stdout


def test_complete_transfer_passes(tmp_path):
    valid_backup(tmp_path/"backup")
    result = verify(tmp_path/"backup")
    assert result.returncode == 0, result.stderr
    assert "HOST_BACKUP_VERIFY=PASS" in result.stdout


@pytest.mark.parametrize("damage", ["archive", "duplicate", "unlisted", "commit", "no_runs"])
def test_incomplete_or_inconsistent_transfer_fails(tmp_path, damage):
    directory = tmp_path/"backup"
    valid_backup(directory)
    if damage == "archive":
        next(directory.glob("*.tar.gz")).unlink()
    elif damage == "duplicate":
        p = directory/"checksums.sha256"
        p.write_text(p.read_text()+p.read_text().splitlines()[0]+"\n")
    elif damage == "unlisted":
        (directory/"unexpected.txt").write_text("unexpected")
    elif damage == "commit":
        (directory/"git-commit.txt").write_text("c"*40+"\n")
        checksums(directory)
    elif damage == "no_runs":
        p = directory/"restore-report.json"
        payload = json.loads(p.read_text())
        payload["validated_runs"] = []
        p.write_text(json.dumps(payload))
        checksums(directory)
    result = verify(directory)
    assert result.returncode != 0
    assert "HOST_BACKUP_VERIFY=PASS" not in result.stdout

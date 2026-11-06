from pathlib import Path

import pytest

from ml.collection_release import ReleaseError, create_backup


def test_backup_cannot_be_created_inside_source_or_existing_output(tmp_path: Path):
    with pytest.raises(ReleaseError, match='outside'):
        create_backup(tmp_path,'collection-unit',tmp_path/'backups')
    output=tmp_path.parent/(tmp_path.name+'-existing')
    output.mkdir()
    with pytest.raises(ReleaseError, match='exists'):
        create_backup(tmp_path,'collection-unit',output)

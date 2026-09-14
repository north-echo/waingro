"""Static safety contracts for hanna2 preservation scripts."""

import subprocess
from pathlib import Path

DEPLOY = Path(__file__).parents[1] / "deploy" / "hanna2"


def test_preservation_scripts_parse_as_bash():
    for name in ("backup-host.sh", "restore-drill.sh"):
        result = subprocess.run(  # noqa: S603 -- fixed bash syntax check over repository files.
            ["/bin/bash", "-n", str(DEPLOY / name)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr


def test_backup_requires_hanna2_root_and_a_different_physical_disk():
    script = (DEPLOY / "backup-host.sh").read_text(encoding="utf-8")

    assert "${EUID} -ne 0" in script
    assert "hostname -s) != hanna2" in script
    assert '${ROOT_DISK} == "${DEST_DISK}"' in script
    assert "root-verification-files.sha256" in script
    assert "SHA256SUMS" in script
    assert 'xfsdump -J -l 0 - "${MOUNTPOINT}"' in script


def test_restore_drill_is_confined_to_a_new_temporary_lv():
    script = (DEPLOY / "restore-drill.sh").read_text(encoding="utf-8")

    assert "${EUID} -ne 0" in script
    assert "hostname -s) != hanna2" in script
    assert "DRILL=waingro_restore_drill_${STAMP}" in script
    assert 'lvs "${DRILL_DEVICE}"' in script
    assert 'lvremove -f "${DRILL_DEVICE}"' in script
    assert "root_file_hashes=verified" in script
    assert "boot_archive_restore=verified" in script
    assert 'xfsrestore -J - "${MOUNTPOINT}"' in script
    assert "rm -rf" not in script

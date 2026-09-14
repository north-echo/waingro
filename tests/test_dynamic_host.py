"""Focused regression tests for dynamic host security gates."""

from waingro.dynamic.host import _secure_boot_state


def test_secure_boot_state_requires_an_enabled_uefi_variable(tmp_path):
    variable = tmp_path / "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    variable.write_bytes(b"\x07\x00\x00\x00\x01")
    assert _secure_boot_state(tmp_path) == "enabled"

    variable.write_bytes(b"\x07\x00\x00\x00\x00")
    assert _secure_boot_state(tmp_path) == "disabled"


def test_secure_boot_state_fails_closed_for_missing_or_malformed_variables(tmp_path):
    assert _secure_boot_state(tmp_path) == "unavailable"

    variable = tmp_path / "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    variable.write_bytes(b"malformed")
    assert _secure_boot_state(tmp_path) == "invalid"

    variable.write_bytes(b"\x07\x00\x00\x00\x01")
    (tmp_path / "SecureBoot-duplicate").write_bytes(b"\x07\x00\x00\x00\x01")
    assert _secure_boot_state(tmp_path) == "unavailable"

"""Static safety contracts for hanna2 provisioning and egress lockdown."""

import subprocess
from pathlib import Path

DEPLOY = Path(__file__).parents[1] / "deploy" / "hanna2"


def test_provisioning_scripts_parse_as_bash():
    for name in ("prepare-host.sh", "waingro-egress-lockdown"):
        result = subprocess.run(  # noqa: S603 -- fixed syntax check over repository files.
            ["/bin/bash", "-n", str(DEPLOY / name)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr


def test_host_baseline_disables_audit_suppression_and_world_kvm_access():
    audit_rules = (DEPLOY / "audit-base.rules").read_text(encoding="utf-8")
    kvm_rules = (DEPLOY / "99-waingro-kvm.rules").read_text(encoding="utf-8")
    prepare = (DEPLOY / "prepare-host.sh").read_text(encoding="utf-8")

    assert "never,task" not in audit_rules
    assert "task,never" not in audit_rules
    assert 'MODE="0660"' in kvm_rules
    assert "audit task suppression is active" in prepare
    assert "must not be accessible to other users" in prepare


def test_ssh_baseline_disables_every_forwarding_channel():
    sshd = (DEPLOY / "00-waingro-sshd.conf").read_text(encoding="utf-8")

    for directive in (
        "AllowTcpForwarding no",
        "AllowAgentForwarding no",
        "AllowStreamLocalForwarding no",
        "DisableForwarding yes",
        "PermitOpen none",
        "PermitListen none",
    ):
        assert directive in sshd


def test_libvirt_inventory_failures_cannot_be_hidden_by_a_pipeline():
    script = (DEPLOY / "prepare-host.sh").read_text(encoding="utf-8")

    assert "if ! foreign_domains_raw=$(" in script
    assert "if ! foreign_networks_raw=$(" in script
    assert "cannot query libvirt domains" in script
    assert "cannot query libvirt networks" in script


def test_egress_activation_is_transactional_and_requires_commit():
    prepare = (DEPLOY / "prepare-host.sh").read_text(encoding="utf-8")
    helper = (DEPLOY / "waingro-egress-lockdown").read_text(encoding="utf-8")
    service = (DEPLOY / "waingro-egress-lockdown.service").read_text(encoding="utf-8")
    timer = (DEPLOY / "waingro-egress-rollback.timer").read_text(encoding="utf-8")
    rollback = (DEPLOY / "waingro-egress-rollback.service").read_text(encoding="utf-8")

    assert "enable --now waingro-egress-lockdown.service" not in prepare
    assert "waingro-egress-lockdown arm" in prepare
    assert "write_marker true" in helper
    assert "write_marker false" in helper
    assert "ExecStartPost=/usr/bin/systemctl --no-block restart " in service
    assert "waingro-egress-rollback.timer" in service
    assert "OnActiveSec=120s" in timer
    assert "ExecStart=/usr/bin/systemctl stop waingro-egress-lockdown.service" in rollback


def test_runner_can_read_but_cannot_write_policy_and_lock_marker():
    prepare = (DEPLOY / "prepare-host.sh").read_text(encoding="utf-8")
    helper = (DEPLOY / "waingro-egress-lockdown").read_text(encoding="utf-8")

    assert '-o root -g "${RUNNER}" -m 0750 /etc/waingro' in prepare
    assert '-o root -g "${RUNNER}" -m 0640' in prepare
    assert '-o root -g "${RUNNER_GROUP}" -m 0750 "${RUNTIME_DIR}"' in helper
    assert '/usr/bin/chmod 0640 "${temporary}"' in helper


def test_every_egress_unit_is_installed_by_prepare_host():
    prepare = (DEPLOY / "prepare-host.sh").read_text(encoding="utf-8")

    for name in (
        "waingro-egress-lockdown.service",
        "waingro-egress-rollback.service",
        "waingro-egress-rollback.timer",
    ):
        assert f'"${{SOURCE_DIR}}/{name}"' in prepare
        assert f"/etc/systemd/system/{name}" in prepare


def test_egress_filter_runs_after_conntrack_and_preserves_only_dhcp():
    rules = (DEPLOY / "egress-lockdown.nft").read_text(encoding="utf-8")

    assert "hook output priority 100; policy drop" in rules
    assert "ct state established,related accept" in rules
    assert "udp sport 68 udp dport 67 accept" in rules
    assert "tcp dport" not in rules

"""Parametrized corpus integration tests.

Scans every fixture in tests/fixtures/skills/ through the full pipeline and
asserts verdicts, finding counts, and specific rule IDs.
"""

from pathlib import Path

import pytest

from waingro.scanner import scan_skill

CORPUS_DIR = Path(__file__).parent / "fixtures" / "skills"

# --- Fixture paths ---

BENIGN_FIXTURES = [
    CORPUS_DIR / "benign" / "weather-checker",
    CORPUS_DIR / "benign" / "code-reviewer",
    CORPUS_DIR / "benign" / "daily-standup",
]

MALICIOUS_FIXTURES = [
    # clawhavoc
    CORPUS_DIR / "clawhavoc" / "reverse-shell-skill",
    CORPUS_DIR / "clawhavoc" / "cron-persistence",
    CORPUS_DIR / "clawhavoc" / "c2-beacon",
    # credential-exfiltration
    CORPUS_DIR / "credential-exfiltration" / "env-harvester",
    CORPUS_DIR / "credential-exfiltration" / "keychain-reader",
    CORPUS_DIR / "credential-exfiltration" / "cloud-key-stealer",
    # authtool
    CORPUS_DIR / "authtool" / "oauth-interceptor",
    CORPUS_DIR / "authtool" / "session-stealer",
    CORPUS_DIR / "authtool" / "token-replay",
    # data-exfiltration
    CORPUS_DIR / "data-exfiltration" / "archive-and-send",
    CORPUS_DIR / "data-exfiltration" / "dns-exfil",
    CORPUS_DIR / "data-exfiltration" / "clipboard-monitor",
    # prompt-injection
    CORPUS_DIR / "prompt-injection" / "system-prompt-override",
    CORPUS_DIR / "prompt-injection" / "role-hijack",
    CORPUS_DIR / "prompt-injection" / "ignore-previous",
    # supply-chain
    CORPUS_DIR / "supply-chain" / "pip-install-evil",
    CORPUS_DIR / "supply-chain" / "npm-preinstall-hook",
    CORPUS_DIR / "supply-chain" / "curl-pipe-bash",
    # evasion
    CORPUS_DIR / "evasion" / "base64-split",
    CORPUS_DIR / "evasion" / "variable-concat",
    CORPUS_DIR / "evasion" / "hex-encoded-cmd",
    # mixed-signal
    CORPUS_DIR / "mixed-signal" / "helpful-but-leaky",
    CORPUS_DIR / "mixed-signal" / "mostly-clean",
    CORPUS_DIR / "mixed-signal" / "delayed-payload",
]

# Exhaustive mapping: fixture name -> set of rule IDs that MUST fire.
EXPECTED_RULES: dict[str, set[str]] = {
    # clawhavoc
    "reverse-shell-skill": {"NET-001"},
    "cron-persistence": {"PERSIST-001", "PERSIST-003"},
    "c2-beacon": {"EXEC-003"},  # eval "$RESP" in bundled monitor.sh
    # credential-exfiltration
    "env-harvester": {"EXFIL-005", "EXFIL-001"},  # env|grep + ~/.aws/credentials
    "keychain-reader": {"EXFIL-002"},
    "cloud-key-stealer": {"EXFIL-001"},  # ~/.ssh/id_rsa, ~/.kube/config, etc.
    # authtool
    "oauth-interceptor": {"EXFIL-001"},  # Authorization: Bearer pattern
    "session-stealer": {"EXFIL-003"},  # cookies.sqlite
    "token-replay": {"EXFIL-001"},  # .config/gh/hosts.yml, oauth_token, _authToken, .npmrc
    # data-exfiltration
    "archive-and-send": {"EXFIL-001"},  # ~/.ssh/, ~/.aws/
    "dns-exfil": {"NET-004"},  # dig with variable interpolation + fold -w 63
    "clipboard-monitor": {"EXFIL-007"},  # pbpaste, xclip
    # prompt-injection
    "system-prompt-override": {"INJECT-001", "INJECT-002"},
    "role-hijack": {"INJECT-002"},  # DAN / Do Anything Now
    "ignore-previous": {"INJECT-001"},  # ignore previous instructions
    # supply-chain
    "pip-install-evil": {"SOCIAL-001"},  # urllib4, internal-utils, corp-auth-helper
    "npm-preinstall-hook": {"SOCIAL-003"},  # preinstall curl|bash, child_process
    "curl-pipe-bash": {"EXEC-001"},  # curl|bash, wget|sh
    # evasion
    "base64-split": {"EXEC-002", "EXEC-003"},  # base64.b64decode + eval + subprocess shell=True
    "variable-concat": {"OBFUSC-002"},  # ${VAR}${VAR}, chr() concat, $(echo)
    "hex-encoded-cmd": {"EXEC-005", "EXEC-003"},  # bytes.fromhex, xxd -r -p, eval
    # mixed-signal
    "helpful-but-leaky": {"PERSIST-004"},  # .zshrc modification
    "mostly-clean": {"INJECT-003"},  # injection in YAML description only
    "delayed-payload": {"PERSIST-001"},  # @reboot crontab
}


def _fixture_id(path: Path) -> str:
    """Extract fixture name for test IDs."""
    return path.name


# --- Benign: zero findings, CLEAN verdict ---


@pytest.mark.parametrize("fixture_path", BENIGN_FIXTURES, ids=[p.name for p in BENIGN_FIXTURES])
def test_benign_zero_findings(fixture_path):
    result = scan_skill(fixture_path)
    assert result.verdict == "CLEAN", (
        f"{fixture_path.name}: expected CLEAN, got {result.verdict} "
        f"with findings: {[f.rule_id for f in result.findings]}"
    )
    assert len(result.findings) == 0, (
        f"{fixture_path.name}: expected 0 findings, got: "
        f"{[f.rule_id + ': ' + f.matched_content[:50] for f in result.findings]}"
    )


# --- Malicious: at least 1 finding, non-CLEAN verdict ---


@pytest.mark.parametrize(
    "fixture_path", MALICIOUS_FIXTURES, ids=[p.name for p in MALICIOUS_FIXTURES]
)
def test_malicious_detected(fixture_path):
    result = scan_skill(fixture_path)
    assert result.verdict != "CLEAN", (
        f"{fixture_path.name}: expected non-CLEAN verdict, got CLEAN"
    )
    assert len(result.findings) >= 1, (
        f"{fixture_path.name}: expected >= 1 finding, got 0"
    )


# --- Precision: specific rules fire for specific fixtures ---


EXPECTED_RULE_PARAMS = [
    pytest.param(fixture_path, rule_id, id=f"{fixture_path.name}->{rule_id}")
    for fixture_name, rule_ids in EXPECTED_RULES.items()
    for rule_id in rule_ids
    for fixture_path in MALICIOUS_FIXTURES
    if fixture_path.name == fixture_name
]


@pytest.mark.parametrize("fixture_path,expected_rule_id", EXPECTED_RULE_PARAMS)
def test_expected_rule_fires(fixture_path, expected_rule_id):
    result = scan_skill(fixture_path)
    fired_ids = {f.rule_id for f in result.findings}
    assert expected_rule_id in fired_ids, (
        f"{fixture_path.name}: expected {expected_rule_id} to fire, "
        f"but only got: {fired_ids}"
    )


# --- Edge case: mostly-clean injection is in metadata, not body ---


def test_mostly_clean_inject_003_is_metadata():
    """INJECT-003 fires and finding description references metadata, not body."""
    result = scan_skill(CORPUS_DIR / "mixed-signal" / "mostly-clean")
    inject_003_findings = [f for f in result.findings if f.rule_id == "INJECT-003"]
    assert len(inject_003_findings) >= 1
    # MetadataInjection sets description to mention the metadata field name
    assert any("metadata" in f.description.lower() for f in inject_003_findings), (
        "INJECT-003 finding should reference metadata field, got: "
        + str([f.description for f in inject_003_findings])
    )
    # INJECT-001 should NOT fire on the body (body is clean git commands)
    inject_001_findings = [f for f in result.findings if f.rule_id == "INJECT-001"]
    assert len(inject_001_findings) == 0, (
        "INJECT-001 should not fire on mostly-clean body, but got: "
        + str([f.matched_content for f in inject_001_findings])
    )


# --- Edge case: weather-checker uses curl but NOT piped to shell ---


def test_weather_checker_no_exec_001():
    """weather-checker contains curl but no pipe to shell; EXEC-001 must not fire."""
    result = scan_skill(CORPUS_DIR / "benign" / "weather-checker")
    rule_ids = {f.rule_id for f in result.findings}
    assert "EXEC-001" not in rule_ids, (
        "weather-checker has curl but no pipe-to-shell; EXEC-001 should not fire"
    )

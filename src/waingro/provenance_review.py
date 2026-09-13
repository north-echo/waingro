"""Prepare artifact-bound provenance evidence without network access or execution."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from waingro.dynamic.campaign import _safe_candidate_path
from waingro.parsers.script import read_file_bytes
from waingro.scanner import scan_skill

MAX_QUEUE_BYTES = 16 * 1024 * 1024
MAX_LEDGER_BYTES = 32 * 1024 * 1024
MAX_META_BYTES = 64 * 1024
MAX_REVIEWS_BYTES = 1024 * 1024
MAX_URLS = 512
MAX_CANDIDATES = 500
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_URL_RE = re.compile(r"https?://[^\s<>\[\]{}\"'`]+", re.IGNORECASE)
_SOURCE_HOSTS = {"bitbucket.org", "codeberg.org", "github.com", "gitlab.com"}
_PLACEHOLDER_PARTS = {
    "example",
    "octocat",
    "your-org",
    "your-organization",
    "your-username",
    "your_username",
    "username",
    "very-long-organization-name",
}
_PROVENANCE_DOCUMENTS = {
    "metadata.json",
    "package.json",
    "pyproject.toml",
    "security-manifest.md",
    "security.md",
    "skill.md",
    "skill.yml",
    "skill.yaml",
}
_REPOSITORY_PART_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_REVIEW_STATUSES = {
    "source-corroborated",
    "source-partially-corroborated",
    "source-unavailable",
}
_SOURCE_MATCH_SCOPES = {"full", "core", "partial", "none", "unknown"}


class ProvenancePreparationError(ValueError):
    """A queue cannot be safely converted to a provenance-review ledger."""


def _load_json_object(path: Path, *, max_bytes: int, label: str) -> tuple[dict, bytes]:
    if path.is_symlink() or not path.is_file():
        raise ProvenancePreparationError(f"{label} must be a non-symlink JSON file")
    if path.stat().st_size > max_bytes:
        raise ProvenancePreparationError(f"{label} exceeds {max_bytes} bytes")
    try:
        content = read_file_bytes(path)
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProvenancePreparationError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ProvenancePreparationError(f"{label} root is not an object")
    return value, content


def _content_fingerprint(files: list[dict], excluded: set[str]) -> str:
    """Hash scanned content while excluding named acquisition metadata."""
    digest = hashlib.sha256()
    for item in files:
        relative = item.get("path")
        sha256 = item.get("sha256")
        size = item.get("size_bytes")
        if relative in excluded:
            continue
        if (
            not isinstance(relative, str)
            or not isinstance(sha256, str)
            or not isinstance(size, int)
        ):
            raise ProvenancePreparationError("artifact identity contains an invalid file record")
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(size.to_bytes(8, "big"))
        digest.update(bytes.fromhex(sha256))
    return digest.hexdigest()


def _clean_url(raw: str) -> str | None:
    value = raw.rstrip(".,;:!?)\\]}")
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    hostname = parsed.hostname.lower() if parsed.hostname else ""
    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        return None
    if parsed.username or parsed.password:
        return None
    try:
        normalized_host = str(ipaddress.ip_address(hostname))
    except ValueError:
        try:
            normalized_host = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            return None
        if not all(
            label
            and len(label) <= 63
            and not label.startswith("-")
            and not label.endswith("-")
            and re.fullmatch(r"[a-z0-9-]+", label)
            for label in normalized_host.split(".")
        ):
            return None
    try:
        port = parsed.port
    except ValueError:
        return None
    netloc = f"{normalized_host}:{port}" if port else normalized_host
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path, parsed.query, ""))


def _claim_kind(line: str, start: int, end: int) -> str:
    lowered = line[max(0, start - 160) : end + 80].lower()
    if "git clone" in lowered:
        return "clone"
    if re.search(r"(?:repository|sourcerepo|skillrepo)[\"'*\]]*\s*[:=]", lowered) is not None:
        return "repository"
    if re.search(r"(?:^|[\[\s{,])source(?:\]|\s|\"|')?\s*[:=]", lowered):
        return "source"
    if "homepage" in lowered:
        return "homepage"
    return "reference"


def _repository_identity(url: str) -> tuple[str | None, str | None, bool]:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    if host not in _SOURCE_HOSTS:
        return None, None, False
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return None, None, False
    owner = parts[0]
    repository = parts[1].removesuffix(".git")
    if not _REPOSITORY_PART_RE.fullmatch(owner) or not _REPOSITORY_PART_RE.fullmatch(repository):
        return None, None, False
    normalized = f"https://{host}/{owner}/{repository}"
    subpath = None
    if len(parts) > 4 and parts[2] in {"blob", "tree"}:
        subpath = "/".join(parts[4:])
    placeholder = any(part.lower() in _PLACEHOLDER_PARTS for part in (owner, repository))
    return normalized, subpath, placeholder


def _is_provenance_document(relative: str) -> bool:
    path = Path(relative)
    if len(path.parts) != 1:
        return False
    name = path.name.lower()
    return name in _PROVENANCE_DOCUMENTS or name.startswith("readme")


def _extract_url_evidence(
    candidate: Path, artifact_files: list[dict]
) -> tuple[list[dict], list[dict]]:
    claims: list[dict] = []
    hosts: dict[str, dict] = {}
    seen_claims: set[tuple] = set()
    for item in artifact_files:
        relative = item["path"]
        path = candidate / relative
        raw = read_file_bytes(path)
        if hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ProvenancePreparationError(f"candidate changed during provenance read: {path}")
        text = raw.decode("utf-8", errors="replace")
        for line_number, line in enumerate(text.splitlines(), 1):
            for match in _URL_RE.finditer(line):
                url = _clean_url(match.group(0))
                if url is None:
                    continue
                parsed = urlsplit(url)
                hostname = parsed.hostname or ""
                host_record = hosts.setdefault(
                    hostname,
                    {
                        "host": hostname,
                        "source_control": hostname in _SOURCE_HOSTS,
                        "loopback": hostname in {"localhost", "127.0.0.1", "::1"},
                        "occurrences": 0,
                    },
                )
                host_record["occurrences"] += 1
                if len(hosts) > MAX_URLS:
                    raise ProvenancePreparationError("candidate exceeds provenance host limit")
                repository, subpath, placeholder = _repository_identity(url)
                if repository is None or not _is_provenance_document(relative):
                    continue
                kind = _claim_kind(line, match.start(), match.end())
                key = (repository, subpath, kind)
                if key in seen_claims:
                    continue
                seen_claims.add(key)
                claims.append(
                    {
                        "url": url,
                        "repository": repository,
                        "subpath": subpath,
                        "kind": kind,
                        "file": relative,
                        "line": line_number,
                        "placeholder": placeholder,
                    }
                )
                if len(claims) > MAX_URLS:
                    raise ProvenancePreparationError("candidate exceeds provenance URL limit")
    return sorted(claims, key=lambda item: (item["file"], item["line"], item["url"])), [
        hosts[key] for key in sorted(hosts)
    ]


def _registry_metadata(
    candidate: Path,
    publisher: object,
    slug: object,
    expected_sha256: str | None,
) -> dict:
    path = candidate / "_meta.json"
    if not path.exists():
        return {
            "present": False,
            "artifact_identity_verified": None,
            "identity_matches_queue": None,
        }
    if expected_sha256 is None:
        return {
            "present": True,
            "artifact_identity_verified": False,
            "identity_matches_queue": None,
        }
    raw, content = _load_json_object(path, max_bytes=MAX_META_BYTES, label="registry metadata")
    if hashlib.sha256(content).hexdigest() != expected_sha256:
        raise ProvenancePreparationError(f"candidate changed during registry read: {path}")
    owner_id = raw.get("ownerId")
    registry_slug = raw.get("slug")
    return {
        "present": True,
        "owner_id": owner_id if isinstance(owner_id, str) else None,
        "slug": registry_slug if isinstance(registry_slug, str) else None,
        "version": raw.get("version") if isinstance(raw.get("version"), str) else None,
        "published_at": raw.get("publishedAt")
        if isinstance(raw.get("publishedAt"), (int, float))
        and not isinstance(raw.get("publishedAt"), bool)
        else None,
        "artifact_identity_verified": True,
        "identity_matches_queue": owner_id == publisher and registry_slug == slug,
    }


def _inspect_candidate(candidate_record: dict, corpus_root: Path) -> dict:
    if candidate_record.get("execution_authorized") is not False:
        raise ProvenancePreparationError("every queue candidate must remain unauthorized")
    candidate = _safe_candidate_path(candidate_record.get("path"), corpus_root)
    if candidate is None:
        raise ProvenancePreparationError("queue contains an unsafe or missing candidate path")
    expected = candidate_record.get("artifact_sha256")
    if not isinstance(expected, str) or not _DIGEST_RE.fullmatch(expected):
        raise ProvenancePreparationError("queue contains an invalid artifact SHA-256")
    result = scan_skill(candidate)
    artifact = result.artifact_identity
    if artifact is None or artifact.sha256 != expected:
        actual = artifact.sha256 if artifact else "unavailable"
        raise ProvenancePreparationError(
            f"artifact SHA-256 mismatch for {candidate}: expected {expected}, scanned {actual}"
        )
    artifact_dict = artifact.to_dict()
    registry_file = next(
        (item for item in artifact_dict["files"] if item.get("path") == "_meta.json"),
        None,
    )
    claims, hosts = _extract_url_evidence(candidate, artifact_dict["files"])
    strong_claims = [
        item
        for item in claims
        if item["kind"] in {"clone", "repository", "source"} and not item["placeholder"]
    ]
    return {
        "publisher": candidate_record.get("publisher"),
        "slug": candidate_record.get("slug"),
        "path": str(candidate),
        "artifact_sha256": artifact.sha256,
        "declared_metadata": {
            "name": result.metadata.name,
            "description": result.metadata.description,
            "version": result.metadata.version,
            "author": result.metadata.author,
            "tags": result.metadata.tags,
        },
        "review_context": {
            "review_score": candidate_record.get("review_score"),
            "review_priority": candidate_record.get("review_priority"),
            "rules": candidate_record.get("rules", []),
            "entrypoint_candidates": candidate_record.get("entrypoint_candidates", []),
        },
        "content_sha256_without_registry_metadata": _content_fingerprint(
            artifact_dict["files"], {"_meta.json"}
        ),
        "core_content_sha256": _content_fingerprint(
            artifact_dict["files"], {"_meta.json", "skill-card.md"}
        ),
        "registry_metadata": _registry_metadata(
            candidate,
            candidate_record.get("publisher"),
            candidate_record.get("slug"),
            registry_file.get("sha256") if registry_file else None,
        ),
        "source_claims": claims,
        "strong_source_claim_count": len(strong_claims),
        "service_hosts": hosts,
        "package_references": [
            {
                "runner": item.runner,
                "selector": item.selector,
                "file": item.file_path.relative_to(candidate).as_posix(),
                "line": item.line_number,
                "immutable": item.immutable,
                "network_allowed": item.network_allowed,
            }
            for item in result.package_references
        ],
        "external_verification": {
            "status": "not-checked",
            "repository": None,
            "revision": None,
            "artifact_source_match": None,
        },
        "content_equivalent_queue_entries": [],
        "core_content_equivalent_queue_entries": [],
        "execution_authorized": False,
    }


def prepare_provenance_ledger(queue_path: Path, output: Path) -> dict:
    """Verify an unauthorized queue and extract bounded, offline provenance evidence."""
    if output.exists():
        raise ProvenancePreparationError("provenance output already exists")
    queue, queue_content = _load_json_object(
        queue_path, max_bytes=MAX_QUEUE_BYTES, label="campaign queue"
    )
    if queue.get("execution_authorized") is not False:
        raise ProvenancePreparationError("provenance preparation requires an unauthorized queue")
    corpus_value = queue.get("corpus_root")
    if not isinstance(corpus_value, str):
        raise ProvenancePreparationError("campaign queue has no corpus root")
    corpus_root = Path(corpus_value)
    if corpus_root.is_symlink() or not corpus_root.is_dir():
        raise ProvenancePreparationError("campaign corpus root is unsafe or missing")
    candidates = queue.get("candidates")
    if not isinstance(candidates, list):
        raise ProvenancePreparationError("campaign queue candidates are not a list")
    if len(candidates) > MAX_CANDIDATES:
        raise ProvenancePreparationError(
            f"campaign queue exceeds the {MAX_CANDIDATES}-candidate provenance limit"
        )

    records = [
        _inspect_candidate(item, corpus_root) for item in candidates if isinstance(item, dict)
    ]
    if len(records) != len(candidates):
        raise ProvenancePreparationError("campaign queue contains a non-object candidate")

    equivalents: defaultdict[str, list[dict]] = defaultdict(list)
    core_equivalents: defaultdict[str, list[dict]] = defaultdict(list)
    for item in records:
        equivalents[item["content_sha256_without_registry_metadata"]].append(item)
        core_equivalents[item["core_content_sha256"]].append(item)
    for group in equivalents.values():
        if len(group) < 2:
            continue
        for item in group:
            item["content_equivalent_queue_entries"] = [
                {
                    "publisher": peer["publisher"],
                    "slug": peer["slug"],
                    "artifact_sha256": peer["artifact_sha256"],
                }
                for peer in group
                if peer is not item
            ]
    for group in core_equivalents.values():
        if len(group) < 2:
            continue
        for item in group:
            item["core_content_equivalent_queue_entries"] = [
                {
                    "publisher": peer["publisher"],
                    "slug": peer["slug"],
                    "artifact_sha256": peer["artifact_sha256"],
                }
                for peer in group
                if peer is not item
            ]

    document = {
        "schema_version": "1.0",
        "source_queue": str(queue_path.resolve()),
        "source_queue_sha256": hashlib.sha256(queue_content).hexdigest(),
        "corpus_root": str(corpus_root.resolve()),
        "execution_authorized": False,
        "network_access_performed": False,
        "counts": {
            "candidates": len(records),
            "artifact_identities_verified": len(records),
            "registry_identities_matching": sum(
                item["registry_metadata"]["identity_matches_queue"] is True for item in records
            ),
            "with_strong_source_claims": sum(
                item["strong_source_claim_count"] > 0 for item in records
            ),
            "without_strong_source_claims": sum(
                item["strong_source_claim_count"] == 0 for item in records
            ),
            "with_package_runner_references": sum(
                bool(item["package_references"]) for item in records
            ),
            "content_equivalence_groups": sum(len(group) > 1 for group in equivalents.values()),
            "core_content_equivalence_groups": sum(
                len(group) > 1 for group in core_equivalents.values()
            ),
        },
        "candidates": records,
    }
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        payload = (json.dumps(document, indent=2) + "\n").encode()
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return document


def _validated_external_review(raw: dict, known_artifacts: set[str]) -> dict:
    digest = raw.get("artifact_sha256")
    if not isinstance(digest, str) or digest not in known_artifacts:
        raise ProvenancePreparationError("external review is not bound to a ledger artifact")
    status = raw.get("status")
    if status not in _REVIEW_STATUSES:
        raise ProvenancePreparationError("external review has an unsupported status")
    repository = raw.get("repository")
    if repository is not None:
        cleaned = _clean_url(repository) if isinstance(repository, str) else None
        identity = _repository_identity(cleaned) if cleaned else (None, None, False)
        if cleaned != repository or identity[0] is None:
            raise ProvenancePreparationError(
                "external review repository is not a normalized source URL"
            )
    revision = raw.get("revision")
    if revision is not None and (
        not isinstance(revision, str) or not _REVISION_RE.fullmatch(revision)
    ):
        raise ProvenancePreparationError("external review revision is not a full Git SHA-1")
    source_match = raw.get("artifact_source_match")
    if source_match not in _SOURCE_MATCH_SCOPES:
        raise ProvenancePreparationError("external review has an unsupported source-match scope")
    if status == "source-partially-corroborated" and source_match != "partial":
        raise ProvenancePreparationError(
            "partially corroborated source review requires a partial source match"
        )
    if status == "source-unavailable" and (
        revision is not None or source_match not in {"none", "unknown"}
    ):
        raise ProvenancePreparationError(
            "unavailable source review cannot claim a revision or positive source match"
        )
    if status != "source-unavailable" and (repository is None or revision is None):
        raise ProvenancePreparationError(
            "corroborated source review requires a repository and full revision"
        )
    counts = raw.get("match_counts")
    if counts is not None:
        if not isinstance(counts, dict):
            raise ProvenancePreparationError("external review match counts are not an object")
        values = [counts.get(key) for key in ("total", "matched", "missing", "changed")]
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in values
        ):
            raise ProvenancePreparationError("external review match counts are invalid")
        if sum(values[1:]) != values[0]:
            raise ProvenancePreparationError("external review match counts do not reconcile")
    evidence_urls = raw.get("evidence_urls", [])
    if not isinstance(evidence_urls, list) or len(evidence_urls) > 20:
        raise ProvenancePreparationError("external review evidence URLs are invalid")
    for url in evidence_urls:
        cleaned = _clean_url(url) if isinstance(url, str) else None
        if cleaned != url or urlsplit(cleaned).scheme != "https":
            raise ProvenancePreparationError("external review evidence URL is not normalized HTTPS")
    note = raw.get("note")
    if note is not None and (not isinstance(note, str) or len(note) > 2000):
        raise ProvenancePreparationError("external review note is invalid")
    return {
        "status": status,
        "repository": repository,
        "revision": revision,
        "artifact_source_match": source_match,
        "match_counts": counts,
        "evidence_urls": evidence_urls,
        "note": note,
    }


def apply_external_reviews(ledger_path: Path, reviews_path: Path, output: Path) -> dict:
    """Attach manual, artifact-bound source checks without changing intent verdicts."""
    if output.exists():
        raise ProvenancePreparationError("reviewed provenance output already exists")
    ledger, ledger_content = _load_json_object(
        ledger_path, max_bytes=MAX_LEDGER_BYTES, label="provenance ledger"
    )
    reviews, reviews_content = _load_json_object(
        reviews_path, max_bytes=MAX_REVIEWS_BYTES, label="external reviews"
    )
    if ledger.get("execution_authorized") is not False:
        raise ProvenancePreparationError(
            "external review requires an unauthorized provenance ledger"
        )
    if reviews.get("schema_version") != "1.0" or not isinstance(reviews.get("reviews"), list):
        raise ProvenancePreparationError("unsupported external-review schema")
    candidates = ledger.get("candidates")
    if not isinstance(candidates, list) or any(not isinstance(item, dict) for item in candidates):
        raise ProvenancePreparationError("provenance ledger candidates are invalid")
    known = {
        item.get("artifact_sha256")
        for item in candidates
        if isinstance(item.get("artifact_sha256"), str)
    }
    reviewed: dict[str, dict] = {}
    for raw in reviews["reviews"]:
        if not isinstance(raw, dict):
            raise ProvenancePreparationError("external review entry is not an object")
        digest = raw.get("artifact_sha256")
        if digest in reviewed:
            raise ProvenancePreparationError("duplicate external review artifact")
        reviewed[digest] = _validated_external_review(raw, known)

    status_counts: defaultdict[str, int] = defaultdict(int)
    for item in candidates:
        digest = item["artifact_sha256"]
        if digest in reviewed:
            item["external_verification"] = reviewed[digest]
            status_counts[reviewed[digest]["status"]] += 1
        else:
            status_counts["not-checked"] += 1
    ledger["schema_version"] = "1.1"
    ledger["source_ledger"] = str(ledger_path.resolve())
    ledger["source_ledger_sha256"] = hashlib.sha256(ledger_content).hexdigest()
    ledger["external_reviews"] = {
        "source": str(reviews_path.resolve()),
        "source_sha256": hashlib.sha256(reviews_content).hexdigest(),
        "network_access_performed_by_apply_command": False,
        "intent_verdicts_changed": False,
        "counts": dict(sorted(status_counts.items())),
    }
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        payload = (json.dumps(ledger, indent=2) + "\n").encode()
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return ledger

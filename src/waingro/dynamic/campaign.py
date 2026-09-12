"""Prepare a bounded manual-review queue without executing candidate content."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

_DIGEST_LENGTH = 64
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_RUNNABLE_SUFFIXES = {
    ".py": "python",
    ".js": "node",
    ".mjs": "node",
    ".cjs": "node",
    ".sh": "shell",
}
_SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_SECRET_RULES = {"EXFIL-006"}


class CampaignPreparationError(ValueError):
    """Input data cannot be safely converted to a campaign queue."""


def _safe_candidate_path(value: object, corpus_root: Path) -> Path | None:
    if not isinstance(value, str):
        return None
    candidate = Path(value)
    try:
        root = corpus_root.resolve(strict=True)
        relative = candidate.relative_to(root)
    except (OSError, ValueError):
        return None
    if len(relative.parts) != 2 or ".." in relative.parts:
        return None
    current = root
    try:
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                return None
        resolved = current.resolve(strict=True)
    except OSError:
        return None
    return resolved if resolved.is_dir() else None


def _entrypoints(candidate: Path) -> list[dict[str, str]]:
    records = []
    for root, directories, files in os.walk(candidate):
        relative_root = Path(root).relative_to(candidate)
        if len(relative_root.parts) >= 2:
            directories.clear()
        directories[:] = sorted(
            name for name in directories if not (Path(root) / name).is_symlink()
        )
        for name in sorted(files):
            path = Path(root) / name
            relative = path.relative_to(candidate)
            if len(relative.parts) > 2 or path.is_symlink() or not path.is_file():
                continue
            interpreter = _RUNNABLE_SUFFIXES.get(path.suffix.lower())
            if interpreter:
                records.append({"path": relative.as_posix(), "interpreter": interpreter})
    return records


def _behavior_fingerprint(record: dict) -> str:
    material = {
        "rules": sorted(
            {
                item.get("rule")
                for item in record.get("findings", [])
                if isinstance(item, dict) and isinstance(item.get("rule"), str)
            }
        ),
        "paths": sorted(
            {
                tuple(item.get("stages", []))
                for item in record.get("attack_paths", [])
                if isinstance(item, dict)
                and isinstance(item.get("stages"), list)
                and all(isinstance(stage, str) for stage in item["stages"])
            }
        ),
    }
    canonical = json.dumps(material, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(canonical).hexdigest()


def _priority(record: dict) -> tuple[float, float, int, float, str]:
    confidences = [
        float(item.get("confidence", 0))
        for item in record.get("attack_paths", [])
        if isinstance(item, dict) and isinstance(item.get("confidence"), (int, float))
    ]
    severities = [
        _SEVERITY_WEIGHT.get(str(item.get("severity", "")).lower(), 0)
        for item in record.get("findings", [])
        if isinstance(item, dict)
    ]
    security_tool_score = record.get("security_tool_score", 0)
    if not isinstance(security_tool_score, (int, float)):
        security_tool_score = 0
    return (
        float(record.get("review_score", 0))
        if isinstance(record.get("review_score"), (int, float))
        else 0.0,
        max(confidences, default=0),
        max(severities, default=0),
        -float(security_tool_score),
        str(record.get("artifact_sha256", "")),
    )


def prepare_campaign_queue(
    input_jsonl: Path,
    corpus_root: Path,
    output: Path,
    *,
    limit: int = 50,
    min_path_confidence: float = 0.95,
    min_review_score: float = 0.35,
    per_behavior_limit: int = 3,
) -> dict:
    """Select review candidates; never import, install, or execute their files."""
    if not 1 <= limit <= 500:
        raise CampaignPreparationError("campaign queue limit must be between 1 and 500")
    if not 1 <= per_behavior_limit <= 10:
        raise CampaignPreparationError("per-behavior limit must be between 1 and 10")
    if not 0.5 <= min_path_confidence <= 1:
        raise CampaignPreparationError("minimum path confidence must be between 0.5 and 1.0")
    if not 0.0 <= min_review_score <= 1:
        raise CampaignPreparationError("minimum review score must be between 0.0 and 1.0")
    if output.exists():
        raise CampaignPreparationError("campaign queue output already exists")
    if input_jsonl.is_symlink() or not input_jsonl.is_file():
        raise CampaignPreparationError("input must be a non-symlink JSONL file")
    if corpus_root.is_symlink() or not corpus_root.is_dir():
        raise CampaignPreparationError("corpus root must be a non-symlink directory")

    seen_artifacts: set[str] = set()
    excluded: Counter[str] = Counter()
    eligible = []
    total = 0
    with input_jsonl.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            total += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CampaignPreparationError(f"invalid JSON on line {line_number}") from exc
            if not isinstance(record, dict):
                raise CampaignPreparationError(f"line {line_number} is not an object")
            review_score = record.get("review_score")
            has_review_score = isinstance(review_score, (int, float))
            legacy_eligible = (
                not has_review_score
                and record.get("hybrid_verdict") == "SUSPICIOUS"
                and record.get("dynamic_priority") == "high"
            )
            review_eligible = (
                has_review_score
                and float(review_score) >= min_review_score
                and record.get("dynamic_priority") in {"high", "medium"}
            )
            if not (legacy_eligible or review_eligible):
                excluded["below-review-priority"] += 1
                continue
            digest = record.get("artifact_sha256")
            if (
                not isinstance(digest, str)
                or len(digest) != _DIGEST_LENGTH
                or not _DIGEST_RE.fullmatch(digest)
            ):
                excluded["invalid-artifact-digest"] += 1
                continue
            if digest in seen_artifacts:
                excluded["duplicate-artifact"] += 1
                continue
            seen_artifacts.add(digest)
            findings = [item for item in record.get("findings", []) if isinstance(item, dict)]
            tool_score = record.get("security_tool_score", 0)
            tool_annotation = any(
                "security tool" in str(item.get("note", "")).lower()
                or "security tool" in str(item.get("context_note", "")).lower()
                for item in findings
            )
            if (
                isinstance(tool_score, (int, float)) and tool_score >= 0.3
            ) or tool_annotation:
                excluded["probable-security-tool"] += 1
                continue
            if any(item.get("rule") in _SECRET_RULES for item in findings):
                excluded["possible-embedded-credential"] += 1
                continue
            confidences = [
                float(item.get("confidence", 0))
                for item in record.get("attack_paths", [])
                if isinstance(item, dict) and isinstance(item.get("confidence"), (int, float))
            ]
            if (
                max(confidences, default=0) < min_path_confidence
                and not review_eligible
            ):
                excluded["below-path-or-review-threshold"] += 1
                continue
            candidate = _safe_candidate_path(record.get("path"), corpus_root)
            if candidate is None:
                excluded["unsafe-or-missing-path"] += 1
                continue
            entrypoints = _entrypoints(candidate)
            if not entrypoints:
                excluded["no-explicit-runnable-entrypoint"] += 1
                continue
            behavior = _behavior_fingerprint(record)
            eligible.append({
                "publisher": record.get("publisher"),
                "slug": record.get("slug"),
                "path": str(candidate),
                "artifact_sha256": digest,
                "behavior_fingerprint": behavior,
                "max_path_confidence": max(confidences, default=0.0),
                "review_score": round(float(review_score), 3) if has_review_score else None,
                "review_priority": record.get("review_priority", record.get("dynamic_priority")),
                "security_tool_score": tool_score,
                "rules": sorted({item.get("rule") for item in findings if item.get("rule")}),
                "entrypoint_candidates": entrypoints,
                "review_status": "manual-review-required",
                "execution_authorized": False,
                "review_requirements": [
                    "confirm stated purpose against executed behavior",
                    "select one exact artifact-bound entrypoint",
                    "confirm no possible live credential is present",
                    "define required runtime coverage and negative control",
                    "record provenance and publisher context",
                ],
                "_priority": _priority(record),
            })

    eligible.sort(key=lambda item: item["_priority"], reverse=True)
    behavior_counts: defaultdict[str, int] = defaultdict(int)
    selected = []
    considered = 0
    for item in eligible:
        considered += 1
        fingerprint = item["behavior_fingerprint"]
        if behavior_counts[fingerprint] >= per_behavior_limit:
            excluded["behavior-family-cap"] += 1
            continue
        behavior_counts[fingerprint] += 1
        item.pop("_priority")
        selected.append(item)
        if len(selected) >= limit:
            break
    if beyond_limit := max(0, len(eligible) - considered):
        excluded["eligible-beyond-limit"] += beyond_limit
    document = {
        "schema_version": "1.1",
        "created_at": datetime.now(UTC).isoformat(),
        "input": str(input_jsonl.resolve()),
        "corpus_root": str(corpus_root.resolve()),
        "execution_authorized": False,
        "policy": {
            "limit": limit,
            "minimum_path_confidence": min_path_confidence,
            "minimum_review_score": min_review_score,
            "per_behavior_limit": per_behavior_limit,
            "possible_embedded_credentials_excluded": True,
            "security_tool_threshold": 0.3,
            "requires_manual_review": True,
        },
        "counts": {
            "input_records": total,
            "eligible_before_family_cap": len(eligible),
            "selected_for_manual_review": len(selected),
            "excluded": dict(sorted(excluded.items())),
        },
        "candidates": selected,
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

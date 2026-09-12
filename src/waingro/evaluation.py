"""Ground-truth evaluation for labeled OpenClaw skill datasets."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory

from waingro.scanner import scan_skill

PREDICATES: dict[str, Callable[[str], bool]] = {
    "alert": lambda verdict: verdict != "CLEAN",
    "suspicious": lambda verdict: verdict in {"SUSPICIOUS", "MALICIOUS"},
    "malicious": lambda verdict: verdict == "MALICIOUS",
}


@dataclass(frozen=True)
class BenchmarkCase:
    """One labeled skill directory."""

    path: Path
    label: str
    category: str


@dataclass
class BinaryMetrics:
    """Binary classification metrics at one scanner threshold."""

    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0

    @property
    def precision(self) -> float:
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else 0.0

    @property
    def specificity(self) -> float:
        denominator = self.true_negative + self.false_positive
        return self.true_negative / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        denominator = self.precision + self.recall
        return 2 * self.precision * self.recall / denominator if denominator else 0.0

    def to_dict(self) -> dict:
        return {
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "specificity": round(self.specificity, 4),
            "f1": round(self.f1, 4),
        }


@dataclass
class BenchmarkRecord:
    """Scanner output for one labeled case."""

    path: str
    label: str
    category: str
    verdict: str
    rule_ids: list[str]
    hybrid_verdict: str
    review_score: float
    review_priority: str

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "label": self.label,
            "category": self.category,
            "verdict": self.verdict,
            "hybrid_verdict": self.hybrid_verdict,
            "review_score": round(self.review_score, 3),
            "review_priority": self.review_priority,
            "rule_ids": self.rule_ids,
        }


@dataclass
class BenchmarkReport:
    """Complete deterministic benchmark result."""

    dataset: str
    analysis_mode: str = "static"
    records: list[BenchmarkRecord] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)

    def metrics(self, threshold: str) -> BinaryMetrics:
        predicate = PREDICATES[threshold]
        result = BinaryMetrics()
        for record in self.records:
            predicted = predicate(record.verdict)
            positive = record.label == "malicious"
            if positive and predicted:
                result.true_positive += 1
            elif positive:
                result.false_negative += 1
            elif predicted:
                result.false_positive += 1
            else:
                result.true_negative += 1
        return result

    def ranking_metrics(self) -> dict:
        """Measure whether known malicious cases rise to the review queue."""
        ranked = sorted(self.records, key=lambda item: (-item.review_score, item.path))
        positives = sum(record.label == "malicious" for record in ranked)
        hits = 0
        precision_sum = 0.0
        for rank, record in enumerate(ranked, 1):
            if record.label == "malicious":
                hits += 1
                precision_sum += hits / rank
        average_precision = precision_sum / positives if positives else 0.0

        cutoffs = sorted({min(value, len(ranked)) for value in (10, 25, 50, positives) if value})
        at_k = {}
        for cutoff in cutoffs:
            retrieved = sum(
                record.label == "malicious" for record in ranked[:cutoff]
            )
            at_k[str(cutoff)] = {
                "true_positive": retrieved,
                "false_positive": cutoff - retrieved,
                "precision": round(retrieved / cutoff, 4),
                "recall": round(retrieved / positives, 4) if positives else 0.0,
            }
        return {
            "score": "intent-neutral review_score",
            "tie_breaker": "path ascending",
            "positives": positives,
            "average_precision": round(average_precision, 4),
            "recall_at_positive_count": (
                at_k.get(str(positives), {}).get("recall", 0.0) if positives else 0.0
            ),
            "at_k": at_k,
        }

    def to_dict(self) -> dict:
        verdicts: dict[str, Counter] = defaultdict(Counter)
        rule_hits: Counter = Counter()
        category_recall: dict[str, dict] = {}
        for record in self.records:
            verdicts[record.label][record.verdict] += 1
            rule_hits.update(record.rule_ids)

        malicious_categories = sorted(
            {record.category for record in self.records if record.label == "malicious"}
        )
        for category in malicious_categories:
            subset = [
                record
                for record in self.records
                if record.label == "malicious" and record.category == category
            ]
            detected = sum(
                record.verdict in {"SUSPICIOUS", "MALICIOUS"} for record in subset
            )
            category_recall[category] = {
                "detected": detected,
                "total": len(subset),
                "recall": round(detected / len(subset), 4) if subset else 0.0,
            }

        return {
            "schema_version": "1.1",
            "dataset": self.dataset,
            "analysis_mode": self.analysis_mode,
            "cases": len(self.records),
            "errors": self.errors,
            "verdicts": {
                label: dict(sorted(counts.items())) for label, counts in sorted(verdicts.items())
            },
            "thresholds": {
                threshold: self.metrics(threshold).to_dict() for threshold in PREDICATES
            },
            "ranking": self.ranking_metrics(),
            "malicious_category_recall_at_suspicious": category_recall,
            "rule_hits": dict(sorted(rule_hits.items())),
            "records": [record.to_dict() for record in self.records],
        }


def discover_benchmark_cases(dataset: Path) -> list[BenchmarkCase]:
    """Discover directory-form skills and flat Markdown benchmark cases."""
    cases: list[BenchmarkCase] = []
    for label in ("benign", "malicious"):
        label_dir = dataset / label
        if not label_dir.is_dir():
            raise ValueError(f"benchmark dataset is missing directory: {label_dir}")
        for path in sorted(label_dir.iterdir()):
            if path.is_dir() and (path / "SKILL.md").is_file():
                parts = path.name.split("-", 2)
                category = parts[1] if len(parts) == 3 else "unspecified"
            elif path.is_file() and path.suffix.lower() == ".md":
                parts = path.stem.split("_")
                category = parts[2] if len(parts) >= 4 else "unspecified"
            else:
                continue
            cases.append(BenchmarkCase(path=path, label=label, category=category))
    if not cases:
        raise ValueError(f"benchmark dataset contains no skill cases: {dataset}")
    return cases


def _scan_case(path: Path):
    if path.is_dir() or path.name == "SKILL.md":
        return scan_skill(path)
    # Flat benchmark fixtures are adapted to the scanner's real manifest name
    # in a private temporary directory. Their content is read, never executed.
    with TemporaryDirectory(prefix="waingro-eval-") as temporary:
        manifest = Path(temporary) / "SKILL.md"
        manifest.write_bytes(path.read_bytes())
        return scan_skill(manifest)


def evaluate_dataset(dataset: Path, *, analysis_mode: str = "static") -> BenchmarkReport:
    """Scan a labeled dataset without executing any skill content."""
    if analysis_mode not in {"static", "hybrid-static"}:
        raise ValueError(f"unsupported benchmark analysis mode: {analysis_mode}")
    dataset = dataset.resolve()
    report = BenchmarkReport(dataset=str(dataset), analysis_mode=analysis_mode)
    for case in discover_benchmark_cases(dataset):
        try:
            result = _scan_case(case.path)
        except (OSError, ValueError) as exc:
            report.errors.append(
                {"path": str(case.path), "error": f"{type(exc).__name__}: {exc}"}
            )
            continue
        from waingro.analyzers.hybrid import assess_scan

        assessment = assess_scan(result)
        verdict = (
            assessment.verdict.value if analysis_mode == "hybrid-static" else result.verdict
        )
        report.records.append(
            BenchmarkRecord(
                path=str(case.path.relative_to(dataset)),
                label=case.label,
                category=case.category,
                verdict=verdict,
                hybrid_verdict=assessment.verdict.value,
                review_score=assessment.review_score,
                review_priority=assessment.review_priority,
                rule_ids=sorted({finding.rule_id for finding in result.findings}),
            )
        )
    return report

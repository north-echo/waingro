"""Ground-truth evaluation for labeled OpenClaw skill datasets."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

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

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "label": self.label,
            "category": self.category,
            "verdict": self.verdict,
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
            "schema_version": "1.0",
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
            "malicious_category_recall_at_suspicious": category_recall,
            "rule_hits": dict(sorted(rule_hits.items())),
            "records": [record.to_dict() for record in self.records],
        }


def discover_benchmark_cases(dataset: Path) -> list[BenchmarkCase]:
    """Discover ``benign/`` and ``malicious/`` skill directories."""
    cases: list[BenchmarkCase] = []
    for label in ("benign", "malicious"):
        label_dir = dataset / label
        if not label_dir.is_dir():
            raise ValueError(f"benchmark dataset is missing directory: {label_dir}")
        for path in sorted(label_dir.iterdir()):
            if not path.is_dir() or not (path / "SKILL.md").is_file():
                continue
            parts = path.name.split("-", 2)
            category = parts[1] if len(parts) == 3 else "unspecified"
            cases.append(BenchmarkCase(path=path, label=label, category=category))
    if not cases:
        raise ValueError(f"benchmark dataset contains no SKILL.md cases: {dataset}")
    return cases


def evaluate_dataset(dataset: Path, *, analysis_mode: str = "static") -> BenchmarkReport:
    """Scan a labeled dataset without executing any skill content."""
    if analysis_mode not in {"static", "hybrid-static"}:
        raise ValueError(f"unsupported benchmark analysis mode: {analysis_mode}")
    dataset = dataset.resolve()
    report = BenchmarkReport(dataset=str(dataset), analysis_mode=analysis_mode)
    for case in discover_benchmark_cases(dataset):
        try:
            result = scan_skill(case.path)
        except (OSError, ValueError) as exc:
            report.errors.append(
                {"path": str(case.path), "error": f"{type(exc).__name__}: {exc}"}
            )
            continue
        verdict = result.verdict
        if analysis_mode == "hybrid-static":
            from waingro.analyzers.hybrid import assess_scan

            verdict = assess_scan(result).verdict.value
        report.records.append(
            BenchmarkRecord(
                path=str(case.path.relative_to(dataset)),
                label=case.label,
                category=case.category,
                verdict=verdict,
                rule_ids=sorted({finding.rule_id for finding in result.findings}),
            )
        )
    return report

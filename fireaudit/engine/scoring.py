"""Posture scoring — compute a single weighted score from a list of findings."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fireaudit.engine.evaluator import Finding

# Severity weights: critical rules contribute more to the score than low/info.
# A critical pass or fail counts 5× more than a low pass or fail.
_WEIGHTS: dict[str, int] = {
    "critical": 5,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 1,
}

_GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (90, "A"),
    (75, "B"),
    (60, "C"),
    (40, "D"),
    (0,  "F"),
]


def grade_for_score(score: int) -> str:
    for threshold, letter in _GRADE_THRESHOLDS:
        if score >= threshold:
            return letter
    return "F"


def compute_posture_score(findings: list) -> dict:
    """Compute a posture score from a list of Finding objects or finding dicts.

    Uses a severity-weighted pass rate so the score reflects both the proportion
    of rules that pass *and* the severity of failures.  Critical rules carry 5×
    the weight of low/info rules; a single critical fail therefore costs more than
    five low fails, but the score can never be crushed to zero by failures alone
    when many rules still pass.

    Returns::

        {
            "score": 74,
            "grade": "C",
            "fail_counts": {"critical": 1, "high": 3, "medium": 5, "low": 2, "info": 0},
            "total_rules": 59,
            "pass_count": 48,
            "fail_count": 11,
            "not_applicable_count": 0,
            "manual_check_count": 0,
            "error_count": 0,
        }
    """
    fail_counts: dict[str, int] = {s: 0 for s in _WEIGHTS}
    pass_count = 0
    fail_count = 0
    na_count = 0
    manual_count = 0
    error_count = 0

    pass_weight = 0
    total_weight = 0

    for f in findings:
        # Support both Finding dataclass and dict (from to_dict())
        if isinstance(f, dict):
            status = f.get("status", "")
            severity = f.get("severity", "info")
        else:
            status = f.status
            severity = f.severity

        if status == "pass":
            pass_count += 1
            w = _WEIGHTS.get(severity, 1)
            pass_weight += w
            total_weight += w
        elif status == "fail":
            fail_count += 1
            fail_counts[severity] = fail_counts.get(severity, 0) + 1
            w = _WEIGHTS.get(severity, 1)
            total_weight += w
        elif status == "not_applicable":
            na_count += 1
        elif status == "manual_check":
            manual_count += 1
        elif status == "error":
            error_count += 1

    score = round(pass_weight / total_weight * 100) if total_weight > 0 else 100
    return {
        "score": score,
        "grade": grade_for_score(score),
        "fail_counts": fail_counts,
        "total_rules": len(findings),
        "pass_count": pass_count,
        "fail_count": fail_count,
        "not_applicable_count": na_count,
        "manual_check_count": manual_count,
        "error_count": error_count,
    }

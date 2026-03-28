"""Tests for posture scoring."""

import pytest
from fireaudit.engine.scoring import compute_posture_score, grade_for_score


def _f(status: str, severity: str = "medium") -> dict:
    return {"status": status, "severity": severity}


class TestGradeForScore:
    def test_a(self):
        assert grade_for_score(100) == "A"
        assert grade_for_score(90) == "A"

    def test_b(self):
        assert grade_for_score(89) == "B"
        assert grade_for_score(75) == "B"

    def test_c(self):
        assert grade_for_score(74) == "C"
        assert grade_for_score(60) == "C"

    def test_d(self):
        assert grade_for_score(59) == "D"
        assert grade_for_score(40) == "D"

    def test_f(self):
        assert grade_for_score(39) == "F"
        assert grade_for_score(0) == "F"


class TestComputePostureScore:
    def test_all_pass(self):
        findings = [_f("pass", "high"), _f("pass", "critical"), _f("pass", "low")]
        result = compute_posture_score(findings)
        assert result["score"] == 100
        assert result["grade"] == "A"
        assert result["fail_count"] == 0
        assert result["pass_count"] == 3

    def test_single_critical_fail(self):
        # Only one rule evaluated and it fails → 0 pass weight / 5 total weight → 0
        findings = [_f("fail", "critical")]
        result = compute_posture_score(findings)
        assert result["score"] == 0
        assert result["grade"] == "F"
        assert result["fail_counts"]["critical"] == 1

    def test_single_high_fail(self):
        # Only one rule evaluated and it fails → 0 pass weight / 3 total weight → 0
        findings = [_f("fail", "high")]
        result = compute_posture_score(findings)
        assert result["score"] == 0

    def test_floor_at_zero(self):
        findings = [_f("fail", "critical")] * 10
        result = compute_posture_score(findings)
        assert result["score"] == 0
        assert result["grade"] == "F"

    def test_mixed_severities(self):
        # pass_weight = low(1) + medium(2) = 3
        # total_weight = critical(5) + high(3) + high(3) + medium(2) + low(1) + medium(2) = 16
        # score = round(3/16 * 100) = 19
        findings = [
            _f("fail", "critical"),
            _f("fail", "high"),
            _f("fail", "high"),
            _f("fail", "medium"),
            _f("pass", "low"),
            _f("pass", "medium"),
        ]
        result = compute_posture_score(findings)
        assert result["score"] == 19
        assert result["grade"] == "F"
        assert result["fail_count"] == 4
        assert result["pass_count"] == 2

    def test_not_applicable_not_deducted(self):
        findings = [_f("not_applicable", "critical"), _f("pass", "high")]
        result = compute_posture_score(findings)
        assert result["score"] == 100
        assert result["not_applicable_count"] == 1

    def test_manual_check_not_deducted(self):
        findings = [_f("manual_check", "high"), _f("pass", "medium")]
        result = compute_posture_score(findings)
        assert result["score"] == 100
        assert result["manual_check_count"] == 1

    def test_empty_findings(self):
        result = compute_posture_score([])
        assert result["score"] == 100
        assert result["grade"] == "A"
        assert result["total_rules"] == 0

    def test_total_rules_count(self):
        findings = [_f("pass"), _f("fail"), _f("not_applicable"), _f("manual_check")]
        result = compute_posture_score(findings)
        assert result["total_rules"] == 4

    def test_accepts_finding_objects(self):
        """compute_posture_score should work with Finding dataclass objects too."""
        from fireaudit.engine.evaluator import Finding
        findings = [
            Finding(rule_id="X-001", name="test", severity="high", status="fail"),
            Finding(rule_id="X-002", name="test2", severity="low", status="pass"),
        ]
        result = compute_posture_score(findings)
        # pass_weight = low(1), total_weight = high(3) + low(1) = 4 → score = round(1/4*100) = 25
        assert result["score"] == 25
        assert result["fail_count"] == 1

"""Smoke tests for HTML, JSON, and PDF report renderers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fireaudit.parsers import get_parser
from fireaudit.engine.loader import RuleLoader
from fireaudit.engine.evaluator import RuleEvaluator, build_report

_RULES_DIR = Path(__file__).parent.parent.parent / "rules"
_FIXTURE = Path(__file__).parent.parent / "fixtures" / "fortigate" / "sample_full.conf"


@pytest.fixture(scope="module")
def report():
    parser = get_parser("fortigate")()
    ir = parser.parse_file(_FIXTURE)
    loader = RuleLoader(_RULES_DIR)
    rules = loader.load_for_vendor("fortigate")
    evaluator = RuleEvaluator(rules)
    findings = evaluator.evaluate(ir, vendor="fortigate")
    return build_report(ir, findings)


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

class TestJSONReport:
    def test_renders_string(self, report):
        from fireaudit.output.json_report import render_json
        result = render_json(report)
        assert isinstance(result, str)

    def test_valid_json(self, report):
        from fireaudit.output.json_report import render_json
        result = render_json(report)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_contains_findings(self, report):
        from fireaudit.output.json_report import render_json
        parsed = json.loads(render_json(report))
        assert "findings" in parsed
        assert len(parsed["findings"]) > 0

    def test_contains_posture_score(self, report):
        from fireaudit.output.json_report import render_json
        parsed = json.loads(render_json(report))
        assert "posture_score" in parsed
        assert "score" in parsed["posture_score"]

    def test_writes_file(self, report, tmp_path):
        from fireaudit.output.json_report import render_json
        out = tmp_path / "report.json"
        render_json(report, output_path=out)
        assert out.exists()
        assert out.stat().st_size > 100
        parsed = json.loads(out.read_text())
        assert "findings" in parsed


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

class TestHTMLReport:
    def test_renders_string(self, report):
        from fireaudit.output.html_report import render_html
        result = render_html(report)
        assert isinstance(result, str)

    def test_contains_doctype(self, report):
        from fireaudit.output.html_report import render_html
        result = render_html(report)
        assert "<!DOCTYPE html>" in result

    def test_contains_posture_grade(self, report):
        from fireaudit.output.html_report import render_html
        result = render_html(report)
        # Grade letter should appear in the posture banner
        assert "posture-grade" in result

    def test_contains_findings_table(self, report):
        from fireaudit.output.html_report import render_html
        result = render_html(report)
        assert "FW-ADM-001" in result or "FW-ADM-002" in result

    def test_writes_file(self, report, tmp_path):
        from fireaudit.output.html_report import render_html
        out = tmp_path / "report.html"
        render_html(report, output_path=out)
        assert out.exists()
        assert out.stat().st_size > 1000

    def test_contains_framework_section(self, report):
        from fireaudit.output.html_report import render_html
        result = render_html(report)
        assert "Compliance Framework" in result or "fw-card" in result


# ---------------------------------------------------------------------------
# PDF report
# ---------------------------------------------------------------------------

class TestPDFReport:
    def test_renders_bytes(self, report):
        from fireaudit.output.pdf_report import render_pdf
        result = render_pdf(report)
        assert isinstance(result, bytes)

    def test_starts_with_pdf_magic(self, report):
        from fireaudit.output.pdf_report import render_pdf
        result = render_pdf(report)
        assert result[:4] == b"%PDF"

    def test_minimum_size(self, report):
        from fireaudit.output.pdf_report import render_pdf
        result = render_pdf(report)
        # A report with findings should be at least 10 KB
        assert len(result) > 10_000

    def test_writes_file(self, report, tmp_path):
        from fireaudit.output.pdf_report import render_pdf
        out = tmp_path / "report.pdf"
        render_pdf(report, output_path=out)
        assert out.exists()
        assert out.stat().st_size > 10_000

    def test_all_vendor_fixtures(self):
        """PDF render should not crash for any vendor with a fixture."""
        from fireaudit.output.pdf_report import render_pdf

        fixtures_dir = Path(__file__).parent.parent / "fixtures"
        vendor_map = {
            "fortigate": "fortigate",
            "paloalto": "paloalto",
            "cisco_asa": "cisco_asa",
            "pfsense": "pfsense",
            "sonicwall": "sonicwall",
            "sophos_xg": "sophos_xg",
            "watchguard": "watchguard",
            "checkpoint": "checkpoint",
            "juniper_srx": "juniper_srx",
        }
        fixture_files = {
            "fortigate": "sample_full.conf",
            "paloalto": "sample_running.xml",
            "cisco_asa": "sample_running.conf",
            "pfsense": "sample_config.xml",
            "sonicwall": "sample_export.xml",
            "sophos_xg": "sample_backup.xml",
            "watchguard": "sample_policy.xml",
            "checkpoint": "sample_gaia.conf",
            "juniper_srx": "sample_config.conf",
        }

        errors = []
        for vendor, fixture_name in fixture_files.items():
            fixture = fixtures_dir / vendor / fixture_name
            if not fixture.exists():
                continue
            try:
                parser = get_parser(vendor)()
                ir = parser.parse_file(fixture)
                loader = RuleLoader(_RULES_DIR)
                rules = loader.load_for_vendor(vendor)
                evaluator = RuleEvaluator(rules)
                findings = evaluator.evaluate(ir, vendor=vendor)
                rpt = build_report(ir, findings)
                result = render_pdf(rpt)
                assert result[:4] == b"%PDF", f"{vendor}: output is not a valid PDF"
            except Exception as exc:
                errors.append(f"{vendor}: {exc}")

        assert errors == [], "PDF render failed for vendors:\n" + "\n".join(errors)

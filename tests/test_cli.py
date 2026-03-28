"""Tests for the FireAudit CLI using Click's CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from fireaudit.cli import main

# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures"
FORTIGATE_CONF = FIXTURES / "fortigate" / "sample_full.conf"
CISCO_ASA_CONF = FIXTURES / "cisco_asa" / "sample_running.conf"
PFSENSE_CONF = FIXTURES / "pfsense" / "sample_config.xml"


# ---------------------------------------------------------------------------
# TestAuditCommand
# ---------------------------------------------------------------------------

class TestAuditCommand:
    def test_audit_html_stdout(self):
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", "-c", str(FORTIGATE_CONF), "-v", "fortigate",
        ])
        assert result.exit_code in (0, 2), (
            f"Unexpected exit code {result.exit_code}: {result.output}"
        )
        assert "<!DOCTYPE" in result.output or "html" in result.output.lower(), (
            f"Expected HTML output, got: {result.output[:200]}"
        )

    def test_audit_json_stdout(self):
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", "-c", str(FORTIGATE_CONF), "-v", "fortigate",
            "--format", "json",
        ])
        assert result.exit_code in (0, 2), (
            f"Unexpected exit code {result.exit_code}: {result.output}"
        )
        assert '"findings"' in result.output, (
            f"Expected JSON with findings key, got: {result.output[:200]}"
        )

    def test_audit_html_file(self, tmp_path):
        runner = CliRunner()
        out_file = tmp_path / "report.html"
        result = runner.invoke(main, [
            "audit", "-c", str(FORTIGATE_CONF), "-v", "fortigate",
            "-o", str(out_file),
        ])
        assert result.exit_code in (0, 2), (
            f"Unexpected exit code {result.exit_code}: {result.output}"
        )
        assert out_file.exists(), "HTML report file was not created"
        assert out_file.stat().st_size > 1000, (
            f"HTML report too small: {out_file.stat().st_size} bytes"
        )

    def test_audit_pdf_file(self, tmp_path):
        runner = CliRunner()
        out_file = tmp_path / "report.pdf"
        result = runner.invoke(main, [
            "audit", "-c", str(FORTIGATE_CONF), "-v", "fortigate",
            "--format", "pdf", "-o", str(out_file),
        ])
        assert result.exit_code in (0, 2), (
            f"Unexpected exit code {result.exit_code}: {result.output}"
        )
        assert out_file.exists(), "PDF report file was not created"
        content = out_file.read_bytes()
        assert content.startswith(b"%PDF"), (
            f"File does not start with %PDF: {content[:8]!r}"
        )

    def test_audit_both_file(self, tmp_path):
        runner = CliRunner()
        base = tmp_path / "report"
        result = runner.invoke(main, [
            "audit", "-c", str(FORTIGATE_CONF), "-v", "fortigate",
            "--format", "both", "-o", str(base),
        ])
        assert result.exit_code in (0, 2), (
            f"Unexpected exit code {result.exit_code}: {result.output}"
        )
        html_file = tmp_path / "report.html"
        pdf_file = tmp_path / "report.pdf"
        assert html_file.exists(), "report.html was not created"
        assert pdf_file.exists(), "report.pdf was not created"

    def test_audit_json_file(self, tmp_path):
        runner = CliRunner()
        out_file = tmp_path / "report.json"
        result = runner.invoke(main, [
            "audit", "-c", str(FORTIGATE_CONF), "-v", "fortigate",
            "--format", "json", "-o", str(out_file),
        ])
        assert result.exit_code in (0, 2), (
            f"Unexpected exit code {result.exit_code}: {result.output}"
        )
        assert out_file.exists(), "JSON report file was not created"
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert "findings" in data, "JSON report missing 'findings' key"

    def test_audit_severity_filter(self, tmp_path):
        runner = CliRunner()

        # Run without filter
        result_all = runner.invoke(main, [
            "audit", "-c", str(FORTIGATE_CONF), "-v", "fortigate",
            "--format", "json",
        ])
        assert result_all.exit_code in (0, 2)

        # Find the JSON portion of output (skip rich console lines)
        json_start = result_all.output.find("{")
        all_data = json.loads(result_all.output[json_start:])
        all_count = len(all_data["findings"])

        # Run with critical-only filter
        result_filtered = runner.invoke(main, [
            "audit", "-c", str(FORTIGATE_CONF), "-v", "fortigate",
            "--format", "json", "--severity", "critical",
        ])
        assert result_filtered.exit_code in (0, 2)
        json_start = result_filtered.output.find("{")
        filtered_data = json.loads(result_filtered.output[json_start:])
        filtered_count = len(filtered_data["findings"])

        assert filtered_count <= all_count, (
            "Severity filter should return fewer or equal findings"
        )

    def test_audit_framework_filter(self):
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", "-c", str(FORTIGATE_CONF), "-v", "fortigate",
            "--framework", "nist_800-53",
        ])
        assert result.exit_code in (0, 2), (
            f"Unexpected exit code {result.exit_code}: {result.output}"
        )

    def test_audit_missing_config(self):
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", "-c", "/nonexistent/path.conf", "-v", "fortigate",
        ])
        assert result.exit_code != 0, (
            "Expected non-zero exit for missing config file"
        )

    def test_audit_bad_vendor(self):
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", "-c", str(FORTIGATE_CONF), "-v", "badvendor",
        ])
        assert result.exit_code != 0, (
            "Expected non-zero exit for invalid vendor"
        )

    def test_audit_ir_output(self, tmp_path):
        runner = CliRunner()
        ir_file = tmp_path / "ir.json"
        result = runner.invoke(main, [
            "audit", "-c", str(FORTIGATE_CONF), "-v", "fortigate",
            "--ir-output", str(ir_file),
        ])
        assert result.exit_code in (0, 2), (
            f"Unexpected exit code {result.exit_code}: {result.output}"
        )
        assert ir_file.exists(), "IR output file was not created"
        data = json.loads(ir_file.read_text(encoding="utf-8"))
        assert isinstance(data, dict), "IR output should be a JSON object"

    def test_audit_show_commands(self):
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", "-c", str(FORTIGATE_CONF), "-v", "fortigate",
            "--show-commands",
        ])
        assert result.exit_code in (0, 2), (
            f"Unexpected exit code {result.exit_code}: {result.output}"
        )


# ---------------------------------------------------------------------------
# TestParseCommand
# ---------------------------------------------------------------------------

class TestParseCommand:
    def test_parse_stdout(self):
        runner = CliRunner()
        result = runner.invoke(main, [
            "parse", "-c", str(FORTIGATE_CONF), "-v", "fortigate",
        ])
        assert result.exit_code == 0, (
            f"Unexpected exit code {result.exit_code}: {result.output}"
        )
        # Output should be valid JSON
        data = json.loads(result.output)
        assert isinstance(data, dict), "parse stdout should be a JSON object"

    def test_parse_file(self, tmp_path):
        runner = CliRunner()
        out_file = tmp_path / "ir.json"
        result = runner.invoke(main, [
            "parse", "-c", str(FORTIGATE_CONF), "-v", "fortigate",
            "-o", str(out_file),
        ])
        assert result.exit_code == 0, (
            f"Unexpected exit code {result.exit_code}: {result.output}"
        )
        assert out_file.exists(), "IR output file was not created"
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert isinstance(data, dict)

    def test_parse_bad_vendor(self):
        runner = CliRunner()
        result = runner.invoke(main, [
            "parse", "-c", str(FORTIGATE_CONF), "-v", "badvendor",
        ])
        assert result.exit_code != 0, (
            "Expected non-zero exit for invalid vendor"
        )


# ---------------------------------------------------------------------------
# TestRulesListCommand
# ---------------------------------------------------------------------------

class TestRulesListCommand:
    def test_rules_list(self):
        runner = CliRunner()
        result = runner.invoke(main, ["rules", "list"])
        assert result.exit_code == 0, (
            f"Unexpected exit code {result.exit_code}: {result.output}"
        )
        # Rich table may truncate IDs; check count line and a known rule name instead
        assert "rules" in result.output, (
            f"Expected rule count in rules list output"
        )
        assert "HTTP Management Must Be Disabled" in result.output, (
            f"Expected a known rule name in rules list output"
        )

    def test_rules_list_vendor_filter(self):
        runner = CliRunner()
        result = runner.invoke(main, ["rules", "list", "-v", "fortigate"])
        assert result.exit_code == 0, (
            f"Unexpected exit code {result.exit_code}: {result.output}"
        )

    def test_rules_list_severity_filter(self):
        runner = CliRunner()
        result = runner.invoke(main, ["rules", "list", "-s", "critical"])
        assert result.exit_code == 0, (
            f"Unexpected exit code {result.exit_code}: {result.output}"
        )

    def test_rules_list_framework_filter(self):
        runner = CliRunner()
        result = runner.invoke(main, ["rules", "list", "-f", "nist_800-53"])
        assert result.exit_code == 0, (
            f"Unexpected exit code {result.exit_code}: {result.output}"
        )


# ---------------------------------------------------------------------------
# TestBulkCommand
# ---------------------------------------------------------------------------

class TestBulkCommand:
    def test_bulk_directory(self, tmp_path):
        runner = CliRunner()
        fortigate_fixtures = str(FIXTURES / "fortigate")
        result = runner.invoke(main, [
            "bulk", fortigate_fixtures,
            "--output-dir", str(tmp_path),
        ])
        assert result.exit_code in (0, 1, 2), (
            f"Unexpected exit code {result.exit_code}: {result.output}"
        )
        summary = tmp_path / "fleet_summary.html"
        assert summary.exists(), (
            f"fleet_summary.html was not created in {tmp_path}"
        )

    def test_bulk_json_format(self, tmp_path):
        runner = CliRunner()
        fortigate_fixtures = str(FIXTURES / "fortigate")
        result = runner.invoke(main, [
            "bulk", fortigate_fixtures,
            "--output-dir", str(tmp_path),
            "--format", "json",
        ])
        assert result.exit_code in (0, 1, 2), (
            f"Unexpected exit code {result.exit_code}: {result.output}"
        )
        json_files = list(tmp_path.glob("*.json"))
        # fleet_summary.json is always written; individual .json per config file
        assert len(json_files) >= 1, "Expected at least one .json file in output dir"

    def test_bulk_pdf_format(self, tmp_path):
        runner = CliRunner()
        fortigate_fixtures = str(FIXTURES / "fortigate")
        result = runner.invoke(main, [
            "bulk", fortigate_fixtures,
            "--output-dir", str(tmp_path),
            "--format", "pdf",
        ])
        assert result.exit_code in (0, 1, 2), (
            f"Unexpected exit code {result.exit_code}: {result.output}"
        )
        pdf_files = list(tmp_path.glob("*.pdf"))
        assert len(pdf_files) >= 1, "Expected at least one .pdf file in output dir"

    def test_bulk_forced_vendor(self, tmp_path):
        runner = CliRunner()
        fortigate_fixtures = str(FIXTURES / "fortigate")
        result = runner.invoke(main, [
            "bulk", fortigate_fixtures,
            "--output-dir", str(tmp_path),
            "--vendor", "fortigate",
        ])
        assert result.exit_code in (0, 1, 2), (
            f"Unexpected exit code {result.exit_code}: {result.output}"
        )

    def test_bulk_empty_dir(self, tmp_path):
        runner = CliRunner()
        empty_dir = tmp_path / "empty_configs"
        empty_dir.mkdir()
        out_dir = tmp_path / "reports"
        result = runner.invoke(main, [
            "bulk", str(empty_dir),
            "--output-dir", str(out_dir),
        ])
        # Should exit cleanly (0) with no config files found
        assert result.exit_code == 0, (
            f"Expected exit 0 for empty directory, got {result.exit_code}: {result.output}"
        )


# ---------------------------------------------------------------------------
# TestVersionCommand
# ---------------------------------------------------------------------------

class TestVersionCommand:
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0, (
            f"Unexpected exit code {result.exit_code}: {result.output}"
        )
        assert "0.5" in result.output, (
            f"Expected version containing '0.5', got: {result.output}"
        )

"""FireAudit CLI entrypoint.

Usage:
  fireaudit audit --config firewall.conf --vendor fortigate
  fireaudit audit --config fw.conf --vendor fortigate --framework nist_800-53 --output report.html
  fireaudit rules list
  fireaudit parse --config fw.conf --vendor fortigate --output ir.json
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel

from fireaudit import __version__
from fireaudit.parsers import get_parser
from fireaudit.engine.loader import RuleLoader, RuleLoadError
from fireaudit.engine.evaluator import RuleEvaluator, build_report
from fireaudit.output.html_report import render_html
from fireaudit.output.json_report import render_json
from fireaudit.wizard import run_wizard

console = Console()

# Default rules directory — respects FIREAUDIT_RULES_DIR for frozen exe bundles
import os as _os
_DEFAULT_RULES_DIR = Path(
    _os.environ.get("FIREAUDIT_RULES_DIR", str(Path(__file__).parent.parent / "rules"))
)


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(__version__, prog_name="fireaudit")
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging")
def main(debug: bool) -> None:
    """FireAudit — offline firewall configuration auditing tool."""
    level = logging.DEBUG if debug else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


# ---------------------------------------------------------------------------
# wizard command
# ---------------------------------------------------------------------------

@main.command("wizard")
def wizard_cmd() -> None:
    """Interactive wizard — guided audit with no flags required."""
    run_wizard()


# ---------------------------------------------------------------------------
# audit command
# ---------------------------------------------------------------------------

@main.command()
@click.option("--config", "-c", required=True, type=click.Path(exists=True), help="Path to firewall config file")
@click.option("--vendor", "-v", required=True, type=click.Choice(
    ["fortigate", "paloalto", "cisco_asa", "cisco_ftd", "pfsense", "opnsense",
     "sonicwall", "sophos_xg", "watchguard"],
    case_sensitive=False,
), help="Firewall vendor")
@click.option("--rules-dir", "-r", default=None, type=click.Path(), help="Custom rules directory (default: built-in rules/)")
@click.option("--framework", "-f", default=None, help="Filter findings by framework (e.g. nist_800-53, cis, iso27001, cmmc)")
@click.option("--output", "-o", default=None, type=click.Path(), help="Output file path (.json or .html). Prints to stdout if omitted.")
@click.option("--format", "fmt", default="html", type=click.Choice(["json", "html"]), show_default=True, help="Output format")
@click.option("--severity", "-s", default=None, type=click.Choice(["critical", "high", "medium", "low", "info"]), help="Minimum severity filter")
@click.option("--ir-output", default=None, type=click.Path(), help="Also write the parsed IR to this JSON file")
@click.option("--scrub", is_flag=True, default=False, help="Scrub potentially sensitive values from IR and findings output")
def audit(
    config: str,
    vendor: str,
    rules_dir: str | None,
    framework: str | None,
    output: str | None,
    fmt: str,
    severity: str | None,
    ir_output: str | None,
    scrub: bool,
) -> None:
    """Parse a firewall config and audit it against the rule set."""
    config_path = Path(config)
    rules_path = Path(rules_dir) if rules_dir else _DEFAULT_RULES_DIR

    # --- Parse config ---
    with console.status(f"[bold]Parsing {vendor} config…"):
        try:
            parser_cls = get_parser(vendor)
            parser = parser_cls(source_file=config_path)
            ir = parser.parse_file(config_path)
        except Exception as exc:
            console.print(f"[red]Parse error:[/red] {exc}")
            sys.exit(1)

    if scrub:
        ir = _scrub_ir(ir)

    if ir_output:
        Path(ir_output).write_text(json.dumps(ir, indent=2, default=str), encoding="utf-8")
        console.print(f"[dim]IR written to {ir_output}[/dim]")

    # --- Load rules ---
    with console.status("[bold]Loading rules…"):
        try:
            loader = RuleLoader(rules_path)
            rules = loader.load_for_vendor(vendor)
        except RuleLoadError as exc:
            console.print(f"[red]Rule load error:[/red] {exc}")
            sys.exit(1)

    if not rules:
        console.print("[yellow]Warning:[/yellow] No rules loaded. Check rules directory.")
        sys.exit(0)

    # --- Evaluate ---
    with console.status(f"[bold]Evaluating {len(rules)} rules…"):
        evaluator = RuleEvaluator(rules)
        findings = evaluator.evaluate(ir, vendor=vendor)

    # Apply severity filter
    sev_order = ["critical", "high", "medium", "low", "info"]
    if severity:
        cutoff = sev_order.index(severity)
        findings = [f for f in findings if sev_order.index(f.severity) <= cutoff]

    # Build report
    report = build_report(ir, findings, framework_filter=framework)

    # --- Print summary to console ---
    _print_summary(report)

    # --- Output ---
    if output:
        out_path = Path(output)
        actual_fmt = fmt
        if out_path.suffix == ".json":
            actual_fmt = "json"
        elif out_path.suffix in (".html", ".htm"):
            actual_fmt = "html"

        if actual_fmt == "json":
            render_json(report, output_path=out_path)
        else:
            render_html(report, output_path=out_path)
        console.print(f"[green]Report written:[/green] {out_path.resolve()}")
    else:
        if fmt == "json":
            click.echo(render_json(report))
        else:
            click.echo(render_html(report))

    # Exit with non-zero if any critical/high failures
    critical_fails = [f for f in findings if f.status == "fail" and f.severity in ("critical", "high")]
    if critical_fails:
        sys.exit(2)


# ---------------------------------------------------------------------------
# parse command (IR only)
# ---------------------------------------------------------------------------

@main.command("parse")
@click.option("--config", "-c", required=True, type=click.Path(exists=True))
@click.option("--vendor", "-v", required=True, type=click.Choice(
    ["fortigate", "paloalto", "cisco_asa", "cisco_ftd", "pfsense", "opnsense",
     "sonicwall", "sophos_xg", "watchguard"],
    case_sensitive=False,
))
@click.option("--output", "-o", default=None, type=click.Path())
@click.option("--scrub", is_flag=True, default=False)
def parse_cmd(config: str, vendor: str, output: str | None, scrub: bool) -> None:
    """Parse a firewall config and emit the normalized IR as JSON."""
    try:
        parser_cls = get_parser(vendor)
        parser = parser_cls(source_file=config)
        ir = parser.parse_file(config)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)

    if scrub:
        ir = _scrub_ir(ir)

    text = json.dumps(ir, indent=2, default=str)
    if output:
        Path(output).write_text(text, encoding="utf-8")
        console.print(f"[green]IR written to {output}[/green]")
    else:
        click.echo(text)


# ---------------------------------------------------------------------------
# rules commands
# ---------------------------------------------------------------------------

@main.group("rules")
def rules_group() -> None:
    """Manage and inspect audit rules."""


@rules_group.command("list")
@click.option("--rules-dir", default=None, type=click.Path())
@click.option("--vendor", "-v", default=None, help="Filter by vendor")
@click.option("--severity", "-s", default=None)
@click.option("--framework", "-f", default=None)
def rules_list(rules_dir: str | None, vendor: str | None, severity: str | None, framework: str | None) -> None:
    """List all available rules."""
    rules_path = Path(rules_dir) if rules_dir else _DEFAULT_RULES_DIR
    loader = RuleLoader(rules_path)
    try:
        rules = loader.load_all()
    except RuleLoadError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)

    if vendor:
        rules = [r for r in rules if RuleLoader._applies_to_vendor(r, vendor)]
    if severity:
        rules = [r for r in rules if r["severity"] == severity.lower()]
    if framework:
        rules = [r for r in rules if any(framework.lower() in fw.lower() for fw in r.get("frameworks", {}))]

    table = Table(box=box.SIMPLE_HEAD, show_lines=False)
    table.add_column("Rule ID", style="bold cyan", width=18)
    table.add_column("Name", width=45)
    table.add_column("Severity", width=10)
    table.add_column("Vendors", width=20)
    table.add_column("Frameworks", width=30)

    sev_colors = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "green", "info": "blue"}

    for r in sorted(rules, key=lambda x: x["rule_id"]):
        sev = r["severity"]
        color = sev_colors.get(sev, "white")
        vendors_str = ", ".join(r.get("vendors", ["all"]))
        fw_str = ", ".join(r.get("frameworks", {}).keys())
        table.add_row(r["rule_id"], r["name"], f"[{color}]{sev}[/{color}]", vendors_str, fw_str)

    console.print(table)
    console.print(f"[dim]{len(rules)} rules[/dim]")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_summary(report: dict) -> None:
    summary = report["summary"]
    device = report["device"]

    title = f"[bold]FireAudit Results[/bold] — {device['vendor'].upper()} {device.get('hostname') or ''}"
    lines = [
        f"Rules: {summary['total_rules']}  "
        f"[green]Pass: {summary['pass']}[/green]  "
        f"[red]Fail: {summary['fail']}[/red]  "
        f"[dim]Error: {summary.get('error', 0)}[/dim]",
    ]

    by_sev = summary.get("by_severity", {})
    sev_parts = []
    for sev in ["critical", "high", "medium", "low"]:
        data = by_sev.get(sev, {})
        fails = data.get("fail", 0)
        if fails:
            colors = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "green"}
            sev_parts.append(f"[{colors[sev]}]{sev.upper()}: {fails}[/{colors[sev]}]")
    if sev_parts:
        lines.append("Failures: " + "  ".join(sev_parts))

    scores = report.get("compliance_scores", {})
    for fw, data in scores.items():
        score = data["score_percent"]
        color = "green" if score >= 80 else "yellow" if score >= 60 else "red"
        lines.append(f"{fw}: [{color}]{score}%[/{color}] ({data['pass']}/{data['pass']+data['fail']} rules passed)")

    console.print(Panel("\n".join(lines), title=title, border_style="blue"))


_SCRUB_FIELDS = {"community_strings", "banner", "password", "secret", "key", "psk"}
_SCRUB_PATHS = {
    ("logging", "syslog_servers"),
    ("logging", "ntp_servers"),
    ("vpn", "ipsec_tunnels"),
}


def _scrub_ir(ir: dict) -> dict:
    """Redact potentially sensitive values from the IR."""
    import copy
    ir = copy.deepcopy(ir)

    def _redact(obj: object) -> object:
        if isinstance(obj, dict):
            return {k: "[REDACTED]" if k in _SCRUB_FIELDS else _redact(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_redact(i) for i in obj]
        return obj

    # Redact IPs in specific paths
    for syslog in ir.get("logging", {}).get("syslog_servers", []):
        syslog["host"] = "[REDACTED-IP]"
    for ntp_idx in range(len(ir.get("logging", {}).get("ntp_servers", []))):
        ir["logging"]["ntp_servers"][ntp_idx] = "[REDACTED-IP]"
    for tunnel in ir.get("vpn", {}).get("ipsec_tunnels", []):
        if tunnel.get("remote_gateway"):
            tunnel["remote_gateway"] = "[REDACTED-IP]"
    for iface in ir.get("interfaces", []):
        if iface.get("ip_address"):
            iface["ip_address"] = "[REDACTED-IP]"

    # Redact sensitive settings keys
    ir = _redact(ir)
    return ir

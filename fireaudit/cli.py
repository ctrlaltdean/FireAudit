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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn

from fireaudit import __version__
from fireaudit.parsers import get_parser, VENDOR_PARSERS
from fireaudit.parsers.base import detect_vendor
from fireaudit.engine.loader import RuleLoader, RuleLoadError
from fireaudit.engine.evaluator import RuleEvaluator, build_report
from fireaudit.output.html_report import render_html
from fireaudit.output.json_report import render_json
from fireaudit.wizard import run_wizard
from fireaudit.updater import (
    check_for_update,
    fetch_latest_release,
    apply_binary_update,
    apply_rules_update,
    effective_rules_dir,
    current_version,
    USER_RULES_DIR,
)

console = Console()

# Default rules directory resolution order:
#   1. FIREAUDIT_RULES_DIR env var (set by frozen exe shim)
#   2. ~/.fireaudit/rules/ if it exists and has rules (post-update user dir)
#   3. Bundled rules/ directory
import os as _os
_BUNDLED_RULES_DIR = Path(
    _os.environ.get("FIREAUDIT_RULES_DIR", str(Path(__file__).parent.parent / "rules"))
)
_DEFAULT_RULES_DIR = effective_rules_dir(_BUNDLED_RULES_DIR)


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
# update commands
# ---------------------------------------------------------------------------

@main.group("update")
def update_group() -> None:
    """Check for and apply application / rules updates."""


@update_group.command("check")
def update_check() -> None:
    """Check whether a newer version is available."""
    console.print(f"Current version: [bold]{current_version()}[/bold]")
    with console.status("Checking GitHub for updates…"):
        try:
            release = check_for_update()
        except Exception as exc:
            console.print(f"[red]Error:[/red] {exc}")
            sys.exit(1)

    if release:
        console.print(
            f"[green]Update available:[/green] [bold]{release['tag_name']}[/bold]  "
            f"— run [cyan]fireaudit update apply[/cyan] to install"
        )
        console.print(f"[dim]Release notes:[/dim] {release.get('html_url', '')}")
    else:
        console.print("[green]You are on the latest version.[/green]")


@update_group.command("apply")
@click.option("--yes", "-y", is_flag=True, default=False, help="Skip confirmation prompt")
def update_apply(yes: bool) -> None:
    """Download and install the latest application binary."""
    console.print(f"Current version: [bold]{current_version()}[/bold]")

    with console.status("Fetching latest release info…"):
        try:
            release = fetch_latest_release()
        except Exception as exc:
            console.print(f"[red]Error:[/red] {exc}")
            sys.exit(1)

    latest_tag = release["tag_name"]
    from fireaudit.updater import is_newer
    if not is_newer(latest_tag):
        console.print("[green]Already on the latest version.[/green]")
        return

    console.print(f"[bold]{latest_tag}[/bold] is available  (you have {current_version()})")
    if not yes and not click.confirm("Download and install update?", default=True):
        console.print("[yellow]Update cancelled.[/yellow]")
        return

    progress: list[int] = [0]

    def _progress(downloaded: int, total: int) -> None:
        if total and downloaded - progress[0] > 512 * 1024:
            pct = int(downloaded / total * 100)
            console.print(f"  [dim]{pct}%[/dim]", end="\r")
            progress[0] = downloaded

    with console.status(f"Downloading {latest_tag}…"):
        try:
            msg = apply_binary_update(release, progress_cb=_progress)
        except Exception as exc:
            console.print(f"[red]Update failed:[/red] {exc}")
            sys.exit(1)

    console.print(f"[green]{msg}[/green]")


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

    # --- Print summary + findings table to console ---
    _print_summary(report)
    _print_findings_table(report)

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
# bulk command
# ---------------------------------------------------------------------------

_CONFIG_EXTENSIONS = {".conf", ".xml", ".cfg", ".acl", ".txt"}


def _discover_configs(path: Path) -> list[Path]:
    """Return all config files under a directory (recursively) or expand a glob."""
    if path.is_dir():
        return sorted(
            p for p in path.rglob("*")
            if p.is_file() and p.suffix.lower() in _CONFIG_EXTENSIONS
        )
    # Treat as glob pattern
    import glob as _glob
    return sorted(Path(p) for p in _glob.glob(str(path), recursive=True) if Path(p).is_file())


def _audit_one(
    config_path: Path,
    vendor: str | None,
    rules_path: Path,
) -> dict:
    """Parse and audit a single config file. Returns a result dict."""
    result: dict = {
        "filename": config_path.name,
        "path": str(config_path),
        "vendor": None,
        "hostname": None,
        "posture_score": None,
        "grade": None,
        "fail_counts": {},
        "report": None,
        "error": None,
        "report_file": None,
    }

    try:
        content = config_path.read_text(encoding="utf-8", errors="replace")

        # Vendor detection
        detected = vendor or detect_vendor(content)
        if not detected:
            result["error"] = "vendor unknown — use --vendor to force"
            return result
        result["vendor"] = detected

        parser_cls = get_parser(detected)
        parser = parser_cls(source_file=config_path)
        ir = parser.parse(content)
        result["hostname"] = ir.get("meta", {}).get("hostname")

        loader = RuleLoader(rules_path)
        rules = loader.load_for_vendor(detected)
        evaluator = RuleEvaluator(rules)
        findings = evaluator.evaluate(ir, vendor=detected)
        report = build_report(ir, findings)

        result["posture_score"] = report["posture_score"]["score"]
        result["grade"] = report["posture_score"]["grade"]
        result["fail_counts"] = report["posture_score"]["fail_counts"]
        result["report"] = report
    except Exception as exc:
        result["error"] = str(exc)

    return result


@main.command("bulk")
@click.argument("path", type=click.Path())
@click.option("--output-dir", "-o", default="fireaudit-reports", show_default=True, type=click.Path(), help="Directory to write reports into")
@click.option("--format", "fmt", default="html", type=click.Choice(["html", "json", "both"]), show_default=True, help="Report format per device")
@click.option("--vendor", "-v", default=None, type=click.Choice(list(VENDOR_PARSERS), case_sensitive=False), help="Force vendor for all files (skips auto-detect)")
@click.option("--rules-dir", "-r", default=None, type=click.Path(), help="Custom rules directory")
@click.option("--workers", default=4, show_default=True, type=int, help="Parallel worker threads")
def bulk(path: str, output_dir: str, fmt: str, vendor: str | None, rules_dir: str | None, workers: int) -> None:
    """Audit all firewall configs in a directory or matching a glob pattern.

    \b
    Examples:
      fireaudit bulk ./configs/
      fireaudit bulk ./configs/*.conf --vendor fortigate --format both
      fireaudit bulk ./configs/ --output-dir ./reports/ --workers 8
    """
    target = Path(path)
    out_dir = Path(output_dir)
    rules_path = Path(rules_dir) if rules_dir else _DEFAULT_RULES_DIR

    configs = _discover_configs(target)
    if not configs:
        console.print(f"[yellow]No config files found in:[/yellow] {target}")
        return

    out_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"Found [bold]{len(configs)}[/bold] config file(s)  →  reports: [cyan]{out_dir.resolve()}[/cyan]")

    results: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Auditing…", total=len(configs))

        def _process(cfg: Path) -> dict:
            res = _audit_one(cfg, vendor, rules_path)
            if res["report"] and not res["error"]:
                stem = cfg.stem
                if fmt in ("html", "both"):
                    out_path = out_dir / f"{stem}.html"
                    render_html(res["report"], output_path=out_path)
                    res["report_file"] = str(out_path.name)
                if fmt in ("json", "both"):
                    out_path = out_dir / f"{stem}.json"
                    render_json(res["report"], output_path=out_path)
                    if fmt == "json":
                        res["report_file"] = str(out_path.name)
            return res

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_process, cfg): cfg for cfg in configs}
            for future in as_completed(futures):
                res = future.result()
                results.append(res)
                progress.advance(task)

    # Sort worst score first (errors/unknowns at bottom)
    results.sort(key=lambda r: (r["posture_score"] is None, r["posture_score"] or 0))

    # Print fleet table
    grade_colors = {"A": "green", "B": "bright_green", "C": "yellow", "D": "orange1", "F": "red"}
    tbl = Table(box=box.SIMPLE_HEAD, show_lines=False, padding=(0, 1))
    tbl.add_column("File", width=30)
    tbl.add_column("Vendor", width=12)
    tbl.add_column("Hostname", width=20)
    tbl.add_column("Score", width=8, justify="right")
    tbl.add_column("Grade", width=6, justify="center")
    tbl.add_column("Crit", width=5, justify="right")
    tbl.add_column("High", width=5, justify="right")
    tbl.add_column("Med", width=5, justify="right")
    tbl.add_column("Low", width=5, justify="right")
    tbl.add_column("Status", width=20)

    for r in results:
        if r["error"]:
            tbl.add_row(r["filename"], r["vendor"] or "?", "—", "—", "—", "—", "—", "—", "—",
                        f"[red]{r['error'][:20]}[/red]")
            continue
        gc = grade_colors.get(r["grade"], "white")
        fc = r["fail_counts"]
        tbl.add_row(
            r["filename"],
            r["vendor"] or "?",
            r["hostname"] or "—",
            f"[{gc}]{r['posture_score']}[/{gc}]",
            f"[{gc}]{r['grade']}[/{gc}]",
            f"[red]{fc.get('critical', 0)}[/red]" if fc.get("critical") else "0",
            f"[orange1]{fc.get('high', 0)}[/orange1]" if fc.get("high") else "0",
            f"[yellow]{fc.get('medium', 0)}[/yellow]" if fc.get("medium") else "0",
            str(fc.get("low", 0)),
            f"[dim]{r['report_file'] or ''}[/dim]",
        )

    console.print(tbl)

    # Fleet summary score
    scored = [r for r in results if r["posture_score"] is not None]
    errors = [r for r in results if r["error"]]
    if scored:
        fleet_score = round(sum(r["posture_score"] for r in scored) / len(scored))
        from fireaudit.engine.scoring import grade_for_score
        fleet_grade = grade_for_score(fleet_score)
        gc = grade_colors.get(fleet_grade, "white")
        console.print(Panel(
            f"Fleet Posture Score: [{gc}][bold]{fleet_score}/100  Grade: {fleet_grade}[/bold][/{gc}]"
            f"  |  {len(scored)} audited  {len(errors)} error(s)",
            border_style="blue",
        ))

    # Write fleet_summary.json
    fleet_json = {
        "generated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "total_devices": len(results),
        "fleet_posture_score": round(sum(r["posture_score"] for r in scored) / len(scored)) if scored else None,
        "fleet_grade": grade_for_score(round(sum(r["posture_score"] for r in scored) / len(scored))) if scored else None,
        "devices": [
            {
                "filename": r["filename"],
                "vendor": r["vendor"],
                "hostname": r["hostname"],
                "posture_score": r["posture_score"],
                "grade": r["grade"],
                "fail_counts": r["fail_counts"],
                "report_file": r["report_file"],
                "error": r["error"],
            }
            for r in results
        ],
    }
    summary_json_path = out_dir / "fleet_summary.json"
    summary_json_path.write_text(json.dumps(fleet_json, indent=2, default=str), encoding="utf-8")

    # Write fleet_summary.html
    _write_fleet_html(results, fleet_json, out_dir / "fleet_summary.html")
    console.print(f"[green]Fleet summary:[/green] {(out_dir / 'fleet_summary.html').resolve()}")

    if errors:
        sys.exit(1)
    if any(r["posture_score"] is not None and r["posture_score"] < 60 for r in results):
        sys.exit(2)


def _write_fleet_html(results: list[dict], fleet_json: dict, out_path: Path) -> None:
    """Write the fleet summary HTML report."""
    from jinja2 import Environment, BaseLoader
    grade_color_map = {"A": "#16a34a", "B": "#65a30d", "C": "#d97706", "D": "#ea580c", "F": "#dc2626"}

    FLEET_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FireAudit Fleet Summary</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; background: #f8fafc; color: #1e293b; }
  header { background: #1e293b; color: white; padding: 2rem; }
  header h1 { font-size: 1.75rem; font-weight: 700; }
  header p { margin-top: .5rem; opacity: .7; font-size: .9rem; }
  .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
  .fleet-banner { background: white; border-radius: 8px; padding: 1.5rem 2rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); margin-bottom: 1.5rem; display: flex; align-items: center; gap: 2rem; }
  .fleet-grade { font-size: 4rem; font-weight: 800; line-height: 1; min-width: 80px; text-align: center; }
  .fleet-bar-wrap { height: 12px; background: #e2e8f0; border-radius: 6px; overflow: hidden; margin: .5rem 0; flex: 1; }
  .fleet-bar { height: 100%; border-radius: 6px; }
  table { width: 100%; border-collapse: collapse; font-size: .875rem; background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.1); overflow: hidden; }
  th { background: #f1f5f9; padding: .6rem 1rem; text-align: left; font-weight: 600; font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; color: #64748b; }
  td { padding: .75rem 1rem; border-bottom: 1px solid #e2e8f0; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #f8fafc; }
  .badge { display: inline-block; padding: .15rem .6rem; border-radius: 9999px; font-size: .8rem; font-weight: 700; }
  footer { text-align: center; padding: 2rem; font-size: .8rem; color: #94a3b8; }
</style>
</head>
<body>
<header>
  <h1>FireAudit — Fleet Summary</h1>
  <p>Generated {{ fleet.generated_at }} &nbsp;|&nbsp; {{ fleet.total_devices }} device(s) audited</p>
</header>
<div class="container">
  {% set fs = fleet.fleet_posture_score %}
  {% set fg = fleet.fleet_grade %}
  {% set gc = grade_color_map.get(fg, "#64748b") %}
  <div class="fleet-banner">
    <div class="fleet-grade" style="color:{{ gc }};">{{ fg or "—" }}</div>
    <div style="flex:1;">
      <div style="font-size:1rem;font-weight:600;margin-bottom:.5rem;">Fleet Posture Score</div>
      <div class="fleet-bar-wrap">
        <div class="fleet-bar" style="width:{{ fs or 0 }}%;background:{{ gc }};"></div>
      </div>
      <span style="font-size:1.75rem;font-weight:700;">{{ fs or "—" }}</span>
      <span style="font-size:.9rem;color:#64748b;">/100</span>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>File</th><th>Vendor</th><th>Hostname</th>
        <th>Score</th><th>Grade</th>
        <th>Critical</th><th>High</th><th>Medium</th><th>Low</th>
        <th>Report</th>
      </tr>
    </thead>
    <tbody>
    {% for d in fleet.devices %}
    {% set gc2 = grade_color_map.get(d.grade, "#64748b") %}
    <tr>
      <td>{{ d.filename }}</td>
      <td>{{ d.vendor or "?" }}</td>
      <td>{{ d.hostname or "—" }}</td>
      <td><strong style="color:{{ gc2 }};">{{ d.posture_score if d.posture_score is not none else "—" }}</strong></td>
      <td><span class="badge" style="background:{{ gc2 }}1a;color:{{ gc2 }};">{{ d.grade or "?" }}</span></td>
      <td style="color:#dc2626;font-weight:{% if d.fail_counts.get('critical',0) %}600{% else %}400{% endif %};">{{ d.fail_counts.get("critical", 0) }}</td>
      <td style="color:#ea580c;">{{ d.fail_counts.get("high", 0) }}</td>
      <td style="color:#d97706;">{{ d.fail_counts.get("medium", 0) }}</td>
      <td>{{ d.fail_counts.get("low", 0) }}</td>
      <td>{% if d.report_file %}<a href="{{ d.report_file }}">{{ d.report_file }}</a>{% elif d.error %}<span style="color:#dc2626;font-size:.8rem;">{{ d.error[:40] }}</span>{% else %}—{% endif %}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
<footer>FireAudit — fireaudit.local</footer>
</body>
</html>"""

    env = Environment(loader=BaseLoader())
    tmpl = env.from_string(FLEET_TEMPLATE)
    html = tmpl.render(fleet=fleet_json, grade_color_map=grade_color_map)
    out_path.write_text(html, encoding="utf-8")


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

    if USER_RULES_DIR.exists() and any(USER_RULES_DIR.rglob("*.yaml")):
        console.print(f"[dim]Source: {USER_RULES_DIR} (user-updated)[/dim]")
    else:
        console.print(f"[dim]Source: {_DEFAULT_RULES_DIR} (bundled)[/dim]")


@rules_group.command("update")
@click.option("--yes", "-y", is_flag=True, default=False, help="Skip confirmation prompt")
@click.option("--tag", default=None, help="Specific release tag to pull rules from (default: latest)")
def rules_update(yes: bool, tag: str | None) -> None:
    """Download the latest rules from GitHub and install to ~/.fireaudit/rules/."""
    with console.status("Fetching release info…"):
        try:
            if tag:
                from fireaudit.updater import _github_get, GITHUB_API_RELEASE
                release = _github_get(GITHUB_API_RELEASE.format(tag=tag))
            else:
                release = fetch_latest_release()
        except Exception as exc:
            console.print(f"[red]Error:[/red] {exc}")
            sys.exit(1)

    console.print(
        f"Rules from [bold]{release['tag_name']}[/bold]  →  "
        f"[cyan]{USER_RULES_DIR}[/cyan]"
    )
    if not yes and not click.confirm("Download and install rules?", default=True):
        console.print("[yellow]Cancelled.[/yellow]")
        return

    with console.status("Downloading rules.zip…"):
        try:
            msg = apply_rules_update(release)
        except Exception as exc:
            console.print(f"[red]Rules update failed:[/red] {exc}")
            sys.exit(1)

    console.print(f"[green]{msg}[/green]")


@rules_group.command("reset")
@click.option("--yes", "-y", is_flag=True, default=False, help="Skip confirmation prompt")
def rules_reset(yes: bool) -> None:
    """Remove user-installed rules and revert to bundled rules."""
    if not USER_RULES_DIR.exists():
        console.print("[dim]No user rules directory found — already using bundled rules.[/dim]")
        return

    console.print(f"This will delete [cyan]{USER_RULES_DIR}[/cyan] and revert to bundled rules.")
    if not yes and not click.confirm("Proceed?", default=False):
        console.print("[yellow]Cancelled.[/yellow]")
        return

    import shutil
    shutil.rmtree(USER_RULES_DIR)
    console.print("[green]User rules removed. Bundled rules are now active.[/green]")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_findings_table(report: dict) -> None:
    """Print a Rich table of all findings to the console."""
    findings = report.get("findings", [])
    if not findings:
        return

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sev_colors = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "green", "info": "blue"}
    status_order = {"fail": 0, "error": 1, "manual_check": 2, "pass": 3, "not_applicable": 4}

    sorted_findings = sorted(
        findings,
        key=lambda f: (status_order.get(f["status"], 9), sev_order.get(f["severity"], 9)),
    )

    table = Table(box=box.SIMPLE_HEAD, show_lines=False, padding=(0, 1))
    table.add_column("Rule ID", style="bold cyan", width=14, no_wrap=True)
    table.add_column("Name", width=40)
    table.add_column("Sev", width=9, no_wrap=True)
    table.add_column("Status", width=12, no_wrap=True)
    table.add_column("Detail", width=45)

    for f in sorted_findings:
        status = f["status"]
        severity = f["severity"]
        sev_color = sev_colors.get(severity, "white")

        if status == "pass":
            status_markup = "[green]✓ pass[/green]"
        elif status == "fail":
            status_markup = "[red]✗ fail[/red]"
        elif status == "manual_check":
            mr = f.get("manual_result", "")
            if mr == "confirmed_ok":
                status_markup = "[green]✓ confirmed[/green]"
            elif mr == "needs_attention":
                status_markup = "[red]✗ attention[/red]"
            else:
                status_markup = "[yellow]⚠ manual[/yellow]"
        elif status == "error":
            status_markup = "[magenta]! error[/magenta]"
        else:
            status_markup = f"[dim]{status}[/dim]"

        detail = f.get("details", "") or ""
        if not detail and status == "fail":
            detail = (f.get("remediation") or "")[:80]
        if len(detail) > 80:
            detail = detail[:77] + "…"

        table.add_row(
            f["rule_id"],
            f["name"],
            f"[{sev_color}]{severity}[/{sev_color}]",
            status_markup,
            f"[dim]{detail}[/dim]" if detail else "",
        )

    console.print(table)


def _posture_bar(score: int, width: int = 30) -> str:
    """Return a Rich markup progress-bar string for the posture score."""
    filled = round(score / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    if score >= 90:
        color = "green"
    elif score >= 75:
        color = "bright_green"
    elif score >= 60:
        color = "yellow"
    elif score >= 40:
        color = "orange1"
    else:
        color = "red"
    return f"[{color}]{bar}[/{color}]"


def _print_summary(report: dict) -> None:
    summary = report["summary"]
    device = report["device"]
    posture = report.get("posture_score", {})

    title = f"[bold]FireAudit Results[/bold] — {device['vendor'].upper()} {device.get('hostname') or ''}"
    lines = []

    # Posture score line
    if posture:
        score = posture["score"]
        grade = posture["grade"]
        grade_colors = {"A": "green", "B": "bright_green", "C": "yellow", "D": "orange1", "F": "red"}
        gc = grade_colors.get(grade, "white")
        bar = _posture_bar(score)
        lines.append(
            f"Posture Score: [{gc}][bold]{score}/100[/bold]  Grade: {grade}[/{gc}]  {bar}"
        )

    lines.append(
        f"Rules: {summary['total_rules']}  "
        f"[green]Pass: {summary['pass']}[/green]  "
        f"[red]Fail: {summary['fail']}[/red]  "
        f"[dim]N/A: {summary.get('not_applicable', 0)}  Error: {summary.get('error', 0)}[/dim]"
    )

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

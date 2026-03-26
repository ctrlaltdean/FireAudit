"""Interactive wizard for FireAudit.

Guides the user through: vendor → config file → framework → output → run.
Falls back to simple click prompts if questionary is not installed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

_VENDOR_LABELS = {
    "fortigate":  "FortiGate       (.conf backup)",
    "paloalto":   "Palo Alto       (XML running config)",
    "cisco_asa":  "Cisco ASA       (show run output)",
    "cisco_ftd":  "Cisco FTD       (show run output)",
    "pfsense":    "pfSense         (config.xml)",
    "opnsense":   "OPNsense        (config.xml)",
    "sonicwall":  "SonicWall       (XML settings export)",
    "sophos_xg":  "Sophos XG/SFOS  (XML backup)",
    "watchguard": "WatchGuard      (XML policy backup)",
}

_FRAMEWORK_LABELS = {
    "all":         "All frameworks (no filter)",
    "cis":         "CIS Benchmarks",
    "nist_800-53": "NIST SP 800-53",
    "iso27001":    "ISO 27001:2022",
    "cmmc":        "CMMC 2.0 / DFARS",
}

_SEVERITY_LABELS = {
    "all":      "All severities",
    "critical": "Critical only",
    "high":     "High and above",
    "medium":   "Medium and above",
    "low":      "Low and above",
}


def _try_questionary() -> bool:
    """Return True if questionary is importable AND a real TTY is available."""
    try:
        import questionary  # noqa: F401
    except ImportError:
        return False
    # questionary requires a real Windows console (not xterm/Cygwin)
    import sys
    if not sys.stdout.isatty():
        return False
    try:
        from prompt_toolkit.output import create_output
        create_output()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# questionary-based wizard (rich arrow-key UX)
# ---------------------------------------------------------------------------

def _wizard_questionary() -> dict:
    import questionary
    from questionary import Style

    custom_style = Style([
        ("qmark",        "fg:#00bfff bold"),
        ("question",     "fg:#ffffff bold"),
        ("answer",       "fg:#00ff7f bold"),
        ("pointer",      "fg:#00bfff bold"),
        ("highlighted",  "fg:#00bfff bold"),
        ("selected",     "fg:#00ff7f"),
        ("separator",    "fg:#555555"),
        ("instruction",  "fg:#888888"),
    ])

    console.print()
    console.print(Panel(
        Text.from_markup(
            "[bold cyan]FireAudit[/bold cyan] — Interactive Wizard\n"
            "[dim]Use arrow keys to navigate, Enter to select[/dim]"
        ),
        border_style="cyan",
        padding=(0, 2),
    ))
    console.print()

    # 1. Vendor
    vendor_choices = [
        questionary.Choice(title=label, value=key)
        for key, label in _VENDOR_LABELS.items()
    ]
    vendor = questionary.select(
        "Which firewall vendor?",
        choices=vendor_choices,
        style=custom_style,
    ).ask()
    if vendor is None:
        console.print("[yellow]Cancelled.[/yellow]")
        sys.exit(0)

    # 2. Config file
    while True:
        config_path_str = questionary.path(
            "Path to firewall config file:",
            style=custom_style,
            only_directories=False,
        ).ask()
        if config_path_str is None:
            console.print("[yellow]Cancelled.[/yellow]")
            sys.exit(0)
        config_path = Path(config_path_str.strip())
        if config_path.exists():
            break
        console.print(f"[red]File not found:[/red] {config_path}")

    # 3. Compliance framework
    framework_choices = [
        questionary.Choice(title=label, value=key)
        for key, label in _FRAMEWORK_LABELS.items()
    ]
    framework_key = questionary.select(
        "Filter by compliance framework?",
        choices=framework_choices,
        style=custom_style,
    ).ask()
    if framework_key is None:
        sys.exit(0)
    framework = None if framework_key == "all" else framework_key

    # 4. Minimum severity
    sev_choices = [
        questionary.Choice(title=label, value=key)
        for key, label in _SEVERITY_LABELS.items()
    ]
    sev_key = questionary.select(
        "Minimum severity to report?",
        choices=sev_choices,
        default="all",
        style=custom_style,
    ).ask()
    if sev_key is None:
        sys.exit(0)
    severity = None if sev_key == "all" else sev_key

    # 5. Output format
    fmt = questionary.select(
        "Output format?",
        choices=[
            questionary.Choice("HTML report  (opens in browser)", value="html"),
            questionary.Choice("JSON         (machine-readable)", value="json"),
        ],
        style=custom_style,
    ).ask()
    if fmt is None:
        sys.exit(0)

    # 6. Output path
    default_stem = config_path.stem
    default_out = str(Path.cwd() / f"{default_stem}_fireaudit.{fmt}")
    out_str = questionary.text(
        "Save report to:",
        default=default_out,
        style=custom_style,
    ).ask()
    if out_str is None:
        sys.exit(0)
    output = out_str.strip() if out_str.strip() else default_out

    # 7. Scrub sensitive data
    scrub = questionary.confirm(
        "Scrub IP addresses and credentials from output?",
        default=False,
        style=custom_style,
    ).ask()
    if scrub is None:
        sys.exit(0)

    # 8. Manual check walkthrough
    do_manual_checks = questionary.confirm(
        "Walk through manual verification checks interactively after the automated audit?",
        default=True,
        style=custom_style,
    ).ask()
    if do_manual_checks is None:
        sys.exit(0)

    return {
        "vendor": vendor,
        "config": str(config_path),
        "framework": framework,
        "severity": severity,
        "fmt": fmt,
        "output": output,
        "scrub": scrub,
        "do_manual_checks": do_manual_checks,
    }


# ---------------------------------------------------------------------------
# Fallback: click-based prompts (works without questionary)
# ---------------------------------------------------------------------------

def _wizard_click() -> dict:
    import click

    console.print()
    console.print(Panel(
        Text.from_markup(
            "[bold cyan]FireAudit[/bold cyan] — Interactive Wizard\n"
            "[dim]Answer the prompts below to configure your audit[/dim]"
        ),
        border_style="cyan",
        padding=(0, 2),
    ))
    console.print()

    # 1. Vendor
    console.print("[bold]Available vendors:[/bold]")
    vendor_keys = list(_VENDOR_LABELS.keys())
    for i, (k, label) in enumerate(_VENDOR_LABELS.items(), 1):
        console.print(f"  [cyan]{i:2}[/cyan]  {label}")
    console.print()
    while True:
        raw = click.prompt("Select vendor number")
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(vendor_keys):
                vendor = vendor_keys[idx]
                break
        except (ValueError, IndexError):
            pass
        console.print("[red]Invalid selection, try again.[/red]")

    # 2. Config file
    while True:
        config_str = click.prompt("Path to firewall config file")
        config_path = Path(config_str.strip())
        if config_path.exists():
            break
        console.print(f"[red]File not found:[/red] {config_path}")

    # 3. Framework
    console.print("\n[bold]Compliance frameworks:[/bold]")
    fw_keys = list(_FRAMEWORK_LABELS.keys())
    for i, (k, label) in enumerate(_FRAMEWORK_LABELS.items(), 1):
        console.print(f"  [cyan]{i}[/cyan]  {label}")
    while True:
        raw = click.prompt("Select framework number", default="1")
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(fw_keys):
                framework_key = fw_keys[idx]
                break
        except (ValueError, IndexError):
            pass
        console.print("[red]Invalid selection.[/red]")
    framework = None if framework_key == "all" else framework_key

    # 4. Severity
    console.print("\n[bold]Minimum severity:[/bold]")
    sev_keys = list(_SEVERITY_LABELS.keys())
    for i, (k, label) in enumerate(_SEVERITY_LABELS.items(), 1):
        console.print(f"  [cyan]{i}[/cyan]  {label}")
    while True:
        raw = click.prompt("Select severity number", default="1")
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(sev_keys):
                sev_key = sev_keys[idx]
                break
        except (ValueError, IndexError):
            pass
        console.print("[red]Invalid selection.[/red]")
    severity = None if sev_key == "all" else sev_key

    # 5. Output format
    fmt = click.prompt("Output format [html/json]", default="html").lower().strip()
    if fmt not in ("html", "json"):
        fmt = "html"

    # 6. Output path
    default_out = str(Path.cwd() / f"{config_path.stem}_fireaudit.{fmt}")
    output = click.prompt("Save report to", default=default_out).strip()

    # 7. Scrub
    scrub = click.confirm("Scrub IP addresses and credentials from output?", default=False)

    # 8. Manual check walkthrough
    do_manual_checks = click.confirm(
        "Walk through manual verification checks interactively after the automated audit?",
        default=True,
    )

    return {
        "vendor": vendor,
        "config": str(config_path),
        "framework": framework,
        "severity": severity,
        "fmt": fmt,
        "output": output,
        "scrub": scrub,
        "do_manual_checks": do_manual_checks,
    }


# ---------------------------------------------------------------------------
# Run the audit with gathered settings
# ---------------------------------------------------------------------------

def _run_manual_walkthrough(findings: list) -> None:
    """Interactively walk the user through each manual check finding."""
    import click

    manual = [f for f in findings if f.status == "manual_check"]
    if not manual:
        return

    console.print()
    console.rule("[bold yellow]Manual Verification Checks[/bold yellow]")
    console.print(
        f"[dim]{len(manual)} checks require human review. "
        "Answer Y if confirmed OK, N if it needs attention, or press Enter to skip.[/dim]"
    )
    console.print()

    for idx, f in enumerate(manual, 1):
        console.print(f"[bold cyan][{idx}/{len(manual)}][/bold cyan]  [bold]{f.rule_id}[/bold]: {f.name}")
        if f.details:
            console.print(f"  [dim]{f.details}[/dim]")
        if f.remediation:
            console.print(f"  [italic dim]Guidance: {f.remediation[:200]}[/italic dim]")

        try:
            raw = click.prompt(
                "  Confirmed OK?",
                default="skip",
                show_default=True,
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[yellow]Manual check walkthrough cancelled.[/yellow]")
            return

        if raw in ("y", "yes"):
            f.manual_result = "confirmed_ok"
            console.print("  [green]✓ Marked as confirmed OK[/green]")
        elif raw in ("n", "no"):
            f.manual_result = "needs_attention"
            console.print("  [red]✗ Marked as needs attention[/red]")
        else:
            console.print("  [dim]Skipped[/dim]")
        console.print()


def _run_audit(settings: dict) -> None:
    from fireaudit.parsers import get_parser
    from fireaudit.engine.loader import RuleLoader, RuleLoadError
    from fireaudit.engine.evaluator import RuleEvaluator, build_report
    from fireaudit.output.html_report import render_html
    from fireaudit.output.json_report import render_json
    from fireaudit.cli import _print_summary, _print_findings_table, _scrub_ir

    config_path = Path(settings["config"])
    vendor = settings["vendor"]
    framework = settings["framework"]
    severity = settings["severity"]
    fmt = settings["fmt"]
    output = settings["output"]
    scrub = settings["scrub"]
    do_manual_checks = settings.get("do_manual_checks", False)

    rules_path = Path(__file__).parent.parent / "rules"

    console.print()
    console.rule("[bold cyan]Running Audit[/bold cyan]")
    console.print()

    # Parse
    with console.status(f"[bold]Parsing {_VENDOR_LABELS[vendor].split()[0]} config…"):
        try:
            parser_cls = get_parser(vendor)
            parser = parser_cls(source_file=config_path)
            ir = parser.parse_file(config_path)
        except Exception as exc:
            console.print(f"[red]Parse error:[/red] {exc}")
            sys.exit(1)

    if scrub:
        ir = _scrub_ir(ir)

    # Load rules
    with console.status("[bold]Loading rules…"):
        try:
            loader = RuleLoader(rules_path)
            rules = loader.load_for_vendor(vendor)
        except RuleLoadError as exc:
            console.print(f"[red]Rule load error:[/red] {exc}")
            sys.exit(1)

    if not rules:
        console.print("[yellow]Warning:[/yellow] No rules loaded.")
        sys.exit(0)

    # Evaluate
    with console.status(f"[bold]Evaluating {len(rules)} rules…"):
        evaluator = RuleEvaluator(rules)
        findings = evaluator.evaluate(ir, vendor=vendor)

    # Severity filter
    sev_order = ["critical", "high", "medium", "low", "info"]
    if severity:
        cutoff = sev_order.index(severity)
        findings = [f for f in findings if sev_order.index(f.severity) <= cutoff]

    # Optional manual check walkthrough (updates findings in place before report)
    if do_manual_checks:
        _run_manual_walkthrough(findings)

    report = build_report(ir, findings, framework_filter=framework)
    _print_summary(report)
    _print_findings_table(report)

    # Write output
    out_path = Path(output)
    if fmt == "json":
        render_json(report, output_path=out_path)
    else:
        render_html(report, output_path=out_path)
    console.print(f"\n[green]Report written:[/green] {out_path.resolve()}")

    # Offer to open HTML report
    if fmt == "html":
        try:
            import click
            if click.confirm("\nOpen report in browser?", default=True):
                import webbrowser
                webbrowser.open(out_path.resolve().as_uri())
        except Exception:
            pass

    critical_fails = [f for f in findings if f.status == "fail" and f.severity in ("critical", "high")]
    if critical_fails:
        sys.exit(2)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_wizard() -> None:
    """Launch the interactive wizard and run the audit."""
    if _try_questionary():
        settings = _wizard_questionary()
    else:
        settings = _wizard_click()

    # Confirmation summary
    console.print()
    console.print(Panel(
        "\n".join([
            f"  [bold]Vendor:[/bold]          {_VENDOR_LABELS[settings['vendor']]}",
            f"  [bold]Config:[/bold]          {settings['config']}",
            f"  [bold]Framework:[/bold]       {_FRAMEWORK_LABELS.get(settings['framework'] or 'all', settings['framework'])}",
            f"  [bold]Severity:[/bold]        {_SEVERITY_LABELS.get(settings['severity'] or 'all', settings['severity'])}",
            f"  [bold]Output:[/bold]          {settings['output']} ({settings['fmt'].upper()})",
            f"  [bold]Scrub:[/bold]           {'Yes' if settings['scrub'] else 'No'}",
            f"  [bold]Manual checks:[/bold]   {'Walk through interactively' if settings.get('do_manual_checks') else 'Skip (included as unreviewed)'}",
        ]),
        title="[bold]Audit Configuration[/bold]",
        border_style="green",
        padding=(0, 1),
    ))
    console.print()

    import click
    if not click.confirm("Proceed with audit?", default=True):
        console.print("[yellow]Cancelled.[/yellow]")
        sys.exit(0)

    _run_audit(settings)

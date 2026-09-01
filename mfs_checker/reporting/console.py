"""
Rich Terminal Console Reporter for Bangladesh Bank Compliance Audits.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from mfs_checker.models import ComplianceScorecard, RuleStatus, Severity, ComplianceTier

console = Console()

def render_console_report(scorecard: ComplianceScorecard):
    """Render high-impact audit scorecard in terminal."""
    # 1. Header Panel
    tier_color = "green" if scorecard.tier == ComplianceTier.TIER_1_COMPLIANT else ("yellow" if scorecard.tier == ComplianceTier.TIER_2_CONDITIONAL else "red")

    header_text = Text()
    header_text.append("BANGLADESH BANK CYBERSECURITY FRAMEWORK (v1.0, FEB 2025)\n", style="bold cyan")
    header_text.append(f"MFS Application Audit: {scorecard.app_name} ({scorecard.package_name})\n", style="bold white")
    header_text.append(f"Version: {scorecard.version_name} (Code: {scorecard.version_code}) | Size: {scorecard.apk_size_mb:.2f} MB\n")
    header_text.append(f"SHA-256: {scorecard.sha256_hash}\n\n", style="dim")
    header_text.append(f"Cybersecurity Maturity Score: {scorecard.maturity_score:.1f} / 100.0\n", style=f"bold {tier_color}")
    header_text.append(f"Regulatory Status: {scorecard.tier.value}", style=f"bold {tier_color}")

    console.print(Panel(header_text, title="[bold]Automated Compliance Scorecard[/bold]", border_style=tier_color))

    # 2. Rule Findings Table
    table = Table(title="Bangladesh Bank Regulatory Clause Audit Matrix", show_header=True, header_style="bold magenta")
    table.add_column("Rule ID", style="dim", width=12)
    table.add_column("BB Clause", width=14)
    table.add_column("Title & Function", width=34)
    table.add_column("Status", width=10)
    table.add_column("Severity", width=10)
    table.add_column("Penalty", width=8, justify="right")
    table.add_column("Key Finding", width=36)

    for r in scorecard.rule_results:
        if r.status == RuleStatus.PASSED:
            status_text = Text("PASSED", style="bold green")
        elif r.status == RuleStatus.FAILED:
            status_text = Text("FAILED", style="bold red")
        elif r.status == RuleStatus.WARNING:
            status_text = Text("WARN", style="bold yellow")
        else:
            status_text = Text("N/A", style="dim")

        sev_color = "red" if r.severity == Severity.CRITICAL else ("bright_red" if r.severity == Severity.HIGH else "yellow")
        finding_desc = r.findings[0].description if r.findings else r.details

        table.add_row(
            r.rule_id,
            r.clause,
            f"{r.title}\n[dim]({r.function})[/dim]",
            status_text,
            Text(r.severity.value, style=sev_color),
            f"-{r.penalty}" if r.penalty > 0 else "0",
            finding_desc[:80] + ("..." if len(finding_desc) > 80 else "")
        )

    console.print(table)

    # 3. Summary Footer
    summary_text = (
        f"Audit Summary: {scorecard.total_rules} Rules Evaluated | "
        f"[green]{scorecard.passed_rules} Passed[/green] | "
        f"[red]{scorecard.failed_rules} Failed ({scorecard.critical_violations} Critical)[/red] | "
        f"[yellow]{scorecard.warning_rules} Warnings[/yellow] | "
        f"Elapsed: {scorecard.execution_time_seconds:.2f}s"
    )
    console.print(Panel(summary_text, style="cyan"))

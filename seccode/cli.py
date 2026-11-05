"""Command Line Interface for SecCode Mobile."""

import os
import sys
import click
from seccode.orchestrator import SecCodeOrchestrator
from seccode.config import default_config


@click.command()
@click.option("--repo", "-r", required=True, type=click.Path(exists=True), help="Target repository directory to audit")
@click.option("--scope", "-s", default="M1,M5,M9", help="Comma-separated OWASP categories (e.g. M1,M5,M9)")
@click.option("--output-json", "-j", default=None, help="Path to write JSON audit report")
@click.option("--output-md", "-m", default=None, help="Path to write Markdown report")
@click.option("--use-llm", is_flag=True, default=False, help="Enable live LLM reasoning calls")
def main(repo: str, scope: str, output_json: str, output_md: str, use_llm: bool):
    """SecCode Mobile: Multi-Agent Audit and Remediation Engine for OWASP Mobile Top 10."""
    click.echo(click.style(f"[*] Initializing SecCode Mobile Multi-Agent Engine...", fg="cyan", bold=True))
    click.echo(f"[*] Target Repository: {os.path.abspath(repo)}")
    categories = [c.strip().upper() for c in scope.split(",") if c.strip()]
    click.echo(f"[*] Target Scope: {', '.join(categories)}")

    orchestrator = SecCodeOrchestrator(default_config)
    report = orchestrator.run_audit(repo, categories=categories, use_llm=use_llm)

    m = report.metrics
    click.echo(click.style(f"\n[+] Audit Completed in {m.duration_seconds}s", fg="green", bold=True))
    click.echo(f"    - Confirmed Findings: {m.total_confirmed}")
    click.echo(f"    - Plausible Patches:  {m.plausible_patches} ({m.plausibility_rate}%)")

    for cat, cnt in m.findings_by_category.items():
        click.echo(f"      • {cat}: {cnt}")

    # Write JSON output
    if output_json:
        with open(output_json, "w", encoding="utf-8") as f:
            f.write(report.model_dump_json(indent=2))
        click.echo(f"[+] Saved JSON report to: {output_json}")

    # Write Markdown output
    if output_md:
        md_content = SecCodeOrchestrator.format_markdown(report)
        with open(output_md, "w", encoding="utf-8") as f:
            f.write(md_content)
        click.echo(f"[+] Saved Markdown report to: {output_md}")


if __name__ == "__main__":
    main()

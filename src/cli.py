"""Command-line interface for the AI compliance assessor."""

import sys
import json
from pathlib import Path
from typing import Optional

try:
    import click
    from rich.console import Console
    from rich.table import Table
except ImportError:
    print("Please install required packages: pip install click rich")
    sys.exit(1)

# Handle both absolute and relative imports
try:
    from src.assessor import AIComplianceAssessor
    from src.assessor.models import AISystemInfo
    from src.reports import ReportGenerator
except (ImportError, ModuleNotFoundError):
    from .assessor import AIComplianceAssessor
    from .assessor.models import AISystemInfo
    from .reports import ReportGenerator


console = Console()


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """AI Compliance and Security Assessor CLI."""
    pass


@cli.command()
@click.option('--config', '-c', type=click.Path(exists=True), help='Path to configuration file (JSON/YAML)')
@click.option('--name', help='AI system name')
@click.option('--type', 'ai_type', help='AI system type (llm, vision, etc.)')
@click.option('--use-case', help='Use case (e.g., customer_support, medical)')
@click.option('--frameworks', '-f', multiple=True, help='Frameworks to assess (can specify multiple)')
@click.option('--security', '-s', multiple=True, help='Security checks to run (can specify multiple)')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', 'output_format', type=click.Choice(['json', 'markdown', 'html']), default='markdown')
def assess(config, name, ai_type, use_case, frameworks, security, output, output_format):
    """Perform a compliance and security assessment."""
    console.print("[bold blue]AI Compliance and Security Assessor[/bold blue]")
    console.print()

    # Load configuration
    if config:
        config_path = Path(config)
        if config_path.suffix == '.json':
            system_info = json.loads(config_path.read_text())
        else:
            console.print("[red]Only JSON config files are currently supported[/red]")
            sys.exit(1)
    else:
        # Build from CLI options
        if not all([name, ai_type, use_case]):
            console.print("[red]Error: --name, --type, and --use-case are required when not using --config[/red]")
            sys.exit(1)

        system_info = {
            "name": name,
            "type": ai_type,
            "use_case": use_case,
            "data_types": []
        }

    # Initialize assessor
    console.print("[yellow]Initializing assessor...[/yellow]")
    assessor = AIComplianceAssessor()

    # Run assessment
    console.print(f"[yellow]Assessing {system_info['name']}...[/yellow]")

    frameworks_list = list(frameworks) if frameworks else None
    security_list = list(security) if security else None

    result = assessor.assess(
        system_info=system_info,
        frameworks=frameworks_list,
        security_checks=security_list
    )

    # Display summary
    console.print()
    console.print("[bold green]Assessment Complete![/bold green]")
    console.print()
    console.print(result.summary())

    # Generate report
    if output:
        console.print(f"\n[yellow]Generating {output_format} report...[/yellow]")
        generator = ReportGenerator()

        if output_format == 'json':
            generator.generate_json(result, output)
        elif output_format == 'markdown':
            generator.generate_markdown(result, output)
        elif output_format == 'html':
            generator.generate_html(result, output)

        console.print(f"[green]Report saved to: {output}[/green]")


@cli.command()
def list_frameworks():
    """List available compliance frameworks."""
    assessor = AIComplianceAssessor()
    frameworks = assessor.list_frameworks()

    table = Table(title="Available Compliance Frameworks")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="green")

    framework_names = {
        "gdpr": "GDPR - General Data Protection Regulation",
        "eu_ai_act": "EU AI Act - Risk-based AI Regulation",
        "nist": "NIST AI RMF - AI Risk Management Framework",
        "iso42001": "ISO/IEC 42001 - AI Management System",
        "hipaa": "HIPAA - Healthcare Privacy and Security"
    }

    for fw_id in frameworks:
        table.add_row(fw_id, framework_names.get(fw_id, fw_id))

    console.print(table)


@cli.command()
def list_checks():
    """List available security checks."""
    assessor = AIComplianceAssessor()
    checks = assessor.list_security_checks()

    table = Table(title="Available Security Checks")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="green")

    check_names = {
        "owasp_llm": "OWASP Top 10 for LLM Applications",
        "adversarial": "Adversarial Robustness Testing",
        "data_privacy": "Data Privacy and PII Protection",
        "model_security": "Model Security Assessment",
        "supply_chain": "Supply Chain Security"
    }

    for check_id in checks:
        table.add_row(check_id, check_names.get(check_id, check_id))

    console.print(table)


if __name__ == '__main__':
    cli()

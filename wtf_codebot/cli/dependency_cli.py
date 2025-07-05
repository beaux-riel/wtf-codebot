"""
Command-line interface for dependency analysis
"""

import json
import sys
from pathlib import Path
from typing import List, Dict, Any

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

from wtf_codebot.analyzers.dependency_analyzer import DependencyAnalyzer, DependencyAnalysisResult


console = Console()


def format_vulnerability_severity(severity: str) -> str:
    """Format vulnerability severity with color coding"""
    colors = {
        'critical': 'red',
        'high': 'red',
        'medium': 'yellow',
        'low': 'green',
        'unknown': 'dim'
    }
    return f"[{colors.get(severity.lower(), 'dim')}]{severity.upper()}[/{colors.get(severity.lower(), 'dim')}]"


def display_dependency_summary(result: DependencyAnalysisResult):
    """Display dependency summary"""
    console.print(f"\n[bold blue]📦 Package Manager:[/bold blue] {result.package_manager}")
    console.print(f"[bold blue]📄 File:[/bold blue] {result.file_path}")
    console.print(f"[bold blue]🔍 Dependencies Found:[/bold blue] {len(result.dependencies)}")
    console.print(f"[bold blue]🚨 Vulnerabilities:[/bold blue] {len(result.vulnerabilities)}")
    
    if result.license_summary:
        console.print(f"[bold blue]📜 License Types:[/bold blue] {len(result.license_summary)}")


def display_dependencies_table(result: DependencyAnalysisResult):
    """Display dependencies in a table format"""
    table = Table(title="Dependencies")
    table.add_column("Package", style="cyan", no_wrap=True)
    table.add_column("Version", style="magenta")
    table.add_column("Type", style="green")
    table.add_column("License", style="yellow")
    table.add_column("Description", style="dim", max_width=40)
    
    for name, dep in result.dependencies.items():
        dep_type = "dev" if dep.dev_dependency else "prod"
        if dep.optional:
            dep_type += " (optional)"
        
        table.add_row(
            name,
            dep.version_constraint or dep.version,
            dep_type,
            dep.license or "Unknown",
            dep.description or ""
        )
    
    console.print(table)


def display_vulnerabilities(result: DependencyAnalysisResult):
    """Display vulnerabilities"""
    if not result.vulnerabilities:
        console.print("[green]✅ No vulnerabilities found![/green]")
        return
    
    console.print(f"\n[bold red]🚨 Security Vulnerabilities ({len(result.vulnerabilities)})[/bold red]")
    
    for vuln in result.vulnerabilities:
        severity_text = format_vulnerability_severity(vuln.severity)
        
        panel_content = []
        if vuln.cve_id:
            panel_content.append(f"[bold]CVE ID:[/bold] {vuln.cve_id}")
        if vuln.advisory_id:
            panel_content.append(f"[bold]Advisory ID:[/bold] {vuln.advisory_id}")
        
        panel_content.append(f"[bold]Severity:[/bold] {severity_text}")
        panel_content.append(f"[bold]Source:[/bold] {vuln.source}")
        
        if vuln.affected_versions:
            panel_content.append(f"[bold]Affected Versions:[/bold] {', '.join(vuln.affected_versions)}")
        
        if vuln.fixed_versions:
            panel_content.append(f"[bold]Fixed Versions:[/bold] {', '.join(vuln.fixed_versions)}")
        
        if vuln.description:
            panel_content.append(f"[bold]Description:[/bold] {vuln.description}")
        
        console.print(Panel(
            "\n".join(panel_content),
            title=vuln.title or "Vulnerability",
            border_style="red"
        ))


def display_license_summary(result: DependencyAnalysisResult):
    """Display license summary"""
    if not result.license_summary:
        console.print("[yellow]⚠️  No license information available[/yellow]")
        return
    
    console.print("\n[bold green]📜 License Summary[/bold green]")
    
    table = Table()
    table.add_column("License", style="green")
    table.add_column("Count", style="magenta")
    table.add_column("Packages", style="dim")
    
    for license_type, packages in result.license_summary.items():
        table.add_row(
            license_type.title(),
            str(len(packages)),
            ", ".join(packages[:5]) + ("..." if len(packages) > 5 else "")
        )
    
    console.print(table)


def export_to_json(results: List[DependencyAnalysisResult], output_file: str):
    """Export results to JSON file"""
    json_data = []
    
    for result in results:
        result_dict = {
            "package_manager": result.package_manager,
            "file_path": result.file_path,
            "analysis_timestamp": result.analysis_timestamp.isoformat(),
            "dependencies": {
                name: {
                    "name": dep.name,
                    "version": dep.version,
                    "version_constraint": dep.version_constraint,
                    "license": dep.license,
                    "description": dep.description,
                    "dependencies": dep.dependencies,
                    "dev_dependency": dep.dev_dependency,
                    "optional": dep.optional
                }
                for name, dep in result.dependencies.items()
            },
            "vulnerabilities": [
                {
                    "cve_id": vuln.cve_id,
                    "advisory_id": vuln.advisory_id,
                    "severity": vuln.severity,
                    "title": vuln.title,
                    "description": vuln.description,
                    "affected_versions": vuln.affected_versions,
                    "fixed_versions": vuln.fixed_versions,
                    "source": vuln.source
                }
                for vuln in result.vulnerabilities
            ],
            "license_summary": result.license_summary,
            "dependency_tree": result.dependency_tree
        }
        json_data.append(result_dict)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
    
    console.print(f"[green]✅ Results exported to {output_file}[/green]")


@click.command()
@click.option(
    '--path', '-p',
    type=click.Path(exists=True, path_type=Path),
    default='.',
    help='Path to analyze (directory or file)'
)
@click.option(
    '--output', '-o',
    type=click.Path(path_type=Path),
    help='Output file for JSON export'
)
@click.option(
    '--vulnerabilities-only', '-v',
    is_flag=True,
    help='Show only vulnerabilities'
)
@click.option(
    '--licenses-only', '-l',
    is_flag=True,
    help='Show only license information'
)
@click.option(
    '--no-network', '-n',
    is_flag=True,
    help='Skip network requests for vulnerability checking'
)
@click.option(
    '--format',
    type=click.Choice(['table', 'json', 'summary']),
    default='table',
    help='Output format'
)
def analyze_dependencies(path: Path, output: Path, vulnerabilities_only: bool, 
                        licenses_only: bool, no_network: bool, format: str):
    """
    Analyze dependencies and security vulnerabilities in package manager files.
    
    Supports:
    - npm (package.json)
    - Python (requirements.txt, pyproject.toml, poetry.lock, Pipfile)
    - And more coming soon!
    """
    
    console.print("[bold blue]🔍 Dependency & Security Analysis[/bold blue]")
    console.print(f"Analyzing: {path}")
    
    analyzer = DependencyAnalyzer()
    
    # Disable network requests if requested
    if no_network:
        analyzer.security_client = None
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("Analyzing dependencies...", total=None)
            
            if path.is_file():
                results = [analyzer.analyze_dependency_file(str(path))]
            else:
                results = analyzer.analyze_directory(str(path))
            
            progress.update(task, description="Analysis complete!")
        
        if not results:
            console.print("[yellow]⚠️  No package manager files found[/yellow]")
            return
        
        # Display results
        for result in results:
            if format == 'json':
                print(json.dumps({
                    "package_manager": result.package_manager,
                    "file_path": result.file_path,
                    "dependencies_count": len(result.dependencies),
                    "vulnerabilities_count": len(result.vulnerabilities),
                    "license_types": len(result.license_summary)
                }, indent=2))
            elif format == 'summary':
                display_dependency_summary(result)
            else:
                display_dependency_summary(result)
                
                if not vulnerabilities_only and not licenses_only:
                    display_dependencies_table(result)
                
                if not licenses_only:
                    display_vulnerabilities(result)
                
                if not vulnerabilities_only:
                    display_license_summary(result)
                
                console.print("─" * 80)
        
        # Export to JSON if requested
        if output:
            export_to_json(results, str(output))
        
        # Summary statistics
        total_deps = sum(len(r.dependencies) for r in results)
        total_vulns = sum(len(r.vulnerabilities) for r in results)
        
        console.print(f"\n[bold green]📊 Summary Statistics[/bold green]")
        console.print(f"Files analyzed: {len(results)}")
        console.print(f"Total dependencies: {total_deps}")
        console.print(f"Total vulnerabilities: {total_vulns}")
        
        if total_vulns > 0:
            console.print(f"[bold red]⚠️  {total_vulns} vulnerabilities found! Consider updating affected packages.[/bold red]")
            sys.exit(1)
        else:
            console.print("[bold green]✅ No vulnerabilities found![/bold green]")
    
    except Exception as e:
        console.print(f"[bold red]❌ Error during analysis: {e}[/bold red]")
        sys.exit(1)


if __name__ == '__main__':
    analyze_dependencies()

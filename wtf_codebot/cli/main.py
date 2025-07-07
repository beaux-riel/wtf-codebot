"""Main CLI entry point for WTF CodeBot."""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from ..core.config import get_config, Config
from ..core.logging import setup_logging, get_logger
from ..core.exceptions import WTFCodeBotError, ConfigurationError


console = Console()


def handle_exceptions(func):
    """Decorator to handle exceptions gracefully."""
    import functools
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ConfigurationError as e:
            console.print(f"[red]Configuration Error:[/red] {e}", style="red")
            sys.exit(1)
        except WTFCodeBotError as e:
            console.print(f"[red]Error:[/red] {e}", style="red")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red]Unexpected Error:[/red] {e}", style="red")
            sys.exit(1)
    return wrapper


@click.group()
@click.option(
    '--config',
    '-c',
    type=click.Path(exists=True, path_type=Path),
    help='Path to configuration file'
)
@click.option(
    '--verbose',
    '-v',
    is_flag=True,
    help='Enable verbose output'
)
@click.option(
    '--dry-run',
    is_flag=True,
    help='Perform dry run without making changes'
)
@click.pass_context
def cli(ctx: click.Context, config: Optional[Path], verbose: bool, dry_run: bool):
    """WTF CodeBot - AI-powered code analysis and review tool."""
    ctx.ensure_object(dict)
    
    # Load configuration
    try:
        config_obj = get_config(str(config) if config else None)
        
        # Override with CLI options
        if verbose:
            config_obj.verbose = True
        if dry_run:
            config_obj.dry_run = True
        
        # Setup logging
        setup_logging(config_obj)
        
        # Store config in context
        ctx.obj['config'] = config_obj
        
    except Exception as e:
        console.print(f"[red]Failed to load configuration:[/red] {e}", style="red")
        sys.exit(1)


@cli.command()
@click.argument('path', type=click.Path(exists=True, path_type=Path))
@click.option(
    '--output',
    '-o',
    type=click.Path(path_type=Path),
    help='Output file path'
)
@click.option(
    '--format',
    '-f',
    'output_format',
    type=click.Choice(['console', 'json', 'markdown']),
    help='Output format'
)
@click.option(
    '--include-tests',
    is_flag=True,
    help='Include test files in analysis'
)
@click.option(
    '--exclude',
    multiple=True,
    help='Exclude patterns (can be specified multiple times)'
)
@click.option(
    '--export-sarif',
    type=click.Path(path_type=Path),
    help='Export results to SARIF file'
)
@click.option(
    '--export-html',
    type=click.Path(path_type=Path),
    help='Export results to HTML file'
)
@click.option(
    '--export-csv',
    type=click.Path(path_type=Path),
    help='Export results to CSV file'
)
@click.option(
    '--github-issues',
    is_flag=True,
    help='Create GitHub issues for critical/high findings'
)
@click.option(
    '--github-repo',
    help='GitHub repository (owner/repo)'
)
@click.option(
    '--webhook-url',
    help='Webhook URL to send results'
)
@click.option(
    '--slack-webhook',
    help='Slack webhook URL to post results'
)
@click.option(
    '--jira-project',
    help='JIRA project key to create tickets'
)
@click.pass_context
@handle_exceptions
def analyze(ctx: click.Context, path: Path, output: Optional[Path], 
           output_format: Optional[str], include_tests: bool, exclude: tuple,
           export_sarif: Optional[Path], export_html: Optional[Path], export_csv: Optional[Path],
           github_issues: bool, github_repo: Optional[str], webhook_url: Optional[str],
           slack_webhook: Optional[str], jira_project: Optional[str]):
    """Analyze code in the specified path."""
    config: Config = ctx.obj['config']
    logger = get_logger("cli.analyze")
    
    logger.info("Starting code analysis", path=str(path))
    
    # Override config with CLI options
    if output:
        config.output_file = str(output)
    if output_format:
        config.output_format = output_format
    if include_tests:
        config.analysis.include_tests = True
    if exclude:
        config.analysis.exclude_patterns.extend(exclude)
    
    # Handle integration options
    if any([export_sarif, export_html, export_csv, github_issues, webhook_url, slack_webhook, jira_project]):
        config.integrations.enabled = True
        
        if export_sarif:
            config.integrations.export_sarif = True
            config.integrations.sarif_output_path = str(export_sarif)
        if export_html:
            config.integrations.export_html = True
            config.integrations.html_output_path = str(export_html)
        if export_csv:
            config.integrations.export_csv = True
            config.integrations.csv_output_path = str(export_csv)
            
        if github_issues:
            config.integrations.github_issues_enabled = True
            if github_repo:
                config.integrations.github_repository = github_repo
                
        if webhook_url:
            config.integrations.webhook_enabled = True
            config.integrations.webhook_url = webhook_url
            
        if slack_webhook:
            config.integrations.slack_enabled = True
            config.integrations.slack_webhook_url = slack_webhook
            
        if jira_project:
            config.integrations.jira_enabled = True
            config.integrations.jira_project_key = jira_project
    
    console.print(f"[green]Analyzing code in:[/green] {path}")
    console.print(f"[blue]Configuration:[/blue]")
    console.print(f"  - Output format: {config.output_format}")
    console.print(f"  - Include tests: {config.analysis.include_tests}")
    console.print(f"  - Max file size: {config.analysis.max_file_size} bytes")
    console.print(f"  - Analysis depth: {config.analysis.analysis_depth}")
    
    if config.dry_run:
        console.print("[yellow]Dry run mode - no changes will be made[/yellow]")
    
    # Implement analysis logic using the new AnalysisEngine
    from ..core.analysis_engine import AnalysisEngine
    analysis_engine = AnalysisEngine(config)
    results = analysis_engine.analyze(path)
    report = analysis_engine.generate_report(results, output_format=config.output_format)

    console.print(report)


@cli.command()
@click.pass_context
@handle_exceptions
def config_info(ctx: click.Context):
    """Display current configuration."""
    config: Config = ctx.obj['config']
    
    console.print("[green]Current Configuration:[/green]")
    console.print(f"  [blue]Anthropic Model:[/blue] {config.anthropic_model}")
    console.print(f"  [blue]Output Format:[/blue] {config.output_format}")
    console.print(f"  [blue]Verbose Mode:[/blue] {config.verbose}")
    console.print(f"  [blue]Dry Run Mode:[/blue] {config.dry_run}")
    
    console.print("\n[green]Analysis Configuration:[/green]")
    console.print(f"  [blue]Max File Size:[/blue] {config.analysis.max_file_size} bytes")
    console.print(f"  [blue]Include Tests:[/blue] {config.analysis.include_tests}")
    console.print(f"  [blue]Analysis Depth:[/blue] {config.analysis.analysis_depth}")
    console.print(f"  [blue]Supported Extensions:[/blue] {', '.join(config.analysis.supported_extensions)}")
    
    console.print("\n[green]Logging Configuration:[/green]")
    console.print(f"  [blue]Log Level:[/blue] {config.logging.level}")
    console.print(f"  [blue]Log File:[/blue] {config.logging.file_path or 'None'}")


@cli.command()
@click.option(
    '--output',
    '-o',
    type=click.Path(path_type=Path),
    default="wtf-codebot.yaml",
    help='Output configuration file path'
)
@click.pass_context
@handle_exceptions
def init_config(ctx: click.Context, output: Path):
    """Initialize a new configuration file."""
    if output.exists():
        if not click.confirm(f"Configuration file {output} already exists. Overwrite?"):
            console.print("[yellow]Configuration initialization cancelled[/yellow]")
            return
    
    # Create a sample configuration
    sample_config = {
        "anthropic_api_key": "your-api-key-here",
        "anthropic_model": "claude-3-7-sonnet-20250219",
        "output_format": "console",
        "verbose": False,
        "dry_run": False,
        "analysis": {
            "max_file_size": 1048576,
            "include_tests": True,
            "analysis_depth": "standard",
            "supported_extensions": [".py", ".js", ".ts", ".java", ".cpp", ".c", ".h", ".hpp", ".go", ".rs", ".rb"],
            "exclude_patterns": ["**/node_modules/**", "**/.git/**", "**/__pycache__/**", "**/venv/**", "**/.env"]
        },
        "logging": {
            "level": "INFO",
            "file_path": None
        }
    }
    
    import yaml
    with open(output, 'w') as f:
        yaml.dump(sample_config, f, default_flow_style=False, indent=2)
    
    console.print(f"[green]Configuration file created:[/green] {output}")
    console.print("[yellow]Please edit the configuration file to set your Anthropic API key and other preferences.[/yellow]")


@cli.command()
@click.option(
    '--host',
    default='0.0.0.0',
    help='Host to bind the web server to'
)
@click.option(
    '--port',
    default=8000,
    type=int,
    help='Port to run the web server on'
)
@click.option(
    '--reload',
    is_flag=True,
    help='Enable auto-reload for development'
)
@click.pass_context
@handle_exceptions
def web(ctx: click.Context, host: str, port: int, reload: bool):
    """Start the web interface server."""
    config: Config = ctx.obj['config']
    
    console.print(f"[green]Starting WTF Codebot Web Interface...[/green]")
    console.print(f"[blue]Host:[/blue] {host}")
    console.print(f"[blue]Port:[/blue] {port}")
    console.print(f"[blue]Reload:[/blue] {reload}")
    console.print(f"\n[green]Access the web interface at:[/green] http://{host}:{port}")
    console.print("[yellow]Press Ctrl+C to stop the server[/yellow]\n")
    
    try:
        import uvicorn
    except ImportError as e:
        console.print(f"[red]Error:[/red] uvicorn not available: {e}")
        console.print("[yellow]Install web dependencies with: pip install wtf-codebot[web][/yellow]")
        sys.exit(1)
    
    try:
        from ..web.server import app
    except ImportError as e:
        console.print(f"[red]Error:[/red] Failed to import web server: {e}")
        console.print("[yellow]There may be missing dependencies or import issues.[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] Failed to initialize web server: {e}")
        sys.exit(1)
    
    try:
        # Run the server
        uvicorn.run(
            app,
            host=host,
            port=port,
            reload=reload,
            log_level="info" if config.verbose else "warning"
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Error:[/red] Server failed to start: {e}")
        sys.exit(1)


@cli.command()
@click.pass_context
@handle_exceptions
def version(ctx: click.Context):
    """Show version information."""
    from .. import __version__
    console.print(f"[green]WTF CodeBot version:[/green] {__version__}")


def main():
    """Main entry point."""
    cli(obj={})


if __name__ == '__main__':
    main()

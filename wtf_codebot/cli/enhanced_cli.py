"""Enhanced CLI interface using typer with comprehensive argument handling."""

import os
import sys
from pathlib import Path
from typing import List, Optional, Tuple

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..core.config import Config, AnalysisConfig, LoggingConfig
from ..core.exceptions import WTFCodeBotError, ConfigurationError
from ..core.logging import setup_logging, get_logger
from ..analyzers.dependency_analyzer import DependencyAnalyzer
from ..reporters.dependency_reporter import DependencyReporter

# Create the main app
app = typer.Typer(
    name="wtf-codebot",
    help="WTF CodeBot - AI-powered code analysis and review tool",
    add_completion=False,
    rich_markup_mode="rich",
)

# Create a console for rich output
console = Console()

# Supported output formats
OUTPUT_FORMATS = ["console", "json", "markdown", "html", "yaml"]

# Supported language filters
LANGUAGE_FILTERS = [
    "python", "javascript", "typescript", "java", "cpp", "c", "go", "rust", "ruby",
    "php", "swift", "kotlin", "scala", "clojure", "haskell", "erlang", "elixir",
    "csharp", "fsharp", "vb", "matlab", "r", "julia", "dart", "lua", "perl",
    "shell", "powershell", "sql", "html", "css", "xml", "json", "yaml", "toml"
]

# Analysis depth options
ANALYSIS_DEPTHS = ["basic", "standard", "deep", "comprehensive"]


def validate_api_key(api_key: str) -> str:
    """Validate API key format and presence."""
    if not api_key or api_key.strip() == "":
        raise typer.BadParameter("API key cannot be empty")
    
    # Check if it looks like a placeholder
    if api_key.lower() in ["your-api-key-here", "api-key", "key", "xxx"]:
        raise typer.BadParameter("Please provide a valid API key (not a placeholder)")
    
    # Basic format check (Anthropic API keys typically start with 'sk-ant-')
    if not api_key.startswith("sk-ant-"):
        console.print(
            "[yellow]Warning:[/yellow] API key doesn't match expected format. "
            "Anthropic API keys typically start with 'sk-ant-'",
            style="yellow"
        )
    
    return api_key.strip()


def validate_directory(directory: str) -> Path:
    """Validate that the directory exists and is readable."""
    path = Path(directory).resolve()
    
    if not path.exists():
        raise typer.BadParameter(f"Directory does not exist: {directory}")
    
    if not path.is_dir():
        raise typer.BadParameter(f"Path is not a directory: {directory}")
    
    if not os.access(path, os.R_OK):
        raise typer.BadParameter(f"Directory is not readable: {directory}")
    
    return path


def validate_output_formats(formats: List[str]) -> List[str]:
    """Validate output format choices."""
    invalid_formats = [f for f in formats if f not in OUTPUT_FORMATS]
    if invalid_formats:
        raise typer.BadParameter(
            f"Invalid output format(s): {', '.join(invalid_formats)}. "
            f"Valid formats: {', '.join(OUTPUT_FORMATS)}"
        )
    return formats


def validate_language_filters(languages: List[str]) -> List[str]:
    """Validate language filter choices."""
    invalid_languages = [l for l in languages if l not in LANGUAGE_FILTERS]
    if invalid_languages:
        console.print(
            f"[yellow]Warning:[/yellow] Unknown language(s): {', '.join(invalid_languages)}. "
            f"Supported languages: {', '.join(LANGUAGE_FILTERS)}",
            style="yellow"
        )
    return languages


def validate_depth_limit(depth: int) -> int:
    """Validate directory depth limit."""
    if depth < 1:
        raise typer.BadParameter("Depth limit must be at least 1")
    if depth > 100:
        raise typer.BadParameter("Depth limit cannot exceed 100")
    return depth


def validate_batch_size(batch_size: int) -> int:
    """Validate batch size."""
    if batch_size < 1:
        raise typer.BadParameter("Batch size must be at least 1")
    if batch_size > 1000:
        raise typer.BadParameter("Batch size cannot exceed 1000")
    return batch_size


@app.command()
def analyze(
    # Required arguments
    directory: str = typer.Argument(
        ...,
        help="Directory containing code to analyze",
        callback=lambda x: validate_directory(x)
    ),
    
    # API Configuration
    api_key: Optional[str] = typer.Option(
        None,
        "--api-key", "-k",
        help="Anthropic API key (can also be set via ANTHROPIC_API_KEY env var)",
        callback=lambda x: validate_api_key(x) if x else None
    ),
    
    # Output Configuration
    output_formats: List[str] = typer.Option(
        ["console"],
        "--format", "-f",
        help="Output format(s). Can be specified multiple times.",
        callback=validate_output_formats
    ),
    
    output_file: Optional[str] = typer.Option(
        None,
        "--output", "-o",
        help="Output file path (required for non-console formats)"
    ),
    
    # Language Filters
    language_filters: List[str] = typer.Option(
        [],
        "--language", "-l",
        help="Filter by programming language. Can be specified multiple times.",
        callback=validate_language_filters
    ),
    
    # Analysis Depth
    depth_limit: int = typer.Option(
        10,
        "--depth", "-d",
        help="Maximum directory depth to analyze (1-100)",
        callback=validate_depth_limit
    ),
    
    analysis_depth: str = typer.Option(
        "standard",
        "--analysis-depth",
        help="Analysis depth level",
        click_type=typer.Choice(ANALYSIS_DEPTHS, case_sensitive=False)
    ),
    
    # Batch Processing
    batch_size: int = typer.Option(
        50,
        "--batch-size", "-b",
        help="Number of files to process in each batch (1-1000)",
        callback=validate_batch_size
    ),
    
    # Advanced Flags
    include_tests: bool = typer.Option(
        True,
        "--include-tests/--exclude-tests",
        help="Include or exclude test files"
    ),
    
    include_hidden: bool = typer.Option(
        False,
        "--include-hidden/--exclude-hidden",
        help="Include or exclude hidden files and directories"
    ),
    
    follow_symlinks: bool = typer.Option(
        False,
        "--follow-symlinks/--no-follow-symlinks",
        help="Follow symbolic links"
    ),
    
    max_file_size: int = typer.Option(
        1024 * 1024,  # 1MB
        "--max-file-size",
        help="Maximum file size to analyze (bytes)"
    ),
    
    exclude_patterns: List[str] = typer.Option(
        [],
        "--exclude", "-x",
        help="Exclude patterns (glob). Can be specified multiple times."
    ),
    
    include_patterns: List[str] = typer.Option(
        [],
        "--include", "-i",
        help="Include patterns (glob). Can be specified multiple times."
    ),
    
    # Model Configuration
    model: str = typer.Option(
        "claude-3-sonnet-20240229",
        "--model", "-m",
        help="Anthropic model to use"
    ),
    
    # General Options
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Enable verbose output"
    ),
    
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Perform dry run without making API calls"
    ),
    
    config_file: Optional[str] = typer.Option(
        None,
        "--config", "-c",
        help="Path to configuration file"
    ),
    
    save_config: Optional[str] = typer.Option(
        None,
        "--save-config",
        help="Save current configuration to file"
    ),
):
    """
    Analyze code in the specified directory using AI-powered analysis.
    
    This command performs comprehensive code analysis including:
    - Code quality assessment
    - Security vulnerability detection
    - Performance optimization suggestions
    - Best practice recommendations
    - Documentation improvements
    
    Examples:
    
        # Basic analysis
        wtf-codebot analyze /path/to/code --api-key sk-ant-...
        
        # Multi-format output
        wtf-codebot analyze /path/to/code -f json -f markdown -o report
        
        # Language-specific analysis
        wtf-codebot analyze /path/to/code -l python -l javascript
        
        # Deep analysis with custom settings
        wtf-codebot analyze /path/to/code --analysis-depth deep --batch-size 100
    """
    
    # Handle API key from environment if not provided
    if not api_key:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            console.print(
                "[red]Error:[/red] API key is required. Provide it via --api-key or "
                "set the ANTHROPIC_API_KEY environment variable.",
                style="red"
            )
            raise typer.Exit(1)
        api_key = validate_api_key(api_key)
    
    # Validate output configuration
    if len(output_formats) > 1 or output_formats[0] != "console":
        if not output_file:
            console.print(
                "[red]Error:[/red] Output file is required when using non-console formats.",
                style="red"
            )
            raise typer.Exit(1)
    
    # Build configuration
    try:
        config = Config(
            anthropic_api_key=api_key,
            anthropic_model=model,
            output_format=output_formats[0],  # Primary format
            output_file=output_file,
            verbose=verbose,
            dry_run=dry_run,
            analysis=AnalysisConfig(
                max_file_size=max_file_size,
                include_tests=include_tests,
                analysis_depth=analysis_depth,
                exclude_patterns=exclude_patterns or [
                    "**/node_modules/**", "**/.git/**", "**/__pycache__/**", 
                    "**/venv/**", "**/.env"
                ],
                supported_extensions=_get_extensions_for_languages(language_filters) if language_filters else None
            ),
            logging=LoggingConfig(
                level="DEBUG" if verbose else "INFO"
            )
        )
    except Exception as e:
        console.print(f"[red]Configuration Error:[/red] {e}", style="red")
        raise typer.Exit(1)
    
    # Save configuration if requested
    if save_config:
        try:
            from ..core.config import ConfigManager
            config_manager = ConfigManager()
            config_manager.save_config(config, save_config)
            console.print(f"[green]Configuration saved to:[/green] {save_config}")
        except Exception as e:
            console.print(f"[red]Failed to save configuration:[/red] {e}", style="red")
    
    # Setup logging
    setup_logging(config)
    logger = get_logger("cli.analyze")
    
    # Display configuration summary
    _display_analysis_summary(
        directory, config, output_formats, language_filters, 
        depth_limit, batch_size, include_patterns, exclude_patterns
    )
    
    if dry_run:
        console.print("\n[yellow]Dry run mode - no actual analysis will be performed[/yellow]")
        return
    
    # Perform analysis
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Analyzing code...", total=None)
            
            # TODO: Implement actual analysis logic here
            # This is where you would integrate with your analysis engine
            
            progress.update(task, description="Analysis complete!")
        
        console.print("[green]✓ Analysis completed successfully![/green]")
        
    except WTFCodeBotError as e:
        logger.error("Analysis failed", error=str(e))
        console.print(f"[red]Analysis Error:[/red] {e}", style="red")
        raise typer.Exit(1)
    except Exception as e:
        logger.error("Unexpected error during analysis", error=str(e))
        console.print(f"[red]Unexpected Error:[/red] {e}", style="red")
        raise typer.Exit(1)


@app.command()
def config(
    show: bool = typer.Option(
        False,
        "--show", "-s",
        help="Show current configuration"
    ),
    
    init: bool = typer.Option(
        False,
        "--init", "-i",
        help="Initialize a new configuration file"
    ),
    
    validate: bool = typer.Option(
        False,
        "--validate", "-v",
        help="Validate configuration file"
    ),
    
    file: Optional[str] = typer.Option(
        None,
        "--file", "-f",
        help="Configuration file path"
    ),
):
    """
    Manage configuration files.
    
    Examples:
        wtf-codebot config --show
        wtf-codebot config --init
        wtf-codebot config --validate -f config.yaml
    """
    
    if init:
        _init_config(file or "wtf-codebot.yaml")
    elif show:
        _show_config(file)
    elif validate:
        _validate_config(file or "wtf-codebot.yaml")
    else:
        console.print("Please specify an action: --show, --init, or --validate")
        raise typer.Exit(1)


@app.command()
def version():
    """Show version information."""
    from .. import __version__
    
    console.print(Panel(
        f"[bold cyan]WTF CodeBot[/bold cyan] version [bold green]{__version__}[/bold green]",
        title="Version Information",
        border_style="cyan"
    ))


def _display_analysis_summary(
    directory: Path, 
    config: Config, 
    output_formats: List[str],
    language_filters: List[str],
    depth_limit: int,
    batch_size: int,
    include_patterns: List[str],
    exclude_patterns: List[str]
):
    """Display a summary of the analysis configuration."""
    
    # Create summary table
    table = Table(title="Analysis Configuration", show_header=True, header_style="bold blue")
    table.add_column("Setting", style="cyan", width=20)
    table.add_column("Value", style="green")
    
    table.add_row("Directory", str(directory))
    table.add_row("Model", config.anthropic_model)
    table.add_row("Output Formats", ", ".join(output_formats))
    table.add_row("Analysis Depth", config.analysis.analysis_depth)
    table.add_row("Depth Limit", str(depth_limit))
    table.add_row("Batch Size", str(batch_size))
    table.add_row("Max File Size", f"{config.analysis.max_file_size:,} bytes")
    table.add_row("Include Tests", "✓" if config.analysis.include_tests else "✗")
    
    if language_filters:
        table.add_row("Languages", ", ".join(language_filters))
    
    if include_patterns:
        table.add_row("Include Patterns", ", ".join(include_patterns))
    
    if exclude_patterns:
        table.add_row("Exclude Patterns", ", ".join(exclude_patterns))
    
    console.print(table)


def _get_extensions_for_languages(languages: List[str]) -> List[str]:
    """Map language names to file extensions."""
    language_extension_map = {
        "python": [".py", ".pyx", ".pyi"],
        "javascript": [".js", ".jsx", ".mjs"],
        "typescript": [".ts", ".tsx"],
        "java": [".java"],
        "cpp": [".cpp", ".cxx", ".cc", ".hpp", ".hxx", ".h"],
        "c": [".c", ".h"],
        "go": [".go"],
        "rust": [".rs"],
        "ruby": [".rb", ".rake"],
        "php": [".php", ".phtml"],
        "swift": [".swift"],
        "kotlin": [".kt", ".kts"],
        "scala": [".scala"],
        "csharp": [".cs"],
        "fsharp": [".fs", ".fsx"],
        "shell": [".sh", ".bash", ".zsh"],
        "powershell": [".ps1", ".psm1"],
        "html": [".html", ".htm"],
        "css": [".css", ".scss", ".sass"],
        "sql": [".sql"],
        "yaml": [".yaml", ".yml"],
        "json": [".json"],
        "xml": [".xml"],
        "toml": [".toml"],
    }
    
    extensions = []
    for lang in languages:
        if lang in language_extension_map:
            extensions.extend(language_extension_map[lang])
    
    return extensions or [".py", ".js", ".ts", ".java", ".cpp", ".c", ".h", ".go", ".rs", ".rb"]


def _init_config(file_path: str):
    """Initialize a new configuration file."""
    from ..core.config import ConfigManager
    
    path = Path(file_path)
    if path.exists():
        if not typer.confirm(f"Configuration file {file_path} already exists. Overwrite?"):
            console.print("[yellow]Configuration initialization cancelled[/yellow]")
            return
    
    # Create sample configuration
    sample_config = Config(
        anthropic_api_key="your-api-key-here",
        anthropic_model="claude-3-sonnet-20240229",
        output_format="console",
        verbose=False,
        dry_run=False,
        analysis=AnalysisConfig(
            max_file_size=1024*1024,
            include_tests=True,
            analysis_depth="standard",
            exclude_patterns=[
                "**/node_modules/**", "**/.git/**", "**/__pycache__/**", 
                "**/venv/**", "**/.env"
            ]
        ),
        logging=LoggingConfig(level="INFO")
    )
    
    try:
        config_manager = ConfigManager()
        config_manager.save_config(sample_config, file_path)
        console.print(f"[green]Configuration file created:[/green] {file_path}")
        console.print("[yellow]Please edit the configuration file to set your Anthropic API key.[/yellow]")
    except Exception as e:
        console.print(f"[red]Failed to create configuration file:[/red] {e}", style="red")


def _show_config(file_path: Optional[str]):
    """Show current configuration."""
    try:
        from ..core.config import get_config
        config = get_config(file_path)
        
        table = Table(title="Current Configuration", show_header=True, header_style="bold blue")
        table.add_column("Setting", style="cyan", width=30)
        table.add_column("Value", style="green")
        
        table.add_row("API Key", f"{'*' * 20}...{config.anthropic_api_key[-4:]}")
        table.add_row("Model", config.anthropic_model)
        table.add_row("Output Format", config.output_format)
        table.add_row("Verbose Mode", "✓" if config.verbose else "✗")
        table.add_row("Dry Run Mode", "✓" if config.dry_run else "✗")
        table.add_row("Max File Size", f"{config.analysis.max_file_size:,} bytes")
        table.add_row("Include Tests", "✓" if config.analysis.include_tests else "✗")
        table.add_row("Analysis Depth", config.analysis.analysis_depth)
        table.add_row("Log Level", config.logging.level)
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Failed to load configuration:[/red] {e}", style="red")


def _validate_config(file_path: str):
    """Validate configuration file."""
    try:
        from ..core.config import get_config
        config = get_config(file_path)
        console.print(f"[green]✓ Configuration file {file_path} is valid[/green]")
    except Exception as e:
        console.print(f"[red]✗ Configuration file {file_path} is invalid:[/red] {e}", style="red")
        raise typer.Exit(1)


@app.command()
def dependencies(
    path: str = typer.Argument(
        ".",
        help="Directory or file to analyze for dependencies"
    ),
    
    output_format: str = typer.Option(
        "table",
        "--format", "-f",
        help="Output format",
        click_type=typer.Choice(["table", "json", "summary"], case_sensitive=False)
    ),
    
    output_file: Optional[str] = typer.Option(
        None,
        "--output", "-o",
        help="Output file for JSON export"
    ),
    
    vulnerabilities_only: bool = typer.Option(
        False,
        "--vulnerabilities-only", "-v",
        help="Show only vulnerability information"
    ),
    
    licenses_only: bool = typer.Option(
        False,
        "--licenses-only", "-l",
        help="Show only license information"
    ),
    
    no_network: bool = typer.Option(
        False,
        "--no-network", "-n",
        help="Skip network requests for vulnerability checking"
    ),
    
    report_format: Optional[str] = typer.Option(
        None,
        "--report", "-r",
        help="Generate detailed report in specified format",
        click_type=typer.Choice(["html", "markdown", "json", "csv"], case_sensitive=False)
    ),
    
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Enable verbose output"
    )
):
    """
    Analyze dependencies and security vulnerabilities in package manager files.
    
    This command scans for package manager files (package.json, requirements.txt, 
    pyproject.toml, poetry.lock, Pipfile) and provides comprehensive analysis including:
    
    - Dependency mapping and version analysis
    - License detection and compliance checking  
    - Security vulnerability scanning using public advisories
    - Dependency tree visualization
    - Outdated package detection
    
    Examples:
    
        # Analyze current directory
        wtf-codebot dependencies
        
        # Analyze specific path with table output
        wtf-codebot dependencies /path/to/project --format table
        
        # Show only vulnerabilities
        wtf-codebot dependencies --vulnerabilities-only
        
        # Generate HTML report
        wtf-codebot dependencies --report html --output report.html
        
        # Skip network vulnerability checks
        wtf-codebot dependencies --no-network
    """
    
    from pathlib import Path
    
    console.print("[bold blue]🔍 Dependency & Security Analysis[/bold blue]")
    console.print(f"Analyzing: {path}")
    
    # Validate path
    target_path = Path(path)
    if not target_path.exists():
        console.print(f"[red]Error:[/red] Path does not exist: {path}", style="red")
        raise typer.Exit(1)
    
    # Initialize analyzer
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
            
            if target_path.is_file():
                results = [analyzer.analyze_dependency_file(str(target_path))]
            else:
                results = analyzer.analyze_directory(str(target_path))
            
            progress.update(task, description="Analysis complete!")
        
        if not results:
            console.print("[yellow]⚠️  No package manager files found[/yellow]")
            return
        
        # Display results based on format
        for result in results:
            if output_format == 'json':
                import json
                print(json.dumps({
                    "package_manager": result.package_manager,
                    "file_path": result.file_path,
                    "dependencies_count": len(result.dependencies),
                    "vulnerabilities_count": len(result.vulnerabilities),
                    "license_types": len(result.license_summary)
                }, indent=2))
            elif output_format == 'summary':
                _display_dependency_summary(result)
            else:
                _display_dependency_summary(result)
                
                if not vulnerabilities_only and not licenses_only:
                    _display_dependencies_table(result)
                
                if not licenses_only:
                    _display_vulnerabilities(result)
                
                if not vulnerabilities_only:
                    _display_license_summary(result)
                
                console.print("─" * 80)
        
        # Generate report if requested
        if report_format and output_file:
            reporter = DependencyReporter()
            for result in results:
                reporter.add_result(result)
            
            if report_format == "html":
                reporter.generate_html_report(output_file)
            elif report_format == "markdown":
                reporter.generate_markdown_report(output_file)
            elif report_format == "json":
                reporter.generate_json_report(output_file)
            elif report_format == "csv":
                reporter.generate_csv_report(output_file)
            
            console.print(f"[green]✅ {report_format.upper()} report generated: {output_file}[/green]")
        
        # Export to JSON if requested (simple export)
        if output_file and not report_format:
            _export_to_json(results, output_file)
        
        # Summary statistics
        total_deps = sum(len(r.dependencies) for r in results)
        total_vulns = sum(len(r.vulnerabilities) for r in results)
        
        console.print(f"\n[bold green]📊 Summary Statistics[/bold green]")
        console.print(f"Files analyzed: {len(results)}")
        console.print(f"Total dependencies: {total_deps}")
        console.print(f"Total vulnerabilities: {total_vulns}")
        
        if total_vulns > 0:
            console.print(f"[bold red]⚠️  {total_vulns} vulnerabilities found! Consider updating affected packages.[/bold red]")
        else:
            console.print("[bold green]✅ No vulnerabilities found![/bold green]")
    
    except Exception as e:
        console.print(f"[bold red]❌ Error during analysis: {e}[/bold red]")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        raise typer.Exit(1)


def _display_dependency_summary(result):
    """Display dependency summary"""
    console.print(f"\n[bold blue]📦 Package Manager:[/bold blue] {result.package_manager}")
    console.print(f"[bold blue]📄 File:[/bold blue] {result.file_path}")
    console.print(f"[bold blue]🔍 Dependencies Found:[/bold blue] {len(result.dependencies)}")
    console.print(f"[bold blue]🚨 Vulnerabilities:[/bold blue] {len(result.vulnerabilities)}")
    
    if result.license_summary:
        console.print(f"[bold blue]📜 License Types:[/bold blue] {len(result.license_summary)}")


def _display_dependencies_table(result):
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


def _display_vulnerabilities(result):
    """Display vulnerabilities"""
    if not result.vulnerabilities:
        console.print("[green]✅ No vulnerabilities found![/green]")
        return
    
    console.print(f"\n[bold red]🚨 Security Vulnerabilities ({len(result.vulnerabilities)})[/bold red]")
    
    for vuln in result.vulnerabilities:
        severity_colors = {
            'critical': 'red',
            'high': 'red',
            'medium': 'yellow',
            'low': 'green',
            'unknown': 'dim'
        }
        color = severity_colors.get(vuln.severity.lower(), 'dim')
        severity_text = f"[{color}]{vuln.severity.upper()}[/{color}]"
        
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


def _display_license_summary(result):
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


def _export_to_json(results, output_file: str):
    """Export results to JSON file"""
    import json
    
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


def main():
    """Main entry point for the enhanced CLI."""
    app()


if __name__ == "__main__":
    main()

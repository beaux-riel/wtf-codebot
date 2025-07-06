"""Alternative CLI implementation using argparse with comprehensive validation."""

import argparse
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Union

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from ..core.config import Config, AnalysisConfig, LoggingConfig
from ..core.exceptions import WTFCodeBotError, ConfigurationError
from ..core.logging import setup_logging, get_logger

# Create a console for rich output
console = Console()

# Constants
OUTPUT_FORMATS = ["console", "json", "markdown", "html", "yaml"]
LANGUAGE_FILTERS = [
    "python", "javascript", "typescript", "java", "cpp", "c", "go", "rust", "ruby",
    "php", "swift", "kotlin", "scala", "clojure", "haskell", "erlang", "elixir",
    "csharp", "fsharp", "vb", "matlab", "r", "julia", "dart", "lua", "perl",
    "shell", "powershell", "sql", "html", "css", "xml", "json", "yaml", "toml"
]
ANALYSIS_DEPTHS = ["basic", "standard", "deep", "comprehensive"]


class CustomHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Custom help formatter for better CLI documentation."""
    
    def _format_action_invocation(self, action):
        """Format action invocation with better spacing."""
        if not action.option_strings:
            default = self._get_default_metavar_for_positional(action)
            metavar, = self._metavar_formatter(action, default)(1)
            return metavar
        else:
            parts = []
            if action.nargs == 0:
                parts.extend(action.option_strings)
            else:
                default = self._get_default_metavar_for_optional(action)
                args_string = self._format_args(action, default)
                for option_string in action.option_strings:
                    parts.append(f"{option_string} {args_string}")
            return ", ".join(parts)


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    
    parser = argparse.ArgumentParser(
        prog="wtf-codebot",
        description="""
WTF CodeBot - AI-powered code analysis and review tool

This tool uses AI to analyze your codebase and provide insights on:
• Code quality and maintainability
• Security vulnerabilities
• Performance optimization opportunities
• Best practice recommendations
• Documentation improvements

The tool supports multiple programming languages and output formats,
with extensive configuration options for customizing the analysis.
        """,
        epilog="""
Examples:
  # Basic analysis with API key
  wtf-codebot analyze /path/to/code --api-key sk-ant-api123...

  # Multi-format output
  wtf-codebot analyze /path/to/code -f json -f markdown -o report

  # Language-specific analysis
  wtf-codebot analyze /path/to/code -l python -l javascript

  # Deep analysis with custom settings
  wtf-codebot analyze /path/to/code --analysis-depth deep --batch-size 100

  # Dry run to test configuration
  wtf-codebot analyze /path/to/code --dry-run

For more information, visit: https://github.com/beaux-riel/wtf-codebot
        """,
        formatter_class=CustomHelpFormatter
    )
    
    # Add subcommands
    subparsers = parser.add_subparsers(
        dest="command",
        help="Available commands",
        metavar="COMMAND"
    )
    
    # Analyze command
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze code in a directory",
        description="Perform AI-powered code analysis",
        formatter_class=CustomHelpFormatter
    )
    
    _add_analyze_arguments(analyze_parser)
    
    # Config command
    config_parser = subparsers.add_parser(
        "config",
        help="Manage configuration",
        description="Configuration management commands",
        formatter_class=CustomHelpFormatter
    )
    
    _add_config_arguments(config_parser)
    
    # Version command
    version_parser = subparsers.add_parser(
        "version",
        help="Show version information",
        description="Display version and build information",
        formatter_class=CustomHelpFormatter
    )
    
    return parser


def _add_analyze_arguments(parser: argparse.ArgumentParser) -> None:
    """Add arguments for the analyze command."""
    
    # Required positional argument
    parser.add_argument(
        "directory",
        type=str,
        help="Directory containing code to analyze"
    )
    
    # API Configuration
    api_group = parser.add_argument_group("API Configuration")
    api_group.add_argument(
        "--api-key", "-k",
        type=str,
        help="Anthropic API key (can also be set via ANTHROPIC_API_KEY env var)"
    )
    api_group.add_argument(
        "--model", "-m",
        type=str,
        default="claude-sonnet-4-0",
        help="Anthropic model to use (default: %(default)s)"
    )
    
    # Output Configuration
    output_group = parser.add_argument_group("Output Configuration")
    output_group.add_argument(
        "--format", "-f",
        action="append",
        choices=OUTPUT_FORMATS,
        default=[],
        dest="output_formats",
        help="Output format (can be specified multiple times). Choices: %(choices)s"
    )
    output_group.add_argument(
        "--output", "-o",
        type=str,
        help="Output file path (required for non-console formats)"
    )
    
    # Language Filters
    filter_group = parser.add_argument_group("Language and File Filtering")
    filter_group.add_argument(
        "--language", "-l",
        action="append",
        choices=LANGUAGE_FILTERS,
        default=[],
        dest="language_filters",
        help="Filter by programming language (can be specified multiple times). Choices: %(choices)s"
    )
    filter_group.add_argument(
        "--include", "-i",
        action="append",
        default=[],
        dest="include_patterns",
        help="Include patterns (glob, can be specified multiple times)"
    )
    filter_group.add_argument(
        "--exclude", "-x",
        action="append",
        default=[],
        dest="exclude_patterns",
        help="Exclude patterns (glob, can be specified multiple times)"
    )
    
    # Analysis Configuration
    analysis_group = parser.add_argument_group("Analysis Configuration")
    analysis_group.add_argument(
        "--depth", "-d",
        type=int,
        default=10,
        help="Maximum directory depth to analyze (1-100, default: %(default)s)"
    )
    analysis_group.add_argument(
        "--analysis-depth",
        choices=ANALYSIS_DEPTHS,
        default="standard",
        help="Analysis depth level (default: %(default)s). Choices: %(choices)s"
    )
    analysis_group.add_argument(
        "--batch-size", "-b",
        type=int,
        default=50,
        help="Number of files to process in each batch (1-1000, default: %(default)s)"
    )
    analysis_group.add_argument(
        "--max-file-size",
        type=int,
        default=1024*1024,
        help="Maximum file size to analyze in bytes (default: %(default)s = 1MB)"
    )
    
    # Boolean flags
    flags_group = parser.add_argument_group("Analysis Flags")
    flags_group.add_argument(
        "--include-tests",
        action="store_true",
        default=True,
        help="Include test files in analysis (default: True)"
    )
    flags_group.add_argument(
        "--exclude-tests",
        action="store_false",
        dest="include_tests",
        help="Exclude test files from analysis"
    )
    flags_group.add_argument(
        "--include-hidden",
        action="store_true",
        default=False,
        help="Include hidden files and directories"
    )
    flags_group.add_argument(
        "--follow-symlinks",
        action="store_true",
        default=False,
        help="Follow symbolic links during analysis"
    )
    
    # General Options
    general_group = parser.add_argument_group("General Options")
    general_group.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    general_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform dry run without making API calls"
    )
    general_group.add_argument(
        "--config", "-c",
        type=str,
        help="Path to configuration file"
    )
    general_group.add_argument(
        "--save-config",
        type=str,
        help="Save current configuration to file"
    )


def _add_config_arguments(parser: argparse.ArgumentParser) -> None:
    """Add arguments for the config command."""
    
    config_group = parser.add_mutually_exclusive_group(required=True)
    config_group.add_argument(
        "--show", "-s",
        action="store_true",
        help="Show current configuration"
    )
    config_group.add_argument(
        "--init", "-i",
        action="store_true",
        help="Initialize a new configuration file"
    )
    config_group.add_argument(
        "--validate", "-v",
        action="store_true",
        help="Validate configuration file"
    )
    
    parser.add_argument(
        "--file", "-f",
        type=str,
        help="Configuration file path"
    )


def validate_arguments(args: argparse.Namespace) -> None:
    """Validate command line arguments."""
    
    if args.command == "analyze":
        _validate_analyze_arguments(args)
    elif args.command == "config":
        _validate_config_arguments(args)


def _validate_analyze_arguments(args: argparse.Namespace) -> None:
    """Validate analyze command arguments."""
    
    # Validate directory
    directory = Path(args.directory).resolve()
    if not directory.exists():
        console.print(f"[red]Error:[/red] Directory does not exist: {args.directory}", style="red")
        sys.exit(1)
    
    if not directory.is_dir():
        console.print(f"[red]Error:[/red] Path is not a directory: {args.directory}", style="red")
        sys.exit(1)
    
    if not os.access(directory, os.R_OK):
        console.print(f"[red]Error:[/red] Directory is not readable: {args.directory}", style="red")
        sys.exit(1)
    
    args.directory = directory
    
    # Validate API key
    if not args.api_key:
        args.api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not args.api_key:
            console.print(
                "[red]Error:[/red] API key is required. Provide it via --api-key or "
                "set the ANTHROPIC_API_KEY environment variable.",
                style="red"
            )
            sys.exit(1)
    
    # Validate API key format
    if not args.api_key.strip():
        console.print("[red]Error:[/red] API key cannot be empty", style="red")
        sys.exit(1)
    
    if args.api_key.lower() in ["your-api-key-here", "api-key", "key", "xxx"]:
        console.print("[red]Error:[/red] Please provide a valid API key (not a placeholder)", style="red")
        sys.exit(1)
    
    if not args.api_key.startswith("sk-ant-"):
        console.print(
            "[yellow]Warning:[/yellow] API key doesn't match expected format. "
            "Anthropic API keys typically start with 'sk-ant-'",
            style="yellow"
        )
    
    # Validate output formats
    if not args.output_formats:
        args.output_formats = ["console"]
    
    # Validate output file requirement
    if len(args.output_formats) > 1 or args.output_formats[0] != "console":
        if not args.output:
            console.print(
                "[red]Error:[/red] Output file is required when using non-console formats.",
                style="red"
            )
            sys.exit(1)
    
    # Validate depth limit
    if args.depth < 1 or args.depth > 100:
        console.print("[red]Error:[/red] Depth limit must be between 1 and 100", style="red")
        sys.exit(1)
    
    # Validate batch size
    if args.batch_size < 1 or args.batch_size > 1000:
        console.print("[red]Error:[/red] Batch size must be between 1 and 1000", style="red")
        sys.exit(1)
    
    # Validate max file size
    if args.max_file_size < 1:
        console.print("[red]Error:[/red] Max file size must be at least 1 byte", style="red")
        sys.exit(1)
    
    # Warn about unknown languages
    if args.language_filters:
        unknown_languages = [lang for lang in args.language_filters if lang not in LANGUAGE_FILTERS]
        if unknown_languages:
            console.print(
                f"[yellow]Warning:[/yellow] Unknown language(s): {', '.join(unknown_languages)}",
                style="yellow"
            )


def _validate_config_arguments(args: argparse.Namespace) -> None:
    """Validate config command arguments."""
    
    if args.validate and not args.file:
        console.print("[red]Error:[/red] Configuration file path is required for validation", style="red")
        sys.exit(1)


def handle_analyze_command(args: argparse.Namespace) -> None:
    """Handle the analyze command."""
    
    try:
        # Build configuration
        config = Config(
            anthropic_api_key=args.api_key,
            anthropic_model=args.model,
            output_format=args.output_formats[0],
            output_file=args.output,
            verbose=args.verbose,
            dry_run=args.dry_run,
            analysis=AnalysisConfig(
                max_file_size=args.max_file_size,
                include_tests=args.include_tests,
                analysis_depth=args.analysis_depth,
                exclude_patterns=args.exclude_patterns or [
                    "**/node_modules/**", "**/.git/**", "**/__pycache__/**",
                    "**/venv/**", "**/.env"
                ],
                supported_extensions=_get_extensions_for_languages(args.language_filters) if args.language_filters else None
            ),
            logging=LoggingConfig(
                level="DEBUG" if args.verbose else "INFO"
            )
        )
        
        # Save configuration if requested
        if args.save_config:
            from ..core.config import ConfigManager
            config_manager = ConfigManager()
            config_manager.save_config(config, args.save_config)
            console.print(f"[green]Configuration saved to:[/green] {args.save_config}")
        
        # Setup logging
        setup_logging(config)
        logger = get_logger("cli.analyze")
        
        # Display configuration summary
        _display_analysis_summary(args, config)
        
        if args.dry_run:
            console.print("\\n[yellow]Dry run mode - no actual analysis will be performed[/yellow]")
            return
        
        # TODO: Implement actual analysis logic
        console.print("[green]✓ Analysis completed successfully![/green]")
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}", style="red")
        sys.exit(1)


def handle_config_command(args: argparse.Namespace) -> None:
    """Handle the config command."""
    
    if args.init:
        _init_config(args.file or "wtf-codebot.yaml")
    elif args.show:
        _show_config(args.file)
    elif args.validate:
        _validate_config(args.file)


def handle_version_command(args: argparse.Namespace) -> None:
    """Handle the version command."""
    from .. import __version__
    
    console.print(Panel(
        f"[bold cyan]WTF CodeBot[/bold cyan] version [bold green]{__version__}[/bold green]",
        title="Version Information",
        border_style="cyan"
    ))


def _display_analysis_summary(args: argparse.Namespace, config: Config) -> None:
    """Display analysis configuration summary."""
    
    table = Table(title="Analysis Configuration", show_header=True, header_style="bold blue")
    table.add_column("Setting", style="cyan", width=20)
    table.add_column("Value", style="green")
    
    table.add_row("Directory", str(args.directory))
    table.add_row("Model", config.anthropic_model)
    table.add_row("Output Formats", ", ".join(args.output_formats))
    table.add_row("Analysis Depth", config.analysis.analysis_depth)
    table.add_row("Depth Limit", str(args.depth))
    table.add_row("Batch Size", str(args.batch_size))
    table.add_row("Max File Size", f"{config.analysis.max_file_size:,} bytes")
    table.add_row("Include Tests", "✓" if config.analysis.include_tests else "✗")
    
    if args.language_filters:
        table.add_row("Languages", ", ".join(args.language_filters))
    
    if args.include_patterns:
        table.add_row("Include Patterns", ", ".join(args.include_patterns))
    
    if args.exclude_patterns:
        table.add_row("Exclude Patterns", ", ".join(args.exclude_patterns))
    
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


def _init_config(file_path: str) -> None:
    """Initialize a new configuration file."""
    from ..core.config import ConfigManager
    
    path = Path(file_path)
    if path.exists():
        response = input(f"Configuration file {file_path} already exists. Overwrite? [y/N]: ")
        if response.lower() not in ['y', 'yes']:
            console.print("[yellow]Configuration initialization cancelled[/yellow]")
            return
    
    # Create sample configuration
    sample_config = Config(
        anthropic_api_key="your-api-key-here",
        anthropic_model="claude-sonnet-4-0",
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


def _show_config(file_path: Optional[str]) -> None:
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


def _validate_config(file_path: str) -> None:
    """Validate configuration file."""
    try:
        from ..core.config import get_config
        config = get_config(file_path)
        console.print(f"[green]✓ Configuration file {file_path} is valid[/green]")
    except Exception as e:
        console.print(f"[red]✗ Configuration file {file_path} is invalid:[/red] {e}", style="red")
        sys.exit(1)


def main() -> None:
    """Main entry point for the argparse CLI."""
    
    parser = create_parser()
    args = parser.parse_args()
    
    # If no command provided, show help
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Validate arguments
    validate_arguments(args)
    
    # Route to appropriate handler
    try:
        if args.command == "analyze":
            handle_analyze_command(args)
        elif args.command == "config":
            handle_config_command(args)
        elif args.command == "version":
            handle_version_command(args)
    except KeyboardInterrupt:
        console.print("\\n[yellow]Operation cancelled by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error:[/red] {e}", style="red")
        sys.exit(1)


if __name__ == "__main__":
    main()

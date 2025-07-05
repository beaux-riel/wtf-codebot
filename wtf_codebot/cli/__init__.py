"""CLI module for WTF CodeBot."""

from .main import main as click_main
from .enhanced_cli import main as typer_main
from .argparse_cli import main as argparse_main

__all__ = ["click_main", "typer_main", "argparse_main"]

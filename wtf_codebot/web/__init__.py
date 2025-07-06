"""
Web interface module for WTF Codebot.

This module provides a FastAPI-based web interface for the codebot,
allowing users to interactively browse codebases, manage exclusions,
and run analyses through a user-friendly web UI.
"""

from .server import app

__all__ = ['app']

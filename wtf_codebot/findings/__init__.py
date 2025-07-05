"""
Findings aggregation and management module.

This module provides unified handling of findings from multiple sources:
- Static analysis tools (linters, analyzers)
- AI-powered analysis (Claude pattern recognition)
- Dependency analysis results
- Custom analyzers

The module handles deduplication, severity scoring, and multi-format reporting.
"""

from .models import *
from .aggregator import *
from .deduplicator import *
from .reporter import *

__all__ = [
    'UnifiedFinding',
    'FindingSource',
    'FindingSeverity',
    'FindingType',
    'SourceLocation',
    'FindingsAggregator',
    'FindingsDeduplicator',
    'UnifiedReporter',
]

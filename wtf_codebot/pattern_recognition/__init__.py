"""
Pattern recognition module for design pattern detection and code analysis.
"""

from .batcher import CodeBatcher, BatchConfig
from .claude_client import ClaudePatternAnalyzer, PatternAnalysisResult
from .cost_tracker import CostTracker, Usage
from .patterns import PatternType, DesignPattern, AntiPattern, PatternAnalysisResults
from .orchestrator import PatternRecognitionOrchestrator, PatternRecognitionConfig, analyze_codebase_patterns

__all__ = [
    'CodeBatcher',
    'BatchConfig',
    'ClaudePatternAnalyzer',
    'PatternAnalysisResult',
    'CostTracker',
    'Usage',
    'PatternType',
    'DesignPattern',
    'AntiPattern',
    'PatternAnalysisResults',
    'PatternRecognitionOrchestrator',
    'PatternRecognitionConfig',
    'analyze_codebase_patterns',
]

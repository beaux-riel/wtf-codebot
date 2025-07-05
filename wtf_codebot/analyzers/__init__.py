"""Code analyzers for WTF CodeBot."""

from .base import (
    BaseAnalyzer, 
    LinterBasedAnalyzer,
    AnalysisResult, 
    Finding, 
    Metric,
    PatternType, 
    Severity
)
from .python_analyzer import PythonAnalyzer
from .javascript_analyzer import JavaScriptAnalyzer
from .registry import (
    AnalyzerRegistry,
    get_registry,
    register_analyzer,
    analyze_file,
    analyze_codebase
)

__all__ = [
    # Base classes
    'BaseAnalyzer',
    'LinterBasedAnalyzer', 
    'AnalysisResult',
    'Finding',
    'Metric',
    'PatternType',
    'Severity',
    
    # Specific analyzers
    'PythonAnalyzer',
    'JavaScriptAnalyzer',
    
    # Registry
    'AnalyzerRegistry',
    'get_registry',
    'register_analyzer',
    'analyze_file',
    'analyze_codebase'
]

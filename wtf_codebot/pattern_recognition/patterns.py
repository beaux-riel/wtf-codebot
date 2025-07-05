"""
Pattern types and data models for design pattern recognition.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path


class PatternType(Enum):
    """Types of patterns that can be detected."""
    
    # Design Patterns
    SINGLETON = "singleton"
    FACTORY = "factory"
    OBSERVER = "observer"
    STRATEGY = "strategy"
    COMMAND = "command"
    ADAPTER = "adapter"
    DECORATOR = "decorator"
    FACADE = "facade"
    BUILDER = "builder"
    PROTOTYPE = "prototype"
    ABSTRACT_FACTORY = "abstract_factory"
    BRIDGE = "bridge"
    COMPOSITE = "composite"
    FLYWEIGHT = "flyweight"
    PROXY = "proxy"
    CHAIN_OF_RESPONSIBILITY = "chain_of_responsibility"
    INTERPRETER = "interpreter"
    ITERATOR = "iterator"
    MEDIATOR = "mediator"
    MEMENTO = "memento"
    STATE = "state"
    TEMPLATE_METHOD = "template_method"
    VISITOR = "visitor"
    
    # Anti-patterns
    GOD_OBJECT = "god_object"
    SPAGHETTI_CODE = "spaghetti_code"
    MAGIC_NUMBERS = "magic_numbers"
    DEAD_CODE = "dead_code"
    DUPLICATE_CODE = "duplicate_code"
    LONG_PARAMETER_LIST = "long_parameter_list"
    LARGE_CLASS = "large_class"
    FEATURE_ENVY = "feature_envy"
    INAPPROPRIATE_INTIMACY = "inappropriate_intimacy"
    REFUSED_BEQUEST = "refused_bequest"
    LAZY_CLASS = "lazy_class"
    DATA_CLASS = "data_class"
    SWITCH_STATEMENTS = "switch_statements"
    TEMPORARY_FIELD = "temporary_field"
    MESSAGE_CHAINS = "message_chains"
    MIDDLE_MAN = "middle_man"
    DIVERGENT_CHANGE = "divergent_change"
    SHOTGUN_SURGERY = "shotgun_surgery"
    PARALLEL_INHERITANCE = "parallel_inheritance"
    COMMENTS = "comments"
    LONG_METHOD = "long_method"
    
    # Code Quality Issues
    CYCLOMATIC_COMPLEXITY = "cyclomatic_complexity"
    COGNITIVE_COMPLEXITY = "cognitive_complexity"
    MAINTAINABILITY_INDEX = "maintainability_index"
    TECHNICAL_DEBT = "technical_debt"
    SECURITY_VULNERABILITY = "security_vulnerability"
    PERFORMANCE_ISSUE = "performance_issue"


@dataclass
class PatternMatch:
    """Represents a detected pattern match."""
    pattern_type: PatternType
    confidence: float  # 0.0 to 1.0
    file_path: Path
    line_start: int
    line_end: int
    description: str
    evidence: List[str]
    severity: str  # info, warning, error, critical
    impact: str  # low, medium, high, critical
    effort: str  # low, medium, high
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'pattern_type': self.pattern_type.value,
            'confidence': self.confidence,
            'file_path': str(self.file_path),
            'line_start': self.line_start,
            'line_end': self.line_end,
            'description': self.description,
            'evidence': self.evidence,
            'severity': self.severity,
            'impact': self.impact,
            'effort': self.effort
        }


@dataclass
class DesignPattern(PatternMatch):
    """Represents a detected design pattern."""
    benefits: List[str]
    use_cases: List[str]
    related_patterns: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        base_dict = super().to_dict()
        base_dict.update({
            'benefits': self.benefits,
            'use_cases': self.use_cases,
            'related_patterns': self.related_patterns
        })
        return base_dict


@dataclass
class AntiPattern(PatternMatch):
    """Represents a detected anti-pattern."""
    problems: List[str]
    solutions: List[str]
    refactoring_suggestions: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        base_dict = super().to_dict()
        base_dict.update({
            'problems': self.problems,
            'solutions': self.solutions,
            'refactoring_suggestions': self.refactoring_suggestions
        })
        return base_dict


@dataclass
class PatternAnalysisResults:
    """Container for pattern analysis results."""
    design_patterns: List[DesignPattern]
    anti_patterns: List[AntiPattern]
    code_quality_issues: List[PatternMatch]
    total_files_analyzed: int
    total_lines_analyzed: int
    analysis_duration: float
    
    def get_all_patterns(self) -> List[PatternMatch]:
        """Get all pattern matches combined."""
        return self.design_patterns + self.anti_patterns + self.code_quality_issues
    
    def get_patterns_by_severity(self, severity: str) -> List[PatternMatch]:
        """Get patterns filtered by severity."""
        return [p for p in self.get_all_patterns() if p.severity == severity]
    
    def get_patterns_by_file(self, file_path: Path) -> List[PatternMatch]:
        """Get patterns filtered by file."""
        return [p for p in self.get_all_patterns() if p.file_path == file_path]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'design_patterns': [p.to_dict() for p in self.design_patterns],
            'anti_patterns': [p.to_dict() for p in self.anti_patterns],
            'code_quality_issues': [p.to_dict() for p in self.code_quality_issues],
            'total_files_analyzed': self.total_files_analyzed,
            'total_lines_analyzed': self.total_lines_analyzed,
            'analysis_duration': self.analysis_duration,
            'summary': {
                'total_patterns': len(self.get_all_patterns()),
                'design_patterns_count': len(self.design_patterns),
                'anti_patterns_count': len(self.anti_patterns),
                'code_quality_issues_count': len(self.code_quality_issues),
                'critical_issues': len(self.get_patterns_by_severity('critical')),
                'high_issues': len(self.get_patterns_by_severity('error')),
                'medium_issues': len(self.get_patterns_by_severity('warning')),
                'low_issues': len(self.get_patterns_by_severity('info'))
            }
        }

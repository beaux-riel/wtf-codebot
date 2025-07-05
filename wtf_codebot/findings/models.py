"""
Unified findings data models for aggregating AI and static analysis results.

This module defines the core data structures for representing findings from
various sources including linters, analyzers, and AI analysis tools.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Union
import hashlib
import json


class FindingSource(Enum):
    """Source of a finding."""
    STATIC_ANALYZER = "static_analyzer"
    LINTER = "linter"
    AI_ANALYSIS = "ai_analysis"
    DEPENDENCY_ANALYSIS = "dependency_analysis"
    PATTERN_RECOGNITION = "pattern_recognition"
    SECURITY_SCANNER = "security_scanner"
    CUSTOM = "custom"


class FindingSeverity(Enum):
    """Severity levels for findings."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    def score(self) -> int:
        """Get numeric score for severity (higher = more severe)."""
        scores = {
            FindingSeverity.INFO: 1,
            FindingSeverity.LOW: 2,
            FindingSeverity.MEDIUM: 3,
            FindingSeverity.HIGH: 4,
            FindingSeverity.CRITICAL: 5
        }
        return scores[self]


class FindingType(Enum):
    """Types of findings."""
    # Code Quality
    CODE_SMELL = "code_smell"
    DESIGN_PATTERN = "design_pattern"
    ANTI_PATTERN = "anti_pattern"
    CYCLOMATIC_COMPLEXITY = "cyclomatic_complexity"
    COGNITIVE_COMPLEXITY = "cognitive_complexity"
    MAINTAINABILITY = "maintainability"
    
    # Security
    SECURITY_VULNERABILITY = "security_vulnerability"
    AUTHENTICATION_ISSUE = "authentication_issue"
    AUTHORIZATION_ISSUE = "authorization_issue"
    INPUT_VALIDATION = "input_validation"
    CRYPTOGRAPHY_ISSUE = "cryptography_issue"
    
    # Performance
    PERFORMANCE_ISSUE = "performance_issue"
    MEMORY_LEAK = "memory_leak"
    INEFFICIENT_ALGORITHM = "inefficient_algorithm"
    
    # Dependencies
    OUTDATED_DEPENDENCY = "outdated_dependency"
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"
    LICENSE_ISSUE = "license_issue"
    UNUSED_DEPENDENCY = "unused_dependency"
    
    # Syntax & Style
    SYNTAX_ERROR = "syntax_error"
    STYLE_VIOLATION = "style_violation"
    FORMATTING_ISSUE = "formatting_issue"
    NAMING_CONVENTION = "naming_convention"
    
    # Documentation
    MISSING_DOCUMENTATION = "missing_documentation"
    OUTDATED_DOCUMENTATION = "outdated_documentation"
    
    # Testing
    MISSING_TESTS = "missing_tests"
    POOR_TEST_COVERAGE = "poor_test_coverage"
    FLAKY_TEST = "flaky_test"
    
    # Generic
    ERROR = "error"
    WARNING = "warning"
    OTHER = "other"


@dataclass
class SourceLocation:
    """Represents a location in source code."""
    file_path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    column_start: Optional[int] = None
    column_end: Optional[int] = None
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    
    def __str__(self) -> str:
        """String representation of location."""
        location_parts = [self.file_path]
        
        if self.line_start is not None:
            if self.line_end is not None and self.line_end != self.line_start:
                location_parts.append(f":{self.line_start}-{self.line_end}")
            else:
                location_parts.append(f":{self.line_start}")
                
        if self.column_start is not None:
            if self.column_end is not None and self.column_end != self.column_start:
                location_parts.append(f":{self.column_start}-{self.column_end}")
            else:
                location_parts.append(f":{self.column_start}")
        
        return "".join(location_parts)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'file_path': self.file_path,
            'line_start': self.line_start,
            'line_end': self.line_end,
            'column_start': self.column_start,
            'column_end': self.column_end,
            'function_name': self.function_name,
            'class_name': self.class_name
        }


@dataclass
class UnifiedFinding:
    """
    Unified representation of a finding from any source.
    
    This class normalizes findings from static analyzers, linters, 
    AI analysis, and other sources into a common format.
    """
    # Core identification
    id: str = field(default="")
    title: str = ""
    description: str = ""
    
    # Classification
    finding_type: FindingType = FindingType.OTHER
    severity: FindingSeverity = FindingSeverity.INFO
    confidence: float = 1.0  # 0.0 to 1.0
    
    # Source information
    source: FindingSource = FindingSource.STATIC_ANALYZER
    tool_name: str = ""
    rule_id: Optional[str] = None
    
    # Location
    location: SourceLocation = field(default_factory=lambda: SourceLocation(""))
    
    # Content and context
    affected_code: Optional[str] = None
    message: str = ""
    suggestion: str = ""
    fix_recommendation: str = ""
    
    # Additional data
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    
    # Analysis information
    detected_at: datetime = field(default_factory=datetime.now)
    impact: str = "medium"  # low, medium, high, critical
    effort_to_fix: str = "medium"  # low, medium, high
    
    # Relationships
    related_findings: List[str] = field(default_factory=list)  # IDs of related findings
    duplicate_of: Optional[str] = None  # ID of original finding if this is a duplicate
    
    def __post_init__(self):
        """Post-initialization processing."""
        if not self.id:
            self.id = self._generate_id()
        
        # Ensure tags is a set
        if isinstance(self.tags, list):
            self.tags = set(self.tags)
    
    def _generate_id(self) -> str:
        """Generate a unique ID for this finding."""
        # Create a hash based on key characteristics
        content = f"{self.finding_type.value}:{self.location.file_path}:{self.location.line_start}:{self.title}:{self.rule_id}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def is_duplicate_of(self, other: 'UnifiedFinding', 
                       location_tolerance: int = 2) -> bool:
        """
        Check if this finding is a duplicate of another.
        
        Args:
            other: Other finding to compare with
            location_tolerance: Line number tolerance for location matching
            
        Returns:
            True if this finding is likely a duplicate
        """
        # Must be same file
        if self.location.file_path != other.location.file_path:
            return False
        
        # Must be same type or compatible types
        if not self._are_compatible_types(other):
            return False
        
        # Check location proximity
        if not self._are_locations_close(other, location_tolerance):
            return False
        
        # Check content similarity
        return self._are_contents_similar(other)
    
    def _are_compatible_types(self, other: 'UnifiedFinding') -> bool:
        """Check if finding types are compatible for deduplication."""
        # Exact match
        if self.finding_type == other.finding_type:
            return True
        
        # Compatible security types
        security_types = {
            FindingType.SECURITY_VULNERABILITY,
            FindingType.AUTHENTICATION_ISSUE,
            FindingType.AUTHORIZATION_ISSUE,
            FindingType.INPUT_VALIDATION,
            FindingType.CRYPTOGRAPHY_ISSUE
        }
        
        if self.finding_type in security_types and other.finding_type in security_types:
            return True
        
        # Compatible quality types
        quality_types = {
            FindingType.CODE_SMELL,
            FindingType.ANTI_PATTERN,
            FindingType.MAINTAINABILITY
        }
        
        if self.finding_type in quality_types and other.finding_type in quality_types:
            return True
        
        return False
    
    def _are_locations_close(self, other: 'UnifiedFinding', 
                           tolerance: int) -> bool:
        """Check if locations are close enough to be duplicates."""
        if self.location.line_start is None or other.location.line_start is None:
            # If either has no line number, check function/class
            return (self.location.function_name == other.location.function_name or
                   self.location.class_name == other.location.class_name)
        
        line_diff = abs(self.location.line_start - other.location.line_start)
        return line_diff <= tolerance
    
    def _are_contents_similar(self, other: 'UnifiedFinding') -> bool:
        """Check if finding contents are similar."""
        # Check rule IDs
        if self.rule_id and other.rule_id and self.rule_id == other.rule_id:
            return True
        
        # Check title similarity (simple substring check)
        if self.title and other.title:
            title1 = self.title.lower()
            title2 = other.title.lower()
            if title1 in title2 or title2 in title1:
                return True
        
        # Check message similarity
        if self.message and other.message:
            msg1 = self.message.lower()
            msg2 = other.message.lower()
            if msg1 in msg2 or msg2 in msg1:
                return True
        
        return False
    
    def merge_with(self, other: 'UnifiedFinding') -> 'UnifiedFinding':
        """
        Merge this finding with another duplicate finding.
        
        Args:
            other: Other finding to merge with
            
        Returns:
            Merged finding with combined information
        """
        # Choose the higher severity
        merged_severity = (self.severity if self.severity.score() >= other.severity.score() 
                         else other.severity)
        
        # Choose the higher confidence
        merged_confidence = max(self.confidence, other.confidence)
        
        # Combine descriptions
        descriptions = []
        if self.description:
            descriptions.append(self.description)
        if other.description and other.description != self.description:
            descriptions.append(other.description)
        
        # Combine suggestions
        suggestions = []
        if self.suggestion:
            suggestions.append(self.suggestion)
        if other.suggestion and other.suggestion != self.suggestion:
            suggestions.append(other.suggestion)
        
        # Combine metadata
        merged_metadata = dict(self.metadata)
        merged_metadata.update(other.metadata)
        
        # Add source information to metadata
        merged_metadata['merged_from'] = {
            'sources': [self.source.value, other.source.value],
            'tools': [self.tool_name, other.tool_name],
            'rule_ids': [r for r in [self.rule_id, other.rule_id] if r]
        }
        
        # Combine tags
        merged_tags = self.tags.union(other.tags)
        
        return UnifiedFinding(
            id=self.id,  # Keep original ID
            title=self.title or other.title,
            description=" | ".join(descriptions),
            finding_type=self.finding_type,
            severity=merged_severity,
            confidence=merged_confidence,
            source=self.source,  # Keep primary source
            tool_name=f"{self.tool_name}, {other.tool_name}",
            rule_id=self.rule_id or other.rule_id,
            location=self.location,
            affected_code=self.affected_code or other.affected_code,
            message=self.message or other.message,
            suggestion=" | ".join(suggestions),
            fix_recommendation=self.fix_recommendation or other.fix_recommendation,
            metadata=merged_metadata,
            tags=merged_tags,
            detected_at=min(self.detected_at, other.detected_at),
            impact=self.impact if self.severity.score() >= other.severity.score() else other.impact,
            effort_to_fix=self.effort_to_fix,
            related_findings=list(set(self.related_findings + other.related_findings))
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'finding_type': self.finding_type.value,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'source': self.source.value,
            'tool_name': self.tool_name,
            'rule_id': self.rule_id,
            'location': self.location.to_dict(),
            'affected_code': self.affected_code,
            'message': self.message,
            'suggestion': self.suggestion,
            'fix_recommendation': self.fix_recommendation,
            'metadata': self.metadata,
            'tags': list(self.tags),
            'detected_at': self.detected_at.isoformat(),
            'impact': self.impact,
            'effort_to_fix': self.effort_to_fix,
            'related_findings': self.related_findings,
            'duplicate_of': self.duplicate_of
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UnifiedFinding':
        """Create finding from dictionary."""
        # Convert enum fields
        finding_type = FindingType(data.get('finding_type', 'other'))
        severity = FindingSeverity(data.get('severity', 'info'))
        source = FindingSource(data.get('source', 'static_analyzer'))
        
        # Convert location
        location_data = data.get('location', {})
        location = SourceLocation(**location_data)
        
        # Convert datetime
        detected_at = datetime.fromisoformat(data.get('detected_at', datetime.now().isoformat()))
        
        # Convert tags
        tags = set(data.get('tags', []))
        
        return cls(
            id=data.get('id', ''),
            title=data.get('title', ''),
            description=data.get('description', ''),
            finding_type=finding_type,
            severity=severity,
            confidence=data.get('confidence', 1.0),
            source=source,
            tool_name=data.get('tool_name', ''),
            rule_id=data.get('rule_id'),
            location=location,
            affected_code=data.get('affected_code'),
            message=data.get('message', ''),
            suggestion=data.get('suggestion', ''),
            fix_recommendation=data.get('fix_recommendation', ''),
            metadata=data.get('metadata', {}),
            tags=tags,
            detected_at=detected_at,
            impact=data.get('impact', 'medium'),
            effort_to_fix=data.get('effort_to_fix', 'medium'),
            related_findings=data.get('related_findings', []),
            duplicate_of=data.get('duplicate_of')
        )


@dataclass
class FindingsCollection:
    """Collection of unified findings with analysis metadata."""
    findings: List[UnifiedFinding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    
    def add_finding(self, finding: UnifiedFinding) -> None:
        """Add a finding to the collection."""
        self.findings.append(finding)
    
    def get_by_severity(self, severity: FindingSeverity) -> List[UnifiedFinding]:
        """Get findings by severity level."""
        return [f for f in self.findings if f.severity == severity]
    
    def get_by_type(self, finding_type: FindingType) -> List[UnifiedFinding]:
        """Get findings by type."""
        return [f for f in self.findings if f.finding_type == finding_type]
    
    def get_by_source(self, source: FindingSource) -> List[UnifiedFinding]:
        """Get findings by source."""
        return [f for f in self.findings if f.source == source]
    
    def get_by_file(self, file_path: str) -> List[UnifiedFinding]:
        """Get findings for a specific file."""
        return [f for f in self.findings if f.location.file_path == file_path]
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics for the collection."""
        total = len(self.findings)
        if total == 0:
            return {'total': 0}
        
        # Count by severity
        severity_counts = {}
        for severity in FindingSeverity:
            count = len(self.get_by_severity(severity))
            severity_counts[severity.value] = count
        
        # Count by type
        type_counts = {}
        for finding_type in FindingType:
            count = len(self.get_by_type(finding_type))
            if count > 0:
                type_counts[finding_type.value] = count
        
        # Count by source
        source_counts = {}
        for source in FindingSource:
            count = len(self.get_by_source(source))
            if count > 0:
                source_counts[source.value] = count
        
        # Files affected
        affected_files = set(f.location.file_path for f in self.findings)
        
        return {
            'total': total,
            'severity_counts': severity_counts,
            'type_counts': type_counts,
            'source_counts': source_counts,
            'affected_files_count': len(affected_files),
            'affected_files': sorted(affected_files)
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'findings': [f.to_dict() for f in self.findings],
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat(),
            'summary': self.get_summary_stats()
        }

"""
Findings aggregator for merging results from multiple analysis sources.

This module converts findings from various sources (linters, analyzers, AI analysis,
dependency scanners) into a unified format and aggregates them for reporting.
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from datetime import datetime

from .models import (
    UnifiedFinding, FindingsCollection, SourceLocation, 
    FindingSource, FindingSeverity, FindingType
)

# Import existing analyzers and data structures
try:
    from ..analyzers.base import AnalysisResult, Finding as StaticFinding, Severity, PatternType
    from ..analyzers.dependency_analyzer import DependencyAnalysisResult, VulnerabilityInfo
    from ..pattern_recognition.patterns import (
        PatternMatch, DesignPattern, AntiPattern, PatternAnalysisResults,
        PatternType as AIPatternType
    )
except ImportError as e:
    logging.warning(f"Could not import some analysis modules: {e}")
    # Define fallback classes for testing
    StaticFinding = None
    AnalysisResult = None
    DependencyAnalysisResult = None
    PatternMatch = None

logger = logging.getLogger(__name__)


class FindingsAggregator:
    """
    Aggregates findings from multiple analysis sources into a unified format.
    
    Supports:
    - Static analyzer results (base.AnalysisResult)
    - Dependency analysis results (DependencyAnalysisResult)
    - AI pattern recognition results (PatternAnalysisResults)
    - Custom findings
    """
    
    def __init__(self):
        """Initialize the aggregator."""
        self.findings_collection = FindingsCollection()
        self._source_priority = {
            FindingSource.SECURITY_SCANNER: 5,
            FindingSource.AI_ANALYSIS: 4,
            FindingSource.DEPENDENCY_ANALYSIS: 3,
            FindingSource.STATIC_ANALYZER: 2,
            FindingSource.LINTER: 1,
            FindingSource.CUSTOM: 1
        }
    
    def add_static_analysis_results(self, results: 'AnalysisResult', 
                                  tool_name: str = "static_analyzer") -> None:
        """
        Add findings from static analysis results.
        
        Args:
            results: Static analysis results
            tool_name: Name of the analyzer tool
        """
        if not results or not hasattr(results, 'findings'):
            logger.warning("Invalid static analysis results provided")
            return
        
        for finding in results.findings:
            unified_finding = self._convert_static_finding(finding, tool_name)
            if unified_finding:
                self.findings_collection.add_finding(unified_finding)
        
        logger.info(f"Added {len(results.findings)} findings from {tool_name}")
    
    def add_dependency_analysis_results(self, results: List['DependencyAnalysisResult']) -> None:
        """
        Add findings from dependency analysis results.
        
        Args:
            results: List of dependency analysis results
        """
        if not results:
            logger.warning("No dependency analysis results provided")
            return
        
        findings_added = 0
        for result in results:
            # Convert vulnerability findings
            for vuln in result.vulnerabilities:
                unified_finding = self._convert_vulnerability_finding(vuln, result.file_path)
                if unified_finding:
                    self.findings_collection.add_finding(unified_finding)
                    findings_added += 1
            
            # Convert outdated package findings
            for package in result.outdated_packages:
                unified_finding = self._convert_outdated_package_finding(package, result.file_path)
                if unified_finding:
                    self.findings_collection.add_finding(unified_finding)
                    findings_added += 1
        
        logger.info(f"Added {findings_added} dependency findings")
    
    def add_ai_analysis_results(self, results: 'PatternAnalysisResults', 
                              tool_name: str = "claude_pattern_analyzer") -> None:
        """
        Add findings from AI pattern analysis results.
        
        Args:
            results: AI pattern analysis results
            tool_name: Name of the AI tool
        """
        if not results:
            logger.warning("No AI analysis results provided")
            return
        
        findings_added = 0
        
        # Convert design patterns
        for pattern in results.design_patterns:
            unified_finding = self._convert_design_pattern(pattern, tool_name)
            if unified_finding:
                self.findings_collection.add_finding(unified_finding)
                findings_added += 1
        
        # Convert anti-patterns
        for anti_pattern in results.anti_patterns:
            unified_finding = self._convert_anti_pattern(anti_pattern, tool_name)
            if unified_finding:
                self.findings_collection.add_finding(unified_finding)
                findings_added += 1
        
        # Convert code quality issues
        for issue in results.code_quality_issues:
            unified_finding = self._convert_code_quality_issue(issue, tool_name)
            if unified_finding:
                self.findings_collection.add_finding(unified_finding)
                findings_added += 1
        
        logger.info(f"Added {findings_added} AI analysis findings from {tool_name}")
    
    def add_linter_results(self, output: str, file_path: str, 
                          tool_name: str, parser_func: callable) -> None:
        """
        Add findings from linter output.
        
        Args:
            output: Raw linter output
            file_path: File that was analyzed
            tool_name: Name of the linter
            parser_func: Function to parse linter output into findings
        """
        try:
            raw_findings = parser_func(output)
            for raw_finding in raw_findings:
                unified_finding = self._convert_linter_finding(raw_finding, file_path, tool_name)
                if unified_finding:
                    self.findings_collection.add_finding(unified_finding)
            
            logger.info(f"Added {len(raw_findings)} findings from {tool_name}")
        except Exception as e:
            logger.error(f"Failed to parse {tool_name} output: {e}")
    
    def add_custom_finding(self, finding: UnifiedFinding) -> None:
        """
        Add a custom unified finding.
        
        Args:
            finding: Pre-constructed unified finding
        """
        self.findings_collection.add_finding(finding)
    
    def get_findings_collection(self) -> FindingsCollection:
        """Get the aggregated findings collection."""
        return self.findings_collection
    
    def clear_findings(self) -> None:
        """Clear all findings from the collection."""
        self.findings_collection = FindingsCollection()
    
    # Conversion methods for different source types
    
    def _convert_static_finding(self, finding: 'StaticFinding', tool_name: str) -> Optional[UnifiedFinding]:
        """Convert static analysis finding to unified format."""
        if not finding:
            return None
        
        # Map severity
        severity_map = {
            'INFO': FindingSeverity.INFO,
            'WARNING': FindingSeverity.MEDIUM,
            'ERROR': FindingSeverity.HIGH,
            'CRITICAL': FindingSeverity.CRITICAL
        }
        
        severity = FindingSeverity.MEDIUM
        if hasattr(finding, 'severity'):
            severity_str = str(finding.severity).upper()
            severity = severity_map.get(severity_str, FindingSeverity.MEDIUM)
        
        # Map finding type
        finding_type = FindingType.CODE_SMELL
        if hasattr(finding, 'pattern_type'):
            if 'design_pattern' in str(finding.pattern_type).lower():
                finding_type = FindingType.DESIGN_PATTERN
            elif 'anti_pattern' in str(finding.pattern_type).lower():
                finding_type = FindingType.ANTI_PATTERN
        
        # Create location
        location = SourceLocation(
            file_path=getattr(finding, 'file_path', ''),
            line_start=getattr(finding, 'line_number', None),
            column_start=getattr(finding, 'column_number', None)
        )
        
        return UnifiedFinding(
            title=getattr(finding, 'pattern_name', 'Static Analysis Finding'),
            description=getattr(finding, 'description', ''),
            finding_type=finding_type,
            severity=severity,
            source=FindingSource.STATIC_ANALYZER,
            tool_name=tool_name,
            rule_id=getattr(finding, 'pattern_name', None),
            location=location,
            message=getattr(finding, 'message', ''),
            suggestion=getattr(finding, 'suggestion', ''),
            metadata=getattr(finding, 'metadata', {})
        )
    
    def _convert_vulnerability_finding(self, vuln: 'VulnerabilityInfo', 
                                     file_path: str) -> Optional[UnifiedFinding]:
        """Convert vulnerability info to unified finding."""
        if not vuln:
            return None
        
        # Map severity
        severity_map = {
            'low': FindingSeverity.LOW,
            'medium': FindingSeverity.MEDIUM,
            'high': FindingSeverity.HIGH,
            'critical': FindingSeverity.CRITICAL
        }
        
        severity = severity_map.get(vuln.severity.lower(), FindingSeverity.MEDIUM)
        
        # Create description
        description_parts = []
        if vuln.description:
            description_parts.append(vuln.description)
        if vuln.affected_versions:
            description_parts.append(f"Affected versions: {', '.join(vuln.affected_versions)}")
        if vuln.fixed_versions:
            description_parts.append(f"Fixed in: {', '.join(vuln.fixed_versions)}")
        
        # Create metadata
        metadata = {
            'cve_id': vuln.cve_id,
            'advisory_id': vuln.advisory_id,
            'source': vuln.source,
            'published_date': vuln.published_date.isoformat() if vuln.published_date else None,
            'affected_versions': vuln.affected_versions,
            'fixed_versions': vuln.fixed_versions
        }
        
        return UnifiedFinding(
            title=vuln.title or f"Security Vulnerability {vuln.cve_id or vuln.advisory_id}",
            description=" | ".join(description_parts),
            finding_type=FindingType.VULNERABLE_DEPENDENCY,
            severity=severity,
            source=FindingSource.DEPENDENCY_ANALYSIS,
            tool_name="dependency_analyzer",
            rule_id=vuln.cve_id or vuln.advisory_id,
            location=SourceLocation(file_path=file_path),
            message=f"Vulnerable dependency detected: {vuln.title}",
            metadata=metadata,
            tags={'security', 'dependency', 'vulnerability'}
        )
    
    def _convert_outdated_package_finding(self, package: str, 
                                        file_path: str) -> Optional[UnifiedFinding]:
        """Convert outdated package to unified finding."""
        return UnifiedFinding(
            title=f"Outdated Package: {package}",
            description=f"Package {package} is outdated and should be updated",
            finding_type=FindingType.OUTDATED_DEPENDENCY,
            severity=FindingSeverity.LOW,
            source=FindingSource.DEPENDENCY_ANALYSIS,
            tool_name="dependency_analyzer",
            location=SourceLocation(file_path=file_path),
            message=f"Package {package} is outdated",
            suggestion="Update to the latest stable version",
            tags={'dependency', 'outdated', 'maintenance'}
        )
    
    def _convert_design_pattern(self, pattern: 'DesignPattern', 
                              tool_name: str) -> Optional[UnifiedFinding]:
        """Convert design pattern to unified finding."""
        if not pattern:
            return None
        
        severity_map = {
            'info': FindingSeverity.INFO,
            'warning': FindingSeverity.LOW,
            'error': FindingSeverity.MEDIUM,
            'critical': FindingSeverity.HIGH
        }
        
        severity = severity_map.get(pattern.severity.lower(), FindingSeverity.INFO)
        
        # Create location
        location = SourceLocation(
            file_path=str(pattern.file_path),
            line_start=pattern.line_start,
            line_end=pattern.line_end
        )
        
        # Create metadata
        metadata = {
            'benefits': getattr(pattern, 'benefits', []),
            'use_cases': getattr(pattern, 'use_cases', []),
            'related_patterns': getattr(pattern, 'related_patterns', []),
            'evidence': pattern.evidence,
            'impact': pattern.impact,
            'effort': pattern.effort
        }
        
        return UnifiedFinding(
            title=f"Design Pattern: {pattern.pattern_type.value.replace('_', ' ').title()}",
            description=pattern.description,
            finding_type=FindingType.DESIGN_PATTERN,
            severity=severity,
            confidence=pattern.confidence,
            source=FindingSource.AI_ANALYSIS,
            tool_name=tool_name,
            rule_id=pattern.pattern_type.value,
            location=location,
            message=f"Design pattern detected: {pattern.pattern_type.value}",
            metadata=metadata,
            impact=pattern.impact,
            effort_to_fix=pattern.effort,
            tags={'design-pattern', 'architecture', 'ai-detected'}
        )
    
    def _convert_anti_pattern(self, anti_pattern: 'AntiPattern', 
                            tool_name: str) -> Optional[UnifiedFinding]:
        """Convert anti-pattern to unified finding."""
        if not anti_pattern:
            return None
        
        severity_map = {
            'info': FindingSeverity.INFO,
            'warning': FindingSeverity.MEDIUM,
            'error': FindingSeverity.HIGH,
            'critical': FindingSeverity.CRITICAL
        }
        
        severity = severity_map.get(anti_pattern.severity.lower(), FindingSeverity.MEDIUM)
        
        # Create location
        location = SourceLocation(
            file_path=str(anti_pattern.file_path),
            line_start=anti_pattern.line_start,
            line_end=anti_pattern.line_end
        )
        
        # Create metadata
        metadata = {
            'problems': getattr(anti_pattern, 'problems', []),
            'solutions': getattr(anti_pattern, 'solutions', []),
            'refactoring_suggestions': getattr(anti_pattern, 'refactoring_suggestions', []),
            'evidence': anti_pattern.evidence,
            'impact': anti_pattern.impact,
            'effort': anti_pattern.effort
        }
        
        # Create suggestion from solutions
        suggestions = getattr(anti_pattern, 'solutions', [])
        suggestion = "; ".join(suggestions) if suggestions else ""
        
        return UnifiedFinding(
            title=f"Anti-Pattern: {anti_pattern.pattern_type.value.replace('_', ' ').title()}",
            description=anti_pattern.description,
            finding_type=FindingType.ANTI_PATTERN,
            severity=severity,
            confidence=anti_pattern.confidence,
            source=FindingSource.AI_ANALYSIS,
            tool_name=tool_name,
            rule_id=anti_pattern.pattern_type.value,
            location=location,
            message=f"Anti-pattern detected: {anti_pattern.pattern_type.value}",
            suggestion=suggestion,
            metadata=metadata,
            impact=anti_pattern.impact,
            effort_to_fix=anti_pattern.effort,
            tags={'anti-pattern', 'code-smell', 'refactoring', 'ai-detected'}
        )
    
    def _convert_code_quality_issue(self, issue: 'PatternMatch', 
                                  tool_name: str) -> Optional[UnifiedFinding]:
        """Convert code quality issue to unified finding."""
        if not issue:
            return None
        
        severity_map = {
            'info': FindingSeverity.INFO,
            'warning': FindingSeverity.MEDIUM,
            'error': FindingSeverity.HIGH,
            'critical': FindingSeverity.CRITICAL
        }
        
        severity = severity_map.get(issue.severity.lower(), FindingSeverity.MEDIUM)
        
        # Map to appropriate finding type
        finding_type_map = {
            'security_vulnerability': FindingType.SECURITY_VULNERABILITY,
            'performance_issue': FindingType.PERFORMANCE_ISSUE,
            'cyclomatic_complexity': FindingType.CYCLOMATIC_COMPLEXITY,
            'cognitive_complexity': FindingType.COGNITIVE_COMPLEXITY,
            'maintainability': FindingType.MAINTAINABILITY
        }
        
        finding_type = finding_type_map.get(
            issue.pattern_type.value if hasattr(issue.pattern_type, 'value') else str(issue.pattern_type),
            FindingType.CODE_SMELL
        )
        
        # Create location
        location = SourceLocation(
            file_path=str(issue.file_path),
            line_start=issue.line_start,
            line_end=issue.line_end
        )
        
        # Create metadata
        metadata = {
            'evidence': issue.evidence,
            'impact': issue.impact,
            'effort': issue.effort
        }
        
        return UnifiedFinding(
            title=f"Code Quality: {issue.pattern_type.value.replace('_', ' ').title()}" if hasattr(issue.pattern_type, 'value') else str(issue.pattern_type),
            description=issue.description,
            finding_type=finding_type,
            severity=severity,
            confidence=issue.confidence,
            source=FindingSource.AI_ANALYSIS,
            tool_name=tool_name,
            rule_id=issue.pattern_type.value if hasattr(issue.pattern_type, 'value') else str(issue.pattern_type),
            location=location,
            message=f"Code quality issue: {issue.pattern_type.value if hasattr(issue.pattern_type, 'value') else str(issue.pattern_type)}",
            metadata=metadata,
            impact=issue.impact,
            effort_to_fix=issue.effort,
            tags={'code-quality', 'ai-detected'}
        )
    
    def _convert_linter_finding(self, raw_finding: Dict[str, Any], 
                              file_path: str, tool_name: str) -> Optional[UnifiedFinding]:
        """Convert raw linter finding to unified format."""
        if not raw_finding:
            return None
        
        # Extract common fields from linter output
        line_number = raw_finding.get('line', raw_finding.get('line_number'))
        column_number = raw_finding.get('column', raw_finding.get('column_number'))
        message = raw_finding.get('message', raw_finding.get('msg', ''))
        rule_id = raw_finding.get('rule', raw_finding.get('rule_id', raw_finding.get('code')))
        severity_str = raw_finding.get('severity', raw_finding.get('type', 'warning')).lower()
        
        # Map severity
        severity_map = {
            'error': FindingSeverity.HIGH,
            'warning': FindingSeverity.MEDIUM,
            'info': FindingSeverity.LOW,
            'note': FindingSeverity.INFO
        }
        severity = severity_map.get(severity_str, FindingSeverity.MEDIUM)
        
        # Determine finding type based on rule or content
        finding_type = FindingType.STYLE_VIOLATION
        if 'security' in message.lower() or 'vulnerability' in message.lower():
            finding_type = FindingType.SECURITY_VULNERABILITY
        elif 'performance' in message.lower():
            finding_type = FindingType.PERFORMANCE_ISSUE
        elif 'syntax' in message.lower():
            finding_type = FindingType.SYNTAX_ERROR
        elif 'format' in message.lower():
            finding_type = FindingType.FORMATTING_ISSUE
        
        # Create location
        location = SourceLocation(
            file_path=file_path,
            line_start=line_number,
            column_start=column_number
        )
        
        return UnifiedFinding(
            title=f"Linter Issue: {rule_id}" if rule_id else "Linter Issue",
            description=message,
            finding_type=finding_type,
            severity=severity,
            source=FindingSource.LINTER,
            tool_name=tool_name,
            rule_id=rule_id,
            location=location,
            message=message,
            metadata=raw_finding,
            tags={'linter', tool_name.lower()}
        )


# Utility functions for parsing common linter outputs

def parse_pylint_output(output: str) -> List[Dict[str, Any]]:
    """Parse pylint output into structured findings."""
    findings = []
    for line in output.strip().split('\n'):
        if ':' in line and not line.startswith('*'):
            parts = line.split(':', 4)
            if len(parts) >= 4:
                findings.append({
                    'line': int(parts[1]) if parts[1].isdigit() else None,
                    'column': int(parts[2]) if parts[2].isdigit() else None,
                    'type': parts[3].strip(),
                    'message': parts[4].strip() if len(parts) > 4 else '',
                    'rule_id': parts[3].strip()
                })
    return findings


def parse_flake8_output(output: str) -> List[Dict[str, Any]]:
    """Parse flake8 output into structured findings."""
    findings = []
    for line in output.strip().split('\n'):
        if ':' in line:
            parts = line.split(':', 3)
            if len(parts) >= 4:
                # Extract rule code from message
                message = parts[3].strip()
                rule_code = ''
                if ' ' in message:
                    first_word = message.split()[0]
                    if first_word.isupper() and len(first_word) <= 5:
                        rule_code = first_word
                        message = ' '.join(message.split()[1:])
                
                findings.append({
                    'line': int(parts[1]) if parts[1].isdigit() else None,
                    'column': int(parts[2]) if parts[2].isdigit() else None,
                    'severity': 'warning',
                    'message': message,
                    'rule_id': rule_code
                })
    return findings


def parse_eslint_output(output: str) -> List[Dict[str, Any]]:
    """Parse ESLint output into structured findings."""
    findings = []
    # This is a simplified parser - real ESLint output might be JSON
    for line in output.strip().split('\n'):
        if 'error' in line.lower() or 'warning' in line.lower():
            parts = line.split()
            if len(parts) >= 3:
                line_col = parts[0].split(':')
                severity = 'error' if 'error' in line.lower() else 'warning'
                message = ' '.join(parts[1:])
                
                findings.append({
                    'line': int(line_col[0]) if len(line_col) > 0 and line_col[0].isdigit() else None,
                    'column': int(line_col[1]) if len(line_col) > 1 and line_col[1].isdigit() else None,
                    'severity': severity,
                    'message': message,
                    'rule_id': parts[1] if len(parts) > 1 else None
                })
    return findings

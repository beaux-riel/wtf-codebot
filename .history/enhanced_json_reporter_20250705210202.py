#!/usr/bin/env python3
"""
Enhanced JSON Report Generator for Unified Findings

This module provides an enhanced JSON report generation system that serializes
unified findings to a structured JSON schema including comprehensive metadata,
pattern names, severity levels, detailed explanations, and remediation suggestions.

The schema is designed to be:
- Machine-readable for automated processing
- Human-readable for manual review
- Compatible with various CI/CD systems
- Extensible for future enhancements
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field

from wtf_codebot.findings.models import (
    FindingsCollection, UnifiedFinding, FindingSeverity, 
    FindingType, FindingSource, SourceLocation
)
from wtf_codebot.findings.reporter import UnifiedReporter

logger = logging.getLogger(__name__)


@dataclass
class EnhancedReportMetadata:
    """Enhanced metadata for JSON reports."""
    generated_at: datetime = field(default_factory=datetime.now)
    tool_name: str = "wtf-codebot-enhanced"
    tool_version: str = "1.0.0"
    schema_version: str = "2.0.0"
    report_id: str = ""
    analysis_start_time: Optional[datetime] = None
    analysis_end_time: Optional[datetime] = None
    analysis_duration_seconds: Optional[float] = None
    total_files_analyzed: int = 0
    total_lines_analyzed: int = 0
    configuration: Dict[str, Any] = field(default_factory=dict)
    environment: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "generated_at": self.generated_at.isoformat(),
            "tool": {
                "name": self.tool_name,
                "version": self.tool_version,
                "schema_version": self.schema_version,
                "report_id": self.report_id
            },
            "analysis": {
                "start_time": self.analysis_start_time.isoformat() if self.analysis_start_time else None,
                "end_time": self.analysis_end_time.isoformat() if self.analysis_end_time else None,
                "duration_seconds": self.analysis_duration_seconds,
                "total_files_analyzed": self.total_files_analyzed,
                "total_lines_analyzed": self.total_lines_analyzed
            },
            "configuration": self.configuration,
            "environment": self.environment
        }


@dataclass
class PatternInfo:
    """Information about detected patterns."""
    pattern_id: str
    pattern_name: str
    pattern_category: str
    description: str
    confidence_score: float
    evidence: List[str] = field(default_factory=list)
    related_patterns: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "pattern_id": self.pattern_id,
            "name": self.pattern_name,
            "category": self.pattern_category,
            "description": self.description,
            "confidence_score": self.confidence_score,
            "evidence": self.evidence,
            "related_patterns": self.related_patterns
        }


@dataclass
class RemediationSuggestion:
    """Detailed remediation suggestion."""
    priority: str  # immediate, high, medium, low
    category: str  # refactor, fix, optimize, modernize
    description: str
    steps: List[str] = field(default_factory=list)
    code_example: Optional[str] = None
    estimated_effort: str = "medium"  # low, medium, high
    risk_level: str = "low"  # low, medium, high
    prerequisites: List[str] = field(default_factory=list)
    references: List[Dict[str, str]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "priority": self.priority,
            "category": self.category,
            "description": self.description,
            "steps": self.steps,
            "code_example": self.code_example,
            "estimated_effort": self.estimated_effort,
            "risk_level": self.risk_level,
            "prerequisites": self.prerequisites,
            "references": self.references
        }


@dataclass
class EnhancedFinding:
    """Enhanced finding with additional metadata and remediation info."""
    base_finding: UnifiedFinding
    pattern_info: Optional[PatternInfo] = None
    remediation: Optional[RemediationSuggestion] = None
    impact_analysis: Dict[str, Any] = field(default_factory=dict)
    business_impact: Optional[str] = None
    technical_debt_score: Optional[float] = None
    cwe_ids: List[str] = field(default_factory=list)
    owasp_categories: List[str] = field(default_factory=list)
    compliance_violations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to enhanced dictionary for serialization."""
        result = self.base_finding.to_dict()
        
        # Add enhanced fields
        if self.pattern_info:
            result["pattern_info"] = self.pattern_info.to_dict()
        
        if self.remediation:
            result["remediation"] = self.remediation.to_dict()
        
        result["impact_analysis"] = self.impact_analysis
        result["business_impact"] = self.business_impact
        result["technical_debt_score"] = self.technical_debt_score
        result["security_info"] = {
            "cwe_ids": self.cwe_ids,
            "owasp_categories": self.owasp_categories,
            "compliance_violations": self.compliance_violations
        }
        
        return result


class EnhancedJSONReporter(UnifiedReporter):
    """Enhanced JSON reporter with comprehensive schema and metadata."""
    
    def __init__(self, 
                 include_pattern_analysis: bool = True,
                 include_remediation_suggestions: bool = True,
                 include_security_mapping: bool = True,
                 include_technical_debt_analysis: bool = True,
                 **kwargs):
        """
        Initialize enhanced reporter.
        
        Args:
            include_pattern_analysis: Include pattern recognition analysis
            include_remediation_suggestions: Include detailed remediation suggestions
            include_security_mapping: Include CWE/OWASP security mappings
            include_technical_debt_analysis: Include technical debt scoring
            **kwargs: Additional arguments passed to base reporter
        """
        super().__init__(**kwargs)
        self.include_pattern_analysis = include_pattern_analysis
        self.include_remediation_suggestions = include_remediation_suggestions
        self.include_security_mapping = include_security_mapping
        self.include_technical_debt_analysis = include_technical_debt_analysis
    
    def generate_enhanced_json_report(self,
                                    collection: FindingsCollection,
                                    output_path: Optional[str] = None,
                                    metadata: Optional[EnhancedReportMetadata] = None,
                                    pretty: bool = True) -> str:
        """
        Generate enhanced JSON report with comprehensive schema.
        
        Args:
            collection: Findings collection
            output_path: Optional file path to write report
            metadata: Enhanced metadata for the report
            pretty: Whether to format JSON nicely
            
        Returns:
            JSON string with enhanced schema
        """
        if metadata is None:
            metadata = EnhancedReportMetadata()
        
        # Generate report ID if not provided
        if not metadata.report_id:
            metadata.report_id = f"wtf-codebot-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Filter findings
        filtered_findings = self._filter_findings(collection.findings)
        
        # Enhance findings with additional data
        enhanced_findings = self._enhance_findings(filtered_findings)
        
        # Generate comprehensive statistics
        stats = self._generate_enhanced_statistics(enhanced_findings)
        
        # Build the enhanced report structure
        report_data = {
            "schema": {
                "version": "2.0.0",
                "specification": "wtf-codebot-enhanced-findings",
                "documentation": "https://github.com/beaux-riel/wtf-codebot/docs/json-schema.md"
            },
            "metadata": metadata.to_dict(),
            "statistics": stats,
            "findings": [finding.to_dict() for finding in enhanced_findings],
            "recommendations": self._generate_global_recommendations(enhanced_findings),
            "quality_metrics": self._calculate_quality_metrics(enhanced_findings),
            "risk_assessment": self._perform_risk_assessment(enhanced_findings)
        }
        
        # Add collection metadata
        if self.include_metadata and collection.metadata:
            report_data["metadata"]["collection_metadata"] = collection.metadata
        
        # Serialize to JSON
        indent = 2 if pretty else None
        json_content = json.dumps(report_data, indent=indent, ensure_ascii=False, sort_keys=True)
        
        # Write to file if path provided
        if output_path:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(json_content)
            
            logger.info(f"Enhanced JSON report written to {output_path}")
            
            # Also generate a minified version
            minified_path = output_file.with_suffix('.min.json')
            minified_content = json.dumps(report_data, separators=(',', ':'), ensure_ascii=False)
            with open(minified_path, 'w', encoding='utf-8') as f:
                f.write(minified_content)
            logger.info(f"Minified JSON report written to {minified_path}")
        
        return json_content
    
    def _enhance_findings(self, findings: List[UnifiedFinding]) -> List[EnhancedFinding]:
        """Enhance findings with additional metadata and analysis."""
        enhanced = []
        
        for finding in findings:
            enhanced_finding = EnhancedFinding(base_finding=finding)
            
            # Add pattern analysis
            if self.include_pattern_analysis:
                enhanced_finding.pattern_info = self._analyze_pattern(finding)
            
            # Add remediation suggestions
            if self.include_remediation_suggestions:
                enhanced_finding.remediation = self._generate_remediation(finding)
            
            # Add security mappings
            if self.include_security_mapping:
                self._add_security_mappings(enhanced_finding)
            
            # Add technical debt analysis
            if self.include_technical_debt_analysis:
                enhanced_finding.technical_debt_score = self._calculate_technical_debt_score(finding)
            
            # Add impact analysis
            enhanced_finding.impact_analysis = self._analyze_impact(finding)
            enhanced_finding.business_impact = self._assess_business_impact(finding)
            
            enhanced.append(enhanced_finding)
        
        return enhanced
    
    def _analyze_pattern(self, finding: UnifiedFinding) -> Optional[PatternInfo]:
        """Analyze and identify patterns in the finding."""
        # This would typically use the pattern recognition system
        pattern_mappings = {
            FindingType.ANTI_PATTERN: {
                "god_object": PatternInfo(
                    pattern_id="god_object",
                    pattern_name="God Object",
                    pattern_category="anti_pattern",
                    description="A class that knows too much or does too much",
                    confidence_score=0.85,
                    evidence=["Large class size", "Multiple responsibilities", "High coupling"],
                    related_patterns=["single_responsibility_violation", "high_coupling"]
                ),
                "spaghetti_code": PatternInfo(
                    pattern_id="spaghetti_code",
                    pattern_name="Spaghetti Code",
                    pattern_category="anti_pattern",
                    description="Code with complex and tangled control flow",
                    confidence_score=0.75,
                    evidence=["Complex control flow", "Nested conditions", "No clear structure"]
                )
            },
            FindingType.DESIGN_PATTERN: {
                "singleton": PatternInfo(
                    pattern_id="singleton",
                    pattern_name="Singleton Pattern",
                    pattern_category="creational_pattern",
                    description="Ensures a class has only one instance",
                    confidence_score=0.92,
                    evidence=["Private constructor", "Static instance method", "Single instance guarantee"]
                )
            }
        }
        
        if finding.finding_type in pattern_mappings:
            # Simple rule-based pattern detection based on rule_id or title
            for pattern_key, pattern_info in pattern_mappings[finding.finding_type].items():
                if (finding.rule_id and pattern_key in finding.rule_id.lower()) or \
                   (finding.title and pattern_key.replace('_', ' ') in finding.title.lower()):
                    return pattern_info
        
        return None
    
    def _generate_remediation(self, finding: UnifiedFinding) -> Optional[RemediationSuggestion]:
        """Generate detailed remediation suggestions for the finding."""
        remediation_templates = {
            FindingType.SECURITY_VULNERABILITY: RemediationSuggestion(
                priority="immediate",
                category="fix",
                description="Address security vulnerability immediately",
                steps=[
                    "Review the vulnerable code section",
                    "Apply security patches or updates",
                    "Implement input validation if applicable",
                    "Add security tests",
                    "Conduct security review"
                ],
                estimated_effort="medium",
                risk_level="high",
                references=[
                    {"type": "owasp", "url": "https://owasp.org/www-project-top-ten/"},
                    {"type": "cwe", "url": "https://cwe.mitre.org/"}
                ]
            ),
            FindingType.CODE_SMELL: RemediationSuggestion(
                priority="medium",
                category="refactor",
                description="Refactor code to improve maintainability",
                steps=[
                    "Identify the root cause of the code smell",
                    "Extract methods or classes as needed",
                    "Improve naming and structure",
                    "Add or update documentation",
                    "Write unit tests for refactored code"
                ],
                estimated_effort="medium",
                risk_level="low"
            ),
            FindingType.ANTI_PATTERN: RemediationSuggestion(
                priority="high",
                category="refactor",
                description="Restructure code to eliminate anti-pattern",
                steps=[
                    "Analyze the current structure",
                    "Design a better architecture",
                    "Break down large components",
                    "Apply SOLID principles",
                    "Incrementally refactor"
                ],
                estimated_effort="high",
                risk_level="medium"
            ),
            FindingType.OUTDATED_DEPENDENCY: RemediationSuggestion(
                priority="medium",
                category="modernize",
                description="Update dependencies to latest stable versions",
                steps=[
                    "Check for breaking changes in newer versions",
                    "Update dependencies incrementally",
                    "Run comprehensive tests",
                    "Update documentation if needed"
                ],
                estimated_effort="low",
                risk_level="medium"
            )
        }
        
        base_remediation = remediation_templates.get(finding.finding_type)
        if base_remediation and finding.suggestion:
            # Customize based on specific finding
            base_remediation.description = finding.suggestion
            if finding.fix_recommendation:
                base_remediation.code_example = finding.fix_recommendation
        
        return base_remediation
    
    def _add_security_mappings(self, enhanced_finding: EnhancedFinding) -> None:
        """Add security-related mappings (CWE, OWASP, etc.)."""
        finding = enhanced_finding.base_finding
        
        # Security mapping based on finding type and content
        security_mappings = {
            "sql_injection": {
                "cwe_ids": ["CWE-89"],
                "owasp_categories": ["A03:2021 – Injection"],
                "compliance_violations": ["PCI-DSS", "SOX"]
            },
            "xss": {
                "cwe_ids": ["CWE-79"],
                "owasp_categories": ["A03:2021 – Injection"],
                "compliance_violations": ["PCI-DSS"]
            },
            "authentication": {
                "cwe_ids": ["CWE-287", "CWE-306"],
                "owasp_categories": ["A07:2021 – Identification and Authentication Failures"],
                "compliance_violations": ["PCI-DSS", "HIPAA"]
            }
        }
        
        # Check for security patterns in the finding
        finding_text = f"{finding.title} {finding.description} {finding.message}".lower()
        
        for pattern, mappings in security_mappings.items():
            if pattern.replace('_', ' ') in finding_text:
                enhanced_finding.cwe_ids.extend(mappings.get("cwe_ids", []))
                enhanced_finding.owasp_categories.extend(mappings.get("owasp_categories", []))
                enhanced_finding.compliance_violations.extend(mappings.get("compliance_violations", []))
                break
    
    def _calculate_technical_debt_score(self, finding: UnifiedFinding) -> float:
        """Calculate technical debt score for the finding."""
        # Base score from severity
        severity_scores = {
            FindingSeverity.CRITICAL: 10.0,
            FindingSeverity.HIGH: 8.0,
            FindingSeverity.MEDIUM: 5.0,
            FindingSeverity.LOW: 2.0,
            FindingSeverity.INFO: 0.5
        }
        
        base_score = severity_scores.get(finding.severity, 5.0)
        
        # Adjust based on finding type
        type_multipliers = {
            FindingType.SECURITY_VULNERABILITY: 1.5,
            FindingType.ANTI_PATTERN: 1.3,
            FindingType.CODE_SMELL: 1.1,
            FindingType.PERFORMANCE_ISSUE: 1.2,
            FindingType.STYLE_VIOLATION: 0.8
        }
        
        multiplier = type_multipliers.get(finding.finding_type, 1.0)
        
        # Adjust based on confidence
        confidence_factor = finding.confidence
        
        return round(base_score * multiplier * confidence_factor, 2)
    
    def _analyze_impact(self, finding: UnifiedFinding) -> Dict[str, Any]:
        """Analyze the impact of the finding."""
        return {
            "maintainability_impact": self._assess_maintainability_impact(finding),
            "security_impact": self._assess_security_impact(finding),
            "performance_impact": self._assess_performance_impact(finding),
            "reliability_impact": self._assess_reliability_impact(finding)
        }
    
    def _assess_maintainability_impact(self, finding: UnifiedFinding) -> str:
        """Assess maintainability impact."""
        maintainability_types = {
            FindingType.CODE_SMELL, FindingType.ANTI_PATTERN,
            FindingType.STYLE_VIOLATION, FindingType.MISSING_DOCUMENTATION
        }
        
        if finding.finding_type in maintainability_types:
            if finding.severity in [FindingSeverity.HIGH, FindingSeverity.CRITICAL]:
                return "high"
            elif finding.severity == FindingSeverity.MEDIUM:
                return "medium"
            else:
                return "low"
        return "minimal"
    
    def _assess_security_impact(self, finding: UnifiedFinding) -> str:
        """Assess security impact."""
        security_types = {
            FindingType.SECURITY_VULNERABILITY, FindingType.AUTHENTICATION_ISSUE,
            FindingType.AUTHORIZATION_ISSUE, FindingType.INPUT_VALIDATION,
            FindingType.CRYPTOGRAPHY_ISSUE
        }
        
        if finding.finding_type in security_types:
            if finding.severity == FindingSeverity.CRITICAL:
                return "critical"
            elif finding.severity == FindingSeverity.HIGH:
                return "high"
            elif finding.severity == FindingSeverity.MEDIUM:
                return "medium"
            else:
                return "low"
        return "minimal"
    
    def _assess_performance_impact(self, finding: UnifiedFinding) -> str:
        """Assess performance impact."""
        performance_types = {
            FindingType.PERFORMANCE_ISSUE, FindingType.MEMORY_LEAK,
            FindingType.INEFFICIENT_ALGORITHM
        }
        
        if finding.finding_type in performance_types:
            return finding.severity.value
        return "minimal"
    
    def _assess_reliability_impact(self, finding: UnifiedFinding) -> str:
        """Assess reliability impact."""
        reliability_types = {
            FindingType.MEMORY_LEAK, FindingType.PERFORMANCE_ISSUE,
            FindingType.SYNTAX_ERROR, FindingType.FLAKY_TEST
        }
        
        if finding.finding_type in reliability_types:
            return finding.severity.value
        return "minimal"
    
    def _assess_business_impact(self, finding: UnifiedFinding) -> str:
        """Assess business impact of the finding."""
        critical_types = {
            FindingType.SECURITY_VULNERABILITY,
            FindingType.PERFORMANCE_ISSUE,
            FindingType.MEMORY_LEAK
        }
        
        if finding.finding_type in critical_types:
            if finding.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
                return "high"
            elif finding.severity == FindingSeverity.MEDIUM:
                return "medium"
            else:
                return "low"
        
        return "low"
    
    def _generate_enhanced_statistics(self, findings: List[EnhancedFinding]) -> Dict[str, Any]:
        """Generate enhanced statistics for the findings."""
        base_stats = self._generate_summary([f.base_finding for f in findings])
        
        # Add enhanced statistics
        enhanced_stats = dict(base_stats)
        
        # Technical debt analysis
        debt_scores = [f.technical_debt_score for f in findings if f.technical_debt_score is not None]
        if debt_scores:
            enhanced_stats["technical_debt"] = {
                "total_score": round(sum(debt_scores), 2),
                "average_score": round(sum(debt_scores) / len(debt_scores), 2),
                "max_score": max(debt_scores),
                "min_score": min(debt_scores)
            }
        
        # Pattern analysis
        patterns = {}
        for finding in findings:
            if finding.pattern_info:
                pattern_cat = finding.pattern_info.pattern_category
                patterns[pattern_cat] = patterns.get(pattern_cat, 0) + 1
        
        if patterns:
            enhanced_stats["patterns"] = patterns
        
        # Security analysis
        security_findings = [f for f in findings if f.cwe_ids or f.owasp_categories]
        if security_findings:
            all_cwes = []
            all_owasp = []
            for f in security_findings:
                all_cwes.extend(f.cwe_ids)
                all_owasp.extend(f.owasp_categories)
            
            enhanced_stats["security"] = {
                "total_security_findings": len(security_findings),
                "unique_cwe_ids": list(set(all_cwes)),
                "unique_owasp_categories": list(set(all_owasp))
            }
        
        return enhanced_stats
    
    def _generate_global_recommendations(self, findings: List[EnhancedFinding]) -> List[Dict[str, Any]]:
        """Generate global recommendations based on findings patterns."""
        recommendations = []
        
        # Analyze patterns across all findings
        finding_types = [f.base_finding.finding_type for f in findings]
        severity_counts = {}
        for finding in findings:
            severity = finding.base_finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # High-level recommendations based on patterns
        if severity_counts.get('critical', 0) > 0:
            recommendations.append({
                "priority": "immediate",
                "category": "security",
                "title": "Address Critical Security Issues",
                "description": f"Found {severity_counts['critical']} critical issues that require immediate attention",
                "action": "Review and fix all critical security vulnerabilities before deployment"
            })
        
        if FindingType.CODE_SMELL in finding_types:
            code_smell_count = finding_types.count(FindingType.CODE_SMELL)
            if code_smell_count > 5:
                recommendations.append({
                    "priority": "high",
                    "category": "maintainability",
                    "title": "Code Quality Improvement",
                    "description": f"Found {code_smell_count} code smells affecting maintainability",
                    "action": "Consider refactoring to improve code quality and reduce technical debt"
                })
        
        if FindingType.OUTDATED_DEPENDENCY in finding_types:
            dep_count = finding_types.count(FindingType.OUTDATED_DEPENDENCY)
            recommendations.append({
                "priority": "medium",
                "category": "maintenance",
                "title": "Dependency Updates",
                "description": f"Found {dep_count} outdated dependencies",
                "action": "Regularly update dependencies to maintain security and performance"
            })
        
        return recommendations
    
    def _calculate_quality_metrics(self, findings: List[EnhancedFinding]) -> Dict[str, Any]:
        """Calculate overall quality metrics."""
        total_findings = len(findings)
        if total_findings == 0:
            return {"overall_score": 100.0, "grade": "A"}
        
        # Calculate weighted score based on severity
        severity_weights = {
            FindingSeverity.CRITICAL: 10,
            FindingSeverity.HIGH: 5,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 1,
            FindingSeverity.INFO: 0.1
        }
        
        total_weight = sum(severity_weights[f.base_finding.severity] for f in findings)
        
        # Calculate score (higher weight = lower score)
        max_possible_weight = total_findings * severity_weights[FindingSeverity.INFO]
        if max_possible_weight > 0:
            score = max(0, 100 - (total_weight / max_possible_weight * 100))
        else:
            score = 100.0
        
        # Assign letter grade
        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"
        
        return {
            "overall_score": round(score, 1),
            "grade": grade,
            "total_issues": total_findings,
            "weighted_severity_score": round(total_weight, 1)
        }
    
    def _perform_risk_assessment(self, findings: List[EnhancedFinding]) -> Dict[str, Any]:
        """Perform risk assessment based on findings."""
        security_findings = len([f for f in findings 
                               if f.base_finding.finding_type in {
                                   FindingType.SECURITY_VULNERABILITY,
                                   FindingType.AUTHENTICATION_ISSUE,
                                   FindingType.AUTHORIZATION_ISSUE
                               }])
        
        critical_findings = len([f for f in findings 
                               if f.base_finding.severity == FindingSeverity.CRITICAL])
        
        high_findings = len([f for f in findings 
                           if f.base_finding.severity == FindingSeverity.HIGH])
        
        # Calculate risk level
        if critical_findings > 0 or security_findings > 3:
            risk_level = "high"
        elif high_findings > 5 or security_findings > 1:
            risk_level = "medium"
        elif high_findings > 0 or security_findings > 0:
            risk_level = "low"
        else:
            risk_level = "minimal"
        
        return {
            "overall_risk_level": risk_level,
            "security_risk_factors": security_findings,
            "critical_issues": critical_findings,
            "high_priority_issues": high_findings,
            "risk_score": min(100, (critical_findings * 25) + (high_findings * 10) + (security_findings * 15))
        }


def main():
    """Generate enhanced JSON report from existing findings."""
    import sys
    from wtf_codebot.findings.models import FindingsCollection
    
    # Load existing findings if available
    reports_dir = Path("reports")
    existing_json = reports_dir / "unified_findings.json"
    
    if existing_json.exists():
        print("Loading existing findings...")
        with open(existing_json, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Convert back to findings collection
        findings = []
        for finding_data in data.get("findings", []):
            finding = UnifiedFinding.from_dict(finding_data)
            findings.append(finding)
        
        collection = FindingsCollection(findings=findings, metadata=data.get("metadata", {}))
        
        # Generate enhanced report
        print("Generating enhanced JSON report...")
        reporter = EnhancedJSONReporter(
            include_pattern_analysis=True,
            include_remediation_suggestions=True,
            include_security_mapping=True,
            include_technical_debt_analysis=True
        )
        
        # Create enhanced metadata
        metadata = EnhancedReportMetadata(
            total_files_analyzed=len(data.get("summary", {}).get("affected_files", [])),
            configuration={
                "analysis_types": ["static_analysis", "pattern_recognition", "security_scan"],
                "enabled_rules": ["all"],
                "severity_threshold": "info"
            },
            environment={
                "python_version": sys.version,
                "platform": sys.platform,
                "cwd": str(Path.cwd())
            }
        )
        
        # Generate enhanced report
        output_path = reports_dir / "enhanced_unified_findings.json"
        enhanced_json = reporter.generate_enhanced_json_report(
            collection=collection,
            output_path=str(output_path),
            metadata=metadata,
            pretty=True
        )
        
        print(f"Enhanced JSON report generated: {output_path}")
        print(f"Report size: {len(enhanced_json)} characters")
        print(f"Total findings: {len(findings)}")
        
        # Print summary
        report_data = json.loads(enhanced_json)
        quality_metrics = report_data.get("quality_metrics", {})
        risk_assessment = report_data.get("risk_assessment", {})
        
        print(f"\nQuality Metrics:")
        print(f"  Overall Score: {quality_metrics.get('overall_score', 'N/A')}")
        print(f"  Grade: {quality_metrics.get('grade', 'N/A')}")
        print(f"\nRisk Assessment:")
        print(f"  Risk Level: {risk_assessment.get('overall_risk_level', 'N/A')}")
        print(f"  Risk Score: {risk_assessment.get('risk_score', 'N/A')}")
        
    else:
        print(f"No existing findings found at {existing_json}")
        print("Please run the analysis pipeline first to generate findings.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Demo script showing unified findings aggregation and multi-format reporting.

This script demonstrates how to:
1. Aggregate findings from multiple sources (static analysis, AI, dependencies)
2. Deduplicate similar findings
3. Generate reports in multiple formats (JSON, HTML, Markdown, CSV, SARIF)
"""

import json
import logging
from pathlib import Path
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

from wtf_codebot.findings import (
    FindingsAggregator, FindingsDeduplicator, UnifiedReporter,
    UnifiedFinding, SourceLocation, FindingSource, FindingSeverity, FindingType
)
from wtf_codebot.findings.aggregator import parse_pylint_output, parse_flake8_output

def create_sample_findings():
    """Create sample findings from different sources for demonstration."""
    findings = []
    
    # Sample static analyzer findings
    findings.append(UnifiedFinding(
        title="Long method detected",
        description="Method has 150 lines, consider breaking it down into smaller methods",
        finding_type=FindingType.CODE_SMELL,
        severity=FindingSeverity.MEDIUM,
        source=FindingSource.STATIC_ANALYZER,
        tool_name="pylint",
        rule_id="too-many-lines",
        location=SourceLocation(
            file_path="/src/user_service.py",
            line_start=45,
            line_end=195,
            function_name="process_user_data"
        ),
        message="Method 'process_user_data' has too many lines (150/50)",
        suggestion="Break down into smaller, focused methods",
        tags={'complexity', 'maintainability'}
    ))
    
    # Sample AI analysis finding (design pattern)
    findings.append(UnifiedFinding(
        title="Design Pattern: Singleton",
        description="Well-implemented Singleton pattern for configuration management",
        finding_type=FindingType.DESIGN_PATTERN,
        severity=FindingSeverity.INFO,
        confidence=0.92,
        source=FindingSource.AI_ANALYSIS,
        tool_name="claude_pattern_analyzer",
        rule_id="singleton",
        location=SourceLocation(
            file_path="/src/config.py",
            line_start=10,
            line_end=35,
            class_name="ConfigManager"
        ),
        message="Singleton pattern detected with proper implementation",
        metadata={
            'benefits': ['Global access', 'Single instance guarantee'],
            'use_cases': ['Configuration management', 'Logging services'],
            'evidence': ['Private constructor', 'Static instance method', 'Thread-safe implementation']
        },
        impact="low",
        effort_to_fix="low",
        tags={'design-pattern', 'architecture', 'ai-detected'}
    ))
    
    # Sample security vulnerability from dependency analysis
    findings.append(UnifiedFinding(
        title="Security Vulnerability: SQL Injection",
        description="Potential SQL injection vulnerability in user authentication",
        finding_type=FindingType.SECURITY_VULNERABILITY,
        severity=FindingSeverity.CRITICAL,
        source=FindingSource.DEPENDENCY_ANALYSIS,
        tool_name="bandit",
        rule_id="B608",
        location=SourceLocation(
            file_path="/src/auth.py",
            line_start=78,
            line_end=82,
            function_name="authenticate_user"
        ),
        message="Possible SQL injection vector through string formatting",
        suggestion="Use parameterized queries or ORM methods",
        fix_recommendation="Replace string formatting with parameterized query: cursor.execute('SELECT * FROM users WHERE username = %s', (username,))",
        affected_code="cursor.execute(f\"SELECT * FROM users WHERE username = '{username}'\")",
        metadata={
            'cve_id': 'CVE-2023-12345',
            'affected_versions': ['1.0.0', '1.1.0'],
            'fixed_versions': ['1.2.0']
        },
        impact="critical",
        effort_to_fix="medium",
        tags={'security', 'sql-injection', 'critical'}
    ))
    
    # Sample duplicate finding (similar to the first one)
    findings.append(UnifiedFinding(
        title="Method too long",
        description="Function exceeds recommended length",
        finding_type=FindingType.CODE_SMELL,
        severity=FindingSeverity.MEDIUM,
        source=FindingSource.LINTER,
        tool_name="flake8",
        rule_id="C901",
        location=SourceLocation(
            file_path="/src/user_service.py",
            line_start=47,  # Slightly different line
            function_name="process_user_data"
        ),
        message="Function is too complex (C901)",
        suggestion="Refactor into smaller functions",
        tags={'complexity', 'linter'}
    ))
    
    # Sample outdated dependency
    findings.append(UnifiedFinding(
        title="Outdated Package: requests",
        description="Package requests is outdated and should be updated",
        finding_type=FindingType.OUTDATED_DEPENDENCY,
        severity=FindingSeverity.LOW,
        source=FindingSource.DEPENDENCY_ANALYSIS,
        tool_name="dependency_analyzer",
        location=SourceLocation(file_path="/requirements.txt"),
        message="Package requests is outdated",
        suggestion="Update to the latest stable version",
        metadata={
            'current_version': '2.25.1',
            'latest_version': '2.31.0'
        },
        tags={'dependency', 'outdated', 'maintenance'}
    ))
    
    # Sample AI anti-pattern finding
    findings.append(UnifiedFinding(
        title="Anti-Pattern: God Object",
        description="Class has too many responsibilities and should be split",
        finding_type=FindingType.ANTI_PATTERN,
        severity=FindingSeverity.HIGH,
        confidence=0.85,
        source=FindingSource.AI_ANALYSIS,
        tool_name="claude_pattern_analyzer",
        rule_id="god_object",
        location=SourceLocation(
            file_path="/src/user_service.py",
            line_start=1,
            line_end=300,
            class_name="UserService"
        ),
        message="Class has multiple unrelated responsibilities",
        suggestion="Split into focused service classes; Apply Single Responsibility Principle",
        metadata={
            'problems': ['Poor maintainability', 'High coupling', 'Testing difficulties'],
            'solutions': ['Split into focused classes', 'Use composition', 'Apply SOLID principles'],
            'evidence': ['50+ methods', 'Multiple unrelated concerns', 'Large class size']
        },
        impact="high",
        effort_to_fix="high",
        tags={'anti-pattern', 'code-smell', 'refactoring', 'ai-detected'}
    ))
    
    return findings

def simulate_linter_integration():
    """Simulate integration with actual linter tools."""
    # Sample pylint output
    pylint_output = """
/src/utils.py:10:0: C0103: Constant name "api_key" doesn't conform to UPPER_CASE naming style (invalid-name)
/src/utils.py:25:4: W0613: Unused argument 'request' (unused-argument)
/src/utils.py:45:0: R0903: Too few public methods (1/2) (too-few-public-methods)
    """
    
    # Sample flake8 output
    flake8_output = """
/src/api.py:15:80: E501 line too long (82 > 79 characters)
/src/api.py:23:1: F401 'os' imported but unused
/src/api.py:34:25: E203 whitespace before ':'
    """
    
    # Parse linter outputs
    pylint_findings = parse_pylint_output(pylint_output)
    flake8_findings = parse_flake8_output(flake8_output)
    
    return pylint_findings, flake8_findings

def main():
    """Demonstrate the unified findings aggregation system."""
    print("🔍 WTF-Codebot Unified Findings Aggregation Demo")
    print("=" * 60)
    
    # Initialize aggregator
    aggregator = FindingsAggregator()
    
    # Add sample findings from different sources
    print("\n📥 Adding findings from multiple sources...")
    
    # Add pre-created sample findings
    sample_findings = create_sample_findings()
    for finding in sample_findings:
        aggregator.add_custom_finding(finding)
    
    # Simulate linter integration
    pylint_findings, flake8_findings = simulate_linter_integration()
    
    # Add linter findings
    aggregator.add_linter_results(
        output="mock_output", 
        file_path="/src/utils.py",
        tool_name="pylint",
        parser_func=lambda x: pylint_findings
    )
    
    aggregator.add_linter_results(
        output="mock_output",
        file_path="/src/api.py", 
        tool_name="flake8",
        parser_func=lambda x: flake8_findings
    )
    
    # Get the aggregated collection
    collection = aggregator.get_findings_collection()
    print(f"✅ Aggregated {len(collection.findings)} findings from multiple sources")
    
    # Display summary before deduplication
    print(f"\n📊 Summary before deduplication:")
    stats = collection.get_summary_stats()
    print(f"  - Total findings: {stats['total']}")
    print(f"  - Files affected: {stats['affected_files_count']}")
    print(f"  - By severity: {stats['severity_counts']}")
    print(f"  - By source: {stats['source_counts']}")
    
    # Deduplicate findings
    print(f"\n🔄 Deduplicating findings...")
    deduplicator = FindingsDeduplicator(location_tolerance=3)
    deduplicated_collection = deduplicator.deduplicate_findings(collection)
    
    # Display summary after deduplication
    print(f"\n📊 Summary after deduplication:")
    dedup_stats = deduplicated_collection.get_summary_stats()
    print(f"  - Total findings: {dedup_stats['total']}")
    print(f"  - Reduction: {stats['total'] - dedup_stats['total']} duplicates removed")
    
    # Generate deduplication report
    dedup_report = deduplicator.get_deduplication_report(collection, deduplicated_collection)
    print(f"  - Reduction percentage: {dedup_report['summary']['reduction_percentage']}%")
    
    # Initialize reporter
    reporter = UnifiedReporter()
    
    # Generate reports in multiple formats
    print(f"\n📝 Generating reports in multiple formats...")
    
    # Ensure reports directory exists
    reports_dir = Path("./reports")
    reports_dir.mkdir(exist_ok=True)
    
    # JSON Report
    json_report = reporter.generate_json_report(
        deduplicated_collection, 
        output_path="./reports/unified_findings.json"
    )
    print(f"  ✅ JSON report: ./reports/unified_findings.json")
    
    # HTML Report
    html_report = reporter.generate_html_report(
        deduplicated_collection,
        output_path="./reports/unified_findings.html",
        title="WTF-Codebot Unified Analysis Report"
    )
    print(f"  ✅ HTML report: ./reports/unified_findings.html")
    
    # Markdown Report
    markdown_report = reporter.generate_markdown_report(
        deduplicated_collection,
        output_path="./reports/unified_findings.md",
        title="WTF-Codebot Unified Analysis Report"
    )
    print(f"  ✅ Markdown report: ./reports/unified_findings.md")
    
    # CSV Report
    csv_report = reporter.generate_csv_report(
        deduplicated_collection,
        output_path="./reports/unified_findings.csv"
    )
    print(f"  ✅ CSV report: ./reports/unified_findings.csv")
    
    # SARIF Report
    sarif_report = reporter.generate_sarif_report(
        deduplicated_collection,
        output_path="./reports/unified_findings.sarif"
    )
    print(f"  ✅ SARIF report: ./reports/unified_findings.sarif")
    
    # Text Summary
    text_summary = reporter.generate_text_summary(deduplicated_collection)
    print(f"\n📋 Text Summary:")
    print("-" * 40)
    print(text_summary)
    
    # Demonstrate filtering
    print(f"\n🔍 Demonstrating severity filtering...")
    critical_reporter = UnifiedReporter(severity_filter=[FindingSeverity.CRITICAL, FindingSeverity.HIGH])
    critical_json = critical_reporter.generate_json_report(deduplicated_collection)
    critical_data = json.loads(critical_json)
    print(f"  - Critical/High findings only: {critical_data['metadata']['total_findings']}")
    
    # Show some sample findings
    print(f"\n📋 Sample findings:")
    for i, finding in enumerate(deduplicated_collection.findings[:3], 1):
        print(f"\n  {i}. {finding.title}")
        print(f"     Severity: {finding.severity.value.upper()}")
        print(f"     Type: {finding.finding_type.value.replace('_', ' ').title()}")
        print(f"     Source: {finding.source.value.replace('_', ' ').title()} ({finding.tool_name})")
        print(f"     Location: {finding.location}")
        if finding.message:
            print(f"     Message: {finding.message}")
        
        # Show merge information if available
        if finding.metadata.get('is_merged'):
            merge_info = finding.metadata.get('merge_info', {})
            print(f"     🔗 Merged from {merge_info.get('merged_from_count', 0)} findings")
            print(f"     📍 Merge reasons: {', '.join(merge_info.get('merge_reasons', []))}")
    
    print(f"\n✨ Demo completed successfully!")
    print(f"📁 All reports saved to ./reports/ directory")
    print(f"\n🎯 Key capabilities demonstrated:")
    print(f"  ✅ Multi-source aggregation (static analysis, AI, dependencies, linters)")
    print(f"  ✅ Intelligent deduplication with configurable tolerance")
    print(f"  ✅ Severity scoring and impact assessment")
    print(f"  ✅ Multi-format reporting (JSON, HTML, Markdown, CSV, SARIF)")
    print(f"  ✅ Filtering and customization options")
    print(f"  ✅ Source location tracking and metadata preservation")

if __name__ == "__main__":
    main()

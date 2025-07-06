"""
Unified reporter for multi-format reporting of aggregated findings.

This module provides comprehensive reporting capabilities for unified findings,
supporting multiple output formats including JSON, HTML, Markdown, CSV, and SARIF.
"""

import json
import csv
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from io import StringIO

from .models import FindingsCollection, UnifiedFinding, FindingSeverity, FindingType, FindingSource

logger = logging.getLogger(__name__)


class UnifiedReporter:
    """
    Multi-format reporter for unified findings.
    
    Supports output formats:
    - JSON: Structured data for API consumption
    - HTML: Rich web-based report with interactive features
    - Markdown: Documentation-friendly format
    - CSV: Tabular data for spreadsheet analysis
    - SARIF: Static Analysis Results Interchange Format
    - XML: Structured XML format
    - Text: Simple text summary
    """
    
    def __init__(self, include_source_locations: bool = True,
                 include_metadata: bool = True,
                 severity_filter: Optional[List[FindingSeverity]] = None):
        """
        Initialize the reporter.
        
        Args:
            include_source_locations: Include source location details in reports
            include_metadata: Include metadata in reports
            severity_filter: Only include findings with these severities (None = all)
        """
        self.include_source_locations = include_source_locations
        self.include_metadata = include_metadata
        self.severity_filter = severity_filter or []
    
    def generate_json_report(self, collection: FindingsCollection, 
                           output_path: Optional[str] = None,
                           pretty: bool = True) -> str:
        """
        Generate JSON report.
        
        Args:
            collection: Findings collection
            output_path: Optional file path to write report
            pretty: Whether to format JSON nicely
            
        Returns:
            JSON string
        """
        filtered_findings = self._filter_findings(collection.findings)
        
        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "wtf-codebot unified reporter",
                "version": "1.0.0",
                "total_findings": len(filtered_findings),
                "collection_metadata": collection.metadata if self.include_metadata else {}
            },
            "summary": self._generate_summary(filtered_findings),
            "findings": [
                self._finding_to_dict(finding) 
                for finding in filtered_findings
            ]
        }
        
        indent = 2 if pretty else None
        json_content = json.dumps(report_data, indent=indent, ensure_ascii=False)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_content)
            logger.info(f"JSON report written to {output_path}")
        
        return json_content
    
    def generate_html_report(self, collection: FindingsCollection,
                           output_path: Optional[str] = None,
                           title: str = "Code Analysis Report") -> str:
        """
        Generate HTML report with interactive features.
        
        Args:
            collection: Findings collection
            output_path: Optional file path to write report
            title: Report title
            
        Returns:
            HTML string
        """
        filtered_findings = self._filter_findings(collection.findings)
        summary = self._generate_summary(filtered_findings)
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        {self._get_html_styles()}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🔍 {title}</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}</p>
        </header>
        
        <div class="content">
            {self._generate_html_summary(summary, filtered_findings)}
            {self._generate_html_findings(filtered_findings)}
        </div>
    </div>
    
    <script>
        {self._get_html_scripts()}
    </script>
</body>
</html>
        """.strip()
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"HTML report written to {output_path}")
        
        return html_content
    
    def generate_markdown_report(self, collection: FindingsCollection,
                               output_path: Optional[str] = None,
                               title: str = "Code Analysis Report") -> str:
        """
        Generate Markdown report.
        
        Args:
            collection: Findings collection
            output_path: Optional file path to write report
            title: Report title
            
        Returns:
            Markdown string
        """
        filtered_findings = self._filter_findings(collection.findings)
        summary = self._generate_summary(filtered_findings)
        
        content = []
        
        # Header
        content.append(f"# {title}")
        content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        content.append("")
        
        # Summary
        content.append("## 📊 Summary")
        content.append(f"- **Total Findings**: {summary['total']}")
        content.append(f"- **Critical Issues**: {summary['severity_counts'].get('critical', 0)}")
        content.append(f"- **High Issues**: {summary['severity_counts'].get('high', 0)}")
        content.append(f"- **Medium Issues**: {summary['severity_counts'].get('medium', 0)}")
        content.append(f"- **Low Issues**: {summary['severity_counts'].get('low', 0)}")
        content.append(f"- **Files Affected**: {summary['affected_files_count']}")
        content.append("")
        
        # Severity breakdown
        if summary['severity_counts']:
            content.append("### 🚨 Findings by Severity")
            for severity, count in summary['severity_counts'].items():
                if count > 0:
                    emoji = self._get_severity_emoji(severity)
                    content.append(f"- **{emoji} {severity.title()}**: {count}")
            content.append("")
        
        # Type breakdown
        if summary['type_counts']:
            content.append("### 📋 Findings by Type")
            for finding_type, count in summary['type_counts'].items():
                content.append(f"- **{finding_type.replace('_', ' ').title()}**: {count}")
            content.append("")
        
        # Source breakdown
        if summary['source_counts']:
            content.append("### 🔧 Findings by Source")
            for source, count in summary['source_counts'].items():
                content.append(f"- **{source.replace('_', ' ').title()}**: {count}")
            content.append("")
        
        # Detailed findings
        content.append("## 📋 Detailed Findings")
        content.append("")
        
        # Group by file
        by_file = {}
        for finding in filtered_findings:
            file_path = finding.location.file_path
            if file_path not in by_file:
                by_file[file_path] = []
            by_file[file_path].append(finding)
        
        for file_path, file_findings in sorted(by_file.items()):
            content.append(f"### 📄 {file_path}")
            content.append("")
            
            for finding in sorted(file_findings, key=lambda f: (f.severity.score(), f.location.line_start or 0), reverse=True):
                content.append(f"#### {self._get_severity_emoji(finding.severity.value)} {finding.title}")
                content.append(f"**Severity**: {finding.severity.value.title()}")
                content.append(f"**Type**: {finding.finding_type.value.replace('_', ' ').title()}")
                content.append(f"**Source**: {finding.source.value.replace('_', ' ').title()} ({finding.tool_name})")
                
                if finding.location.line_start:
                    line_info = f"Line {finding.location.line_start}"
                    if finding.location.line_end and finding.location.line_end != finding.location.line_start:
                        line_info += f"-{finding.location.line_end}"
                    content.append(f"**Location**: {line_info}")
                
                if finding.description:
                    content.append(f"**Description**: {finding.description}")
                
                if finding.message:
                    content.append(f"**Message**: {finding.message}")
                
                if finding.suggestion:
                    content.append(f"**Suggestion**: {finding.suggestion}")
                
                if finding.affected_code:
                    content.append("**Affected Code**:")
                    content.append("```")
                    content.append(finding.affected_code)
                    content.append("```")
                
                content.append("")
        
        markdown_content = "\\n".join(content)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(markdown_content)
            logger.info(f"Markdown report written to {output_path}")
        
        return markdown_content
    
    def generate_csv_report(self, collection: FindingsCollection,
                          output_path: Optional[str] = None) -> str:
        """
        Generate CSV report.
        
        Args:
            collection: Findings collection
            output_path: Optional file path to write report
            
        Returns:
            CSV string
        """
        filtered_findings = self._filter_findings(collection.findings)
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Header
        headers = [
            'ID', 'Title', 'Severity', 'Type', 'Source', 'Tool', 'File', 
            'Line Start', 'Line End', 'Column Start', 'Column End',
            'Rule ID', 'Message', 'Description', 'Suggestion', 'Confidence',
            'Impact', 'Effort to Fix', 'Tags', 'Detected At'
        ]
        writer.writerow(headers)
        
        # Data rows
        for finding in filtered_findings:
            row = [
                finding.id,
                finding.title,
                finding.severity.value,
                finding.finding_type.value,
                finding.source.value,
                finding.tool_name,
                finding.location.file_path,
                finding.location.line_start,
                finding.location.line_end,
                finding.location.column_start,
                finding.location.column_end,
                finding.rule_id or '',
                finding.message,
                finding.description,
                finding.suggestion,
                finding.confidence,
                finding.impact,
                finding.effort_to_fix,
                ', '.join(sorted(finding.tags)),
                finding.detected_at.isoformat()
            ]
            writer.writerow(row)
        
        csv_content = output.getvalue()
        output.close()
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8', newline='') as f:
                f.write(csv_content)
            logger.info(f"CSV report written to {output_path}")
        
        return csv_content
    
    def generate_sarif_report(self, collection: FindingsCollection,
                            output_path: Optional[str] = None) -> str:
        """
        Generate SARIF (Static Analysis Results Interchange Format) report.
        
        Args:
            collection: Findings collection
            output_path: Optional file path to write report
            
        Returns:
            SARIF JSON string
        """
        filtered_findings = self._filter_findings(collection.findings)
        
        # Group findings by tool
        tools_findings = {}
        for finding in filtered_findings:
            tool_key = f"{finding.source.value}:{finding.tool_name}"
            if tool_key not in tools_findings:
                tools_findings[tool_key] = []
            tools_findings[tool_key].append(finding)
        
        # Build SARIF structure
        runs = []
        for tool_key, tool_findings in tools_findings.items():
            source, tool_name = tool_key.split(':', 1)
            
            # Create rules
            rules = {}
            for finding in tool_findings:
                if finding.rule_id and finding.rule_id not in rules:
                    rules[finding.rule_id] = {
                        "id": finding.rule_id,
                        "name": finding.title,
                        "shortDescription": {"text": finding.message or finding.title},
                        "fullDescription": {"text": finding.description or finding.message or finding.title},
                        "defaultConfiguration": {
                            "level": self._severity_to_sarif_level(finding.severity)
                        },
                        "properties": {
                            "category": finding.finding_type.value,
                            "tags": list(finding.tags)
                        }
                    }
            
            # Create results
            results = []
            for finding in tool_findings:
                result = {
                    "ruleId": finding.rule_id,
                    "level": self._severity_to_sarif_level(finding.severity),
                    "message": {"text": finding.message or finding.title},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.location.file_path},
                            "region": {}
                        }
                    }]
                }
                
                # Add location details if available
                region = result["locations"][0]["physicalLocation"]["region"]
                if finding.location.line_start:
                    region["startLine"] = finding.location.line_start
                if finding.location.line_end:
                    region["endLine"] = finding.location.line_end
                if finding.location.column_start:
                    region["startColumn"] = finding.location.column_start
                if finding.location.column_end:
                    region["endColumn"] = finding.location.column_end
                
                # Add properties
                result["properties"] = {
                    "confidence": finding.confidence,
                    "impact": finding.impact,
                    "effort": finding.effort_to_fix,
                    "source": finding.source.value,
                    "findingType": finding.finding_type.value
                }
                
                results.append(result)
            
            # Create run
            run = {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": "1.0.0",
                        "informationUri": "https://github.com/beaux-riel/wtf-codebot",
                        "rules": list(rules.values())
                    }
                },
                "results": results
            }
            
            runs.append(run)
        
        sarif_data = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": runs
        }
        
        sarif_content = json.dumps(sarif_data, indent=2, ensure_ascii=False)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(sarif_content)
            logger.info(f"SARIF report written to {output_path}")
        
        return sarif_content
    
    def generate_text_summary(self, collection: FindingsCollection) -> str:
        """
        Generate a concise text summary.
        
        Args:
            collection: Findings collection
            
        Returns:
            Text summary string
        """
        filtered_findings = self._filter_findings(collection.findings)
        summary = self._generate_summary(filtered_findings)
        
        lines = []
        lines.append("CODE ANALYSIS SUMMARY")
        lines.append("=" * 50)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total Findings: {summary['total']}")
        lines.append(f"Files Affected: {summary['affected_files_count']}")
        lines.append("")
        
        lines.append("SEVERITY BREAKDOWN:")
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = summary['severity_counts'].get(severity, 0)
            if count > 0:
                lines.append(f"  {severity.upper()}: {count}")
        lines.append("")
        
        if summary['type_counts']:
            lines.append("TOP FINDING TYPES:")
            sorted_types = sorted(summary['type_counts'].items(), key=lambda x: x[1], reverse=True)
            for finding_type, count in sorted_types[:10]:
                lines.append(f"  {finding_type.replace('_', ' ').title()}: {count}")
            lines.append("")
        
        if summary['source_counts']:
            lines.append("ANALYSIS SOURCES:")
            for source, count in summary['source_counts'].items():
                lines.append(f"  {source.replace('_', ' ').title()}: {count}")
        
        return "\\n".join(lines)
    
    # Helper methods
    
    def _filter_findings(self, findings: List[UnifiedFinding]) -> List[UnifiedFinding]:
        """Filter findings based on severity filter."""
        if not self.severity_filter:
            return findings
        
        return [f for f in findings if f.severity in self.severity_filter]
    
    def _finding_to_dict(self, finding: UnifiedFinding) -> Dict[str, Any]:
        """Convert finding to dictionary with optional filtering."""
        data = finding.to_dict()
        
        if not self.include_source_locations:
            data.pop('location', None)
        
        if not self.include_metadata:
            data.pop('metadata', None)
        
        return data
    
    def _generate_summary(self, findings: List[UnifiedFinding]) -> Dict[str, Any]:
        """Generate summary statistics for findings."""
        if not findings:
            return {'total': 0}
        
        # Count by severity
        severity_counts = {}
        for severity in FindingSeverity:
            count = len([f for f in findings if f.severity == severity])
            severity_counts[severity.value] = count
        
        # Count by type
        type_counts = {}
        for finding_type in FindingType:
            count = len([f for f in findings if f.finding_type == finding_type])
            if count > 0:
                type_counts[finding_type.value] = count
        
        # Count by source
        source_counts = {}
        for source in FindingSource:
            count = len([f for f in findings if f.source == source])
            if count > 0:
                source_counts[source.value] = count
        
        # Files affected
        affected_files = set(f.location.file_path for f in findings)
        
        return {
            'total': len(findings),
            'severity_counts': severity_counts,
            'type_counts': type_counts,
            'source_counts': source_counts,
            'affected_files_count': len(affected_files),
            'affected_files': sorted(affected_files)
        }
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level."""
        emoji_map = {
            'critical': '🚨',
            'high': '🔴',
            'medium': '🟠',
            'low': '🟡',
            'info': '🔵'
        }
        return emoji_map.get(severity.lower(), '⚪')
    
    def _severity_to_sarif_level(self, severity: FindingSeverity) -> str:
        """Convert severity to SARIF level."""
        mapping = {
            FindingSeverity.CRITICAL: "error",
            FindingSeverity.HIGH: "error",
            FindingSeverity.MEDIUM: "warning",
            FindingSeverity.LOW: "note",
            FindingSeverity.INFO: "note"
        }
        return mapping.get(severity, "warning")
    
    def _get_html_styles(self) -> str:
        """Get CSS styles for HTML report."""
        return """
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px 8px 0 0;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .content {
            padding: 30px;
        }
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #007bff;
        }
        .card.critical { border-left-color: #dc3545; }
        .card.high { border-left-color: #fd7e14; }
        .card.medium { border-left-color: #ffc107; }
        .card.low { border-left-color: #28a745; }
        .card.info { border-left-color: #17a2b8; }
        .card-number {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .card-label {
            color: #6c757d;
            font-size: 0.9em;
        }
        .finding {
            border: 1px solid #ddd;
            border-radius: 8px;
            margin: 15px 0;
            padding: 20px;
            background: white;
        }
        .finding.critical { border-left: 4px solid #dc3545; }
        .finding.high { border-left: 4px solid #fd7e14; }
        .finding.medium { border-left: 4px solid #ffc107; }
        .finding.low { border-left: 4px solid #28a745; }
        .finding.info { border-left: 4px solid #17a2b8; }
        .finding-title {
            font-size: 1.2em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .finding-meta {
            display: flex;
            gap: 15px;
            margin-bottom: 15px;
            font-size: 0.9em;
            color: #6c757d;
        }
        .badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }
        .badge.critical { background: #dc3545; color: white; }
        .badge.high { background: #fd7e14; color: white; }
        .badge.medium { background: #ffc107; color: black; }
        .badge.low { background: #28a745; color: white; }
        .badge.info { background: #17a2b8; color: white; }
        .code-block {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            padding: 15px;
            margin: 10px 0;
            font-family: 'Monaco', 'Consolas', monospace;
            overflow-x: auto;
        }
        .filter-controls {
            margin: 20px 0;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        .filter-controls label {
            margin-right: 15px;
        }
        """
    
    def _get_html_scripts(self) -> str:
        """Get JavaScript for HTML report interactivity."""
        return """
        function filterBySeverity(severity) {
            const findings = document.querySelectorAll('.finding');
            findings.forEach(finding => {
                if (severity === 'all' || finding.classList.contains(severity)) {
                    finding.style.display = 'block';
                } else {
                    finding.style.display = 'none';
                }
            });
        }
        
        function filterByType(type) {
            const findings = document.querySelectorAll('.finding');
            findings.forEach(finding => {
                const typeElement = finding.querySelector('[data-type]');
                if (type === 'all' || (typeElement && typeElement.dataset.type === type)) {
                    finding.style.display = 'block';
                } else {
                    finding.style.display = 'none';
                }
            });
        }
        
        document.addEventListener('DOMContentLoaded', function() {
            // Add click handlers for collapsible sections
            const titles = document.querySelectorAll('.finding-title');
            titles.forEach(title => {
                title.style.cursor = 'pointer';
                title.addEventListener('click', function() {
                    const content = this.nextElementSibling;
                    if (content.style.display === 'none') {
                        content.style.display = 'block';
                    } else {
                        content.style.display = 'none';
                    }
                });
            });
        });
        """
    
    def _generate_html_summary(self, summary: Dict[str, Any], findings: List[UnifiedFinding]) -> str:
        """Generate HTML summary section."""
        cards_html = []
        
        # Total findings card
        cards_html.append(f"""
        <div class="card">
            <div class="card-number">{summary['total']}</div>
            <div class="card-label">Total Findings</div>
        </div>
        """)
        
        # Severity cards
        for severity in ['critical', 'high', 'medium', 'low']:
            count = summary['severity_counts'].get(severity, 0)
            if count > 0:
                cards_html.append(f"""
                <div class="card {severity}">
                    <div class="card-number">{count}</div>
                    <div class="card-label">{severity.title()}</div>
                </div>
                """)
        
        # Files affected card
        cards_html.append(f"""
        <div class="card">
            <div class="card-number">{summary['affected_files_count']}</div>
            <div class="card-label">Files Affected</div>
        </div>
        """)
        
        return f"""
        <div class="summary-cards">
            {''.join(cards_html)}
        </div>
        
        <div class="filter-controls">
            <label>Filter by Severity:</label>
            <select onchange="filterBySeverity(this.value)">
                <option value="all">All</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
            </select>
        </div>
        """
    
    def _generate_html_findings(self, findings: List[UnifiedFinding]) -> str:
        """Generate HTML findings section."""
        findings_html = []
        
        for finding in findings:
            location_info = ""
            if finding.location.line_start:
                location_info = f"Line {finding.location.line_start}"
                if finding.location.line_end and finding.location.line_end != finding.location.line_start:
                    location_info += f"-{finding.location.line_end}"
            
            code_block = ""
            if finding.affected_code:
                code_block = f"""
                <div class="code-block">
                    <strong>Affected Code:</strong><br>
                    <pre>{finding.affected_code}</pre>
                </div>
                """
            
            findings_html.append(f"""
            <div class="finding {finding.severity.value}">
                <div class="finding-title">{finding.title}</div>
                <div class="finding-meta">
                    <span class="badge {finding.severity.value}">{finding.severity.value.upper()}</span>
                    <span data-type="{finding.finding_type.value}">{finding.finding_type.value.replace('_', ' ').title()}</span>
                    <span>{finding.source.value.replace('_', ' ').title()}</span>
                    <span>{finding.location.file_path}</span>
                    {f'<span>{location_info}</span>' if location_info else ''}
                </div>
                <div class="finding-content">
                    {f'<p><strong>Description:</strong> {finding.description}</p>' if finding.description else ''}
                    {f'<p><strong>Message:</strong> {finding.message}</p>' if finding.message else ''}
                    {f'<p><strong>Suggestion:</strong> {finding.suggestion}</p>' if finding.suggestion else ''}
                    {code_block}
                </div>
            </div>
            """)
        
        return f"""
        <h2>Detailed Findings</h2>
        {''.join(findings_html)}
        """

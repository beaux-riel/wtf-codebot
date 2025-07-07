"""
Main analysis engine that orchestrates codebase scanning, analysis, and reporting.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
import logging

from ..discovery.scanner import CodebaseScanner
from ..analyzers.registry import get_registry
from ..analyzers.dependency_analyzer import DependencyAnalyzer
from ..core.config import Config
from ..core.exceptions import WTFCodeBotError

logger = logging.getLogger(__name__)


class AnalysisEngine:
    """
    Main analysis engine that coordinates the entire analysis workflow.
    
    This engine:
    1. Scans the codebase to discover files
    2. Runs static analysis using registered analyzers
    3. Runs dependency analysis for security vulnerabilities
    4. Aggregates and deduplicates findings
    5. Generates reports in requested formats
    """
    
    def __init__(self, config: Config):
        """
        Initialize the analysis engine.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.scanner = CodebaseScanner(
            max_file_size=config.analysis.max_file_size,
            include_content=True,
            parse_ast=True,
            ignore_dirs=set(config.analysis.exclude_patterns)
        )
        self.analyzer_registry = get_registry()
        self.dependency_analyzer = None  # Will be created per-analysis with callback
        
    def analyze(self, path: Path, progress_callback: Optional[Callable[[str, str, int, int], None]] = None) -> Dict[str, Any]:
        """
        Run complete analysis on the specified path.
        
        Args:
            path: Path to analyze (file or directory)
            progress_callback: Optional callback function to report progress (language, file_path, current_index, total_count)
            
        Returns:
            Dict[str, Any]: Analysis results
        """
        logger.info(f"Starting analysis of {path}")
        
        try:
            # Step 1: Scan codebase
            logger.info("Scanning codebase...")
            if path.is_file():
                # Handle single file analysis
                codebase_graph = self._scan_single_file(path)
            else:
                # Handle directory analysis
                codebase_graph = self.scanner.scan_directory(path)
            
            logger.info(f"Found {codebase_graph.total_files} files")
            
            # Step 2: Run static analysis
            logger.info("Running static analysis...")
            static_results = self.analyzer_registry.analyze_codebase(codebase_graph, progress_callback=progress_callback)
            
            # Step 3: Run dependency analysis (skip for single files)
            dependency_results = {}
            if path.is_file():
                logger.info("Skipping dependency analysis for single file")
            else:
                logger.info("Running dependency analysis...")
                dependency_results = self.dependency_analyzer.analyze_directory(str(path))
            
            # Step 4: Aggregate findings
            logger.info("Aggregating findings...")
            all_findings = self._aggregate_findings(static_results, dependency_results)
            
            # Step 5: Generate analysis results
            results = {
                "summary": self._generate_summary(codebase_graph, all_findings),
                "codebase_info": self._get_codebase_info(codebase_graph),
                "findings": self._convert_findings_to_dict(all_findings),
                "metrics": self._calculate_metrics(codebase_graph, all_findings),
                "dependencies": self._extract_dependencies(dependency_results),
                "vulnerabilities": self._extract_vulnerabilities(dependency_results),
            }
            
            logger.info(f"Analysis complete. Found {len(all_findings)} findings")
            return results
            
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            raise WTFCodeBotError(f"Analysis failed: {str(e)}") from e
    
    def analyze_selected_paths(self, base_path: Path, selected_paths: List[str], progress_callback: Optional[Callable[[str, str, int, int], None]] = None) -> Dict[str, Any]:
        """
        Analyze only selected files and directories.
        
        Args:
            base_path: Base directory path
            selected_paths: List of paths to analyze (relative to base_path)
            progress_callback: Optional callback function to report progress (language, file_path, current_index, total_count)
            
        Returns:
            Dict[str, Any]: Analysis results
        """
        logger.info(f"Starting analysis of selected paths in {base_path}")
        
        try:
            # Create a custom codebase graph with only selected files
            from ..discovery.models import CodebaseGraph
            codebase_graph = CodebaseGraph(root_path=base_path)
            
            for path_str in selected_paths:
                # Handle both absolute and relative paths
                if Path(path_str).is_absolute():
                    path = Path(path_str)
                else:
                    path = base_path / path_str
                    
                if path.exists():
                    if path.is_file():
                        # Scan single file
                        file_graph = self._scan_single_file(path)
                        for file_node in file_graph.files.values():
                            codebase_graph.add_file(file_node)
                    else:
                        # Scan directory
                        dir_graph = self.scanner.scan_directory(path)
                        for file_node in dir_graph.files.values():
                            codebase_graph.add_file(file_node)
            
            logger.info(f"Found {codebase_graph.total_files} files in selected paths")
            
            # Run static analysis
            logger.info("Running static analysis...")
            static_results = self.analyzer_registry.analyze_codebase(codebase_graph, progress_callback=progress_callback)
            
            # Skip dependency analysis for single file analysis or when only one file is selected
            dependency_results = {}
            if codebase_graph.total_files > 1 or len(selected_paths) > 1:
                logger.info("Running dependency analysis...")
                
                # Create dependency analyzer with progress callback
                def dep_progress_callback(message: str, current: int, total: int):
                    if progress_callback:
                        progress_callback("dependency", message, current, total)
                
                dependency_analyzer = DependencyAnalyzer("DependencyAnalyzer", progress_callback=dep_progress_callback)
                dependency_results = dependency_analyzer.analyze_directory(str(base_path))
            else:
                logger.info("Skipping dependency analysis for single file")
            
            # Aggregate findings
            logger.info("Aggregating findings...")
            all_findings = self._aggregate_findings(static_results, dependency_results)
            
            # Generate analysis results
            results = {
                "total_files": codebase_graph.total_files,
                "findings": all_findings,
                "dependencies": self._extract_dependencies(dependency_results),
                "vulnerabilities": self._extract_vulnerabilities(dependency_results),
            }
            
            logger.info(f"Analysis complete. Found {len(all_findings)} findings")
            return results
            
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            raise WTFCodeBotError(f"Analysis failed: {str(e)}") from e
    
    def _scan_single_file(self, file_path: Path):
        """Scan a single file and create a minimal codebase graph."""
        from ..discovery.models import CodebaseGraph, FileNode, FileType
        
        codebase_graph = CodebaseGraph(root_path=file_path.parent)
        
        # Determine file type
        extension = file_path.suffix.lower()
        file_type_map = {
            '.py': FileType.PYTHON,
            '.js': FileType.JAVASCRIPT,
            '.jsx': FileType.JAVASCRIPT,
            '.ts': FileType.TYPESCRIPT,
            '.tsx': FileType.TYPESCRIPT,
            '.html': FileType.HTML,
            '.css': FileType.CSS,
            '.json': FileType.JSON,
            '.yaml': FileType.YAML,
            '.yml': FileType.YAML,
            '.md': FileType.MARKDOWN,
        }
        file_type = file_type_map.get(extension, FileType.UNKNOWN)
        
        # Read file content
        try:
            content = file_path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            try:
                content = file_path.read_text(encoding='latin-1')
            except Exception:
                content = ""
        
        # Create file node
        stat = file_path.stat()
        file_node = FileNode(
            path=file_path,
            file_type=file_type,
            size=stat.st_size,
            last_modified=stat.st_mtime,
            content=content
        )
        
        codebase_graph.add_file(file_node)
        return codebase_graph
    
    def _aggregate_findings(self, static_results: Dict, dependency_results: Dict) -> List[Dict]:
        """Aggregate findings from different analysis sources."""
        all_findings = []
        
        # Add static analysis findings
        for language, analysis_result in static_results.items():
            for finding in analysis_result.findings:
                finding_dict = {
                    "id": f"{language}_{len(all_findings)}",
                    "source": "static_analysis",
                    "tool": language,
                    "severity": finding.severity.value,
                    "type": finding.pattern_type.value,
                    "title": finding.pattern_name,
                    "description": finding.description or finding.message,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "column_number": finding.column_number,
                    "message": finding.message,
                    "suggestion": finding.suggestion,
                    "metadata": finding.metadata
                }
                all_findings.append(finding_dict)
        
        # Add dependency vulnerabilities
        if dependency_results:
            # Handle list of DependencyAnalysisResult objects
            if isinstance(dependency_results, list):
                vuln_count = 0
                for dep_result in dependency_results:
                    if hasattr(dep_result, 'vulnerabilities'):
                        for vuln in dep_result.vulnerabilities:
                            finding_dict = {
                                "id": f"vuln_{vuln_count}",
                                "source": "dependency_analysis",
                                "tool": "dependency_analyzer",
                                "severity": getattr(vuln, 'severity', 'medium'),
                                "type": "vulnerability",
                                "title": getattr(vuln, 'title', 'Security Vulnerability'),
                                "description": getattr(vuln, 'description', ''),
                                "file_path": getattr(vuln, 'file_path', ''),
                                "line_number": None,
                                "column_number": None,
                                "message": getattr(vuln, 'summary', ''),
                                "suggestion": getattr(vuln, 'fix_recommendation', ''),
                                "metadata": vuln.__dict__ if hasattr(vuln, '__dict__') else {}
                            }
                            all_findings.append(finding_dict)
                            vuln_count += 1
            # Handle dict format (legacy)
            elif isinstance(dependency_results, dict) and "vulnerabilities" in dependency_results:
                for i, vuln in enumerate(dependency_results["vulnerabilities"]):
                    finding_dict = {
                        "id": f"vuln_{i}",
                        "source": "dependency_analysis",
                        "tool": "dependency_analyzer",
                        "severity": vuln.get("severity", "medium"),
                        "type": "vulnerability",
                        "title": vuln.get("title", "Security Vulnerability"),
                        "description": vuln.get("description", ""),
                        "file_path": vuln.get("file_path", ""),
                        "line_number": None,
                        "column_number": None,
                        "message": vuln.get("summary", ""),
                        "suggestion": vuln.get("fix_recommendation", ""),
                        "metadata": vuln
                    }
                    all_findings.append(finding_dict)
        
        return all_findings
    
    def _extract_dependencies(self, dependency_results):
        """Extract dependencies from dependency analysis results."""
        dependencies = []
        if isinstance(dependency_results, list):
            for dep_result in dependency_results:
                if hasattr(dep_result, 'dependencies'):
                    for name, dep_info in dep_result.dependencies.items():
                        dependencies.append({
                            "name": name,
                            "version": getattr(dep_info, 'version', ''),
                            "license": getattr(dep_info, 'license', ''),
                            "description": getattr(dep_info, 'description', ''),
                        })
        elif isinstance(dependency_results, dict):
            dependencies = dependency_results.get("dependencies", [])
        return dependencies
    
    def _extract_vulnerabilities(self, dependency_results):
        """Extract vulnerabilities from dependency analysis results."""
        vulnerabilities = []
        if isinstance(dependency_results, list):
            for dep_result in dependency_results:
                if hasattr(dep_result, 'vulnerabilities'):
                    for vuln in dep_result.vulnerabilities:
                        vulnerabilities.append({
                            "advisory_id": getattr(vuln, 'advisory_id', ''),
                            "severity": getattr(vuln, 'severity', 'unknown'),
                            "title": getattr(vuln, 'title', ''),
                            "description": getattr(vuln, 'description', ''),
                            "source": getattr(vuln, 'source', ''),
                        })
        elif isinstance(dependency_results, dict):
            vulnerabilities = dependency_results.get("vulnerabilities", [])
        return vulnerabilities
    
    def _convert_findings_to_dict(self, findings: List[Dict]) -> List[Dict]:
        """Convert findings to dictionary format."""
        return findings
    
    def _generate_summary(self, codebase_graph, findings: List[Dict]) -> Dict[str, Any]:
        """Generate analysis summary."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            "total_files": codebase_graph.total_files,
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "file_types": self.scanner.get_file_type_statistics(codebase_graph),
            "scan_errors": len(codebase_graph.scan_errors),
        }
    
    def _get_codebase_info(self, codebase_graph) -> Dict[str, Any]:
        """Get codebase information."""
        return {
            "root_path": str(codebase_graph.root_path),
            "total_files": codebase_graph.total_files,
            "file_types": self.scanner.get_file_type_statistics(codebase_graph),
            "scan_errors": codebase_graph.scan_errors,
        }
    
    def _calculate_metrics(self, codebase_graph, findings: List[Dict]) -> Dict[str, Any]:
        """Calculate analysis metrics."""
        total_lines = 0
        for file_type, file_paths in codebase_graph.file_types.items():
            for file_path in file_paths:
                file_node = codebase_graph.files.get(file_path)
                if file_node and file_node.content:
                    total_lines += len(file_node.content.splitlines())
        
        critical_findings = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
        high_findings = sum(1 for f in findings if f.get("severity", "").lower() == "high")
        
        # Calculate technical debt score (simple heuristic)
        debt_score = (critical_findings * 10) + (high_findings * 5)
        
        return {
            "total_lines_of_code": total_lines,
            "findings_per_kloc": round((len(findings) / max(total_lines / 1000, 1)), 2),
            "technical_debt_score": debt_score,
            "code_quality_grade": self._calculate_quality_grade(debt_score, total_lines),
        }
    
    def _calculate_quality_grade(self, debt_score: int, total_lines: int) -> str:
        """Calculate a simple code quality grade."""
        if total_lines == 0:
            return "N/A"
        
        debt_ratio = debt_score / max(total_lines / 1000, 1)
        
        if debt_ratio <= 1:
            return "A"
        elif debt_ratio <= 3:
            return "B"
        elif debt_ratio <= 7:
            return "C"
        elif debt_ratio <= 15:
            return "D"
        else:
            return "F"
    
    def generate_report(self, results: Dict[str, Any], output_format: str = "console") -> str:
        """
        Generate a report from analysis results.
        
        Args:
            results: Analysis results
            output_format: Output format ('console', 'json', 'markdown', 'html')
            
        Returns:
            str: Generated report
        """
        if output_format == "console":
            return self._generate_console_report(results)
        elif output_format == "json":
            return json.dumps(results, indent=2, default=str)
        elif output_format == "markdown":
            return self._generate_markdown_report(results)
        elif output_format == "html":
            return self._generate_html_report(results)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    
    def _generate_console_report(self, results: Dict[str, Any]) -> str:
        """Generate a console-friendly report."""
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from io import StringIO
        
        output = StringIO()
        console = Console(file=output, width=80)
        
        # Summary panel
        summary = results["summary"]
        summary_text = f"""
Total Files: {summary['total_files']}
Total Findings: {summary['total_findings']}
Quality Grade: {results['metrics']['code_quality_grade']}
Lines of Code: {results['metrics']['total_lines_of_code']:,}
Technical Debt Score: {results['metrics']['technical_debt_score']}
        """.strip()
        
        console.print(Panel(summary_text, title="Analysis Summary", style="green"))
        
        # Severity breakdown
        severity_table = Table(title="Findings by Severity")
        severity_table.add_column("Severity", style="bold")
        severity_table.add_column("Count", justify="right")
        
        for severity, count in summary["severity_breakdown"].items():
            if count > 0:
                style = "red" if severity in ["CRITICAL", "HIGH"] else "yellow" if severity == "MEDIUM" else "blue"
                severity_table.add_row(severity, str(count), style=style)
        
        console.print(severity_table)
        
        # File types
        if summary["file_types"]:
            file_table = Table(title="Files by Type")
            file_table.add_column("File Type", style="bold")
            file_table.add_column("Count", justify="right")
            
            for file_type, count in summary["file_types"].items():
                file_table.add_row(file_type, str(count))
            
            console.print(file_table)
        
        # Top findings
        findings = results.get("findings", [])
        if findings:
            console.print("\n[bold]Top Findings:[/bold]")
            for i, finding in enumerate(findings[:10], 1):
                console.print(f"{i}. [{finding['severity']}] {finding['title']}")
                if finding.get('file_path'):
                    console.print(f"   File: {finding['file_path']}")
                console.print(f"   {finding['description'][:100]}...")
                console.print()
        
        return output.getvalue()
    
    def _generate_markdown_report(self, results: Dict[str, Any]) -> str:
        """Generate a simple markdown report."""
        summary = results["summary"]
        findings = results.get("findings", [])
        
        report = f"# WTF CodeBot Analysis Report\n\n"
        report += f"## Summary\n\n"
        report += f"- **Total Files:** {summary['total_files']}\n"
        report += f"- **Total Findings:** {summary['total_findings']}\n"
        report += f"- **Quality Grade:** {results['metrics']['code_quality_grade']}\n"
        report += f"- **Lines of Code:** {results['metrics']['total_lines_of_code']:,}\n\n"
        
        report += f"## Findings by Severity\n\n"
        for severity, count in summary["severity_breakdown"].items():
            if count > 0:
                report += f"- **{severity.title()}:** {count}\n"
        
        if findings:
            report += f"\n## Top Findings\n\n"
            for i, finding in enumerate(findings[:10], 1):
                report += f"### {i}. {finding['title']}\n\n"
                report += f"- **Severity:** {finding['severity']}\n"
                report += f"- **File:** {finding['file_path']}\n"
                if finding.get('line_number'):
                    report += f"- **Line:** {finding['line_number']}\n"
                report += f"- **Description:** {finding['description']}\n\n"
        
        return report
    
    def _generate_html_report(self, results: Dict[str, Any]) -> str:
        """Generate a simple HTML report."""
        summary = results["summary"]
        findings = results.get("findings", [])
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>WTF CodeBot Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 5px; }}
        .finding {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #d32f2f; }}
        .high {{ border-left: 5px solid #f57c00; }}
        .medium {{ border-left: 5px solid #fbc02d; }}
        .low {{ border-left: 5px solid #388e3c; }}
        .info {{ border-left: 5px solid #1976d2; }}
    </style>
</head>
<body>
    <h1>WTF CodeBot Analysis Report</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Files:</strong> {summary['total_files']}</p>
        <p><strong>Total Findings:</strong> {summary['total_findings']}</p>
        <p><strong>Quality Grade:</strong> {results['metrics']['code_quality_grade']}</p>
        <p><strong>Lines of Code:</strong> {results['metrics']['total_lines_of_code']:,}</p>
    </div>
    
    <h2>Findings by Severity</h2>
    <ul>"""
        
        for severity, count in summary["severity_breakdown"].items():
            if count > 0:
                html += f"<li><strong>{severity.title()}:</strong> {count}</li>"
        
        html += "</ul>"
        
        if findings:
            html += "<h2>Findings</h2>"
            for finding in findings:
                severity_class = finding.get('severity', 'info').lower()
                html += f'<div class="finding {severity_class}">'
                html += f"<h3>{finding['title']}</h3>"
                html += f"<p><strong>Severity:</strong> {finding['severity']}</p>"
                html += f"<p><strong>File:</strong> {finding['file_path']}</p>"
                if finding.get('line_number'):
                    html += f"<p><strong>Line:</strong> {finding['line_number']}</p>"
                html += f"<p><strong>Description:</strong> {finding['description']}</p>"
                html += "</div>"
        
        html += "</body></html>"
        return html

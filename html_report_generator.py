#!/usr/bin/env python3
"""
Interactive HTML Report Generator

This module transforms JSON findings and dependency analysis into interactive HTML reports
using Jinja2 templating, Chart.js, and Plotly for comprehensive visualizations including:
- Metrics dashboards
- Dependency graphs
- Clickable issue lists
- Interactive filters and drill-downs
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
import base64
from collections import defaultdict, Counter

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)


class InteractiveHTMLReporter:
    """Interactive HTML report generator with advanced visualizations."""
    
    def __init__(self, template_dir: Optional[str] = None):
        """
        Initialize the HTML reporter.
        
        Args:
            template_dir: Directory containing Jinja2 templates
        """
        self.template_dir = template_dir or Path(__file__).parent / "templates"
        self.setup_templates()
        
    def setup_templates(self):
        """Setup Jinja2 template environment."""
        # Create template directory if it doesn't exist
        Path(self.template_dir).mkdir(parents=True, exist_ok=True)
        
        # Setup Jinja2 environment
        self.env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
        
        # Add custom filters
        self.env.filters['datetime'] = self._format_datetime
        self.env.filters['percentage'] = self._format_percentage
        self.env.filters['truncate_text'] = self._truncate_text
        self.env.filters['severity_color'] = self._get_severity_color
        self.env.filters['impact_color'] = self._get_impact_color
        
    def generate_interactive_report(self, 
                                  findings_json_path: str,
                                  dependencies_json_path: Optional[str] = None,
                                  output_path: str = "reports/interactive_report.html",
                                  title: str = "Code Analysis Report") -> str:
        """
        Generate interactive HTML report from JSON data.
        
        Args:
            findings_json_path: Path to findings JSON file
            dependencies_json_path: Path to dependencies JSON file
            output_path: Output path for HTML report
            title: Report title
            
        Returns:
            Path to generated HTML report
        """
        # Load data
        findings_data = self._load_json(findings_json_path)
        dependencies_data = self._load_json(dependencies_json_path) if dependencies_json_path else {}
        
        # Process data for visualization
        processed_data = self._process_data(findings_data, dependencies_data)
        
        # Create templates if they don't exist
        self._create_templates()
        
        # Generate HTML report
        template = self.env.get_template('main_report.html')
        html_content = template.render(
            title=title,
            generated_at=datetime.now(),
            data=processed_data,
            findings=findings_data,
            dependencies=dependencies_data
        )
        
        # Write to file
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Interactive HTML report generated: {output_path}")
        return str(output_file)
    
    def _load_json(self, file_path: str) -> Dict[str, Any]:
        """Load JSON data from file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"JSON file not found: {file_path}")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in file {file_path}: {e}")
            return {}
    
    def _process_data(self, findings_data: Dict[str, Any], dependencies_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process raw JSON data for visualization."""
        processed = {
            'metrics': self._calculate_metrics(findings_data, dependencies_data),
            'charts': self._prepare_chart_data(findings_data, dependencies_data),
            'tables': self._prepare_table_data(findings_data, dependencies_data),
            'dependencies': self._prepare_dependency_graph(dependencies_data),
            'summary': self._generate_summary(findings_data, dependencies_data)
        }
        return processed
    
    def _calculate_metrics(self, findings_data: Dict[str, Any], dependencies_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate key metrics for dashboard."""
        findings = findings_data.get('findings', [])
        
        # Basic counts
        total_findings = len(findings)
        severity_counts = Counter(f.get('severity', 'unknown') for f in findings)
        type_counts = Counter(f.get('finding_type', 'unknown') for f in findings)
        
        # Technical debt
        technical_debt_scores = [f.get('technical_debt_score', 0) for f in findings if f.get('technical_debt_score')]
        avg_technical_debt = sum(technical_debt_scores) / len(technical_debt_scores) if technical_debt_scores else 0
        
        # Security metrics
        security_findings = [f for f in findings if f.get('security_info', {}).get('cwe_ids')]
        security_count = len(security_findings)
        
        # Files affected
        affected_files = set()
        for finding in findings:
            location = finding.get('location', {})
            if location.get('file_path'):
                affected_files.add(location['file_path'])
        
        # Dependencies
        dep_summary = dependencies_data.get('summary', {})
        total_dependencies = dep_summary.get('total_dependencies', 0)
        vulnerabilities = dep_summary.get('total_vulnerabilities', 0)
        
        # Quality metrics
        quality_metrics = findings_data.get('quality_metrics', {})
        overall_score = quality_metrics.get('overall_score', 0)
        grade = quality_metrics.get('grade', 'N/A')
        
        return {
            'total_findings': total_findings,
            'severity_counts': dict(severity_counts),
            'type_counts': dict(type_counts),
            'affected_files_count': len(affected_files),
            'security_findings_count': security_count,
            'average_technical_debt': round(avg_technical_debt, 2),
            'total_dependencies': total_dependencies,
            'dependency_vulnerabilities': vulnerabilities,
            'overall_quality_score': overall_score,
            'quality_grade': grade,
            'risk_level': findings_data.get('risk_assessment', {}).get('overall_risk_level', 'unknown')
        }
    
    def _prepare_chart_data(self, findings_data: Dict[str, Any], dependencies_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for Chart.js visualizations."""
        findings = findings_data.get('findings', [])
        
        # Severity distribution
        severity_counts = Counter(f.get('severity', 'unknown') for f in findings)
        severity_chart = {
            'labels': list(severity_counts.keys()),
            'data': list(severity_counts.values()),
            'backgroundColor': [self._get_severity_color(s) for s in severity_counts.keys()]
        }
        
        # Finding types distribution
        type_counts = Counter(f.get('finding_type', 'unknown') for f in findings)
        type_chart = {
            'labels': list(type_counts.keys()),
            'data': list(type_counts.values())
        }
        
        # Technical debt over time (if timestamps available)
        debt_timeline = []
        for finding in findings:
            if finding.get('detected_at') and finding.get('technical_debt_score'):
                debt_timeline.append({
                    'date': finding['detected_at'],
                    'score': finding['technical_debt_score']
                })
        
        # Files with most issues
        file_issues = defaultdict(int)
        for finding in findings:
            location = finding.get('location', {})
            if location.get('file_path'):
                file_issues[location['file_path']] += 1
        
        top_files = sorted(file_issues.items(), key=lambda x: x[1], reverse=True)[:10]
        files_chart = {
            'labels': [f[0].split('/')[-1] for f in top_files],  # Just filename
            'data': [f[1] for f in top_files],
            'full_paths': [f[0] for f in top_files]
        }
        
        # Impact analysis
        impact_analysis = defaultdict(lambda: defaultdict(int))
        for finding in findings:
            impact = finding.get('impact_analysis', {})
            for impact_type, level in impact.items():
                if level and level != 'minimal':
                    impact_analysis[impact_type][level] += 1
        
        # License distribution (from dependencies)
        license_dist = dependencies_data.get('summary', {}).get('license_distribution', {})
        license_chart = {
            'labels': list(license_dist.keys()),
            'data': list(license_dist.values())
        }
        
        return {
            'severity_distribution': severity_chart,
            'type_distribution': type_chart,
            'technical_debt_timeline': debt_timeline,
            'files_with_issues': files_chart,
            'impact_analysis': dict(impact_analysis),
            'license_distribution': license_chart
        }
    
    def _prepare_table_data(self, findings_data: Dict[str, Any], dependencies_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for interactive tables."""
        findings = findings_data.get('findings', [])
        
        # Process findings for table
        processed_findings = []
        for finding in findings:
            location = finding.get('location', {})
            processed_finding = {
                'id': finding.get('id', ''),
                'title': finding.get('title', ''),
                'severity': finding.get('severity', 'unknown'),
                'type': finding.get('finding_type', 'unknown'),
                'file_path': location.get('file_path', ''),
                'line_start': location.get('line_start', ''),
                'line_end': location.get('line_end', ''),
                'function_name': location.get('function_name', ''),
                'class_name': location.get('class_name', ''),
                'description': finding.get('description', ''),
                'confidence': finding.get('confidence', 0),
                'technical_debt_score': finding.get('technical_debt_score', 0),
                'business_impact': finding.get('business_impact', 'unknown'),
                'effort_to_fix': finding.get('effort_to_fix', 'unknown'),
                'source': finding.get('source', ''),
                'tool_name': finding.get('tool_name', ''),
                'detected_at': finding.get('detected_at', ''),
                'tags': finding.get('tags', []),
                'cwe_ids': finding.get('security_info', {}).get('cwe_ids', []),
                'owasp_categories': finding.get('security_info', {}).get('owasp_categories', []),
                'remediation_description': finding.get('remediation', {}).get('description', ''),
                'remediation_priority': finding.get('remediation', {}).get('priority', ''),
                'pattern_name': finding.get('pattern_info', {}).get('name', ''),
                'pattern_confidence': finding.get('pattern_info', {}).get('confidence_score', 0)
            }
            processed_findings.append(processed_finding)
        
        # Process dependencies for table
        processed_dependencies = []
        for result in dependencies_data.get('results', []):
            for dep_name, dep_info in result.get('dependencies', {}).items():
                processed_dep = {
                    'name': dep_name,
                    'version': dep_info.get('version', ''),
                    'license': dep_info.get('license', 'Unknown'),
                    'description': dep_info.get('description', ''),
                    'dev_dependency': dep_info.get('dev_dependency', False),
                    'optional': dep_info.get('optional', False),
                    'file_path': result.get('file_path', ''),
                    'package_manager': result.get('package_manager', '')
                }
                processed_dependencies.append(processed_dep)
        
        return {
            'findings': processed_findings,
            'dependencies': processed_dependencies
        }
    
    def _prepare_dependency_graph(self, dependencies_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare dependency graph data for network visualization."""
        if not dependencies_data:
            return {'nodes': [], 'edges': []}
        
        nodes = []
        edges = []
        
        # Process dependency relationships
        for result in dependencies_data.get('results', []):
            file_path = result.get('file_path', '')
            package_manager = result.get('package_manager', '')
            
            # Add file node
            file_node = {
                'id': file_path,
                'label': file_path.split('/')[-1],
                'type': 'file',
                'size': 20,
                'color': '#ff6b6b'
            }
            nodes.append(file_node)
            
            # Add dependency nodes and edges
            for dep_name, dep_info in result.get('dependencies', {}).items():
                dep_node = {
                    'id': dep_name,
                    'label': dep_name,
                    'type': 'dependency',
                    'size': 15,
                    'color': '#4ecdc4' if not dep_info.get('dev_dependency') else '#45b7d1',
                    'license': dep_info.get('license', 'Unknown'),
                    'version': dep_info.get('version', ''),
                    'dev_dependency': dep_info.get('dev_dependency', False)
                }
                nodes.append(dep_node)
                
                # Add edge from file to dependency
                edge = {
                    'from': file_path,
                    'to': dep_name,
                    'label': 'depends on',
                    'color': '#999'
                }
                edges.append(edge)
        
        return {
            'nodes': nodes,
            'edges': edges
        }
    
    def _generate_summary(self, findings_data: Dict[str, Any], dependencies_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary."""
        findings = findings_data.get('findings', [])
        
        # Top issues by severity
        critical_issues = [f for f in findings if f.get('severity') == 'critical']
        high_issues = [f for f in findings if f.get('severity') == 'high']
        
        # Security summary
        security_findings = [f for f in findings if f.get('security_info', {}).get('cwe_ids')]
        unique_cwes = set()
        for f in security_findings:
            unique_cwes.update(f.get('security_info', {}).get('cwe_ids', []))
        
        # Recommendations
        recommendations = findings_data.get('recommendations', [])
        
        return {
            'critical_issues_count': len(critical_issues),
            'high_issues_count': len(high_issues),
            'security_findings_count': len(security_findings),
            'unique_cwe_count': len(unique_cwes),
            'top_recommendations': recommendations[:5],
            'risk_assessment': findings_data.get('risk_assessment', {}),
            'quality_metrics': findings_data.get('quality_metrics', {})
        }
    
    def _create_templates(self):
        """Create Jinja2 templates if they don't exist."""
        templates = {
            'main_report.html': self._get_main_template(),
            'charts.html': self._get_charts_template(),
            'tables.html': self._get_tables_template(),
            'dependencies.html': self._get_dependencies_template(),
            'styles.css': self._get_styles_template()
        }
        
        for template_name, content in templates.items():
            template_path = Path(self.template_dir) / template_name
            if not template_path.exists():
                with open(template_path, 'w', encoding='utf-8') as f:
                    f.write(content)
    
    def _get_main_template(self) -> str:
        """Get main HTML template."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    
    <!-- External Libraries -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://cdn.datatables.net/1.13.4/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.4/js/dataTables.bootstrap5.min.js"></script>
    
    <style>
        {% include 'styles.css' %}
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="#">
                <i class="fas fa-code"></i> {{ title }}
            </a>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text">
                    <i class="fas fa-clock"></i> Generated: {{ generated_at.strftime('%Y-%m-%d %H:%M') }}
                </span>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container-fluid py-4">
        <!-- Dashboard Overview -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-tachometer-alt"></i> Dashboard Overview
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-3">
                                <div class="metric-card text-center">
                                    <div class="metric-value">{{ data.metrics.total_findings }}</div>
                                    <div class="metric-label">Total Findings</div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="metric-card text-center">
                                    <div class="metric-value">{{ data.metrics.affected_files_count }}</div>
                                    <div class="metric-label">Affected Files</div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="metric-card text-center">
                                    <div class="metric-value">{{ data.metrics.overall_quality_score }}%</div>
                                    <div class="metric-label">Quality Score</div>
                                    <div class="metric-grade">Grade: {{ data.metrics.quality_grade }}</div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="metric-card text-center">
                                    <div class="metric-value risk-{{ data.metrics.risk_level }}">
                                        {{ data.metrics.risk_level|title }}
                                    </div>
                                    <div class="metric-label">Risk Level</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Tabs Navigation -->
        <ul class="nav nav-tabs" id="reportTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="overview-tab" data-bs-toggle="tab" data-bs-target="#overview" type="button" role="tab">
                    <i class="fas fa-chart-pie"></i> Overview
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="findings-tab" data-bs-toggle="tab" data-bs-target="#findings" type="button" role="tab">
                    <i class="fas fa-exclamation-triangle"></i> Findings ({{ data.metrics.total_findings }})
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="dependencies-tab" data-bs-toggle="tab" data-bs-target="#dependencies" type="button" role="tab">
                    <i class="fas fa-sitemap"></i> Dependencies ({{ data.metrics.total_dependencies }})
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="security-tab" data-bs-toggle="tab" data-bs-target="#security" type="button" role="tab">
                    <i class="fas fa-shield-alt"></i> Security ({{ data.metrics.security_findings_count }})
                </button>
            </li>
        </ul>

        <!-- Tab Content -->
        <div class="tab-content" id="reportTabsContent">
            <!-- Overview Tab -->
            <div class="tab-pane fade show active" id="overview" role="tabpanel">
                {% include 'charts.html' %}
            </div>

            <!-- Findings Tab -->
            <div class="tab-pane fade" id="findings" role="tabpanel">
                {% include 'tables.html' %}
            </div>

            <!-- Dependencies Tab -->
            <div class="tab-pane fade" id="dependencies" role="tabpanel">
                {% include 'dependencies.html' %}
            </div>

            <!-- Security Tab -->
            <div class="tab-pane fade" id="security" role="tabpanel">
                <div class="row mt-4">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">
                                    <i class="fas fa-shield-alt"></i> Security Analysis
                                </h5>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <h6>Risk Assessment</h6>
                                        <div class="alert alert-{{ data.summary.risk_assessment.overall_risk_level|default('info') }}">
                                            <strong>Risk Level:</strong> {{ data.summary.risk_assessment.overall_risk_level|title }}
                                            <br>
                                            <strong>Security Findings:</strong> {{ data.summary.security_findings_count }}
                                            <br>
                                            <strong>Unique CWEs:</strong> {{ data.summary.unique_cwe_count }}
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <h6>Security Recommendations</h6>
                                        <div class="list-group">
                                            {% for rec in data.summary.top_recommendations %}
                                            {% if rec.category == 'security' %}
                                            <div class="list-group-item">
                                                <strong>{{ rec.title }}</strong>
                                                <p class="mb-1">{{ rec.description }}</p>
                                                <small class="text-muted">{{ rec.action }}</small>
                                            </div>
                                            {% endif %}
                                            {% endfor %}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Scripts -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Global data for JavaScript
        const reportData = {{ data|tojson }};
        const findingsData = {{ findings|tojson }};
        const dependenciesData = {{ dependencies|tojson }};
    </script>
    
    <script>
        // Initialize charts and tables when document is ready
        document.addEventListener('DOMContentLoaded', function() {
            initializeCharts();
            initializeTables();
            initializeDependencyGraph();
            setupEventHandlers();
        });

        function initializeCharts() {
            // Severity Distribution Chart
            const severityCtx = document.getElementById('severityChart');
            if (severityCtx) {
                new Chart(severityCtx, {
                    type: 'doughnut',
                    data: {
                        labels: reportData.charts.severity_distribution.labels,
                        datasets: [{
                            data: reportData.charts.severity_distribution.data,
                            backgroundColor: reportData.charts.severity_distribution.backgroundColor
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: {
                                position: 'bottom'
                            }
                        }
                    }
                });
            }

            // Finding Types Chart
            const typesCtx = document.getElementById('typesChart');
            if (typesCtx) {
                new Chart(typesCtx, {
                    type: 'bar',
                    data: {
                        labels: reportData.charts.type_distribution.labels,
                        datasets: [{
                            label: 'Number of Findings',
                            data: reportData.charts.type_distribution.data,
                            backgroundColor: 'rgba(54, 162, 235, 0.7)'
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            }

            // Files with Issues Chart
            const filesCtx = document.getElementById('filesChart');
            if (filesCtx) {
                new Chart(filesCtx, {
                    type: 'horizontalBar',
                    data: {
                        labels: reportData.charts.files_with_issues.labels,
                        datasets: [{
                            label: 'Number of Issues',
                            data: reportData.charts.files_with_issues.data,
                            backgroundColor: 'rgba(255, 99, 132, 0.7)'
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            x: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            }

            // Technical Debt Timeline
            if (reportData.charts.technical_debt_timeline.length > 0) {
                const debtData = reportData.charts.technical_debt_timeline.map(item => ({
                    x: new Date(item.date),
                    y: item.score
                }));

                const timelineCtx = document.getElementById('debtTimelineChart');
                if (timelineCtx) {
                    new Chart(timelineCtx, {
                        type: 'line',
                        data: {
                            datasets: [{
                                label: 'Technical Debt Score',
                                data: debtData,
                                borderColor: 'rgb(75, 192, 192)',
                                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                                tension: 0.1
                            }]
                        },
                        options: {
                            responsive: true,
                            scales: {
                                x: {
                                    type: 'time',
                                    time: {
                                        unit: 'day'
                                    }
                                },
                                y: {
                                    beginAtZero: true
                                }
                            }
                        }
                    });
                }
            }
        }

        function initializeTables() {
            // Initialize DataTables for findings
            $('#findingsTable').DataTable({
                responsive: true,
                pageLength: 25,
                order: [[2, 'desc']], // Sort by severity
                columnDefs: [
                    {
                        targets: [2], // Severity column
                        render: function(data, type, row) {
                            return `<span class="badge bg-${getSeverityColor(data)}">${data}</span>`;
                        }
                    },
                    {
                        targets: [5], // Technical debt score
                        render: function(data, type, row) {
                            return data ? parseFloat(data).toFixed(1) : '0.0';
                        }
                    }
                ]
            });

            // Initialize DataTables for dependencies
            $('#dependenciesTable').DataTable({
                responsive: true,
                pageLength: 25,
                order: [[0, 'asc']], // Sort by name
                columnDefs: [
                    {
                        targets: [3], // Dev dependency column
                        render: function(data, type, row) {
                            return data ? '<i class="fas fa-check text-success"></i>' : '<i class="fas fa-times text-muted"></i>';
                        }
                    }
                ]
            });
        }

        function initializeDependencyGraph() {
            const container = document.getElementById('dependencyGraph');
            if (container && reportData.dependencies.nodes.length > 0) {
                const data = {
                    nodes: new vis.DataSet(reportData.dependencies.nodes),
                    edges: new vis.DataSet(reportData.dependencies.edges)
                };

                const options = {
                    nodes: {
                        shape: 'dot',
                        scaling: {
                            min: 10,
                            max: 30
                        },
                        font: {
                            size: 12,
                            face: 'Tahoma'
                        }
                    },
                    edges: {
                        width: 2,
                        color: {inherit: 'from'},
                        smooth: {
                            type: 'continuous'
                        }
                    },
                    physics: {
                        stabilization: {iterations: 200}
                    }
                };

                const network = new vis.Network(container, data, options);
                
                // Add click event for node details
                network.on('click', function(params) {
                    if (params.nodes.length > 0) {
                        const nodeId = params.nodes[0];
                        const node = reportData.dependencies.nodes.find(n => n.id === nodeId);
                        if (node) {
                            showNodeDetails(node);
                        }
                    }
                });
            }
        }

        function setupEventHandlers() {
            // Filter by severity
            document.getElementById('severityFilter')?.addEventListener('change', function() {
                const table = $('#findingsTable').DataTable();
                table.column(2).search(this.value).draw();
            });

            // Filter by type
            document.getElementById('typeFilter')?.addEventListener('change', function() {
                const table = $('#findingsTable').DataTable();
                table.column(3).search(this.value).draw();
            });

            // Clear filters
            document.getElementById('clearFilters')?.addEventListener('click', function() {
                const table = $('#findingsTable').DataTable();
                table.search('').columns().search('').draw();
                document.getElementById('severityFilter').value = '';
                document.getElementById('typeFilter').value = '';
            });
        }

        function getSeverityColor(severity) {
            const colors = {
                'critical': 'danger',
                'high': 'warning',
                'medium': 'info',
                'low': 'secondary',
                'info': 'light'
            };
            return colors[severity] || 'secondary';
        }

        function showNodeDetails(node) {
            const modalBody = document.getElementById('nodeDetailsBody');
            if (modalBody) {
                modalBody.innerHTML = `
                    <h6>${node.label}</h6>
                    <p><strong>Type:</strong> ${node.type}</p>
                    ${node.license ? `<p><strong>License:</strong> ${node.license}</p>` : ''}
                    ${node.version ? `<p><strong>Version:</strong> ${node.version}</p>` : ''}
                    ${node.dev_dependency !== undefined ? `<p><strong>Dev Dependency:</strong> ${node.dev_dependency ? 'Yes' : 'No'}</p>` : ''}
                `;
                
                const modal = new bootstrap.Modal(document.getElementById('nodeDetailsModal'));
                modal.show();
            }
        }
    </script>
</body>
</html>"""

    def _get_charts_template(self) -> str:
        """Get charts template."""
        return """
<div class="row mt-4">
    <!-- Severity Distribution -->
    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h6 class="mb-0">
                    <i class="fas fa-chart-pie"></i> Severity Distribution
                </h6>
            </div>
            <div class="card-body">
                <canvas id="severityChart"></canvas>
            </div>
        </div>
    </div>

    <!-- Finding Types -->
    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h6 class="mb-0">
                    <i class="fas fa-chart-bar"></i> Finding Types
                </h6>
            </div>
            <div class="card-body">
                <canvas id="typesChart"></canvas>
            </div>
        </div>
    </div>

    <!-- Files with Most Issues -->
    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h6 class="mb-0">
                    <i class="fas fa-file-code"></i> Files with Most Issues
                </h6>
            </div>
            <div class="card-body">
                <canvas id="filesChart"></canvas>
            </div>
        </div>
    </div>
</div>

<div class="row mt-4">
    <!-- Technical Debt Timeline -->
    <div class="col-md-8">
        <div class="card">
            <div class="card-header">
                <h6 class="mb-0">
                    <i class="fas fa-chart-line"></i> Technical Debt Timeline
                </h6>
            </div>
            <div class="card-body">
                <canvas id="debtTimelineChart"></canvas>
            </div>
        </div>
    </div>

    <!-- Summary Statistics -->
    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h6 class="mb-0">
                    <i class="fas fa-list"></i> Summary Statistics
                </h6>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-6">
                        <div class="text-center">
                            <div class="h4 text-danger">{{ data.summary.critical_issues_count }}</div>
                            <small class="text-muted">Critical</small>
                        </div>
                    </div>
                    <div class="col-6">
                        <div class="text-center">
                            <div class="h4 text-warning">{{ data.summary.high_issues_count }}</div>
                            <small class="text-muted">High</small>
                        </div>
                    </div>
                </div>
                <hr>
                <div class="row">
                    <div class="col-6">
                        <div class="text-center">
                            <div class="h4 text-info">{{ data.metrics.average_technical_debt }}</div>
                            <small class="text-muted">Avg Debt</small>
                        </div>
                    </div>
                    <div class="col-6">
                        <div class="text-center">
                            <div class="h4 text-success">{{ data.metrics.overall_quality_score }}%</div>
                            <small class="text-muted">Quality</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
"""

    def _get_tables_template(self) -> str:
        """Get tables template."""
        return """
<div class="row mt-4">
    <div class="col-12">
        <div class="card">
            <div class="card-header">
                <div class="row align-items-center">
                    <div class="col">
                        <h5 class="mb-0">
                            <i class="fas fa-list"></i> Findings Details
                        </h5>
                    </div>
                    <div class="col-auto">
                        <div class="row g-2">
                            <div class="col-auto">
                                <select class="form-select form-select-sm" id="severityFilter">
                                    <option value="">All Severities</option>
                                    <option value="critical">Critical</option>
                                    <option value="high">High</option>
                                    <option value="medium">Medium</option>
                                    <option value="low">Low</option>
                                    <option value="info">Info</option>
                                </select>
                            </div>
                            <div class="col-auto">
                                <select class="form-select form-select-sm" id="typeFilter">
                                    <option value="">All Types</option>
                                    {% for type in data.metrics.type_counts.keys() %}
                                    <option value="{{ type }}">{{ type|title }}</option>
                                    {% endfor %}
                                </select>
                            </div>
                            <div class="col-auto">
                                <button class="btn btn-sm btn-outline-secondary" id="clearFilters">
                                    <i class="fas fa-times"></i> Clear
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table id="findingsTable" class="table table-striped table-hover">
                        <thead>
                            <tr>
                                <th>Title</th>
                                <th>File</th>
                                <th>Severity</th>
                                <th>Type</th>
                                <th>Line</th>
                                <th>Debt Score</th>
                                <th>Effort</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for finding in data.tables.findings %}
                            <tr>
                                <td>
                                    <div class="fw-bold">{{ finding.title }}</div>
                                    <small class="text-muted">{{ finding.description|truncate_text(100) }}</small>
                                </td>
                                <td>
                                    <div class="text-monospace">{{ finding.file_path|default('N/A') }}</div>
                                    {% if finding.function_name %}
                                    <small class="text-muted">in {{ finding.function_name }}</small>
                                    {% endif %}
                                </td>
                                <td>
                                    <span class="badge bg-{{ finding.severity|severity_color }}">
                                        {{ finding.severity|title }}
                                    </span>
                                </td>
                                <td>
                                    <span class="badge bg-secondary">{{ finding.type|title }}</span>
                                </td>
                                <td>
                                    {% if finding.line_start %}
                                    <span class="text-monospace">{{ finding.line_start }}</span>
                                    {% if finding.line_end and finding.line_end != finding.line_start %}
                                    <span class="text-muted">-{{ finding.line_end }}</span>
                                    {% endif %}
                                    {% else %}
                                    <span class="text-muted">N/A</span>
                                    {% endif %}
                                </td>
                                <td>
                                    {% if finding.technical_debt_score %}
                                    <span class="badge bg-{{ finding.technical_debt_score|float|round|string|impact_color }}">
                                        {{ finding.technical_debt_score }}
                                    </span>
                                    {% else %}
                                    <span class="text-muted">N/A</span>
                                    {% endif %}
                                </td>
                                <td>
                                    <span class="badge bg-info">{{ finding.effort_to_fix|title }}</span>
                                </td>
                                <td>
                                    <button class="btn btn-sm btn-outline-primary" onclick="showFindingDetails('{{ finding.id }}')">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Finding Details Modal -->
<div class="modal fade" id="findingDetailsModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Finding Details</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body" id="findingDetailsBody">
                <!-- Content will be populated by JavaScript -->
            </div>
        </div>
    </div>
</div>

<script>
function showFindingDetails(findingId) {
    const finding = reportData.tables.findings.find(f => f.id === findingId);
    if (finding) {
        const modalBody = document.getElementById('findingDetailsBody');
        modalBody.innerHTML = `
            <div class="row">
                <div class="col-md-6">
                    <h6>Basic Information</h6>
                    <p><strong>Title:</strong> ${finding.title}</p>
                    <p><strong>Severity:</strong> <span class="badge bg-${getSeverityColor(finding.severity)}">${finding.severity}</span></p>
                    <p><strong>Type:</strong> ${finding.type}</p>
                    <p><strong>Source:</strong> ${finding.source} (${finding.tool_name})</p>
                    <p><strong>Confidence:</strong> ${(finding.confidence * 100).toFixed(1)}%</p>
                </div>
                <div class="col-md-6">
                    <h6>Location</h6>
                    <p><strong>File:</strong> <code>${finding.file_path}</code></p>
                    ${finding.line_start ? `<p><strong>Line:</strong> ${finding.line_start}${finding.line_end ? '-' + finding.line_end : ''}</p>` : ''}
                    ${finding.function_name ? `<p><strong>Function:</strong> ${finding.function_name}</p>` : ''}
                    ${finding.class_name ? `<p><strong>Class:</strong> ${finding.class_name}</p>` : ''}
                </div>
            </div>
            <div class="row mt-3">
                <div class="col-12">
                    <h6>Description</h6>
                    <p>${finding.description}</p>
                </div>
            </div>
            ${finding.remediation_description ? `
            <div class="row mt-3">
                <div class="col-12">
                    <h6>Remediation</h6>
                    <p>${finding.remediation_description}</p>
                    <p><strong>Priority:</strong> <span class="badge bg-info">${finding.remediation_priority}</span></p>
                    <p><strong>Effort:</strong> <span class="badge bg-secondary">${finding.effort_to_fix}</span></p>
                </div>
            </div>
            ` : ''}
            ${finding.cwe_ids && finding.cwe_ids.length > 0 ? `
            <div class="row mt-3">
                <div class="col-12">
                    <h6>Security Information</h6>
                    <p><strong>CWE IDs:</strong> ${finding.cwe_ids.join(', ')}</p>
                    ${finding.owasp_categories && finding.owasp_categories.length > 0 ? `<p><strong>OWASP Categories:</strong> ${finding.owasp_categories.join(', ')}</p>` : ''}
                </div>
            </div>
            ` : ''}
            ${finding.tags && finding.tags.length > 0 ? `
            <div class="row mt-3">
                <div class="col-12">
                    <h6>Tags</h6>
                    <p>${finding.tags.map(tag => `<span class="badge bg-light text-dark">${tag}</span>`).join(' ')}</p>
                </div>
            </div>
            ` : ''}
        `;
        
        const modal = new bootstrap.Modal(document.getElementById('findingDetailsModal'));
        modal.show();
    }
}
</script>
"""

    def _get_dependencies_template(self) -> str:
        """Get dependencies template."""
        return """
<div class="row mt-4">
    <div class="col-12">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">
                    <i class="fas fa-sitemap"></i> Dependency Network Graph
                </h5>
            </div>
            <div class="card-body">
                <div id="dependencyGraph" style="height: 400px;"></div>
            </div>
        </div>
    </div>
</div>

<div class="row mt-4">
    <div class="col-12">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">
                    <i class="fas fa-table"></i> Dependencies Details
                </h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table id="dependenciesTable" class="table table-striped table-hover">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Version</th>
                                <th>License</th>
                                <th>Dev Dependency</th>
                                <th>Package Manager</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for dep in data.tables.dependencies %}
                            <tr>
                                <td>
                                    <div class="fw-bold">{{ dep.name }}</div>
                                    <small class="text-muted">{{ dep.file_path|default('N/A') }}</small>
                                </td>
                                <td>
                                    <code>{{ dep.version }}</code>
                                </td>
                                <td>
                                    <span class="badge bg-{{ 'success' if dep.license != 'Unknown' else 'secondary' }}">
                                        {{ dep.license|default('Unknown') }}
                                    </span>
                                </td>
                                <td>
                                    {% if dep.dev_dependency %}
                                    <i class="fas fa-check text-success"></i>
                                    {% else %}
                                    <i class="fas fa-times text-muted"></i>
                                    {% endif %}
                                </td>
                                <td>
                                    <span class="badge bg-info">{{ dep.package_manager }}</span>
                                </td>
                                <td>
                                    <span class="text-muted">{{ dep.description|truncate_text(100) }}</span>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Node Details Modal -->
<div class="modal fade" id="nodeDetailsModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Node Details</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body" id="nodeDetailsBody">
                <!-- Content will be populated by JavaScript -->
            </div>
        </div>
    </div>
</div>
"""

    def _get_styles_template(self) -> str:
        """Get CSS styles template."""
        return """
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa;
        }

        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1.5rem;
            border-radius: 10px;
            margin-bottom: 1rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .metric-value {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }

        .metric-label {
            font-size: 0.9rem;
            opacity: 0.9;
        }

        .metric-grade {
            font-size: 0.8rem;
            margin-top: 0.25rem;
            opacity: 0.8;
        }

        .risk-critical {
            color: #dc3545;
        }

        .risk-high {
            color: #fd7e14;
        }

        .risk-medium {
            color: #ffc107;
        }

        .risk-low {
            color: #28a745;
        }

        .risk-minimal {
            color: #6c757d;
        }

        .card {
            border: none;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 1rem;
        }

        .card-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 10px 10px 0 0 !important;
            border: none;
        }

        .nav-tabs .nav-link {
            border-radius: 10px 10px 0 0;
            border: none;
            color: #495057;
            font-weight: 500;
        }

        .nav-tabs .nav-link.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }

        .table th {
            background-color: #f8f9fa;
            font-weight: 600;
            border-top: none;
        }

        .badge {
            font-size: 0.75rem;
            padding: 0.5em 0.75em;
        }

        .alert {
            border-radius: 10px;
            border: none;
        }

        .btn {
            border-radius: 8px;
            font-weight: 500;
        }

        .text-monospace {
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 0.9em;
        }

        .navbar-brand {
            font-weight: bold;
        }

        #dependencyGraph {
            border: 1px solid #dee2e6;
            border-radius: 8px;
        }

        .form-select-sm {
            border-radius: 6px;
        }

        .btn-sm {
            padding: 0.375rem 0.75rem;
            font-size: 0.875rem;
        }

        .modal-content {
            border-radius: 10px;
            border: none;
        }

        .modal-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 10px 10px 0 0;
            border: none;
        }

        .list-group-item {
            border-radius: 8px;
            border: 1px solid #dee2e6;
            margin-bottom: 0.5rem;
        }

        .list-group-item:hover {
            background-color: #f8f9fa;
        }

        /* DataTables custom styling */
        .dataTables_wrapper .dataTables_filter input {
            border-radius: 6px;
            border: 1px solid #ced4da;
        }

        .dataTables_wrapper .dataTables_length select {
            border-radius: 6px;
            border: 1px solid #ced4da;
        }

        .page-link {
            border-radius: 6px;
            margin: 0 2px;
        }

        /* Chart containers */
        .chart-container {
            position: relative;
            height: 300px;
            margin: 1rem 0;
        }

        /* Responsive adjustments */
        @media (max-width: 768px) {
            .metric-value {
                font-size: 2rem;
            }
            
            .metric-card {
                padding: 1rem;
            }
            
            .container-fluid {
                padding: 1rem;
            }
        }
        """

    # Filter functions
    def _format_datetime(self, value):
        """Format datetime for display."""
        if isinstance(value, str):
            try:
                dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                return dt.strftime('%Y-%m-%d %H:%M')
            except:
                return value
        return value

    def _format_percentage(self, value):
        """Format value as percentage."""
        try:
            return f"{float(value):.1f}%"
        except:
            return "0.0%"

    def _truncate_text(self, text, length=100):
        """Truncate text to specified length."""
        if not text:
            return ""
        return text[:length] + "..." if len(text) > length else text

    def _get_severity_color(self, severity):
        """Get Bootstrap color class for severity."""
        colors = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'secondary',
            'info': 'light'
        }
        return colors.get(severity.lower(), 'secondary')

    def _get_impact_color(self, impact):
        """Get Bootstrap color class for impact."""
        try:
            value = float(impact)
            if value >= 8:
                return 'danger'
            elif value >= 5:
                return 'warning'
            elif value >= 2:
                return 'info'
            else:
                return 'success'
        except:
            return 'secondary'


def main():
    """Generate interactive HTML report from existing JSON data."""
    reports_dir = Path("reports")
    
    # Check for existing JSON files
    findings_json = reports_dir / "enhanced_unified_findings.json"
    dependencies_json = reports_dir / "dependency_analysis.json"
    
    if not findings_json.exists():
        print(f"Findings JSON not found at {findings_json}")
        print("Using basic unified findings instead...")
        findings_json = reports_dir / "unified_findings.json"
        
    if not findings_json.exists():
        print("No findings JSON found. Please run the analysis first.")
        return
    
    # Initialize reporter
    reporter = InteractiveHTMLReporter()
    
    # Generate interactive report
    print("Generating interactive HTML report...")
    output_path = reports_dir / "interactive_report.html"
    
    generated_path = reporter.generate_interactive_report(
        findings_json_path=str(findings_json),
        dependencies_json_path=str(dependencies_json) if dependencies_json.exists() else None,
        output_path=str(output_path),
        title="WTF Codebot - Interactive Analysis Report"
    )
    
    print(f"Interactive HTML report generated: {generated_path}")
    print(f"Open in browser: file://{Path(generated_path).absolute()}")
    
    # Print summary
    with open(findings_json, 'r') as f:
        findings_data = json.load(f)
    
    total_findings = len(findings_data.get('findings', []))
    critical_count = len([f for f in findings_data.get('findings', []) if f.get('severity') == 'critical'])
    high_count = len([f for f in findings_data.get('findings', []) if f.get('severity') == 'high'])
    
    print(f"\nReport Summary:")
    print(f"  Total Findings: {total_findings}")
    print(f"  Critical Issues: {critical_count}")
    print(f"  High Priority Issues: {high_count}")
    
    if dependencies_json.exists():
        with open(dependencies_json, 'r') as f:
            deps_data = json.load(f)
        total_deps = deps_data.get('summary', {}).get('total_dependencies', 0)
        print(f"  Total Dependencies: {total_deps}")


if __name__ == "__main__":
    main()

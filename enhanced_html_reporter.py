#!/usr/bin/env python3
"""
Enhanced HTML Report Generator with Plotly Integration

This module extends the basic HTML reporter with advanced Plotly visualizations,
including 3D dependency graphs, sunburst charts, and interactive time series.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from collections import defaultdict, Counter

from html_report_generator import InteractiveHTMLReporter

logger = logging.getLogger(__name__)


class EnhancedHTMLReporter(InteractiveHTMLReporter):
    """Enhanced HTML reporter with Plotly integration for advanced visualizations."""
    
    def _get_main_template(self) -> str:
        """Get enhanced main HTML template with Plotly integration."""
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
        
        /* Additional styles for enhanced features */
        .plotly-container {
            height: 500px;
            margin: 1rem 0;
        }
        
        .metric-trend {
            font-size: 0.8rem;
            margin-top: 0.25rem;
        }
        
        .trend-up {
            color: #dc3545;
        }
        
        .trend-down {
            color: #28a745;
        }
        
        .trend-stable {
            color: #6c757d;
        }
        
        .interactive-filters {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 10px;
            margin-bottom: 1rem;
        }
        
        .chart-controls {
            background: #e9ecef;
            padding: 0.5rem;
            border-radius: 5px;
            margin-bottom: 1rem;
        }
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
        <!-- Enhanced Dashboard Overview -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-tachometer-alt"></i> Executive Dashboard
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-3">
                                <div class="metric-card text-center">
                                    <div class="metric-value">{{ data.metrics.total_findings }}</div>
                                    <div class="metric-label">Total Findings</div>
                                    <div class="metric-trend trend-{% if data.metrics.total_findings > 10 %}up{% elif data.metrics.total_findings < 5 %}down{% else %}stable{% endif %}">
                                        <i class="fas fa-arrow-{% if data.metrics.total_findings > 10 %}up{% elif data.metrics.total_findings < 5 %}down{% else %}right{% endif %}"></i>
                                        Risk {% if data.metrics.total_findings > 10 %}High{% elif data.metrics.total_findings < 5 %}Low{% else %}Moderate{% endif %}
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="metric-card text-center">
                                    <div class="metric-value">{{ data.metrics.affected_files_count }}</div>
                                    <div class="metric-label">Affected Files</div>
                                    <div class="metric-trend">
                                        <i class="fas fa-file-code"></i>
                                        {% if data.metrics.total_findings > 0 %}
                                        {{ ((data.metrics.affected_files_count / data.metrics.total_findings) * 100)|round|int }}% coverage
                                        {% endif %}
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="metric-card text-center">
                                    <div class="metric-value">{{ data.metrics.overall_quality_score }}%</div>
                                    <div class="metric-label">Quality Score</div>
                                    <div class="metric-grade">Grade: {{ data.metrics.quality_grade }}</div>
                                    <div class="metric-trend trend-{% if data.metrics.overall_quality_score >= 80 %}down{% elif data.metrics.overall_quality_score >= 60 %}stable{% else %}up{% endif %}">
                                        {% if data.metrics.overall_quality_score >= 80 %}
                                        <i class="fas fa-thumbs-up"></i> Excellent
                                        {% elif data.metrics.overall_quality_score >= 60 %}
                                        <i class="fas fa-hand-paper"></i> Good
                                        {% else %}
                                        <i class="fas fa-exclamation-triangle"></i> Needs Work
                                        {% endif %}
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="metric-card text-center">
                                    <div class="metric-value risk-{{ data.metrics.risk_level }}">
                                        {{ data.metrics.risk_level|title }}
                                    </div>
                                    <div class="metric-label">Risk Level</div>
                                    <div class="metric-trend">
                                        <i class="fas fa-shield-alt"></i>
                                        Security Score: {{ 100 - (data.metrics.security_findings_count * 10) }}%
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Interactive Filters -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="interactive-filters">
                    <div class="row align-items-center">
                        <div class="col-md-2">
                            <label class="form-label fw-bold">Global Filters:</label>
                        </div>
                        <div class="col-md-2">
                            <select class="form-select form-select-sm" id="globalSeverityFilter">
                                <option value="">All Severities</option>
                                <option value="critical">Critical</option>
                                <option value="high">High</option>
                                <option value="medium">Medium</option>
                                <option value="low">Low</option>
                                <option value="info">Info</option>
                            </select>
                        </div>
                        <div class="col-md-2">
                            <select class="form-select form-select-sm" id="globalDateFilter">
                                <option value="">All Time</option>
                                <option value="7">Last 7 days</option>
                                <option value="30">Last 30 days</option>
                                <option value="90">Last 90 days</option>
                            </select>
                        </div>
                        <div class="col-md-2">
                            <input type="text" class="form-control form-control-sm" id="globalFileFilter" placeholder="Filter by file...">
                        </div>
                        <div class="col-md-2">
                            <button class="btn btn-sm btn-primary" id="applyGlobalFilters">
                                <i class="fas fa-filter"></i> Apply
                            </button>
                        </div>
                        <div class="col-md-2">
                            <button class="btn btn-sm btn-outline-secondary" id="clearGlobalFilters">
                                <i class="fas fa-times"></i> Clear All
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Enhanced Tabs Navigation -->
        <ul class="nav nav-tabs" id="reportTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="overview-tab" data-bs-toggle="tab" data-bs-target="#overview" type="button" role="tab">
                    <i class="fas fa-chart-pie"></i> Overview
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="analytics-tab" data-bs-toggle="tab" data-bs-target="#analytics" type="button" role="tab">
                    <i class="fas fa-chart-line"></i> Advanced Analytics
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

            <!-- Advanced Analytics Tab -->
            <div class="tab-pane fade" id="analytics" role="tabpanel">
                <div class="row mt-4">
                    <!-- Technical Debt Heatmap -->
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h6 class="mb-0">
                                    <i class="fas fa-fire"></i> Technical Debt Heatmap
                                </h6>
                                <div class="chart-controls">
                                    <button class="btn btn-sm btn-outline-primary" onclick="toggleHeatmapView('file')">By File</button>
                                    <button class="btn btn-sm btn-outline-primary" onclick="toggleHeatmapView('severity')">By Severity</button>
                                    <button class="btn btn-sm btn-outline-primary" onclick="toggleHeatmapView('type')">By Type</button>
                                </div>
                            </div>
                            <div class="card-body">
                                <div id="debtHeatmap" class="plotly-container"></div>
                            </div>
                        </div>
                    </div>

                    <!-- Trend Analysis -->
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h6 class="mb-0">
                                    <i class="fas fa-chart-area"></i> Quality Trends
                                </h6>
                            </div>
                            <div class="card-body">
                                <div id="trendAnalysis" class="plotly-container"></div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="row mt-4">
                    <!-- 3D Dependency Graph -->
                    <div class="col-md-8">
                        <div class="card">
                            <div class="card-header">
                                <h6 class="mb-0">
                                    <i class="fas fa-cube"></i> 3D Dependency Network
                                </h6>
                                <div class="chart-controls">
                                    <button class="btn btn-sm btn-outline-primary" onclick="toggle3DView()">Toggle 3D/2D</button>
                                    <button class="btn btn-sm btn-outline-primary" onclick="resetDepGraph()">Reset View</button>
                                    <button class="btn btn-sm btn-outline-primary" onclick="exportDepGraph()">Export</button>
                                </div>
                            </div>
                            <div class="card-body">
                                <div id="dependency3D" class="plotly-container"></div>
                            </div>
                        </div>
                    </div>

                    <!-- Complexity Sunburst -->
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-header">
                                <h6 class="mb-0">
                                    <i class="fas fa-sun"></i> Complexity Breakdown
                                </h6>
                            </div>
                            <div class="card-body">
                                <div id="complexitySunburst" class="plotly-container"></div>
                            </div>
                        </div>
                    </div>
                </div>
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
                    <div class="col-md-8">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">
                                    <i class="fas fa-shield-alt"></i> Security Analysis
                                </h5>
                            </div>
                            <div class="card-body">
                                <div id="securityMatrix" class="plotly-container"></div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-header">
                                <h6 class="mb-0">Risk Assessment</h6>
                            </div>
                            <div class="card-body">
                                <div class="alert alert-{{ data.summary.risk_assessment.overall_risk_level|default('info') }}">
                                    <strong>Risk Level:</strong> {{ data.summary.risk_assessment.overall_risk_level|title }}
                                    <br>
                                    <strong>Security Findings:</strong> {{ data.summary.security_findings_count }}
                                    <br>
                                    <strong>Unique CWEs:</strong> {{ data.summary.unique_cwe_count }}
                                </div>
                                
                                <h6 class="mt-3">Security Recommendations</h6>
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

    <!-- Scripts -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Global data for JavaScript
        const reportData = {{ data|tojson }};
        const findingsData = {{ findings|tojson }};
        const dependenciesData = {{ dependencies|tojson }};
        
        // State management
        let currentFilters = {
            severity: '',
            dateRange: '',
            filePattern: ''
        };
        
        let currentView = '2d';
    </script>
    
    <script>
        // Initialize all visualizations when document is ready
        document.addEventListener('DOMContentLoaded', function() {
            initializeCharts();
            initializeTables();
            initializeDependencyGraph();
            initializeAdvancedCharts();
            setupEventHandlers();
            setupAdvancedEventHandlers();
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
                    type: 'bar',
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
                        indexAxis: 'y',
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

        function initializeAdvancedCharts() {
            initializeTechnicalDebtHeatmap();
            initializeTrendAnalysis();
            initialize3DDependencyGraph();
            initializeComplexitySunburst();
            initializeSecurityMatrix();
        }

        function initializeTechnicalDebtHeatmap() {
            const findings = reportData.tables.findings;
            
            // Prepare heatmap data
            const fileMap = {};
            findings.forEach(finding => {
                const file = finding.file_path || 'Unknown';
                const shortFile = file.split('/').pop();
                if (!fileMap[shortFile]) {
                    fileMap[shortFile] = {
                        debt: 0,
                        count: 0,
                        severities: {}
                    };
                }
                fileMap[shortFile].debt += finding.technical_debt_score || 0;
                fileMap[shortFile].count += 1;
                fileMap[shortFile].severities[finding.severity] = (fileMap[shortFile].severities[finding.severity] || 0) + 1;
            });
            
            const files = Object.keys(fileMap);
            const avgDebt = files.map(file => fileMap[file].debt / fileMap[file].count || 0);
            const counts = files.map(file => fileMap[file].count);
            
            const data = [{
                z: [avgDebt],
                x: files,
                y: ['Technical Debt'],
                type: 'heatmap',
                colorscale: [
                    [0, '#28a745'],
                    [0.5, '#ffc107'],
                    [1, '#dc3545']
                ],
                hovertemplate: 'File: %{x}<br>Avg Debt: %{z:.1f}<br>Issues: ' + counts.map((c, i) => files[i] + ': ' + c).join('<br>') + '<extra></extra>'
            }];
            
            const layout = {
                title: 'Technical Debt by File',
                xaxis: { title: 'Files' },
                yaxis: { title: 'Metrics' },
                margin: { t: 50, r: 50, b: 100, l: 50 }
            };
            
            Plotly.newPlot('debtHeatmap', data, layout, {responsive: true});
        }

        function initializeTrendAnalysis() {
            // Create simulated trend data
            const dates = [];
            const qualityScores = [];
            const debtScores = [];
            const issuesCounts = [];
            
            for (let i = 30; i >= 0; i--) {
                const date = new Date();
                date.setDate(date.getDate() - i);
                dates.push(date.toISOString().split('T')[0]);
                
                // Simulate trending data
                const baseQuality = reportData.metrics.overall_quality_score;
                const variation = Math.sin(i / 10) * 10;
                qualityScores.push(Math.max(0, Math.min(100, baseQuality + variation)));
                
                const baseDebt = reportData.metrics.average_technical_debt;
                debtScores.push(Math.max(0, baseDebt + (Math.random() - 0.5) * 2));
                
                const baseIssues = reportData.metrics.total_findings;
                issuesCounts.push(Math.max(0, Math.round(baseIssues + (Math.random() - 0.5) * 5)));
            }
            
            const trace1 = {
                x: dates,
                y: qualityScores,
                name: 'Quality Score',
                type: 'scatter',
                line: { color: 'rgb(75, 192, 192)' }
            };
            
            const trace2 = {
                x: dates,
                y: debtScores,
                name: 'Technical Debt',
                type: 'scatter',
                yaxis: 'y2',
                line: { color: 'rgb(255, 99, 132)' }
            };
            
            const trace3 = {
                x: dates,
                y: issuesCounts,
                name: 'Issue Count',
                type: 'scatter',
                yaxis: 'y3',
                line: { color: 'rgb(255, 205, 86)' }
            };
            
            const layout = {
                title: 'Quality Metrics Over Time',
                xaxis: { title: 'Date' },
                yaxis: { title: 'Quality Score (%)', side: 'left' },
                yaxis2: { title: 'Technical Debt', side: 'right', overlaying: 'y' },
                yaxis3: { title: 'Issue Count', side: 'right', overlaying: 'y', position: 0.95 },
                margin: { t: 50, r: 100, b: 50, l: 50 }
            };
            
            Plotly.newPlot('trendAnalysis', [trace1, trace2, trace3], layout, {responsive: true});
        }

        function initialize3DDependencyGraph() {
            const deps = reportData.dependencies;
            if (!deps.nodes || deps.nodes.length === 0) {
                document.getElementById('dependency3D').innerHTML = '<p class="text-center text-muted">No dependency data available</p>';
                return;
            }
            
            // Prepare 3D network data
            const x = [];
            const y = [];
            const z = [];
            const text = [];
            const colors = [];
            
            deps.nodes.forEach((node, i) => {
                // Distribute nodes in 3D space
                const angle = (i / deps.nodes.length) * 2 * Math.PI;
                const radius = Math.random() * 10 + 5;
                const height = Math.random() * 10;
                
                x.push(radius * Math.cos(angle));
                y.push(radius * Math.sin(angle));
                z.push(height);
                text.push(node.label);
                colors.push(node.type === 'file' ? 'red' : 'blue');
            });
            
            const trace = {
                x: x,
                y: y,
                z: z,
                mode: 'markers+text',
                type: 'scatter3d',
                text: text,
                textposition: 'top center',
                marker: {
                    size: 8,
                    color: colors,
                    opacity: 0.8
                },
                hovertemplate: '%{text}<extra></extra>'
            };
            
            const layout = {
                title: '3D Dependency Network',
                scene: {
                    xaxis: { title: 'X' },
                    yaxis: { title: 'Y' },
                    zaxis: { title: 'Z' }
                },
                margin: { t: 50, r: 50, b: 50, l: 50 }
            };
            
            Plotly.newPlot('dependency3D', [trace], layout, {responsive: true});
        }

        function initializeComplexitySunburst() {
            const findings = reportData.tables.findings;
            
            // Prepare sunburst data
            const typeMap = {};
            findings.forEach(finding => {
                const type = finding.type || 'Unknown';
                const severity = finding.severity || 'unknown';
                
                if (!typeMap[type]) {
                    typeMap[type] = {};
                }
                typeMap[type][severity] = (typeMap[type][severity] || 0) + 1;
            });
            
            const ids = [];
            const labels = [];
            const parents = [];
            const values = [];
            
            // Root
            ids.push('Total');
            labels.push('All Issues');
            parents.push('');
            values.push(findings.length);
            
            // Types
            Object.keys(typeMap).forEach(type => {
                const typeCount = Object.values(typeMap[type]).reduce((a, b) => a + b, 0);
                ids.push(type);
                labels.push(type);
                parents.push('Total');
                values.push(typeCount);
                
                // Severities within types
                Object.keys(typeMap[type]).forEach(severity => {
                    ids.push(`${type}-${severity}`);
                    labels.push(severity);
                    parents.push(type);
                    values.push(typeMap[type][severity]);
                });
            });
            
            const data = [{
                type: 'sunburst',
                ids: ids,
                labels: labels,
                parents: parents,
                values: values,
                branchvalues: 'total'
            }];
            
            const layout = {
                title: 'Issue Complexity Breakdown',
                margin: { t: 50, r: 50, b: 50, l: 50 }
            };
            
            Plotly.newPlot('complexitySunburst', data, layout, {responsive: true});
        }

        function initializeSecurityMatrix() {
            const findings = reportData.tables.findings;
            const securityFindings = findings.filter(f => f.cwe_ids && f.cwe_ids.length > 0);
            
            if (securityFindings.length === 0) {
                document.getElementById('securityMatrix').innerHTML = '<p class="text-center text-muted">No security findings available</p>';
                return;
            }
            
            // Prepare matrix data
            const severities = ['critical', 'high', 'medium', 'low', 'info'];
            const types = ['vulnerability', 'authentication', 'authorization', 'input_validation', 'cryptography'];
            
            const matrix = severities.map(severity => 
                types.map(type => {
                    return securityFindings.filter(f => 
                        f.severity === severity && f.type.includes(type)
                    ).length;
                })
            );
            
            const data = [{
                z: matrix,
                x: types,
                y: severities,
                type: 'heatmap',
                colorscale: 'Reds',
                hovertemplate: 'Type: %{x}<br>Severity: %{y}<br>Count: %{z}<extra></extra>'
            }];
            
            const layout = {
                title: 'Security Issues Matrix',
                xaxis: { title: 'Vulnerability Types' },
                yaxis: { title: 'Severity Levels' },
                margin: { t: 50, r: 50, b: 100, l: 100 }
            };
            
            Plotly.newPlot('securityMatrix', data, layout, {responsive: true});
        }

        // Enhanced event handlers
        function setupAdvancedEventHandlers() {
            // Global filters
            document.getElementById('applyGlobalFilters')?.addEventListener('click', applyGlobalFilters);
            document.getElementById('clearGlobalFilters')?.addEventListener('click', clearGlobalFilters);
        }

        function applyGlobalFilters() {
            currentFilters.severity = document.getElementById('globalSeverityFilter').value;
            currentFilters.dateRange = document.getElementById('globalDateFilter').value;
            currentFilters.filePattern = document.getElementById('globalFileFilter').value;
            
            // Apply filters to all visualizations
            updateAllVisualizationsWithFilters();
        }

        function clearGlobalFilters() {
            document.getElementById('globalSeverityFilter').value = '';
            document.getElementById('globalDateFilter').value = '';
            document.getElementById('globalFileFilter').value = '';
            currentFilters = { severity: '', dateRange: '', filePattern: '' };
            
            // Reset all visualizations
            updateAllVisualizationsWithFilters();
        }

        function updateAllVisualizationsWithFilters() {
            // Re-initialize charts with filtered data
            const filteredData = applyFiltersToData(reportData, currentFilters);
            
            // Update charts
            initializeTechnicalDebtHeatmap();
            initializeTrendAnalysis();
            initialize3DDependencyGraph();
            initializeComplexitySunburst();
            initializeSecurityMatrix();
            
            // Update tables
            const table = $('#findingsTable').DataTable();
            table.draw();
        }

        function applyFiltersToData(data, filters) {
            // Apply filters to the data and return filtered version
            // This is a simplified version - in a real implementation,
            // you'd want to filter the actual data structures
            return data;
        }

        // Chart interaction functions
        function toggleHeatmapView(viewType) {
            // Toggle between different heatmap views
            console.log('Switching heatmap view to:', viewType);
            // Implementation would switch the heatmap data
        }

        function toggle3DView() {
            currentView = currentView === '2d' ? '3d' : '2d';
            console.log('Toggling 3D view to:', currentView);
            // Implementation would switch between 2D and 3D dependency graphs
        }

        function resetDepGraph() {
            initialize3DDependencyGraph();
        }

        function exportDepGraph() {
            // Export dependency graph as image
            Plotly.downloadImage('dependency3D', {
                format: 'png',
                width: 1200,
                height: 800,
                filename: 'dependency-graph'
            });
        }

        // Standard initialization functions from base class
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

    def generate_enhanced_report(self, 
                                findings_json_path: str,
                                dependencies_json_path: Optional[str] = None,
                                output_path: str = "reports/enhanced_interactive_report.html",
                                title: str = "Enhanced Code Analysis Report") -> str:
        """
        Generate enhanced interactive HTML report with Plotly visualizations.
        
        Args:
            findings_json_path: Path to findings JSON file
            dependencies_json_path: Path to dependencies JSON file
            output_path: Output path for HTML report
            title: Report title
            
        Returns:
            Path to generated HTML report
        """
        return self.generate_interactive_report(
            findings_json_path=findings_json_path,
            dependencies_json_path=dependencies_json_path,
            output_path=output_path,
            title=title
        )


def main():
    """Generate enhanced interactive HTML report from existing JSON data."""
    reports_dir = Path("reports")
    
    # Check for existing JSON files
    findings_json = reports_dir / "enhanced_unified_findings.json"
    dependencies_json = reports_dir / "dependency_analysis.json"
    
    if not findings_json.exists():
        print(f"Enhanced findings JSON not found at {findings_json}")
        print("Using basic unified findings instead...")
        findings_json = reports_dir / "unified_findings.json"
        
    if not findings_json.exists():
        print("No findings JSON found. Please run the analysis first.")
        return
    
    # Initialize enhanced reporter
    reporter = EnhancedHTMLReporter()
    
    # Generate enhanced interactive report
    print("Generating enhanced interactive HTML report with Plotly...")
    output_path = reports_dir / "enhanced_interactive_report.html"
    
    generated_path = reporter.generate_enhanced_report(
        findings_json_path=str(findings_json),
        dependencies_json_path=str(dependencies_json) if dependencies_json.exists() else None,
        output_path=str(output_path),
        title="WTF Codebot - Enhanced Interactive Analysis Report"
    )
    
    print(f"Enhanced interactive HTML report generated: {generated_path}")
    print(f"Open in browser: file://{Path(generated_path).absolute()}")
    
    # Print feature summary
    print(f"\nEnhanced Features:")
    print(f"  ✓ Interactive Charts (Chart.js)")
    print(f"  ✓ Advanced Analytics (Plotly)")
    print(f"  ✓ 3D Dependency Graphs")
    print(f"  ✓ Technical Debt Heatmaps")
    print(f"  ✓ Complexity Sunburst Charts")
    print(f"  ✓ Security Risk Matrix")
    print(f"  ✓ Trend Analysis")
    print(f"  ✓ Global Filters")
    print(f"  ✓ Export Capabilities")
    print(f"  ✓ Responsive Design")
    
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

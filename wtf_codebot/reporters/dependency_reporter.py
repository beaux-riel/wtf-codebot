"""
Dependency Analysis Reporter

Generates comprehensive reports for dependency and security analysis results.
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from wtf_codebot.analyzers.dependency_analyzer import DependencyAnalysisResult, VulnerabilityInfo


class DependencyReporter:
    """Reporter for dependency analysis results"""
    
    def __init__(self):
        self.results: List[DependencyAnalysisResult] = []
    
    def add_result(self, result: DependencyAnalysisResult):
        """Add a dependency analysis result"""
        self.results.append(result)
    
    def generate_html_report(self, output_path: str) -> str:
        """Generate an HTML report"""
        html_content = self._generate_html_template()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    def generate_json_report(self, output_path: str) -> str:
        """Generate a JSON report"""
        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "wtf-codebot dependency analyzer",
                "version": "1.0.0",
                "total_files": len(self.results),
                "total_dependencies": sum(len(r.dependencies) for r in self.results),
                "total_vulnerabilities": sum(len(r.vulnerabilities) for r in self.results)
            },
            "summary": self._generate_summary(),
            "results": []
        }
        
        for result in self.results:
            result_data = {
                "package_manager": result.package_manager,
                "file_path": result.file_path,
                "analysis_timestamp": result.analysis_timestamp.isoformat(),
                "statistics": {
                    "total_dependencies": len(result.dependencies),
                    "production_dependencies": len([d for d in result.dependencies.values() if not d.dev_dependency]),
                    "dev_dependencies": len([d for d in result.dependencies.values() if d.dev_dependency]),
                    "optional_dependencies": len([d for d in result.dependencies.values() if d.optional]),
                    "vulnerabilities": len(result.vulnerabilities),
                    "unique_licenses": len(result.license_summary)
                },
                "dependencies": {
                    name: {
                        "name": dep.name,
                        "version": dep.version,
                        "version_constraint": dep.version_constraint,
                        "license": dep.license,
                        "description": dep.description,
                        "dependencies": dep.dependencies,
                        "dev_dependency": dep.dev_dependency,
                        "optional": dep.optional
                    }
                    for name, dep in result.dependencies.items()
                },
                "vulnerabilities": [
                    {
                        "cve_id": vuln.cve_id,
                        "advisory_id": vuln.advisory_id,
                        "severity": vuln.severity,
                        "title": vuln.title,
                        "description": vuln.description,
                        "affected_versions": vuln.affected_versions,
                        "fixed_versions": vuln.fixed_versions,
                        "published_date": vuln.published_date.isoformat() if vuln.published_date else None,
                        "source": vuln.source
                    }
                    for vuln in result.vulnerabilities
                ],
                "license_summary": result.license_summary,
                "dependency_tree": result.dependency_tree
            }
            report_data["results"].append(result_data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        return output_path
    
    def generate_markdown_report(self, output_path: str) -> str:
        """Generate a Markdown report"""
        content = []
        
        # Header
        content.append("# Dependency & Security Analysis Report")
        content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        content.append("")
        
        # Summary
        summary = self._generate_summary()
        content.append("## 📊 Summary")
        content.append(f"- **Files Analyzed**: {summary['total_files']}")
        content.append(f"- **Total Dependencies**: {summary['total_dependencies']}")
        content.append(f"- **Security Vulnerabilities**: {summary['total_vulnerabilities']}")
        content.append(f"- **License Types**: {summary['total_license_types']}")
        content.append("")
        
        # Vulnerability Summary
        if summary['vulnerability_by_severity']:
            content.append("### 🚨 Vulnerabilities by Severity")
            for severity, count in summary['vulnerability_by_severity'].items():
                content.append(f"- **{severity.title()}**: {count}")
            content.append("")
        
        # License Summary
        if summary['license_distribution']:
            content.append("### 📜 License Distribution")
            for license_type, count in summary['license_distribution'].items():
                content.append(f"- **{license_type}**: {count} packages")
            content.append("")
        
        # Detailed Results
        content.append("## 📋 Detailed Analysis")
        content.append("")
        
        for i, result in enumerate(self.results, 1):
            content.append(f"### {i}. {os.path.basename(result.file_path)}")
            content.append(f"**Package Manager**: {result.package_manager}")
            content.append(f"**File Path**: `{result.file_path}`")
            content.append("")
            
            # Dependencies Table
            if result.dependencies:
                content.append("#### Dependencies")
                content.append("| Package | Version | Type | License |")
                content.append("|---------|---------|------|---------|")
                
                for name, dep in result.dependencies.items():
                    dep_type = "dev" if dep.dev_dependency else "prod"
                    if dep.optional:
                        dep_type += " (optional)"
                    
                    content.append(f"| {name} | {dep.version_constraint or dep.version} | {dep_type} | {dep.license or 'Unknown'} |")
                content.append("")
            
            # Vulnerabilities
            if result.vulnerabilities:
                content.append("#### 🚨 Security Vulnerabilities")
                for vuln in result.vulnerabilities:
                    content.append(f"##### {vuln.title or 'Vulnerability'}")
                    if vuln.cve_id:
                        content.append(f"**CVE ID**: {vuln.cve_id}")
                    if vuln.advisory_id:
                        content.append(f"**Advisory ID**: {vuln.advisory_id}")
                    content.append(f"**Severity**: {vuln.severity.upper()}")
                    content.append(f"**Source**: {vuln.source}")
                    if vuln.description:
                        content.append(f"**Description**: {vuln.description}")
                    if vuln.affected_versions:
                        content.append(f"**Affected Versions**: {', '.join(vuln.affected_versions)}")
                    if vuln.fixed_versions:
                        content.append(f"**Fixed Versions**: {', '.join(vuln.fixed_versions)}")
                    content.append("")
            else:
                content.append("#### ✅ No vulnerabilities found")
                content.append("")
            
            content.append("---")
            content.append("")
        
        # Recommendations
        content.append("## 💡 Recommendations")
        recommendations = self._generate_recommendations()
        for rec in recommendations:
            content.append(f"- {rec}")
        content.append("")
        
        markdown_content = "\n".join(content)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        return output_path
    
    def generate_csv_report(self, output_path: str) -> str:
        """Generate a CSV report for dependencies"""
        import csv
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'File', 'Package Manager', 'Package Name', 'Version', 'Version Constraint',
                'License', 'Type', 'Optional', 'Description', 'Has Vulnerabilities'
            ])
            
            # Data
            for result in self.results:
                vuln_packages = {vuln.title for vuln in result.vulnerabilities}
                
                for name, dep in result.dependencies.items():
                    dep_type = "dev" if dep.dev_dependency else "production"
                    has_vulns = name in vuln_packages
                    
                    writer.writerow([
                        result.file_path,
                        result.package_manager,
                        name,
                        dep.version,
                        dep.version_constraint,
                        dep.license or '',
                        dep_type,
                        dep.optional,
                        dep.description or '',
                        has_vulns
                    ])
        
        return output_path
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics"""
        total_dependencies = sum(len(r.dependencies) for r in self.results)
        total_vulnerabilities = sum(len(r.vulnerabilities) for r in self.results)
        
        # Vulnerability by severity
        vuln_by_severity = {}
        for result in self.results:
            for vuln in result.vulnerabilities:
                severity = vuln.severity.lower()
                vuln_by_severity[severity] = vuln_by_severity.get(severity, 0) + 1
        
        # License distribution
        license_dist = {}
        for result in self.results:
            for license_type, packages in result.license_summary.items():
                license_dist[license_type] = license_dist.get(license_type, 0) + len(packages)
        
        # Package manager distribution
        pm_dist = {}
        for result in self.results:
            pm = result.package_manager
            pm_dist[pm] = pm_dist.get(pm, 0) + 1
        
        return {
            "total_files": len(self.results),
            "total_dependencies": total_dependencies,
            "total_vulnerabilities": total_vulnerabilities,
            "total_license_types": len(license_dist),
            "vulnerability_by_severity": vuln_by_severity,
            "license_distribution": license_dist,
            "package_manager_distribution": pm_dist
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on analysis results"""
        recommendations = []
        
        # Check for vulnerabilities
        total_vulns = sum(len(r.vulnerabilities) for r in self.results)
        if total_vulns > 0:
            recommendations.append(f"🚨 Found {total_vulns} security vulnerabilities. Update affected packages immediately.")
        
        # Check for missing licenses
        unlicensed_count = 0
        for result in self.results:
            for dep in result.dependencies.values():
                if not dep.license:
                    unlicensed_count += 1
        
        if unlicensed_count > 0:
            recommendations.append(f"📜 {unlicensed_count} dependencies have unknown licenses. Review for compliance.")
        
        # Check for dev dependencies in production
        prod_files = [r for r in self.results if 'requirements.txt' in r.file_path or 'package.json' in r.file_path]
        if prod_files:
            recommendations.append("🔍 Ensure dev dependencies are not included in production builds.")
        
        # General recommendations
        recommendations.extend([
            "🔄 Regularly update dependencies to latest stable versions.",
            "🛡️ Set up automated security scanning in your CI/CD pipeline.",
            "📊 Monitor dependency health with tools like Dependabot or Renovate.",
            "🏷️ Use semantic versioning and pin critical dependency versions.",
            "📋 Maintain a software bill of materials (SBOM) for compliance."
        ])
        
        return recommendations
    
    def _generate_html_template(self) -> str:
        """Generate HTML report template"""
        summary = self._generate_summary()
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dependency & Security Analysis Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }}
        .content {{ padding: 30px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #007bff; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #007bff; }}
        .stat-label {{ color: #6c757d; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f8f9fa; font-weight: 600; }}
        .vulnerability {{ background: #fff5f5; border-left: 4px solid #e53e3e; padding: 15px; margin: 10px 0; border-radius: 4px; }}
        .severity-critical {{ color: #e53e3e; font-weight: bold; }}
        .severity-high {{ color: #dd6b20; font-weight: bold; }}
        .severity-medium {{ color: #d69e2e; font-weight: bold; }}
        .severity-low {{ color: #38a169; font-weight: bold; }}
        .license-badge {{ background: #e2e8f0; color: #2d3748; padding: 4px 8px; border-radius: 4px; font-size: 0.85em; }}
        .dev-badge {{ background: #fed7d7; color: #c53030; padding: 4px 8px; border-radius: 4px; font-size: 0.85em; }}
        .prod-badge {{ background: #c6f6d5; color: #2f855a; padding: 4px 8px; border-radius: 4px; font-size: 0.85em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Dependency & Security Analysis Report</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}</p>
        </div>
        
        <div class="content">
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{summary['total_files']}</div>
                    <div class="stat-label">Files Analyzed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{summary['total_dependencies']}</div>
                    <div class="stat-label">Dependencies</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{summary['total_vulnerabilities']}</div>
                    <div class="stat-label">Vulnerabilities</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{summary['total_license_types']}</div>
                    <div class="stat-label">License Types</div>
                </div>
            </div>
            
            {self._generate_html_results()}
        </div>
    </div>
</body>
</html>
        """
        return html.strip()
    
    def _generate_html_results(self) -> str:
        """Generate HTML for detailed results"""
        html_parts = []
        
        for i, result in enumerate(self.results, 1):
            html_parts.append(f"""
            <h2>{i}. {os.path.basename(result.file_path)}</h2>
            <p><strong>Package Manager:</strong> {result.package_manager}</p>
            <p><strong>File Path:</strong> <code>{result.file_path}</code></p>
            
            <h3>Dependencies ({len(result.dependencies)})</h3>
            <table>
                <thead>
                    <tr>
                        <th>Package</th>
                        <th>Version</th>
                        <th>Type</th>
                        <th>License</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
            """)
            
            for name, dep in result.dependencies.items():
                dep_type = "dev" if dep.dev_dependency else "prod"
                badge_class = "dev-badge" if dep.dev_dependency else "prod-badge"
                
                html_parts.append(f"""
                    <tr>
                        <td><strong>{name}</strong></td>
                        <td>{dep.version_constraint or dep.version}</td>
                        <td><span class="{badge_class}">{dep_type}</span></td>
                        <td><span class="license-badge">{dep.license or 'Unknown'}</span></td>
                        <td>{dep.description or ''}</td>
                    </tr>
                """)
            
            html_parts.append("</tbody></table>")
            
            # Vulnerabilities
            if result.vulnerabilities:
                html_parts.append(f"<h3>🚨 Security Vulnerabilities ({len(result.vulnerabilities)})</h3>")
                for vuln in result.vulnerabilities:
                    severity_class = f"severity-{vuln.severity.lower()}"
                    html_parts.append(f"""
                    <div class="vulnerability">
                        <h4>{vuln.title or 'Vulnerability'}</h4>
                        <p><strong>Severity:</strong> <span class="{severity_class}">{vuln.severity.upper()}</span></p>
                        <p><strong>Source:</strong> {vuln.source}</p>
                        {f'<p><strong>CVE ID:</strong> {vuln.cve_id}</p>' if vuln.cve_id else ''}
                        {f'<p><strong>Advisory ID:</strong> {vuln.advisory_id}</p>' if vuln.advisory_id else ''}
                        {f'<p><strong>Description:</strong> {vuln.description}</p>' if vuln.description else ''}
                        {f'<p><strong>Affected Versions:</strong> {", ".join(vuln.affected_versions)}</p>' if vuln.affected_versions else ''}
                        {f'<p><strong>Fixed Versions:</strong> {", ".join(vuln.fixed_versions)}</p>' if vuln.fixed_versions else ''}
                    </div>
                    """)
            else:
                html_parts.append("<h3>✅ No vulnerabilities found</h3>")
            
            html_parts.append("<hr>")
        
        return "".join(html_parts)

#!/usr/bin/env python3
"""
Demo script for dependency analysis functionality

This script demonstrates the dependency and security analysis capabilities
of the wtf-codebot tool.
"""

import os
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from wtf_codebot.analyzers.dependency_analyzer import DependencyAnalyzer
from wtf_codebot.reporters.dependency_reporter import DependencyReporter


def main():
    """Run dependency analysis demo"""
    print("🔍 WTF-Codebot Dependency & Security Analysis Demo")
    print("=" * 60)
    
    # Initialize analyzer
    analyzer = DependencyAnalyzer()
    reporter = DependencyReporter()
    
    # Analyze current project
    print(f"📂 Analyzing project: {project_root}")
    
    try:
        # Analyze the current directory
        results = analyzer.analyze_directory(str(project_root))
        
        if not results:
            print("❌ No package manager files found!")
            return
        
        print(f"✅ Found {len(results)} package manager file(s)")
        
        # Add results to reporter
        for result in results:
            reporter.add_result(result)
            
            print(f"\n📦 {result.package_manager} - {os.path.basename(result.file_path)}")
            print(f"   Dependencies: {len(result.dependencies)}")
            print(f"   Vulnerabilities: {len(result.vulnerabilities)}")
            print(f"   License types: {len(result.license_summary)}")
            
            # Show some example dependencies
            if result.dependencies:
                print("   📋 Sample dependencies:")
                for i, (name, dep) in enumerate(list(result.dependencies.items())[:5]):
                    dep_type = "dev" if dep.dev_dependency else "prod"
                    print(f"      - {name} ({dep.version}) [{dep_type}]")
                
                if len(result.dependencies) > 5:
                    print(f"      ... and {len(result.dependencies) - 5} more")
            
            # Show vulnerabilities if any
            if result.vulnerabilities:
                print("   🚨 Vulnerabilities found:")
                for vuln in result.vulnerabilities[:3]:
                    print(f"      - {vuln.title or 'Vulnerability'} ({vuln.severity})")
                
                if len(result.vulnerabilities) > 3:
                    print(f"      ... and {len(result.vulnerabilities) - 3} more")
            else:
                print("   ✅ No vulnerabilities found")
        
        # Generate reports
        print("\n📊 Generating reports...")
        
        # Create reports directory
        reports_dir = project_root / "reports"
        reports_dir.mkdir(exist_ok=True)
        
        # Generate different report formats
        json_report = reporter.generate_json_report(str(reports_dir / "dependency_analysis.json"))
        markdown_report = reporter.generate_markdown_report(str(reports_dir / "dependency_analysis.md"))
        html_report = reporter.generate_html_report(str(reports_dir / "dependency_analysis.html"))
        csv_report = reporter.generate_csv_report(str(reports_dir / "dependencies.csv"))
        
        print(f"📄 JSON report: {json_report}")
        print(f"📄 Markdown report: {markdown_report}")
        print(f"📄 HTML report: {html_report}")
        print(f"📄 CSV report: {csv_report}")
        
        # Summary statistics
        total_deps = sum(len(r.dependencies) for r in results)
        total_vulns = sum(len(r.vulnerabilities) for r in results)
        
        print("\n📈 Summary Statistics:")
        print(f"   Total files analyzed: {len(results)}")
        print(f"   Total dependencies: {total_deps}")
        print(f"   Total vulnerabilities: {total_vulns}")
        
        if total_vulns > 0:
            print(f"\n⚠️  WARNING: {total_vulns} security vulnerabilities detected!")
            print("   Review the generated reports for details and remediation steps.")
        else:
            print("\n✅ No security vulnerabilities detected!")
        
        print("\n🎉 Analysis complete! Check the reports directory for detailed results.")
        
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

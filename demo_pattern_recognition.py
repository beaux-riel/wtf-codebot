#!/usr/bin/env python3
"""
Demo script for the pattern recognition system.

This script demonstrates how to use the pattern recognition system to analyze
code for design patterns, anti-patterns, and code quality issues.
"""

import asyncio
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from wtf_codebot.discovery.scanner import CodebaseScanner
from wtf_codebot.pattern_recognition.orchestrator import (
    PatternRecognitionOrchestrator,
    PatternRecognitionConfig,
    analyze_codebase_patterns
)
from wtf_codebot.core.logging import setup_logging


async def demo_pattern_recognition():
    """Demonstrate pattern recognition on the current codebase."""
    
    # Setup logging
    setup_logging()
    
    print("=== Pattern Recognition Demo ===")
    print("Analyzing the current codebase for patterns...")
    
    # Scan the current codebase
    print("\n1. Scanning codebase...")
    scanner = CodebaseScanner()
    codebase = scanner.scan_directory(project_root)
    
    print(f"Found {codebase.total_files} files ({codebase.total_size:,} bytes)")
    
    # Configure pattern recognition
    config = PatternRecognitionConfig(
        max_tokens_per_batch=50000,  # Smaller batches for demo
        concurrent_requests=2,       # Fewer concurrent requests
        enable_cost_tracking=True,
        daily_budget_limit=5.0,      # $5 daily limit
        output_directory=Path("demo_pattern_results"),
        output_formats=["json", "markdown", "csv"],
        save_batches=True,
        exclude_patterns=[
            "**/test/**", "**/tests/**", "**/*test*", 
            "**/node_modules/**", "**/.git/**", "**/venv/**", 
            "**/reports/**", "**/demo_pattern_results/**"
        ]
    )
    
    # Create orchestrator
    print("\n2. Initializing pattern recognition...")
    orchestrator = PatternRecognitionOrchestrator(config)
    
    try:
        # Analyze patterns
        print("\n3. Analyzing patterns...")
        results = await orchestrator.analyze_codebase(codebase)
        
        # Display results summary
        print("\n=== ANALYSIS RESULTS ===")
        summary = results.to_dict()["summary"]
        
        print(f"Total patterns found: {summary['total_patterns']}")
        print(f"  • Design patterns: {summary['design_patterns_count']}")
        print(f"  • Anti-patterns: {summary['anti_patterns_count']}")
        print(f"  • Quality issues: {summary['code_quality_issues_count']}")
        
        print(f"\nFiles analyzed: {results.total_files_analyzed}")
        print(f"Lines analyzed: {results.total_lines_analyzed:,}")
        print(f"Analysis duration: {results.analysis_duration:.2f}s")
        
        # Show severity breakdown
        print(f"\nIssues by severity:")
        print(f"  • Critical: {summary['critical_issues']}")
        print(f"  • High: {summary['high_issues']}")
        print(f"  • Medium: {summary['medium_issues']}")
        print(f"  • Low: {summary['low_issues']}")
        
        # Show some example patterns
        if results.design_patterns:
            print(f"\n=== DESIGN PATTERNS FOUND ===")
            for i, pattern in enumerate(results.design_patterns[:3]):  # Show first 3
                print(f"{i+1}. {pattern.pattern_type.value.title()}")
                print(f"   File: {pattern.file_path}")
                print(f"   Lines: {pattern.line_start}-{pattern.line_end}")
                print(f"   Confidence: {pattern.confidence:.2f}")
                print(f"   Description: {pattern.description}")
                if len(results.design_patterns) > 3:
                    print(f"   ... and {len(results.design_patterns) - 3} more")
                    break
        
        if results.anti_patterns:
            print(f"\n=== ANTI-PATTERNS FOUND ===")
            for i, pattern in enumerate(results.anti_patterns[:3]):  # Show first 3
                print(f"{i+1}. {pattern.pattern_type.value.title()} ({pattern.severity.upper()})")
                print(f"   File: {pattern.file_path}")
                print(f"   Lines: {pattern.line_start}-{pattern.line_end}")
                print(f"   Confidence: {pattern.confidence:.2f}")
                print(f"   Description: {pattern.description}")
                if len(results.anti_patterns) > 3:
                    print(f"   ... and {len(results.anti_patterns) - 3} more")
                    break
        
        # Show cost information
        cost_summary = orchestrator.get_cost_summary()
        if cost_summary:
            usage = cost_summary["usage_summary"]
            budget = cost_summary["budget_status"]
            
            print(f"\n=== COST ANALYSIS ===")
            print(f"Total cost: ${usage['total_cost']:.4f}")
            print(f"Tokens processed: {usage['total_tokens']:,}")
            print(f"Successful requests: {usage['successful_requests']}")
            
            if budget["budget_enabled"]:
                daily = budget["daily"]
                print(f"Daily budget: ${daily['used']:.2f} / ${daily['limit']:.2f} ({daily['percentage']:.1f}%)")
        
        print(f"\n=== OUTPUT FILES ===")
        output_dir = config.output_directory
        print(f"Results saved to: {output_dir}")
        print("Files generated:")
        for format_type in config.output_formats:
            if format_type == "json":
                file_path = output_dir / "pattern_analysis.json"
            elif format_type == "csv":
                file_path = output_dir / "pattern_analysis.csv"
            elif format_type == "markdown":
                file_path = output_dir / "pattern_analysis.md"
            
            if file_path.exists():
                print(f"  • {file_path} ({file_path.stat().st_size:,} bytes)")
        
        if (output_dir / "cost_summary.json").exists():
            print(f"  • {output_dir / 'cost_summary.json'}")
        
        if (output_dir / "code_batches.json").exists():
            print(f"  • {output_dir / 'code_batches.json'}")
        
        print(f"\nPattern recognition demo completed successfully!")
        return True
        
    except Exception as e:
        print(f"\nError during pattern analysis: {e}")
        import traceback
        traceback.print_exc()
        return False


async def demo_simple_analysis():
    """Demonstrate simple pattern analysis using the convenience function."""
    
    print("\n=== Simple Pattern Analysis Demo ===")
    
    # Scan codebase
    scanner = CodebaseScanner()
    codebase = scanner.scan_directory(project_root)
    
    # Use the convenience function
    results = await analyze_codebase_patterns(
        codebase=codebase,
        output_dir=Path("simple_pattern_results"),
        max_tokens_per_batch=30000,
        concurrent_requests=2,
        enable_cost_tracking=True,
        budget_limit=2.0  # $2 limit for simple demo
    )
    
    print(f"Simple analysis found {len(results.get_all_patterns())} patterns")
    print(f"Results saved to: simple_pattern_results/")


async def main():
    """Main demo function."""
    
    print("WTF CodeBot Pattern Recognition Demo")
    print("====================================")
    
    # Check if we have the required API key
    try:
        from wtf_codebot.core.config import get_config
        config = get_config()
        if not config.anthropic_api_key:
            print("ERROR: ANTHROPIC_API_KEY not set!")
            print("Please set your Anthropic API key in environment variables or config file.")
            return False
    except Exception as e:
        print(f"Configuration error: {e}")
        return False
    
    success = True
    
    # Run main demo
    print("\nRunning full pattern recognition demo...")
    if not await demo_pattern_recognition():
        success = False
    
    # Run simple demo
    print("\nRunning simple pattern analysis demo...")
    try:
        await demo_simple_analysis()
    except Exception as e:
        print(f"Simple demo failed: {e}")
        success = False
    
    if success:
        print("\n✅ All demos completed successfully!")
        print("\nNext steps:")
        print("  1. Review the generated reports in the output directories")
        print("  2. Customize the configuration for your specific needs")
        print("  3. Integrate pattern recognition into your development workflow")
        print("  4. Set up appropriate cost budgets and monitoring")
    else:
        print("\n❌ Some demos failed. Check the error messages above.")
    
    return success


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)

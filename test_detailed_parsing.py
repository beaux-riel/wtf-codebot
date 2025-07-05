#!/usr/bin/env python3
"""
Detailed test script to demonstrate parsing capabilities.
"""

import logging
from pathlib import Path
from wtf_codebot.discovery import CodebaseScanner
from wtf_codebot.discovery.models import FileType


def main():
    """Detailed parsing test."""
    logging.basicConfig(level=logging.WARNING)  # Reduce noise
    
    print("🔬 WTF Codebot - Detailed Parsing Test")
    print("=" * 50)
    
    # Initialize scanner
    scanner = CodebaseScanner(
        include_content=True,
        parse_ast=True,
        max_file_size=1 * 1024 * 1024  # 1MB limit
    )
    
    # Scan just the wtf_codebot directory
    scan_dir = Path("wtf_codebot")
    print(f"📁 Scanning directory: {scan_dir.absolute()}")
    
    codebase_graph = scanner.scan_directory(scan_dir)
    
    print(f"\n📊 Detailed Results:")
    print(f"   • Total files: {codebase_graph.total_files}")
    print(f"   • Dependencies found: {len(codebase_graph.dependency_graph.edges)}")
    
    # Show detailed parsing for each file type
    file_types = [FileType.PYTHON, FileType.MARKDOWN, FileType.JSON, FileType.YAML]
    
    for file_type in file_types:
        files = codebase_graph.get_files_by_type(file_type)
        if not files:
            continue
            
        print(f"\n📁 {file_type.value.upper()} Files ({len(files)} total):")
        
        # Show details for first file of this type
        for file_node in files[:2]:  # Show first 2 files of each type
            print(f"\n   📄 {file_node.path}")
            print(f"      Size: {file_node.size} bytes")
            
            if file_node.functions:
                print(f"      Functions: {', '.join(list(file_node.functions)[:5])}")
                if len(file_node.functions) > 5:
                    print(f"                 ... and {len(file_node.functions) - 5} more")
            
            if file_node.classes:
                print(f"      Classes: {', '.join(list(file_node.classes)[:5])}")
                if len(file_node.classes) > 5:
                    print(f"               ... and {len(file_node.classes) - 5} more")
            
            if file_node.variables:
                print(f"      Variables: {', '.join(list(file_node.variables)[:5])}")
                if len(file_node.variables) > 5:
                    print(f"                 ... and {len(file_node.variables) - 5} more")
            
            if file_node.dependencies:
                print(f"      Dependencies:")
                for dep in file_node.dependencies[:3]:  # Show first 3 dependencies
                    print(f"        • {dep.target} ({dep.dependency_type})")
                if len(file_node.dependencies) > 3:
                    print(f"        ... and {len(file_node.dependencies) - 3} more")
            
            if file_node.ast_root:
                print(f"      AST: {file_node.ast_root.node_type} with {len(file_node.ast_root.children)} children")
            
            if file_node.parse_errors:
                print(f"      Parse errors: {len(file_node.parse_errors)}")
    
    # Show dependency graph insights
    print(f"\n🔗 Dependency Graph Analysis:")
    
    # External vs internal dependencies
    external_deps = [dep for dep in codebase_graph.dependency_graph.edges if dep.is_external]
    internal_deps = [dep for dep in codebase_graph.dependency_graph.edges if not dep.is_external]
    
    print(f"   • External dependencies: {len(external_deps)}")
    print(f"   • Internal dependencies: {len(internal_deps)}")
    
    # Most common external dependencies
    if external_deps:
        from collections import Counter
        external_targets = [dep.target for dep in external_deps]
        common_external = Counter(external_targets).most_common(5)
        
        print(f"   • Most common external dependencies:")
        for target, count in common_external:
            print(f"     - {target}: {count} imports")
    
    # Files with most dependencies
    file_dep_counts = {}
    for dep in codebase_graph.dependency_graph.edges:
        if dep.source not in file_dep_counts:
            file_dep_counts[dep.source] = 0
        file_dep_counts[dep.source] += 1
    
    if file_dep_counts:
        sorted_files = sorted(file_dep_counts.items(), key=lambda x: x[1], reverse=True)
        print(f"   • Files with most dependencies:")
        for file_path, count in sorted_files[:3]:
            print(f"     - {file_path}: {count} dependencies")
    
    print(f"\n✅ Detailed parsing test completed!")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Demo script to test the codebase discovery and parsing layer.
"""

import logging
from pathlib import Path
from wtf_codebot.discovery import CodebaseScanner


def main():
    """Main demo function."""
    # Setup basic logging
    logging.basicConfig(level=logging.INFO)
    
    print("🔍 WTF Codebot - Codebase Discovery Demo")
    print("=" * 50)
    
    # Initialize scanner
    scanner = CodebaseScanner(
        include_content=True,
        parse_ast=True,
        max_file_size=5 * 1024 * 1024  # 5MB limit
    )
    
    # Scan current directory
    current_dir = Path(".")
    print(f"📁 Scanning directory: {current_dir.absolute()}")
    
    try:
        # Perform the scan
        codebase_graph = scanner.scan_directory(current_dir)
        
        # Display results
        print(f"\n📊 Scan Results:")
        print(f"   • Total files: {codebase_graph.total_files}")
        print(f"   • Total size: {codebase_graph.total_size:,} bytes")
        print(f"   • Dependencies found: {len(codebase_graph.dependency_graph.edges)}")
        print(f"   • Scan errors: {len(codebase_graph.scan_errors)}")
        
        # File type breakdown
        print(f"\n📁 File Types:")
        stats = codebase_graph.get_statistics()
        for file_type, count in stats['file_types'].items():
            print(f"   • {file_type}: {count} files")
        
        # Show some example files
        print(f"\n📄 Example Files:")
        for i, (file_path, file_node) in enumerate(codebase_graph.files.items()):
            if i >= 5:  # Limit to first 5 files
                break
            
            print(f"   • {file_path}")
            print(f"     Type: {file_node.file_type.value}")
            print(f"     Size: {file_node.size} bytes")
            print(f"     Functions: {len(file_node.functions)}")
            print(f"     Classes: {len(file_node.classes)}")
            print(f"     Dependencies: {len(file_node.dependencies)}")
            if file_node.parse_errors:
                print(f"     Parse errors: {len(file_node.parse_errors)}")
        
        # Show dependencies
        print(f"\n🔗 Dependencies:")
        dependency_count = 0
        for dep in codebase_graph.dependency_graph.edges:
            if dependency_count >= 10:  # Limit to first 10 dependencies
                break
            
            print(f"   • {dep.source} -> {dep.target}")
            print(f"     Type: {dep.dependency_type}")
            print(f"     External: {dep.is_external}")
            if dep.line_number:
                print(f"     Line: {dep.line_number}")
            dependency_count += 1
        
        if len(codebase_graph.dependency_graph.edges) > 10:
            remaining = len(codebase_graph.dependency_graph.edges) - 10
            print(f"   ... and {remaining} more dependencies")
        
        # Show scan errors if any
        if codebase_graph.scan_errors:
            print(f"\n⚠️  Scan Errors:")
            for error in codebase_graph.scan_errors[:5]:  # Show first 5 errors
                print(f"   • {error}")
            
            if len(codebase_graph.scan_errors) > 5:
                remaining = len(codebase_graph.scan_errors) - 5
                print(f"   ... and {remaining} more errors")
        
        # Show parser capabilities
        print(f"\n🔧 Parser Capabilities:")
        supported_types = scanner.parser_factory.get_supported_file_types()
        for file_type in supported_types:
            print(f"   • {file_type.value}")
        
        print(f"\n✅ Discovery completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Error during scanning: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

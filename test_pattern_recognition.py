#!/usr/bin/env python3
"""
Basic test for pattern recognition functionality.
"""

import asyncio
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from wtf_codebot.pattern_recognition.batcher import CodeBatcher, BatchConfig, CodeSnippet
from wtf_codebot.pattern_recognition.cost_tracker import CostTracker
from wtf_codebot.pattern_recognition.patterns import PatternType, PatternMatch
from wtf_codebot.discovery.models import FileNode, FileType
# Simple logging setup for testing
import logging
def setup_logging():
    logging.basicConfig(level=logging.INFO)


def test_token_counting():
    """Test token counting functionality."""
    print("Testing token counting...")
    
    # Create a simple code snippet
    snippet = CodeSnippet(
        content="def hello_world():\n    print('Hello, World!')\n    return True",
        file_path=Path("test.py"),
        start_line=1,
        end_line=3,
        snippet_type="function",
        language="python"
    )
    
    token_count = snippet.get_token_count()
    print(f"Token count for simple function: {token_count}")
    assert token_count > 0, "Token count should be positive"
    
    print("✓ Token counting test passed")


def test_cost_calculation():
    """Test cost calculation."""
    print("Testing cost calculation...")
    
    tracker = CostTracker()
    
    # Test cost calculation for Claude Sonnet
    cost = tracker.calculate_cost("claude-sonnet-4-0", 1000, 500)
    print(f"Cost for 1000 input + 500 output tokens: ${cost:.4f}")
    assert cost > 0, "Cost should be positive"
    
    # Test unknown model fallback
    cost_unknown = tracker.calculate_cost("unknown-model", 1000, 500)
    print(f"Cost for unknown model (fallback): ${cost_unknown:.4f}")
    assert cost_unknown == cost, "Unknown model should fallback to Sonnet pricing"
    
    print("✓ Cost calculation test passed")


def test_batching():
    """Test code batching functionality."""
    print("Testing code batching...")
    
    # Create some test file nodes
    file_nodes = []
    
    # Small Python file
    python_content = """
def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)

class Calculator:
    def add(self, a, b):
        return a + b
    
    def multiply(self, a, b):
        return a * b
"""
    
    file_node = FileNode(
        path=Path("calculator.py"),
        file_type=FileType.PYTHON,
        size=len(python_content),
        last_modified=0.0,
        content=python_content
    )
    file_nodes.append(file_node)
    
    # JavaScript file
    js_content = """
function fibonacci(n) {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

class EventEmitter {
    constructor() {
        this.events = {};
    }
    
    on(event, callback) {
        if (!this.events[event]) {
            this.events[event] = [];
        }
        this.events[event].push(callback);
    }
    
    emit(event, ...args) {
        if (this.events[event]) {
            this.events[event].forEach(callback => callback(...args));
        }
    }
}
"""
    
    js_file = FileNode(
        path=Path("events.js"),
        file_type=FileType.JAVASCRIPT,
        size=len(js_content),
        last_modified=0.0,
        content=js_content
    )
    file_nodes.append(js_file)
    
    # Create batcher
    config = BatchConfig(
        max_tokens_per_batch=50000,
        min_batch_size=10,
        chunk_large_files=True
    )
    batcher = CodeBatcher(config)
    
    # Create batches
    batches = batcher.create_batches_from_files(file_nodes)
    
    print(f"Created {len(batches)} batches from {len(file_nodes)} files")
    
    assert len(batches) > 0, "Should create at least one batch"
    
    for i, batch in enumerate(batches):
        print(f"Batch {i+1}: {len(batch.snippets)} snippets, {batch.total_tokens} tokens")
        assert batch.total_tokens > 0, "Batch should have positive token count"
        assert len(batch.snippets) > 0, "Batch should have snippets"
    
    print("✓ Batching test passed")


def test_pattern_matching():
    """Test pattern matching data structures."""
    print("Testing pattern matching...")
    
    # Create a test pattern
    pattern = PatternMatch(
        pattern_type=PatternType.SINGLETON,
        confidence=0.9,
        file_path=Path("singleton.py"),
        line_start=10,
        line_end=25,
        description="Singleton pattern implementation",
        evidence=["Private constructor", "Static instance method"],
        severity="info",
        impact="low",
        effort="low"
    )
    
    # Test serialization
    pattern_dict = pattern.to_dict()
    
    assert pattern_dict["pattern_type"] == "singleton"
    assert pattern_dict["confidence"] == 0.9
    assert pattern_dict["file_path"] == "singleton.py"
    assert len(pattern_dict["evidence"]) == 2
    
    print("✓ Pattern matching test passed")


def test_usage_tracking():
    """Test usage tracking."""
    print("Testing usage tracking...")
    
    tracker = CostTracker(auto_save=False)  # Don't save to disk in test
    
    # Record some usage
    usage = tracker.record_usage(
        model="claude-sonnet-4-0",
        input_tokens=1000,
        output_tokens=500,
        request_type="test_request",
        duration=2.5,
        success=True
    )
    
    assert usage.model == "claude-sonnet-4-0"
    assert usage.input_tokens == 1000
    assert usage.output_tokens == 500
    assert usage.success is True
    assert usage.cost > 0
    
    # Get summary
    summary = tracker.get_usage_summary(days=1)
    
    assert summary["total_requests"] == 1
    assert summary["successful_requests"] == 1
    assert summary["failed_requests"] == 0
    assert summary["total_cost"] > 0
    
    print(f"Tracked usage: ${summary['total_cost']:.4f} for {summary['total_tokens']} tokens")
    print("✓ Usage tracking test passed")


async def main():
    """Run all tests."""
    print("Running Pattern Recognition Tests")
    print("=================================")
    
    # Setup minimal logging
    setup_logging()
    
    try:
        test_token_counting()
        test_cost_calculation()
        test_batching()
        test_pattern_matching()
        test_usage_tracking()
        
        print("\n✅ All tests passed!")
        print("\nPattern recognition system is ready to use.")
        print("Next step: Run 'python demo_pattern_recognition.py' for a full demo")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)

#!/usr/bin/env python3
"""
Quick test script to verify rate limiting is working correctly.
"""

import asyncio
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from wtf_codebot.pattern_recognition.rate_limiter import TokenRateLimiter, BatchSizeCalculator
from wtf_codebot.pattern_recognition.claude_client import ClaudePatternAnalyzer
from wtf_codebot.pattern_recognition.batcher import CodeSnippet, CodeBatch

async def test_rate_limiter():
    """Test the rate limiter functionality."""
    print("=== Testing Rate Limiter ===")
    
    # Create rate limiter with 40k tokens/min
    rate_limiter = TokenRateLimiter(tokens_per_minute=40000)
    
    # Test immediate acquisition
    print("\n1. Testing immediate token acquisition...")
    wait_time = await rate_limiter.acquire(5000)
    print(f"   Acquired 5,000 tokens, wait time: {wait_time:.1f}s")
    
    status = rate_limiter.get_status()
    print(f"   Current usage: {status['current_usage']:,}/{status['limit']:,} tokens")
    
    # Test multiple acquisitions
    print("\n2. Testing multiple acquisitions...")
    for i in range(5):
        wait_time = await rate_limiter.acquire(8000)
        print(f"   Batch {i+1}: Acquired 8,000 tokens, wait time: {wait_time:.1f}s")
        status = rate_limiter.get_status()
        print(f"   Current usage: {status['current_usage']:,}/{status['limit']:,} tokens")
    
    # Test rate limit enforcement
    print("\n3. Testing rate limit enforcement...")
    print("   Attempting to acquire 10,000 more tokens (should trigger wait)...")
    wait_time = await rate_limiter.acquire(10000)
    print(f"   Wait time: {wait_time:.1f}s")
    
    print("\n✅ Rate limiter test completed!")

async def test_batch_calculator():
    """Test the batch size calculator."""
    print("\n=== Testing Batch Size Calculator ===")
    
    calculator = BatchSizeCalculator(
        tokens_per_minute=40000,
        max_tokens_per_batch=10000,
        safety_margin=0.8
    )
    
    # Test optimal batch size calculation
    print("\n1. Testing optimal batch size calculation...")
    test_cases = [
        (100000, 1),  # Large total, single request
        (100000, 3),  # Large total, concurrent requests
        (50000, 5),   # Medium total, high concurrency
    ]
    
    for total_tokens, concurrent in test_cases:
        optimal_size = calculator.calculate_optimal_batch_size(total_tokens, concurrent)
        print(f"   Total: {total_tokens:,}, Concurrent: {concurrent} → Optimal batch: {optimal_size:,} tokens")
    
    # Test processing time estimation
    print("\n2. Testing processing time estimation...")
    for total_tokens, batch_size, concurrent in [(100000, 8000, 3), (50000, 5000, 2)]:
        est_time = calculator.estimate_processing_time(total_tokens, batch_size, concurrent)
        print(f"   {total_tokens:,} tokens in {batch_size:,}-token batches with {concurrent} concurrent requests")
        print(f"   → Estimated time: {est_time:.1f}s ({est_time/60:.1f} minutes)")
    
    print("\n✅ Batch calculator test completed!")

async def test_claude_client_rate_limiting():
    """Test the Claude client with rate limiting."""
    print("\n=== Testing Claude Client Rate Limiting ===")
    
    # Check if API key is available
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        print("⚠️  Skipping Claude client test - no API key found")
        return
    
    # Create a small test batch
    snippet = CodeSnippet(
        content="def hello():\n    print('Hello, world!')",
        file_path=Path("test.py"),
        start_line=1,
        end_line=2,
        snippet_type="function",
        language="python"
    )
    
    batch = CodeBatch(
        id="test_batch",
        snippets=[snippet],
        total_tokens=100  # Small batch
    )
    
    # Create analyzer with rate limiting
    analyzer = ClaudePatternAnalyzer(
        cost_tracker=None,
        tokens_per_minute=40000
    )
    
    print("\n1. Analyzing test batch...")
    try:
        result = await analyzer.analyze_batch(batch)
        print(f"   Analysis completed in {result.analysis_time:.2f}s")
        print(f"   Success: {result.success}")
        if not result.success:
            print(f"   Error: {result.error_message}")
    except Exception as e:
        print(f"   Error: {e}")
    
    print("\n✅ Claude client rate limiting test completed!")

async def main():
    """Run all tests."""
    print("WTF CodeBot Rate Limiting Tests")
    print("===============================")
    
    await test_rate_limiter()
    await test_batch_calculator()
    await test_claude_client_rate_limiting()
    
    print("\n🎉 All tests completed!")

if __name__ == "__main__":
    asyncio.run(main())
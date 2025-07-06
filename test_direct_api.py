#!/usr/bin/env python3
"""Direct test of pattern recognition with explicit configuration"""

import asyncio
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables FIRST
load_dotenv()

# Now import the modules
from wtf_codebot.pattern_recognition.claude_client import ClaudePatternAnalyzer
from wtf_codebot.pattern_recognition.batcher import CodeBatch, CodeSnippet

async def test_direct():
    """Test pattern recognition directly"""
    
    # Print environment
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    model = os.environ.get('ANTHROPIC_MODEL', 'claude-sonnet-4-0')
    
    print(f"API Key: {api_key[:10] if api_key else 'NOT FOUND'}...")
    print(f"Model: {model}")
    
    # Create a simple code snippet to analyze
    test_code = '''
class UserManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.users = []
            self.initialized = True
    
    def add_user(self, user):
        self.users.append(user)
    '''
    
    # Create a batch
    snippet = CodeSnippet(
        content=test_code,
        file_path=Path("test.py"),
        start_line=1,
        end_line=15,
        snippet_type="class",
        language="python"
    )
    
    batch = CodeBatch(
        id="test_batch",
        snippets=[snippet],
        total_tokens=100  # Approximate
    )
    
    # Initialize analyzer with explicit config
    from wtf_codebot.core.config import Config
    config = Config(
        anthropic_api_key=api_key,
        anthropic_model=model
    )
    
    # Monkey patch the config
    import wtf_codebot.pattern_recognition.claude_client
    old_get_config = wtf_codebot.pattern_recognition.claude_client.get_config
    wtf_codebot.pattern_recognition.claude_client.get_config = lambda: config
    
    try:
        analyzer = ClaudePatternAnalyzer()
        
        print("\nAnalyzing code for patterns...")
        result = await analyzer.analyze_batch(batch)
        
        if result.success:
            print(f"\n✅ Analysis successful!")
            print(f"Found {len(result.patterns)} patterns")
            for pattern in result.patterns:
                print(f"  - {pattern.pattern_type.value}: {pattern.description}")
        else:
            print(f"\n❌ Analysis failed: {result.error_message}")
    
    finally:
        # Restore original get_config
        wtf_codebot.pattern_recognition.claude_client.get_config = old_get_config

if __name__ == "__main__":
    asyncio.run(test_direct())
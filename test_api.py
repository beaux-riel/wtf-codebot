#!/usr/bin/env python3
"""Test script to verify Anthropic API connection"""

import os
import sys
from anthropic import Anthropic
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_api():
    """Test the Anthropic API connection"""
    
    # Get API key
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        print("❌ ERROR: ANTHROPIC_API_KEY not found in environment")
        return False
    
    print(f"✓ API Key found: {api_key[:10]}...{api_key[-4:]}")
    
    # Get model name
    model = os.environ.get('ANTHROPIC_MODEL', 'claude-3-7-sonnet-20250219')
    print(f"✓ Model: {model}")
    
    # Test API connection
    try:
        client = Anthropic(api_key=api_key)
        
        print("\n🔍 Testing API connection...")
        response = client.messages.create(
            model=model,
            max_tokens=100,
            messages=[
                {
                    "role": "user",
                    "content": "Say 'API connection successful!' and nothing else."
                }
            ]
        )
        
        print(f"\n✅ Success! Response: {response.content[0].text}")
        return True
        
    except Exception as e:
        print(f"\n❌ API Error: {type(e).__name__}: {e}")
        
        # Provide helpful error messages
        if "model_not_found" in str(e):
            print("\n💡 Hint: The model name might be incorrect. Valid models include:")
            print("   - claude-3-7-sonnet-20250219")
            print("   - claude-3-opus-20240229")
            print("   - claude-3-haiku-20240307")
            print("   - claude-3-haiku-20240307")
        elif "invalid_api_key" in str(e):
            print("\n💡 Hint: Your API key appears to be invalid. Please check:")
            print("   1. The API key is correct")
            print("   2. The API key has not been revoked")
            print("   3. You have the necessary permissions")
        elif "rate_limit" in str(e):
            print("\n💡 Hint: You've hit the rate limit. Please wait a moment and try again.")
        
        return False

if __name__ == "__main__":
    print("🧪 Testing Anthropic API Connection")
    print("=" * 40)
    
    if test_api():
        print("\n✨ API connection is working! You can use the pattern recognition features.")
    else:
        print("\n⚠️  Please fix the API connection issues before using pattern recognition.")
        sys.exit(1)
"""
Rate limiting utilities for API calls
"""

import time
import threading
from typing import Optional
import logging


class RateLimiter:
    """A simple rate limiter to prevent overwhelming external APIs"""
    
    def __init__(self, calls_per_second: float = 2.0, burst_size: Optional[int] = None):
        """
        Initialize rate limiter.
        
        Args:
            calls_per_second: Maximum number of calls per second
            burst_size: Maximum burst size (defaults to calls_per_second)
        """
        self.calls_per_second = calls_per_second
        self.interval = 1.0 / calls_per_second
        self.burst_size = burst_size or int(calls_per_second)
        
        # Token bucket algorithm
        self.tokens = float(self.burst_size)
        self.max_tokens = float(self.burst_size)
        self.last_update = time.time()
        self.lock = threading.Lock()
        
        self.logger = logging.getLogger(__name__)
    
    def acquire(self, tokens: int = 1) -> float:
        """
        Acquire tokens, blocking if necessary.
        
        Args:
            tokens: Number of tokens to acquire
            
        Returns:
            Time waited in seconds
        """
        wait_time = 0.0
        
        with self.lock:
            now = time.time()
            
            # Refill tokens based on time elapsed
            elapsed = now - self.last_update
            self.tokens = min(self.max_tokens, self.tokens + elapsed * self.calls_per_second)
            self.last_update = now
            
            # Check if we have enough tokens
            if self.tokens < tokens:
                # Calculate wait time
                tokens_needed = tokens - self.tokens
                wait_time = tokens_needed / self.calls_per_second
                
                # Log if wait time is significant
                if wait_time > 0.1:
                    self.logger.debug(f"Rate limiting: waiting {wait_time:.2f}s")
                
                # Wait
                time.sleep(wait_time)
                
                # Update tokens after waiting
                now = time.time()
                elapsed = now - self.last_update
                self.tokens = min(self.max_tokens, self.tokens + elapsed * self.calls_per_second)
                self.last_update = now
            
            # Consume tokens
            self.tokens -= tokens
            
        return wait_time
    
    def try_acquire(self, tokens: int = 1) -> bool:
        """
        Try to acquire tokens without blocking.
        
        Args:
            tokens: Number of tokens to acquire
            
        Returns:
            True if tokens were acquired, False otherwise
        """
        with self.lock:
            now = time.time()
            
            # Refill tokens based on time elapsed
            elapsed = now - self.last_update
            self.tokens = min(self.max_tokens, self.tokens + elapsed * self.calls_per_second)
            self.last_update = now
            
            # Check if we have enough tokens
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False
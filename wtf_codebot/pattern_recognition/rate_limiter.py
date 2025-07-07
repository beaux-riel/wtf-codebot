"""
Token-based rate limiter for API calls.
"""

import time
import asyncio
from typing import Optional, Dict, List
from dataclasses import dataclass, field
from collections import deque

try:
    from ..core.logging import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


@dataclass
class TokenUsage:
    """Record of token usage at a specific time."""
    timestamp: float
    tokens: int


class TokenRateLimiter:
    """Token-based rate limiter for API calls.
    
    Tracks token usage over a sliding window to ensure compliance
    with rate limits.
    """
    
    def __init__(self, 
                 tokens_per_minute: int = 40000,
                 window_size_seconds: int = 60):
        """Initialize the rate limiter.
        
        Args:
            tokens_per_minute: Maximum tokens allowed per minute
            window_size_seconds: Size of the sliding window in seconds
        """
        self.tokens_per_minute = tokens_per_minute
        self.window_size_seconds = window_size_seconds
        self.usage_history: deque[TokenUsage] = deque()
        self._lock = asyncio.Lock()
        
        logger.info(f"Initialized token rate limiter: {tokens_per_minute} tokens/min")
    
    async def acquire(self, tokens: int) -> float:
        """Acquire tokens, waiting if necessary.
        
        Args:
            tokens: Number of tokens to acquire
            
        Returns:
            Actual delay waited in seconds
        """
        async with self._lock:
            # Clean up old entries
            self._cleanup_old_entries()
            
            # Calculate current usage
            current_usage = self._get_current_usage()
            
            # Check if we can proceed immediately
            if current_usage + tokens <= self.tokens_per_minute:
                self.usage_history.append(TokenUsage(time.time(), tokens))
                logger.debug(f"Acquired {tokens} tokens immediately. "
                           f"Current usage: {current_usage + tokens}/{self.tokens_per_minute}")
                return 0.0
            
            # Calculate how long to wait
            wait_time = self._calculate_wait_time(tokens)
            
            if wait_time > 0:
                logger.info(f"Rate limit reached. Waiting {wait_time:.1f}s to acquire {tokens} tokens. "
                          f"Current usage: {current_usage}/{self.tokens_per_minute}")
                await asyncio.sleep(wait_time)
                
                # Clean up again after waiting
                self._cleanup_old_entries()
            
            # Record the usage
            self.usage_history.append(TokenUsage(time.time(), tokens))
            
            return wait_time
    
    def _cleanup_old_entries(self) -> None:
        """Remove entries older than the window size."""
        current_time = time.time()
        cutoff_time = current_time - self.window_size_seconds
        
        while self.usage_history and self.usage_history[0].timestamp < cutoff_time:
            self.usage_history.popleft()
    
    def _get_current_usage(self) -> int:
        """Get current token usage within the window."""
        return sum(usage.tokens for usage in self.usage_history)
    
    def _calculate_wait_time(self, tokens: int) -> float:
        """Calculate how long to wait before acquiring tokens."""
        if not self.usage_history:
            return 0.0
        
        # Find the oldest entry that would need to expire
        # for us to have enough capacity
        current_usage = self._get_current_usage()
        needed_capacity = tokens - (self.tokens_per_minute - current_usage)
        
        if needed_capacity <= 0:
            return 0.0
        
        # Find when enough tokens will expire
        accumulated = 0
        for usage in self.usage_history:
            accumulated += usage.tokens
            if accumulated >= needed_capacity:
                # Wait until this entry expires
                time_until_expiry = (usage.timestamp + self.window_size_seconds) - time.time()
                return max(0, time_until_expiry + 0.1)  # Add small buffer
        
        # If we get here, we need to wait for everything to expire
        oldest_timestamp = self.usage_history[0].timestamp
        time_until_expiry = (oldest_timestamp + self.window_size_seconds) - time.time()
        return max(0, time_until_expiry + 0.1)
    
    def get_status(self) -> Dict[str, any]:
        """Get current rate limiter status."""
        self._cleanup_old_entries()
        current_usage = self._get_current_usage()
        
        return {
            "current_usage": current_usage,
            "limit": self.tokens_per_minute,
            "available": max(0, self.tokens_per_minute - current_usage),
            "window_seconds": self.window_size_seconds,
            "entries_in_window": len(self.usage_history)
        }


class BatchSizeCalculator:
    """Calculate optimal batch sizes based on rate limits."""
    
    def __init__(self,
                 tokens_per_minute: int = 40000,
                 max_tokens_per_batch: int = 10000,
                 safety_margin: float = 0.8):
        """Initialize the batch size calculator.
        
        Args:
            tokens_per_minute: Rate limit in tokens per minute
            max_tokens_per_batch: Maximum tokens allowed per batch
            safety_margin: Safety margin (0.0-1.0) to avoid hitting limits
        """
        self.tokens_per_minute = tokens_per_minute
        self.max_tokens_per_batch = max_tokens_per_batch
        self.safety_margin = safety_margin
        
        # Calculate effective limits with safety margin
        self.effective_tokens_per_minute = int(tokens_per_minute * safety_margin)
        self.effective_max_tokens_per_batch = int(max_tokens_per_batch * safety_margin)
        
        logger.info(f"Batch size calculator initialized: "
                   f"effective limit {self.effective_tokens_per_minute} tokens/min, "
                   f"max batch {self.effective_max_tokens_per_batch} tokens")
    
    def calculate_optimal_batch_size(self, 
                                   total_tokens: int,
                                   concurrent_requests: int = 3) -> int:
        """Calculate optimal batch size for given parameters.
        
        Args:
            total_tokens: Total tokens to process
            concurrent_requests: Number of concurrent requests
            
        Returns:
            Optimal tokens per batch
        """
        # Calculate tokens per request per minute
        tokens_per_request_per_minute = self.effective_tokens_per_minute / concurrent_requests
        
        # Don't exceed max batch size
        optimal_size = min(
            self.effective_max_tokens_per_batch,
            int(tokens_per_request_per_minute)
        )
        
        # Ensure we have at least a reasonable minimum
        optimal_size = max(optimal_size, 1000)
        
        logger.debug(f"Calculated optimal batch size: {optimal_size} tokens "
                    f"(total: {total_tokens}, concurrent: {concurrent_requests})")
        
        return optimal_size
    
    def estimate_processing_time(self,
                               total_tokens: int,
                               batch_size: int,
                               concurrent_requests: int = 3) -> float:
        """Estimate time to process all tokens.
        
        Args:
            total_tokens: Total tokens to process
            batch_size: Tokens per batch
            concurrent_requests: Number of concurrent requests
            
        Returns:
            Estimated time in seconds
        """
        num_batches = (total_tokens + batch_size - 1) // batch_size
        
        # Calculate batches per minute based on rate limit
        tokens_per_minute = min(
            self.effective_tokens_per_minute,
            batch_size * concurrent_requests * 60
        )
        batches_per_minute = tokens_per_minute / batch_size
        
        # Estimate time
        minutes = num_batches / batches_per_minute
        seconds = minutes * 60
        
        return seconds
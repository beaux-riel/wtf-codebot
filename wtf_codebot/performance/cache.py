"""
Caching system for repeated analysis results.
"""

import hashlib
import json
import pickle
import time
from pathlib import Path
from typing import Any, Dict, Optional, Union, List
from dataclasses import dataclass, asdict
import logging
import sqlite3
import threading
from contextlib import contextmanager

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Represents a cache entry."""
    key: str
    value: Any
    timestamp: float
    ttl: Optional[float] = None
    file_hash: Optional[str] = None
    dependencies: List[str] = None
    
    def is_expired(self) -> bool:
        """Check if the cache entry is expired."""
        if self.ttl is None:
            return False
        return time.time() - self.timestamp > self.ttl
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)


class AnalysisCache:
    """In-memory cache for analysis results."""
    
    def __init__(self, max_size: int = 1000, default_ttl: float = 3600):
        """
        Initialize the cache.
        
        Args:
            max_size: Maximum number of entries to store
            default_ttl: Default time-to-live in seconds
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: Dict[str, CacheEntry] = {}
        self._access_times: Dict[str, float] = {}
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
    
    def get(self, key: str) -> Optional[Any]:
        """Get a value from the cache."""
        with self._lock:
            if key not in self._cache:
                self._misses += 1
                return None
            
            entry = self._cache[key]
            
            # Check if expired
            if entry.is_expired():
                del self._cache[key]
                if key in self._access_times:
                    del self._access_times[key]
                self._misses += 1
                return None
            
            # Update access time
            self._access_times[key] = time.time()
            self._hits += 1
            return entry.value
    
    def set(self, key: str, value: Any, ttl: Optional[float] = None, 
            file_hash: Optional[str] = None, dependencies: Optional[List[str]] = None) -> None:
        """Set a value in the cache."""
        with self._lock:
            # Use default TTL if not specified
            if ttl is None:
                ttl = self.default_ttl
            
            # Create cache entry
            entry = CacheEntry(
                key=key,
                value=value,
                timestamp=time.time(),
                ttl=ttl,
                file_hash=file_hash,
                dependencies=dependencies or []
            )
            
            # Add to cache
            self._cache[key] = entry
            self._access_times[key] = time.time()
            
            # Evict if over capacity
            self._evict_if_needed()
    
    def invalidate(self, key: str) -> bool:
        """Invalidate a specific cache entry."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                if key in self._access_times:
                    del self._access_times[key]
                return True
            return False
    
    def invalidate_by_file_hash(self, file_hash: str) -> int:
        """Invalidate entries by file hash."""
        with self._lock:
            keys_to_remove = []
            for key, entry in self._cache.items():
                if entry.file_hash == file_hash:
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                del self._cache[key]
                if key in self._access_times:
                    del self._access_times[key]
            
            return len(keys_to_remove)
    
    def invalidate_by_dependency(self, dependency: str) -> int:
        """Invalidate entries that depend on a specific file."""
        with self._lock:
            keys_to_remove = []
            for key, entry in self._cache.items():
                if entry.dependencies and dependency in entry.dependencies:
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                del self._cache[key]
                if key in self._access_times:
                    del self._access_times[key]
            
            return len(keys_to_remove)
    
    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            self._cache.clear()
            self._access_times.clear()
            self._hits = 0
            self._misses = 0
    
    def _evict_if_needed(self) -> None:
        """Evict entries if cache is over capacity."""
        if len(self._cache) <= self.max_size:
            return
        
        # Sort by access time (LRU)
        sorted_keys = sorted(self._access_times.keys(), 
                           key=lambda k: self._access_times[k])
        
        # Remove oldest entries
        num_to_remove = len(self._cache) - self.max_size
        for key in sorted_keys[:num_to_remove]:
            del self._cache[key]
            del self._access_times[key]
    
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total_requests = self._hits + self._misses
            hit_rate = self._hits / total_requests if total_requests > 0 else 0
            
            return {
                'size': len(self._cache),
                'max_size': self.max_size,
                'hits': self._hits,
                'misses': self._misses,
                'hit_rate': hit_rate,
                'total_requests': total_requests,
            }


class PersistentCache:
    """Persistent cache using SQLite."""
    
    def __init__(self, db_path: Union[str, Path], default_ttl: float = 3600):
        """
        Initialize the persistent cache.
        
        Args:
            db_path: Path to the SQLite database
            default_ttl: Default time-to-live in seconds
        """
        self.db_path = Path(db_path)
        self.default_ttl = default_ttl
        self._lock = threading.RLock()
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize the database schema."""
        with self._get_connection() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS cache_entries (
                    key TEXT PRIMARY KEY,
                    value BLOB,
                    timestamp REAL,
                    ttl REAL,
                    file_hash TEXT,
                    dependencies TEXT
                )
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_timestamp ON cache_entries(timestamp)
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_file_hash ON cache_entries(file_hash)
            ''')
            conn.commit()
    
    @contextmanager
    def _get_connection(self):
        """Get a database connection."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            yield conn
        finally:
            conn.close()
    
    def get(self, key: str) -> Optional[Any]:
        """Get a value from the cache."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    'SELECT value, timestamp, ttl FROM cache_entries WHERE key = ?',
                    (key,)
                )
                row = cursor.fetchone()
                
                if row is None:
                    return None
                
                value_blob, timestamp, ttl = row
                
                # Check if expired
                if ttl and time.time() - timestamp > ttl:
                    self.invalidate(key)
                    return None
                
                try:
                    return pickle.loads(value_blob)
                except Exception as e:
                    logger.warning(f"Failed to deserialize cache value for key {key}: {e}")
                    self.invalidate(key)
                    return None
    
    def set(self, key: str, value: Any, ttl: Optional[float] = None,
            file_hash: Optional[str] = None, dependencies: Optional[List[str]] = None) -> None:
        """Set a value in the cache."""
        with self._lock:
            if ttl is None:
                ttl = self.default_ttl
            
            try:
                value_blob = pickle.dumps(value)
                dependencies_json = json.dumps(dependencies) if dependencies else None
                
                with self._get_connection() as conn:
                    conn.execute('''
                        INSERT OR REPLACE INTO cache_entries 
                        (key, value, timestamp, ttl, file_hash, dependencies)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (key, value_blob, time.time(), ttl, file_hash, dependencies_json))
                    conn.commit()
            
            except Exception as e:
                logger.warning(f"Failed to serialize cache value for key {key}: {e}")
    
    def invalidate(self, key: str) -> bool:
        """Invalidate a specific cache entry."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute('DELETE FROM cache_entries WHERE key = ?', (key,))
                conn.commit()
                return cursor.rowcount > 0
    
    def invalidate_by_file_hash(self, file_hash: str) -> int:
        """Invalidate entries by file hash."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute('DELETE FROM cache_entries WHERE file_hash = ?', (file_hash,))
                conn.commit()
                return cursor.rowcount
    
    def invalidate_by_dependency(self, dependency: str) -> int:
        """Invalidate entries that depend on a specific file."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute('''
                    DELETE FROM cache_entries 
                    WHERE dependencies LIKE ?
                ''', (f'%"{dependency}"%',))
                conn.commit()
                return cursor.rowcount
    
    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute('DELETE FROM cache_entries')
                conn.commit()
    
    def cleanup_expired(self) -> int:
        """Clean up expired entries."""
        with self._lock:
            current_time = time.time()
            with self._get_connection() as conn:
                cursor = conn.execute('''
                    DELETE FROM cache_entries 
                    WHERE ttl IS NOT NULL AND (timestamp + ttl) < ?
                ''', (current_time,))
                conn.commit()
                return cursor.rowcount
    
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute('SELECT COUNT(*) FROM cache_entries')
                total_entries = cursor.fetchone()[0]
                
                cursor = conn.execute('''
                    SELECT COUNT(*) FROM cache_entries 
                    WHERE ttl IS NOT NULL AND (timestamp + ttl) < ?
                ''', (time.time(),))
                expired_entries = cursor.fetchone()[0]
                
                return {
                    'total_entries': total_entries,
                    'expired_entries': expired_entries,
                    'active_entries': total_entries - expired_entries,
                    'db_size_bytes': self.db_path.stat().st_size if self.db_path.exists() else 0,
                }


class CacheManager:
    """Manages multiple cache instances and provides unified interface."""
    
    def __init__(self, cache_dir: Optional[Union[str, Path]] = None):
        """
        Initialize the cache manager.
        
        Args:
            cache_dir: Directory for persistent cache files
        """
        self.cache_dir = Path(cache_dir) if cache_dir else Path.cwd() / '.wtf_cache'
        self.cache_dir.mkdir(exist_ok=True)
        
        self.memory_cache = AnalysisCache()
        self.persistent_cache = PersistentCache(self.cache_dir / 'analysis.db')
        
        # File hash cache for tracking file changes
        self._file_hashes: Dict[str, str] = {}
    
    def get_file_hash(self, file_path: Union[str, Path]) -> str:
        """Get hash of a file for cache invalidation."""
        file_path = Path(file_path)
        
        # Use modification time and size as a quick hash
        try:
            stat = file_path.stat()
            content = f"{stat.st_mtime}:{stat.st_size}"
            return hashlib.md5(content.encode()).hexdigest()
        except (OSError, IOError):
            return hashlib.md5(str(file_path).encode()).hexdigest()
    
    def get_content_hash(self, content: str) -> str:
        """Get hash of content for cache keys."""
        return hashlib.md5(content.encode()).hexdigest()
    
    def get_analysis_result(self, key: str) -> Optional[Any]:
        """Get analysis result from cache."""
        # Try memory cache first
        result = self.memory_cache.get(key)
        if result is not None:
            return result
        
        # Try persistent cache
        result = self.persistent_cache.get(key)
        if result is not None:
            # Store in memory cache for faster access
            self.memory_cache.set(key, result)
            return result
        
        return None
    
    def set_analysis_result(self, key: str, result: Any, file_path: Optional[Union[str, Path]] = None,
                          dependencies: Optional[List[str]] = None, ttl: Optional[float] = None) -> None:
        """Set analysis result in cache."""
        file_hash = None
        if file_path:
            file_hash = self.get_file_hash(file_path)
            self._file_hashes[str(file_path)] = file_hash
        
        # Store in both caches
        self.memory_cache.set(key, result, ttl=ttl, file_hash=file_hash, dependencies=dependencies)
        self.persistent_cache.set(key, result, ttl=ttl, file_hash=file_hash, dependencies=dependencies)
    
    def invalidate_file(self, file_path: Union[str, Path]) -> int:
        """Invalidate cache entries for a specific file."""
        file_path_str = str(file_path)
        old_hash = self._file_hashes.get(file_path_str)
        
        total_invalidated = 0
        
        if old_hash:
            # Invalidate by old hash
            total_invalidated += self.memory_cache.invalidate_by_file_hash(old_hash)
            total_invalidated += self.persistent_cache.invalidate_by_file_hash(old_hash)
        
        # Invalidate dependencies
        total_invalidated += self.memory_cache.invalidate_by_dependency(file_path_str)
        total_invalidated += self.persistent_cache.invalidate_by_dependency(file_path_str)
        
        # Update file hash
        self._file_hashes[file_path_str] = self.get_file_hash(file_path)
        
        return total_invalidated
    
    def check_file_changes(self, file_paths: List[Union[str, Path]]) -> List[str]:
        """Check which files have changed since last cache."""
        changed_files = []
        
        for file_path in file_paths:
            file_path_str = str(file_path)
            current_hash = self.get_file_hash(file_path)
            old_hash = self._file_hashes.get(file_path_str)
            
            if old_hash != current_hash:
                changed_files.append(file_path_str)
                self.invalidate_file(file_path)
        
        return changed_files
    
    def clear_all(self) -> None:
        """Clear all caches."""
        self.memory_cache.clear()
        self.persistent_cache.clear()
        self._file_hashes.clear()
    
    def cleanup(self) -> Dict[str, int]:
        """Cleanup expired entries."""
        expired_persistent = self.persistent_cache.cleanup_expired()
        
        return {
            'expired_persistent': expired_persistent,
        }
    
    def stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics."""
        return {
            'memory_cache': self.memory_cache.stats(),
            'persistent_cache': self.persistent_cache.stats(),
            'file_hashes': len(self._file_hashes),
        }

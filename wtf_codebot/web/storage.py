"""
Local storage module for persistent audit results.

This module provides utilities for storing and retrieving audit results
in a persistent local storage mechanism.
"""

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

# Get app data directory
def get_app_data_dir() -> Path:
    """Get the application data directory for storing persistent data."""
    home = Path.home()
    
    if os.name == 'nt':  # Windows
        app_data = home / 'AppData' / 'Local' / 'WTF-Codebot'
    elif os.name == 'posix':  # macOS, Linux
        if os.path.exists(home / 'Library'):  # macOS
            app_data = home / 'Library' / 'Application Support' / 'WTF-Codebot'
        else:  # Linux
            app_data = home / '.local' / 'share' / 'wtf-codebot'
    else:
        app_data = home / '.wtf-codebot'
    
    # Create directory if it doesn't exist
    app_data.mkdir(parents=True, exist_ok=True)
    
    return app_data

class AnalysisStorage:
    """Storage manager for analysis results."""
    
    def __init__(self):
        """Initialize the storage manager."""
        self.db_path = get_app_data_dir() / 'analysis_history.db'
        self._init_db()
    
    def _init_db(self):
        """Initialize the database schema."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Create tables if they don't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            directory TEXT NOT NULL,
            result_json TEXT NOT NULL,
            metadata_json TEXT
        )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_analysis(self, directory: str, result: Dict[str, Any], 
                     excluded_paths: Optional[List[str]] = None, 
                     included_paths: Optional[List[str]] = None) -> int:
        """
        Save analysis result to persistent storage.
        
        Args:
            directory: The directory that was analyzed
            result: The analysis result data
            excluded_paths: Paths that were excluded from analysis
            included_paths: Paths that were specifically included in analysis
            
        Returns:
            The ID of the saved analysis
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Convert result to JSON
        result_json = json.dumps(result)
        
        # Prepare metadata
        metadata = {
            'excluded_paths': excluded_paths or [],
            'included_paths': included_paths or []
        }
        metadata_json = json.dumps(metadata)
        
        # Insert record
        cursor.execute(
            'INSERT INTO analysis_history (timestamp, directory, result_json, metadata_json) VALUES (?, ?, ?, ?)',
            (datetime.now().isoformat(), directory, result_json, metadata_json)
        )
        
        analysis_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return analysis_id
    
    def get_analysis(self, analysis_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve a specific analysis by ID.
        
        Args:
            analysis_id: The ID of the analysis to retrieve
            
        Returns:
            The analysis data or None if not found
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT id, timestamp, directory, result_json, metadata_json FROM analysis_history WHERE id = ?',
            (analysis_id,)
        )
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        id, timestamp, directory, result_json, metadata_json = row
        
        # Parse JSON data
        result = json.loads(result_json)
        metadata = json.loads(metadata_json) if metadata_json else {}
        
        return {
            'id': id,
            'timestamp': timestamp,
            'directory': directory,
            'result': result,
            'excluded_paths': metadata.get('excluded_paths', []),
            'included_paths': metadata.get('included_paths', [])
        }
    
    def get_all_analyses(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Retrieve all analyses with pagination.
        
        Args:
            limit: Maximum number of analyses to retrieve
            offset: Number of analyses to skip
            
        Returns:
            List of analysis data
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT id, timestamp, directory, result_json, metadata_json FROM analysis_history ORDER BY id DESC LIMIT ? OFFSET ?',
            (limit, offset)
        )
        
        rows = cursor.fetchall()
        conn.close()
        
        analyses = []
        for row in rows:
            id, timestamp, directory, result_json, metadata_json = row
            
            # Parse JSON data
            result = json.loads(result_json)
            metadata = json.loads(metadata_json) if metadata_json else {}
            
            # Create summary version with minimal info for listings
            summary_result = {
                'total_files': result.get('total_files', 0),
                'findings': result.get('findings', []),
                'summary': result.get('summary', {})
            }
            
            analyses.append({
                'id': id,
                'timestamp': timestamp,
                'directory': directory,
                'result': summary_result,  # Use summary to reduce size
                'excluded_paths': metadata.get('excluded_paths', []),
                'included_paths': metadata.get('included_paths', [])
            })
        
        return analyses
    
    def count_analyses(self) -> int:
        """Get the total number of analyses stored."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM analysis_history')
        count = cursor.fetchone()[0]
        
        conn.close()
        return count
    
    def delete_analysis(self, analysis_id: int) -> bool:
        """
        Delete a specific analysis by ID.
        
        Args:
            analysis_id: The ID of the analysis to delete
            
        Returns:
            True if deleted successfully, False otherwise
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM analysis_history WHERE id = ?', (analysis_id,))
        deleted = cursor.rowcount > 0
        
        conn.commit()
        conn.close()
        
        return deleted
    
    def delete_all_analyses(self) -> int:
        """
        Delete all analyses.
        
        Returns:
            Number of analyses deleted
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM analysis_history')
        deleted_count = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        return deleted_count
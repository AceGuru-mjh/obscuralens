"""
Database Module for storing query history and results
Supports: SQLite, PostgreSQL, MySQL
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from contextlib import contextmanager

from .config import config


@dataclass
class QueryRecord:
    """Query history record"""
    id: Optional[int] = None
    query_type: str = ""  # ip, phone, username, email
    query_value: str = ""
    result_data: str = ""  # JSON string
    created_at: Optional[str] = None
    success: bool = True
    error_message: str = ""


class DatabaseManager:
    """Database manager for ObscuraLens"""

    def __init__(self):
        self.db_type = config.db_config.db_type
        self.db_path = Path(config.db_config.sqlite_path)
        self._init_database()

    def _init_database(self):
        """Initialize database tables"""
        if self.db_type == "sqlite":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Query history table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS query_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        query_type TEXT NOT NULL,
                        query_value TEXT NOT NULL,
                        result_data TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        success BOOLEAN DEFAULT 1,
                        error_message TEXT
                    )
                ''')
                
                # Create indexes
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_query_type ON query_history(query_type)
                ''')
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_query_value ON query_history(query_value)
                ''')
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_created_at ON query_history(created_at)
                ''')
                
                conn.commit()

    @contextmanager
    def _get_connection(self):
        """Get database connection"""
        if self.db_type == "sqlite":
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()
        else:
            # TODO: Implement PostgreSQL/MySQL support
            raise NotImplementedError(f"Database type {self.db_type} not yet implemented")

    def save_query(self, query_type: str, query_value: str, 
                   result_data: Dict[str, Any], success: bool = True,
                   error_message: str = "") -> int:
        """Save a query to history"""
        if not config.app_config.save_history:
            return -1

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO query_history (query_type, query_value, result_data, success, error_message)
                VALUES (?, ?, ?, ?, ?)
            ''', (query_type, query_value, json.dumps(result_data), success, error_message))
            conn.commit()
            return cursor.lastrowid

    def get_history(self, query_type: Optional[str] = None, 
                    limit: int = 100) -> List[QueryRecord]:
        """Get query history"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if query_type:
                cursor.execute('''
                    SELECT * FROM query_history 
                    WHERE query_type = ? 
                    ORDER BY created_at DESC 
                    LIMIT ?
                ''', (query_type, limit))
            else:
                cursor.execute('''
                    SELECT * FROM query_history 
                    ORDER BY created_at DESC 
                    LIMIT ?
                ''', (limit,))
            
            rows = cursor.fetchall()
            return [QueryRecord(
                id=row['id'],
                query_type=row['query_type'],
                query_value=row['query_value'],
                result_data=row['result_data'],
                created_at=row['created_at'],
                success=bool(row['success']),
                error_message=row['error_message']
            ) for row in rows]

    def get_query_by_id(self, query_id: int) -> Optional[QueryRecord]:
        """Get a specific query by ID"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM query_history WHERE id = ?', (query_id,))
            row = cursor.fetchone()
            
            if row:
                return QueryRecord(
                    id=row['id'],
                    query_type=row['query_type'],
                    query_value=row['query_value'],
                    result_data=row['result_data'],
                    created_at=row['created_at'],
                    success=bool(row['success']),
                    error_message=row['error_message']
                )
            return None

    def search_history(self, search_term: str) -> List[QueryRecord]:
        """Search query history"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM query_history 
                WHERE query_value LIKE ? 
                ORDER BY created_at DESC
            ''', (f'%{search_term}%',))
            
            rows = cursor.fetchall()
            return [QueryRecord(
                id=row['id'],
                query_type=row['query_type'],
                query_value=row['query_value'],
                result_data=row['result_data'],
                created_at=row['created_at'],
                success=bool(row['success']),
                error_message=row['error_message']
            ) for row in rows]

    def delete_history(self, query_id: int) -> bool:
        """Delete a specific history record"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM query_history WHERE id = ?', (query_id,))
            conn.commit()
            return cursor.rowcount > 0

    def clear_history(self, query_type: Optional[str] = None) -> int:
        """Clear all history or history of specific type"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if query_type:
                cursor.execute('DELETE FROM query_history WHERE query_type = ?', (query_type,))
            else:
                cursor.execute('DELETE FROM query_history')
            
            conn.commit()
            return cursor.rowcount

    @staticmethod
    def count_fields(result_data: str) -> int:
        """
        Count populated top-level fields in a stored result.

        Used by the history view to show how much data each query produced.
        """
        if not result_data:
            return 0
        try:
            data = json.loads(result_data)
        except (ValueError, TypeError):
            return 0

        if not isinstance(data, dict):
            return 0

        # New format nests everything under 'info'.
        info = data.get('info')
        if isinstance(info, dict):
            # Explicit False counts: disposable=False is a real collected fact.
            return len([v for v in info.values()
                        if v is not None and v != '' and v != [] and v != {}])

        # Username results store a list per platform.
        results = data.get('results')
        if isinstance(results, list):
            total = 0
            for item in results:
                if isinstance(item, dict):
                    total += len(item.get('profile') or {})
            return total

        return len([v for v in data.values()
                    if v is not None and v != '' and v != [] and v != {}])

    def get_statistics(self) -> Dict[str, Any]:
        """Get query statistics"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Total queries
            cursor.execute('SELECT COUNT(*) as total FROM query_history')
            total = cursor.fetchone()['total']
            
            # Queries by type
            cursor.execute('''
                SELECT query_type, COUNT(*) as count 
                FROM query_history 
                GROUP BY query_type
            ''')
            by_type = {row['query_type']: row['count'] for row in cursor.fetchall()}
            
            # Success rate
            cursor.execute('''
                SELECT 
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as success_count,
                    COUNT(*) as total
                FROM query_history
            ''')
            row = cursor.fetchone()
            success_rate = (row['success_count'] / row['total'] * 100) if row['total'] > 0 else 0
            
            # Recent queries (last 7 days)
            cursor.execute('''
                SELECT COUNT(*) as count 
                FROM query_history 
                WHERE created_at >= datetime('now', '-7 days')
            ''')
            recent = cursor.fetchone()['count']
            
            return {
                'total_queries': total,
                'queries_by_type': by_type,
                'success_rate': round(success_rate, 2),
                'recent_queries_7d': recent
            }


# Global database instance
db = DatabaseManager()

"""
SQLite-backed TTL cache for HTTP GET responses.

Keeps repeated lookups fast and reduces load on public OSINT endpoints. Only
successful (HTTP 200) responses are stored. Entries are zlib-compressed JSON
and expire after ``cache_ttl`` seconds. The cache can be disabled through
``app.cache_enabled: false`` in config.yaml or OBSCURALENS_CACHE_ENABLED=0.
"""

import json
import sqlite3
import threading
import time
import zlib
from pathlib import Path
from typing import Any, Dict, Optional

from ..config import config

# Never cache an individual payload larger than this (bytes, uncompressed).
MAX_ENTRY_BYTES = 1_500_000


class HttpCache:
    """Thread-safe SQLite TTL cache."""

    def __init__(self, path: Optional[str] = None, default_ttl: Optional[int] = None):
        self._path = path
        self._default_ttl = default_ttl
        self._lock = threading.Lock()
        self._ready = False
        self.hits = 0
        self.misses = 0

    # -- configuration ----------------------------------------------------

    @property
    def path(self) -> Path:
        return Path(self._path or config.app_config.cache_path)

    @property
    def default_ttl(self) -> int:
        return self._default_ttl or config.app_config.cache_ttl

    @property
    def enabled(self) -> bool:
        return bool(config.app_config.cache_enabled)

    # -- storage ----------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        path = self.path
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), timeout=10)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS http_cache (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL,
                expires_at REAL NOT NULL,
                created_at REAL NOT NULL
            )
        ''')
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_http_cache_expires
            ON http_cache(expires_at)
        ''')
        return conn

    @staticmethod
    def _key(namespace: str, url: str) -> str:
        return f"{namespace}:{url}"

    def get(self, namespace: str, url: str) -> Optional[Any]:
        """Return a cached value, or None when absent/expired/disabled."""
        if not self.enabled:
            return None
        key = self._key(namespace, url)
        try:
            with self._lock:
                conn = self._connect()
                try:
                    row = conn.execute(
                        'SELECT value, expires_at FROM http_cache WHERE key = ?',
                        (key,)).fetchone()
                    if row is None:
                        self.misses += 1
                        return None
                    value, expires_at = row
                    if expires_at < time.time():
                        conn.execute('DELETE FROM http_cache WHERE key = ?', (key,))
                        conn.commit()
                        self.misses += 1
                        return None
                    self.hits += 1
                    return json.loads(zlib.decompress(value).decode('utf-8'))
                finally:
                    conn.close()
        except (sqlite3.Error, ValueError, zlib.error, OSError):
            self.misses += 1
            return None

    def set(self, namespace: str, url: str, value: Any,
            ttl: Optional[int] = None) -> bool:
        """Store a value; returns False when skipped (disabled/too large)."""
        if not self.enabled:
            return False
        try:
            payload = json.dumps(value, ensure_ascii=False, default=str).encode('utf-8')
        except (TypeError, ValueError):
            return False
        if len(payload) > MAX_ENTRY_BYTES:
            return False

        key = self._key(namespace, url)
        now = time.time()
        expires_at = now + (ttl if ttl is not None else self.default_ttl)
        try:
            with self._lock:
                conn = self._connect()
                try:
                    conn.execute(
                        'INSERT OR REPLACE INTO http_cache '
                        '(key, value, expires_at, created_at) VALUES (?, ?, ?, ?)',
                        (key, zlib.compress(payload), expires_at, now))
                    conn.commit()
                    return True
                finally:
                    conn.close()
        except (sqlite3.Error, OSError):
            return False

    # -- maintenance ------------------------------------------------------

    def prune(self) -> int:
        """Delete expired rows; returns the number removed."""
        try:
            with self._lock:
                conn = self._connect()
                try:
                    cur = conn.execute('DELETE FROM http_cache WHERE expires_at < ?',
                                       (time.time(),))
                    conn.commit()
                    return cur.rowcount
                finally:
                    conn.close()
        except (sqlite3.Error, OSError):
            return 0

    def clear(self) -> int:
        """Delete every cached entry; returns the number removed."""
        try:
            with self._lock:
                conn = self._connect()
                try:
                    cur = conn.execute('DELETE FROM http_cache')
                    conn.commit()
                    return cur.rowcount
                finally:
                    conn.close()
        except (sqlite3.Error, OSError):
            return 0

    def stats(self) -> Dict[str, Any]:
        """Cache counters and freshness information."""
        total = 0
        fresh = 0
        size_bytes = 0
        try:
            with self._lock:
                conn = self._connect()
                try:
                    now = time.time()
                    total = conn.execute('SELECT COUNT(*) FROM http_cache').fetchone()[0]
                    fresh = conn.execute(
                        'SELECT COUNT(*) FROM http_cache WHERE expires_at >= ?',
                        (now,)).fetchone()[0]
                    size_bytes = conn.execute(
                        'SELECT COALESCE(SUM(LENGTH(value)), 0) FROM http_cache'
                    ).fetchone()[0]
                finally:
                    conn.close()
        except (sqlite3.Error, OSError):
            pass
        return {
            'enabled': self.enabled,
            'entries': total,
            'fresh': fresh,
            'expired': total - fresh,
            'size_bytes': size_bytes,
            'hits': self.hits,
            'misses': self.misses,
            'path': str(self.path),
            'default_ttl': self.default_ttl,
        }


# Shared cache instance
cache = HttpCache()

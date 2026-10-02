"""
Source health package: persisted per-source reliability statistics and a
circuit breaker that keeps failing sources out of the request path.
"""

from .source_health import SourceHealth, health

__all__ = ['SourceHealth', 'health']

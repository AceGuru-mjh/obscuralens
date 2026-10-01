"""
Optional web UI and REST API for ObscuraLens.

Importing this package is cheap: FastAPI and uvicorn are only imported when
``create_app`` or ``serve`` is actually called, so the core CLI keeps working
without the optional ``web`` extra installed.
"""

from .app import create_app, serve

__all__ = ['create_app', 'serve']

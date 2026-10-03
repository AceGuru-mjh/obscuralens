"""
Advanced analysis package (v5.0).

Higher-level investigation tooling built on top of the trackers and the
stored lookup history:

* :mod:`obscuralens.advanced.batch`      - parallel batch lookups + exports
* :mod:`obscuralens.advanced.alerts`     - opt-in webhook notifications
* :mod:`obscuralens.advanced.patterns`   - pattern-of-life analysis
* :mod:`obscuralens.advanced.geospatial` - geographic profiling of history
* :mod:`obscuralens.advanced.report_builder` - self-contained HTML reports

Every module is importable independently; nothing here is required by the
core trackers. The sub-modules are also wired into the CLI (``obscuralens
report / patterns / geo / alerts / batch``), the REST API (``/api/tools/*``,
``/api/report/*``, ``/api/patterns``, ``/api/alerts``) and the MCP server.
"""

from . import alerts, batch, geospatial, patterns, report_builder

__all__ = ['alerts', 'batch', 'geospatial', 'patterns', 'report_builder']

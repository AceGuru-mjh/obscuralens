"""
YAML-driven investigation pipelines for ObscuraLens v4.0.

A pipeline is a small YAML document describing a repeatable investigation:
lookups, risk scoring, timeline building, correlation, assertions and output
rendering. See ``pipelines/examples/`` in the repository for ready-made
pipelines and ``engine`` for the execution semantics.
"""

from .engine import (
    ACTIONS,
    PIPELINE_FORMATS,
    TRACKER_MAP,
    PipelineError,
    list_pipelines,
    load_pipeline,
    pipeline_sections,
    resolve_trackers,
    run_pipeline,
    save_pipeline,
    shipped_pipelines_dir,
)

__all__ = [
    'ACTIONS',
    'PIPELINE_FORMATS',
    'TRACKER_MAP',
    'PipelineError',
    'list_pipelines',
    'load_pipeline',
    'pipeline_sections',
    'resolve_trackers',
    'run_pipeline',
    'save_pipeline',
    'shipped_pipelines_dir',
]

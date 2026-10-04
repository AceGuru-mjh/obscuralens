"""
ObscuraLens benchmark suite (v6.2 part 6).

A self-contained, offline, deterministic timing harness for the platform's
pure-computation hot paths: validators, detection, caching, rate limiting,
metrics, formatting, coordinate maths, dorks, the data catalog, every
analytics module, and the SDK / MCP / reporting / export / plugin /
completion / i18n / database platform surfaces.

Design contract (mirrored by every module in this package):

* **Offline** - no network, no real API calls; every input is synthetic and
  deterministic (seeded :class:`random.Random` only).
* **Hermetic** - no writes outside temporary directories; stateful benches
  (cache, database, plugins) isolate themselves under a caller-supplied
  workdir and restore any patched global state on teardown.
* **Fast enough** - the full suite finishes in well under two minutes and
  ``--quick`` mode (CI) in a handful of seconds.

Run it with::

    python -m benchmarks.run            # full run, saved to results/latest.json
    python -m benchmarks.run --quick    # CI mode
    python -m benchmarks.run --list     # what is registered

See :mod:`benchmarks.harness` for the timing machinery and
``benchmarks/README.md`` for the full guide.
"""

from .harness import (
    BenchReport,
    BenchSpec,
    BenchSuite,
    CompareRow,
    Timer,
    Timing,
    compare,
    compare_table,
    measure,
    percentile,
    state_dir,
)

__version__ = '1.0.0'

__all__ = [
    'BenchReport',
    'BenchSpec',
    'BenchSuite',
    'CompareRow',
    'Timer',
    'Timing',
    '__version__',
    'compare',
    'compare_table',
    'measure',
    'percentile',
    'state_dir',
]

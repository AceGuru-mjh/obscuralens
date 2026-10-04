"""
CLI entry point for the ObscuraLens benchmark suite.

Usage::

    python -m benchmarks.run [OPTIONS]

Options:

* ``--quick`` - CI mode: every benchmark's repeat/number is divided by the
  harness quick scale so the whole suite finishes in seconds.
* ``--only NAME`` - substring filter, repeatable (OR semantics).
* ``--tags TAG`` - tag filter, repeatable (OR semantics).
* ``--save PATH`` - where to write the JSON report (default
  ``benchmarks/results/latest.json``; the committed baseline
  ``benchmarks/results/baseline.json`` is NEVER written automatically -
  regenerate it deliberately with
  ``python -m benchmarks.run --save benchmarks/results/baseline.json``).
* ``--compare PATH`` - baseline to compare against (defaults to
  ``benchmarks/results/baseline.json`` when that file exists).
* ``--json`` - print the machine-readable report to stdout instead of the
  human tables.
* ``--list`` - print every registered benchmark name with its tags and exit.
* ``--tolerance X`` - regression band for the comparison (default 0.35).
* ``--fail-on-regression`` - exit 2 when any benchmark is verdict 'slower'.

Exit codes: ``0`` normal (slower verdicts alone never fail a run),
``1`` when a benchmark raised, ``2`` with ``--fail-on-regression`` and at
least one 'slower' verdict.

Hermetic bootstrap: this module redirects the package's on-disk artefacts
(database, cache, reports) into a private temporary directory through the
``OBSCURALENS_*`` environment variables *before* any benchmark module (and
therefore any ``obscuralens`` import) is loaded, so a benchmark run never
touches the user's config, history or cache - and never writes into the
repository working directory. The override is applied at module import and
**undone when :func:`main` returns** (:func:`restore_env`): importing this
module from a test process therefore never leaks the hermetic paths into
the surrounding process's later config resolution.
"""

import argparse
import atexit
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, List, Optional

# --- hermetic environment bootstrap (must precede obscuralens imports) -------

_BOOTDIR = Path(tempfile.mkdtemp(prefix='obscuralens-bench-env-'))
atexit.register(lambda: shutil.rmtree(_BOOTDIR, ignore_errors=True))

#: Hermetic overrides applied while a benchmark run is active.
_HERMETIC_ENV = {
    'OBSCURALENS_CONFIG_DIR': str(_BOOTDIR / 'config'),
    'OBSCURALENS_SQLITE_PATH': str(_BOOTDIR / 'history.db'),
    'OBSCURALENS_CACHE_PATH': str(_BOOTDIR / 'http_cache.db'),
    'OBSCURALENS_REPORT_DIR': str(_BOOTDIR / 'reports'),
    'OBSCURALENS_CHART_DIR': str(_BOOTDIR / 'reports' / 'charts'),
    'OBSCURALENS_REQUESTS_PER_SECOND': '0',
    'OBSCURALENS_SAVE_HISTORY': '1',
    'NO_COLOR': '1',
}

#: Pre-bootstrap values (``None`` = the variable was not set at all).
_ORIGINAL_ENV = {key: os.environ.get(key) for key in _HERMETIC_ENV}

#: Whether the hermetic overrides are currently applied.
_BOOTSTRAPPED = False


def bootstrap_env() -> None:
    """Apply the hermetic environment overrides (idempotent)."""
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return
    os.environ.update(_HERMETIC_ENV)
    _BOOTSTRAPPED = True


# The module import itself must be hermetic for the ``python -m
# benchmarks.run`` path (bench modules import obscuralens below), so the
# overrides go on immediately - main() takes them off again afterwards.
bootstrap_env()


def restore_env() -> None:
    """
    Undo the hermetic environment overrides.

    Restores every overridden variable to its pre-bootstrap value (or
    removes it entirely when it was unset), so a surrounding process -
    typically pytest importing this module for CLI tests - never resolves
    ObscuraLens state into the (deleted) benchmark boot directory.
    """
    global _BOOTSTRAPPED
    if not _BOOTSTRAPPED:
        return
    for key, value in _ORIGINAL_ENV.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    _BOOTSTRAPPED = False

# --- benchmark modules (import after the bootstrap) ---------------------------

from . import bench_analytics, bench_core, bench_platform  # noqa: E402
from .harness import (  # noqa: E402
    DEFAULT_TOLERANCE,
    BenchSuite,
    compare,
    compare_table,
)

#: The bench modules whose ``build_benches`` populate the default suite.
BENCH_MODULES = (bench_core, bench_analytics, bench_platform)

#: Directory holding committed baselines and per-run reports.
RESULTS_DIR = Path(__file__).resolve().parent / 'results'

#: Default report destination (never the committed baseline).
DEFAULT_SAVE = RESULTS_DIR / 'latest.json'

#: Default comparison source when it exists.
DEFAULT_BASELINE = RESULTS_DIR / 'baseline.json'


# --- suite assembly -----------------------------------------------------------

def build_suite(workdir: Optional[str] = None) -> BenchSuite:
    """
    Assemble the full benchmark suite from every bench module.

    Args:
        workdir: optional caller-owned directory under which stateful
            benches (cache, database) isolate their on-disk state; when
            None each of them self-manages a tempdir via its teardown.

    Returns:
        The registered :class:`~benchmarks.harness.BenchSuite`.
    """
    suite = BenchSuite()
    for module in BENCH_MODULES:
        for spec in module.build_benches(workdir=workdir):
            suite.add_spec(spec)
    return suite


# --- CLI -----------------------------------------------------------------------

def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='python -m benchmarks.run',
        description='ObscuraLens offline benchmark suite (see benchmarks/README.md)')
    parser.add_argument('--quick', action='store_true',
                        help='CI mode: divide each benchmark\'s work so the '
                             'whole suite finishes in seconds')
    parser.add_argument('--only', action='append', default=[], metavar='NAME',
                        help='substring filter on benchmark names (repeatable)')
    parser.add_argument('--tags', action='append', default=[], metavar='TAG',
                        help='tag filter, e.g. core/analytics/platform (repeatable)')
    parser.add_argument('--save', metavar='PATH', default=None,
                        help='write the JSON report here (default '
                             'benchmarks/results/latest.json)')
    parser.add_argument('--compare', metavar='PATH', default=None,
                        help='baseline JSON to compare against (default '
                             'benchmarks/results/baseline.json when present)')
    parser.add_argument('--json', action='store_true',
                        help='print the machine-readable report to stdout')
    parser.add_argument('--list', action='store_true',
                        help='list registered benchmarks (name + tags) and exit')
    parser.add_argument('--tolerance', type=float, default=DEFAULT_TOLERANCE,
                        help='regression band for --compare verdicts '
                             '(default 0.35 = 35%%)')
    parser.add_argument('--fail-on-regression', action='store_true',
                        help='exit 2 when any benchmark is slower than the '
                             'baseline beyond the tolerance')
    return parser


def _load_baseline(path: Path) -> Optional[Any]:
    """Load a baseline document, returning None when unreadable."""
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        print(f'warning: could not load baseline {path}: {exc}', file=sys.stderr)
        return None


def main(argv: Optional[List[str]] = None) -> int:
    """
    Run the benchmark suite from command-line arguments.

    Args:
        argv: argument list (defaults to ``sys.argv[1:]``).

    Returns:
        Exit code: 0 normal, 1 when a benchmark raised, 2 when
        ``--fail-on-regression`` flagged a slower benchmark.

    The hermetic environment overrides are re-applied on entry (in case a
    previous call restored them) and always undone on exit, so importing
    this module from a long-lived process - pytest running the CLI tests,
    say - never leaks the benchmark boot paths into later tests.
    """
    bootstrap_env()
    try:
        return _run_cli(argv)
    finally:
        restore_env()


def _run_cli(argv: Optional[List[str]]) -> int:
    """Argument-parsing body of :func:`main` (env already bootstrapped)."""
    args = _parser().parse_args(argv)

    # One caller-owned workdir for the whole run: stateful benches (cache,
    # database) isolate their on-disk state in named subdirectories of it
    # during their setup/teardown pair inside suite.run().
    workdir = tempfile.mkdtemp(prefix='obscuralens-bench-')
    suite = build_suite(workdir=workdir)

    if args.list:
        shutil.rmtree(workdir, ignore_errors=True)
        for entry in suite.registered():
            tags = ', '.join(entry['tags']) or '-'
            print(f"{entry['name']:<45} [{tags}]")
        return 0

    try:
        report = suite.run(only=args.only or None, tags=args.tags or None,
                           quick=args.quick)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    save_path = Path(args.save) if args.save else DEFAULT_SAVE

    # Resolve (and load) the comparison baseline BEFORE saving the fresh
    # report, so regenerating the baseline compares against the previous
    # baseline rather than against itself.
    compare_path: Optional[Path] = None
    if args.compare:
        compare_path = Path(args.compare)
    elif DEFAULT_BASELINE.exists():
        compare_path = DEFAULT_BASELINE
    baseline_doc = None
    if compare_path is not None and compare_path.exists():
        baseline_doc = _load_baseline(compare_path)

    report.save(save_path)
    rows = compare(report, baseline_doc, tolerance=args.tolerance) \
        if baseline_doc is not None else []

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        mode = 'quick' if args.quick else 'full'
        filters = []
        if args.only:
            filters.append(f"only={'/'.join(args.only)}")
        if args.tags:
            filters.append(f"tags={'/'.join(args.tags)}")
        suffix = f" ({', '.join(filters)})" if filters else ''
        print(f'ObscuraLens benchmark suite - {mode} run{suffix}')
        print(f'python {report.to_dict().get("python", "?")}'
              f' | saved to {save_path}')
        print()
        print(report.to_table())
        print()
        print(report.summary())
        if rows:
            print()
            print(f'comparison against {compare_path} '
                  f'(tolerance {args.tolerance:.0%}):')
            print(compare_table(rows))
            slower = [row for row in rows if row.verdict == 'slower']
            faster = [row for row in rows if row.verdict == 'faster']
            print(f"verdicts: {len([r for r in rows if r.verdict == 'stable'])} stable, "
                  f"{len(slower)} slower, {len(faster)} faster, "
                  f"{len([r for r in rows if r.verdict == 'new'])} new, "
                  f"{len([r for r in rows if r.verdict == 'missing'])} missing")

    if report.errors:
        for entry in report.errors:
            print(f"error: {entry.get('name')}: {entry.get('error')}",
                  file=sys.stderr)
        return 1
    if args.fail_on_regression and any(row.verdict == 'slower' for row in rows):
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())

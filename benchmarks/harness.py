"""
Stdlib timing harness for the ObscuraLens benchmark suite.

Everything a benchmark needs except the benchmarks themselves:

* :class:`Timer` - a ``time.perf_counter`` context manager.
* :func:`measure` - repeat/number timing of one callable, returning a
  :class:`Timing` record with per-call min/mean/median/p95/stdev and an
  ops-per-second figure.
* :class:`BenchSuite` - registration plus filtered execution
  (``only`` substring filters, ``tags``, and a ``quick`` mode that divides
  the work so the whole suite finishes in seconds).
* :class:`BenchReport` - the JSON-serialisable result of one suite run,
  with an aligned text :meth:`BenchReport.to_table` renderer and
  :meth:`BenchReport.save` / :meth:`BenchReport.load` persistence.
* :func:`compare` / :func:`compare_table` - current-vs-baseline regression
  comparison with a generous default tolerance (CI machines vary) and
  verdicts that never raise on missing entries.

The module is pure standard library (Python 3.9+) and deliberately
side-effect free: it writes nothing, touches no configuration and never
imports :mod:`obscuralens`.
"""

import json
import math
import platform
import statistics
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union

# --- public constants -------------------------------------------------------

#: Report schema tag written into every saved JSON document.
REPORT_SCHEMA = 'obscuralens-benchmarks/1'

#: Quick mode divides ``repeat`` and ``number`` by this factor (floored at 1)
#: so a CI run costs a fraction of a full run.
QUICK_SCALE = 5

#: Default repeat count for :func:`measure` (samples per benchmark).
DEFAULT_REPEAT = 5

#: Default calls per sample for :func:`measure`.
DEFAULT_NUMBER = 1

#: Default warmup calls before timing starts (absorbs lazy imports and
#: first-touch caches so samples measure steady-state cost).
DEFAULT_WARMUP = 1

#: Default regression tolerance for :func:`compare` (35%).  CI hardware
#: varies far more than that between runners; anything inside the band is
#: "stable", not "slower".
DEFAULT_TOLERANCE = 0.35

Verdict = str


# --- percentile helpers -----------------------------------------------------

def percentile(values: Sequence[float], q: float) -> float:
    """
    Percentile through sorted-index linear interpolation.

    Hand-rolled instead of :func:`statistics.quantiles` because the stdlib
    helper only produces fixed quantile sets (``n`` equal chunks) and its
    "exclusive"/"inclusive" methods disagree with the numpy-style
    interpolation analysts expect.  This implementation matches
    ``numpy.percentile``'s default ``linear`` method: position
    ``(n - 1) * q`` interpolated between the two neighbouring order
    statistics.

    Args:
        values: any numeric sequence (unsorted is fine; empty is allowed).
        q: quantile in [0, 1] (0.95 for a p95).

    Returns:
        The interpolated percentile; ``0.0`` for an empty sequence.

    Example:
        >>> percentile([1, 2, 3, 4], 0.95)
        3.85
        >>> percentile([5], 0.5)
        5.0
    """
    if not values:
        return 0.0
    ordered = sorted(float(v) for v in values)
    if len(ordered) == 1:
        return ordered[0]
    q = min(max(float(q), 0.0), 1.0)
    pos = (len(ordered) - 1) * q
    low = math.floor(pos)
    high = math.ceil(pos)
    if low == high:
        return ordered[int(pos)]
    weight = pos - low
    return ordered[low] + (ordered[high] - ordered[low]) * weight


# --- timing primitives ------------------------------------------------------

class Timer:
    """
    ``time.perf_counter`` stopwatch as a context manager.

    Example:
        >>> with Timer() as timer:
        ...     _ = sum(range(1000))
        >>> timer.elapsed >= 0
        True
    """

    def __init__(self) -> None:
        self.elapsed: float = 0.0
        self._start: float = 0.0

    def __enter__(self) -> 'Timer':
        self._start = time.perf_counter()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        self.elapsed = time.perf_counter() - self._start
        return False


@dataclass
class Timing:
    """
    Statistical summary of one benchmark's timing samples.

    Every duration field is *seconds per single call*: each of the
    ``repeat`` samples times ``number`` consecutive calls and is divided by
    ``number``, so the statistics describe individual invocations regardless
    of how calls were batched.
    """

    #: Benchmark name (unique within a suite run).
    name: str
    #: Samples actually taken (after quick-mode reduction).
    repeat: int
    #: Calls per sample.
    number: int
    #: ``repeat * number`` total invocations.
    total_calls: int
    #: Fastest observed per-call time, seconds.
    min_s: float
    #: Arithmetic mean per-call time, seconds.
    mean_s: float
    #: Median per-call time, seconds.
    median_s: float
    #: 95th percentile per-call time (linear interpolation), seconds.
    p95_s: float
    #: Sample standard deviation of the per-call times, seconds
    #: (0.0 when fewer than two samples).
    stdev_s: float
    #: Throughput from the mean: ``1 / mean_s`` (0.0 when unmeasurable).
    ops_per_sec: float
    #: Raw per-call samples, seconds (one entry per repeat).
    samples: List[float] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe plain-dict view of this record."""
        return {
            'name': self.name,
            'repeat': self.repeat,
            'number': self.number,
            'total_calls': self.total_calls,
            'min_s': self.min_s,
            'mean_s': self.mean_s,
            'median_s': self.median_s,
            'p95_s': self.p95_s,
            'stdev_s': self.stdev_s,
            'ops_per_sec': self.ops_per_sec,
            'samples': list(self.samples),
        }

    @classmethod
    def from_dict(cls, data: Any) -> 'Timing':
        """Rebuild a :class:`Timing` from :meth:`to_dict` output."""
        payload = data if isinstance(data, dict) else {}
        samples = payload.get('samples') or []
        return cls(
            name=str(payload.get('name', '')),
            repeat=int(payload.get('repeat', 0)),
            number=int(payload.get('number', 0)),
            total_calls=int(payload.get('total_calls', 0)),
            min_s=float(payload.get('min_s', 0.0)),
            mean_s=float(payload.get('mean_s', 0.0)),
            median_s=float(payload.get('median_s', 0.0)),
            p95_s=float(payload.get('p95_s', 0.0)),
            stdev_s=float(payload.get('stdev_s', 0.0)),
            ops_per_sec=float(payload.get('ops_per_sec', 0.0)),
            samples=[float(s) for s in samples],
        )


def measure(fn: Callable[[], Any], *, name: str = 'bench',
            repeat: int = DEFAULT_REPEAT, number: int = DEFAULT_NUMBER,
            warmup: int = DEFAULT_WARMUP) -> Timing:
    """
    Time one callable with ``time.perf_counter``.

    ``warmup`` unmeasured calls run first so lazy imports and first-touch
    caches (the data catalog, the analytics modules, the MCP registry) are
    absorbed before sampling.  Each of the ``repeat`` samples then times
    ``number`` back-to-back calls and is normalised to a per-call duration.

    Args:
        fn: zero-argument callable to time.
        name: benchmark name stamped onto the :class:`Timing`.
        repeat: number of samples.
        number: calls per sample.
        warmup: unmeasured calls before sampling.

    Returns:
        The :class:`Timing` summary; never raises for slow functions, only
        for a raising ``fn`` (the suite catches that).
    """
    for _ in range(max(0, int(warmup))):
        fn()
    repeat = max(1, int(repeat))
    number = max(1, int(number))
    samples: List[float] = []
    for _ in range(repeat):
        start = time.perf_counter()
        for _ in range(number):
            fn()
        samples.append((time.perf_counter() - start) / number)
    mean_s = statistics.fmean(samples) if samples else 0.0
    stdev_s = statistics.stdev(samples) if len(samples) > 1 else 0.0
    return Timing(
        name=name,
        repeat=repeat,
        number=number,
        total_calls=repeat * number,
        min_s=min(samples) if samples else 0.0,
        mean_s=mean_s,
        median_s=statistics.median(samples) if samples else 0.0,
        p95_s=percentile(samples, 0.95),
        stdev_s=stdev_s,
        ops_per_sec=(1.0 / mean_s) if mean_s > 0 else 0.0,
        samples=samples,
    )


# --- suite registration glue ------------------------------------------------

@dataclass
class BenchSpec:
    """
    One registered benchmark: name, callable and execution knobs.

    ``setup`` runs immediately before the timing loop and ``teardown``
    immediately after (even when the benchmark raises); stateful benches
    use them to prepare isolated on-disk state and restore patched globals.
    """

    name: str
    fn: Callable[[], Any]
    repeat: int = DEFAULT_REPEAT
    number: int = DEFAULT_NUMBER
    tags: Tuple[str, ...] = ('core',)
    setup: Optional[Callable[[], Any]] = None
    teardown: Optional[Callable[[], Any]] = None
    warmup: int = DEFAULT_WARMUP


def state_dir(workdir: Optional[Union[str, Path]],
              name: str) -> Tuple[Path, Optional[Callable[[], None]]]:
    """
    Resolve a per-benchmark state directory under ``workdir``.

    Hermetic-state glue for the benches that need on-disk state (the SQLite
    cache and history databases): when the caller supplies a workdir the
    state lives in a named subdirectory of it and the caller owns the
    cleanup (no callback returned); when ``workdir`` is None a fresh
    temporary directory is created and a cleanup callback is returned so
    the bench can remove it in its teardown ``finally``.

    Args:
        workdir: caller-owned directory, or None for an self-managed tempdir.
        name: subdirectory name, e.g. ``'cache'`` or ``'database'``.

    Returns:
        ``(path, cleanup)`` where ``cleanup`` is None when the caller owns
        the directory.
    """
    if workdir is not None:
        path = Path(workdir) / name
        path.mkdir(parents=True, exist_ok=True)
        return path, None
    tmp = tempfile.TemporaryDirectory(prefix=f'obscuralens-bench-{name}-')
    return Path(tmp.name), tmp.cleanup


# --- suite ------------------------------------------------------------------

@dataclass
class BenchReport:
    """
    Result of one :meth:`BenchSuite.run`.

    Carries the per-benchmark :class:`Timing` records plus the run's
    metadata (quick mode flag, wall time, interpreter) and any benchmark
    that raised (name + error text; the suite continues past failures).
    """

    #: Successful benchmark timings, in registration order.
    results: List[Timing] = field(default_factory=list)
    #: Failures: ``{'name', 'error'}`` per raising benchmark.
    errors: List[Dict[str, str]] = field(default_factory=list)
    #: Whether the run used quick-mode work reduction.
    quick: bool = False
    #: Wall-clock seconds of the measured portion of the run.
    total_seconds: float = 0.0
    #: ISO timestamp of when the run finished.
    created: str = ''

    # -- views --------------------------------------------------------------

    def names(self) -> List[str]:
        """Benchmark names in registration order (successful ones only)."""
        return [timing.name for timing in self.results]

    def ops(self) -> Dict[str, float]:
        """Mapping of benchmark name to ops-per-second."""
        return {timing.name: timing.ops_per_sec for timing in self.results}

    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe representation (round-trips through :meth:`from_dict`)."""
        return {
            'schema': REPORT_SCHEMA,
            'created': self.created,
            'quick': self.quick,
            'total_seconds': self.total_seconds,
            'total_benches': len(self.results),
            'total_errors': len(self.errors),
            'python': platform.python_version(),
            'platform': platform.platform(),
            'machine': platform.machine(),
            'results': [timing.to_dict() for timing in self.results],
            'errors': [dict(entry) for entry in self.errors],
        }

    @classmethod
    def from_dict(cls, data: Any) -> 'BenchReport':
        """Rebuild a report from :meth:`to_dict` output (tolerant of junk)."""
        payload = data if isinstance(data, dict) else {}
        raw_results = payload.get('results') or []
        raw_errors = payload.get('errors') or []
        return cls(
            results=[Timing.from_dict(item) for item in raw_results
                     if isinstance(item, dict)],
            errors=[dict(item) for item in raw_errors if isinstance(item, dict)],
            quick=bool(payload.get('quick', False)),
            total_seconds=float(payload.get('total_seconds', 0.0) or 0.0),
            created=str(payload.get('created', '')),
        )

    # -- rendering ----------------------------------------------------------

    def to_table(self) -> str:
        """
        Aligned text table: name, ops/sec, min/median/p95 in milliseconds.

        Example:
            >>> report = BenchReport(results=[Timing('demo', 1, 1, 1,
            ...     0.001, 0.001, 0.001, 0.001, 0.0, 1000.0, [0.001])])
            >>> 'demo' in report.to_table() and 'ops/sec' in report.to_table()
            True
        """
        header = f"{'benchmark':<40} {'ops/sec':>12} {'min (ms)':>10} " \
                 f"{'median (ms)':>12} {'p95 (ms)':>10}"
        lines = [header, '-' * len(header)]
        for timing in self.results:
            lines.append(
                f"{timing.name:<40} {timing.ops_per_sec:>12,.0f} "
                f"{timing.min_s * 1000:>10.3f} {timing.median_s * 1000:>12.3f} "
                f"{timing.p95_s * 1000:>10.3f}")
        for entry in self.errors:
            lines.append(f"{entry.get('name', '?'):<40} {'ERROR':>12}")
        if not self.results and not self.errors:
            lines.append('(no benchmarks ran)')
        return '\n'.join(lines)

    def summary(self) -> str:
        """
        Human one-glance summary: totals plus slowest and fastest benches.
        """
        if not self.results:
            return 'no benchmarks ran'
        slowest = min(self.results, key=lambda t: t.ops_per_sec)
        fastest = max(self.results, key=lambda t: t.ops_per_sec)
        mode = ' (quick mode)' if self.quick else ''
        lines = [
            f'benchmarks: {len(self.results)}{mode}',
            f'errors: {len(self.errors)}',
            f'total measured time: {self.total_seconds:.2f} s',
            f"slowest: {slowest.name} ({slowest.median_s * 1000:.3f} ms/call)",
            f"fastest: {fastest.name} ({fastest.median_s * 1000:.3f} ms/call)",
        ]
        return '\n'.join(lines)

    # -- persistence --------------------------------------------------------

    def save(self, path: Union[str, Path]) -> Path:
        """
        Write the report as indented JSON, creating parent directories.

        Args:
            path: destination file path.

        Returns:
            The resolved path written.
        """
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2) + '\n',
                          encoding='utf-8')
        return target

    @classmethod
    def load(cls, path: Union[str, Path]) -> 'BenchReport':
        """
        Load a report previously written by :meth:`save`.

        Raises:
            OSError: when the file cannot be read.
            ValueError: when the content is not valid JSON.
        """
        data = json.loads(Path(path).read_text(encoding='utf-8'))
        return cls.from_dict(data)


class BenchSuite:
    """
    An ordered registry of benchmarks plus filtered execution.

    Example:
        >>> suite = BenchSuite()
        >>> _ = suite.register('add', lambda: 1 + 1, number=10)
        >>> report = suite.run()
        >>> report.names()
        ['add']
    """

    def __init__(self) -> None:
        self._benches: List[Dict[str, Any]] = []

    # -- registration -------------------------------------------------------

    def register(self, name: str, fn: Callable[[], Any], *,
                 repeat: int = DEFAULT_REPEAT, number: int = DEFAULT_NUMBER,
                 tags: Iterable[str] = (), setup: Optional[Callable[[], Any]] = None,
                 teardown: Optional[Callable[[], Any]] = None,
                 warmup: int = DEFAULT_WARMUP) -> None:
        """
        Add one benchmark.

        Args:
            name: unique benchmark name (later duplicates are ignored).
            fn: zero-argument callable to measure.
            repeat: samples to take.
            number: calls per sample.
            tags: labels for the ``--tags`` filter (e.g. ``('core',)``).
            setup: optional pre-run hook (state preparation).
            teardown: optional post-run hook (state restore), always run.
            warmup: unmeasured calls before sampling.
        """
        if any(entry['name'] == name for entry in self._benches):
            return
        self._benches.append({
            'name': name,
            'fn': fn,
            'repeat': repeat,
            'number': number,
            'tags': tuple(tags),
            'setup': setup,
            'teardown': teardown,
            'warmup': warmup,
        })

    def add_spec(self, spec: BenchSpec) -> None:
        """Register a :class:`BenchSpec` (the form the bench modules build)."""
        self.register(spec.name, spec.fn, repeat=spec.repeat, number=spec.number,
                      tags=spec.tags, setup=spec.setup, teardown=spec.teardown,
                      warmup=spec.warmup)

    def registered(self) -> List[Dict[str, Any]]:
        """A copy of the registry: ``name``/``tags`` per benchmark."""
        return [{'name': entry['name'], 'tags': entry['tags']}
                for entry in self._benches]

    # -- execution ----------------------------------------------------------

    def _match(self, entry: Dict[str, Any], only: Optional[Sequence[str]],
               tags: Optional[Sequence[str]]) -> bool:
        name_ok = not only or any(needle in entry['name'] for needle in only)
        tag_ok = not tags or any(tag in entry['tags'] for tag in tags)
        return name_ok and tag_ok

    def run(self, only: Optional[Sequence[str]] = None,
            tags: Optional[Sequence[str]] = None,
            quick: bool = False) -> BenchReport:
        """
        Execute the matching benchmarks and collect a :class:`BenchReport`.

        Quick mode divides ``repeat`` and ``number`` by
        :data:`QUICK_SCALE` (floored at 1) so the whole suite costs a
        fraction of a full run; warmup calls are unaffected.  A benchmark
        whose function, setup or teardown raises is recorded in the
        report's ``errors`` list and execution continues.

        Args:
            only: substring filters - keep benchmarks whose name contains
                any of these strings.
            tags: tag filters - keep benchmarks carrying any of these tags.
            quick: reduce per-benchmark work for CI runs.

        Returns:
            The finished :class:`BenchReport`.
        """
        report = BenchReport(quick=quick)
        started = time.perf_counter()
        for entry in self._benches:
            if not self._match(entry, only, tags):
                continue
            repeat = entry['repeat']
            number = entry['number']
            if quick:
                repeat = max(1, repeat // QUICK_SCALE)
                number = max(1, number // QUICK_SCALE)
            setup, teardown = entry['setup'], entry['teardown']
            try:
                if setup is not None:
                    setup()
                timing = measure(entry['fn'], name=entry['name'], repeat=repeat,
                                 number=number, warmup=entry['warmup'])
                report.results.append(timing)
            except Exception as exc:  # noqa: BLE001 - record, keep running
                report.errors.append({'name': entry['name'],
                                      'error': f'{type(exc).__name__}: {exc}'})
            finally:
                if teardown is not None:
                    try:
                        teardown()
                    except Exception as exc:  # noqa: BLE001
                        report.errors.append({
                            'name': entry['name'],
                            'error': f'teardown failed: {type(exc).__name__}: {exc}'})
        report.total_seconds = time.perf_counter() - started
        report.created = time.strftime('%Y-%m-%dT%H:%M:%S')
        return report


# --- regression comparison --------------------------------------------------

@dataclass
class CompareRow:
    """
    One current-vs-baseline comparison verdict.

    ``current_ops``/``baseline_ops`` are None for 'new'/'missing' rows;
    ``ratio`` is ``current / baseline`` (None when either side is missing).
    """

    name: str
    current_ops: Optional[float]
    baseline_ops: Optional[float]
    ratio: Optional[float]
    verdict: Verdict


def _baseline_ops(baseline: Any) -> Dict[str, float]:
    """
    Extract ``name -> ops_per_sec`` from a baseline document.

    Accepts the full saved-report shape (``{'results': [...]}``) or a bare
    ``{'name': ops}`` mapping, which keeps hand-crafted baselines in tests
    and ad-hoc scripts working.
    """
    if not isinstance(baseline, dict):
        return {}
    results = baseline.get('results')
    if isinstance(results, list):
        ops: Dict[str, float] = {}
        for entry in results:
            if isinstance(entry, dict) and 'name' in entry:
                try:
                    ops[str(entry['name'])] = float(entry.get('ops_per_sec', 0.0))
                except (TypeError, ValueError):
                    ops[str(entry['name'])] = 0.0
        return ops
    if results is None and all(isinstance(v, (int, float)) for v in baseline.values()):
        return {str(k): float(v) for k, v in baseline.items()}
    return {}


def compare(current: BenchReport, baseline: Any,
            tolerance: float = DEFAULT_TOLERANCE) -> List[CompareRow]:
    """
    Compare a fresh report against a baseline document.

    Verdict rules (documented, generous by design):

    * ``'slower'`` - throughput dropped by more than ``tolerance``
      (``ratio < 1 - tolerance``); the default 35% band absorbs CI runner
      variance, so only real regressions are flagged.
    * ``'faster'`` - throughput improved by more than ``tolerance``.
    * ``'stable'`` - inside the band (including noise).
    * ``'new'`` - the benchmark is absent from the baseline.
    * ``'missing'`` - the baseline entry did not run this time.

    Missing baseline entries never raise - they are simply 'new'.

    Args:
        current: the just-measured report.
        baseline: loaded baseline JSON (full report dict or a bare
            ``{'name': ops}`` mapping).
        tolerance: relative band for 'stable', as a fraction.

    Returns:
        :class:`CompareRow` list: current-run benches first (registration
        order), then baseline-only entries as 'missing'.
    """
    base = _baseline_ops(baseline)
    rows: List[CompareRow] = []
    current_ops = current.ops()
    for name, ops in current_ops.items():
        if name not in base:
            rows.append(CompareRow(name, ops, None, None, 'new'))
            continue
        base_ops = base[name]
        ratio = (ops / base_ops) if base_ops > 0 else None
        if ratio is None:
            verdict: Verdict = 'stable' if ops == 0 else 'faster'
        elif ratio < 1.0 - tolerance:
            verdict = 'slower'
        elif ratio > 1.0 + tolerance:
            verdict = 'faster'
        else:
            verdict = 'stable'
        rows.append(CompareRow(name, ops, base_ops, ratio, verdict))
    for name, base_ops in base.items():
        if name not in current_ops:
            rows.append(CompareRow(name, None, base_ops, None, 'missing'))
    return rows


def compare_table(rows: Sequence[CompareRow]) -> str:
    """
    Render :func:`compare` rows as an aligned text table.

    Columns: benchmark, current ops/sec, baseline ops/sec, ratio, verdict.
    """
    header = (f"{'benchmark':<40} {'current':>12} {'baseline':>12} "
              f"{'ratio':>7} {'verdict':>8}")
    lines = [header, '-' * len(header)]
    for row in rows:
        current = f'{row.current_ops:,.0f}' if row.current_ops is not None else '-'
        base = f'{row.baseline_ops:,.0f}' if row.baseline_ops is not None else '-'
        ratio = f'{row.ratio:.2f}x' if row.ratio is not None else '-'
        lines.append(f'{row.name:<40} {current:>12} {base:>12} '
                     f'{ratio:>7} {row.verdict:>8}')
    if not rows:
        lines.append('(nothing to compare)')
    return '\n'.join(lines)


__all__ = [
    'BenchReport',
    'BenchSpec',
    'BenchSuite',
    'CompareRow',
    'DEFAULT_NUMBER',
    'DEFAULT_REPEAT',
    'DEFAULT_TOLERANCE',
    'DEFAULT_WARMUP',
    'QUICK_SCALE',
    'REPORT_SCHEMA',
    'Timer',
    'Timing',
    'compare',
    'compare_table',
    'measure',
    'percentile',
    'state_dir',
]

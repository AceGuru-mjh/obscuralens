"""
InvestigationSession — a fluent, receipt-keeping investigation wrapper.

The synchronous client is a thin endpoint mapper; real OSINT work is a
*sequence* of steps — look up the IP, pivot to the domain, score the
risk, jot a note, export the evidence — and the interesting artefact is
the **trail**, not any single response. :class:`InvestigationSession`
wraps an :class:`~obscuralens.sdk.client.ObscuraLensClient` and records
every step it performs so the analyst can replay, summarise and file
the whole investigation at the end::

    from obscuralens.sdk import ObscuraLensClient, InvestigationSession

    with ObscuraLensClient() as client, \\
            InvestigationSession(client, label='phishing-2024') as session:
        session.lookup('ip', '1.2.3.4')            # records a step
        session.investigate('evil.example.com')    # records a step
        session.risk('domain', 'evil.example.com')
        session.note('victim reported 2024-05-01')
        session.to_case('Phishing case')            # case + items via API
        session.export_stix('domain', 'evil.example.com')
        session.timeline()
        print(session.summary())                    # multi-step report
        session.dump('session.json')                # JSON receipt

Design notes:

* **Composition over HTTP** — the session never touches a transport; it
  only calls public client methods, so a
  :class:`~obscuralens.sdk.transport.StaticTransport` under the client
  makes the whole session testable offline.
* **Errors are data** — a failing step records the exception (type and
  message) and the investigation *continues*; ``strict=True`` flips the
  behaviour to raise instead, for pipelines that want fail-fast.
* **Receipts are portable** — :meth:`InvestigationSession.dump` writes a
  plain-JSON receipt and :meth:`InvestigationSession.load` rebuilds a
  session from it *without a client* (an audit artefact, not a live
  handle).
"""

import json as _json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Union

__all__ = ['InvestigationSession', 'SessionStep']

#: Receipt format written by :meth:`InvestigationSession.dump`.
RECEIPT_FORMAT = 'obscuralens-session/1'


@dataclass
class SessionStep:
    """
    One recorded investigation step.

    Attributes:
        method: the session method that ran (``lookup``, ``investigate``,
            ``risk``, ``timeline``, ``intel``, ``dorks``, ``note``,
            ``to_case``, ``export_stix``, ``export_misp``).
        target: the step's target value (case name for ``to_case``,
            ``''`` for notes and parameterless calls).
        ok: True when the step completed without raising.
        error: ``"ExceptionType: message"`` for failed steps, ``''``
            otherwise.
        duration: wall-clock seconds the step took.
        field_count: how many fields/objects/attributes the step's
            result carried (notes and failures carry 0).
        detail: one-line human summary of the result (a note's text, a
            lookup's ``summary()`` line, a case's id...).
        at: ISO timestamp recorded when the step finished.
    """

    method: str = ''
    target: str = ''
    ok: bool = False
    error: str = ''
    duration: float = 0.0
    field_count: int = 0
    detail: str = ''
    at: str = ''
    raw: Dict[str, Any] = field(default_factory=dict)

    # -- serialisation ------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """
        The JSON-ready step record (receipts embed a list of these).

        Example:
            >>> step = SessionStep(method='note', ok=True, detail='hello')
            >>> step.to_dict()['detail']
            'hello'
        """
        return {
            'method': self.method,
            'target': self.target,
            'ok': self.ok,
            'error': self.error,
            'duration': round(float(self.duration), 6),
            'field_count': self.field_count,
            'detail': self.detail,
            'at': self.at,
        }

    @classmethod
    def from_dict(cls, data: Any) -> 'SessionStep':
        """
        Rebuild one step from its receipt record (junk-tolerant).

        Args:
            data: the mapping written by :meth:`to_dict`.

        Returns:
            A populated :class:`SessionStep`; junk input yields defaults
            and never raises.
        """
        payload = data if isinstance(data, dict) else {}
        ok = payload.get('ok')
        duration = payload.get('duration')
        field_count = payload.get('field_count')
        return cls(
            method=str(payload.get('method') or ''),
            target=str(payload.get('target') or ''),
            ok=bool(ok) if ok is not None else False,
            error=str(payload.get('error') or ''),
            duration=float(duration) if isinstance(duration, (int, float))
            else 0.0,
            field_count=int(field_count) if isinstance(field_count, int)
            else 0,
            detail=str(payload.get('detail') or ''),
            at=str(payload.get('at') or ''),
        )

    # -- presentation -------------------------------------------------------

    def headline(self) -> str:
        """
        One-line status: ``"lookup ip 1.2.3.4 — ok (0.4s): ..."``.

        Example:
            >>> SessionStep(method='note', ok=True,
            ...             detail='victim called').headline()
            'note — ok: victim called'
        """
        label = f'{self.method} {self.target}'.strip()
        if self.ok:
            timing = f' ({self.duration:.2f}s)' if self.duration else ''
            fields = f', {self.field_count} field(s)' if self.field_count else ''
            suffix = f': {self.detail}' if self.detail else ''
            return f'{label} — ok{timing}{fields}{suffix}'
        return f'{label} — FAILED: {self.error or "unknown error"}'


class InvestigationSession:
    """
    A guided, step-recording investigation on top of one client.

    Every public step method calls exactly one client method, records a
    :class:`SessionStep` (method, target, ok/error, duration,
    field count, one-line detail) and returns the underlying model so
    callers can keep working with the data. Failures are captured, not
    raised (unless ``strict=True``), and the collected target set feeds
    :meth:`to_case`.

    Args:
        client: the :class:`~obscuralens.sdk.client.ObscuraLensClient`
            to compose over. ``None`` is allowed only for sessions
            rebuilt from receipts (see :meth:`from_dict`) — calling a
            step method on a clientless session raises
            :class:`RuntimeError`.
        label: human label threaded into ``summary()`` and receipts
            (e.g. ``'phishing-2024'``).
        strict: when True, a failing step re-raises after being recorded
            (fail-fast pipelines); the default records and continues.
        clock: monotonic callable used for step durations (injectable
            for tests; default :func:`time.perf_counter`).

    Example:
        >>> client = ObscuraLensClient()                     # doctest: +SKIP
        >>> with InvestigationSession(client, 'demo') as session:
        ...     session.note('first contact')                # doctest: +SKIP
        ...     print(len(session))                          # doctest: +SKIP
        1
    """

    def __init__(self, client: Any = None, label: str = '',
                 strict: bool = False,
                 clock: Callable[[], float] = time.perf_counter) -> None:
        self._client = client
        self.label = str(label or '')
        self.strict = bool(strict)
        self._clock = clock
        self.steps: List[SessionStep] = []
        self.started_at = datetime.now().isoformat(timespec='seconds')
        self.closed = False
        self._targets: Dict[str, None] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def __enter__(self) -> 'InvestigationSession':
        """Enter the context manager (returns self)."""
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        """Exit the context manager, closing the session (not the client)."""
        self.close()

    def close(self) -> None:
        """
        Mark the session closed — further steps raise RuntimeError.

        Read-only helpers (:meth:`summary`, :meth:`to_dict`,
        :meth:`dump`) keep working so the receipt can still be written
        after the ``with`` block. The wrapped client is *not* closed:
        it owns its own lifecycle.
        """
        self.closed = True

    def __repr__(self) -> str:
        """Debug representation with label, step count and failures."""
        state = 'closed' if self.closed else 'open'
        return (f'<InvestigationSession {self.label!r} '
                f'{len(self.steps)} step(s), {self.failed_count} failed, '
                f'{state}>')

    # ------------------------------------------------------------------
    # Guards and step plumbing
    # ------------------------------------------------------------------

    def _require_open(self) -> None:
        """Raise RuntimeError when the session has been closed."""
        if self.closed:
            raise RuntimeError('session is closed — start a new session')

    def _require_client(self) -> Any:
        """Raise RuntimeError when the session has no client attached."""
        if self._client is None:
            raise RuntimeError(
                'session has no client — this handle was rebuilt from a '
                'receipt; construct a fresh session to run steps')
        return self._client

    def _record(self, method: str, target: str, call: Callable[[], Any],
                counter: Callable[[Any], int],
                describe: Callable[[Any], str]) -> Any:
        """
        Run one client call, record the step, return the model.

        Args:
            method: step name recorded on the trail.
            target: target value recorded (and added to the target set).
            call: zero-argument callable performing the client call.
            counter: result -> field/object count for the step record.
            describe: result -> one-line human detail.

        Returns:
            The call's result, or ``None`` when it failed in non-strict
            mode (strict mode re-raises after recording).
        """
        self._require_open()
        self._require_client()
        started = self._clock()
        try:
            result = call()
        except Exception as exc:  # noqa: BLE001 - errors are session data
            duration = self._clock() - started
            error = f'{type(exc).__name__}: {exc}'
            self._append(SessionStep(method=method, target=str(target),
                                     ok=False, error=error,
                                     duration=duration, field_count=0,
                                     detail=''))
            if self.strict:
                raise
            return None
        duration = self._clock() - started
        try:
            field_count = int(counter(result))
        except (TypeError, ValueError):
            field_count = 0
        self._append(SessionStep(method=method, target=str(target), ok=True,
                                 error='', duration=duration,
                                 field_count=field_count,
                                 detail=str(describe(result))))
        return result

    def _append(self, step: SessionStep,
                collect_target: bool = True) -> None:
        """
        Store one step (with its timestamp) and collect its target.

        Args:
            step: the step to record.
            collect_target: add the step's target to the session's
                target set (``to_case`` steps opt out — a case name is
                bookkeeping, not an indicator).
        """
        step.at = datetime.now().isoformat(timespec='seconds')
        self.steps.append(step)
        if collect_target and step.target:
            self._targets.setdefault(step.target, None)

    # ------------------------------------------------------------------
    # Collections
    # ------------------------------------------------------------------

    def targets(self) -> List[str]:
        """
        The deduplicated target set, sorted alphabetically.

        Every step's target is collected — failed lookups included,
        because "we tried this and it failed" is part of the trail.

        Example:
            >>> session = InvestigationSession()
            >>> session.lookup('ip', '8.8.8.8')      # doctest: +SKIP
            >>> session.targets()                     # doctest: +SKIP
            ['8.8.8.8']
        """
        return sorted(self._targets)

    @property
    def notes(self) -> List[str]:
        """The text of every ``note`` step, in order."""
        return [step.detail for step in self.steps if step.method == 'note']

    @property
    def ok_count(self) -> int:
        """How many steps completed successfully."""
        return sum(1 for step in self.steps if step.ok)

    @property
    def failed_count(self) -> int:
        """How many steps failed (recorded errors)."""
        return sum(1 for step in self.steps if not step.ok)

    def __len__(self) -> int:
        """Number of recorded steps."""
        return len(self.steps)

    def __iter__(self) -> Iterator[SessionStep]:
        """Iterate over the recorded steps, oldest first."""
        return iter(list(self.steps))

    def step(self, index: int) -> Optional[SessionStep]:
        """One step by position (0-based), or ``None`` when out of range."""
        if 0 <= index < len(self.steps):
            return self.steps[index]
        return None

    # ------------------------------------------------------------------
    # Steps — lookups and pivots
    # ------------------------------------------------------------------

    def lookup(self, kind: str, target: str) -> Optional[Any]:
        """
        One tracker lookup, recorded as a step.

        Args:
            kind: tracker kind (``ip``, ``domain``, ... — all 20).
            target: the indicator value.

        Returns:
            The :class:`~obscuralens.sdk.models.LookupResult`, or
            ``None`` when the lookup failed in non-strict mode.

        Example:
            >>> session = InvestigationSession(client)      # doctest: +SKIP
            >>> result = session.lookup('ip', '8.8.8.8')    # doctest: +SKIP
            >>> result.get('country')                       # doctest: +SKIP
            'United States'
        """
        client = self._require_client()

        def call() -> Any:
            return client.lookup(kind, target)

        return self._record('lookup', target, call,
                            counter=lambda result: getattr(result,
                                                           'field_count', 0),
                            describe=lambda result: result.summary())

    def investigate(self, target: str, pivot: bool = True) -> Optional[Any]:
        """
        Auto-detect a target and follow bounded pivots, recorded as a step.

        Args:
            target: any supported kind value.
            pivot: follow related lookups (default True).

        Returns:
            The :class:`~obscuralens.sdk.models.InvestigationReport`, or
            ``None`` on failure in non-strict mode.
        """
        client = self._require_client()

        def call() -> Any:
            return client.investigate(target, pivot=pivot)

        return self._record(
            'investigate', target, call,
            counter=lambda result: len(getattr(result, 'entities', []) or []),
            describe=lambda result: result.summary())

    def risk(self, kind: str, target: str) -> Optional[Any]:
        """
        Risk-scored lookup, recorded as a step.

        Args:
            kind: tracker kind.
            target: the indicator value.

        Returns:
            The :class:`~obscuralens.sdk.models.RiskReport`, or ``None``
            on failure in non-strict mode.
        """
        client = self._require_client()

        def call() -> Any:
            return client.risk(kind, target)

        return self._record(
            'risk', target, call,
            counter=lambda result: len(getattr(result, 'signals', []) or []),
            describe=lambda result: f'{result.band} '
                                    f'({getattr(result, "score", 0)}/100)')

    def timeline(self, target: Optional[str] = None,
                 limit: int = 100) -> Optional[Any]:
        """
        History timeline step — the session's own closing summary call.

        Args:
            target: optional substring filter on stored values.
            limit: maximum events kept.

        Returns:
            The :class:`~obscuralens.sdk.models.Timeline`, or ``None``
            on failure in non-strict mode.
        """
        client = self._require_client()

        def call() -> Any:
            return client.timeline(target=target, limit=limit)

        return self._record(
            'timeline', target or '', call,
            counter=lambda result: len(getattr(result, 'events', []) or []),
            describe=lambda result: f'{getattr(result, "count", 0)} event(s)')

    def intel(self, target: str) -> Optional[Any]:
        """
        Threat-intel verdict for an IP, recorded as a step.

        Args:
            target: IPv4/IPv6 address.

        Returns:
            The :class:`~obscuralens.sdk.models.IntelVerdict`, or
            ``None`` on failure in non-strict mode.
        """
        client = self._require_client()

        def call() -> Any:
            return client.intel(target)

        return self._record(
            'intel', target, call,
            counter=lambda result: len(getattr(result, 'feeds', {}) or {}),
            describe=lambda result: result.summary())

    def dorks(self, target: str, kind: Optional[str] = None
              ) -> Optional[Any]:
        """
        Search-dork generation for a target, recorded as a step.

        Args:
            target: the value to build dorks for.
            kind: optional kind override; ``None`` auto-detects.

        Returns:
            The :class:`~obscuralens.sdk.models.DorkReport`, or ``None``
            on failure in non-strict mode.
        """
        client = self._require_client()

        def call() -> Any:
            return client.dorks(target, kind=kind)

        return self._record(
            'dorks', target, call,
            counter=lambda result: getattr(result, 'count', 0),
            describe=lambda result: result.summary())

    # ------------------------------------------------------------------
    # Steps — intelligence sharing
    # ------------------------------------------------------------------

    def export_stix(self, kind: str, target: str) -> Optional[Any]:
        """
        STIX 2.1 bundle export step (run the lookup first, then export).

        Args:
            kind: tracker kind.
            target: the indicator value.

        Returns:
            The :class:`~obscuralens.sdk.models.StixBundle`, or ``None``
            on failure in non-strict mode.
        """
        client = self._require_client()

        def call() -> Any:
            return client.export_stix(kind, target)

        return self._record(
            'export_stix', target, call,
            counter=lambda result: len(getattr(result, 'objects', []) or []),
            describe=lambda result: result.summary())

    def export_misp(self, kind: str, target: str) -> Optional[Any]:
        """
        MISP core-format event export step.

        Args:
            kind: tracker kind.
            target: the indicator value.

        Returns:
            The :class:`~obscuralens.sdk.models.MispEvent`, or ``None``
            on failure in non-strict mode.
        """
        client = self._require_client()

        def call() -> Any:
            return client.export_misp(kind, target)

        return self._record(
            'export_misp', target, call,
            counter=lambda result: getattr(result, 'attribute_count',
                                           lambda: 0)(),
            describe=lambda result: result.summary())

    # ------------------------------------------------------------------
    # Steps — analyst bookkeeping
    # ------------------------------------------------------------------

    def note(self, text: str) -> SessionStep:
        """
        Record a free-form analyst note as a step (no API call).

        Args:
            text: the note text (blank notes are still recorded).

        Returns:
            The recorded :class:`SessionStep`.

        Example:
            >>> session = InvestigationSession()
            >>> session.note('victim reported 2024-05-01').detail
            'victim reported 2024-05-01'
        """
        self._require_open()
        step = SessionStep(method='note', target='', ok=True, error='',
                           duration=0.0, field_count=0,
                           detail=str(text or ''))
        self._append(step)
        return step

    def to_case(self, name: str, description: str = '') -> Optional[Any]:
        """
        File the investigation: create a case, add every collected target.

        Creates the case via ``POST /api/cases`` then adds each target
        from :meth:`targets` via ``POST /api/cases/{id}/items`` with
        ``kind='auto'``. A failing case creation records a failed step;
        individual add failures are collected into the step's error
        without aborting the other adds.

        Args:
            name: case name (non-empty).
            description: free-form case description.

        Returns:
            The created :class:`~obscuralens.sdk.models.Case`, or
            ``None`` when creation failed in non-strict mode.
        """
        self._require_open()
        client = self._require_client()
        targets = sorted(self._targets)
        started = self._clock()
        try:
            case = client.create_case(name, description)
        except Exception as exc:  # noqa: BLE001 - errors are session data
            duration = self._clock() - started
            error = f'{type(exc).__name__}: {exc}'
            self._append(SessionStep(method='to_case', target=str(name),
                                     ok=False, error=error,
                                     duration=duration, field_count=0,
                                     detail=''), collect_target=False)
            if self.strict:
                raise
            return None
        failures: List[str] = []
        for target in targets:
            try:
                client.add_case_item(case.id, target, kind='auto')
            except Exception as exc:  # noqa: BLE001 - keep adding the rest
                failures.append(f'{target}: {type(exc).__name__}: {exc}')
        duration = self._clock() - started
        error = '; '.join(failures)
        detail = f'#{case.id} {case.title}: {len(targets)} item(s)'
        self._append(SessionStep(method='to_case', target=str(name),
                                 ok=not failures, error=error,
                                 duration=duration,
                                 field_count=len(targets), detail=detail),
                     collect_target=False)
        if failures and self.strict:
            raise RuntimeError(f'case item failures: {error}')
        return case

    # ------------------------------------------------------------------
    # Reporting and receipts
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """
        The human-readable multi-step investigation report.

        Returns:
            A header line (label, step tally, target count), one line
            per step (index, headline) and a trailing target list. Empty
            sessions report ``0 step(s)`` with no step lines.

        Example:
            >>> session = InvestigationSession(label='demo')
            >>> session.note('hello')  # doctest: +ELLIPSIS
            SessionStep(...)
            >>> 'demo' in session.summary()
            True
        """
        header = (f'{self.label or "session"} — {len(self.steps)} step(s): '
                  f'{self.ok_count} ok, {self.failed_count} failed, '
                  f'{len(self._targets)} target(s)')
        lines = [header]
        for index, step in enumerate(self.steps, start=1):
            lines.append(f'  [{index}] {step.headline()}')
        if self._targets:
            lines.append(f'targets ({len(self._targets)}): '
                         f'{", ".join(sorted(self._targets))}')
        return '\n'.join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """
        The JSON-ready session receipt.

        Returns:
            ``{'format': 'obscuralens-session/1', 'label': ...,
            'strict': ..., 'started_at': ..., 'step_count': n,
            'steps': [...], 'targets': [...]}``.

        Example:
            >>> InvestigationSession(label='x').to_dict()['step_count']
            0
        """
        return {
            'format': RECEIPT_FORMAT,
            'label': self.label,
            'strict': self.strict,
            'started_at': self.started_at,
            'step_count': len(self.steps),
            'steps': [step.to_dict() for step in self.steps],
            'targets': sorted(self._targets),
        }

    @classmethod
    def from_dict(cls, data: Any,
                  client: Any = None) -> 'InvestigationSession':
        """
        Rebuild a session from a receipt (no client required).

        Args:
            data: the mapping written by :meth:`to_dict` (junk input
                yields an empty session and never raises).
            client: optional client to attach — without one the session
                is a read-only audit artefact and step methods raise
                :class:`RuntimeError`.

        Returns:
            A populated :class:`InvestigationSession`.

        Example:
            >>> receipt = {'label': 'demo', 'steps': [
            ...     {'method': 'note', 'ok': True, 'detail': 'hi'}]}
            >>> session = InvestigationSession.from_dict(receipt)
            >>> session.notes
            ['hi']
        """
        payload = data if isinstance(data, dict) else {}
        strict = payload.get('strict')
        session = cls(client=client,
                      label=str(payload.get('label') or ''),
                      strict=bool(strict) if strict is not None else False)
        started = str(payload.get('started_at') or '')
        if started:
            session.started_at = started
        for item in payload.get('steps') or []:
            if isinstance(item, dict):
                session.steps.append(SessionStep.from_dict(item))
        for target in payload.get('targets') or []:
            if target:
                session._targets.setdefault(str(target), None)
        return session

    def dump(self, path: Union[str, Path]) -> Path:
        """
        Write the JSON receipt to disk.

        Args:
            path: destination file path.

        Returns:
            The :class:`~pathlib.Path` written to (parent directories
            are not created — a missing parent raises ``OSError``).

        Example:
            >>> session = InvestigationSession(label='demo')
            >>> session.dump('receipt.json').name   # doctest: +SKIP
            'receipt.json'
        """
        destination = Path(path)
        destination.write_text(
            _json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding='utf-8')
        return destination

    @classmethod
    def load(cls, path: Union[str, Path],
             client: Any = None) -> 'InvestigationSession':
        """
        Load a session from a JSON receipt file.

        Args:
            path: receipt file written by :meth:`dump`.
            client: optional client to re-attach for further steps.

        Returns:
            A populated :class:`InvestigationSession`.

        Raises:
            OSError: the file cannot be read.
            ValueError: the file is not valid JSON.
        """
        receipt = _json.loads(Path(path).read_text(encoding='utf-8'))
        return cls.from_dict(receipt, client=client)

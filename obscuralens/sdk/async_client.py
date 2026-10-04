"""
AsyncObscuraLensClient — the asyncio face of the ObscuraLens SDK.

A thin, stdlib-only wrapper that runs the synchronous
:class:`~obscuralens.sdk.client.ObscuraLensClient` methods in a dedicated
thread pool via ``loop.run_in_executor`` (Python 3.9-safe — the running
loop is captured inside each coroutine, and a private
``ThreadPoolExecutor`` is used so ``aclose()`` can shut it down
deterministically). No third-party event-loop or HTTP libraries are
imported.

The async surface mirrors the sync client: every lookup kind (the 20
kinds including the six v6.0 sensors), investigations, risk, timelines,
correlation, stats, sources and the liveness probe — plus the v6.0
coverage: the dork builder, the nine analytics endpoints, notification
channels and broadcasts, the automation scheduler, the STIX/MISP
exports and the live-stream topic declaration. Anything missing can
still be awaited through the escape hatch::

    result = await async_client._run(sync_client.ip, "8.8.8.8")

or simply called through the wrapped sync client at
``async_client._client``.

Example:
    >>> import asyncio
    >>> from obscuralens.sdk import AsyncObscuraLensClient
    >>> async def main():
    ...     async with AsyncObscuraLensClient() as client:
    ...         result = await client.ip("8.8.8.8")      # doctest: +SKIP
    ...         ok = await client.ping()
    ...         return result.summary(), ok
    >>> asyncio.run(main())                               # doctest: +SKIP
    ('ip 8.8.8.8: 14 field(s) from 5 source(s), 1 failed', True)
"""

import asyncio
import concurrent.futures
import functools
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from .client import DEFAULT_BACKOFF, DEFAULT_BASE_URL, DEFAULT_RETRIES, DEFAULT_TIMEOUT, ObscuraLensClient
from .models import (
    AnalyticsEnvelope,
    AutomationTasks,
    AutomationTaskView,
    CorrelationResult,
    DorkReport,
    HistoryResult,
    IntelVerdict,
    InvestigationReport,
    KindInfo,
    LookupResult,
    MispEvent,
    NotifyChannel,
    NotifyChannels,
    NotifyDelivery,
    PairComparison,
    RiskReport,
    SourceHealthEntry,
    StatsSummary,
    StixBundle,
    Timeline,
)
from .transport import Transport

__all__ = ['AsyncObscuraLensClient']

#: Default worker threads for the internal executor.
DEFAULT_MAX_WORKERS = 8


class AsyncObscuraLensClient:
    """
    Asynchronous client for the ObscuraLens REST API.

    Every method is a coroutine that delegates to a
    :class:`~obscuralens.sdk.client.ObscuraLensClient` running in a
    private thread pool — safe to use from a single event loop with many
    concurrent coroutines (lookups run in parallel up to
    ``max_workers``).

    Args:
        base_url: scheme + host + port of the server (default
            ``http://127.0.0.1:8000``).
        api_key: optional ``X-API-Key`` session key (see the sync client).
        timeout: per-request timeout in seconds.
        retries: maximum total attempts per request (including the first).
        backoff: base retry backoff in seconds.
        transport: optional custom :class:`~obscuralens.sdk.transport.Transport`
            (a :class:`~obscuralens.sdk.transport.StaticTransport` makes the
            async client fully testable offline).
        verify_ssl: forwarded to the default transport.
        executor: an existing ``concurrent.futures.Executor`` to submit
            calls to; when omitted a private ``ThreadPoolExecutor`` is
            created and owned by this client.
        max_workers: worker threads for the private executor (ignored when
            ``executor`` is given).

    Raises:
        ValueError: invalid ``base_url`` (from the sync constructor).

    Example:
        >>> client = AsyncObscuraLensClient("http://127.0.0.1:8000")
        >>> result = await client.ip("8.8.8.8")   # doctest: +SKIP
    """

    def __init__(self, base_url: str = DEFAULT_BASE_URL,
                 api_key: Optional[str] = None,
                 timeout: float = DEFAULT_TIMEOUT,
                 retries: int = DEFAULT_RETRIES,
                 backoff: float = DEFAULT_BACKOFF,
                 transport: Optional[Transport] = None,
                 verify_ssl: bool = True,
                 executor: Optional[concurrent.futures.Executor] = None,
                 max_workers: int = DEFAULT_MAX_WORKERS) -> None:
        self._client = ObscuraLensClient(
            base_url=base_url, api_key=api_key, timeout=timeout,
            retries=retries, backoff=backoff, transport=transport,
            verify_ssl=verify_ssl)
        self._owns_executor = executor is None
        self._executor = executor if executor is not None else \
            concurrent.futures.ThreadPoolExecutor(
                max_workers=max(1, int(max_workers)),
                thread_name_prefix='obscuralens-sdk')

    # ------------------------------------------------------------------
    # Plumbing
    # ------------------------------------------------------------------

    async def _run(self, fn: Callable[..., Any], *args: Any,
                   **kwargs: Any) -> Any:
        """
        Run one sync client call in the executor and await it.

        Args:
            fn: the callable to run (usually a bound sync-client method).
            args: positional arguments for ``fn``.
            kwargs: keyword arguments for ``fn``.

        Returns:
            Whatever ``fn`` returns.

        Raises:
            Whatever ``fn`` raises (:class:`~obscuralens.sdk.exceptions.SdkError`
            subclasses surface unchanged).

        Example:
            >>> async_client = AsyncObscuraLensClient()
            >>> res = await async_client._run(          # doctest: +SKIP
            ...     async_client._client.domain, "example.com")
        """
        loop = asyncio.get_running_loop()
        call = functools.partial(fn, *args, **kwargs)
        return await loop.run_in_executor(self._executor, call)

    @property
    def sync_client(self) -> ObscuraLensClient:
        """The wrapped synchronous client (call directly for rare endpoints)."""
        return self._client

    async def __aenter__(self) -> 'AsyncObscuraLensClient':
        """Enter the async context manager (returns self)."""
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        """Exit the async context manager, closing client and executor."""
        await self.aclose()

    async def aclose(self) -> None:
        """
        Close the wrapped sync client and (when owned) the executor.

        Idempotent; in-flight submissions are awaited first because the
        executor shuts down with ``wait=True``.

        Example:
            >>> client = AsyncObscuraLensClient()
            >>> await client.aclose()   # doctest: +SKIP
        """
        self._client.close()
        if self._owns_executor and self._executor is not None:
            self._executor.shutdown(wait=True)

    def __repr__(self) -> str:
        """Debug representation with base URL."""
        return f'<AsyncObscuraLensClient {self._client.base_url!r}>'

    # ------------------------------------------------------------------
    # Liveness
    # ------------------------------------------------------------------

    async def ping(self) -> bool:
        """
        Check that the server is reachable and answering (never raises).

        Returns:
            True when ``GET /api/stats`` answered, False on any
            :class:`~obscuralens.sdk.exceptions.SdkError`.

        Example:
            >>> async with AsyncObscuraLensClient() as client:
            ...     await client.ping()   # doctest: +SKIP
            True
        """
        return await self._run(self._client.ping)

    async def health(self) -> Dict[str, Any]:
        """
        Liveness probe with the server's package version.

        Returns:
            ``{'status': 'ok', 'version': '...'}``.

        Raises:
            TransportError: server unreachable.

        Example:
            >>> async with AsyncObscuraLensClient() as client:
            ...     await client.health()   # doctest: +SKIP
            {'status': 'ok', 'version': '5.1.0'}
        """
        return await self._run(self._client.health)

    # ------------------------------------------------------------------
    # Lookups (14 kinds)
    # ------------------------------------------------------------------

    async def lookup(self, kind: str, target: str) -> LookupResult:
        """
        Run the tracker for one kind (``GET /api/lookup/{kind}/{target}``).

        Args:
            kind: one of the 14 kinds (ip, phone, username, email, domain,
                url, crypto, hash, cve, asn, mac, iban, imei, coords).
            target: the indicator value.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            ValueError: unknown kind.
            BadRequestError: failed server-side validation.

        Example:
            >>> async with AsyncObscuraLensClient() as client:
            ...     res = await client.lookup("domain", "example.com")   # doctest: +SKIP
        """
        return await self._run(self._client.lookup, kind, target)

    async def ip(self, target: str) -> LookupResult:
        """
        Look up an IP address (geo, ASN, reverse DNS, threat intel).

        Args:
            target: IP address, e.g. ``"8.8.8.8"``.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid IP address.

        Example:
            >>> async with AsyncObscuraLensClient() as client:
            ...     res = await client.ip("8.8.8.8")   # doctest: +SKIP
        """
        return await self._run(self._client.ip, target)

    async def phone(self, target: str) -> LookupResult:
        """
        Look up a phone number (E.164, carrier hints, geo enrichment).

        Args:
            target: phone number, e.g. ``"+14155552671"``.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid phone number.

        Example:
            >>> res = await client.phone("+14155552671")   # doctest: +SKIP
        """
        return await self._run(self._client.phone, target)

    async def username(self, target: str) -> LookupResult:
        """
        Check a username across ~45 platforms.

        Args:
            target: username, e.g. ``"johndoe"``.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid username.

        Example:
            >>> res = await client.username("johndoe")   # doctest: +SKIP
        """
        return await self._run(self._client.username, target)

    async def email(self, target: str) -> LookupResult:
        """
        Look up an email address (breaches, reputation, profiles).

        Args:
            target: email address, e.g. ``"user@example.com"``.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid email address.

        Example:
            >>> res = await client.email("user@example.com")   # doctest: +SKIP
        """
        return await self._run(self._client.email, target)

    async def domain(self, target: str) -> LookupResult:
        """
        Look up a domain (registration, DNS posture, CT logs).

        Args:
            target: domain name, e.g. ``"example.com"``.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid domain.

        Example:
            >>> res = await client.domain("example.com")   # doctest: +SKIP
        """
        return await self._run(self._client.domain, target)

    async def url(self, target: str) -> LookupResult:
        """
        Look up a URL (redirects, urlscan, archives, safety verdicts).

        Args:
            target: full URL with scheme.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid URL.

        Example:
            >>> res = await client.url("https://example.com/page")   # doctest: +SKIP
        """
        return await self._run(self._client.url, target)

    async def crypto(self, target: str) -> LookupResult:
        """
        Look up a BTC/ETH/LTC/DOGE address (balances, activity).

        Args:
            target: crypto address.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: unrecognised address format.

        Example:
            >>> res = await client.crypto("1BoatSLRHtKN42kdutzZbHwYQeMwfQ7HNo")   # doctest: +SKIP
        """
        return await self._run(self._client.crypto, target)

    async def hash_(self, target: str) -> LookupResult:
        """
        Look up a file hash (malware family, detections).

        Args:
            target: MD5/SHA1/SHA256 digest.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid digest shape.

        Example:
            >>> res = await client.hash_("44d88612fea8a8f36de82e1278abb02f")   # doctest: +SKIP
        """
        return await self._run(self._client.hash_, target)

    async def cve(self, target: str) -> LookupResult:
        """
        Look up a CVE (CVSS, affected products, EPSS).

        Args:
            target: CVE id, e.g. ``"CVE-2021-44228"``.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid CVE id.

        Example:
            >>> res = await client.cve("CVE-2021-44228")   # doctest: +SKIP
        """
        return await self._run(self._client.cve, target)

    async def asn(self, target: str) -> LookupResult:
        """
        Look up an AS number (holder, prefixes, peers).

        Args:
            target: AS number, e.g. ``"AS15169"``.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid AS number.

        Example:
            >>> res = await client.asn("AS15169")   # doctest: +SKIP
        """
        return await self._run(self._client.asn, target)

    async def mac(self, target: str) -> LookupResult:
        """
        Look up a MAC address (vendor from the offline OUI pack).

        Args:
            target: MAC in colon/dash/dot notation.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid MAC address.

        Example:
            >>> res = await client.mac("b8:27:eb:aa:bb:cc")   # doctest: +SKIP
        """
        return await self._run(self._client.mac, target)

    async def iban(self, target: str) -> LookupResult:
        """
        Look up an IBAN (checksum, issuing bank, country).

        Args:
            target: IBAN value.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid IBAN (mod-97 checked server-side).

        Example:
            >>> res = await client.iban("DE89370400440532013000")   # doctest: +SKIP
        """
        return await self._run(self._client.iban, target)

    async def imei(self, target: str) -> LookupResult:
        """
        Look up an IMEI (TAC decomposition, manufacturer).

        Args:
            target: IMEI value.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid IMEI (Luhn checked server-side).

        Example:
            >>> res = await client.imei("356938035643809")   # doctest: +SKIP
        """
        return await self._run(self._client.imei, target)

    async def coords(self, target: str) -> LookupResult:
        """
        Look up coordinates (formats, reverse geocode, elevation).

        Args:
            target: coordinates, e.g. ``"48.8584, 2.2945"``.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: unrecognised coordinate format.

        Example:
            >>> res = await client.coords("48.8584, 2.2945")   # doctest: +SKIP
        """
        return await self._run(self._client.coords, target)

    async def vin(self, target: str) -> LookupResult:
        """
        Look up a vehicle identification number (WMI, region, model year).

        Args:
            target: 17-character VIN, e.g. ``"1HGCM82633A004352"``.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid VIN shape.

        Example:
            >>> res = await client.vin("1HGCM82633A004352")   # doctest: +SKIP
        """
        return await self._run(self._client.vin, target)

    async def flight(self, target: str) -> LookupResult:
        """
        Look up a flight (route, times, live position when airborne).

        Args:
            target: flight designator, e.g. ``"BA117"``.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid flight designator.

        Example:
            >>> res = await client.flight("BA117")   # doctest: +SKIP
        """
        return await self._run(self._client.flight, target)

    async def mmsi(self, target: str) -> LookupResult:
        """
        Look up a vessel's MMSI (flag state, name, AIS position).

        Args:
            target: 9-digit MMSI, e.g. ``"366982610"``.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid MMSI shape.

        Example:
            >>> res = await client.mmsi("366982610")   # doctest: +SKIP
        """
        return await self._run(self._client.mmsi, target)

    async def app(self, target: str) -> LookupResult:
        """
        Look up a software package / app identifier (registry probes).

        Args:
            target: package identifier, e.g. ``"left-pad@1.3.0"``.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid package identifier.

        Example:
            >>> res = await client.app("requests")   # doctest: +SKIP
        """
        return await self._run(self._client.app, target)

    async def package(self, target: str) -> LookupResult:
        """
        Alias for :meth:`app` — the software-package sensor.

        Args:
            target: package identifier (see :meth:`app`).

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Example:
            >>> res = await client.package("left-pad")   # doctest: +SKIP
        """
        return await self._run(self._client.package, target)

    async def bssid(self, target: str) -> LookupResult:
        """
        Look up a wireless access point BSSID (OUI vendor, location hints).

        Args:
            target: BSSID in colon notation.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid BSSID.

        Example:
            >>> res = await client.bssid("b8:27:eb:aa:bb:cc")   # doctest: +SKIP
        """
        return await self._run(self._client.bssid, target)

    async def plate(self, target: str) -> LookupResult:
        """
        Look up a licence plate (format detection, region context).

        Args:
            target: plate value, e.g. ``"B-AB 1234"``.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: unrecognised plate format.

        Example:
            >>> res = await client.plate("B-AB 1234")   # doctest: +SKIP
        """
        return await self._run(self._client.plate, target)

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    async def investigate(self, target: str,
                          pivot: bool = True) -> InvestigationReport:
        """
        Auto-detect a target and follow bounded pivots.

        Args:
            target: any supported kind value.
            pivot: follow related lookups (default True).

        Returns:
            An :class:`~obscuralens.sdk.models.InvestigationReport`.

        Raises:
            BadRequestError: unknown target type.

        Example:
            >>> report = await client.investigate("example.com")   # doctest: +SKIP
        """
        return await self._run(self._client.investigate, target, pivot=pivot)

    async def risk(self, kind: str, target: str) -> RiskReport:
        """
        Run a lookup with explainable heuristic risk scoring attached.

        Args:
            kind: tracker kind.
            target: the indicator value.

        Returns:
            A :class:`~obscuralens.sdk.models.RiskReport` — score, band,
            weighted signals and the underlying lookup envelope.

        Raises:
            ValueError: unknown kind.
            BadRequestError: invalid target.

        Example:
            >>> report = await client.risk("domain", "example.com")   # doctest: +SKIP
        """
        return await self._run(self._client.risk, kind, target)

    async def timeline(self, target: Optional[str] = None,
                       limit: int = 100) -> Timeline:
        """
        Chronological event timeline across stored lookup history.

        Args:
            target: optional substring filter on stored values.
            limit: maximum events kept.

        Returns:
            A :class:`~obscuralens.sdk.models.Timeline` (oldest first).

        Example:
            >>> timeline = await client.timeline(limit=50)   # doctest: +SKIP
        """
        return await self._run(self._client.timeline, target, limit=limit)

    async def correlate(self, limit: Optional[int] = None
                        ) -> CorrelationResult:
        """
        Correlation graph, clusters and bridge entities from history.

        Args:
            limit: how many history rows to consider (``None`` = server
                default).

        Returns:
            A :class:`~obscuralens.sdk.models.CorrelationResult`.

        Example:
            >>> graph = await client.correlate()   # doctest: +SKIP
        """
        return await self._run(self._client.correlate, limit=limit)

    async def correlate_pair(self, a: str, b: str) -> PairComparison:
        """
        Shared-infrastructure comparison between two targets.

        Args:
            a: first target value.
            b: second target value.

        Returns:
            A :class:`~obscuralens.sdk.models.PairComparison`.

        Example:
            >>> pair = await client.correlate_pair("8.8.8.8", "dns.google")   # doctest: +SKIP
        """
        return await self._run(self._client.correlate_pair, a, b)

    async def intel(self, target: str) -> IntelVerdict:
        """
        Threat-intel verdict for an IP (Tor exit, blocklist feeds).

        Args:
            target: IPv4/IPv6 address.

        Returns:
            An :class:`~obscuralens.sdk.models.IntelVerdict`.

        Raises:
            BadRequestError: invalid IP address.

        Example:
            >>> verdict = await client.intel("45.148.10.99")   # doctest: +SKIP
        """
        return await self._run(self._client.intel, target)

    # ------------------------------------------------------------------
    # Platform
    # ------------------------------------------------------------------

    async def sources(self) -> Dict[str, Dict[str, str]]:
        """
        Source catalogues for every kind (``GET /api/sources``).

        Returns:
            ``{kind: {source: description}}``.

        Example:
            >>> catalog = await client.sources()   # doctest: +SKIP
        """
        return await self._run(self._client.sources)

    async def sources_health(self) -> List[SourceHealthEntry]:
        """
        Per-source health rows (from ``GET /api/stats`` source_health).

        Returns:
            A list of :class:`~obscuralens.sdk.models.SourceHealthEntry`.

        Example:
            >>> rows = await client.sources_health()   # doctest: +SKIP
        """
        return await self._run(self._client.sources_health)

    async def stats(self) -> StatsSummary:
        """
        Database, cache, network and source-health statistics.

        Returns:
            A :class:`~obscuralens.sdk.models.StatsSummary`.

        Example:
            >>> summary = await client.stats()   # doctest: +SKIP
        """
        return await self._run(self._client.stats)

    async def kinds(self) -> List[KindInfo]:
        """
        Registry of every target kind with labels and source lists.

        Returns:
            A list of :class:`~obscuralens.sdk.models.KindInfo`.

        Example:
            >>> kinds = await client.kinds()   # doctest: +SKIP
        """
        return await self._run(self._client.kinds)

    async def history(self, kind: Optional[str] = None,
                      q: Optional[str] = None,
                      limit: int = 100) -> HistoryResult:
        """
        Search stored lookup history.

        Args:
            kind: restrict rows to one kind.
            q: case-insensitive substring match on the stored value.
            limit: cap rows (server clamps to 1..500).

        Returns:
            A :class:`~obscuralens.sdk.models.HistoryResult`.

        Example:
            >>> result = await client.history(kind="ip", q="8.8.8")   # doctest: +SKIP
        """
        return await self._run(self._client.history, kind, q=q, limit=limit)

    async def cases(self) -> List[Any]:
        """
        Every investigation case with row counts (``GET /api/cases``).

        Returns:
            A list of parsed case records.

        Example:
            >>> rows = await client.cases()   # doctest: +SKIP
        """
        return await self._run(self._client.cases)

    async def watch(self) -> List[Any]:
        """
        Every watched target (``GET /api/watch``).

        Returns:
            A list of parsed watch records.

        Example:
            >>> entries = await client.watch()   # doctest: +SKIP
        """
        return await self._run(self._client.watch)

    # ------------------------------------------------------------------
    # v6.0 — dorks, analytics, notifications, automation, exports, stream
    # ------------------------------------------------------------------

    async def dorks(self, target: str,
                    kind: Optional[str] = None) -> DorkReport:
        """
        Ready-to-open search-engine dorks for a target.

        Args:
            target: the value to build dorks for.
            kind: optional kind override; ``None`` auto-detects.

        Returns:
            A :class:`~obscuralens.sdk.models.DorkReport`.

        Raises:
            BadRequestError: blank target.

        Example:
            >>> report = await client.dorks("example.com")   # doctest: +SKIP
        """
        return await self._run(self._client.dorks, target, kind=kind)

    async def analytics_stats(self, values: Sequence[float],
                              bins: int = 10) -> AnalyticsEnvelope:
        """
        Descriptive statistics plus a histogram for a numeric list.

        Args:
            values: the numbers to profile.
            bins: histogram bin count (server clamps to 1..100).

        Returns:
            An :class:`~obscuralens.sdk.models.AnalyticsEnvelope`
            (``kind='stats'``).

        Example:
            >>> envelope = await client.analytics_stats(   # doctest: +SKIP
            ...     [1, 2, 3, 4, 100])
        """
        return await self._run(self._client.analytics_stats, values,
                               bins=bins)

    async def analytics_anomalies(self, values: Sequence[float],
                                  method: str = 'ensemble',
                                  threshold: Optional[float] = None
                                  ) -> AnalyticsEnvelope:
        """
        Outlier detection over a numeric list.

        Args:
            values: the numbers to screen.
            method: detector name (default ``ensemble``).
            threshold: z-score cutoff — only sent for ``method='zscore'``.

        Returns:
            An :class:`~obscuralens.sdk.models.AnalyticsEnvelope`
            (``kind='anomalies'``).

        Example:
            >>> envelope = await client.analytics_anomalies(   # doctest: +SKIP
            ...     [1, 2, 3, 4, 10000], method='mad')
        """
        return await self._run(self._client.analytics_anomalies, values,
                               method=method, threshold=threshold)

    async def analytics_timeseries(self, values: Sequence[float]
                                   ) -> AnalyticsEnvelope:
        """
        Trend / changepoint summary for a value sequence.

        Args:
            values: the sequence to profile (oldest first).

        Returns:
            An :class:`~obscuralens.sdk.models.AnalyticsEnvelope`
            (``kind='timeseries'``).

        Example:
            >>> envelope = await client.analytics_timeseries(   # doctest: +SKIP
            ...     [5, 6, 5, 6, 20, 21])
        """
        return await self._run(self._client.analytics_timeseries, values)

    async def analytics_clusters(self, points: Sequence[Sequence[float]],
                                 eps_km: float = 25.0,
                                 min_points: int = 3) -> AnalyticsEnvelope:
        """
        Kilometre-space clustering of ``[lat, lon]`` pairs.

        Args:
            points: ``[lat, lon]`` rows.
            eps_km: cluster radius in kilometres (default 25).
            min_points: DBSCAN density threshold (default 3).

        Returns:
            An :class:`~obscuralens.sdk.models.AnalyticsEnvelope`
            (``kind='clusters'``).

        Example:
            >>> envelope = await client.analytics_clusters(   # doctest: +SKIP
            ...     [[52.0, 13.0], [52.1, 13.1]])
        """
        return await self._run(self._client.analytics_clusters, points,
                               eps_km=eps_km, min_points=min_points)

    async def analytics_keywords(self, text: str,
                                 top: int = 10) -> AnalyticsEnvelope:
        """
        Stopword-filtered keyword mining for a text.

        Args:
            text: the free-form text to mine.
            top: how many terms to keep (default 10).

        Returns:
            An :class:`~obscuralens.sdk.models.AnalyticsEnvelope`
            (``kind='keywords'``).

        Example:
            >>> envelope = await client.analytics_keywords(   # doctest: +SKIP
            ...     "the quick brown fox", top=2)
        """
        return await self._run(self._client.analytics_keywords, text,
                               top=top)

    async def analytics_language(self, text: str) -> AnalyticsEnvelope:
        """
        Script and language fingerprint for a text.

        Args:
            text: the text to fingerprint.

        Returns:
            An :class:`~obscuralens.sdk.models.AnalyticsEnvelope`
            (``kind='language'``).

        Example:
            >>> envelope = await client.analytics_language(   # doctest: +SKIP
            ...     "Le renard brun rapide")
        """
        return await self._run(self._client.analytics_language, text)

    async def analytics_similarity(self, a: str,
                                   b: str) -> AnalyticsEnvelope:
        """
        Four-metric similarity between two texts.

        Args:
            a: first text.
            b: second text.

        Returns:
            An :class:`~obscuralens.sdk.models.AnalyticsEnvelope`
            (``kind='similarity'``).

        Example:
            >>> envelope = await client.analytics_similarity(   # doctest: +SKIP
            ...     "paypal.com", "paypa1.com")
        """
        return await self._run(self._client.analytics_similarity, a, b)

    async def analytics_graph(self, entities: Sequence[Any],
                              links: Sequence[Any]) -> AnalyticsEnvelope:
        """
        Graph metrics over an ``entities``/``links`` payload.

        Args:
            entities: entity dicts.
            links: link dicts.

        Returns:
            An :class:`~obscuralens.sdk.models.AnalyticsEnvelope`
            (``kind='graph'``).

        Example:
            >>> envelope = await client.analytics_graph(   # doctest: +SKIP
            ...     [{'id': 'a'}], [{'source': 'a', 'target': 'b'}])
        """
        return await self._run(self._client.analytics_graph, entities, links)

    async def analytics_history(self, limit: int = 500) -> AnalyticsEnvelope:
        """
        Enrichment report over stored query history.

        Args:
            limit: how many newest history rows to consider (default
                500).

        Returns:
            An :class:`~obscuralens.sdk.models.AnalyticsEnvelope`
            (``kind='history'``).

        Example:
            >>> envelope = await client.analytics_history()   # doctest: +SKIP
        """
        return await self._run(self._client.analytics_history, limit=limit)

    async def notify_channels(self) -> NotifyChannels:
        """
        Every configured notification channel plus vocabularies.

        Returns:
            A :class:`~obscuralens.sdk.models.NotifyChannels`.

        Example:
            >>> channels = await client.notify_channels()   # doctest: +SKIP
        """
        return await self._run(self._client.notify_channels)

    async def add_notify_channel(self, name: str, channel_type: str,
                                 target: str = '',
                                 events: Optional[Sequence[str]] = None,
                                 min_severity: Optional[str] = None,
                                 quiet_hours: Optional[Sequence[int]] = None
                                 ) -> NotifyChannel:
        """
        Register one notification channel.

        Args:
            name: unique human label.
            channel_type: channel type (webhook/telegram/discord/
                slack/smtp) — validated server-side.
            target: delivery target; may be empty when a global config
                key covers it.
            events: event types to subscribe to (``None`` =
                everything).
            min_severity: weakest severity worth waking this channel.
            quiet_hours: optional ``(start, end)`` local-hour pair.

        Returns:
            The created :class:`~obscuralens.sdk.models.NotifyChannel`.

        Raises:
            BadRequestError: rejected spec.

        Example:
            >>> channel = await client.add_notify_channel(   # doctest: +SKIP
            ...     "team-chat", channel_type="telegram",
            ...     target="bot:chat")
        """
        return await self._run(self._client.add_notify_channel, name,
                               channel_type,
                               target=target, events=events,
                               min_severity=min_severity,
                               quiet_hours=quiet_hours)

    async def remove_notify_channel(self, name: str) -> Dict[str, Any]:
        """
        Delete one notification channel by name.

        Args:
            name: channel name (case-insensitive).

        Returns:
            ``{'ok': True, 'removed': <name>}``.

        Raises:
            NotFoundError: unknown channel name.

        Example:
            >>> await client.remove_notify_channel("team-chat")   # doctest: +SKIP
        """
        return await self._run(self._client.remove_notify_channel, name)

    async def test_notify_channel(self, name: str) -> NotifyDelivery:
        """
        Probe one channel with a one-off test message.

        Args:
            name: the channel to probe.

        Returns:
            A :class:`~obscuralens.sdk.models.NotifyDelivery`.

        Raises:
            NotFoundError: unknown channel name.

        Example:
            >>> delivery = await client.test_notify_channel(   # doctest: +SKIP
            ...     "team-chat")
        """
        return await self._run(self._client.test_notify_channel, name)

    async def notify_recent(self, limit: int = 20) -> Dict[str, Any]:
        """
        Recent notification history, newest first (plain dict).

        Args:
            limit: how many entries to return (default 20).

        Returns:
            ``{'count': n, 'recent': [...]}`` as a plain dict.

        Example:
            >>> log = await client.notify_recent(limit=5)   # doctest: +SKIP
        """
        return await self._run(self._client.notify_recent, limit=limit)

    async def notify_broadcast(self, title: str, body: str,
                               severity: str = 'info',
                               event_type: str = 'manual') -> NotifyDelivery:
        """
        Fan one event out to every configured channel.

        Args:
            title: headline (non-empty).
            body: message body (non-empty).
            severity: one of info/low/medium/high/critical.
            event_type: free-form event label.

        Returns:
            A :class:`~obscuralens.sdk.models.NotifyDelivery`.

        Raises:
            BadRequestError: blank ``title`` or ``body``.

        Example:
            >>> delivery = await client.notify_broadcast(   # doctest: +SKIP
            ...     "watch diff", "example.com changed NS",
            ...     severity="high")
        """
        return await self._run(self._client.notify_broadcast, title, body,
                               severity=severity, event_type=event_type)

    async def automation_tasks(self) -> AutomationTasks:
        """
        Every scheduled task (schedules, bookkeeping, health).

        Returns:
            An :class:`~obscuralens.sdk.models.AutomationTasks`.

        Example:
            >>> tasks = await client.automation_tasks()   # doctest: +SKIP
        """
        return await self._run(self._client.automation_tasks)

    async def add_automation_task(self, name: str, action: str,
                                  schedule: str = 'interval',
                                  interval_seconds: int = 3600,
                                  at_time: Optional[str] = None,
                                  weekday: Optional[int] = None,
                                  params: Optional[Dict[str, Any]] = None,
                                  enabled: bool = True
                                  ) -> AutomationTaskView:
        """
        Register one scheduled task.

        Args:
            name: unique human label.
            action: executor action (watch_check/pipeline/report/
                feed_refresh/notify_test).
            schedule: interval/daily/weekly (default interval).
            interval_seconds: period for the interval schedule.
            at_time: ``'HH:MM'`` for daily/weekly schedules.
            weekday: 0 = Monday ... 6 = Sunday (weekly).
            params: executor payload.
            enabled: master switch.

        Returns:
            The created
            :class:`~obscuralens.sdk.models.AutomationTaskView`.

        Raises:
            BadRequestError: rejected spec.

        Example:
            >>> task = await client.add_automation_task(   # doctest: +SKIP
            ...     "daily-watch", "watch_check", schedule="daily",
            ...     at_time="09:00")
        """
        return await self._run(self._client.add_automation_task, name,
                               action, schedule=schedule,
                               interval_seconds=interval_seconds,
                               at_time=at_time, weekday=weekday,
                               params=params, enabled=enabled)

    async def remove_automation_task(self, name: str) -> Dict[str, Any]:
        """
        Delete one scheduled task by name.

        Args:
            name: task name (case-insensitive).

        Returns:
            ``{'ok': True, 'removed': <name>}``.

        Raises:
            NotFoundError: unknown task name.

        Example:
            >>> await client.remove_automation_task("daily-watch")   # doctest: +SKIP
        """
        return await self._run(self._client.remove_automation_task, name)

    async def run_automation_task(self, name: str) -> Dict[str, Any]:
        """
        Execute one task now, regardless of its schedule.

        Args:
            name: task name.

        Returns:
            The run outcome dict (``ok``/``started``/``finished``/
            ``error``/``summary``).

        Raises:
            NotFoundError: unknown task name.

        Example:
            >>> await client.run_automation_task("daily-watch")   # doctest: +SKIP
        """
        return await self._run(self._client.run_automation_task, name)

    async def run_due_automation(self) -> Dict[str, Any]:
        """
        Run every due task and persist the bookkeeping.

        Returns:
            ``{'ran': n, 'results': [...]}``.

        Example:
            >>> await client.run_due_automation()   # doctest: +SKIP
        """
        return await self._run(self._client.run_due_automation)

    async def automation_next(self) -> Dict[str, Any]:
        """
        When every task runs next (stored + recomputed).

        Returns:
            ``{'count': n, 'tasks': [...]}``.

        Example:
            >>> snapshot = await client.automation_next()   # doctest: +SKIP
        """
        return await self._run(self._client.automation_next)

    async def export_stix(self, kind: str, target: str) -> StixBundle:
        """
        A STIX 2.1 bundle for the newest stored lookup of one target.

        Args:
            kind: tracker kind.
            target: the indicator value.

        Returns:
            A :class:`~obscuralens.sdk.models.StixBundle`.

        Raises:
            ValueError: unknown kind.
            NotFoundError: no stored lookup for the target.

        Example:
            >>> bundle = await client.export_stix(   # doctest: +SKIP
            ...     "domain", "example.com")
        """
        return await self._run(self._client.export_stix, kind, target)

    async def export_misp(self, kind: str, target: str) -> MispEvent:
        """
        A MISP core-format event for the newest stored lookup.

        Args:
            kind: tracker kind.
            target: the indicator value.

        Returns:
            A :class:`~obscuralens.sdk.models.MispEvent`.

        Raises:
            ValueError: unknown kind.
            NotFoundError: no stored lookup for the target.

        Example:
            >>> event = await client.export_misp(   # doctest: +SKIP
            ...     "domain", "example.com")
        """
        return await self._run(self._client.export_misp, kind, target)

    async def set_stream_topics(self, topics: Union[Sequence[str], str]
                                ) -> Dict[str, Any]:
        """
        Declare the event topics the live stream should carry.

        Args:
            topics: topic names — a list/tuple or one comma-separated
                string.

        Returns:
            ``{'topics': [...], 'count': n, 'subscriber_count': n}``.

        Raises:
            BadRequestError: missing/empty topics.

        Example:
            >>> await client.set_stream_topics("lookup, watch")   # doctest: +SKIP
        """
        return await self._run(self._client.set_stream_topics, topics)

    async def gather(self, calls: Sequence[Any]) -> List[Any]:
        """
        Await several SDK coroutines concurrently (convenience wrapper).

        Thin wrapper around :func:`asyncio.gather` kept next to the
        lookups it is usually used with. Failed lookups raise unless you
        pass ``return_exceptions=True`` inside each call's kwargs —
        :class:`~obscuralens.sdk.exceptions.SdkError` propagates otherwise.

        Args:
            calls: awaitable callables (zero-argument coroutines or
                ``functools.partial`` of this class's methods).

        Returns:
            The list of results in input order.

        Example:
            >>> results = await client.gather([
            ...     client.ip("8.8.8.8"), client.domain("example.com")])   # doctest: +SKIP
        """
        return await asyncio.gather(*calls)

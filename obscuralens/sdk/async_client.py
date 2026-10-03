"""
AsyncObscuraLensClient — the asyncio face of the ObscuraLens SDK.

A thin, stdlib-only wrapper that runs the synchronous
:class:`~obscuralens.sdk.client.ObscuraLensClient` methods in a dedicated
thread pool via ``loop.run_in_executor`` (Python 3.9-safe — the running
loop is captured inside each coroutine, and a private
``ThreadPoolExecutor`` is used so ``aclose()`` can shut it down
deterministically). No third-party event-loop or HTTP libraries are
imported.

The async surface mirrors the most-used sync methods — every lookup kind,
investigations, risk, timelines, correlation, stats, sources and the
liveness probe. Anything missing can still be awaited through the escape
hatch::

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
from typing import Any, Callable, Dict, List, Optional, Sequence

from .client import DEFAULT_BACKOFF, DEFAULT_BASE_URL, DEFAULT_RETRIES, DEFAULT_TIMEOUT, ObscuraLensClient
from .models import (
    CorrelationResult,
    HistoryResult,
    IntelVerdict,
    InvestigationReport,
    KindInfo,
    LookupResult,
    PairComparison,
    RiskReport,
    SourceHealthEntry,
    StatsSummary,
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

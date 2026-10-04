"""
ObscuraLensClient — the synchronous Python SDK for the ObscuraLens REST API.

One class, every endpoint exposed by ``obscuralens/web/app.py``: the 20
tracker kinds (14 classic + the six v6.0 sensor kinds ``vin`` / ``flight``
/ ``mmsi`` / ``app`` / ``bssid`` / ``plate``), investigations, risk
scoring, timelines, correlation, threat intel, cases, the watchlist,
graph exports, history, settings/keys, the analyst toolbox (including
the dork builder), HTML reports, pattern-of-life, webhook alerts, batch
lookups — and the v6.0 surface: the nine analytics endpoints,
notification channels and broadcasts, the automation scheduler and the
STIX 2.1 / MISP intelligence-sharing exports, plus the live-stream topic
declaration.

Quickstart::

    from obscuralens.sdk import ObscuraLensClient

    client = ObscuraLensClient("http://127.0.0.1:8000")
    with client:
        result = client.ip("8.8.8.8")
        print(result.summary())            # "ip 8.8.8.8: 14 field(s) ..."
        print(result.get("country"))       # merged field access

        report = client.risk("domain", "example.com")
        if report.is_high_or_worse():
            print(report.explain())        # weighted signal lines

        dorks = client.dorks("example.com")
        print(dorks.links()[0])            # ready-to-open search URL

        envelope = client.analytics_stats([1, 2, 3, 4, 100])
        print(envelope.get("summary"))     # mean/median/quartiles block

The client is transport-agnostic: pass any
:class:`~obscuralens.sdk.transport.Transport` (e.g. the bundled
:class:`~obscuralens.sdk.transport.StaticTransport`) to fake the server in
tests. Retries with exponential backoff, ``Retry-After`` handling and the
full exception mapping are built in — see
:mod:`obscuralens.sdk.exceptions`. For guided multi-step investigations
on top of this client see
:class:`~obscuralens.sdk.session.InvestigationSession`.
"""

import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from .exceptions import (
    ApiError,
    BadRequestError,
    MalformedResponseError,
    NotFoundError,
    RateLimitError,
    SdkError,
    ServerError,
    TransportError,
)
from .exceptions import (
    TimeoutError as SdkTimeoutError,
)
from .models import (
    KINDS,
    AlertConfig,
    AnalyticsEnvelope,
    AutomationTasks,
    AutomationTaskView,
    BatchProgress,
    Case,
    CaseItem,
    CaseNote,
    CorrelationResult,
    DiffReport,
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
    PatternReport,
    RiskReport,
    ServiceKey,
    SourceHealthEntry,
    StatsSummary,
    StixBundle,
    Timeline,
    ToolboxResult,
    WatchDiff,
    WatchEntry,
)
from .transport import (
    API_KEY_HEADER,
    SDK_VERSION,
    Response,
    Transport,
    UrllibTransport,
    header_value,
)

__all__ = ['ObscuraLensClient', 'DEFAULT_BASE_URL', 'SDK_VERSION']

#: Default server address (matches ``obscuralens serve`` defaults).
DEFAULT_BASE_URL = 'http://127.0.0.1:8000'

#: Default per-request timeout (seconds).
DEFAULT_TIMEOUT = 30.0

#: Default total attempts per request (see ``retries``).
DEFAULT_RETRIES = 3

#: Default retry backoff base (seconds); doubles per attempt.
DEFAULT_BACKOFF = 0.5

#: Upper bound for any single computed backoff sleep.
MAX_BACKOFF = 30.0

#: Export formats accepted by ``GET /api/export/{fmt}/{target}``.
EXPORT_FORMATS = ('graphml', 'gexf', 'dot', 'jsonl', 'csv')

#: Valid case statuses for ``update_case`` (PATCH /api/cases/{id}).
CASE_STATUSES = ('open', 'closed', 'archived')

#: Toolbox tool names accepted by :meth:`ObscuraLensClient.toolbox`.
TOOLBOX_TOOLS = ('encodings', 'decode', 'jwt', 'hash-id', 'coords',
                 'extract', 'squat')

#: Decode-scheme aliases accepted by :meth:`ObscuraLensClient.toolbox`.
_DECODE_SCHEMES = ('hex', 'base32', 'base64', 'base85', 'url_percent',
                   'html_entity', 'rot13', 'caesar', 'binary', 'decimal',
                   'reversed', 'morse', 'gzip')

#: File extensions mapped to upload content types (exif/stego endpoints).
_UPLOAD_TYPES = {
    '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
    '.gif': 'image/gif', '.bmp': 'image/bmp', '.webp': 'image/webp',
}


class ObscuraLensClient:
    """
    Synchronous client for the ObscuraLens REST API.

    Args:
        base_url: scheme + host + port of the server (with or without a
            trailing slash). A path prefix such as
            ``http://host/obscuralens`` is preserved.
        api_key: optional session API key sent as an ``X-API-Key`` header
            on every request. The stock server ignores it (it has no
            built-in auth), but authenticating reverse proxies and the
            ``OBSCURALENS_API_KEY`` deployment pattern honour it. Leave
            ``None`` when talking to a plain local server.
        timeout: per-request timeout in seconds (``None`` = transport
            default).
        retries: maximum number of attempts per request *including the
            first* (default 3 — one try plus up to two retries). Requests
            failing with :class:`TransportError`, :class:`TimeoutError` or
            :class:`RateLimitError` are retried; other HTTP errors raise
            immediately.
        backoff: base sleep between retries in seconds — the delay is
            ``backoff * 2**attempt`` capped at ``max_backoff``.
        transport: a :class:`~obscuralens.sdk.transport.Transport`
            implementation; when omitted a
            :class:`~obscuralens.sdk.transport.UrllibTransport` is built
            (stdlib-only).
        verify_ssl: forwarded to the default transport — verify TLS
            certificates for ``https://`` base URLs. Ignored when a custom
            transport is supplied.
        sleep_fn: callable used to sleep between retries (injectable for
            tests; default :func:`time.sleep`).
        max_backoff: ceiling for the exponential backoff sleep.

    Raises:
        ValueError: if ``base_url`` has no scheme/host.

    Example:
        >>> client = ObscuraLensClient("http://127.0.0.1:8000")
        >>> res = client.ip("8.8.8.8")   # doctest: +SKIP
        >>> res.summary()                # doctest: +SKIP
        'ip 8.8.8.8: 14 field(s) from 5 source(s), 1 failed'
    """

    def __init__(self, base_url: str = DEFAULT_BASE_URL,
                 api_key: Optional[str] = None,
                 timeout: float = DEFAULT_TIMEOUT,
                 retries: int = DEFAULT_RETRIES,
                 backoff: float = DEFAULT_BACKOFF,
                 transport: Optional[Transport] = None,
                 verify_ssl: bool = True,
                 sleep_fn: Callable[[float], None] = time.sleep,
                 max_backoff: float = MAX_BACKOFF) -> None:
        base = str(base_url or DEFAULT_BASE_URL).strip().rstrip('/')
        parsed = urllib.parse.urlparse(base)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(
                f'base_url must look like http://host:port — got {base_url!r}')
        self.base_url = base
        self.api_key = api_key or None
        self.timeout = timeout
        self.retries = max(1, int(retries))
        self.backoff = max(0.0, float(backoff))
        self.max_backoff = max(0.0, float(max_backoff))
        self._sleep_fn = sleep_fn
        self._transport = transport if transport is not None else \
            UrllibTransport(timeout=float(timeout) if timeout is not None
                            else DEFAULT_TIMEOUT, verify_ssl=verify_ssl)
        self._closed = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def __enter__(self) -> 'ObscuraLensClient':
        """Enter the context manager (returns self)."""
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        """Exit the context manager, closing the underlying transport."""
        self.close()

    def close(self) -> None:
        """
        Close the underlying transport and mark the client closed.

        Idempotent; further requests raise :class:`TransportError`. The
        context manager calls this automatically.

        Example:
            >>> client = ObscuraLensClient()
            >>> client.close()
        """
        self._closed = True
        self._transport.close()

    def __repr__(self) -> str:
        """Debug representation with base URL and SDK version."""
        state = 'closed' if self._closed else 'open'
        return (f'<ObscuraLensClient {self.base_url!r} '
                f'sdk={SDK_VERSION} {state}>')

    @property
    def transport(self) -> Transport:
        """The transport this client sends requests through."""
        return self._transport

    # ------------------------------------------------------------------
    # Request plumbing
    # ------------------------------------------------------------------

    def _sleep(self, seconds: float) -> None:
        """Sleep via the injectable sleeper (no-op for negative values)."""
        if seconds and seconds > 0:
            self._sleep_fn(seconds)

    def _backoff_delay(self, attempt: int) -> float:
        """Exponential backoff for one attempt index (0-based)."""
        return min(self.backoff * (2 ** attempt), self.max_backoff)

    @staticmethod
    def _encode_path_segment(value: Any) -> str:
        """Percent-encode one path segment (slashes, colons, commas...)."""
        return urllib.parse.quote(str(value), safe='')

    def _path(self, template: str, *segments: Any) -> str:
        """Build an API path from a template and encoded segments."""
        encoded = [self._encode_path_segment(segment) for segment in segments]
        return template.format(*encoded)

    def _build_url(self, path: str,
                   params: Optional[Dict[str, Any]] = None) -> str:
        """Join base URL, path and query parameters into a request URL."""
        return UrllibTransport.build_url(self.base_url, path, params)

    def _base_headers(self) -> Dict[str, str]:
        """Default request headers: Accept, User-Agent and API key."""
        headers = {
            'Accept': 'application/json',
            'User-Agent': f'obscuralens-sdk/{SDK_VERSION}',
        }
        if self.api_key:
            headers[API_KEY_HEADER] = self.api_key
        return headers

    def _send(self, method: str, path: str,
              params: Optional[Dict[str, Any]] = None,
              json_body: Any = None, body: Optional[bytes] = None,
              extra_headers: Optional[Dict[str, str]] = None) -> Response:
        """
        Perform one request with retries; return the raw Response.

        Retries :class:`TransportError`, :class:`TimeoutError` and
        :class:`RateLimitError` (sleeping ``Retry-After`` seconds when the
        server sent one, else the exponential backoff) up to ``retries``
        total attempts. Non-2xx statuses raise the mapped SDK exception on
        the final attempt.

        Args:
            method: HTTP verb.
            path: absolute API path (``/api/...``).
            params: query parameters (``None`` values dropped).
            json_body: JSON request body, or ``None``.
            body: raw request body bytes (multipart uploads), or ``None``.
            extra_headers: extra headers merged over the defaults.

        Returns:
            The successful (2xx) :class:`~obscuralens.sdk.transport.Response`.

        Raises:
            TransportError: attempts exhausted with connection errors.
            TimeoutError: attempts exhausted with timeouts.
            BadRequestError: HTTP 400.
            NotFoundError: HTTP 404.
            RateLimitError: HTTP 429 that did not recover.
            ServerError: HTTP 5xx.
            ApiError: any other non-2xx status.
        """
        if self._closed:
            raise TransportError('client is closed')
        url = self._build_url(path, params)
        headers = self._base_headers()
        if extra_headers:
            headers.update(extra_headers)
        attempts = self.retries
        for attempt in range(attempts):
            final = attempt + 1 >= attempts
            try:
                response = self._transport.request(
                    method, url, headers=headers, params=params,
                    json_body=json_body, body=body, timeout=self.timeout)
            except (TransportError, SdkTimeoutError, RateLimitError) as exc:
                if final:
                    raise
                delay = self._backoff_delay(attempt)
                if isinstance(exc, RateLimitError) and \
                        exc.retry_after is not None:
                    delay = float(exc.retry_after)
                self._sleep(delay)
                continue
            if 200 <= response.status < 300:
                return response
            error = self._error_for(response)
            if isinstance(error, RateLimitError) and not final:
                delay = self._backoff_delay(attempt)
                if error.retry_after is not None:
                    delay = float(error.retry_after)
                self._sleep(delay)
                continue
            raise error
        raise TransportError(  # pragma: no cover - loop always exits above
            f'{method} {path}: no response after {attempts} attempt(s)')

    def _error_for(self, response: Response) -> ApiError:
        """
        Map one non-2xx response onto the right SDK exception.

        Args:
            response: the offending response.

        Returns:
            The exception instance to raise (never raised here).
        """
        status = int(response.status)
        try:
            payload = response.json()
        except ValueError:
            payload = None
        body: Optional[Dict[str, Any]] = payload if isinstance(
            payload, dict) else None
        detail: Optional[str] = None
        if body is not None:
            raw_detail = body.get('detail')
            if isinstance(raw_detail, str):
                detail = raw_detail
            elif raw_detail is not None:
                detail = str(raw_detail)
        if detail is None:
            detail = f'HTTP {status}'
        if status == 400:
            return BadRequestError(detail, status, body)
        if status == 404:
            return NotFoundError(detail, status, body)
        if status == 429:
            retry_after = _parse_retry_after(response.headers)
            return RateLimitError(detail, status, body,
                                  retry_after=retry_after)
        if 500 <= status < 600:
            return ServerError(detail, status, body)
        return ApiError(detail, status, body)

    def _request(self, method: str, path: str,
                 params: Optional[Dict[str, Any]] = None,
                 json_body: Any = None, body: Optional[bytes] = None,
                 extra_headers: Optional[Dict[str, str]] = None) -> Any:
        """
        Perform one request and return the parsed JSON.

        Args:
            method: HTTP verb.
            path: absolute API path (``/api/...``).
            params: query parameters.
            json_body: JSON request body, or ``None``.
            body: raw body bytes (multipart uploads), or ``None``.
            extra_headers: extra headers merged over the defaults.

        Returns:
            The parsed JSON value (dict or list — the API returns lists
            for ``kinds``, ``cases``, ``watch`` and ``keys``).

        Raises:
            MalformedResponseError: 2xx body that is not valid JSON.
            ApiError subclasses: mapped non-2xx statuses.
            TransportError / TimeoutError: connection-level failures.
        """
        response = self._send(method, path, params=params,
                              json_body=json_body, body=body,
                              extra_headers=extra_headers)
        try:
            return response.json()
        except ValueError as exc:
            excerpt = response.text[:200]
            raise MalformedResponseError(
                f'non-JSON response from {method} {path}: {excerpt!r}',
                status=response.status,
                body_text=response.text[:2000]) from exc

    # ------------------------------------------------------------------
    # Liveness
    # ------------------------------------------------------------------

    def ping(self) -> bool:
        """
        Check that the server is reachable and answering.

        Calls ``GET /api/stats``; any successful response means True. Never
        raises — connection failures, timeouts and HTTP errors return
        False. Note that a dead server burns the full retry budget (use a
        small ``retries`` value when pinging aggressively).

        Returns:
            True when the server answered, False otherwise.

        Example:
            >>> client = ObscuraLensClient(retries=1)
            >>> client.ping()   # doctest: +SKIP
            True
        """
        try:
            self._request('GET', '/api/stats')
            return True
        except SdkError:
            return False

    def health(self) -> Dict[str, Any]:
        """
        Liveness probe with the server's package version.

        Returns:
            ``{'status': 'ok', 'version': '5.1.0'}`` as a dict.

        Raises:
            TransportError: server unreachable.

        Example:
            >>> client = ObscuraLensClient()
            >>> client.health()   # doctest: +SKIP
            {'status': 'ok', 'version': '5.1.0'}
        """
        payload = self._request('GET', '/api/health')
        return payload if isinstance(payload, dict) else {}

    # ------------------------------------------------------------------
    # Lookups (14 kinds)
    # ------------------------------------------------------------------

    def lookup(self, kind: str, target: str) -> LookupResult:
        """
        Run the tracker for one kind — the core lookup endpoint.

        ``GET /api/lookup/{kind}/{target}``

        Args:
            kind: one of the 14 kinds (``ip``, ``phone``, ``username``,
                ``email``, ``domain``, ``url``, ``crypto``, ``hash``,
                ``cve``, ``asn``, ``mac``, ``iban``, ``imei``, ``coords``).
            target: the indicator value; it must pass that kind's
                server-side validator.

        Returns:
            A :class:`~obscuralens.sdk.models.LookupResult` with merged
            ``fields``, per-field ``field_sources`` provenance and
            per-source health (``sources_ok`` / ``sources_failed``).

        Raises:
            ValueError: ``kind`` is not one of the known kinds.
            BadRequestError: the target failed server-side validation.
            NotFoundError / ServerError / ApiError: other HTTP errors.

        Example:
            >>> client = ObscuraLensClient("http://127.0.0.1:8000")
            >>> res = client.lookup("domain", "example.com")   # doctest: +SKIP
            >>> res.get("registrar")                            # doctest: +SKIP
            'Example Registrar, Inc.'
        """
        kind = str(kind or '').strip().lower()
        if kind not in KINDS:
            raise ValueError(
                f'unknown kind {kind!r} — expected one of {", ".join(KINDS)}')
        path = self._path('/api/lookup/{0}/{1}', kind, target)
        payload = self._request('GET', path)
        return LookupResult.from_dict(payload, kind=kind)

    def ip(self, target: str) -> LookupResult:
        """
        Look up an IPv4/IPv6 address (geo, ASN, reverse DNS, threat intel).

        ``GET /api/lookup/ip/{target}``

        Args:
            target: IP address, e.g. ``"8.8.8.8"``.

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult` with fields such
            as ``country``, ``asn``, ``hostname``.

        Raises:
            BadRequestError: invalid IP address.

        Example:
            >>> client = ObscuraLensClient("http://127.0.0.1:8000")
            >>> res = client.ip("8.8.8.8")   # doctest: +SKIP
        """
        return self.lookup('ip', target)

    def phone(self, target: str) -> LookupResult:
        """
        Look up a phone number (E.164 formatting, carrier hints, geo).

        ``GET /api/lookup/phone/{target}``

        Args:
            target: phone number, e.g. ``"+14155552671"``.

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid phone number.

        Example:
            >>> client = ObscuraLensClient()
            >>> res = client.phone("+14155552671")   # doctest: +SKIP
        """
        return self.lookup('phone', target)

    def username(self, target: str) -> LookupResult:
        """
        Check a username across ~45 platforms (honest 3-state verdicts).

        ``GET /api/lookup/username/{target}``

        Args:
            target: username, e.g. ``"johndoe"``.

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult` — ``fields``
            carries the per-platform ``results`` list.

        Raises:
            BadRequestError: invalid username.

        Example:
            >>> client = ObscuraLensClient()
            >>> res = client.username("johndoe")   # doctest: +SKIP
        """
        return self.lookup('username', target)

    def email(self, target: str) -> LookupResult:
        """
        Look up an email address (breach exposure, reputation, profiles).

        ``GET /api/lookup/email/{target}``

        Args:
            target: email address, e.g. ``"user@example.com"``.

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid email address.

        Example:
            >>> client = ObscuraLensClient()
            >>> res = client.email("user@example.com")   # doctest: +SKIP
        """
        return self.lookup('email', target)

    def domain(self, target: str) -> LookupResult:
        """
        Look up a domain (registration, DNS posture, CT logs, archives).

        ``GET /api/lookup/domain/{target}``

        Args:
            target: domain name, e.g. ``"example.com"``.

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid domain.

        Example:
            >>> client = ObscuraLensClient()
            >>> res = client.domain("example.com")   # doctest: +SKIP
        """
        return self.lookup('domain', target)

    def url(self, target: str) -> LookupResult:
        """
        Look up a URL (redirects, urlscan, archives, safety verdicts).

        ``GET /api/lookup/url/{target}``

        Args:
            target: full URL with scheme, e.g.
                ``"https://example.com/page"``.

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid URL (a scheme is required).

        Example:
            >>> client = ObscuraLensClient()
            >>> res = client.url("https://example.com/page")   # doctest: +SKIP
        """
        return self.lookup('url', target)

    def crypto(self, target: str) -> LookupResult:
        """
        Look up a BTC/ETH/LTC/DOGE address (balances, activity).

        ``GET /api/lookup/crypto/{target}``

        Args:
            target: crypto address, e.g.
                ``"1BoatSLRHtKN42kdutzZbHwYQeMwfQ7HNo"``.

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: unrecognised address format.

        Example:
            >>> client = ObscuraLensClient()
            >>> res = client.crypto("1BoatSLRHtKN42kdutzZbHwYQeMwfQ7HNo")   # doctest: +SKIP
        """
        return self.lookup('crypto', target)

    def hash_(self, target: str) -> LookupResult:
        """
        Look up a file hash (malware family, file names, detections).

        ``GET /api/lookup/hash/{target}``

        Args:
            target: MD5/SHA1/SHA256 digest, e.g.
                ``"44d88612fea8a8f36de82e1278abb02f"``.

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid digest shape.

        Example:
            >>> client = ObscuraLensClient()
            >>> res = client.hash_("44d88612fea8a8f36de82e1278abb02f")   # doctest: +SKIP
        """
        return self.lookup('hash', target)

    def cve(self, target: str) -> LookupResult:
        """
        Look up a CVE (CVSS, affected products, EPSS probability).

        ``GET /api/lookup/cve/{target}``

        Args:
            target: CVE id, e.g. ``"CVE-2021-44228"``.

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid CVE id.

        Example:
            >>> client = ObscuraLensClient()
            >>> res = client.cve("CVE-2021-44228")   # doctest: +SKIP
        """
        return self.lookup('cve', target)

    def asn(self, target: str) -> LookupResult:
        """
        Look up an AS number (holder, prefixes, peers).

        ``GET /api/lookup/asn/{target}``

        Args:
            target: AS number, e.g. ``"AS15169"``.

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid AS number.

        Example:
            >>> client = ObscuraLensClient()
            >>> res = client.asn("AS15169")   # doctest: +SKIP
        """
        return self.lookup('asn', target)

    def mac(self, target: str) -> LookupResult:
        """
        Look up a MAC address (vendor from the offline IEEE OUI pack).

        ``GET /api/lookup/mac/{target}``

        Args:
            target: MAC in colon/dash/dot notation, e.g.
                ``"b8:27:eb:aa:bb:cc"``.

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid MAC address.

        Example:
            >>> client = ObscuraLensClient()
            >>> res = client.mac("b8:27:eb:aa:bb:cc")   # doctest: +SKIP
        """
        return self.lookup('mac', target)

    def iban(self, target: str) -> LookupResult:
        """
        Look up an IBAN (checksum, issuing bank, country structure).

        ``GET /api/lookup/iban/{target}``

        Args:
            target: IBAN, e.g. ``"DE89370400440532013000"``.

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid IBAN (mod-97 checksum is checked
                server-side before any source is contacted).

        Example:
            >>> client = ObscuraLensClient()
            >>> res = client.iban("DE89370400440532013000")   # doctest: +SKIP
        """
        return self.lookup('iban', target)

    def imei(self, target: str) -> LookupResult:
        """
        Look up an IMEI (TAC decomposition, manufacturer, Luhn validity).

        ``GET /api/lookup/imei/{target}``

        Args:
            target: IMEI, e.g. ``"356938035643809"``.

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid IMEI (Luhn checked server-side).

        Example:
            >>> client = ObscuraLensClient()
            >>> res = client.imei("356938035643809")   # doctest: +SKIP
        """
        return self.lookup('imei', target)

    def coords(self, target: str) -> LookupResult:
        """
        Look up coordinates (every format, reverse geocode, elevation).

        ``GET /api/lookup/coords/{target}``

        Args:
            target: coordinates, e.g. ``"48.8584, 2.2945"``.

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: unrecognised coordinate format.

        Example:
            >>> client = ObscuraLensClient()
            >>> res = client.coords("48.8584, 2.2945")   # doctest: +SKIP
        """
        return self.lookup('coords', target)

    def vin(self, target: str) -> LookupResult:
        """
        Look up a vehicle identification number (WMI manufacturer, region,
        model-year decode, offline VIN pack).

        ``GET /api/lookup/vin/{target}``

        Args:
            target: 17-character VIN, e.g. ``"1HGCM82633A004352"``.

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult` with fields
            such as ``manufacturer``, ``country``, ``model_year``.

        Raises:
            BadRequestError: invalid VIN shape.

        Example:
            >>> client = ObscuraLensClient()
            >>> res = client.vin("1HGCM82633A004352")   # doctest: +SKIP
        """
        return self.lookup('vin', target)

    def flight(self, target: str) -> LookupResult:
        """
        Look up a flight (IATA number, route airports, scheduled and
        actual times, live position when airborne).

        ``GET /api/lookup/flight/{target}``

        Args:
            target: flight designator, e.g. ``"BA117"``.

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid flight designator.

        Example:
            >>> client = ObscuraLensClient()
            >>> res = client.flight("BA117")   # doctest: +SKIP
        """
        return self.lookup('flight', target)

    def mmsi(self, target: str) -> LookupResult:
        """
        Look up a vessel's MMSI (flag state, MID decode, name, course,
        live AIS position when in range).

        ``GET /api/lookup/mmsi/{target}``

        Args:
            target: 9-digit MMSI, e.g. ``"366982610"``.

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid MMSI shape.

        Example:
            >>> client = ObscuraLensClient()
            >>> res = client.mmsi("366982610")   # doctest: +SKIP
        """
        return self.lookup('mmsi', target)

    def app(self, target: str) -> LookupResult:
        """
        Look up a software package / app identifier (registry probes for
        npm, PyPI, crates.io, Docker Hub and friends).

        ``GET /api/lookup/app/{target}``

        Args:
            target: package identifier, e.g. ``"left-pad@1.3.0"`` or a
                plain name.

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid package identifier.

        Example:
            >>> client = ObscuraLensClient()
            >>> res = client.app("requests")   # doctest: +SKIP
        """
        return self.lookup('app', target)

    def package(self, target: str) -> LookupResult:
        """
        Alias for :meth:`app` — the software-package sensor.

        The web API's kind name is ``app``; this spelling exists for
        callers who find ``package`` more natural.

        ``GET /api/lookup/app/{target}``

        Args:
            target: package identifier (see :meth:`app`).

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid package identifier.

        Example:
            >>> client = ObscuraLensClient()
            >>> res = client.package("left-pad")   # doctest: +SKIP
        """
        return self.lookup('app', target)

    def bssid(self, target: str) -> LookupResult:
        """
        Look up a wireless access point BSSID (OUI vendor, observed
        location hints from crowd-sourced databases).

        ``GET /api/lookup/bssid/{target}``

        Args:
            target: BSSID in colon notation, e.g.
            ``"b8:27:eb:aa:bb:cc"`` — the AP MAC, not a client MAC.

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: invalid BSSID.

        Example:
            >>> client = ObscuraLensClient()
            >>> res = client.bssid("b8:27:eb:aa:bb:cc")   # doctest: +SKIP
        """
        return self.lookup('bssid', target)

    def plate(self, target: str) -> LookupResult:
        """
        Look up a licence plate (country/state format detection from the
        offline plate-formats pack, region context).

        ``GET /api/lookup/plate/{target}``

        Args:
            target: plate value, e.g. ``"B-AB 1234"``.

        Returns:
            :class:`~obscuralens.sdk.models.LookupResult`.

        Raises:
            BadRequestError: unrecognised plate format.

        Example:
            >>> client = ObscuraLensClient()
            >>> res = client.plate("B-AB 1234")   # doctest: +SKIP
        """
        return self.lookup('plate', target)

    # ------------------------------------------------------------------
    # Investigation / risk / analysis
    # ------------------------------------------------------------------

    def investigate(self, target: str, pivot: bool = True
                    ) -> InvestigationReport:
        """
        Auto-detect a target's kind and follow bounded pivots.

        ``GET /api/investigate?target=...&pivot=true``

        Pivots (depth 1): email -> its domain; domain -> A-record IPs;
        ip -> PTR hostname and InternetDB CVEs; url -> its host.

        Args:
            target: any supported kind value.
            pivot: follow related lookups (False = primary lookup only).

        Returns:
            An :class:`~obscuralens.sdk.models.InvestigationReport` with
            per-kind :class:`~obscuralens.sdk.models.LookupResult` envelopes,
            entities and links.

        Raises:
            BadRequestError: unknown target type.

        Example:
            >>> client = ObscuraLensClient()
            >>> report = client.investigate("example.com")   # doctest: +SKIP
            >>> report.summary()                              # doctest: +SKIP
            'domain example.com: 2 lookup(s), 9 entities, 8 link(s)'
        """
        payload = self._request('GET', '/api/investigate',
                                params={'target': target, 'pivot': pivot})
        return InvestigationReport.from_dict(payload)

    def risk(self, kind: str, target: str) -> RiskReport:
        """
        Run a lookup with explainable heuristic risk scoring attached.

        ``GET /api/risk/{kind}/{target}``

        Args:
            kind: tracker kind (see :meth:`lookup`).
            target: the indicator value.

        Returns:
            A :class:`~obscuralens.sdk.models.RiskReport` — ``score``
            (0-100), ``band`` (clean/low/medium/high/critical),
            ``signals`` (weighted explanations) and the underlying
            envelope as ``.lookup``.

        Raises:
            ValueError: unknown kind.
            BadRequestError: invalid target.

        Example:
            >>> client = ObscuraLensClient()
            >>> report = client.risk("domain", "example.com")   # doctest: +SKIP
            >>> report.is_high_or_worse()                        # doctest: +SKIP
            False
        """
        kind = str(kind or '').strip().lower()
        if kind not in KINDS:
            raise ValueError(
                f'unknown kind {kind!r} — expected one of {", ".join(KINDS)}')
        path = self._path('/api/risk/{0}/{1}', kind, target)
        payload = self._request('GET', path)
        return RiskReport.from_dict(payload, kind=kind, target=target)

    def timeline(self, target: Optional[str] = None,
                 limit: int = 100) -> Timeline:
        """
        Chronological event timeline across stored lookup history.

        ``GET /api/timeline?target=...&limit=100``

        Args:
            target: optional substring filter on stored values
                (case-insensitive).
            limit: maximum events kept (most recent kept when capping).

        Returns:
            A :class:`~obscuralens.sdk.models.Timeline` — events sorted
            oldest -> newest with ``first``/``last``/``span_days``.

        Example:
            >>> client = ObscuraLensClient()
            >>> timeline = client.timeline(limit=50)   # doctest: +SKIP
            >>> timeline.events[0].target              # doctest: +SKIP
            '8.8.8.8'
        """
        params: Dict[str, Any] = {}
        if target is not None:
            params['target'] = target
        params['limit'] = limit
        payload = self._request('GET', '/api/timeline', params=params)
        return Timeline.from_dict(payload)

    def correlate(self, limit: Optional[int] = None) -> CorrelationResult:
        """
        Correlation graph, clusters and bridge entities from history.

        ``GET /api/correlate?limit=...``

        Args:
            limit: how many history rows to consider (``None`` = the
                server's ``app.correlation_max_history``, default 500).

        Returns:
            A :class:`~obscuralens.sdk.models.CorrelationResult` with
            entities, links, clusters and bridges.

        Example:
            >>> client = ObscuraLensClient()
            >>> graph = client.correlate()           # doctest: +SKIP
            >>> graph.largest_cluster().size         # doctest: +SKIP
            7
        """
        params: Dict[str, Any] = {}
        if limit is not None:
            params['limit'] = limit
        payload = self._request('GET', '/api/correlate', params=params)
        return CorrelationResult.from_dict(payload)

    def correlate_pair(self, a: str, b: str) -> PairComparison:
        """
        Shared-infrastructure comparison between two targets.

        ``GET /api/correlate/pair?a=...&b=...``

        Args:
            a: first target value (e.g. a domain).
            b: second target value.

        Returns:
            A :class:`~obscuralens.sdk.models.PairComparison` with the
            shared entities, connection count and ``related`` verdict.

        Example:
            >>> client = ObscuraLensClient()
            >>> pair = client.correlate_pair("8.8.8.8", "dns.google")   # doctest: +SKIP
            >>> pair.is_related()                                       # doctest: +SKIP
            True
        """
        payload = self._request('GET', '/api/correlate/pair',
                                params={'a': a, 'b': b})
        return PairComparison.from_dict(payload)

    def intel(self, target: str) -> IntelVerdict:
        """
        Threat-intel verdict for an IP: Tor exit, blocklist feeds.

        ``GET /api/intel/{target}``

        Feed downloads are cached for 6 hours server-side.

        Args:
            target: IPv4/IPv6 address.

        Returns:
            An :class:`~obscuralens.sdk.models.IntelVerdict` with
            ``feeds`` (tor/spamhaus_drop/feodo/firehol_level1...),
            ``tor_exit`` and ``relay`` details.

        Raises:
            BadRequestError: invalid IP address.

        Example:
            >>> client = ObscuraLensClient()
            >>> verdict = client.intel("45.148.10.99")   # doctest: +SKIP
            >>> verdict.is_tor_exit()                    # doctest: +SKIP
            False
        """
        path = self._path('/api/intel/{0}', target)
        payload = self._request('GET', path)
        return IntelVerdict.from_dict(payload)

    # ------------------------------------------------------------------
    # Platform: sources, stats, kinds, history, keys, settings
    # ------------------------------------------------------------------

    def sources(self) -> Dict[str, Dict[str, str]]:
        """
        Source catalogues for every kind (``GET /api/sources``).

        Returns:
            ``{kind: {source_name: description}}`` — kinds without a
            published catalogue (none today) map to an empty dict.

        Example:
            >>> client = ObscuraLensClient()
            >>> catalog = client.sources()                     # doctest: +SKIP
            >>> sorted(catalog['ip'])[:2]                      # doctest: +SKIP
            ['ipwho.is', 'ipwhois.app']
        """
        payload = self._request('GET', '/api/sources')
        if isinstance(payload, dict):
            return {str(kind): (dict(value) if isinstance(value, dict) else {})
                    for kind, value in payload.items()}
        return {}

    def sources_health(self) -> List[SourceHealthEntry]:
        """
        Per-source health rows (success/failure counts, breakers).

        There is no dedicated health endpoint — this convenience method
        calls ``GET /api/stats`` and extracts its ``source_health`` block
        (the same rows the CLI's ``sources health`` command shows).

        Returns:
            A list of :class:`~obscuralens.sdk.models.SourceHealthEntry`
            with ``reliability`` and ``state`` ('healthy' / 'tripped' /
            'untested').

        Example:
            >>> client = ObscuraLensClient()
            >>> rows = client.sources_health()            # doctest: +SKIP
            >>> rows[0].summary()                          # doctest: +SKIP
            'ipwhois.app [ip]: 99.5% over 200 calls (healthy)'
        """
        payload = self._request('GET', '/api/stats')
        rows = payload.get('source_health') if isinstance(payload, dict) else None
        return [SourceHealthEntry.from_dict(item)
                for item in rows or [] if isinstance(item, dict)]

    def stats(self) -> StatsSummary:
        """
        Database, cache, network and source-health statistics.

        ``GET /api/stats``

        Returns:
            A :class:`~obscuralens.sdk.models.StatsSummary` (dict-backed:
            ``.database``, ``.cache``, ``.network`` plus parsed
            ``.source_health`` rows and headline accessors).

        Example:
            >>> client = ObscuraLensClient()
            >>> summary = client.stats()          # doctest: +SKIP
            >>> summary.total_lookups             # doctest: +SKIP
            512
        """
        payload = self._request('GET', '/api/stats')
        return StatsSummary.from_dict(payload)

    def kinds(self) -> List[KindInfo]:
        """
        Registry of every target kind with labels and source lists.

        ``GET /api/kinds``

        Returns:
            A list of :class:`~obscuralens.sdk.models.KindInfo` — one per
            kind, all 14, each with its ``sources`` list.

        Example:
            >>> client = ObscuraLensClient()
            >>> kinds = client.kinds()                     # doctest: +SKIP
            >>> [info.kind for info in kinds][:3]          # doctest: +SKIP
            ['ip', 'phone', 'username']
        """
        payload = self._request('GET', '/api/kinds')
        items = payload if isinstance(payload, list) else []
        return [KindInfo.from_dict(item) for item in items
                if isinstance(item, dict)]

    def history(self, kind: Optional[str] = None, q: Optional[str] = None,
                limit: int = 100) -> HistoryResult:
        """
        Search stored lookup history.

        ``GET /api/history?kind=...&q=...&limit=100``

        Args:
            kind: restrict rows to one target kind.
            q: case-insensitive substring match on the stored value.
            limit: cap rows (server clamps to 1..500).

        Returns:
            A :class:`~obscuralens.sdk.models.HistoryResult` with parsed
            :class:`~obscuralens.sdk.models.HistoryItem` rows.

        Example:
            >>> client = ObscuraLensClient()
            >>> result = client.history(kind="ip", q="8.8.8", limit=50)   # doctest: +SKIP
            >>> result.count                                              # doctest: +SKIP
            3
        """
        params: Dict[str, Any] = {}
        if kind is not None:
            params['kind'] = kind
        if q is not None:
            params['q'] = q
        params['limit'] = limit
        payload = self._request('GET', '/api/history', params=params)
        return HistoryResult.from_dict(payload)

    def keys(self) -> List[ServiceKey]:
        """
        Which keyed services are configured (values never returned).

        ``GET /api/keys``

        Returns:
            A list of :class:`~obscuralens.sdk.models.ServiceKey` — one
            per supported service (shodan, haveibeenpwned, virustotal...),
            each with a ``configured`` flag and description.

        Example:
            >>> client = ObscuraLensClient()
            >>> services = client.keys()                        # doctest: +SKIP
            >>> [s.service for s in services if s.configured]   # doctest: +SKIP
            ['shodan']
        """
        payload = self._request('GET', '/api/keys')
        items = payload if isinstance(payload, list) else []
        return [ServiceKey.from_dict(item) for item in items
                if isinstance(item, dict)]

    def set_key(self, service: str, key: str) -> Dict[str, Any]:
        """
        Store an API key for a service.

        ``POST /api/keys/{service}`` with body ``{"key": "..."}``

        The key lands in the server's git-ignored ``config/secrets.yaml``
        and is never echoed back.

        Args:
            service: service name (see :meth:`keys` for the list).
            key: the API key value (non-empty).

        Returns:
            ``{'ok': True, 'service': ..., 'configured': True}``.

        Raises:
            BadRequestError: unknown service or empty key.
            ServerError: the secrets file could not be written.

        Example:
            >>> client = ObscuraLensClient()
            >>> client.set_key("shodan", "KEY...")   # doctest: +SKIP
            {'ok': True, 'service': 'shodan', 'configured': True}
        """
        path = self._path('/api/keys/{0}', service)
        payload = self._request('POST', path, json_body={'key': key})
        return payload if isinstance(payload, dict) else {}

    def clear_key(self, service: str) -> Dict[str, Any]:
        """
        Remove a stored API key.

        ``DELETE /api/keys/{service}``

        Args:
            service: service name (see :meth:`keys`).

        Returns:
            ``{'ok': True, 'service': ..., 'configured': False}``.

        Raises:
            BadRequestError: unknown service.
            ServerError: the secrets file could not be written.

        Example:
            >>> client = ObscuraLensClient()
            >>> client.clear_key("shodan")   # doctest: +SKIP
            {'ok': True, 'service': 'shodan', 'configured': False}
        """
        path = self._path('/api/keys/{0}', service)
        payload = self._request('DELETE', path)
        return payload if isinstance(payload, dict) else {}

    def settings(self) -> Dict[str, Any]:
        """
        Runtime application settings as dotted-path keys.

        ``GET /api/settings``

        Secret and filesystem-path settings are never exposed; API keys
        live under :meth:`keys`.

        Returns:
            ``{'settings': {'app.cache_ttl': 3600, ...}, 'version': ...,
            'note': ...}``.

        Example:
            >>> client = ObscuraLensClient()
            >>> snapshot = client.settings()                # doctest: +SKIP
            >>> snapshot['settings']['app.max_workers']     # doctest: +SKIP
            12
        """
        payload = self._request('GET', '/api/settings')
        return payload if isinstance(payload, dict) else {}

    def update_settings(self, path: str, value: Any) -> Dict[str, Any]:
        """
        Update one runtime setting (in-memory only, not persisted).

        ``POST /api/settings`` with body ``{"path": ..., "value": ...}``

        Args:
            path: dotted setting path, e.g. ``"app.cache_ttl"`` — must
                start with ``app.`` and not be on the server blocklist.
            value: the new value (coerced to the setting's type).

        Returns:
            ``{'ok': True, 'path': ..., 'value': <coerced>}``.

        Raises:
            BadRequestError: unknown/protected path or type mismatch.

        Example:
            >>> client = ObscuraLensClient()
            >>> client.update_settings("app.max_workers", 16)   # doctest: +SKIP
            {'ok': True, 'path': 'app.max_workers', 'value': 16}
        """
        payload = self._request('POST', '/api/settings',
                                json_body={'path': path, 'value': value})
        return payload if isinstance(payload, dict) else {}

    # ------------------------------------------------------------------
    # Cases
    # ------------------------------------------------------------------

    def cases(self) -> List[Case]:
        """
        Every investigation case (archived included) with row counts.

        ``GET /api/cases``

        Returns:
            A list of :class:`~obscuralens.sdk.models.Case` — list rows
            carry ``item_count``/``note_count``/``tag_count`` and
            ``items_by_kind`` but not the full items/notes arrays (use
            :meth:`case` for those).

        Example:
            >>> client = ObscuraLensClient()
            >>> for case in client.cases():          # doctest: +SKIP
            ...     print(case.summary())            # doctest: +SKIP
            #3 acme-phishing [open]: 4 items, 2 notes, 1 tags
        """
        payload = self._request('GET', '/api/cases')
        items = payload if isinstance(payload, list) else []
        return [Case.from_dict(item) for item in items
                if isinstance(item, dict)]

    def case(self, case_id: int) -> Case:
        """
        One case with its items, notes and tags.

        ``GET /api/cases/{case_id}``

        Args:
            case_id: numeric case id.

        Returns:
            A fully populated :class:`~obscuralens.sdk.models.Case`.

        Raises:
            NotFoundError: unknown case id.

        Example:
            >>> client = ObscuraLensClient()
            >>> case = client.case(1)                  # doctest: +SKIP
            >>> case.items[0].value                    # doctest: +SKIP
            '45.148.10.99'
        """
        path = self._path('/api/cases/{0}', case_id)
        payload = self._request('GET', path)
        return Case.from_dict(payload)

    def create_case(self, name: str, description: str = '') -> Case:
        """
        Create a case.

        ``POST /api/cases`` with body ``{"name": ..., "description": ...}``

        Duplicate names are not an error server-side: the existing case's
        row comes back — check ``.raw`` for an ``'error': 'case exists'``
        marker when that matters.

        Args:
            name: case name (required, non-empty).
            description: free-form description.

        Returns:
            The created :class:`~obscuralens.sdk.models.Case`.

        Raises:
            BadRequestError: missing/blank name.

        Example:
            >>> client = ObscuraLensClient()
            >>> case = client.create_case("acme-phishing",   # doctest: +SKIP
            ...                           "Brand abuse")     # doctest: +SKIP
            >>> case.id                                      # doctest: +SKIP
            3
        """
        payload = self._request('POST', '/api/cases',
                                json_body={'name': name,
                                           'description': description})
        return Case.from_dict(payload)

    def update_case(self, case_id: int, status: str) -> Case:
        """
        Update a case's status (close, archive or reopen).

        ``PATCH /api/cases/{case_id}`` with body ``{"status": ...}``

        Args:
            case_id: numeric case id.
            status: one of ``"open"``, ``"closed"``, ``"archived"``.

        Returns:
            The updated :class:`~obscuralens.sdk.models.Case`.

        Raises:
            ValueError: status is not one of the three valid names.
            BadRequestError: invalid status (server-side check).
            NotFoundError: unknown case id.

        Example:
            >>> client = ObscuraLensClient()
            >>> client.update_case(1, "closed").status   # doctest: +SKIP
            'closed'
        """
        status = str(status or '').strip().lower()
        if status not in CASE_STATUSES:
            raise ValueError(
                f'status must be one of {", ".join(CASE_STATUSES)} — '
                f'got {status!r}')
        path = self._path('/api/cases/{0}', case_id)
        payload = self._request('PATCH', path, json_body={'status': status})
        return Case.from_dict(payload)

    def add_case_item(self, case_id: int, target: str, kind: str = 'auto',
                      note: Optional[str] = None) -> CaseItem:
        """
        Add an indicator to a case.

        ``POST /api/cases/{case_id}/items`` with body
        ``{"kind": ..., "target": ..., "note": ...}``

        Args:
            case_id: numeric case id.
            target: the indicator value (required, non-empty).
            kind: tracker kind, or ``"auto"`` to detect from the value.
            note: optional free-form note attached to the item.

        Returns:
            The created :class:`~obscuralens.sdk.models.CaseItem`.

        Raises:
            BadRequestError: blank target, unknown kind, closed/archived
                case, or duplicate item.

        Example:
            >>> client = ObscuraLensClient()
            >>> item = client.add_case_item(1, "45.148.10.99",   # doctest: +SKIP
            ...                             kind="ip",           # doctest: +SKIP
            ...                             note="kit host")     # doctest: +SKIP
            >>> item.value                                       # doctest: +SKIP
            '45.148.10.99'
        """
        body: Dict[str, Any] = {'kind': kind, 'target': target}
        if note is not None:
            body['note'] = note
        path = self._path('/api/cases/{0}/items', case_id)
        payload = self._request('POST', path, json_body=body)
        return CaseItem.from_dict(payload)

    def add_case_note(self, case_id: int, note: str) -> CaseNote:
        """
        Append a free-form note to a case.

        ``POST /api/cases/{case_id}/notes`` with body ``{"note": ...}``

        Args:
            case_id: numeric case id.
            note: note text (required, non-empty).

        Returns:
            The created :class:`~obscuralens.sdk.models.CaseNote`.

        Raises:
            BadRequestError: blank note or unknown case.

        Example:
            >>> client = ObscuraLensClient()
            >>> entry = client.add_case_note(1, "GSB flagged the URL.")   # doctest: +SKIP
            >>> entry.text                                                # doctest: +SKIP
            'GSB flagged the URL today.'
        """
        path = self._path('/api/cases/{0}/notes', case_id)
        payload = self._request('POST', path, json_body={'note': note})
        return CaseNote.from_dict(payload)

    def add_case_tag(self, case_id: int, tag: str) -> Dict[str, Any]:
        """
        Add a tag to a case.

        ``POST /api/cases/{case_id}/tags`` with body ``{"tag": ...}``

        Args:
            case_id: numeric case id.
            tag: tag name (required, non-empty).

        Returns:
            The server's response — the case's tag list (or a tag record;
            check ``.raw`` shapes if your server version differs).

        Raises:
            BadRequestError: blank tag or unknown case.

        Example:
            >>> client = ObscuraLensClient()
            >>> client.add_case_tag(1, "phishing")   # doctest: +SKIP
            ['phishing', 'brand-abuse']
        """
        path = self._path('/api/cases/{0}/tags', case_id)
        payload = self._request('POST', path, json_body={'tag': tag})
        return payload

    # ------------------------------------------------------------------
    # Watchlist
    # ------------------------------------------------------------------

    def watch(self) -> List[WatchEntry]:
        """
        Every watched target.

        ``GET /api/watch``

        Returns:
            A list of :class:`~obscuralens.sdk.models.WatchEntry` with
            kind, label, snapshot count and ``last_checked``.

        Example:
            >>> client = ObscuraLensClient()
            >>> entries = client.watch()                  # doctest: +SKIP
            >>> entries[0].summary()                      # doctest: +SKIP
            'domain example.com: 3 snapshot(s), corp site'
        """
        payload = self._request('GET', '/api/watch')
        items = payload if isinstance(payload, list) else []
        return [WatchEntry.from_dict(item) for item in items
                if isinstance(item, dict)]

    def add_watch(self, target: str, label: str = '') -> Dict[str, Any]:
        """
        Add a target to the watchlist.

        ``POST /api/watch`` with body ``{"target": ..., "label": ...}``

        Args:
            target: the value to watch (kind auto-detected server-side).
            label: optional human label.

        Returns:
            ``{'id': <watch id>}`` for the new entry.

        Raises:
            BadRequestError: invalid/duplicate target.

        Example:
            >>> client = ObscuraLensClient()
            >>> client.add_watch("example.com", "corp site")   # doctest: +SKIP
            {'id': 3}
        """
        payload = self._request('POST', '/api/watch',
                                json_body={'target': target,
                                           'label': label})
        return payload if isinstance(payload, dict) else {}

    def remove_watch(self, identifier: Union[int, str]) -> Dict[str, Any]:
        """
        Remove a watch by numeric id or target string.

        ``DELETE /api/watch/{identifier}``

        Args:
            identifier: the watch id (int) or the watched target value
                (str).

        Returns:
            ``{'removed': <identifier>}``.

        Raises:
            NotFoundError: no matching watch.

        Example:
            >>> client = ObscuraLensClient()
            >>> client.remove_watch(3)                  # doctest: +SKIP
            {'removed': 3}
            >>> client.remove_watch("example.com")      # doctest: +SKIP
            {'removed': 'example.com'}
        """
        path = self._path('/api/watch/{0}', identifier)
        payload = self._request('DELETE', path)
        return payload if isinstance(payload, dict) else {}

    def check_watch(self, identifier: Optional[str] = None
                    ) -> List[WatchDiff]:
        """
        Run and diff one watch (id or target) or every watch.

        ``POST /api/watch/check?identifier=...``

        Args:
            identifier: watch id or target string; ``None`` checks every
                watched target.

        Returns:
            A list of :class:`~obscuralens.sdk.models.WatchDiff` — one
            change record per checked watch (``added``/``removed``/
            ``changed`` field maps, ``is_first`` for new watches).

        Example:
            >>> client = ObscuraLensClient()
            >>> diffs = client.check_watch("example.com")   # doctest: +SKIP
            >>> diffs[0].has_changes()                       # doctest: +SKIP
            True
        """
        params: Dict[str, Any] = {}
        if identifier is not None:
            params['identifier'] = identifier
        payload = self._request('POST', '/api/watch/check', params=params)
        items = payload if isinstance(payload, list) else []
        return [WatchDiff.from_dict(item) for item in items
                if isinstance(item, dict)]

    def diff(self, kind: str, target: str) -> DiffReport:
        """
        Snapshot diff for one watched target (latest two snapshots).

        ``GET /api/diff/{kind}/{target}``

        Args:
            kind: the target's kind — a real kind or ``"auto"``.
            target: the watched value.

        Returns:
            A :class:`~obscuralens.sdk.models.DiffReport` with
            ``added``/``removed``/``changed`` field sets; a target with
            fewer than two snapshots returns ``changed_any=False`` and a
            helpful ``note``.

        Raises:
            BadRequestError: unknown kind.
            NotFoundError: target is not on the watchlist.
            ServerError: corrupt snapshot data.

        Example:
            >>> client = ObscuraLensClient()
            >>> report = client.diff("domain", "example.com")   # doctest: +SKIP
            >>> report.changed                                   # doctest: +SKIP
            {'registrar': {'from': 'Old', 'to': 'New'}}
        """
        path = self._path('/api/diff/{0}/{1}', kind, target)
        payload = self._request('GET', path)
        return DiffReport.from_dict(payload)

    # ------------------------------------------------------------------
    # Export / reports / patterns
    # ------------------------------------------------------------------

    def export(self, fmt: str, target: str, pivot: bool = True
               ) -> Dict[str, Any]:
        """
        Export an investigation entity graph as text.

        ``GET /api/export/{fmt}/{target}?pivot=true``

        Args:
            fmt: one of ``graphml``, ``gexf``, ``dot``, ``jsonl``, ``csv``.
            target: any auto-detectable target value.
            pivot: run related lookups before rendering (False = primary
                entity graph only).

        Returns:
            ``{'target', 'format', 'graph': <text>, 'entities': n,
            'links': n}`` — save ``graph`` with the matching extension for
            Gephi / yEd / Cytoscape / Graphviz.

        Raises:
            BadRequestError: unknown format or target type.

        Example:
            >>> client = ObscuraLensClient()
            >>> out = client.export("graphml", "example.com")   # doctest: +SKIP
            >>> open("graph.graphml", "w").write(out["graph"])  # doctest: +SKIP
        """
        fmt = str(fmt or '').strip().lower()
        if EXPORT_FORMATS and fmt not in EXPORT_FORMATS:
            raise ValueError(
                f'unknown export format {fmt!r} — expected one of '
                f'{", ".join(EXPORT_FORMATS)}')
        path = self._path('/api/export/{0}/{1}', fmt, target)
        payload = self._request('GET', path, params={'pivot': pivot})
        return payload if isinstance(payload, dict) else {}

    def report(self, kind: str, target: str, download: bool = False,
               save_to: Optional[str] = None) -> Dict[str, Any]:
        """
        Build a self-contained HTML investigation report for one target.

        ``GET /api/report/{kind}/{target}?download=false``

        Args:
            kind: tracker kind (see :meth:`lookup`).
            target: the indicator value.
            download: True to request the raw HTML document (the server
                adds an attachment header) instead of the JSON envelope.
            save_to: optional file path — when given, the HTML is written
                there and the returned dict carries ``saved_to``.

        Returns:
            JSON mode: ``{'kind', 'target', 'size', 'html'}``. Download
            mode (or ``save_to``): ``{'kind', 'target', 'size', 'html'}``
            or ``{'saved_to', 'size'}`` when written to disk.

        Raises:
            BadRequestError: unknown kind or invalid target.
            ServerError: report generation failed.
            MalformedResponseError: never — download mode bypasses the
                JSON parser.

        Example:
            >>> client = ObscuraLensClient()
            >>> out = client.report("domain", "example.com",
            ...                     save_to="report.html")   # doctest: +SKIP
            >>> out["saved_to"]                              # doctest: +SKIP
            'report.html'
        """
        kind = str(kind or '').strip().lower()
        if kind not in KINDS:
            raise ValueError(
                f'unknown kind {kind!r} — expected one of {", ".join(KINDS)}')
        path = self._path('/api/report/{0}/{1}', kind, target)
        if not download and save_to is None:
            payload = self._request('GET', path)
            return payload if isinstance(payload, dict) else {}
        response = self._send('GET', path, params={'download': True})
        html = response.text
        size = len(html)
        if save_to:
            destination = Path(save_to)
            destination.write_text(html, encoding='utf-8')
            return {'kind': kind, 'target': target, 'saved_to': str(destination),
                    'size': size}
        return {'kind': kind, 'target': target, 'size': size, 'html': html}

    def patterns(self, kind: str, target: str) -> PatternReport:
        """
        Pattern-of-life analysis for one target across stored history.

        ``GET /api/patterns?kind=...&target=...``

        Args:
            kind: the tracker kind whose history to analyse.
            target: the target value — a case-insensitive *substring*
                match, so ``'8.8.8'`` picks up every resolver-range row.

        Returns:
            A :class:`~obscuralens.sdk.models.PatternReport` with
            hour/weekday histograms, the 7x24 activity matrix, cadence
            statistics, bursts and verdict lines.

        Raises:
            BadRequestError: unknown kind.

        Example:
            >>> client = ObscuraLensClient()
            >>> pattern = client.patterns("ip", "45.148.10.99")   # doctest: +SKIP
            >>> pattern.peak_hour                                 # doctest: +SKIP
            14
        """
        payload = self._request('GET', '/api/patterns',
                                params={'kind': kind, 'target': target})
        return PatternReport.from_dict(payload)

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def alerts(self) -> AlertConfig:
        """
        Webhook-alert configuration plus the recent event log.

        ``GET /api/alerts``

        Returns:
            An :class:`~obscuralens.sdk.models.AlertConfig` —
            ``webhook_url``, whitelisted ``events``, ``enabled`` flag,
            the last 20 log entries and the canonical ``event_types``.

        Example:
            >>> client = ObscuraLensClient()
            >>> config = client.alerts()         # doctest: +SKIP
            >>> config.is_enabled()              # doctest: +SKIP
            False
        """
        payload = self._request('GET', '/api/alerts')
        return AlertConfig.from_dict(payload)

    def configure_alerts(self, webhook_url: str = '',
                         events: Optional[Sequence[str]] = None
                         ) -> AlertConfig:
        """
        Configure webhook alerts.

        ``POST /api/alerts`` with body ``{"webhook_url": ..., "events":
        [...]}``

        An empty URL disables notifications; the local event log keeps
        recording either way. Canonical events: ``lookup_failed``,
        ``watch_diff``, ``risk_high``, ``source_tripped``, ``case_created``.

        Args:
            webhook_url: webhook endpoint (Slack-compatible
                ``{"text": ...}`` POSTs) — empty string disables delivery.
            events: event names to whitelist; ``None`` whitelists every
                event type.

        Returns:
            The new :class:`~obscuralens.sdk.models.AlertConfig`.

        Raises:
            BadRequestError: unknown event names.

        Example:
            >>> client = ObscuraLensClient()
            >>> config = client.configure_alerts(                     # doctest: +SKIP
            ...     "https://hooks.example/ol", ["risk_high"])        # doctest: +SKIP
            >>> config.events                                         # doctest: +SKIP
            ['risk_high']
        """
        body: Dict[str, Any] = {'webhook_url': webhook_url}
        if events is not None:
            body['events'] = list(events)
        payload = self._request('POST', '/api/alerts', json_body=body)
        return AlertConfig.from_dict(payload)

    def test_alert(self) -> Dict[str, Any]:
        """
        Send a test notification through the configured webhook.

        ``POST /api/alerts/test``

        Returns:
            ``{'ok': bool, 'status': int, 'detail': str}`` — a dead
            webhook is reported as ``ok: False``, not raised as an error.

        Example:
            >>> client = ObscuraLensClient()
            >>> client.test_alert()   # doctest: +SKIP
            {'ok': True, 'status': 200, 'detail': 'delivered'}
        """
        payload = self._request('POST', '/api/alerts/test')
        return payload if isinstance(payload, dict) else {}

    # ------------------------------------------------------------------
    # Analyst toolbox
    # ------------------------------------------------------------------

    def encodings(self, text: str) -> ToolboxResult:
        """
        Encode one input into every scheme plus a full digest panel.

        ``GET /api/tools/encodings?text=...`` — all local computation.

        Args:
            text: the input to encode.

        Returns:
            A :class:`~obscuralens.sdk.models.ToolboxResult` — the raw
            payload carries ``encodings`` (hex/base32/base64/base85/url/
            html/rot13/binary/morse/...) and ``hashes`` (MD5 -> SHA-3 /
            BLAKE2, CRC32).

        Raises:
            BadRequestError: encoding failed.

        Example:
            >>> client = ObscuraLensClient()
            >>> out = client.encodings("admin:password")   # doctest: +SKIP
            >>> out.get("encodings")["base64"]              # doctest: +SKIP
            'YWRtaW46cGFzc3dvcmQ='
        """
        payload = self._request('GET', '/api/tools/encodings',
                                params={'text': text})
        return ToolboxResult.from_dict(payload, tool='encodings')

    def decode(self, value: str, scheme: str = 'auto') -> ToolboxResult:
        """
        Decode a value with one scheme, or rank every scheme's attempt.

        ``POST /api/tools/decode`` with body ``{"scheme": ..., "value":
        ...}``

        Args:
            value: the encoded input (required, non-empty).
            scheme: canonical scheme name (``hex``, ``base32``,
                ``base64``, ``base85``, ``url_percent``, ``html_entity``,
                ``rot13``, ``caesar``, ``binary``, ``decimal``,
                ``reversed``, ``morse``, ``gzip``) or ``"auto"`` for the
                ranked candidate list.

        Returns:
            A :class:`~obscuralens.sdk.models.ToolboxResult` — ``result``
            for a chosen scheme, ``candidates`` for auto mode.

        Raises:
            BadRequestError: blank value, unknown scheme or undecodable
                input.

        Example:
            >>> client = ObscuraLensClient()
            >>> out = client.decode("68656c6c6f", scheme="hex")   # doctest: +SKIP
            >>> out.get("result")                                  # doctest: +SKIP
            'hello'
        """
        payload = self._request('POST', '/api/tools/decode',
                                json_body={'scheme': scheme, 'value': value})
        return ToolboxResult.from_dict(payload, tool='decode')

    def jwt(self, token: str) -> ToolboxResult:
        """
        Decode and inspect a JWT (no signature verification — local).

        ``GET /api/tools/jwt?token=...``

        Args:
            token: the compact JWS token string.

        Returns:
            A :class:`~obscuralens.sdk.models.ToolboxResult` — the raw
            payload carries ``header``, ``payload``, ``claims``,
            ``identifiers``, ``key_info``, ``token_stats`` and ``notes``.

        Raises:
            BadRequestError: malformed token.

        Example:
            >>> client = ObscuraLensClient()
            >>> out = client.jwt("eyJhbGciOiJIUzI1NiJ9.e30.x")   # doctest: +SKIP
            >>> out.get("header")                                 # doctest: +SKIP
            {'alg': 'HS256'}
        """
        payload = self._request('GET', '/api/tools/jwt',
                                params={'token': token})
        return ToolboxResult.from_dict(payload, tool='jwt')

    def hash_id(self, value: str) -> ToolboxResult:
        """
        Identify candidate hash formats for a digest-shaped string.

        ``GET /api/tools/hash-id?value=...``

        Args:
            value: the digest string to identify.

        Returns:
            A :class:`~obscuralens.sdk.models.ToolboxResult` — the raw
            payload carries ``candidates`` ranked by confidence
            (``[{name, confidence, length, charset, note}]``).

        Example:
            >>> client = ObscuraLensClient()
            >>> out = client.hash_id("44d88612fea8a8f36de82e1278abb02f")   # doctest: +SKIP
            >>> out.get("candidates")[0]["name"]                            # doctest: +SKIP
            'MD5'
        """
        payload = self._request('GET', '/api/tools/hash-id',
                                params={'value': value})
        return ToolboxResult.from_dict(payload, tool='hash-id')

    def coords_convert(self, value: str) -> ToolboxResult:
        """
        Parse coordinates (DD/DMS/DDM/UTM/MGRS) and convert to every format.

        ``POST /api/tools/coords`` with body ``{"value": ...}``

        Args:
            value: the coordinate string in any accepted syntax.

        Returns:
            A :class:`~obscuralens.sdk.models.ToolboxResult` — the raw
            payload carries ``latitude``, ``longitude``, ``decimal``,
            ``dms``, ``ddm``, ``utm``, ``mgrs``, ``geohash`` and
            ``maidenhead``.

        Raises:
            BadRequestError: unrecognised coordinate format.

        Example:
            >>> client = ObscuraLensClient()
            >>> out = client.coords_convert("48.8584, 2.2945")   # doctest: +SKIP
            >>> out.get("mgrs")                                   # doctest: +SKIP
            '31U DQ 48288 11087'
        """
        payload = self._request('POST', '/api/tools/coords',
                                json_body={'value': value})
        return ToolboxResult.from_dict(payload, tool='coords')

    def extract_entities(self, text: str) -> ToolboxResult:
        """
        Extract every OSINT pivot target from free text.

        ``POST /api/tools/extract`` with body ``{"text": ...}`` — all
        local regex + validator work, capped at 50 hits per category.

        Args:
            text: the free-form text to mine.

        Returns:
            A :class:`~obscuralens.sdk.models.ToolboxResult` — the raw
            payload carries ``emails``, ``urls``, ``domains``, ``ipv4``,
            ``ipv6``, ``hashes``, ``cves``, ``crypto_addresses``,
            ``macs``, ``ibans``, ``imeis``, ``coords``,
            ``phone_candidates``, ``user_handles``, ``tracking_ids`` and
            a ``summary`` block.

        Raises:
            BadRequestError: blank text.

        Example:
            >>> client = ObscuraLensClient()
            >>> out = client.extract_entities("Contact bob@evil.example")   # doctest: +SKIP
            >>> out.get("emails")                                            # doctest: +SKIP
            ['bob@evil.example']
        """
        payload = self._request('POST', '/api/tools/extract',
                                json_body={'text': text})
        return ToolboxResult.from_dict(payload, tool='extract')

    def squat(self, domain: str) -> ToolboxResult:
        """
        Generate and score typosquatting variants for a domain.

        ``POST /api/tools/squat`` with body ``{"domain": ...}`` — local
        generation only (omission, insertion, transposition, homoglyphs,
        bitsquatting, combo-squatting, TLD swaps...), capped at 300.

        Args:
            domain: the domain to mutate (validated server-side).

        Returns:
            A :class:`~obscuralens.sdk.models.ToolboxResult` — the raw
            payload carries ``domain``, ``count`` and ``variants``
            (``[{domain, category, risk, description}]`` sorted by risk).

        Raises:
            BadRequestError: invalid domain.

        Example:
            >>> client = ObscuraLensClient()
            >>> out = client.squat("example.com")            # doctest: +SKIP
            >>> out.get("variants")[0]["domain"]              # doctest: +SKIP
            'exmaple.com'
        """
        payload = self._request('POST', '/api/tools/squat',
                                json_body={'domain': domain})
        return ToolboxResult.from_dict(payload, tool='squat')

    def dorks(self, target: str, kind: Optional[str] = None) -> DorkReport:
        """
        Ready-to-open search-engine dorks for a target (v6.1).

        ``GET /api/tools/dorks?target=...&kind=...`` — the kind is
        auto-detected unless overridden, and every link is generated
        locally: the analyst stays in control of each active query
        (passive-first). Engines cover Google, Bing, DuckDuckGo, Yandex
        and GitHub code search.

        Args:
            target: the value to build dorks for (any supported kind).
            kind: optional kind override (e.g. ``'domain'`` to force the
                domain template set); ``None`` lets the server detect.

        Returns:
            A :class:`~obscuralens.sdk.models.DorkReport` — the link
            dicts (engine/label/query/url), the detected kind and the
            kinds that carry templates; ``.links()`` extracts the URLs.

        Raises:
            BadRequestError: blank target.

        Example:
            >>> client = ObscuraLensClient()
            >>> report = client.dorks("example.com")        # doctest: +SKIP
            >>> report.detected_kind                        # doctest: +SKIP
            'domain'
            >>> report.links()[0]                            # doctest: +SKIP
            'https://www.google.com/search?q=site%3Aexample.com'
        """
        params: Dict[str, Any] = {'target': target}
        if kind is not None:
            params['kind'] = kind
        payload = self._request('GET', '/api/tools/dorks', params=params)
        return DorkReport.from_dict(payload)

    def toolbox(self, tool: str, value: str) -> ToolboxResult:
        """
        Generic dispatcher for the analyst toolbox endpoints.

        Args:
            tool: one of ``encodings``, ``decode``, ``jwt``, ``hash-id``
                (aliases: ``hash_id``, ``hashid``), ``coords``,
                ``extract`` (alias: ``entity_extract``), ``squat`` — or
                any decode *scheme* name (``base64``, ``hex``, ...) which
                dispatches to :meth:`decode` with that scheme.
            value: the tool's input (text, token, digest, coordinate or
                domain).

        Returns:
            A :class:`~obscuralens.sdk.models.ToolboxResult` for the
            dispatched tool.

        Raises:
            ValueError: the tool name matches no toolbox endpoint.

        Example:
            >>> client = ObscuraLensClient()
            >>> out = client.toolbox("jwt", "eyJhbGciOi...")      # doctest: +SKIP
            >>> out = client.toolbox("base64", "aGVsbG8=")        # doctest: +SKIP
            >>> out.get("result")                                  # doctest: +SKIP
            'hello'
        """
        name = str(tool or '').strip().lower()
        aliases = {
            'hash_id': 'hash-id', 'hashid': 'hash-id',
            'entity_extract': 'extract', 'entities': 'extract',
            'encode': 'encodings', 'encoding': 'encodings',
            'coordinates': 'coords', 'coordinate': 'coords',
            'typosquat': 'squat', 'squats': 'squat',
        }
        name = aliases.get(name, name)
        if name == 'encodings':
            return self.encodings(value)
        if name == 'jwt':
            return self.jwt(value)
        if name == 'hash-id':
            return self.hash_id(value)
        if name == 'coords':
            return self.coords_convert(value)
        if name == 'extract':
            return self.extract_entities(value)
        if name == 'squat':
            return self.squat(value)
        if name == 'decode' or name in _DECODE_SCHEMES:
            return self.decode(value, scheme=name if name != 'decode' else 'auto')
        raise ValueError(
            f'unknown toolbox tool {tool!r} — expected one of '
            f'{", ".join(TOOLBOX_TOOLS)} or a decode scheme '
            f'({", ".join(_DECODE_SCHEMES)})')

    def exif(self, data: Union[bytes, str, Path],
             filename: Optional[str] = None) -> Dict[str, Any]:
        """
        Local EXIF / metadata analysis of an uploaded image.

        ``POST /api/tools/file/exif`` (multipart file upload)

        The bytes are analysed in-process by the server and never stored
        or forwarded — see :meth:`stego` for the entropy/LSB companion.

        Args:
            data: image bytes (JPEG, PNG, GIF, BMP, WebP) or a path to a
                file (``str``/``Path`` — read locally before uploading).
            filename: upload filename; defaults to the source path's
                basename for path inputs (or ``upload.bin`` for bytes) —
                the extension picks the content type header (up to 16 MB
                server-side).

        Returns:
            The parsed analysis dict — ``format``, ``size``, ``sha256``,
            ``camera``, ``gps`` (``coords`` ready for
            :meth:`coords`), ``timeline``, ``osint_notes``, ``exif`` and
            ``xmp`` blocks.

        Raises:
            TransportError / ApiError subclasses: upload failures.

        Example:
            >>> client = ObscuraLensClient()
            >>> out = client.exif("IMG_2031.jpg")   # doctest: +SKIP
            >>> out["gps"]["coords"]                # doctest: +SKIP
            '48.8584, 2.2945'
        """
        return self._analyse_upload('exif', data, filename)

    def stego(self, data: Union[bytes, str, Path],
              filename: Optional[str] = None) -> Dict[str, Any]:
        """
        Local steganography / entropy analysis of an uploaded file.

        ``POST /api/tools/file/stego`` (multipart file upload)

        PNG/BMP/GIF get LSB plane statistics; every format gets entropy
        profiling and embedded-file carving. Nothing is persisted.

        Args:
            data: file bytes or a path to a file (read before upload).
            filename: upload filename; defaults to the source path's
                basename for path inputs (or ``upload.bin`` for bytes) —
                the extension picks the content type header (up to 16 MB
                server-side).

        Returns:
            The parsed analysis dict — ``format``, ``summary``
            (``suspicion`` 0-100, ``verdict``, ``findings``), ``lsb``,
            ``entropy``, ``embedded_files`` and ``strings``.

        Raises:
            TransportError / ApiError subclasses: upload failures.

        Example:
            >>> client = ObscuraLensClient()
            >>> out = client.stego("suspicious.png")        # doctest: +SKIP
            >>> out["summary"]["verdict"]                    # doctest: +SKIP
            'highly suspicious'
        """
        return self._analyse_upload('stego', data, filename)

    def _analyse_upload(self, mode: str, data: Union[bytes, str, Path],
                        filename: Optional[str] = None) -> Dict[str, Any]:
        """Shared multipart upload helper for the exif/stego endpoints."""
        payload_bytes = self._read_upload_bytes(data)
        name = str(filename) if filename else _upload_name(data)
        content_type = _UPLOAD_TYPES.get(Path(name).suffix.lower(),
                                         'application/octet-stream')
        body, boundary = _multipart_body('file', name, payload_bytes,
                                         content_type)
        path = f'/api/tools/file/{mode}'
        response = self._send('POST', path, body=body,
                              extra_headers={
                                  'Content-Type':
                                      f'multipart/form-data; boundary={boundary}',
                              })
        try:
            parsed = response.json()
        except ValueError as exc:
            raise MalformedResponseError(
                f'non-JSON response from POST {path}',
                status=response.status,
                body_text=response.text[:2000]) from exc
        return parsed if isinstance(parsed, dict) else {}

    @staticmethod
    def _read_upload_bytes(data: Union[bytes, str, Path]) -> bytes:
        """Load upload bytes from bytes or a local file path."""
        if isinstance(data, (bytes, bytearray)):
            return bytes(data)
        path = Path(str(data))
        return path.read_bytes()

    def batch(self, kind: str, targets: Sequence[str],
              risk: bool = False) -> BatchProgress:
        """
        Look up many targets of one kind (capped at 25 per request).

        ``POST /api/tools/batch`` with body ``{"kind": ...,
        "targets": [...], "risk": false}``

        The run is synchronous — the response already carries one entry
        per target (failures included as ``success: False`` envelopes,
        never omitted), so there is no status endpoint to poll.

        Args:
            kind: tracker kind (see :meth:`lookup`).
            targets: target values; the server caps at 25 (surplus is
                counted in ``skipped``).
            risk: attach the heuristic risk block to every result.

        Returns:
            A :class:`~obscuralens.sdk.models.BatchProgress` with parsed
            per-target :class:`~obscuralens.sdk.models.BatchEntry` rows
            and the ``summary`` block (total/ok/failed/elapsed).

        Raises:
            ValueError: unknown kind or empty targets.
            BadRequestError: unknown kind, empty/oversized target list.

        Example:
            >>> client = ObscuraLensClient()
            >>> run = client.batch("ip", ["8.8.8.8", "1.1.1.1"])   # doctest: +SKIP
            >>> run.ok                                                # doctest: +SKIP
            2
        """
        kind = str(kind or '').strip().lower()
        if kind not in KINDS:
            raise ValueError(
                f'unknown kind {kind!r} — expected one of {", ".join(KINDS)}')
        target_list = [str(item) for item in targets or []]
        if not target_list:
            raise ValueError('targets must contain at least one value')
        payload = self._request('POST', '/api/tools/batch',
                                json_body={'kind': kind,
                                           'targets': target_list,
                                           'risk': risk})
        return BatchProgress.from_dict(payload)

    # ------------------------------------------------------------------
    # v6.0 part 2 — analytics
    # ------------------------------------------------------------------

    def analytics_stats(self, values: Sequence[float],
                        bins: int = 10) -> AnalyticsEnvelope:
        """
        Descriptive statistics plus a histogram for a numeric list.

        ``POST /api/analytics/stats`` with body
        ``{"values": [...], "bins": n}`` — non-numeric items are dropped
        server-side, then ``summarize`` (count/mean/median/stdev/
        quartiles/skew/kurtosis) and ``histogram`` run over the
        survivors.

        Args:
            values: the numbers to profile (a scalar inside the list is
                fine; the server cleans the rest).
            bins: histogram bin count (server clamps to 1..100).

        Returns:
            An :class:`~obscuralens.sdk.models.AnalyticsEnvelope` with
            ``kind='stats'`` — ``.payload['summary']`` carries the
            descriptive block, ``.payload['histogram']`` the bins.

        Raises:
            BadRequestError: ``values`` missing, not a list, or with no
                usable numbers left after cleaning.

        Example:
            >>> client = ObscuraLensClient()
            >>> envelope = client.analytics_stats(   # doctest: +SKIP
            ...     [1, 2, 3, 4, 100], bins=4)
            >>> envelope.get("count")                    # doctest: +SKIP
            5
        """
        payload = self._request('POST', '/api/analytics/stats',
                                json_body={'values': list(values or []),
                                           'bins': int(bins)})
        return AnalyticsEnvelope.from_dict(payload, kind='stats')

    def analytics_anomalies(self, values: Sequence[float],
                            method: str = 'ensemble',
                            threshold: Optional[float] = None
                            ) -> AnalyticsEnvelope:
        """
        Outlier detection over a numeric list.

        ``POST /api/analytics/anomalies`` with body
        ``{"values": [...], "method": ..., "threshold": ...}`` —
        ``method`` is one of ``zscore`` / ``iqr`` / ``mad`` / ``grubbs`` /
        ``ensemble`` / ``threshold`` (default ``ensemble``). The
        ``threshold`` key is only sent when a threshold was given *and*
        the method is ``zscore`` (the only detector that honours it).

        Args:
            values: the numbers to screen.
            method: detector name (default ``ensemble``).
            threshold: z-score cutoff for the ``zscore`` detector
                (default 3.0 server-side); ignored for other methods.

        Returns:
            An :class:`~obscuralens.sdk.models.AnalyticsEnvelope` with
            ``kind='anomalies'`` — ``.payload['anomalies']`` carries the
            ``value``/``score``/``method``/``detail`` records.

        Raises:
            BadRequestError: no usable numbers in ``values``.

        Example:
            >>> client = ObscuraLensClient()
            >>> envelope = client.analytics_anomalies(   # doctest: +SKIP
            ...     [1, 2, 3, 4, 10000], method='mad')
            >>> envelope.get("anomaly_count")                 # doctest: +SKIP
            1
        """
        body: Dict[str, Any] = {'values': list(values or []),
                                'method': method}
        if threshold is not None and method == 'zscore':
            body['threshold'] = threshold
        payload = self._request('POST', '/api/analytics/anomalies',
                                json_body=body)
        return AnalyticsEnvelope.from_dict(payload, kind='anomalies')

    def analytics_timeseries(self, values: Sequence[float]
                             ) -> AnalyticsEnvelope:
        """
        Trend / changepoint summary for a value sequence.

        ``POST /api/analytics/timeseries`` with body
        ``{"values": [...]}`` — values are indexed as consecutive days,
        then ``series_summary`` reports count, span, least-squares trend
        with direction verdict, mean/variance and CUSUM changepoint
        count.

        Args:
            values: the sequence to profile (oldest first).

        Returns:
            An :class:`~obscuralens.sdk.models.AnalyticsEnvelope` with
            ``kind='timeseries'`` — ``.payload['summary']`` carries the
            trend dossier.

        Raises:
            BadRequestError: no usable numbers in ``values``.

        Example:
            >>> client = ObscuraLensClient()
            >>> envelope = client.analytics_timeseries(   # doctest: +SKIP
            ...     [5, 6, 5, 6, 20, 21])
            >>> envelope.get("summary")["trend"]           # doctest: +SKIP
            'rising'
        """
        payload = self._request('POST', '/api/analytics/timeseries',
                                json_body={'values': list(values or [])})
        return AnalyticsEnvelope.from_dict(payload, kind='timeseries')

    def analytics_clusters(self, points: Sequence[Sequence[float]],
                           eps_km: float = 25.0,
                           min_points: int = 3) -> AnalyticsEnvelope:
        """
        Kilometre-space clustering of ``[lat, lon]`` coordinate pairs.

        ``POST /api/analytics/clusters`` with body
        ``{"points": [[lat, lon], ...], "eps_km": ..., "min_points":
        ...}`` — great-circle DBSCAN via ``cluster_points``; noise
        points stay unclustered.

        Args:
            points: ``[lat, lon]`` rows (lists or tuples).
            eps_km: cluster radius in kilometres (default 25).
            min_points: DBSCAN density threshold (default 3).

        Returns:
            An :class:`~obscuralens.sdk.models.AnalyticsEnvelope` with
            ``kind='clusters'`` — ``.payload['clusters']`` carries the
            cluster records, ``.payload['point_count']`` the usable rows.

        Raises:
            BadRequestError: ``points`` missing, not a list, or with no
                usable two-number rows.

        Example:
            >>> client = ObscuraLensClient()
            >>> envelope = client.analytics_clusters(   # doctest: +SKIP
            ...     [[52.0, 13.0], [52.1, 13.1]], eps_km=10)
            >>> envelope.get("cluster_count")             # doctest: +SKIP
            0
        """
        rows = [list(point) for point in points or []]
        payload = self._request('POST', '/api/analytics/clusters',
                                json_body={'points': rows,
                                           'eps_km': float(eps_km),
                                           'min_points': int(min_points)})
        return AnalyticsEnvelope.from_dict(payload, kind='clusters')

    def analytics_keywords(self, text: str,
                           top: int = 10) -> AnalyticsEnvelope:
        """
        Stopword-filtered keyword mining for a text.

        ``POST /api/analytics/keywords`` with body
        ``{"text": ..., "top": n}`` — returns ``term``/``count``/
        ``weight`` records sorted by weight.

        Args:
            text: the free-form text to mine.
            top: how many terms to keep (default 10).

        Returns:
            An :class:`~obscuralens.sdk.models.AnalyticsEnvelope` with
            ``kind='keywords'`` — ``.payload['keywords']`` carries the
            ranked terms.

        Raises:
            BadRequestError: blank text.

        Example:
            >>> client = ObscuraLensClient()
            >>> envelope = client.analytics_keywords(   # doctest: +SKIP
            ...     "the quick brown fox", top=2)
            >>> envelope.get("keywords")[0]["term"]      # doctest: +SKIP
            'quick'
        """
        payload = self._request('POST', '/api/analytics/keywords',
                                json_body={'text': text, 'top': int(top)})
        return AnalyticsEnvelope.from_dict(payload, kind='keywords')

    def analytics_language(self, text: str) -> AnalyticsEnvelope:
        """
        Script and language fingerprint for a text.

        ``POST /api/analytics/language`` with body ``{"text": ...}`` —
        dominant script, per-script character counts, a language guess
        with confidence and a human-readable hint.

        Args:
            text: the text to fingerprint.

        Returns:
            An :class:`~obscuralens.sdk.models.AnalyticsEnvelope` with
            ``kind='language'`` — ``.payload`` carries ``scripts``,
            ``guess`` and ``hint``.

        Raises:
            BadRequestError: blank text.

        Example:
            >>> client = ObscuraLensClient()
            >>> envelope = client.analytics_language(   # doctest: +SKIP
            ...     "Le renard brun rapide")
            >>> envelope.get("guess")["language"]        # doctest: +SKIP
            'fr'
        """
        payload = self._request('POST', '/api/analytics/language',
                                json_body={'text': text})
        return AnalyticsEnvelope.from_dict(payload, kind='language')

    def analytics_similarity(self, a: str, b: str) -> AnalyticsEnvelope:
        """
        Four-metric similarity between two texts.

        ``POST /api/analytics/similarity`` with body
        ``{"a": ..., "b": ...}`` — Jaro-Winkler, Levenshtein ratio,
        bigram similarity, sparse cosine, their mean and both lengths.

        Args:
            a: first text (e.g. ``"paypal.com"``).
            b: second text (e.g. ``"paypa1.com"``).

        Returns:
            An :class:`~obscuralens.sdk.models.AnalyticsEnvelope` with
            ``kind='similarity'`` — the four metrics plus ``mean``.

        Raises:
            BadRequestError: either text blank.

        Example:
            >>> client = ObscuraLensClient()
            >>> envelope = client.analytics_similarity(   # doctest: +SKIP
            ...     "paypal.com", "paypa1.com")
            >>> envelope.get("mean") > 0.8                 # doctest: +SKIP
            True
        """
        payload = self._request('POST', '/api/analytics/similarity',
                                json_body={'a': a, 'b': b})
        return AnalyticsEnvelope.from_dict(payload, kind='similarity')

    def analytics_graph(self, entities: Sequence[Any],
                        links: Sequence[Any]) -> AnalyticsEnvelope:
        """
        Graph metrics over an ``entities``/``links`` payload.

        ``POST /api/analytics/graph`` with body
        ``{"entities": [...], "links": [...]}`` — the investigate/
        correlation payload shape (``from``/``to`` link keys are
        accepted server-side too). Returns the one-shot
        ``graph_summary`` dossier: node/edge counts, density, components,
        communities, top entities by degree/PageRank/betweenness,
        bridges and isolated nodes.

        Args:
            entities: entity dicts (``[{'id': 'a'}, ...]``).
            links: link dicts (``[{'source': 'a', 'target': 'b'}, ...]``).

        Returns:
            An :class:`~obscuralens.sdk.models.AnalyticsEnvelope` with
            ``kind='graph'`` — ``.payload['summary']`` carries the
            dossier.

        Raises:
            BadRequestError: neither list is present.

        Example:
            >>> client = ObscuraLensClient()
            >>> envelope = client.analytics_graph(   # doctest: +SKIP
            ...     [{'id': 'a'}, {'id': 'b'}], [{'source': 'a',
            ...      'target': 'b'}])
            >>> envelope.get("summary")["nodes"]     # doctest: +SKIP
            2
        """
        payload = self._request('POST', '/api/analytics/graph',
                                json_body={'entities': list(entities or []),
                                           'links': list(links or [])})
        return AnalyticsEnvelope.from_dict(payload, kind='graph')

    def analytics_history(self, limit: int = 500) -> AnalyticsEnvelope:
        """
        Enrichment report over stored query history.

        ``GET /api/analytics/history?limit=500`` (newest rows
        considered) — kind frequency, hour/weekday activity profiles,
        per-kind success rates, field-count statistics, source
        reliability, day-volume anomalies and the most re-queried
        targets. An empty history yields a well-formed empty report,
        not an error.

        Args:
            limit: how many newest history rows to consider (default
                500).

        Returns:
            An :class:`~obscuralens.sdk.models.AnalyticsEnvelope` with
            ``kind='history'`` — the full dossier (``total_queries``,
            ``kind_frequency``, ``hour_profile``...).

        Example:
            >>> client = ObscuraLensClient()
            >>> envelope = client.analytics_history(limit=100)   # doctest: +SKIP
            >>> envelope.get("total_queries")                    # doctest: +SKIP
            42
        """
        payload = self._request('GET', '/api/analytics/history',
                                params={'limit': int(limit)})
        return AnalyticsEnvelope.from_dict(payload, kind='history')

    # ------------------------------------------------------------------
    # v6.0 part 4 — notifications
    # ------------------------------------------------------------------

    def notify_channels(self) -> NotifyChannels:
        """
        Every configured notification channel plus the protocol
        vocabularies.

        ``GET /api/notify/channels``

        Returns:
            A :class:`~obscuralens.sdk.models.NotifyChannels` — the
            parsed channels, the valid ``channel_types`` (webhook,
            telegram, discord, slack, smtp) and the ``severities``
            ladder a UI needs to render pickers.

        Example:
            >>> client = ObscuraLensClient()
            >>> channels = client.notify_channels()    # doctest: +SKIP
            >>> channels.by_name("team-chat")           # doctest: +SKIP
            NotifyChannel(name='team-chat', ...)
        """
        payload = self._request('GET', '/api/notify/channels')
        return NotifyChannels.from_dict(payload)

    def add_notify_channel(self, name: str, channel_type: str,
                           target: str = '',
                           events: Optional[Sequence[str]] = None,
                           min_severity: Optional[str] = None,
                           quiet_hours: Optional[Sequence[int]] = None
                           ) -> NotifyChannel:
        """
        Register one notification channel.

        ``POST /api/notify/channels`` — the body always carries
        ``name`` / ``type`` / ``target`` (the API field is ``type``; the
        Python argument avoids shadowing the builtin as
        ``channel_type``), and ``events`` / ``min_severity`` /
        ``quiet_hours`` are only included when not ``None`` (the server
        applies its own defaults), so a minimal registration is just
        ``name`` + ``channel_type``.

        Args:
            name: unique human label (e.g. ``'team-chat'``).
            channel_type: one of the channel types (webhook/telegram/
                discord/slack/smtp) — validated server-side, so
                newly added types work without an SDK release.
            target: where messages go (URL, ``bot_token:chat_id``, SMTP
                spec); may be empty when the matching global config key
                is set.
            events: event types to subscribe to (``None`` =
                everything).
            min_severity: weakest severity rung worth waking this
                channel (info/low/medium/high/critical).
            quiet_hours: optional ``(start, end)`` local-hour pair —
                the window wraps past midnight, so ``(22, 6)`` silences
                22:00 to 06:00.

        Returns:
            The created :class:`~obscuralens.sdk.models.NotifyChannel`.

        Raises:
            BadRequestError: unknown type, missing target, duplicate
                name — the module's reason is the ``detail``.

        Example:
            >>> client = ObscuraLensClient()
            >>> channel = client.add_notify_channel(   # doctest: +SKIP
            ...     "team-chat", channel_type="telegram",
            ...     target="bot:chat", events=["risk_high"],
            ...     min_severity="low")
            >>> channel.name                              # doctest: +SKIP
            'team-chat'
        """
        body: Dict[str, Any] = {'name': name, 'type': channel_type,
                                'target': target}
        if events is not None:
            body['events'] = list(events)
        if min_severity is not None:
            body['min_severity'] = min_severity
        if quiet_hours is not None:
            body['quiet_hours'] = list(quiet_hours)
        payload = self._request('POST', '/api/notify/channels',
                                json_body=body)
        return NotifyChannel.from_dict(payload)

    def remove_notify_channel(self, name: str) -> Dict[str, Any]:
        """
        Delete one notification channel by name.

        ``DELETE /api/notify/channels/{name}`` — delivery history stays
        behind (the log is the audit trail of everything that *was*
        sent).

        Args:
            name: channel name (case-insensitive).

        Returns:
            ``{'ok': True, 'removed': <name>}``.

        Raises:
            NotFoundError: unknown channel name.

        Example:
            >>> client = ObscuraLensClient()
            >>> client.remove_notify_channel("team-chat")   # doctest: +SKIP
            {'ok': True, 'removed': 'team-chat'}
        """
        path = self._path('/api/notify/channels/{0}', name)
        payload = self._request('DELETE', path)
        return payload if isinstance(payload, dict) else {}

    def test_notify_channel(self, name: str) -> NotifyDelivery:
        """
        Probe one channel with a one-off test message.

        ``POST /api/notify/channels/{name}/test`` — the subscription/
        severity/quiet-hours/dedup filters are bypassed: the question
        answered is "does the pipe work?". A delivery failure is a
        ``200`` with ``ok: False`` (data, not an HTTP error); an
        unknown channel name is a ``404``.

        Args:
            name: the channel to probe (case-insensitive).

        Returns:
            A :class:`~obscuralens.sdk.models.NotifyDelivery` —
            ``ok``, ``error`` and the probed ``channel``.

        Raises:
            NotFoundError: unknown channel name.

        Example:
            >>> client = ObscuraLensClient()
            >>> delivery = client.test_notify_channel(   # doctest: +SKIP
            ...     "team-chat")
            >>> delivery.ok                                 # doctest: +SKIP
            True
        """
        path = self._path('/api/notify/channels/{0}/test', name)
        payload = self._request('POST', path)
        return NotifyDelivery.from_dict(payload)

    def notify_recent(self, limit: int = 20) -> Dict[str, Any]:
        """
        Recent notification history, newest first.

        ``GET /api/notify/recent?limit=20`` — sends, failures and skips
        alike (the log is the account of everything the module wanted
        to say). The server caps the window at 200 entries.

        Args:
            limit: how many entries to return (default 20).

        Returns:
            The raw payload as a plain dict —
            ``{'count': n, 'recent': [{'ts', 'event', 'channel',
            'title', 'severity', 'delivery'}, ...]}``. No model wraps
            this endpoint: the log rows are already flat and
            self-describing.

        Example:
            >>> client = ObscuraLensClient()
            >>> log = client.notify_recent(limit=5)   # doctest: +SKIP
            >>> log["count"]                            # doctest: +SKIP
            3
        """
        payload = self._request('GET', '/api/notify/recent',
                                params={'limit': int(limit)})
        return payload if isinstance(payload, dict) else {}

    def notify_broadcast(self, title: str, body: str,
                         severity: str = 'info',
                         event_type: str = 'manual') -> NotifyDelivery:
        """
        Fan one event out to every configured channel.

        ``POST /api/notify/broadcast`` — per-channel filters (event
        subscriptions, severity floors, quiet hours, dedup) apply
        server-side inside the broadcast; failures never abort the
        loop.

        Args:
            title: headline shown in every chat payload (non-empty).
            body: message body (non-empty).
            severity: one of info/low/medium/high/critical.
            event_type: free-form event label (default ``manual``).

        Returns:
            A :class:`~obscuralens.sdk.models.NotifyDelivery` — the
            ``sent``/``skipped``/``failed``/``total`` aggregate plus the
            per-channel results in ``.raw``.

        Raises:
            BadRequestError: blank ``title`` or ``body``.

        Example:
            >>> client = ObscuraLensClient()
            >>> delivery = client.notify_broadcast(   # doctest: +SKIP
            ...     "watch diff", "example.com changed NS",
            ...     severity="high", event_type="watch_diff")
            >>> delivery.sent                             # doctest: +SKIP
            2
        """
        payload = self._request('POST', '/api/notify/broadcast',
                                json_body={'title': title, 'body': body,
                                           'severity': severity,
                                           'event_type': event_type})
        return NotifyDelivery.from_dict(payload)

    # ------------------------------------------------------------------
    # v6.0 part 4 — automation
    # ------------------------------------------------------------------

    def automation_tasks(self) -> AutomationTasks:
        """
        Every scheduled task (schedules, bookkeeping fields, health).

        ``GET /api/automation/tasks``

        Returns:
            An :class:`~obscuralens.sdk.models.AutomationTasks` — the
            parsed tasks (``last_run``/``next_run``/``run_count``/
            ``error_count`` included) plus the ``actions`` and
            ``schedule_types`` vocabularies.

        Example:
            >>> client = ObscuraLensClient()
            >>> tasks = client.automation_tasks()      # doctest: +SKIP
            >>> tasks.by_name("daily-watch").summary()  # doctest: +SKIP
            'daily-watch [watch_check, daily 09:00]: 12 run(s)'
        """
        payload = self._request('GET', '/api/automation/tasks')
        return AutomationTasks.from_dict(payload)

    def add_automation_task(self, name: str, action: str,
                            schedule: str = 'interval',
                            interval_seconds: int = 3600,
                            at_time: Optional[str] = None,
                            weekday: Optional[int] = None,
                            params: Optional[Dict[str, Any]] = None,
                            enabled: bool = True) -> AutomationTaskView:
        """
        Register one scheduled task.

        ``POST /api/automation/tasks`` — the body always carries
        ``name`` / ``action`` / ``schedule`` / ``enabled``;
        ``interval_seconds`` is only included for the ``interval``
        schedule, and ``at_time`` / ``weekday`` / ``params`` only when
        not ``None``. The stored task comes back with a freshly
        computed ``next_run``.

        Args:
            name: unique human label (max 80 chars).
            action: one of ``watch_check`` / ``pipeline`` / ``report`` /
                ``feed_refresh`` / ``notify_test``.
            schedule: ``interval`` (every ``interval_seconds``),
                ``daily`` (at ``at_time``) or ``weekly`` (at ``at_time``
                on ``weekday``).
            interval_seconds: period for the interval schedule (default
                3600).
            at_time: ``'HH:MM'`` local time for daily/weekly schedules.
            weekday: 0 = Monday ... 6 = Sunday (weekly schedule).
            params: the executor's payload, e.g.
                ``{'path': 'pipelines/daily.yaml'}``.
            enabled: master switch — disabled tasks are never due.

        Returns:
            The created
            :class:`~obscuralens.sdk.models.AutomationTaskView`.

        Raises:
            BadRequestError: rejected spec (unknown action/schedule,
                bad ``at_time``, duplicate name...) — the module's
                reason is the ``detail``.

        Example:
            >>> client = ObscuraLensClient()
            >>> task = client.add_automation_task(   # doctest: +SKIP
            ...     "daily-watch", "watch_check", schedule="daily",
            ...     at_time="09:00")
            >>> task.next_run                          # doctest: +SKIP
            '2024-06-02T09:00:00'
        """
        body: Dict[str, Any] = {'name': name, 'action': action,
                                'schedule': schedule, 'enabled': enabled}
        if schedule == 'interval':
            body['interval_seconds'] = int(interval_seconds)
        if at_time is not None:
            body['at_time'] = at_time
        if weekday is not None:
            body['weekday'] = int(weekday)
        if params is not None:
            body['params'] = dict(params)
        payload = self._request('POST', '/api/automation/tasks',
                                json_body=body)
        return AutomationTaskView.from_dict(payload)

    def remove_automation_task(self, name: str) -> Dict[str, Any]:
        """
        Delete one scheduled task by name.

        ``DELETE /api/automation/tasks/{name}``

        Args:
            name: task name (case-insensitive).

        Returns:
            ``{'ok': True, 'removed': <name>}``.

        Raises:
            NotFoundError: unknown task name.

        Example:
            >>> client = ObscuraLensClient()
            >>> client.remove_automation_task("daily-watch")   # doctest: +SKIP
            {'ok': True, 'removed': 'daily-watch'}
        """
        path = self._path('/api/automation/tasks/{0}', name)
        payload = self._request('DELETE', path)
        return payload if isinstance(payload, dict) else {}

    def run_automation_task(self, name: str) -> Dict[str, Any]:
        """
        Execute one task now, regardless of its schedule.

        ``POST /api/automation/tasks/{name}/run`` — a failing executor
        is a ``200`` with ``ok: False`` (the run outcome, not an HTTP
        error). The persisted bookkeeping (``run_count``, ``next_run``)
        is left to ``run-due`` so manual runs cannot corrupt the cron
        state.

        Args:
            name: task name (case-insensitive).

        Returns:
            ``{'ok': bool, 'started': iso, 'finished': iso, 'error':
            str, 'summary': str}`` — the executor's one-line human
            report included.

        Raises:
            NotFoundError: unknown task name.

        Example:
            >>> client = ObscuraLensClient()
            >>> client.run_automation_task("daily-watch")   # doctest: +SKIP
            {'ok': True, 'started': '...', 'finished': '...',
             'error': '', 'summary': 'checked 4 watch(es)'}
        """
        path = self._path('/api/automation/tasks/{0}/run', name)
        payload = self._request('POST', path)
        return payload if isinstance(payload, dict) else {}

    def run_due_automation(self) -> Dict[str, Any]:
        """
        Run every task whose schedule has arrived, then persist the
        bookkeeping.

        ``POST /api/automation/run-due`` — exactly what the background
        tick loop does every 30 seconds: ``last_run``, ``run_count``,
        ``error_count``, ``last_error`` and a fresh ``next_run`` anchored
        to the due moment.

        Returns:
            ``{'ran': n, 'results': [{'task', 'action', 'ok',
            'started', 'finished', 'error', 'summary'}, ...]}``.

        Example:
            >>> client = ObscuraLensClient()
            >>> client.run_due_automation()        # doctest: +SKIP
            {'ran': 1, 'results': [{'task': 'daily-watch', ...}]}
        """
        payload = self._request('POST', '/api/automation/run-due')
        return payload if isinstance(payload, dict) else {}

    def automation_next(self) -> Dict[str, Any]:
        """
        When every task runs next.

        ``GET /api/automation/next`` — the stored ``next_run`` plus a
        fresh recomputation from *now* (the two differ while a due task
        waits for the next tick). An empty schedule yields an empty
        list.

        Returns:
            ``{'count': n, 'tasks': [{'name', 'action', 'schedule',
            'enabled', 'stored_next_run', 'recomputed_next_run'}, ...]}``.

        Example:
            >>> client = ObscuraLensClient()
            >>> snapshot = client.automation_next()   # doctest: +SKIP
            >>> snapshot["tasks"][0]["name"]           # doctest: +SKIP
            'daily-watch'
        """
        payload = self._request('GET', '/api/automation/next')
        return payload if isinstance(payload, dict) else {}

    # ------------------------------------------------------------------
    # v6.0 part 4 — intelligence-sharing exports
    # ------------------------------------------------------------------

    def export_stix(self, kind: str, target: str) -> StixBundle:
        """
        A STIX 2.1 bundle for the newest stored lookup of one target.

        ``GET /api/export/stix/{kind}/{target}`` — identity + indicator
        (or vulnerability for CVEs) + observed data + provenance note,
        deterministic UUIDv5 ids throughout so re-imports merge. The
        exports describe what was *observed*: run the lookup first, then
        export.

        Args:
            kind: tracker kind (see :meth:`lookup`).
            target: the indicator value.

        Returns:
            A :class:`~obscuralens.sdk.models.StixBundle` —
            ``.objects``, ``.object_types()``, ``.indicator_count()``
            and ``.to_json()`` for the file-ready document.

        Raises:
            ValueError: unknown kind.
            BadRequestError: unknown kind (server-side check).
            NotFoundError: no stored lookup for the target.

        Example:
            >>> client = ObscuraLensClient()
            >>> bundle = client.export_stix(   # doctest: +SKIP
            ...     "domain", "example.com")
            >>> dict(bundle.object_types())    # doctest: +SKIP
            {'identity': 1, 'indicator': 1, 'observed-data': 1, 'relationship': 1, 'note': 1}
        """
        kind = str(kind or '').strip().lower()
        if kind not in KINDS:
            raise ValueError(
                f'unknown kind {kind!r} — expected one of {", ".join(KINDS)}')
        path = self._path('/api/export/stix/{0}/{1}', kind, target)
        payload = self._request('GET', path)
        return StixBundle.from_dict(payload)

    def export_misp(self, kind: str, target: str) -> MispEvent:
        """
        A MISP core-format event for the newest stored lookup of one
        target.

        ``GET /api/export/misp/{kind}/{target}`` — fixed ObscuraLens
        ``orgc``, the target attribute, one text attribute per ``info``
        field and a threat level derived from source health. Run the
        lookup first, then export.

        Args:
            kind: tracker kind (see :meth:`lookup`).
            target: the indicator value.

        Returns:
            A :class:`~obscuralens.sdk.models.MispEvent` — the Event
            block, ``.attributes``, ``.attribute_count()`` and
            ``.to_json()`` for the file-ready document.

        Raises:
            ValueError: unknown kind.
            BadRequestError: unknown kind (server-side check).
            NotFoundError: no stored lookup for the target.

        Example:
            >>> client = ObscuraLensClient()
            >>> event = client.export_misp(   # doctest: +SKIP
            ...     "domain", "example.com")
            >>> event.attribute_count()       # doctest: +SKIP
            7
        """
        kind = str(kind or '').strip().lower()
        if kind not in KINDS:
            raise ValueError(
                f'unknown kind {kind!r} — expected one of {", ".join(KINDS)}')
        path = self._path('/api/export/misp/{0}/{1}', kind, target)
        payload = self._request('GET', path)
        return MispEvent.from_dict(payload)

    # ------------------------------------------------------------------
    # v6.0 part 3 — live stream
    # ------------------------------------------------------------------

    def set_stream_topics(self, topics: Union[Sequence[str], str]
                          ) -> Dict[str, Any]:
        """
        Declare the event topics the live stream should carry.

        ``POST /api/stream/subscribe`` with body
        ``{"topics": [...]}`` — the set is module-level server-side:
        every ``GET /api/stream`` connection without its own
        ``?topics=`` parameter filters through it, and an empty
        declaration clears the filter (all topics again).

        Args:
            topics: topic names — a list/tuple (``['lookup', 'watch']``)
                or a single comma-separated string
                (``'lookup, watch'``). Blank names are dropped.

        Returns:
            ``{'topics': [...], 'count': n, 'subscriber_count': n}`` —
            the normalised, sorted topic list.

        Raises:
            BadRequestError: missing/empty topics or non-string items.

        Example:
            >>> client = ObscuraLensClient()
            >>> client.set_stream_topics("lookup, watch")   # doctest: +SKIP
            {'topics': ['lookup', 'watch'], 'count': 2, 'subscriber_count': 0}
        """
        if isinstance(topics, str):
            names = [item.strip() for item in topics.split(',')
                     if item.strip()]
        else:
            names = [str(item).strip() for item in topics or []
                     if str(item).strip()]
        payload = self._request('POST', '/api/stream/subscribe',
                                json_body={'topics': names})
        return payload if isinstance(payload, dict) else {}

    # ------------------------------------------------------------------
    # Escape hatches
    # ------------------------------------------------------------------

    def raw_get(self, path: str,
                params: Optional[Dict[str, Any]] = None) -> Any:
        """
        GET any API path and return the parsed JSON.

        The escape hatch for endpoints this SDK version does not model —
        new server endpoints work without waiting for an SDK release.

        Args:
            path: absolute path starting with ``/`` (e.g.
                ``/api/some/new/endpoint``).
            params: optional query parameters.

        Returns:
            The parsed JSON body (dict or list).

        Raises:
            MalformedResponseError: non-JSON 2xx body.
            ApiError subclasses: mapped non-2xx statuses.

        Example:
            >>> client = ObscuraLensClient()
            >>> client.raw_get("/api/kinds")   # doctest: +SKIP
            [{'kind': 'ip', ...}, ...]
        """
        if not str(path).startswith('/'):
            path = f'/{path}'
        return self._request('GET', path, params=params)

    def raw_post(self, path: str, json_body: Any = None) -> Any:
        """
        POST any API path and return the parsed JSON.

        Args:
            path: absolute path starting with ``/``.
            json_body: the JSON body to send (``None`` = empty body).

        Returns:
            The parsed JSON body (dict or list).

        Raises:
            MalformedResponseError: non-JSON 2xx body.
            ApiError subclasses: mapped non-2xx statuses.

        Example:
            >>> client = ObscuraLensClient()
            >>> client.raw_post("/api/watch/check")   # doctest: +SKIP
            [{'watch_id': 1, ...}]
        """
        if not str(path).startswith('/'):
            path = f'/{path}'
        return self._request('POST', path, json_body=json_body)


def _upload_name(data: Union[bytes, str, Path]) -> str:
    """Default upload filename: the source path's basename, or ``upload.bin``."""
    if isinstance(data, (bytes, bytearray)):
        return 'upload.bin'
    return Path(str(data)).name or 'upload.bin'


def _parse_retry_after(headers: Dict[str, str]) -> Optional[float]:
    """
    Parse a numeric ``Retry-After`` header (case-insensitive).

    Args:
        headers: the response headers mapping.

    Returns:
        Seconds to wait, or ``None`` when absent or an HTTP-date (which
        the SDK does not compute — the backoff applies instead).
    """
    raw = header_value(headers, 'Retry-After')
    if raw is None:
        return None
    try:
        return float(str(raw).strip())
    except (TypeError, ValueError):
        return None


def _multipart_body(field: str, filename: str, data: bytes,
                    content_type: str = 'application/octet-stream'
                    ) -> Tuple[bytes, str]:
    """
    Build a one-file ``multipart/form-data`` body (stdlib only).

    Args:
        field: the form field name (``file`` for both upload endpoints).
        filename: the upload filename.
        data: the raw file bytes.
        content_type: the file part's content type.

    Returns:
        ``(body_bytes, boundary)`` — set the request ``Content-Type`` to
        ``multipart/form-data; boundary=<boundary>``.

    Example:
        >>> body, boundary = _multipart_body('file', 'a.png', b'PNG')
        >>> body[:40].decode('ascii', errors='replace').startswith('--')
        True
    """
    boundary = f'----obscuralens-sdk-{uuid.uuid4().hex}'
    header = (f'--{boundary}\r\n'
              f'Content-Disposition: form-data; name="{field}"; '
              f'filename="{filename}"\r\n'
              f'Content-Type: {content_type}\r\n\r\n').encode('utf-8')
    footer = f'\r\n--{boundary}--\r\n'.encode('utf-8')
    return header + data + footer, boundary

"""
HTTP transports for the ObscuraLens Python SDK.

The SDK never talks to the network directly — every call goes through a
:class:`Transport` object that turns ``(method, url, headers, params,
json_body)`` into a :class:`Response`. Two implementations ship:

* :class:`UrllibTransport` — the production transport, built entirely on
  the standard library (``urllib.request``). No third-party dependency is
  ever imported by the SDK.
* :class:`StaticTransport` — an in-memory test double. Load it with a
  queue of canned :class:`Response` objects (or exceptions to raise), and
  it records every call it receives in ``.calls`` so tests (and users
  faking a server) can assert on exact method/URL/body.

Custom transports (``requests``, ``httpx``, a caching proxy...) only need
to subclass :class:`Transport` and implement :meth:`Transport.request`.
"""

import json as _json
import socket
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

from .exceptions import TimeoutError, TransportError

__all__ = ['Response', 'Transport', 'UrllibTransport', 'StaticTransport',
           'SDK_USER_AGENT', 'SDK_VERSION']

#: SDK version used in the default ``User-Agent`` header.
#:
#: This must be kept in sync with the package version in
#: ``obscuralens/__init__.py`` (``obscuralens.__version__``). It is
#: duplicated here on purpose: importing the parent package from the SDK
#: would drag config/database side effects into ``import obscuralens.sdk``,
#: and the transport layer must stay import-light (stdlib only).
SDK_VERSION = '5.1.0'

#: Default ``User-Agent`` sent with every SDK request.
SDK_USER_AGENT = f'obscuralens-sdk/{SDK_VERSION}'

#: Header name for the optional session API key (see the client's
#: ``api_key`` parameter; the server honours ``OBSCURALENS_API_KEY``-style
#: gating when deployed behind an authenticating proxy).
API_KEY_HEADER = 'X-API-Key'


@dataclass
class Response:
    """
    One immutable HTTP response.

    Attributes:
        status: the HTTP status code (int).
        headers: response headers as a plain string dict (values joined
            when repeated). Key case is whatever the transport produced —
            use :func:`header_value` for case-insensitive lookup.
        body: the raw response body as bytes.

    Note:
        :meth:`json` raises ``ValueError`` (``json.JSONDecodeError``) on a
        non-JSON body instead of an SDK exception — this module cannot
        import :mod:`obscuralens.sdk.exceptions`' error-mapping behaviour
        without a circular import (exceptions are used by the transport for
        connection errors). The client wraps this ``ValueError`` into
        :class:`~obscuralens.sdk.exceptions.MalformedResponseError`.
    """

    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b''

    @property
    def text(self) -> str:
        """The response body decoded as UTF-8 (replacement on bad bytes)."""
        if not self.body:
            return ''
        return self.body.decode('utf-8', errors='replace')

    @property
    def ok(self) -> bool:
        """True when the status is a 2xx success code."""
        return 200 <= self.status < 300

    def json(self) -> Any:
        """
        Parse the body as JSON.

        Returns:
            The parsed value (dict, list, scalar...).

        Raises:
            ValueError: when the body is not valid JSON (including an
                empty body). The SDK client converts this into
                ``MalformedResponseError``; direct users should catch it
                themselves.

        Example:
            >>> response = Response(200, {}, b'{"status": "ok"}')
            >>> response.json()
            {'status': 'ok'}
        """
        return _json.loads(self.body.decode('utf-8', errors='strict'))

    @classmethod
    def from_json(cls, status: int, payload: Any,
                  headers: Optional[Dict[str, str]] = None) -> 'Response':
        """
        Build a success response from a Python object.

        Args:
            status: HTTP status code (typically 200/201).
            payload: any JSON-serialisable object.
            headers: optional response headers.

        Returns:
            A :class:`Response` whose body is the serialised payload.

        Example:
            >>> Response.from_json(200, {'ok': True}).json()
            {'ok': True}
        """
        body = _json.dumps(payload).encode('utf-8')
        return cls(status=status, headers=dict(headers or {}), body=body)


def header_value(headers: Mapping[str, str], name: str) -> Optional[str]:
    """
    Case-insensitive header lookup.

    Args:
        headers: the response headers mapping.
        name: header name to find (case-insensitive).

    Returns:
        The header value, or ``None`` when absent.

    Example:
        >>> header_value({'retry-after': '2'}, 'Retry-After')
        '2'
    """
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            return value
    return None


class Transport(ABC):
    """
    Abstract HTTP transport used by the SDK clients.

    Subclasses implement :meth:`request` and (optionally) override
    :meth:`close`. The client passes fully-merged headers (including
    ``Accept``, ``Content-Type`` and any API key) and a URL that already
    carries its query string; ``params`` is supplied too so recording
    transports can log the pre-encoded values.

    Args for ``request``:
        method: HTTP verb (``GET``/``POST``/``PUT``/``PATCH``/``DELETE``).
        url: absolute URL, query string already appended.
        headers: request headers to send (never ``None``).
        params: the query parameters before encoding (for logging/records;
            the URL already contains the encoded form).
        json_body: a JSON-serialisable request body, or ``None``.
        body: raw request body bytes, or ``None`` — used by the multipart
            file-upload endpoints. When set, ``json_body`` is ``None`` and
            the caller has already put the right ``Content-Type`` in
            ``headers``.
        timeout: per-request timeout in seconds (``None`` = transport
            default).

    Returns:
        A :class:`Response` for every HTTP status — non-2xx statuses are
        *returned*, not raised; the client maps them to SDK exceptions.

    Raises:
        TransportError: when no HTTP response could be obtained.
        TimeoutError: when the attempt timed out (``socket.timeout``).

    Example:
        >>> class MyTransport(Transport):                 # doctest: +SKIP
        ...     def request(self, method, url, headers=None, params=None,
        ...                 json_body=None, body=None, timeout=None):
        ...         return Response.from_json(200, {'echo': method})
        ...     def close(self):
        ...         pass
    """

    @abstractmethod
    def request(self, method: str, url: str,
                headers: Optional[Dict[str, str]] = None,
                params: Optional[Dict[str, Any]] = None,
                json_body: Any = None, body: Optional[bytes] = None,
                timeout: Optional[float] = None) -> Response:
        """Perform one HTTP request (see :class:`Transport` for the contract)."""
        raise NotImplementedError

    def close(self) -> None:
        """Release any underlying resources. Default: nothing to release."""
        return None


class UrllibTransport(Transport):
    """
    Production transport built on ``urllib.request`` (stdlib only).

    Args:
        timeout: default per-request timeout in seconds.
        verify_ssl: verify TLS certificates for ``https://`` URLs. Setting
            this to False disables both hostname and chain verification —
            only do this against a self-hosted server with a self-signed
            certificate.
        default_headers: headers merged into every request (the client's
            own Accept/Content-Type/API-key headers win on conflict).
        user_agent: ``User-Agent`` value; the default identifies the SDK
            version (see :data:`SDK_USER_AGENT`).

    Example:
        >>> transport = UrllibTransport(timeout=10)
        >>> client = ObscuraLensClient(transport=transport)   # doctest: +SKIP
    """

    def __init__(self, timeout: float = 30.0, verify_ssl: bool = True,
                 default_headers: Optional[Dict[str, str]] = None,
                 user_agent: str = SDK_USER_AGENT) -> None:
        self.timeout = float(timeout)
        self.verify_ssl = bool(verify_ssl)
        self.default_headers: Dict[str, str] = dict(default_headers or {})
        self.user_agent = user_agent
        self._opener = self._build_opener()
        self._closed = False

    # -- construction helpers -------------------------------------------

    def _build_opener(self) -> urllib.request.OpenerDirector:
        """Build the urllib opener, configuring the SSL context."""
        handlers: List[urllib.request.BaseHandler] = []
        try:
            import ssl
            context = ssl.create_default_context()
            if not self.verify_ssl:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=context))
        except ImportError:  # pragma: no cover - Python built without ssl
            pass
        return urllib.request.build_opener(*handlers)

    # -- URL encoding ----------------------------------------------------

    @staticmethod
    def build_query(params: Optional[Mapping[str, Any]]) -> str:
        """
        Encode query parameters into a query string (without ``?``).

        ``None`` values are skipped; lists repeat the key; booleans are
        emitted as lowercase ``true``/``false`` (FastAPI-friendly). Spaces
        are percent-encoded (``%20``), and unicode values are encoded as
        UTF-8 first — ``user@example.com`` and ``48.8584, 2.2945`` survive
        the round trip through FastAPI's query parser.

        Args:
            params: mapping of query parameter names to values.

        Returns:
            The encoded query string ('' when empty).

        Example:
            >>> UrllibTransport.build_query({'q': 'a b', 'kind': None})
            'q=a%20b'
            >>> UrllibTransport.build_query({'pivot': True})
            'pivot=true'
        """
        if not params:
            return ''
        clean: Dict[str, Any] = {}
        for key, value in params.items():
            if value is None:
                continue
            if isinstance(value, bool):
                clean[str(key)] = 'true' if value else 'false'
            else:
                clean[str(key)] = value
        if not clean:
            return ''
        return urllib.parse.urlencode(clean, doseq=True,
                                       quote_via=urllib.parse.quote)

    @classmethod
    def build_url(cls, base_url: str, path: str,
                  params: Optional[Mapping[str, Any]] = None) -> str:
        """
        Join a base URL, a path and query parameters into one URL.

        Args:
            base_url: server root, with or without a trailing slash (a
                path prefix such as ``http://host/obscuralens`` is kept).
            path: absolute path starting with ``/``.
            params: optional query parameters.

        Returns:
            The fully-joined URL.

        Example:
            >>> UrllibTransport.build_url('http://x:1/', '/api/stats')
            'http://x:1/api/stats'
        """
        base = str(base_url or '').rstrip('/')
        path = str(path or '')
        if not path.startswith('/'):
            path = f'/{path}'
        url = f'{base}{path}'
        query = cls.build_query(params)
        if query:
            url = f'{url}?{query}'
        return url

    # -- Transport API ---------------------------------------------------

    def request(self, method: str, url: str,
                headers: Optional[Dict[str, str]] = None,
                params: Optional[Dict[str, Any]] = None,
                json_body: Any = None, body: Optional[bytes] = None,
                timeout: Optional[float] = None) -> Response:
        """
        Perform one HTTP request with ``urllib.request``.

        Args:
            method: HTTP verb (``GET``/``POST``/``PUT``/``PATCH``/``DELETE``).
            url: absolute URL including query string.
            headers: request headers (Accept/Content-Type merged in here).
            params: unused on the wire (URL is pre-encoded); accepted so
                the transport interface stays uniform.
            json_body: JSON-serialisable body — serialised and sent with
                ``Content-Type: application/json``.
            body: raw bytes body (multipart uploads); wins over json_body.
            timeout: per-request timeout overriding the transport default.

        Returns:
            The response — including non-2xx statuses, which are returned
            rather than raised.

        Raises:
            TransportError: DNS failure, refused connection, protocol error.
            TimeoutError: the connection or read timed out.

        Example:
            >>> transport = UrllibTransport()
            >>> transport.request('GET', 'http://127.0.0.1:1/api/stats')
            Traceback (most recent call last):
                ...
            obscuralens.sdk.exceptions.TransportError: ...
        """
        del params  # the URL already carries the encoded query string
        if self._closed:
            raise TransportError('transport is closed')

        merged = dict(self.default_headers)
        merged.setdefault('User-Agent', self.user_agent)
        merged.setdefault('Accept', 'application/json')
        if headers:
            merged.update({str(k): str(v) for k, v in headers.items()})

        data: Optional[bytes] = None
        if body is not None:
            data = body
        elif json_body is not None:
            data = _json.dumps(json_body).encode('utf-8')
            merged.setdefault('Content-Type', 'application/json')

        request = urllib.request.Request(
            url=url, data=data, method=str(method or 'GET').upper())
        for key, value in merged.items():
            request.add_header(key, value)

        effective_timeout = self.timeout if timeout is None else float(timeout)
        try:
            with self._opener.open(request, timeout=effective_timeout) as raw:
                response = Response(
                    status=int(raw.status or 200),
                    headers=_flatten_headers(raw.headers),
                    body=raw.read(),
                )
            return response
        except urllib.error.HTTPError as exc:
            # HTTPError carries the full error response; surface it as a
            # normal Response so the client can map the status code.
            headers = _flatten_headers(exc.headers) if exc.headers else {}
            try:
                error_body = exc.read()
            except (OSError, ValueError):  # pragma: no cover - defensive
                error_body = b''
            return Response(status=int(exc.code), headers=headers,
                            body=error_body)
        except urllib.error.URLError as exc:
            reason = getattr(exc, 'reason', None)
            if isinstance(reason, socket.timeout):
                raise TimeoutError(
                    f'request timed out after {effective_timeout}s: {url}',
                    timeout=effective_timeout) from exc
            raise TransportError(
                f'connection failed: {reason or exc}') from exc
        except socket.timeout as exc:
            raise TimeoutError(
                f'request timed out after {effective_timeout}s: {url}',
                timeout=effective_timeout) from exc
        except OSError as exc:
            raise TransportError(
                f'connection failed: {exc}') from exc

    def close(self) -> None:
        """Mark the transport closed; further requests raise TransportError."""
        self._closed = True


def _flatten_headers(headers: Any) -> Dict[str, str]:
    """Convert an ``email.message.Message`` (or mapping) to a plain dict."""
    flat: Dict[str, str] = {}
    try:
        items = headers.items()
    except AttributeError:  # pragma: no cover - defensive
        return flat
    for key, value in items:
        text = str(value)
        if key in flat:
            flat[key] = f'{flat[key]}, {text}'
        else:
            flat[key] = text
    return flat


#: A queued transport item: a canned Response, or an exception to raise.
TransportScript = Union[Response, Exception]


class StaticTransport(Transport):
    """
    In-memory transport for tests — a programmable fake server.

    Preload a list of :class:`Response` objects and/or exception instances;
    each :meth:`request` pops the next item (responses are returned,
    exceptions are raised). Every call is recorded in :meth:`calls` as a
    dict with the ``method``, ``url``, ``params``, ``json_body``,
    ``body`` and ``headers`` actually sent — perfect for asserting on the
    exact endpoint a client method hit.

    When the script runs dry the transport raises :class:`TransportError`
    so a missing expectation fails loudly instead of silently repeating.

    Args:
        script: sequence of Responses (returned) and Exceptions (raised),
            consumed in order.
        repeat_last: when True the final script item repeats forever
            instead of raising once the script is exhausted.

    Example:
        >>> transport = StaticTransport([Response.from_json(200, {'ok': 1})])
        >>> transport.request('GET', 'http://x/api/stats').json()
        {'ok': 1}
        >>> transport.calls[0]['method']
        'GET'
    """

    def __init__(self, script: Optional[Sequence[TransportScript]] = None,
                 repeat_last: bool = False) -> None:
        self.script: List[TransportScript] = list(script or [])
        self.repeat_last = bool(repeat_last)
        self.calls: List[Dict[str, Any]] = []
        self.closed = False

    # -- script management -------------------------------------------------

    def enqueue(self, *items: TransportScript) -> 'StaticTransport':
        """
        Append more scripted outcomes (responses or exceptions).

        Args:
            items: Responses to return / exceptions to raise, in order.

        Returns:
            self, for chaining.

        Example:
            >>> transport = StaticTransport()
            >>> transport.enqueue(Response.from_json(200, {'a': 1}))
            StaticTransport(script=[Response(status=200, ...)])
        """
        self.script.extend(items)
        return self

    def next_response(self) -> Optional[TransportScript]:
        """Pop the next scripted item without recording a call."""
        if not self.script:
            return None
        if len(self.script) == 1 and self.repeat_last:
            return self.script[0]
        return self.script.pop(0)

    # -- Transport API ---------------------------------------------------

    def request(self, method: str, url: str,
                headers: Optional[Dict[str, str]] = None,
                params: Optional[Dict[str, Any]] = None,
                json_body: Any = None, body: Optional[bytes] = None,
                timeout: Optional[float] = None) -> Response:
        """
        Return/raise the next scripted outcome and record the call.

        Args:
            method: HTTP verb the client asked for.
            url: absolute URL the client built.
            headers: request headers the client merged.
            params: pre-encoded query parameters (recorded verbatim).
            json_body: the JSON body the client serialised (recorded).
            body: raw body bytes when the client bypassed JSON (recorded).
            timeout: requested timeout (recorded).

        Returns:
            The next scripted :class:`Response`.

        Raises:
            Exception: whatever exception instance was next in the script
                (the client retries :class:`TransportError` /
                :class:`TimeoutError` instances).
            TransportError: when the script is exhausted (and
                ``repeat_last`` is False) or the transport was closed.

        Example:
            >>> transport = StaticTransport([Response.from_json(201, {'id': 1})])
            >>> transport.request('POST', 'http://x/api/cases',
            ...                    json_body={'name': 'acme'}).status
            201
        """
        self.calls.append({
            'method': str(method or 'GET').upper(),
            'url': str(url),
            'params': dict(params) if params else {},
            'json_body': json_body,
            'body': body,
            'headers': dict(headers) if headers else {},
            'timeout': timeout,
        })
        if self.closed:
            raise TransportError('transport is closed')
        item = self.next_response()
        if item is None:
            raise TransportError(
                'StaticTransport script exhausted — no response queued '
                f'for {method} {url}')
        if isinstance(item, Exception):
            raise item
        return item

    def close(self) -> None:
        """Flip the ``closed`` flag (recorded calls are kept for asserts)."""
        self.closed = True

    # -- introspection helpers ---------------------------------------------

    @property
    def last_call(self) -> Optional[Dict[str, Any]]:
        """The most recent recorded call, or ``None`` when none yet."""
        return self.calls[-1] if self.calls else None

    def urls(self) -> List[str]:
        """The recorded URLs in call order."""
        return [call['url'] for call in self.calls]

    def methods(self) -> List[str]:
        """The recorded HTTP verbs in call order."""
        return [call['method'] for call in self.calls]

    def header_of(self, call_index: int, name: str) -> Optional[str]:
        """
        Case-insensitive header lookup on a recorded call.

        Args:
            call_index: index into :attr:`calls`.
            name: header name (case-insensitive).

        Returns:
            The recorded header value or ``None``.

        Example:
            >>> transport = StaticTransport([Response.from_json(200, {})])
            >>> transport.request('GET', 'http://x/', headers={'Accept': 'application/json'})
            Response(status=200, ...)
            >>> transport.header_of(0, 'accept')
            'application/json'
        """
        try:
            call = self.calls[call_index]
        except IndexError:
            return None
        return header_value(call.get('headers') or {}, name)

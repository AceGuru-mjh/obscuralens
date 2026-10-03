"""
Exception hierarchy for the ObscuraLens Python SDK.

Every error raised by :class:`~obscuralens.sdk.client.ObscuraLensClient`
(and its async twin) derives from :class:`SdkError`, so callers can guard a
whole session with a single ``except SdkError`` clause::

    from obscuralens.sdk import ObscuraLensClient, SdkError

    client = ObscuraLensClient("http://127.0.0.1:8000")
    try:
        result = client.ip("8.8.8.8")
    except SdkError as exc:
        print(f"lookup failed: {exc} (status={exc.status})")

The hierarchy mirrors where a failure happens:

* :class:`TransportError` / :class:`TimeoutError` — the request never
  produced an HTTP response (DNS failure, refused connection, socket
  timeout). These are the errors the client retries.
* :class:`ApiError` (plus :class:`BadRequestError`, :class:`NotFoundError`,
  :class:`RateLimitError`, :class:`ServerError`) — the server answered with
  a non-2xx status. The parsed JSON body is preserved on ``.payload``.
* :class:`MalformedResponseError` — a 2xx response whose body was not the
  JSON the SDK expected.

All exceptions are safe to construct with partial information; ``.status``
is ``None`` for connection-level failures and ``.payload`` is ``None`` when
the body could not be parsed as JSON.
"""

from typing import Any, Dict, Optional

__all__ = [
    'SdkError',
    'TransportError',
    'TimeoutError',
    'ApiError',
    'BadRequestError',
    'NotFoundError',
    'RateLimitError',
    'ServerError',
    'MalformedResponseError',
]


class SdkError(Exception):
    """
    Base class for every error raised by the ObscuraLens SDK.

    Args:
        message: human-readable description of the failure.
        status: HTTP status code when a response was received, else ``None``.
        payload: parsed JSON body of the error response when available.

    Example:
        >>> try:
        ...     client.lookup("ip", "8.8.8.8")   # doctest: +SKIP
        ... except SdkError as exc:
        ...     print(exc.status, exc.payload)   # doctest: +SKIP
    """

    def __init__(self, message: str, status: Optional[int] = None,
                 payload: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = str(message)
        self.status = status
        self.payload = payload if isinstance(payload, dict) else None

    def __str__(self) -> str:
        """Return the message, suffixed with the status code when known."""
        if self.status is None:
            return self.message
        return f"{self.message} (HTTP {self.status})"


class TransportError(SdkError):
    """
    The request could not be delivered or no response arrived.

    Raised for DNS failures, refused connections and any other
    connection-level problem reported by the transport. The client
    retries requests that fail with this error (up to ``retries``
    attempts) before letting it propagate.

    Args:
        message: description of the connection failure.
        payload: optional parsed body (usually ``None`` for transport errors).

    Example:
        >>> client = ObscuraLensClient("http://127.0.0.1:9")   # doctest: +SKIP
        >>> client.stats()   # TransportError after retries   # doctest: +SKIP
    """

    def __init__(self, message: str,
                 payload: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, status=None, payload=payload)


class TimeoutError(SdkError):
    """
    The request timed out before a response arrived.

    Raised when the transport reports a socket/operation timeout. Like
    :class:`TransportError` this is a connection-level failure with no HTTP
    status; the client retries it with exponential backoff.

    Args:
        message: description of the timeout.
        timeout: the timeout value (seconds) that was in effect, if known.
        payload: optional parsed body (usually ``None`` for timeouts).

    Example:
        >>> client = ObscuraLensClient(timeout=1)   # doctest: +SKIP
        >>> client.lookup("ip", "8.8.8.8")          # TimeoutError   # doctest: +SKIP
    """

    def __init__(self, message: str, timeout: Optional[float] = None,
                 payload: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, status=None, payload=payload)
        self.timeout = timeout


class ApiError(SdkError):
    """
    The server answered with a non-2xx HTTP status.

    The body is parsed as JSON when possible and stored on ``.payload``
    (ObscuraLens error bodies are ``{"detail": "..."}``); the ``detail``
    string is used as the exception message.

    Args:
        message: error description (usually the server's ``detail``).
        status: the HTTP status code (always set for ApiError).
        payload: the parsed JSON error body, when parseable.

    Example:
        >>> try:
        ...     client.lookup("nope", "x")   # doctest: +SKIP
        ... except ApiError as exc:
        ...     print(exc.status, exc.payload)   # doctest: +SKIP
    """

    def __init__(self, message: str, status: int = 0,
                 payload: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, status=int(status), payload=payload)


class BadRequestError(ApiError):
    """
    HTTP 400 — invalid kind, failed target validation or a bad body.

    Example:
        >>> client.lookup("iban", "not-an-iban")   # BadRequestError   # doctest: +SKIP
    """

    def __init__(self, message: str, status: int = 400,
                 payload: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, status=status, payload=payload)


class NotFoundError(ApiError):
    """
    HTTP 404 — unknown resource id (case, watch, diff target...).

    Example:
        >>> client.case(999999)   # NotFoundError   # doctest: +SKIP
    """

    def __init__(self, message: str, status: int = 404,
                 payload: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, status=status, payload=payload)


class RateLimitError(ApiError):
    """
    HTTP 429 — the server applied rate limiting.

    ``.retry_after`` carries the server's ``Retry-After`` header value in
    seconds when the header was numeric; the client honours it before
    retrying (sleeping exactly that long instead of the computed backoff).

    Args:
        message: error description.
        status: HTTP status (429).
        payload: parsed JSON error body, when parseable.
        retry_after: seconds to wait before the next attempt, or ``None``.

    Example:
        >>> try:
        ...     client.stats()   # doctest: +SKIP
        ... except RateLimitError as exc:
        ...     print("retry in", exc.retry_after)   # doctest: +SKIP
    """

    def __init__(self, message: str, status: int = 429,
                 payload: Optional[Dict[str, Any]] = None,
                 retry_after: Optional[float] = None) -> None:
        super().__init__(message, status=status, payload=payload)
        self.retry_after = retry_after


class ServerError(ApiError):
    """
    HTTP 5xx — the server itself failed (report build, corrupt data...).

    Example:
        >>> client.diff("domain", "broken.example")   # ServerError   # doctest: +SKIP
    """

    def __init__(self, message: str, status: int = 500,
                 payload: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, status=status, payload=payload)


class MalformedResponseError(SdkError):
    """
    A 2xx response whose body could not be parsed as JSON.

    The SDK expects JSON from every endpoint it models (the HTML download
    mode of ``report()`` bypasses parsing entirely), so a non-JSON success
    body raises this instead of returning garbage. The raw body text is
    kept on ``.body_text`` for diagnostics.

    Args:
        message: description including a body excerpt.
        status: the HTTP status of the offending response.
        payload: always ``None`` (the body was not JSON).
        body_text: the raw response body as text (may be truncated).

    Example:
        >>> client = ObscuraLensClient(transport=broken_transport)   # doctest: +SKIP
        >>> client.stats()   # MalformedResponseError   # doctest: +SKIP
    """

    def __init__(self, message: str, status: Optional[int] = None,
                 payload: Optional[Dict[str, Any]] = None,
                 body_text: str = '') -> None:
        super().__init__(message, status=status, payload=payload)
        self.body_text = body_text

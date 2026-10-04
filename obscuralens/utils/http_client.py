"""
Shared HTTP client for all OSINT data sources.

Centralises timeouts, retries, rate limiting, optional proxy support, a TTL
response cache and metrics so every tracker behaves the same way and no single
data source can crash a scan.

Cache usage is opt-in per call (``use_cache=True`` for get_json/get_text) and
controlled globally by ``app.cache_enabled``. Only HTTP 200 responses are
stored; failures are never cached.
"""

import contextlib
import hashlib
import logging
import random
from typing import Any, Dict, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter

try:  # urllib3 v1 / v2 compatible
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover
    Retry = None  # type: ignore

from ..config import config
from ..core.cache import cache
from ..core.metrics import metrics
from ..core.ratelimit import acquire as rate_acquire

logger = logging.getLogger(__name__)

# Response bodies larger than this are not stored in the cache.
MAX_CACHED_TEXT = 400_000


class HttpClient:
    """Thin wrapper around requests with retries and graceful failure."""

    def __init__(self, timeout: Optional[int] = None):
        self.timeout = timeout or config.app_config.request_timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config.app_config.user_agent,
            'Accept': 'application/json, text/json, */*',
            'Accept-Language': 'en-US,en;q=0.9',
        })
        if Retry is not None:
            retry = Retry(
                total=2,
                backoff_factor=0.4,
                status_forcelist=(429, 500, 502, 503, 504),
                allowed_methods=frozenset(['GET', 'HEAD']),
            )
            # Pool sized for the parallel fan-out: urllib3 keeps one pool per
            # host, and a 20-source sweep touches 20 different hosts at once
            # while batch runs stack several lookups per host. The old fixed
            # 20/20 pool evicted pools mid-sweep and forced reconnects (a
            # full TCP + TLS handshake each time); scaling with max_workers
            # keeps every source on a warm keep-alive connection (v5.2).
            pool = max(48, int(config.app_config.max_workers or 12) * 4)
            adapter = HTTPAdapter(max_retries=retry, pool_connections=pool,
                                  pool_maxsize=pool)
            self.session.mount('https://', adapter)
            self.session.mount('http://', adapter)
        self._proxy = None
        self._apply_proxy()

    # -- transport --------------------------------------------------------

    def _apply_proxy(self) -> None:
        """Keep the session proxies in sync with the live configuration."""
        proxy = config.app_config.proxy or ''
        if proxy == self._proxy:
            return
        self._proxy = proxy
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        else:
            self.session.proxies = {}

    def get(self, url: str, **kwargs) -> requests.Response:
        """Perform a GET request with rate limiting, proxy and timeout."""
        self._apply_proxy()
        rate_acquire(url)
        metrics.record_request(url)
        kwargs.setdefault('timeout', self.timeout)
        response = self.session.get(url, **kwargs)
        with contextlib.suppress(AttributeError, TypeError):
            metrics.record_bytes(len(response.content or b''))
        return response

    @staticmethod
    def _cache_key(url: str, headers: Optional[Dict[str, str]]) -> str:
        if not headers:
            return url
        digest = hashlib.sha256(
            repr(sorted(headers.items())).encode('utf-8')).hexdigest()[:12]
        return f"{url}#{digest}"

    # -- JSON -------------------------------------------------------------

    def get_json(self, url: str, use_cache: bool = True,
                 cache_ttl: Optional[int] = None,
                 **kwargs) -> Tuple[bool, Any, str]:
        """
        GET a URL and parse JSON.

        Returns:
            (success, parsed_json_or_None, error_message)
        """
        headers = kwargs.get('headers')
        key = self._cache_key(url, headers)
        if use_cache:
            cached = cache.get('json', key)
            if cached is not None:
                metrics.record_cache(True)
                return True, cached, ''

        response = None
        try:
            response = self.get(url, **kwargs)
            response.raise_for_status()
            data = response.json()
            if use_cache:
                cache.set('json', key, data, ttl=cache_ttl)
            return True, data, ''
        except requests.exceptions.Timeout:
            metrics.record_failure('timeout')
            return False, None, 'timeout'
        except requests.exceptions.SSLError:
            metrics.record_failure('ssl')
            return False, None, 'ssl error (source unreachable from this network)'
        except requests.exceptions.ConnectionError:
            metrics.record_failure('connection')
            return False, None, 'connection failed'
        except requests.exceptions.HTTPError:
            code = response.status_code if response is not None else '?'
            metrics.record_failure(f'http {code}')
            if code == 404:
                # Often a legitimate "nothing found" answer rather than a failure.
                return False, None, 'not found'
            return False, None, f'http {code}'
        except ValueError:
            metrics.record_failure('invalid json')
            return False, None, 'invalid json'
        except requests.exceptions.RequestException as e:
            metrics.record_failure(type(e).__name__)
            return False, None, type(e).__name__

    # -- text -------------------------------------------------------------

    def get_text(self, url: str, use_cache: bool = True,
                 cache_ttl: Optional[int] = None,
                 **kwargs) -> Tuple[bool, str, str]:
        """GET a URL and return plain text."""
        headers = kwargs.get('headers')
        key = self._cache_key(url, headers)
        if use_cache:
            cached = cache.get('text', key)
            if cached is not None:
                metrics.record_cache(True)
                return True, cached, ''

        try:
            response = self.get(url, **kwargs)
            response.raise_for_status()
            text = response.text
            if use_cache and len(text) <= MAX_CACHED_TEXT:
                cache.set('text', key, text, ttl=cache_ttl)
            return True, text, ''
        except requests.exceptions.RequestException as e:
            metrics.record_failure(type(e).__name__)
            return False, '', type(e).__name__

    # -- raw response -----------------------------------------------------

    def fetch(self, url: str, use_cache: bool = True,
              cache_ttl: Optional[int] = None,
              **kwargs) -> Tuple[int, str, str]:
        """
        GET a URL and return (status_code, text, error).

        Designed for checks that care about status codes (OpenPGP keyserver,
        Gravatar). Successful (200) bodies are cached; negative answers are
        cheap enough to ask again.
        """
        headers = kwargs.get('headers')
        key = self._cache_key(url, headers)
        if use_cache:
            cached = cache.get('fetch', key)
            if cached is not None and cached.get('status') == 200:
                metrics.record_cache(True)
                return 200, cached.get('text', ''), ''

        try:
            response = self.get(url, **kwargs)
            status = response.status_code
            text = response.text or ''
            if use_cache and status == 200 and len(text) <= MAX_CACHED_TEXT:
                cache.set('fetch', key, {'status': status, 'text': text},
                          ttl=cache_ttl)
            return status, text, ''
        except requests.exceptions.RequestException as e:
            metrics.record_failure(type(e).__name__)
            return 0, '', type(e).__name__

    # -- JSON POST (v4.0) --------------------------------------------------

    def post_json(self, url: str, payload: Optional[Dict[str, Any]] = None,
                  **kwargs) -> Tuple[bool, Any, str]:
        """
        POST a JSON body and parse the JSON response.

        Used by APIs that only accept POST (MalwareBazaar, ThreatFox,
        OpenAI-compatible LLM endpoints). POST responses are never cached.

        Returns:
            (success, parsed_json_or_None, error_message)
        """
        self._apply_proxy()
        rate_acquire(url)
        metrics.record_request(url)
        kwargs.setdefault('timeout', self.timeout)
        response = None
        try:
            response = self.session.post(url, json=payload, **kwargs)
            with contextlib.suppress(AttributeError, TypeError):
                metrics.record_bytes(len(response.content or b''))
            response.raise_for_status()
            return True, response.json(), ''
        except requests.exceptions.Timeout:
            metrics.record_failure('timeout')
            return False, None, 'timeout'
        except requests.exceptions.SSLError:
            metrics.record_failure('ssl')
            return False, None, 'ssl error (source unreachable from this network)'
        except requests.exceptions.ConnectionError:
            metrics.record_failure('connection')
            return False, None, 'connection failed'
        except requests.exceptions.HTTPError:
            code = response.status_code if response is not None else '?'
            metrics.record_failure(f'http {code}')
            if code == 404:
                return False, None, 'not found'
            return False, None, f'http {code}'
        except ValueError:
            metrics.record_failure('invalid json')
            return False, None, 'invalid json'
        except requests.exceptions.RequestException as e:
            metrics.record_failure(type(e).__name__)
            return False, None, type(e).__name__


# Shared client instance
http = HttpClient()


def jitter(seconds: float) -> float:
    """Small randomised delay so parallel calls do not look robotic."""
    return seconds * (0.8 + random.random() * 0.4)


def get_json(url: str, **kwargs) -> Tuple[bool, Any, str]:
    """Module-level convenience wrapper used by source readers."""
    return http.get_json(url, **kwargs)

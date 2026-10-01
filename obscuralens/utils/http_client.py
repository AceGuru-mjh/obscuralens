"""
Shared HTTP client for all OSINT data sources.

Centralises timeouts, retries, User-Agent handling and error capture so every
tracker behaves the same way and no single data source can crash a scan.
"""

import logging
import random
from typing import Any, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter

try:  # urllib3 v1 / v2 compatible
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover
    Retry = None  # type: ignore

from ..config import config

logger = logging.getLogger(__name__)


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
            adapter = HTTPAdapter(max_retries=retry, pool_connections=20,
                                  pool_maxsize=20)
            self.session.mount('https://', adapter)
            self.session.mount('http://', adapter)

    def get(self, url: str, **kwargs) -> requests.Response:
        """Perform a GET request with the configured timeout."""
        kwargs.setdefault('timeout', self.timeout)
        return self.session.get(url, **kwargs)

    def get_json(self, url: str, **kwargs) -> Tuple[bool, Any, str]:
        """
        GET a URL and parse JSON.

        Returns:
            (success, parsed_json_or_None, error_message)
        """
        response = None
        try:
            response = self.get(url, **kwargs)
            response.raise_for_status()
            return True, response.json(), ''
        except requests.exceptions.Timeout:
            return False, None, 'timeout'
        except requests.exceptions.SSLError:
            return False, None, 'ssl error (source unreachable from this network)'
        except requests.exceptions.ConnectionError:
            return False, None, 'connection failed'
        except requests.exceptions.HTTPError:
            code = response.status_code if response is not None else '?'
            if code == 404:
                # Often a legitimate "nothing found" answer rather than a failure.
                return False, None, 'not found'
            return False, None, f'http {code}'
        except ValueError:
            return False, None, 'invalid json'
        except requests.exceptions.RequestException as e:
            return False, None, type(e).__name__

    def get_text(self, url: str, **kwargs) -> Tuple[bool, str, str]:
        """GET a URL and return plain text."""
        try:
            response = self.get(url, **kwargs)
            response.raise_for_status()
            return True, response.text, ''
        except requests.exceptions.RequestException as e:
            return False, '', type(e).__name__


# Shared client instance
http = HttpClient()


def jitter(seconds: float) -> float:
    """Small randomised delay so parallel calls do not look robotic."""
    return seconds * (0.8 + random.random() * 0.4)

"""
Offline test suite for the ObscuraLens Python SDK.

Every test runs against :class:`~obscuralens.sdk.transport.StaticTransport`
(a programmable in-memory server) — no network, no FastAPI, no database.
The suite covers URL building, retries/backoff, error mapping, every
endpoint method's path/params/body, model construction from realistic
payload shapes, the escape hatches and the async wrapper.
"""

import asyncio
import socket
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

import pytest

from obscuralens.sdk import (
    AlertConfig,
    AsyncObscuraLensClient,
    BatchProgress,
    Case,
    CaseItem,
    CaseNote,
    CorrelationResult,
    DiffReport,
    HistoryResult,
    IntelVerdict,
    InvestigationReport,
    KindInfo,
    LookupResult,
    MalformedResponseError,
    NotFoundError,
    ObscuraLensClient,
    PairComparison,
    PatternReport,
    Provenance,
    RateLimitError,
    Response,
    RiskReport,
    SdkError,
    ServerError,
    SourceHealthEntry,
    StaticTransport,
    StatsSummary,
    Timeline,
    ToolboxResult,
    Transport,
    TransportError,
    UrllibTransport,
    WatchDiff,
    WatchEntry,
)
from obscuralens.sdk.exceptions import ApiError, BadRequestError, TimeoutError
from obscuralens.sdk.transport import header_value

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

BASE = 'http://127.0.0.1:8000'


def make_client(script=None, base_url: str = BASE, retries: int = 1,
                backoff: float = 0.0, **kwargs: Any
                ) -> Tuple[ObscuraLensClient, StaticTransport, List[float]]:
    """Build a client on a StaticTransport with a recording sleeper."""
    sleeps: List[float] = []
    transport = StaticTransport(list(script or []))
    client = ObscuraLensClient(
        base_url=base_url, transport=transport, retries=retries,
        backoff=backoff, sleep_fn=sleeps.append, **kwargs)
    return client, transport, sleeps


def ok(payload: Any, status: int = 200) -> Response:
    """Canned JSON success response."""
    return Response.from_json(status, payload)


def err(status: int, detail: str = 'boom',
        headers: Optional[Dict[str, str]] = None) -> Response:
    """Canned JSON error response (the server's {'detail': ...} shape)."""
    return Response.from_json(status, {'detail': detail},
                              headers=headers or {})


IP_PAYLOAD: Dict[str, Any] = {
    'ip': '8.8.8.8',
    'info': {
        'ip': '8.8.8.8', 'country': 'United States', 'country_code': 'US',
        'asn': 'AS15169', 'org': 'Google LLC', 'hostname': 'dns.google',
    },
    'field_sources': {
        'country': ['ipwhois.app', 'ipwho.is'],
        'asn': ['ipwhois.app'],
        'hostname': ['ipwho.is'],
    },
    'sources_ok': ['ipwhois.app', 'ipwho.is'],
    'sources_failed': {'ipinfo': '401'},
    'field_count': 6,
    'success': True,
    'errors': ['1 source(s) unavailable'],
    'elapsed': 0.42,
}


# ---------------------------------------------------------------------------
# Response object
# ---------------------------------------------------------------------------

class TestResponse:

    def test_json_parses_body(self):
        response = Response(200, {'Content-Type': 'application/json'},
                            b'{"status": "ok"}')
        assert response.json() == {'status': 'ok'}

    def test_json_raises_value_error_on_bad_json(self):
        response = Response(200, {}, b'<html>not json</html>')
        with pytest.raises(ValueError):
            response.json()

    def test_json_raises_value_error_on_empty_body(self):
        with pytest.raises(ValueError):
            Response(200, {}, b'').json()

    def test_text_decodes_utf8_and_empty(self):
        assert Response(200, {}, 'héllo'.encode('utf-8')).text == 'héllo'
        assert Response(200, {}, b'').text == ''

    def test_ok_property(self):
        assert Response(200).ok is True
        assert Response(201).ok is True
        assert Response(429).ok is False

    def test_from_json_round_trip(self):
        response = Response.from_json(201, {'id': 3}, {'X': 'y'})
        assert response.status == 201
        assert response.json() == {'id': 3}
        assert response.headers == {'X': 'y'}

    def test_header_value_case_insensitive(self):
        assert header_value({'Retry-After': '2'}, 'retry-after') == '2'
        assert header_value({'retry-after': '2'}, 'Retry-After') == '2'
        assert header_value({}, 'Retry-After') is None


# ---------------------------------------------------------------------------
# StaticTransport behaviour
# ---------------------------------------------------------------------------

class TestStaticTransport:

    def test_returns_scripted_responses_in_order(self):
        transport = StaticTransport([ok({'a': 1}), ok({'b': 2})])
        assert transport.request('GET', 'http://x/1').json() == {'a': 1}
        assert transport.request('GET', 'http://x/2').json() == {'b': 2}

    def test_records_every_call(self):
        transport = StaticTransport([ok({}), ok({})])
        transport.request('GET', 'http://x/api/stats',
                          headers={'Accept': 'application/json'},
                          params={'limit': 5})
        transport.request('POST', 'http://x/api/cases',
                          json_body={'name': 'acme'})
        assert transport.methods() == ['GET', 'POST']
        first, second = transport.calls
        assert first['url'] == 'http://x/api/stats'
        assert first['params'] == {'limit': 5}
        assert first['headers']['Accept'] == 'application/json'
        assert second['json_body'] == {'name': 'acme'}

    def test_raises_scripted_exception(self):
        transport = StaticTransport([TransportError('down')])
        with pytest.raises(TransportError):
            transport.request('GET', 'http://x/')

    def test_exhausted_script_raises_transport_error(self):
        transport = StaticTransport([])
        with pytest.raises(TransportError):
            transport.request('GET', 'http://x/')

    def test_repeat_last_repeats_forever(self):
        transport = StaticTransport([ok({'v': 1})], repeat_last=True)
        for _ in range(5):
            assert transport.request('GET', 'http://x/').json() == {'v': 1}

    def test_close_flag_and_closed_requests(self):
        transport = StaticTransport([ok({})])
        assert transport.closed is False
        transport.close()
        assert transport.closed is True
        with pytest.raises(TransportError):
            transport.request('GET', 'http://x/')

    def test_header_of_records_headers(self):
        transport = StaticTransport([ok({})])
        transport.request('GET', 'http://x/', headers={'X-API-Key': 'k'})
        assert transport.header_of(0, 'x-api-key') == 'k'
        assert transport.header_of(99, 'x-api-key') is None

    def test_enqueue_appends(self):
        transport = StaticTransport()
        transport.enqueue(ok({'a': 1}))
        assert transport.request('GET', 'http://x/').json() == {'a': 1}

    def test_last_call_and_urls(self):
        transport = StaticTransport([ok({}), ok({})])
        transport.request('GET', 'http://x/a')
        transport.request('GET', 'http://x/b')
        assert transport.urls() == ['http://x/a', 'http://x/b']
        assert transport.last_call['url'] == 'http://x/b'

    def test_body_recorded_for_raw_uploads(self):
        transport = StaticTransport([ok({})])
        transport.request('POST', 'http://x/upload', body=b'BINARY')
        assert transport.calls[0]['body'] == b'BINARY'
        assert transport.calls[0]['json_body'] is None


# ---------------------------------------------------------------------------
# UrllibTransport (offline: URL building + monkeypatched urlopen)
# ---------------------------------------------------------------------------

class TestUrllibTransport:

    def test_build_query_encodes_spaces_and_unicode(self):
        query = UrllibTransport.build_query({'q': 'a b', 't': 'ü'})
        assert query == 'q=a%20b&t=%C3%BC'

    def test_build_query_skips_none_and_lowercases_bools(self):
        assert UrllibTransport.build_query(
            {'kind': None, 'pivot': True, 'limit': 10}) == \
            'pivot=true&limit=10'

    def test_build_url_with_and_without_trailing_slash(self):
        assert UrllibTransport.build_url('http://x:1/', '/api/stats') == \
            'http://x:1/api/stats'
        assert UrllibTransport.build_url('http://x:1', '/api/stats') == \
            'http://x:1/api/stats'

    def test_build_url_keeps_path_prefix_and_query(self):
        url = UrllibTransport.build_url('http://x/obscuralens/',
                                        '/api/stats', {'limit': 5})
        assert url == 'http://x/obscuralens/api/stats?limit=5'

    @pytest.mark.parametrize('method', ['GET', 'POST', 'PUT', 'DELETE'])
    def test_request_uses_http_method(self, monkeypatch, method):
        seen = {}

        def fake_open(self, request, timeout=None):
            seen['method'] = request.get_method()
            seen['timeout'] = timeout
            seen['url'] = request.full_url
            return _FakeRaw(200, {}, b'{"ok": true}')

        monkeypatch.setattr(
            urllib.request.OpenerDirector, 'open', fake_open)
        transport = UrllibTransport(timeout=7)
        response = transport.request(method, 'http://x/api/stats')
        assert response.json() == {'ok': True}
        assert seen['method'] == method
        assert seen['timeout'] == 7

    def test_request_sends_accept_and_content_type(self, monkeypatch):
        seen = {}

        def fake_open(self, request, timeout=None):
            seen['headers'] = dict(request.header_items())
            return _FakeRaw(200, {}, b'{}')

        monkeypatch.setattr(
            urllib.request.OpenerDirector, 'open', fake_open)
        transport = UrllibTransport()
        transport.request('POST', 'http://x/api/cases',
                          headers={'Content-Type': 'application/json'},
                          json_body={'name': 'acme'})
        values = {key.lower(): value for key, value in seen['headers'].items()}
        assert values['accept'] == 'application/json'
        assert values['content-type'] == 'application/json'
        assert 'obscuralens-sdk/' in values['user-agent']

    def test_http_error_becomes_response(self, monkeypatch):
        def fake_open(self, request, timeout=None):
            raise urllib.error.HTTPError(
                request.full_url, 404, 'Not Found',
                {'Content-Type': 'application/json'},
                _BytesLike(b'{"detail": "not found"}'))

        monkeypatch.setattr(
            urllib.request.OpenerDirector, 'open', fake_open)
        transport = UrllibTransport()
        response = transport.request('GET', 'http://x/api/cases/9')
        assert response.status == 404
        assert response.json() == {'detail': 'not found'}

    def test_urlerror_becomes_transport_error(self, monkeypatch):
        def fake_open(self, request, timeout=None):
            raise urllib.error.URLError('connection refused')

        monkeypatch.setattr(
            urllib.request.OpenerDirector, 'open', fake_open)
        transport = UrllibTransport()
        with pytest.raises(TransportError):
            transport.request('GET', 'http://x/api/stats')

    def test_socket_timeout_reason_becomes_timeout_error(self, monkeypatch):
        def fake_open(self, request, timeout=None):
            raise urllib.error.URLError(socket.timeout())

        monkeypatch.setattr(
            urllib.request.OpenerDirector, 'open', fake_open)
        transport = UrllibTransport(timeout=3)
        with pytest.raises(TimeoutError):
            transport.request('GET', 'http://x/api/stats')

    def test_direct_socket_timeout_becomes_timeout_error(self, monkeypatch):
        def fake_open(self, request, timeout=None):
            raise socket.timeout()

        monkeypatch.setattr(
            urllib.request.OpenerDirector, 'open', fake_open)
        with pytest.raises(TimeoutError):
            UrllibTransport().request('GET', 'http://x/api/stats')

    def test_closed_transport_refuses_requests(self):
        transport = UrllibTransport()
        transport.close()
        with pytest.raises(TransportError):
            transport.request('GET', 'http://x/api/stats')


class _FakeRaw:
    """Minimal stand-in for the object urlopen() returns."""

    def __init__(self, status: int, headers: Dict[str, str], body: bytes):
        self.status = status
        self.headers = headers
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> '_FakeRaw':
        return self

    def __exit__(self, *args: Any) -> bool:
        return False


class _BytesLike:
    """File-like object for HTTPError payloads."""

    def __init__(self, body: bytes):
        self._body = body

    def read(self) -> bytes:
        return self._body

    def close(self) -> None:
        return None


# ---------------------------------------------------------------------------
# URL building / headers through the client
# ---------------------------------------------------------------------------

class TestUrlBuilding:

    def test_base_url_trailing_slash_normalized(self):
        for base in (BASE, BASE + '/', 'http://127.0.0.1:8000//'):
            client, transport, _ = make_client([ok(IP_PAYLOAD)],
                                               base_url=base)
            client.ip('8.8.8.8')
            assert transport.calls[0]['url'] == \
                f'{BASE}/api/lookup/ip/8.8.8.8'

    def test_invalid_base_url_rejected(self):
        with pytest.raises(ValueError):
            ObscuraLensClient(base_url='not-a-url')

    def test_accept_header_always_sent(self):
        client, transport, _ = make_client([ok(IP_PAYLOAD)])
        client.ip('8.8.8.8')
        assert transport.header_of(0, 'Accept') == 'application/json'

    def test_api_key_header_sent_only_when_configured(self):
        client, transport, _ = make_client([ok(IP_PAYLOAD)], api_key='s3cret')
        client.stats()
        assert transport.header_of(0, 'X-API-Key') == 's3cret'

        client2, transport2, _ = make_client([ok({})])
        client2.stats()
        assert transport2.header_of(0, 'X-API-Key') is None

    def test_unicode_and_space_query_params_encoded(self):
        client, transport, _ = make_client(
            [ok({'items': [], 'count': 0})])
        client.history(q='user@example.com', limit=5)
        url = transport.calls[0]['url']
        assert url == f'{BASE}/api/history?q=user%40example.com&limit=5'

    def test_path_target_with_slashes_encoded(self):
        client, transport, _ = make_client([ok({})])
        client.lookup('url', 'https://example.com/page?a=1')
        assert transport.calls[0]['url'] == (
            f'{BASE}/api/lookup/url/https%3A%2F%2Fexample.com%2Fpage%3Fa%3D1')

    def test_none_query_params_dropped(self):
        client, transport, _ = make_client([ok({'events': []})])
        client.timeline(target=None, limit=50)
        assert transport.calls[0]['url'] == f'{BASE}/api/timeline?limit=50'
        assert transport.calls[0]['params'] == {'limit': 50}

    def test_bool_query_params_lowercase(self):
        client, transport, _ = make_client([ok({})])
        client.investigate('example.com', pivot=False)
        assert transport.calls[0]['url'].endswith(
            '/api/investigate?target=example.com&pivot=false')


# ---------------------------------------------------------------------------
# Retries / backoff
# ---------------------------------------------------------------------------

class TestRetries:

    def test_success_after_two_timeouts(self):
        client, transport, sleeps = make_client(
            [TimeoutError('t1'), TimeoutError('t2'), ok(IP_PAYLOAD)],
            retries=3, backoff=0.5)
        result = client.ip('8.8.8.8')
        assert isinstance(result, LookupResult)
        assert len(transport.calls) == 3
        assert sleeps == [0.5, 1.0]  # backoff * 2**attempt

    def test_retries_exhausted_raises_sdk_error(self):
        client, transport, sleeps = make_client(
            [TransportError('down')] * 5, retries=2, backoff=0.25)
        with pytest.raises(SdkError):
            client.stats()
        assert len(transport.calls) == 2
        assert sleeps == [0.25]

    def test_no_sleep_when_first_attempt_succeeds(self):
        client, transport, sleeps = make_client([ok({})], retries=3)
        client.stats()
        assert sleeps == []
        assert len(transport.calls) == 1

    def test_rate_limit_retry_after_honoured(self):
        client, transport, sleeps = make_client(
            [err(429, 'slow down', {'Retry-After': '2'}), ok(IP_PAYLOAD)],
            retries=3, backoff=10.0)
        result = client.ip('8.8.8.8')
        assert isinstance(result, LookupResult)
        assert sleeps == [2.0]  # Retry-After wins over the backoff

    def test_rate_limit_from_response_body(self):
        client, transport, sleeps = make_client(
            [err(429, 'slow down'), ok({})], retries=3, backoff=0.5)
        client.stats()
        assert sleeps == [0.5]  # no Retry-After header -> backoff applies

    def test_rate_limit_exhausted_raises(self):
        client, transport, _ = make_client(
            [err(429, 'nope')] * 4, retries=3, backoff=0.0)
        with pytest.raises(RateLimitError):
            client.stats()
        assert len(transport.calls) == 3

    def test_server_error_not_retried(self):
        client, transport, sleeps = make_client(
            [err(500, 'broken')] * 3, retries=3, backoff=0.5)
        with pytest.raises(ServerError):
            client.stats()
        assert len(transport.calls) == 1
        assert sleeps == []

    def test_backoff_capped(self):
        client, _, sleeps = make_client(
            [TimeoutError('t')] * 3 + [ok({})],
            retries=4, backoff=20.0, max_backoff=25.0)
        client.stats()
        assert sleeps == [20.0, 25.0, 25.0]

    def test_retries_zero_means_single_attempt(self):
        client, transport, _ = make_client(
            [TimeoutError('t'), ok({})], retries=0)
        with pytest.raises(SdkError):
            client.stats()
        assert len(transport.calls) == 1


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------

class TestErrorMapping:

    def test_404_maps_to_not_found(self):
        client, _, _ = make_client([err(404, 'not found')])
        with pytest.raises(NotFoundError) as excinfo:
            client.case(999)
        assert excinfo.value.status == 404
        assert excinfo.value.message == 'not found'
        assert excinfo.value.payload == {'detail': 'not found'}

    def test_400_maps_to_bad_request(self):
        client, _, _ = make_client([err(400, 'unknown kind')])
        with pytest.raises(BadRequestError):
            client.lookup('iban', 'nope')

    def test_429_maps_to_rate_limit_with_retry_after(self):
        client, _, _ = make_client(
            [err(429, 'slow', {'Retry-After': '7'})], retries=1)
        with pytest.raises(RateLimitError) as excinfo:
            client.stats()
        assert excinfo.value.retry_after == 7.0
        assert excinfo.value.status == 429

    def test_500_maps_to_server_error(self):
        client, _, _ = make_client([err(500, 'report failed')])
        with pytest.raises(ServerError):
            client.diff('domain', 'x.example')

    def test_other_status_maps_to_plain_api_error(self):
        client, _, _ = make_client([err(403, 'forbidden')])
        with pytest.raises(ApiError) as excinfo:
            client.stats()
        assert not isinstance(excinfo.value, (NotFoundError, BadRequestError))
        assert excinfo.value.status == 403

    def test_200_non_json_maps_to_malformed(self):
        client, _, _ = make_client([Response(200, {}, b'<html>oops</html>')])
        with pytest.raises(MalformedResponseError) as excinfo:
            client.stats()
        assert '<html>' in excinfo.value.body_text

    def test_error_str_includes_status(self):
        error = NotFoundError('gone', 404)
        assert str(error) == 'gone (HTTP 404)'
        assert str(TransportError('down')) == 'down'

    def test_error_payload_none_for_non_dict_body(self):
        client, _, _ = make_client([Response(404, {}, b'"just a string"')])
        with pytest.raises(NotFoundError) as excinfo:
            client.case(1)
        assert excinfo.value.payload is None
        assert 'HTTP 404' in excinfo.value.message


# ---------------------------------------------------------------------------
# Lookup endpoints
# ---------------------------------------------------------------------------

KIND_SAMPLES = [
    ('ip', '8.8.8.8', 'ip'),
    ('phone', '+14155552671', 'phone_number'),
    ('username', 'johndoe', 'username'),
    ('email', 'user@example.com', 'email'),
    ('domain', 'example.com', 'domain'),
    ('url', 'https://example.com/page', 'url'),
    ('crypto', '1BoatSLRHtKN42kdutzZbHwYQeMwfQ7HNo', 'address'),
    ('hash', '44d88612fea8a8f36de82e1278abb02f', 'hash'),
    ('cve', 'CVE-2021-44228', 'cve'),
    ('asn', 'AS15169', 'asn'),
    ('mac', 'b8:27:eb:aa:bb:cc', 'mac'),
    ('iban', 'DE89370400440532013000', 'iban'),
    ('imei', '356938035643809', 'imei'),
    ('coords', '48.8584, 2.2945', 'coords'),
]


class TestLookup:

    @pytest.mark.parametrize('kind,target,target_key', KIND_SAMPLES)
    def test_lookup_hits_correct_path_and_builds_model(
            self, kind, target, target_key):
        payload = dict(IP_PAYLOAD)
        payload[target_key] = target
        payload['info'] = {'field_one': 'v1', 'field_two': 'v2'}
        client, transport, _ = make_client([ok(payload)])
        result = client.lookup(kind, target)
        expected = f'{BASE}/api/lookup/{kind}/'
        assert transport.calls[0]['url'].startswith(expected)
        assert transport.calls[0]['method'] == 'GET'
        assert isinstance(result, LookupResult)
        assert result.kind == kind
        assert result.target == target
        assert result.get('field_one') == 'v1'

    def test_lookup_unknown_kind_raises_value_error(self):
        client, transport, _ = make_client([ok({})])
        with pytest.raises(ValueError):
            client.lookup('carrier-pigeon', 'coo')
        assert transport.calls == []

    @pytest.mark.parametrize('method,target', [
        ('ip', '8.8.8.8'), ('phone', '+14155552671'),
        ('username', 'johndoe'), ('email', 'user@example.com'),
        ('domain', 'example.com'), ('url', 'https://example.com/page'),
        ('crypto', '1BoatSLRHtKN42kdutzZbHwYQeMwfQ7HNo'),
        ('hash_', '44d88612fea8a8f36de82e1278abb02f'),
        ('cve', 'CVE-2021-44228'), ('asn', 'AS15169'),
        ('mac', 'b8:27:eb:aa:bb:cc'), ('iban', 'DE89370400440532013000'),
        ('imei', '356938035643809'), ('coords', '48.8584, 2.2945'),
    ])
    def test_convenience_methods_hit_kind_paths(self, method, target):
        client, transport, _ = make_client([ok(IP_PAYLOAD)])
        result = getattr(client, method)(target)
        assert isinstance(result, LookupResult)
        kind = 'hash' if method == 'hash_' else method
        assert f'/api/lookup/{kind}/' in transport.calls[0]['url']

    def test_lookup_result_accessors(self):
        client, _, _ = make_client([ok(IP_PAYLOAD)])
        result = client.ip('8.8.8.8')
        assert result.ok is True
        assert result.get('country') == 'United States'
        assert result.get('missing', 'fallback') == 'fallback'
        assert result.field_count == 6
        assert result.elapsed == 0.42
        assert result.sources_failed == {'ipinfo': '401'}
        assert result.source_names == ['ipwhois.app', 'ipwho.is', 'ipinfo']
        assert result.sources_for('country') == ['ipwhois.app', 'ipwho.is']
        assert result.summary().startswith('ip 8.8.8.8:')

    def test_lookup_result_provenance_helpers(self):
        result = LookupResult.from_dict(IP_PAYLOAD, kind='ip')
        provenance = result.provenance
        assert isinstance(provenance, Provenance)
        assert provenance.fields_from('ipwho.is') == ['country', 'hostname']
        entry = provenance.entry_for('asn')
        assert entry.primary == 'ipwhois.app'
        assert entry.source_count == 1

    def test_lookup_tolerates_missing_and_extra_keys(self):
        sparse = {'ip': '1.1.1.1', 'info': {'a': 1}, 'future_key': 'x'}
        result = LookupResult.from_dict(sparse, kind='ip')
        assert result.success is False
        assert result.field_count == 1
        assert result.sources_ok == []
        assert result.errors == []
        assert result.raw['future_key'] == 'x'

    def test_lookup_failure_envelope(self):
        failure = {
            'ip': '10.0.0.1', 'info': {}, 'sources_ok': [],
            'sources_failed': {'ip': 'ValueError: bad'},
            'field_count': 0, 'success': False,
            'errors': ['ValueError: bad'],
        }
        result = LookupResult.from_dict(failure, kind='ip')
        assert result.ok is False
        assert 'ValueError' in result.summary()

    def test_lookup_fields_fallback_without_info_key(self):
        result = LookupResult.from_dict({'value': 'x', 'fields': {'a': 2}})
        assert result.get('a') == 2
        assert result.target == 'x'


# ---------------------------------------------------------------------------
# Risk model
# ---------------------------------------------------------------------------

class TestRisk:

    def test_risk_endpoint_path_and_model(self):
        payload = dict(IP_PAYLOAD)
        payload['risk'] = {
            'score': 42, 'verdict': 'medium',
            'signals': [
                {'id': 'listed_feeds', 'weight': 30, 'detail': 'on feodo'},
                {'id': 'risky_service_tags', 'weight': 12, 'detail': 'ssh'},
            ],
            'summary': 'heuristic score 42/100 (medium) from 2 signal(s)',
        }
        client, transport, _ = make_client([ok(payload)])
        report = client.risk('ip', '8.8.8.8')
        assert transport.calls[0]['url'] == f'{BASE}/api/risk/ip/8.8.8.8'
        assert isinstance(report, RiskReport)
        assert report.score == 42
        assert report.band == 'medium'
        assert report.lookup is not None
        assert report.lookup.get('country') == 'United States'
        assert report.explain() == ['listed_feeds (+30): on feodo',
                                    'risky_service_tags (+12): ssh']

    def test_band_helpers(self):
        def report_for(score: int, verdict: str) -> RiskReport:
            return RiskReport.from_dict(
                {'score': score, 'verdict': verdict, 'signals': []})

        assert report_for(5, 'clean').is_clean()
        assert report_for(20, 'low').is_low()
        assert report_for(50, 'medium').is_medium()
        assert report_for(75, 'high').is_high()
        assert report_for(95, 'critical').is_critical()
        assert report_for(75, 'high').is_high_or_worse()
        assert report_for(95, 'critical').is_high_or_worse()
        assert report_for(50, 'medium').is_elevated()
        assert not report_for(5, 'clean').is_elevated()
        assert report_for(0, 'unknown').is_unknown()
        assert not report_for(50, 'medium').is_high_or_worse()

    def test_band_derived_from_score_when_verdict_missing(self):
        report = RiskReport.from_dict({'score': 95, 'signals': []})
        assert report.band == 'critical'
        report = RiskReport.from_dict({'score': 16})
        assert report.band == 'low'

    def test_risk_unknown_kind_raises(self):
        client, _, _ = make_client([ok({})])
        with pytest.raises(ValueError):
            client.risk('yolo', 'x')


# ---------------------------------------------------------------------------
# Analysis endpoints
# ---------------------------------------------------------------------------

class TestAnalysis:

    def test_investigate_path_and_model(self):
        payload = {
            'target': 'example.com', 'kind': 'domain',
            'order': ['domain', 'ip'],
            'results': {'domain': dict(IP_PAYLOAD), 'ip': dict(IP_PAYLOAD)},
            'entities': [
                {'type': 'domain', 'value': 'example.com', 'role': 'target'},
                {'type': 'ip', 'value': '93.184.216.34', 'role': 'related'},
            ],
            'links': [
                {'from': 'domain:example.com', 'label': 'resolves_to',
                 'to': 'ip:93.184.216.34'},
            ],
            'errors': [],
        }
        client, transport, _ = make_client([ok(payload)])
        report = client.investigate('example.com')
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/investigate?target=example.com&pivot=true'
        assert transport.calls[0]['params'] == {
            'target': 'example.com', 'pivot': True}
        assert isinstance(report, InvestigationReport)
        assert report.kind == 'domain'
        assert report.pivots == ['domain', 'ip']
        assert isinstance(report.result_for('domain'), LookupResult)
        assert report.result_for('nope') is None
        assert report.summary().startswith('domain example.com:')

    def test_investigate_without_pivot(self):
        client, transport, _ = make_client([ok({'target': 'x', 'kind': 'ip'})])
        client.investigate('1.1.1.1', pivot=False)
        assert transport.calls[0]['params']['pivot'] is False

    def test_timeline_path_and_model(self):
        payload = {
            'events': [
                {'date': '2024-01-01T10:00:00', 'kind': 'domain',
                 'target': 'example.com', 'label': 'created'},
                {'date': '2024-06-01T10:00:00', 'kind': 'ip',
                 'target': '8.8.8.8', 'field': 'last_seen'},
            ],
            'count': 2, 'first': '2024-01-01T10:00:00',
            'last': '2024-06-01T10:00:00',
        }
        client, transport, _ = make_client([ok(payload)])
        timeline = client.timeline(target='example.com', limit=50)
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/timeline?target=example.com&limit=50'
        assert isinstance(timeline, Timeline)
        assert timeline.count == 2
        assert timeline.span_days is not None
        assert timeline.span_days == pytest.approx(152.0, abs=1.0)
        assert timeline.targets == ['example.com', '8.8.8.8']
        assert timeline.events[0].description == 'created'
        assert timeline.for_target('example.com')[0].kind == 'domain'

    def test_correlate_path_and_model(self):
        payload = {
            'entities': [
                {'id': 'domain:example.com', 'type': 'domain',
                 'value': 'example.com'},
                {'id': 'ip:93.184.216.34', 'type': 'ip',
                 'value': '93.184.216.34'},
            ],
            'links': [{'from': 'domain:example.com', 'label': 'resolves_to',
                       'to': 'ip:93.184.216.34'}],
            'clusters': [
                {'id': 'cluster-1', 'size': 2,
                 'entities': ['domain:example.com', 'ip:93.184.216.34']},
            ],
            'stats': {'targets': 1, 'entities': 2, 'links': 1,
                      'clusters': 1, 'largest_cluster': 2,
                      'bridges': [{'id': 'domain:example.com', 'type': 'domain',
                                   'value': 'example.com', 'degree': 3}]},
            'degree': {'domain:example.com': 3},
        }
        client, transport, _ = make_client([ok(payload)])
        graph = client.correlate(limit=200)
        assert transport.calls[0]['url'] == f'{BASE}/api/correlate?limit=200'
        assert isinstance(graph, CorrelationResult)
        assert graph.largest_cluster().size == 2
        assert graph.bridges[0]['degree'] == 3
        assert graph.entity('ip:93.184.216.34')['type'] == 'ip'
        assert 'entities' in graph.summary()

    def test_correlate_default_limit_omits_param(self):
        client, transport, _ = make_client([ok({'entities': [], 'links': [],
                                                'clusters': [], 'stats': {}})])
        client.correlate()
        assert transport.calls[0]['url'] == f'{BASE}/api/correlate'
        assert transport.calls[0]['params'] == {}

    def test_correlate_pair(self):
        payload = {
            'targets': ['8.8.8.8', 'dns.google'],
            'shared': [{'entity': 'AS15169', 'type': 'asn',
                        'via_a': 'asn', 'via_b': 'asn'}],
            'connections': 1, 'related': True,
        }
        client, transport, _ = make_client([ok(payload)])
        pair = client.correlate_pair('8.8.8.8', 'dns.google')
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/correlate/pair?a=8.8.8.8&b=dns.google'
        assert isinstance(pair, PairComparison)
        assert pair.is_related()
        assert pair.summary().endswith('related')

    def test_intel(self):
        payload = {
            'ip': '45.148.10.99',
            'feeds': {'tor': False, 'spamhaus_drop': True, 'feodo': True,
                      'firehol_level1': False, 'listed_count': 2},
            'tor_exit': False, 'relay': {},
        }
        client, transport, _ = make_client([ok(payload)])
        verdict = client.intel('45.148.10.99')
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/intel/45.148.10.99'
        assert isinstance(verdict, IntelVerdict)
        assert verdict.listed_count == 2
        assert 'feed hit' in verdict.summary()


# ---------------------------------------------------------------------------
# Platform endpoints
# ---------------------------------------------------------------------------

class TestPlatform:

    def test_sources(self):
        payload = {'ip': {'ipwhois.app': 'primary geo', 'ipwho.is': ''},
                   'email': {'haveibeenpwned': 'breaches'}}
        client, transport, _ = make_client([ok(payload)])
        catalog = client.sources()
        assert transport.calls[0]['url'] == f'{BASE}/api/sources'
        assert catalog['ip']['ipwhois.app'] == 'primary geo'

    def test_stats_summary(self):
        payload = {
            'database': {'total': 512, 'by_type': {'ip': 300, 'domain': 212}},
            'cache': {'total': 40, 'fresh': 12, 'size_bytes': 9999},
            'network': {'requests': 800, 'cache_hits': 490,
                        'cache_misses': 310, 'cache_hit_rate': 61.2},
            'source_health': [
                {'source': 'ipwhois.app', 'kind': 'ip', 'ok_count': 198,
                 'fail_count': 2, 'reliability': 99.0, 'state': 'healthy',
                 'last_error': ''},
                {'source': 'ipinfo', 'kind': 'ip', 'ok_count': 0,
                 'fail_count': 9, 'reliability': 0.0, 'state': 'tripped',
                 'last_error': '401'},
            ],
        }
        client, transport, _ = make_client([ok(payload)])
        summary = client.stats()
        assert transport.calls[0]['url'] == f'{BASE}/api/stats'
        assert isinstance(summary, StatsSummary)
        assert summary.total_lookups == 512
        assert summary.by_kind == {'ip': 300, 'domain': 212}
        assert summary.cache_hits == 490
        assert len(summary.source_health) == 2
        assert summary.healthy_sources()[0].name == 'ipwhois.app'
        assert summary.tripped_sources()[0].breaker_open is True

    def test_sources_health_extracts_from_stats(self):
        payload = {'source_health': [
            {'source': 'ipwhois.app', 'kind': 'ip', 'ok_count': 10,
             'fail_count': 0, 'reliability': 100.0, 'state': 'healthy'}]}
        client, transport, _ = make_client([ok(payload)])
        rows = client.sources_health()
        assert transport.calls[0]['url'] == f'{BASE}/api/stats'
        assert isinstance(rows[0], SourceHealthEntry)
        assert rows[0].total_calls == 10
        assert rows[0].summary().startswith('ipwhois.app [ip]:')

    def test_kinds(self):
        payload = [
            {'kind': 'ip', 'label': 'IP address', 'example': '8.8.8.8',
             'blurb': 'Geo, ASN, reverse DNS',
             'sources': ['ipwhois.app', 'ipwho.is'], 'source_count': 2},
            {'kind': 'domain', 'label': 'Domain', 'example': 'example.com',
             'blurb': 'Registration', 'sources': ['whois'],
             'source_count': 1},
        ]
        client, transport, _ = make_client([ok(payload)])
        kinds = client.kinds()
        assert transport.calls[0]['url'] == f'{BASE}/api/kinds'
        assert [isinstance(info, KindInfo) for info in kinds]
        assert kinds[0].source_count == 2
        assert kinds[1].label == 'Domain'

    def test_history(self):
        payload = {
            'items': [
                {'id': 9, 'kind': 'ip', 'value': '8.8.8.8',
                 'timestamp': '2024-05-01T12:00:00', 'success': True,
                 'field_count': 6, 'error': ''},
                {'id': 8, 'kind': 'ip', 'value': '8.8.4.4',
                 'timestamp': '2024-05-02T12:00:00', 'success': False,
                 'field_count': 0, 'error': 'all sources failed'},
            ],
            'count': 2, 'limit': 50, 'kind': 'ip', 'q': '8.8.8',
        }
        client, transport, _ = make_client([ok(payload)])
        result = client.history(kind='ip', q='8.8.8', limit=50)
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/history?kind=ip&q=8.8.8&limit=50'
        assert isinstance(result, HistoryResult)
        assert result.count == 2
        assert result.items[0].value == '8.8.8.8'
        assert result.items[1].when() is not None

    def test_keys(self):
        payload = [
            {'service': 'shodan', 'configured': True,
             'description': 'InternetDB is keyless'},
            {'service': 'virustotal', 'configured': False,
             'description': 'URL verdicts'},
        ]
        client, transport, _ = make_client([ok(payload)])
        services = client.keys()
        assert transport.calls[0]['url'] == f'{BASE}/api/keys'
        assert services[0].configured is True
        assert services[1].service == 'virustotal'

    def test_set_key_posts_body(self):
        client, transport, _ = make_client(
            [ok({'ok': True, 'service': 'shodan', 'configured': True})])
        out = client.set_key('shodan', 'KEY123')
        assert transport.calls[0]['method'] == 'POST'
        assert transport.calls[0]['url'] == f'{BASE}/api/keys/shodan'
        assert transport.calls[0]['json_body'] == {'key': 'KEY123'}
        assert out['configured'] is True

    def test_clear_key_uses_delete(self):
        client, transport, _ = make_client(
            [ok({'ok': True, 'service': 'shodan', 'configured': False})])
        client.clear_key('shodan')
        assert transport.calls[0]['method'] == 'DELETE'
        assert transport.calls[0]['url'] == f'{BASE}/api/keys/shodan'

    def test_settings(self):
        payload = {'settings': {'app.max_workers': 12, 'app.cache_ttl': 3600},
                   'version': '5.1.0', 'note': 'runtime view'}
        client, transport, _ = make_client([ok(payload)])
        snapshot = client.settings()
        assert transport.calls[0]['url'] == f'{BASE}/api/settings'
        assert snapshot['settings']['app.max_workers'] == 12

    def test_update_settings_posts_body(self):
        client, transport, _ = make_client(
            [ok({'ok': True, 'path': 'app.max_workers', 'value': 16})])
        out = client.update_settings('app.max_workers', 16)
        assert transport.calls[0]['method'] == 'POST'
        assert transport.calls[0]['json_body'] == \
            {'path': 'app.max_workers', 'value': 16}
        assert out['value'] == 16


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

CASE_ROW = {
    'id': 3, 'name': 'acme-phishing', 'description': 'Brand abuse',
    'status': 'open', 'created_at': '2024-05-01T09:00:00',
    'updated_at': '2024-05-02T09:00:00', 'item_count': 1, 'note_count': 1,
    'tag_count': 1, 'items_by_kind': {'ip': 1},
    'items': [{'id': 1, 'case_id': 3, 'kind': 'ip',
               'value': '45.148.10.99', 'note': 'kit host',
               'added_at': '2024-05-01T10:00:00'}],
    'notes': [{'id': 1, 'case_id': 3, 'text': 'GSB flagged the URL.',
               'created_at': '2024-05-01T11:00:00'}],
    'tags': ['phishing'],
}


class TestCases:

    def test_cases_list(self):
        client, transport, _ = make_client([ok([CASE_ROW])])
        cases = client.cases()
        assert transport.calls[0]['url'] == f'{BASE}/api/cases'
        assert isinstance(cases[0], Case)
        assert cases[0].title == 'acme-phishing'
        assert cases[0].is_open()
        assert cases[0].item_count == 1
        assert cases[0].items_by_kind == {'ip': 1}

    def test_case_get(self):
        client, transport, _ = make_client([ok(CASE_ROW)])
        case = client.case(3)
        assert transport.calls[0]['url'] == f'{BASE}/api/cases/3'
        assert isinstance(case.items[0], CaseItem)
        assert case.items[0].value == '45.148.10.99'
        assert isinstance(case.notes[0], CaseNote)
        assert case.notes[0].text == 'GSB flagged the URL.'
        assert case.tags == ['phishing']
        assert 'acme-phishing' in case.summary()

    def test_create_case_posts_body(self):
        client, transport, _ = make_client([ok(CASE_ROW)], )
        case = client.create_case('acme-phishing', 'Brand abuse')
        assert transport.calls[0]['method'] == 'POST'
        assert transport.calls[0]['url'] == f'{BASE}/api/cases'
        assert transport.calls[0]['json_body'] == \
            {'name': 'acme-phishing', 'description': 'Brand abuse'}
        assert isinstance(case, Case)
        assert case.id == 3

    def test_update_case_patches_status(self):
        archived = dict(CASE_ROW, status='archived')
        client, transport, _ = make_client([ok(archived)])
        case = client.update_case(3, 'archived')
        assert transport.calls[0]['method'] == 'PATCH'
        assert transport.calls[0]['url'] == f'{BASE}/api/cases/3'
        assert transport.calls[0]['json_body'] == {'status': 'archived'}
        assert case.is_archived()

    def test_update_case_rejects_bad_status(self):
        client, transport, _ = make_client([ok({})])
        with pytest.raises(ValueError):
            client.update_case(3, 'deleted')
        assert transport.calls == []

    def test_add_case_item_posts_body(self):
        payload = {'id': 2, 'case_id': 3, 'kind': 'ip',
                   'value': '8.8.8.8', 'note': 'resolver',
                   'added_at': '2024-05-03T10:00:00'}
        client, transport, _ = make_client([ok(payload)])
        item = client.add_case_item(3, '8.8.8.8', kind='ip', note='resolver')
        assert transport.calls[0]['url'] == f'{BASE}/api/cases/3/items'
        assert transport.calls[0]['json_body'] == \
            {'kind': 'ip', 'target': '8.8.8.8', 'note': 'resolver'}
        assert isinstance(item, CaseItem)
        assert item.value == '8.8.8.8'

    def test_add_case_item_omits_null_note(self):
        client, transport, _ = make_client([ok({'id': 3, 'kind': 'ip',
                                                'value': '1.1.1.1'})])
        client.add_case_item(3, '1.1.1.1')
        assert transport.calls[0]['json_body'] == \
            {'kind': 'auto', 'target': '1.1.1.1'}

    def test_add_case_note_posts_body(self):
        payload = {'id': 2, 'case_id': 3, 'note': 'escalated',
                   'created_at': '2024-05-03T11:00:00'}
        client, transport, _ = make_client([ok(payload)])
        note = client.add_case_note(3, 'escalated')
        assert transport.calls[0]['url'] == f'{BASE}/api/cases/3/notes'
        assert transport.calls[0]['json_body'] == {'note': 'escalated'}
        assert isinstance(note, CaseNote)
        assert note.text == 'escalated'

    def test_add_case_tag_posts_body(self):
        client, transport, _ = make_client([ok(['phishing', 'brand'])])
        out = client.add_case_tag(3, 'brand')
        assert transport.calls[0]['url'] == f'{BASE}/api/cases/3/tags'
        assert transport.calls[0]['json_body'] == {'tag': 'brand'}
        assert out == ['phishing', 'brand']


# ---------------------------------------------------------------------------
# Watchlist
# ---------------------------------------------------------------------------

WATCH_ROW = {
    'id': 1, 'target': 'example.com', 'kind': 'domain',
    'label': 'corp site', 'created_at': '2024-05-01T09:00:00',
    'last_checked': '2024-05-02T09:00:00', 'snapshots': 3,
}


class TestWatch:

    def test_watch_list(self):
        client, transport, _ = make_client([ok([WATCH_ROW])])
        entries = client.watch()
        assert transport.calls[0]['url'] == f'{BASE}/api/watch'
        assert isinstance(entries[0], WatchEntry)
        assert entries[0].snapshots == 3
        assert 'corp site' in entries[0].summary()

    def test_add_watch_posts_body(self):
        client, transport, _ = make_client([ok({'id': 2})])
        out = client.add_watch('example.com', 'corp site')
        assert transport.calls[0]['method'] == 'POST'
        assert transport.calls[0]['url'] == f'{BASE}/api/watch'
        assert transport.calls[0]['json_body'] == \
            {'target': 'example.com', 'label': 'corp site'}
        assert out == {'id': 2}

    def test_remove_watch_deletes_by_id_or_target(self):
        client, transport, _ = make_client([ok({'removed': 3})])
        client.remove_watch(3)
        assert transport.calls[0]['method'] == 'DELETE'
        assert transport.calls[0]['url'] == f'{BASE}/api/watch/3'

        client2, transport2, _ = make_client([ok({'removed': 'example.com'})])
        client2.remove_watch('example.com')
        assert transport2.calls[0]['url'] == f'{BASE}/api/watch/example.com'

    def test_check_watch_posts_with_optional_identifier(self):
        diff = {
            'watch_id': 1, 'target': 'example.com', 'kind': 'domain',
            'checked_at': '2024-05-03T09:00:00', 'is_first': False,
            'added': {'registrar': 'New Registrar'},
            'removed': {},
            'changed': {'expires': {'from': '2025-01-01',
                                    'to': '2026-01-01'}},
            'success': True, 'error': '',
        }
        client, transport, _ = make_client([ok([diff])])
        diffs = client.check_watch('example.com')
        assert transport.calls[0]['method'] == 'POST'
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/watch/check?identifier=example.com'
        assert isinstance(diffs[0], WatchDiff)
        assert diffs[0].has_changes()
        assert diffs[0].changed['expires']['to'] == '2026-01-01'

        client2, transport2, _ = make_client([ok([diff])])
        client2.check_watch()
        assert transport2.calls[0]['url'] == f'{BASE}/api/watch/check'
        assert transport2.calls[0]['params'] == {}

    def test_diff(self):
        payload = {
            'target': 'example.com', 'kind': 'domain', 'changed_any': True,
            'added': {'registrar': 'New'}, 'removed': {'dnssec': 'yes'},
            'changed': {'expires': {'from': 'a', 'to': 'b'}},
            'previous': '2024-05-02T09:00:00',
            'current': '2024-05-03T09:00:00',
        }
        client, transport, _ = make_client([ok(payload)])
        report = client.diff('domain', 'example.com')
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/diff/domain/example.com'
        assert isinstance(report, DiffReport)
        assert report.has_changes()
        assert report.removed == {'dnssec': 'yes'}

    def test_diff_single_snapshot_note(self):
        payload = {'target': 'example.com', 'kind': 'domain',
                   'changed_any': False, 'added': {}, 'removed': {},
                   'changed': {}, 'note': 'only one snapshot stored'}
        client, _, _ = make_client([ok(payload)])
        report = client.diff('auto', 'example.com')
        assert report.has_changes() is False
        assert 'snapshot' in report.note


# ---------------------------------------------------------------------------
# Export / report / patterns
# ---------------------------------------------------------------------------

class TestExportAndReport:

    def test_export(self):
        payload = {'target': 'example.com', 'format': 'graphml',
                   'graph': '<graphml>...</graphml>',
                   'entities': 9, 'links': 8}
        client, transport, _ = make_client([ok(payload)])
        out = client.export('graphml', 'example.com')
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/export/graphml/example.com?pivot=true'
        assert out['entities'] == 9
        assert out['graph'].startswith('<graphml>')

    def test_export_rejects_unknown_format(self):
        client, transport, _ = make_client([ok({})])
        with pytest.raises(ValueError):
            client.export('kml', 'example.com')
        assert transport.calls == []

    def test_export_pivot_false(self):
        client, transport, _ = make_client([ok({})])
        client.export('dot', 'example.com', pivot=False)
        assert transport.calls[0]['url'].endswith('pivot=false')

    def test_report_json_mode(self):
        payload = {'kind': 'domain', 'target': 'example.com',
                   'size': 4096, 'html': '<!DOCTYPE html><html>...'}
        client, transport, _ = make_client([ok(payload)])
        out = client.report('domain', 'example.com')
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/report/domain/example.com'
        assert out['size'] == 4096

    def test_report_download_mode_returns_raw_html(self):
        html = '<!DOCTYPE html><html><body>report</body></html>'
        client, transport, _ = make_client(
            [Response(200, {'Content-Type': 'text/html'},
                      html.encode('utf-8'))])
        out = client.report('domain', 'example.com', download=True)
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/report/domain/example.com?download=true'
        assert out['html'] == html
        assert out['size'] == len(html)

    def test_report_save_to_writes_file(self, tmp_path):
        html = '<html>ok</html>'
        target_file = tmp_path / 'report.html'
        client, _, _ = make_client(
            [Response(200, {'Content-Type': 'text/html'},
                      html.encode('utf-8'))])
        out = client.report('domain', 'example.com', save_to=str(target_file))
        assert target_file.read_text(encoding='utf-8') == html
        assert out['saved_to'] == str(target_file)
        assert out['size'] == len(html)

    def test_report_unknown_kind(self):
        client, _, _ = make_client([ok({})])
        with pytest.raises(ValueError):
            client.report('wand', 'example.com')

    def test_patterns(self):
        payload = {
            'kind': 'ip', 'value': '45.148.10.99',
            'hour_histogram': [0] * 14 + [5] + [0] * 9,
            'weekday_histogram': [0, 0, 0, 0, 7, 0, 0],
            'activity_matrix': [[0] * 24 for _ in range(7)],
            'cadence': {'mean_gap_hours': 4.2, 'max_gap_hours': 71.0,
                        'min_gap_hours': 0.1},
            'bursts': [{'start': '2024-05-01T14:00:00',
                        'end': '2024-05-01T14:20:00', 'count': 5}],
            'peak_window': {'hour': 14, 'weekday': 4,
                            'weekday_name': 'Thursday', 'count': 5},
            'verdict': ['activity clusters around 14:00 on Thursdays'],
            'records_analyzed': 7,
        }
        client, transport, _ = make_client([ok(payload)])
        pattern = client.patterns('ip', '45.148.10.99')
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/patterns?kind=ip&target=45.148.10.99'
        assert isinstance(pattern, PatternReport)
        assert pattern.peak_hour == 14
        assert pattern.observations == 7
        assert pattern.findings[0].count == 5
        assert pattern.verdict[0].startswith('activity clusters')


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

class TestAlerts:

    def test_alerts_config(self):
        payload = {
            'webhook_url': 'https://hooks.example/ol',
            'events': ['risk_high', 'watch_diff'], 'enabled': True,
            'recent': [
                {'ts': '2024-05-03T09:00:00', 'event': 'risk_high',
                 'payload': {'score': 75}, 'delivery': 'ok'},
                {'ts': '2024-05-03T10:00:00', 'event': 'watch_diff',
                 'payload': {}, 'delivery': 'failed: timeout'},
            ],
            'event_types': ['lookup_failed', 'watch_diff', 'risk_high',
                            'source_tripped', 'case_created'],
        }
        client, transport, _ = make_client([ok(payload)])
        config = client.alerts()
        assert transport.calls[0]['url'] == f'{BASE}/api/alerts'
        assert isinstance(config, AlertConfig)
        assert config.is_enabled()
        assert config.events == ['risk_high', 'watch_diff']
        assert config.recent[1].delivery == 'failed: timeout'

    def test_configure_alerts_posts_body(self):
        payload = {'webhook_url': 'https://hooks.example/ol',
                   'events': ['risk_high'], 'enabled': True,
                   'recent': [],
                   'event_types': ['risk_high']}
        client, transport, _ = make_client([ok(payload)])
        config = client.configure_alerts('https://hooks.example/ol',
                                         ['risk_high'])
        assert transport.calls[0]['method'] == 'POST'
        assert transport.calls[0]['url'] == f'{BASE}/api/alerts'
        assert transport.calls[0]['json_body'] == {
            'webhook_url': 'https://hooks.example/ol',
            'events': ['risk_high']}
        assert config.events == ['risk_high']

    def test_configure_alerts_disable_omits_events(self):
        payload = {'webhook_url': '', 'events': [], 'enabled': False,
                   'recent': [], 'event_types': []}
        client, transport, _ = make_client([ok(payload)])
        client.configure_alerts('')
        assert transport.calls[0]['json_body'] == {'webhook_url': ''}

    def test_test_alert(self):
        client, transport, _ = make_client(
            [ok({'ok': True, 'status': 200, 'detail': 'delivered'})])
        out = client.test_alert()
        assert transport.calls[0]['method'] == 'POST'
        assert transport.calls[0]['url'] == f'{BASE}/api/alerts/test'
        assert out['ok'] is True


# ---------------------------------------------------------------------------
# Toolbox
# ---------------------------------------------------------------------------

class TestToolbox:

    def test_encodings(self):
        payload = {'text': 'admin:password',
                   'encodings': {'hex': '61646d', 'base64': 'YWRtaW4='},
                   'hashes': {'md5': 'x', 'sha256': 'y'},
                   'schemes': ['hex', 'base64']}
        client, transport, _ = make_client([ok(payload)])
        out = client.encodings('admin:password')
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/tools/encodings?text=admin%3Apassword'
        assert isinstance(out, ToolboxResult)
        assert out.get('encodings')['hex'] == '61646d'
        assert out.input == 'admin:password'

    def test_decode(self):
        client, transport, _ = make_client(
            [ok({'scheme': 'hex', 'result': 'hello'})])
        out = client.decode('68656c6c6f', scheme='hex')
        assert transport.calls[0]['method'] == 'POST'
        assert transport.calls[0]['url'] == f'{BASE}/api/tools/decode'
        assert transport.calls[0]['json_body'] == \
            {'scheme': 'hex', 'value': '68656c6c6f'}
        assert out.get('result') == 'hello'

    def test_jwt(self):
        payload = {'header': {'alg': 'HS256'}, 'payload': {'sub': 'u1'},
                   'notes': [], 'signature_length': 32}
        client, transport, _ = make_client([ok(payload)])
        out = client.jwt('eyJhbGciOiJIUzI1NiJ9.e30.x')
        assert transport.calls[0]['url'].startswith(
            f'{BASE}/api/tools/jwt?token=')
        assert out.get('header') == {'alg': 'HS256'}

    def test_hash_id(self):
        payload = {'value': '44d88612fea8a8f36de82e1278abb02f',
                   'candidates': [{'name': 'MD5', 'confidence': 'high',
                                   'length': 32, 'charset': 'hex',
                                   'note': ''}]}
        client, transport, _ = make_client([ok(payload)])
        out = client.hash_id('44d88612fea8a8f36de82e1278abb02f')
        assert transport.calls[0]['url'].startswith(
            f'{BASE}/api/tools/hash-id?value=')
        assert out.get('candidates')[0]['name'] == 'MD5'

    def test_coords_convert(self):
        payload = {'input': '48.8584, 2.2945', 'latitude': 48.8584,
                   'longitude': 2.2945, 'decimal': '48.8584, 2.2945',
                   'utm': '31U 448288 5411087', 'mgrs': '31U DQ 48288 11087'}
        client, transport, _ = make_client([ok(payload)])
        out = client.coords_convert('48.8584, 2.2945')
        assert transport.calls[0]['method'] == 'POST'
        assert transport.calls[0]['url'] == f'{BASE}/api/tools/coords'
        assert transport.calls[0]['json_body'] == {'value': '48.8584, 2.2945'}
        assert out.get('mgrs') == '31U DQ 48288 11087'

    def test_extract_entities(self):
        payload = {'entities': {}, 'summary': {'emails': 1},
                   'emails': ['bob@evil.example']}
        client, transport, _ = make_client([ok(payload)])
        out = client.extract_entities('Contact bob@evil.example')
        assert transport.calls[0]['json_body'] == \
            {'text': 'Contact bob@evil.example'}
        assert out.get('emails') == ['bob@evil.example']

    def test_squat(self):
        payload = {'domain': 'example.com', 'count': 2,
                   'variants': [{'domain': 'exmaple.com',
                                 'category': 'transposition', 'risk': 94,
                                 'description': 'd'}]}
        client, transport, _ = make_client([ok(payload)])
        out = client.squat('example.com')
        assert transport.calls[0]['url'] == f'{BASE}/api/tools/squat'
        assert transport.calls[0]['json_body'] == {'domain': 'example.com'}
        assert out.get('variants')[0]['domain'] == 'exmaple.com'

    @pytest.mark.parametrize('tool,expected_path,method', [
        ('encodings', '/api/tools/encodings', 'GET'),
        ('jwt', '/api/tools/jwt', 'GET'),
        ('hash-id', '/api/tools/hash-id', 'GET'),
        ('hash_id', '/api/tools/hash-id', 'GET'),
        ('coords', '/api/tools/coords', 'POST'),
        ('coordinates', '/api/tools/coords', 'POST'),
        ('extract', '/api/tools/extract', 'POST'),
        ('squat', '/api/tools/squat', 'POST'),
        ('decode', '/api/tools/decode', 'POST'),
    ])
    def test_toolbox_dispatches(self, tool, expected_path, method):
        client, transport, _ = make_client([ok({'ok': 1})])
        client.toolbox(tool, 'some-value')
        call = transport.calls[0]
        assert call['method'] == method
        assert BASE + expected_path in call['url']

    def test_toolbox_scheme_alias_dispatches_to_decode(self):
        client, transport, _ = make_client([ok({'result': 'hello'})])
        out = client.toolbox('base64', 'aGVsbG8=')
        assert transport.calls[0]['url'] == f'{BASE}/api/tools/decode'
        assert transport.calls[0]['json_body'] == \
            {'scheme': 'base64', 'value': 'aGVsbG8='}
        assert out.get('result') == 'hello'

    def test_toolbox_unknown_tool(self):
        client, _, _ = make_client([ok({})])
        with pytest.raises(ValueError):
            client.toolbox('magic', 'x')

    def test_batch_posts_body_and_builds_model(self):
        payload = {
            'kind': 'ip', 'risk': False, 'skipped': 0, 'stopped': False,
            'results': [
                {'target': '8.8.8.8', 'success': True, 'field_count': 6,
                 'error': '', 'result': dict(IP_PAYLOAD)},
                {'target': '1.1.1.1', 'success': False, 'field_count': 0,
                 'error': 'all data sources failed', 'result': None},
            ],
            'summary': {'total': 2, 'ok': 1, 'failed': 1,
                        'elapsed': 1.25, 'fields_total': 6},
        }
        client, transport, _ = make_client([ok(payload)])
        run = client.batch('ip', ['8.8.8.8', '1.1.1.1'])
        assert transport.calls[0]['url'] == f'{BASE}/api/tools/batch'
        assert transport.calls[0]['json_body'] == {
            'kind': 'ip', 'targets': ['8.8.8.8', '1.1.1.1'], 'risk': False}
        assert isinstance(run, BatchProgress)
        assert run.total == 2
        assert run.ok == 1
        assert run.failed == 1
        assert run.elapsed == 1.25
        assert run.is_complete
        assert run.entry_for('8.8.8.8').result is not None
        assert run.entry_for('nope') is None

    def test_batch_rejects_unknown_kind_and_empty_targets(self):
        client, _, _ = make_client([ok({})])
        with pytest.raises(ValueError):
            client.batch('pigeon', ['a'])
        with pytest.raises(ValueError):
            client.batch('ip', [])


# ---------------------------------------------------------------------------
# File uploads (exif / stego)
# ---------------------------------------------------------------------------

class TestUploads:

    def test_exif_uploads_multipart(self, tmp_path):
        image = tmp_path / 'img.jpg'
        image.write_bytes(b'\xff\xd8\xff\xe0FAKEJPEG')
        payload = {'format': 'jpeg', 'size': 13, 'camera': 'TestCam',
                   'gps': {'coords': '48.8584, 2.2945'}, 'mode': 'exif',
                   'filename': 'img.jpg'}
        client, transport, _ = make_client([ok(payload)])
        out = client.exif(str(image))
        call = transport.calls[0]
        assert call['method'] == 'POST'
        assert call['url'] == f'{BASE}/api/tools/file/exif'
        assert call['body'] is not None
        assert b'FAKEJPEG' in call['body']
        assert b'filename="img.jpg"' in call['body']
        assert call['headers']['Content-Type'].startswith(
            'multipart/form-data; boundary=')
        assert out['gps']['coords'] == '48.8584, 2.2945'

    def test_stego_uploads_bytes_directly(self):
        payload = {'format': 'png',
                   'summary': {'suspicion': 71.3,
                               'verdict': 'highly suspicious'},
                   'mode': 'stego'}
        client, transport, _ = make_client([ok(payload)])
        out = client.stego(b'\x89PNG\r\n\x1a\nDATA', filename='file.png')
        call = transport.calls[0]
        assert call['url'] == f'{BASE}/api/tools/file/stego'
        assert b'\x89PNG' in call['body']
        assert call['headers']['Content-Type'].startswith(
            'multipart/form-data; boundary=')
        assert out['summary']['verdict'] == 'highly suspicious'

    def test_upload_non_json_response_raises_malformed(self):
        client, _, _ = make_client(
            [Response(200, {}, b'<html>proxy error</html>')])
        with pytest.raises(MalformedResponseError):
            client.exif(b'data')


# ---------------------------------------------------------------------------
# ping / lifecycle / escape hatches
# ---------------------------------------------------------------------------

class TestPingAndLifecycle:

    def test_ping_true_on_success(self):
        client, _, _ = make_client([ok({'database': {}})])
        assert client.ping() is True

    def test_ping_false_on_transport_error(self):
        client, _, _ = make_client([TransportError('down')], retries=1)
        assert client.ping() is False

    def test_ping_false_on_http_error_and_never_raises(self):
        client, _, _ = make_client([err(500, 'broken')])
        assert client.ping() is False
        client2, _, _ = make_client([Response(200, {}, b'nope')])
        assert client2.ping() is False

    def test_context_manager_closes_transport(self):
        transport = StaticTransport([ok({})])
        with ObscuraLensClient(transport=transport) as client:
            assert client._closed is False
        assert transport.closed is True

    def test_close_is_idempotent_and_blocks_requests(self):
        client, transport, _ = make_client([ok({})])
        client.close()
        client.close()
        with pytest.raises(TransportError):
            client.stats()

    def test_health_endpoint(self):
        client, transport, _ = make_client(
            [ok({'status': 'ok', 'version': '5.1.0'})])
        assert client.health() == {'status': 'ok', 'version': '5.1.0'}
        assert transport.calls[0]['url'] == f'{BASE}/api/health'

    def test_repr_mentions_base_url(self):
        client, _, _ = make_client([ok({})])
        assert '127.0.0.1:8000' in repr(client)

    def test_transport_property(self):
        client, transport, _ = make_client([ok({})])
        assert client.transport is transport

    def test_raw_get_and_raw_post(self):
        client, transport, _ = make_client(
            [ok([{'kind': 'ip'}]), ok({'ok': 1})])
        payload = client.raw_get('/api/kinds')
        assert payload == [{'kind': 'ip'}]
        assert transport.calls[0]['url'] == f'{BASE}/api/kinds'

        out = client.raw_post('/api/watch/check')
        assert out == {'ok': 1}
        assert transport.calls[1]['method'] == 'POST'

    def test_raw_get_prepends_slash(self):
        client, transport, _ = make_client([ok({})])
        client.raw_get('api/stats')
        assert transport.calls[0]['url'] == f'{BASE}/api/stats'


# ---------------------------------------------------------------------------
# Async client
# ---------------------------------------------------------------------------

class TestAsyncClient:

    @staticmethod
    def make_async(script, **kwargs):
        transport = StaticTransport(list(script))
        async_client = AsyncObscuraLensClient(
            transport=transport, retries=1, **kwargs)
        return async_client, transport

    def test_await_ip_returns_model(self):
        async def scenario():
            client, transport = self.make_async([ok(IP_PAYLOAD)])
            try:
                result = await client.ip('8.8.8.8')
                return result, transport
            finally:
                await client.aclose()

        result, transport = asyncio.run(scenario())
        assert isinstance(result, LookupResult)
        assert transport.calls[0]['url'] == f'{BASE}/api/lookup/ip/8.8.8.8'

    def test_await_ping(self):
        async def scenario(ok_response):
            client, _ = self.make_async([ok_response])
            try:
                return await client.ping()
            finally:
                await client.aclose()

        assert asyncio.run(scenario(ok({}))) is True
        assert asyncio.run(scenario(TransportError('down'))) is False

    def test_await_lookup_all_kinds(self):
        async def scenario():
            client, transport = self.make_async(
                [ok(IP_PAYLOAD)] * len(KIND_SAMPLES))
            try:
                for kind, target, _key in KIND_SAMPLES:
                    result = await client.lookup(kind, target)
                    assert isinstance(result, LookupResult)
                return transport
            finally:
                await client.aclose()

        transport = asyncio.run(scenario())
        assert len(transport.calls) == len(KIND_SAMPLES)
        assert all(call['url'].startswith(f'{BASE}/api/lookup/')
                   for call in transport.calls)

    def test_await_investigate_and_risk(self):
        investigate_payload = {'target': 'example.com', 'kind': 'domain',
                               'order': ['domain'], 'results': {},
                               'entities': [], 'links': [], 'errors': []}
        risk_payload = dict(IP_PAYLOAD)
        risk_payload['risk'] = {'score': 75, 'verdict': 'high',
                                'signals': [], 'summary': ''}

        async def scenario():
            client, _ = self.make_async(
                [ok(investigate_payload), ok(risk_payload)])
            try:
                report = await client.investigate('example.com')
                risk = await client.risk('ip', '8.8.8.8')
                return report, risk
            finally:
                await client.aclose()

        report, risk = asyncio.run(scenario())
        assert isinstance(report, InvestigationReport)
        assert isinstance(risk, RiskReport)
        assert risk.is_high()

    def test_await_timeline_correlate_stats_sources(self):
        timeline_payload = {'events': [], 'count': 0, 'first': None,
                            'last': None}
        correlate_payload = {'entities': [], 'links': [], 'clusters': [],
                             'stats': {}}
        stats_payload = {'database': {'total': 1}, 'cache': {},
                         'network': {'cache_hits': 0},
                         'source_health': []}

        async def scenario():
            client, _ = self.make_async(
                [ok(timeline_payload), ok(correlate_payload),
                 ok(stats_payload), ok({}), ok([])])
            try:
                return (await client.timeline(limit=10),
                        await client.correlate(),
                        await client.stats(),
                        await client.sources(),
                        await client.sources_health())
            finally:
                await client.aclose()

        timeline, graph, stats, sources, health = asyncio.run(scenario())
        assert isinstance(timeline, Timeline)
        assert isinstance(graph, CorrelationResult)
        assert isinstance(stats, StatsSummary)
        assert sources == {}
        assert health == []

    def test_async_errors_propagate(self):
        async def scenario():
            client, _ = self.make_async([err(404, 'not found')])
            try:
                await client.lookup('ip', '8.8.8.8')
            except NotFoundError:
                return 'mapped'
            return 'unmapped'

        assert asyncio.run(scenario()) == 'mapped'

    def test_async_context_manager_closes(self):
        async def scenario():
            client, transport = self.make_async([ok({})])
            async with client:
                await client.ping()
            return transport.closed, client._client._closed

        transport_closed, client_closed = asyncio.run(scenario())
        assert transport_closed is True
        assert client_closed is True

    def test_async_gather_runs_concurrently(self):
        async def scenario():
            client, transport = self.make_async(
                [ok(IP_PAYLOAD)] * 3)
            try:
                results = await client.gather([
                    client.ip('8.8.8.8'),
                    client.domain('example.com'),
                    client.email('user@example.com'),
                ])
                return results, transport
            finally:
                await client.aclose()

        results, transport = asyncio.run(scenario())
        assert len(results) == 3
        assert all(isinstance(result, LookupResult) for result in results)
        assert len(transport.calls) == 3

    def test_async_repr_and_sync_client_property(self):
        async def scenario():
            client, _ = self.make_async([ok({})])
            try:
                return repr(client), isinstance(
                    client.sync_client, ObscuraLensClient)
            finally:
                await client.aclose()

        text, is_sync = asyncio.run(scenario())
        assert '127.0.0.1:8000' in text
        assert is_sync

    def test_async_await_health(self):
        async def scenario():
            client, _ = self.make_async(
                [ok({'status': 'ok', 'version': '5.1.0'})])
            try:
                return await client.health()
            finally:
                await client.aclose()

        assert asyncio.run(scenario()) == {'status': 'ok',
                                           'version': '5.1.0'}

    def test_async_custom_executor_is_not_owned(self):
        import concurrent.futures

        async def scenario():
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            client, _ = self.make_async([], executor=executor)
            await client.aclose()
            return not executor._shutdown

        assert asyncio.run(scenario()) is True


# ---------------------------------------------------------------------------
# Package surface
# ---------------------------------------------------------------------------

class TestPackageSurface:

    def test_all_exports_resolve(self):
        import obscuralens.sdk as sdk

        for name in sdk.__all__:
            assert getattr(sdk, name, None) is not None, name

    def test_version_and_user_agent(self):
        from obscuralens.sdk import SDK_USER_AGENT, SDK_VERSION

        user_agent = SDK_USER_AGENT
        version = SDK_VERSION
        assert user_agent == f'obscuralens-sdk/{version}'
        assert version == '5.1.0'

    def test_no_third_party_imports_in_sdk(self, monkeypatch):
        """The SDK modules must stay stdlib-only at import time."""
        import sys

        before = set(sys.modules)
        import obscuralens.sdk.async_client  # noqa: F401
        import obscuralens.sdk.client  # noqa: F401
        import obscuralens.sdk.exceptions  # noqa: F401
        import obscuralens.sdk.models  # noqa: F401
        import obscuralens.sdk.transport  # noqa: F401
        added = {name.split('.')[0] for name in set(sys.modules) - before}
        third_party = {'fastapi', 'uvicorn', 'requests', 'httpx', 'pydantic',
                       'starlette', 'yaml', 'jinja2'}
        assert not (added & third_party)

    def test_transport_abstract_requires_request(self):
        class Incomplete(Transport):
            pass

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]

    def test_exceptions_hierarchy(self):
        assert issubclass(TransportError, SdkError)
        assert issubclass(TimeoutError, SdkError)
        assert issubclass(ApiError, SdkError)
        assert issubclass(NotFoundError, ApiError)
        assert issubclass(BadRequestError, ApiError)
        assert issubclass(RateLimitError, ApiError)
        assert issubclass(ServerError, ApiError)
        assert issubclass(MalformedResponseError, SdkError)

    def test_timeout_error_carries_timeout_value(self):
        error = TimeoutError('slow', timeout=12.0)
        assert error.timeout == 12.0
        assert error.status is None

    def test_malformed_error_carries_body_text(self):
        error = MalformedResponseError('bad', status=200, body_text='<html>')
        assert error.body_text == '<html>'

"""
Offline v6.0 test suite for the ObscuraLens Python SDK.

Every test runs against :class:`~obscuralens.sdk.transport.StaticTransport`
(a programmable in-memory server) — no network, no FastAPI, no database.
The suite covers the v6 surface end to end: the six sensor-kind lookups,
the dork builder, the nine analytics endpoints, notification channels and
broadcasts, the automation scheduler, the STIX/MISP intelligence-sharing
exports, the live-stream topic declaration, the new models' tolerance of
junk payloads, the fluent :class:`InvestigationSession` (step recording,
error capture, strict mode, case filing, receipt round-trips) and the
async mirrors of every new method.
"""

import asyncio
import json
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

import pytest

from obscuralens.sdk import (
    AnalyticsEnvelope,
    AsyncObscuraLensClient,
    AutomationTasks,
    AutomationTaskView,
    BadRequestError,
    DorkReport,
    InvestigationSession,
    LookupResult,
    MispEvent,
    NotFoundError,
    NotifyChannel,
    NotifyChannels,
    NotifyDelivery,
    ObscuraLensClient,
    Response,
    SessionStep,
    StaticTransport,
    StixBundle,
)
from obscuralens.sdk.models import KINDS

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


def sensor_payload(kind: str, target: str,
                   fields: Dict[str, Any]) -> Dict[str, Any]:
    """A tracker envelope for one of the sensor kinds."""
    return {
        kind: target,
        'info': fields,
        'field_sources': {key: ['pack'] for key in fields},
        'sources_ok': ['pack'],
        'sources_failed': {},
        'field_count': len(fields),
        'success': True,
        'errors': [],
        'elapsed': 0.11,
    }


IP_PAYLOAD: Dict[str, Any] = {
    'ip': '8.8.8.8',
    'info': {'ip': '8.8.8.8', 'country': 'United States', 'asn': 'AS15169'},
    'field_sources': {'country': ['ipwhois.app']},
    'sources_ok': ['ipwhois.app'],
    'sources_failed': {},
    'field_count': 3,
    'success': True,
    'errors': [],
    'elapsed': 0.42,
}

DORKS_PAYLOAD: Dict[str, Any] = {
    'target': 'example.com',
    'detected_kind': 'domain',
    'count': 3,
    'dorks': [
        {'engine': 'Google', 'label': 'Pages on the domain',
         'query': 'site:example.com',
         'url': 'https://www.google.com/search?q=site%3Aexample.com'},
        {'engine': 'Bing', 'label': 'Pages on the domain',
         'query': 'site:example.com',
         'url': 'https://www.bing.com/search?q=site%3Aexample.com'},
        {'engine': 'GitHub Code',
         'label': 'Leaked secrets referencing the domain',
         'query': '"example.com" password',
         'url': 'https://github.com/search?type=code&q=%22example.com%22'},
    ],
    'dork_kinds': ['ip', 'domain', 'email', 'username'],
}

STATS_PAYLOAD: Dict[str, Any] = {
    'count': 5,
    'summary': {'count': 5, 'mean': 22.0, 'median': 3.0, 'stdev': 43.7,
                'q1': 1.5, 'q3': 4.5, 'skew': 1.1, 'kurtosis': -0.8},
    'histogram': {'bins': 4, 'counts': [3, 1, 0, 1]},
}

ANOMALIES_PAYLOAD: Dict[str, Any] = {
    'count': 5,
    'method': 'ensemble',
    'anomaly_count': 1,
    'anomalies': [{'value': 10000.0, 'score': 9.5, 'method': 'mad',
                   'detail': 'deviates 9.5 MADs from the median'}],
}

TIMESERIES_PAYLOAD: Dict[str, Any] = {
    'count': 6,
    'summary': {'count': 6, 'span_days': 5.0, 'trend': 'rising',
                'slope': 3.3, 'mean': 10.5, 'variance': 50.3,
                'changepoints': 1},
}

CLUSTERS_PAYLOAD: Dict[str, Any] = {
    'point_count': 4,
    'eps_km': 25.0,
    'min_points': 3,
    'cluster_count': 1,
    'clusters': [{'size': 3, 'centroid': [52.05, 13.05],
                  'points': [[52.0, 13.0], [52.1, 13.1], [52.05, 13.05]],
                  'radius_km': 8.2}],
}

KEYWORDS_PAYLOAD: Dict[str, Any] = {
    'keyword_count': 2,
    'keywords': [{'term': 'quick', 'count': 1, 'weight': 1.0},
                 {'term': 'brown', 'count': 1, 'weight': 1.0}],
}

LANGUAGE_PAYLOAD: Dict[str, Any] = {
    'scripts': {'latin': 20},
    'dominant': 'latin',
    'guess': {'language': 'fr', 'confidence': 0.9},
    'hint': 'stopwords and diacritics look like French',
}

SIMILARITY_PAYLOAD: Dict[str, Any] = {
    'a': 'paypal.com', 'b': 'paypa1.com',
    'jaro_winkler': 0.97, 'levenshtein': 0.92, 'bigram': 0.9,
    'cosine': 0.8, 'mean': 0.9, 'lengths': [10, 10],
}

GRAPH_PAYLOAD: Dict[str, Any] = {
    'entity_count': 2,
    'link_count': 1,
    'summary': {'nodes': 2, 'edges': 1, 'density': 1.0, 'components': 1,
                'communities': [{'id': 0, 'size': 2}],
                'top_degree': [{'id': 'a', 'degree': 1}],
                'bridges': [], 'isolated': []},
}

HISTORY_PAYLOAD: Dict[str, Any] = {
    'total_queries': 42,
    'span_days': 3.5,
    'kind_frequency': [{'kind': 'ip', 'count': 20},
                       {'kind': 'domain', 'count': 22}],
    'hour_profile': [0] * 24,
    'weekday_profile': [0] * 7,
    'success_rates': [{'kind': 'ip', 'total': 20, 'ok': 19}],
    'field_stats': {},
    'source_reliability': [],
    'anomalies': [],
    'top_targets': [{'value': '8.8.8.8', 'count': 4}],
    'generated_at': '2024-06-01T00:00:00+00:00',
}

CHANNEL_OPS: Dict[str, Any] = {
    'name': 'ops-webhook', 'type': 'webhook',
    'target': 'https://hooks.example/ol',
    'events': ['risk_high', 'watch_diff'],
    'enabled': True,
    'min_severity': 'low',
    'quiet_hours': [22, 6],
    'dedup_key': 'event+title',
    'note': 'oncall',
    'last_sent': '2024-06-01T10:00:00',
}

CHANNEL_CHAT: Dict[str, Any] = {
    'name': 'team-chat', 'type': 'telegram', 'target': 'bot:chat',
    'events': [], 'enabled': False, 'min_severity': 'info',
    'quiet_hours': None, 'dedup_key': None, 'note': '',
    'last_sent': '',
}

NOTIFY_CHANNELS_PAYLOAD: Dict[str, Any] = {
    'count': 2,
    'channels': [CHANNEL_OPS, CHANNEL_CHAT],
    'channel_types': ['webhook', 'telegram', 'discord', 'slack', 'smtp'],
    'severities': ['info', 'low', 'medium', 'high', 'critical'],
}

BROADCAST_PAYLOAD: Dict[str, Any] = {
    'sent': 2,
    'failed': [{'channel': 'team-chat', 'error': 'no target configured'}],
    'skipped': 1,
    'total': 4,
    'results': [{'channel': 'ops-webhook', 'ok': True},
                {'channel': 'team-chat', 'ok': False},
                {'channel': 'quiet-one', 'skipped': True}],
}

TASK_DAILY: Dict[str, Any] = {
    'name': 'daily-watch', 'action': 'watch_check', 'params': {},
    'schedule': 'daily', 'interval_seconds': 3600, 'at_time': '09:00',
    'weekday': 0, 'enabled': True,
    'last_run': '2024-06-01T09:00:03', 'next_run': '2024-06-02T09:00:00',
    'run_count': 12, 'error_count': 0, 'last_error': '',
}

TASK_INTERVAL: Dict[str, Any] = {
    'name': 'feed-refresh', 'action': 'feed_refresh',
    'params': {'hours': 6}, 'schedule': 'interval',
    'interval_seconds': 21600, 'at_time': '09:00', 'weekday': 3,
    'enabled': False, 'last_run': None, 'next_run': None,
    'run_count': 3, 'error_count': 2,
    'last_error': 'ConnectionError: feeds down',
}

AUTOMATION_TASKS_PAYLOAD: Dict[str, Any] = {
    'count': 2,
    'tasks': [TASK_DAILY, TASK_INTERVAL],
    'actions': ['watch_check', 'pipeline', 'report', 'feed_refresh',
                'notify_test'],
    'schedule_types': ['interval', 'daily', 'weekly'],
}

STIX_PAYLOAD: Dict[str, Any] = {
    'type': 'bundle',
    'id': 'bundle--11d3f1a4-1b8e-5d3a-9a97-0a1b2c3d4e5f',
    'objects': [
        {'type': 'identity', 'id': 'identity--a',
         'name': 'ObscuraLens', 'identity_class': 'organization'},
        {'type': 'indicator', 'id': 'indicator--b',
         'pattern': "[domain-name:value = 'example.com']",
         'pattern_type': 'stix', 'valid_from': '2024-06-01T00:00:00Z'},
        {'type': 'observed-data', 'id': 'observed-data--c',
         'first_observed': '2024-06-01T00:00:00Z'},
        {'type': 'relationship', 'id': 'relationship--d',
         'relationship_type': 'related-to',
         'source_ref': 'indicator--b', 'target_ref': 'observed-data--c'},
        {'type': 'note', 'id': 'note--e', 'content': '3 sources replied'},
    ],
}

MISP_PAYLOAD: Dict[str, Any] = {
    'Event': {
        'id': '20240601',
        'info': 'ObscuraLens domain lookup: example.com - '
                '6 field(s) from 3 source(s), 0 error(s)',
        'date': '2024-06-01',
        'threat_level_id': '3',
        'analysis': '0',
        'published': False,
        'timestamp': '1717228800',
        'orgc': {'name': 'ObscuraLens', 'uuid': '10f8d61c-1f8b-11ef'},
        'Attribute': [
            {'value': 'example.com', 'type': 'domain',
             'category': 'Network activity', 'to_ids': True,
             'comment': 'target'},
            {'value': 'United States', 'type': 'text', 'to_ids': False,
             'comment': 'country'},
            {'value': 'AS15169', 'type': 'text', 'to_ids': False,
             'comment': 'asn'},
        ],
        'Tag': [{'name': 'obscuralens:domain'}],
    }
}

INVESTIGATE_PAYLOAD: Dict[str, Any] = {
    'target': 'evil.example.com', 'kind': 'domain',
    'order': ['domain'],
    'results': {'domain': dict(IP_PAYLOAD)},
    'entities': [
        {'type': 'domain', 'value': 'evil.example.com', 'role': 'target'},
        {'type': 'ip', 'value': '93.184.216.34', 'role': 'related'},
    ],
    'links': [{'from': 'domain:evil.example.com', 'label': 'resolves_to',
               'to': 'ip:93.184.216.34'}],
    'errors': [],
}

RISK_PAYLOAD: Dict[str, Any] = {
    'domain': 'evil.example.com',
    'info': {'domain': 'evil.example.com', 'registrar': 'Cheap Reg'},
    'sources_ok': ['whois'],
    'field_count': 2,
    'success': True,
    'risk': {'score': 72, 'verdict': 'high',
             'signals': [{'id': 'young_domain', 'weight': 40,
                          'detail': 'registered 3 days ago'}],
             'summary': 'heuristic score 72/100 (high) from 1 signal(s)'},
}

TIMELINE_PAYLOAD: Dict[str, Any] = {
    'events': [
        {'date': '2024-05-01T10:00:00', 'kind': 'domain',
         'target': 'evil.example.com', 'label': 'created'},
        {'date': '2024-05-02T09:00:00', 'kind': 'ip',
         'target': '1.2.3.4', 'label': 'seen'},
    ],
    'count': 2, 'first': '2024-05-01T10:00:00',
    'last': '2024-05-02T09:00:00',
}

CASE_PAYLOAD: Dict[str, Any] = {
    'id': 7, 'name': 'Phishing case', 'description': 'brand abuse',
    'status': 'open', 'items': [], 'notes': [], 'tags': ['phishing'],
    'created_at': '2024-06-01T10:00:00',
    'updated_at': '2024-06-01T10:00:00',
    'item_count': 0, 'note_count': 0, 'tag_count': 1,
}

CASE_ITEM_PAYLOAD: Dict[str, Any] = {
    'id': 91, 'case_id': 7, 'kind': 'domain',
    'value': 'evil.example.com', 'note': '', 'added_at': '2024-06-01T10:01',
}


# ---------------------------------------------------------------------------
# The six v6.0 sensor lookups
# ---------------------------------------------------------------------------

class TestSensorLookups:

    @pytest.mark.parametrize('kind,target,fields', [
        ('vin', '1HGCM82633A004352',
         {'manufacturer': 'Honda', 'country': 'Japan', 'model_year': 2003}),
        ('flight', 'BA117',
         {'airline': 'British Airways', 'origin': 'LHR',
          'destination': 'JFK'}),
        ('mmsi', '366982610',
         {'country': 'United States', 'mid': '366'}),
        ('app', 'left-pad@1.3.0',
         {'registry': 'npm', 'latest_version': '1.3.0'}),
        ('bssid', 'b8:27:eb:aa:bb:cc', {'vendor': 'Raspberry Pi Trading'}),
        ('plate', 'B-AB 1234', {'country': 'Germany', 'format': 'DIN'}),
    ])
    def test_sensor_lookup_hits_kind_path_and_builds_model(
            self, kind, target, fields):
        payload = sensor_payload(kind, target, fields)
        client, transport, _ = make_client([ok(payload)])
        result = client.lookup(kind, target)
        assert transport.calls[0]['method'] == 'GET'
        assert transport.calls[0]['url'].startswith(
            f'{BASE}/api/lookup/{kind}/')
        assert isinstance(result, LookupResult)
        assert result.kind == kind
        assert result.target == target
        assert result.field_count == len(fields)
        for key, value in fields.items():
            assert result.get(key) == value

    @pytest.mark.parametrize('kind,target,encoded', [
        ('app', 'left-pad@1.3.0', 'left-pad%401.3.0'),
        ('bssid', 'b8:27:eb:aa:bb:cc', 'b8%3A27%3Aeb%3Aaa%3Abb%3Acc'),
        ('plate', 'B-AB 1234', 'B-AB%201234'),
    ])
    def test_sensor_targets_are_percent_encoded(
            self, kind, target, encoded):
        client, transport, _ = make_client(
            [ok(sensor_payload(kind, target, {}))])
        client.lookup(kind, target)
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/lookup/{kind}/{encoded}'

    @pytest.mark.parametrize('method,kind,target', [
        ('vin', 'vin', '1HGCM82633A004352'),
        ('flight', 'flight', 'BA117'),
        ('mmsi', 'mmsi', '366982610'),
        ('app', 'app', 'left-pad@1.3.0'),
        ('package', 'app', 'left-pad@1.3.0'),
        ('bssid', 'bssid', 'b8:27:eb:aa:bb:cc'),
        ('plate', 'plate', 'B-AB 1234'),
    ])
    def test_convenience_methods_hit_kind_paths(self, method, kind, target):
        payload = sensor_payload(kind, target, {'a': 1})
        client, transport, _ = make_client([ok(payload)])
        result = getattr(client, method)(target)
        assert isinstance(result, LookupResult)
        assert result.kind == kind
        assert f'/api/lookup/{kind}/' in transport.calls[0]['url']

    def test_app_and_package_are_the_same_endpoint(self):
        client, transport, _ = make_client(
            [ok(sensor_payload('app', 'left-pad', {'x': 1}))] * 2)
        client.app('left-pad')
        client.package('left-pad')
        assert [call['url'] for call in transport.calls] == [
            f'{BASE}/api/lookup/app/left-pad'] * 2

    def test_sensor_kinds_are_registered(self):
        for kind in ('vin', 'flight', 'mmsi', 'app', 'bssid', 'plate'):
            assert kind in KINDS
        assert len(KINDS) == 20

    def test_unknown_kind_still_raises_value_error(self):
        client, transport, _ = make_client([ok({})])
        with pytest.raises(ValueError):
            client.lookup('carrier-pigeon', 'coo')
        with pytest.raises(ValueError):
            client.export_stix('carrier-pigeon', 'coo')
        with pytest.raises(ValueError):
            client.export_misp('carrier-pigeon', 'coo')
        assert transport.calls == []

    def test_blank_target_is_not_a_client_side_error(self):
        # an empty target is server-side validation, not a client one
        client, transport, _ = make_client([err(400, 'invalid VIN')])
        with pytest.raises(BadRequestError):
            client.vin('')
        assert len(transport.calls) == 1

    def test_sensor_lookup_bad_request_maps_to_sdk_error(self):
        client, _, _ = make_client([err(400, 'invalid VIN')])
        with pytest.raises(BadRequestError):
            client.vin('NOT-A-VIN')

    def test_sensor_lookup_not_found_maps_to_sdk_error(self):
        client, _, _ = make_client([err(404, 'unknown flight')])
        with pytest.raises(NotFoundError):
            client.flight('ZZ999')


# ---------------------------------------------------------------------------
# Dorks
# ---------------------------------------------------------------------------

class TestDorks:

    def test_dorks_path_and_model(self):
        client, transport, _ = make_client([ok(DORKS_PAYLOAD)])
        report = client.dorks('example.com')
        assert transport.calls[0]['method'] == 'GET'
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/tools/dorks?target=example.com'
        assert transport.calls[0]['params'] == {'target': 'example.com'}
        assert isinstance(report, DorkReport)
        assert report.target == 'example.com'
        assert report.detected_kind == 'domain'
        assert report.count == 3
        assert report.dorks[0]['engine'] == 'Google'
        assert report.dork_kinds == ['ip', 'domain', 'email', 'username']

    def test_dorks_with_kind_override_sends_param(self):
        client, transport, _ = make_client([ok(DORKS_PAYLOAD)])
        client.dorks('example.com', kind='domain')
        assert transport.calls[0]['params'] == {'target': 'example.com',
                                                'kind': 'domain'}
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/tools/dorks?target=example.com&kind=domain'

    def test_dorks_helpers(self):
        client, _, _ = make_client([ok(DORKS_PAYLOAD)])
        report = client.dorks('example.com')
        assert report.links() == [dork['url'] for dork in report.dorks]
        assert report.engines() == ['Google', 'Bing', 'GitHub Code']
        assert len(report.for_engine('google')) == 1
        assert report.for_engine('Google')[0]['query'] == 'site:example.com'
        assert report.for_engine('nope') == []
        assert report.summary() == \
            'example.com [domain]: 3 dork(s) across 3 engine(s)'

    def test_dorks_blank_target_is_bad_request(self):
        client, _, _ = make_client([err(400, 'target is required')])
        with pytest.raises(BadRequestError):
            client.dorks('')


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------

class TestAnalytics:

    def test_stats_body_and_model(self):
        client, transport, _ = make_client([ok(STATS_PAYLOAD)])
        envelope = client.analytics_stats([1, 2, 3, 4, 100], bins=4)
        call = transport.calls[0]
        assert call['method'] == 'POST'
        assert call['url'] == f'{BASE}/api/analytics/stats'
        assert call['json_body'] == {'values': [1, 2, 3, 4, 100], 'bins': 4}
        assert isinstance(envelope, AnalyticsEnvelope)
        assert envelope.kind == 'stats'
        assert envelope.get('count') == 5
        assert envelope.get('summary')['mean'] == 22.0
        assert envelope.payload['histogram']['counts'] == [3, 1, 0, 1]
        assert envelope.count == 5

    def test_stats_default_bins(self):
        client, transport, _ = make_client([ok(STATS_PAYLOAD)])
        client.analytics_stats([1, 2, 3])
        assert transport.calls[0]['json_body'] == \
            {'values': [1, 2, 3], 'bins': 10}

    def test_anomalies_body_and_model(self):
        client, transport, _ = make_client([ok(ANOMALIES_PAYLOAD)])
        envelope = client.analytics_anomalies([1, 2, 3, 4, 10000])
        call = transport.calls[0]
        assert call['url'] == f'{BASE}/api/analytics/anomalies'
        assert call['json_body'] == {'values': [1, 2, 3, 4, 10000],
                                     'method': 'ensemble'}
        assert envelope.kind == 'anomalies'
        assert envelope.get('anomaly_count') == 1
        assert envelope.get('anomalies')[0]['value'] == 10000.0

    def test_anomalies_threshold_only_sent_for_zscore(self):
        client, transport, _ = make_client(
            [ok(ANOMALIES_PAYLOAD)] * 3)
        client.analytics_anomalies([1, 2, 30], method='zscore', threshold=2.5)
        client.analytics_anomalies([1, 2, 30], method='zscore')
        client.analytics_anomalies([1, 2, 30], method='mad', threshold=2.5)
        first, second, third = (call['json_body']
                                for call in transport.calls)
        assert first == {'values': [1, 2, 30], 'method': 'zscore',
                         'threshold': 2.5}
        assert 'threshold' not in second
        assert 'threshold' not in third

    def test_timeseries_body_and_model(self):
        client, transport, _ = make_client([ok(TIMESERIES_PAYLOAD)])
        envelope = client.analytics_timeseries([5, 6, 5, 6, 20, 21])
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/analytics/timeseries'
        assert transport.calls[0]['json_body'] == \
            {'values': [5, 6, 5, 6, 20, 21]}
        assert envelope.kind == 'timeseries'
        assert envelope.get('summary')['trend'] == 'rising'

    def test_clusters_body_and_model(self):
        client, transport, _ = make_client([ok(CLUSTERS_PAYLOAD)])
        points = [[52.0, 13.0], [52.1, 13.1], [52.05, 13.05], [60.0, 5.0]]
        envelope = client.analytics_clusters(points, eps_km=10,
                                              min_points=2)
        call = transport.calls[0]
        assert call['url'] == f'{BASE}/api/analytics/clusters'
        assert call['json_body'] == {'points': points, 'eps_km': 10.0,
                                     'min_points': 2}
        assert envelope.kind == 'clusters'
        assert envelope.get('cluster_count') == 1
        assert envelope.get('clusters')[0]['size'] == 3

    def test_clusters_defaults(self):
        client, transport, _ = make_client([ok(CLUSTERS_PAYLOAD)])
        client.analytics_clusters([[52.0, 13.0]])
        assert transport.calls[0]['json_body'] == \
            {'points': [[52.0, 13.0]], 'eps_km': 25.0, 'min_points': 3}

    def test_keywords_body_and_model(self):
        client, transport, _ = make_client([ok(KEYWORDS_PAYLOAD)])
        envelope = client.analytics_keywords('the quick brown fox', top=2)
        call = transport.calls[0]
        assert call['url'] == f'{BASE}/api/analytics/keywords'
        assert call['json_body'] == {'text': 'the quick brown fox',
                                     'top': 2}
        assert envelope.kind == 'keywords'
        assert envelope.get('keyword_count') == 2
        assert envelope.count == 2  # keyword_count fallback
        assert envelope.get('keywords')[0]['term'] == 'quick'

    def test_language_body_and_model(self):
        client, transport, _ = make_client([ok(LANGUAGE_PAYLOAD)])
        envelope = client.analytics_language('Le renard brun rapide')
        assert transport.calls[0]['url'] == f'{BASE}/api/analytics/language'
        assert transport.calls[0]['json_body'] == \
            {'text': 'Le renard brun rapide'}
        assert envelope.kind == 'language'
        assert envelope.get('guess')['language'] == 'fr'

    def test_similarity_body_and_model(self):
        client, transport, _ = make_client([ok(SIMILARITY_PAYLOAD)])
        envelope = client.analytics_similarity('paypal.com', 'paypa1.com')
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/analytics/similarity'
        assert transport.calls[0]['json_body'] == \
            {'a': 'paypal.com', 'b': 'paypa1.com'}
        assert envelope.kind == 'similarity'
        assert envelope.get('mean') == 0.9

    def test_graph_body_and_model(self):
        client, transport, _ = make_client([ok(GRAPH_PAYLOAD)])
        entities = [{'id': 'a'}, {'id': 'b'}]
        links = [{'source': 'a', 'target': 'b'}]
        envelope = client.analytics_graph(entities, links)
        call = transport.calls[0]
        assert call['url'] == f'{BASE}/api/analytics/graph'
        assert call['json_body'] == {'entities': entities, 'links': links}
        assert envelope.kind == 'graph'
        assert envelope.get('summary')['nodes'] == 2

    def test_history_path_and_model(self):
        client, transport, _ = make_client([ok(HISTORY_PAYLOAD)])
        envelope = client.analytics_history(limit=100)
        assert transport.calls[0]['method'] == 'GET'
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/analytics/history?limit=100'
        assert transport.calls[0]['params'] == {'limit': 100}
        assert envelope.kind == 'history'
        assert envelope.get('total_queries') == 42
        assert envelope.count is None  # no count-ish key in the dossier

    def test_history_default_limit(self):
        client, transport, _ = make_client([ok(HISTORY_PAYLOAD)])
        client.analytics_history()
        assert transport.calls[0]['params'] == {'limit': 500}

    def test_analytics_bad_request_maps_to_sdk_error(self):
        client, _, _ = make_client(
            [err(400, 'values contains no usable numbers')])
        with pytest.raises(BadRequestError):
            client.analytics_stats([])

    def test_analytics_summary_and_keys(self):
        envelope = AnalyticsEnvelope.from_dict(STATS_PAYLOAD, kind='stats')
        assert envelope.keys() == ['count', 'summary', 'histogram']
        assert envelope.summary() == 'stats: 3 key(s) — count, summary, histogram'
        long = {f'key{index}': index for index in range(7)}
        assert AnalyticsEnvelope.from_dict(long, 'x').summary().endswith('…')

    def test_analytics_envelope_dict_semantics(self):
        envelope = AnalyticsEnvelope.from_dict(STATS_PAYLOAD, kind='stats')
        assert envelope['count'] == 5
        assert envelope['summary']['mean'] == 22.0
        assert 'count' in envelope
        assert 'missing' not in envelope
        with pytest.raises(KeyError):
            envelope['missing']
        # .get() keeps its tolerant default instead
        assert envelope.get('missing') is None
        assert envelope.get('missing', 0) == 0


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

class TestNotify:

    def test_notify_channels_path_and_model(self):
        client, transport, _ = make_client([ok(NOTIFY_CHANNELS_PAYLOAD)])
        channels = client.notify_channels()
        assert transport.calls[0]['method'] == 'GET'
        assert transport.calls[0]['url'] == f'{BASE}/api/notify/channels'
        assert isinstance(channels, NotifyChannels)
        assert channels.count == 2
        assert len(channels.channels) == 2
        assert channels.channel_types[0] == 'webhook'
        assert channels.severities == \
            ['info', 'low', 'medium', 'high', 'critical']

    def test_notify_channels_accessors(self):
        client, _, _ = make_client([ok(NOTIFY_CHANNELS_PAYLOAD)])
        channels = client.notify_channels()
        ops = channels.by_name('OPS-WEBHOOK')
        assert ops is not None and ops.type == 'webhook'
        assert ops.quiet_hours == [22, 6]
        assert ops.min_severity == 'low'
        assert ops.subscribes_to('risk_high')
        assert not ops.subscribes_to('lookup')
        assert channels.by_name('nope') is None
        chat = channels.by_name('team-chat')
        assert chat.subscribes_to('lookup')  # empty events = everything
        assert [channel.name for channel in channels.enabled()] == \
            ['ops-webhook']
        assert channels.summary() == '2 channel(s), 1 enabled, 5 type(s)'

    def test_add_notify_channel_minimal_body(self):
        client, transport, _ = make_client(
            [ok({'ok': True, 'channel': dict(CHANNEL_CHAT)})])
        channel = client.add_notify_channel('team-chat', 'telegram')
        call = transport.calls[0]
        assert call['method'] == 'POST'
        assert call['url'] == f'{BASE}/api/notify/channels'
        assert call['json_body'] == {'name': 'team-chat',
                                     'type': 'telegram',
                                     'target': ''}
        assert isinstance(channel, NotifyChannel)
        assert channel.name == 'team-chat'
        assert channel.type == 'telegram'

    def test_add_notify_channel_full_body(self):
        client, transport, _ = make_client(
            [ok({'ok': True, 'channel': dict(CHANNEL_OPS)})])
        channel = client.add_notify_channel(
            'ops-webhook', channel_type='webhook',
            target='https://hooks.example/ol',
            events=['risk_high', 'watch_diff'], min_severity='low',
            quiet_hours=(22, 6))
        assert transport.calls[0]['json_body'] == {
            'name': 'ops-webhook', 'type': 'webhook',
            'target': 'https://hooks.example/ol',
            'events': ['risk_high', 'watch_diff'],
            'min_severity': 'low', 'quiet_hours': [22, 6]}
        assert isinstance(channel, NotifyChannel)
        assert channel.quiet_hours == [22, 6]
        assert channel.events == ['risk_high', 'watch_diff']

    def test_add_notify_channel_omits_only_none_keys(self):
        client, transport, _ = make_client(
            [ok({'ok': True, 'channel': dict(CHANNEL_OPS)})])
        client.add_notify_channel('ops-webhook', 'webhook',
                                  'https://hooks.example/ol',
                                  events=[], min_severity=None,
                                  quiet_hours=None)
        # events=[] is not None → sent verbatim; None keys are omitted.
        assert transport.calls[0]['json_body'] == {
            'name': 'ops-webhook', 'type': 'webhook',
            'target': 'https://hooks.example/ol', 'events': []}

    def test_add_notify_channel_rejection_is_bad_request(self):
        client, _, _ = make_client([err(400, 'unknown channel type')])
        with pytest.raises(BadRequestError):
            client.add_notify_channel('x', 'pigeonpost')

    def test_remove_notify_channel(self):
        client, transport, _ = make_client(
            [ok({'ok': True, 'removed': 'team-chat'})])
        result = client.remove_notify_channel('team-chat')
        call = transport.calls[0]
        assert call['method'] == 'DELETE'
        assert call['url'] == f'{BASE}/api/notify/channels/team-chat'
        assert result == {'ok': True, 'removed': 'team-chat'}

    def test_remove_notify_channel_not_found(self):
        client, _, _ = make_client([err(404, "channel 'x' not found")])
        with pytest.raises(NotFoundError):
            client.remove_notify_channel('x')

    def test_test_notify_channel_success(self):
        client, transport, _ = make_client(
            [ok({'ok': True, 'error': '', 'channel': 'ops-webhook'})])
        delivery = client.test_notify_channel('ops-webhook')
        call = transport.calls[0]
        assert call['method'] == 'POST'
        assert call['url'] == \
            f'{BASE}/api/notify/channels/ops-webhook/test'
        assert isinstance(delivery, NotifyDelivery)
        assert delivery.ok is True
        assert delivery.channel == 'ops-webhook'
        assert delivery.summary() == 'ops-webhook: delivered'

    def test_test_notify_channel_failure_is_data_not_error(self):
        client, _, _ = make_client(
            [ok({'ok': False, 'error': 'no target configured',
                 'channel': 'team-chat'})])
        delivery = client.test_notify_channel('team-chat')
        assert delivery.ok is False
        assert delivery.error == 'no target configured'
        assert delivery.summary() == \
            'team-chat: FAILED: no target configured'

    def test_test_notify_channel_unknown_is_not_found(self):
        client, _, _ = make_client([err(404, "channel 'x' not found")])
        with pytest.raises(NotFoundError):
            client.test_notify_channel('x')

    def test_notify_recent_plain_dict(self):
        recent_payload = {
            'count': 2,
            'recent': [
                {'ts': '2024-06-01T10:00:00', 'event': 'risk_high',
                 'channel': 'ops-webhook', 'title': 'ip · 1.2.3.4',
                 'severity': 'high', 'delivery': 'ok'},
                {'ts': '2024-06-01T11:00:00', 'event': 'watch_diff',
                 'channel': 'team-chat', 'title': 'domain · a.com',
                 'severity': 'info', 'delivery': 'skipped: quiet hours'},
            ],
        }
        client, transport, _ = make_client([ok(recent_payload)])
        log = client.notify_recent(limit=5)
        call = transport.calls[0]
        assert call['method'] == 'GET'
        assert call['url'] == f'{BASE}/api/notify/recent?limit=5'
        assert call['params'] == {'limit': 5}
        assert isinstance(log, dict)
        assert log['count'] == 2
        assert log['recent'][0]['channel'] == 'ops-webhook'

    def test_notify_recent_default_limit(self):
        client, transport, _ = make_client([ok({'count': 0, 'recent': []})])
        client.notify_recent()
        assert transport.calls[0]['params'] == {'limit': 20}

    def test_notify_broadcast_body_and_model(self):
        client, transport, _ = make_client([ok(BROADCAST_PAYLOAD)])
        delivery = client.notify_broadcast(
            'watch diff', 'example.com changed NS', severity='high',
            event_type='watch_diff')
        call = transport.calls[0]
        assert call['method'] == 'POST'
        assert call['url'] == f'{BASE}/api/notify/broadcast'
        assert call['json_body'] == {
            'title': 'watch diff', 'body': 'example.com changed NS',
            'severity': 'high', 'event_type': 'watch_diff'}
        assert isinstance(delivery, NotifyDelivery)
        assert delivery.sent == 2
        assert delivery.skipped == 1
        assert delivery.total == 4
        assert delivery.failure_count == 1
        assert delivery.failure_lines() == \
            ['team-chat: no target configured']
        assert delivery.ok is False  # derived: failures exist
        assert delivery.result == BROADCAST_PAYLOAD['results']
        assert delivery.result[0]['channel'] == 'ops-webhook'
        assert delivery.summary() == '2 sent, 1 skipped, 1 failed of 4'

    def test_notify_broadcast_defaults(self):
        client, transport, _ = make_client([ok(BROADCAST_PAYLOAD)])
        client.notify_broadcast('t', 'b')
        assert transport.calls[0]['json_body'] == {
            'title': 't', 'body': 'b', 'severity': 'info',
            'event_type': 'manual'}

    def test_notify_broadcast_blank_title_is_bad_request(self):
        client, _, _ = make_client([err(400, 'title is required')])
        with pytest.raises(BadRequestError):
            client.notify_broadcast('', 'body')


# ---------------------------------------------------------------------------
# Automation
# ---------------------------------------------------------------------------

class TestAutomation:

    def test_automation_tasks_path_and_model(self):
        client, transport, _ = make_client([ok(AUTOMATION_TASKS_PAYLOAD)])
        tasks = client.automation_tasks()
        assert transport.calls[0]['method'] == 'GET'
        assert transport.calls[0]['url'] == f'{BASE}/api/automation/tasks'
        assert isinstance(tasks, AutomationTasks)
        assert tasks.count == 2
        assert len(tasks.tasks) == 2
        assert tasks.actions[:2] == ['watch_check', 'pipeline']
        assert tasks.schedule_types == ['interval', 'daily', 'weekly']

    def test_automation_tasks_accessors(self):
        client, _, _ = make_client([ok(AUTOMATION_TASKS_PAYLOAD)])
        tasks = client.automation_tasks()
        daily = tasks.by_name('DAILY-WATCH')
        assert isinstance(daily, AutomationTaskView)
        assert daily.action == 'watch_check'
        assert daily.schedule == 'daily'
        assert daily.at_time == '09:00'
        assert daily.next_run == '2024-06-02T09:00:00'
        assert daily.run_count == 12
        assert daily.is_healthy()
        assert daily.summary() == \
            'daily-watch [watch_check, daily 09:00]: 12 run(s)'
        interval = tasks.by_name('feed-refresh')
        assert interval.interval_seconds == 21600
        assert interval.enabled is False
        assert not interval.is_healthy()
        assert interval.summary() == \
            'feed-refresh [feed_refresh, every 21600s]: 3 run(s)'
        assert tasks.by_name('nope') is None
        assert [task.name for task in tasks.enabled()] == ['daily-watch']
        assert tasks.summary() == '2 task(s), 1 enabled, 5 action(s)'

    def test_add_automation_task_minimal_body(self):
        client, transport, _ = make_client(
            [ok({'ok': True, 'task': dict(TASK_INTERVAL)})])
        task = client.add_automation_task('feed-refresh', 'feed_refresh')
        call = transport.calls[0]
        assert call['method'] == 'POST'
        assert call['url'] == f'{BASE}/api/automation/tasks'
        assert call['json_body'] == {
            'name': 'feed-refresh', 'action': 'feed_refresh',
            'schedule': 'interval', 'interval_seconds': 3600,
            'enabled': True}
        assert isinstance(task, AutomationTaskView)
        assert task.name == 'feed-refresh'

    def test_add_automation_task_full_body(self):
        client, transport, _ = make_client(
            [ok({'ok': True, 'task': dict(TASK_DAILY)})])
        task = client.add_automation_task(
            'daily-watch', 'watch_check', schedule='daily',
            at_time='09:00', weekday=0, params={'note': 'x'},
            enabled=True)
        assert transport.calls[0]['json_body'] == {
            'name': 'daily-watch', 'action': 'watch_check',
            'schedule': 'daily', 'enabled': True, 'at_time': '09:00',
            'weekday': 0, 'params': {'note': 'x'}}
        assert isinstance(task, AutomationTaskView)
        assert task.params == {}

    def test_add_automation_task_interval_seconds_rule(self):
        client, transport, _ = make_client(
            [ok({'ok': True, 'task': dict(TASK_INTERVAL)}),
             ok({'ok': True, 'task': dict(TASK_DAILY)}),
             ok({'ok': True, 'task': dict(TASK_DAILY)})])
        # interval schedule → interval_seconds sent
        client.add_automation_task('feed-refresh', 'feed_refresh',
                                   schedule='interval',
                                   interval_seconds=7200)
        assert transport.calls[0]['json_body']['interval_seconds'] == 7200
        # daily/weekly schedules → interval_seconds omitted entirely
        client.add_automation_task('daily-watch', 'watch_check',
                                   schedule='daily', at_time='09:00')
        client.add_automation_task('weekly-brief', 'report',
                                   schedule='weekly', at_time='08:30',
                                   weekday=4)
        for call in transport.calls[1:]:
            assert 'interval_seconds' not in call['json_body']

    def test_add_automation_task_rejection_is_bad_request(self):
        client, _, _ = make_client([err(400, 'unknown task action')])
        with pytest.raises(BadRequestError):
            client.add_automation_task('x', 'sing_a_song')

    def test_remove_automation_task(self):
        client, transport, _ = make_client(
            [ok({'ok': True, 'removed': 'daily-watch'})])
        result = client.remove_automation_task('daily-watch')
        call = transport.calls[0]
        assert call['method'] == 'DELETE'
        assert call['url'] == f'{BASE}/api/automation/tasks/daily-watch'
        assert result == {'ok': True, 'removed': 'daily-watch'}

    def test_remove_automation_task_not_found(self):
        client, _, _ = make_client([err(404, "task 'x' not found")])
        with pytest.raises(NotFoundError):
            client.remove_automation_task('x')

    def test_run_automation_task(self):
        run_payload = {'ok': True, 'started': '2024-06-01T09:00:00',
                       'finished': '2024-06-01T09:00:03', 'error': '',
                       'summary': 'checked 4 watch(es)'}
        client, transport, _ = make_client([ok(run_payload)])
        result = client.run_automation_task('daily-watch')
        call = transport.calls[0]
        assert call['method'] == 'POST'
        assert call['url'] == \
            f'{BASE}/api/automation/tasks/daily-watch/run'
        assert result['ok'] is True
        assert result['summary'] == 'checked 4 watch(es)'

    def test_run_automation_task_not_found(self):
        client, _, _ = make_client([err(404, "task 'x' not found")])
        with pytest.raises(NotFoundError):
            client.run_automation_task('x')

    def test_run_due_automation(self):
        run_due_payload = {
            'ran': 1,
            'results': [{'task': 'daily-watch', 'action': 'watch_check',
                         'ok': True, 'started': '2024-06-01T09:00:00',
                         'finished': '2024-06-01T09:00:03', 'error': '',
                         'summary': 'checked 4 watch(es)'}],
        }
        client, transport, _ = make_client([ok(run_due_payload)])
        result = client.run_due_automation()
        call = transport.calls[0]
        assert call['method'] == 'POST'
        assert call['url'] == f'{BASE}/api/automation/run-due'
        assert call['json_body'] is None
        assert result['ran'] == 1
        assert result['results'][0]['task'] == 'daily-watch'

    def test_automation_next(self):
        next_payload = {
            'count': 1,
            'tasks': [{'name': 'daily-watch', 'action': 'watch_check',
                       'schedule': 'daily', 'enabled': True,
                       'stored_next_run': '2024-06-02T09:00:00',
                       'recomputed_next_run': '2024-06-02T09:00:12'}],
        }
        client, transport, _ = make_client([ok(next_payload)])
        result = client.automation_next()
        call = transport.calls[0]
        assert call['method'] == 'GET'
        assert call['url'] == f'{BASE}/api/automation/next'
        assert result['count'] == 1
        assert result['tasks'][0]['recomputed_next_run'] == \
            '2024-06-02T09:00:12'


# ---------------------------------------------------------------------------
# STIX / MISP intelligence-sharing exports
# ---------------------------------------------------------------------------

class TestIntelExports:

    def test_export_stix_path_and_model(self):
        client, transport, _ = make_client([ok(STIX_PAYLOAD)])
        bundle = client.export_stix('domain', 'example.com')
        call = transport.calls[0]
        assert call['method'] == 'GET'
        assert call['url'] == \
            f'{BASE}/api/export/stix/domain/example.com'
        assert isinstance(bundle, StixBundle)
        assert bundle.type == 'bundle'
        assert bundle.id.startswith('bundle--')
        assert len(bundle.objects) == 5
        assert bundle.object_types() == Counter(
            {'identity': 1, 'indicator': 1, 'observed-data': 1,
             'relationship': 1, 'note': 1})
        assert bundle.indicator_count() == 1
        assert len(bundle.objects_of_type('indicator')) == 1
        assert bundle.objects_of_type('vulnerability') == []
        assert bundle.summary() == 'bundle: 5 object(s), 1 indicator(s)'

    def test_export_stix_to_json_round_trip(self):
        client, _, _ = make_client([ok(STIX_PAYLOAD)])
        bundle = client.export_stix('domain', 'example.com')
        text = bundle.to_json()
        assert json.loads(text)['type'] == 'bundle'
        assert '"indicator"' in bundle.to_json(indent=2)
        assert '\n' in bundle.to_json(indent=2)

    def test_export_misp_path_and_model(self):
        client, transport, _ = make_client([ok(MISP_PAYLOAD)])
        event = client.export_misp('domain', 'example.com')
        call = transport.calls[0]
        assert call['method'] == 'GET'
        assert call['url'] == \
            f'{BASE}/api/export/misp/domain/example.com'
        assert isinstance(event, MispEvent)
        assert event.attribute_count() == 3
        assert event.attribute_values() == ['example.com',
                                            'United States', 'AS15169']
        assert event.tags == ['obscuralens:domain']
        assert event.threat_level_id == '3'
        assert event.date == '2024-06-01'
        assert 'example.com' in event.info
        assert event.object_count() == 0
        assert event.summary() == \
            f'{event.info}: 3 attribute(s)'

    def test_export_misp_to_json_round_trip(self):
        client, _, _ = make_client([ok(MISP_PAYLOAD)])
        event = client.export_misp('domain', 'example.com')
        assert json.loads(event.to_json())['Event']['id'] == '20240601'
        assert '\n' in event.to_json(indent=4)

    @pytest.mark.parametrize('method,path', [
        ('export_stix', '/api/export/stix'),
        ('export_misp', '/api/export/misp'),
    ])
    def test_export_unknown_kind_raises_value_error(self, method, path):
        client, transport, _ = make_client([ok({})])
        with pytest.raises(ValueError):
            getattr(client, method)('carrier-pigeon', 'coo')
        assert transport.calls == []

    def test_export_stix_no_stored_lookup_is_not_found(self):
        client, _, _ = make_client(
            [err(404, "no stored domain lookup for 'example.com'")])
        with pytest.raises(NotFoundError):
            client.export_stix('domain', 'example.com')

    def test_export_misp_bad_request(self):
        client, _, _ = make_client([err(400, 'unknown kind')])
        with pytest.raises(BadRequestError):
            client.export_misp('ip', '1.2.3.4')


# ---------------------------------------------------------------------------
# Live stream topics
# ---------------------------------------------------------------------------

class TestStreamTopics:

    def test_set_stream_topics_list_body(self):
        subscribe_payload = {'topics': ['lookup', 'watch'], 'count': 2,
                             'subscriber_count': 1}
        client, transport, _ = make_client([ok(subscribe_payload)])
        result = client.set_stream_topics(['lookup', 'watch'])
        call = transport.calls[0]
        assert call['method'] == 'POST'
        assert call['url'] == f'{BASE}/api/stream/subscribe'
        assert call['json_body'] == {'topics': ['lookup', 'watch']}
        assert result == subscribe_payload

    def test_set_stream_topics_comma_string_normalised(self):
        client, transport, _ = make_client(
            [ok({'topics': ['lookup', 'watch'], 'count': 2,
                 'subscriber_count': 0})])
        client.set_stream_topics('lookup, watch')
        assert transport.calls[0]['json_body'] == \
            {'topics': ['lookup', 'watch']}

    def test_set_stream_topics_tuple_and_blanks(self):
        client, transport, _ = make_client(
            [ok({'topics': ['a', 'b'], 'count': 2,
                 'subscriber_count': 0})])
        client.set_stream_topics((' a ', '', 'b'))
        assert transport.calls[0]['json_body'] == {'topics': ['a', 'b']}

    def test_set_stream_topics_empty_is_bad_request(self):
        client, _, _ = make_client([err(400, 'topics is required')])
        with pytest.raises(BadRequestError):
            client.set_stream_topics('')


# ---------------------------------------------------------------------------
# Model tolerance (junk / missing keys)
# ---------------------------------------------------------------------------

class TestModelsV6:

    # -- DorkReport ---------------------------------------------------------

    def test_dork_report_junk_yields_defaults(self):
        for junk in (None, 'junk', [], 42, {'unexpected': 1}):
            report = DorkReport.from_dict(junk)
            assert report.target == ''
            assert report.detected_kind == ''
            assert report.count == 0
            assert report.dorks == []
            assert report.dork_kinds == []
            assert report.links() == []

    def test_dork_report_count_derived_from_dorks(self):
        report = DorkReport.from_dict(
            {'dorks': [{'engine': 'Google', 'url': 'u'}]})
        assert report.count == 1
        assert report.engines() == ['Google']

    def test_dork_report_skips_dorkless_entries_in_links(self):
        report = DorkReport.from_dict(
            {'dorks': [{'engine': 'Google'}, {'url': 'u'},
                       {'engine': 'Bing', 'url': 'v'}]})
        assert report.links() == ['u', 'v']

    # -- AnalyticsEnvelope --------------------------------------------------

    def test_analytics_envelope_junk_yields_empty_payload(self):
        for junk in (None, 'junk', [], 3.14):
            envelope = AnalyticsEnvelope.from_dict(junk)
            assert envelope.payload == {}
            assert envelope.get('count') is None
            assert envelope.get('count', 0) == 0
            assert envelope.count is None
            assert envelope.keys() == []

    def test_analytics_envelope_kind_falls_back_to_payload(self):
        envelope = AnalyticsEnvelope.from_dict({'kind': 'stats'})
        assert envelope.kind == 'stats'
        assert AnalyticsEnvelope.from_dict(
            {'analysis': 'graph'}).kind == 'graph'
        assert AnalyticsEnvelope.from_dict({}).kind == ''

    def test_analytics_envelope_count_prefers_plain_count(self):
        envelope = AnalyticsEnvelope.from_dict(
            {'count': 7, 'keyword_count': 2})
        assert envelope.count == 7

    def test_analytics_envelope_count_finds_suffixed_key(self):
        assert AnalyticsEnvelope.from_dict(
            {'cluster_count': 3}).count == 3
        assert AnalyticsEnvelope.from_dict(
            {'anomaly_count': 1}).count == 1
        assert AnalyticsEnvelope.from_dict({'counts': 9}).count is None

    # -- NotifyChannel ------------------------------------------------------

    def test_notify_channel_junk_yields_defaults(self):
        for junk in (None, 'junk', [], 5):
            channel = NotifyChannel.from_dict(junk)
            assert channel.name == ''
            assert channel.type == ''
            assert channel.enabled is True
            assert channel.min_severity == 'info'
            assert channel.quiet_hours is None
            assert channel.subscribes_to('anything')

    def test_notify_channel_accepts_wrapped_response(self):
        channel = NotifyChannel.from_dict(
            {'ok': True, 'channel': dict(CHANNEL_OPS)})
        assert channel.name == 'ops-webhook'
        assert channel.quiet_hours == [22, 6]
        assert channel.dedup_key == 'event+title'
        assert channel.last_sent == '2024-06-01T10:00:00'

    def test_notify_channel_quiet_hours_variants(self):
        assert NotifyChannel.from_dict(
            {'quiet_hours': [22, 6]}).quiet_hours == [22, 6]
        assert NotifyChannel.from_dict(
            {'quiet_hours': None}).quiet_hours is None
        assert NotifyChannel.from_dict(
            {'quiet_hours': [1]}).quiet_hours is None
        assert NotifyChannel.from_dict(
            {'quiet_hours': '22-6'}).quiet_hours is None
        assert NotifyChannel.from_dict(
            {'quiet_hours': {'start': 22, 'end': 6}}).quiet_hours == [22, 6]

    def test_notify_channel_disabled_summary(self):
        channel = NotifyChannel.from_dict(
            {'name': 'x', 'type': 'smtp', 'enabled': False})
        assert channel.is_enabled() is False
        assert channel.summary() == 'x [smtp]: everything, disabled'

    # -- NotifyChannels -----------------------------------------------------

    def test_notify_channels_junk_yields_defaults(self):
        for junk in (None, 'junk', [], 5):
            channels = NotifyChannels.from_dict(junk)
            assert channels.count == 0
            assert channels.channels == []
            assert channels.channel_types == []
            assert channels.severities == []

    def test_notify_channels_count_derived_from_list(self):
        channels = NotifyChannels.from_dict(
            {'channels': [{'name': 'a'}, {'name': 'b'}]})
        assert channels.count == 2
        assert channels.by_name('a').name == 'a'
        assert channels.summary() == '2 channel(s), 2 enabled, 0 type(s)'

    # -- NotifyDelivery -----------------------------------------------------

    def test_notify_delivery_test_shape(self):
        delivery = NotifyDelivery.from_dict(
            {'ok': True, 'error': '', 'channel': 'ops-webhook'})
        assert delivery.ok is True
        assert delivery.sent == 0
        assert delivery.failed == []

    def test_notify_delivery_broadcast_ok_derived(self):
        delivery = NotifyDelivery.from_dict(
            {'sent': 3, 'skipped': 0, 'failed': [], 'total': 3})
        assert delivery.ok is True
        assert delivery.failure_lines() == []
        assert delivery.summary() == '3 sent, 0 skipped, 0 failed of 3'

    def test_notify_delivery_junk_yields_defaults(self):
        for junk in (None, 'junk', [], 5):
            delivery = NotifyDelivery.from_dict(junk)
            assert delivery.ok is False  # neither test nor broadcast shape
            assert delivery.sent == 0
            assert delivery.failed == []
            assert delivery.failure_lines() == []

    def test_notify_delivery_failure_lines(self):
        delivery = NotifyDelivery.from_dict(
            {'failed': [{'channel': 'a', 'error': 'x'},
                        {'channel': 'b', 'error': 'y'}]})
        assert delivery.failure_lines() == ['a: x', 'b: y']
        assert delivery.ok is False

    # -- AutomationTaskView / AutomationTasks -------------------------------

    def test_task_view_junk_yields_defaults(self):
        for junk in (None, 'junk', [], 5, {'name': 'x'}):
            task = AutomationTaskView.from_dict(junk)
            assert task.params == {}
            assert task.schedule == 'interval'
            assert task.interval_seconds == 3600
            assert task.enabled is True
            assert task.last_run is None
            assert task.next_run is None
            assert task.run_count == 0

    def test_task_view_accepts_wrapped_response(self):
        task = AutomationTaskView.from_dict(
            {'ok': True, 'task': dict(TASK_DAILY)})
        assert task.name == 'daily-watch'
        assert task.at_time == '09:00'
        assert task.weekday == 0

    def test_task_view_weekly_summary(self):
        task = AutomationTaskView.from_dict(
            {'name': 'w', 'action': 'report', 'schedule': 'weekly',
             'at_time': '08:30', 'weekday': 4})
        assert task.is_due_style() == 'weekly'
        assert task.summary() == 'w [report, weekly 08:30]: 0 run(s)'

    def test_automation_tasks_junk_yields_defaults(self):
        for junk in (None, 'junk', [], 5):
            tasks = AutomationTasks.from_dict(junk)
            assert tasks.count == 0
            assert tasks.tasks == []
            assert tasks.by_name('x') is None
            assert tasks.summary() == '0 task(s), 0 enabled, 0 action(s)'

    # -- StixBundle ---------------------------------------------------------

    def test_stix_bundle_junk_yields_defaults(self):
        for junk in (None, 'junk', [], 5, {'objects': 'nope'}):
            bundle = StixBundle.from_dict(junk)
            assert bundle.type == 'bundle'
            assert bundle.id == ''
            assert bundle.objects == []
            assert bundle.object_types() == Counter()
            assert bundle.indicator_count() == 0
            assert bundle.objects_of_type('indicator') == []

    def test_stix_bundle_type_defaults_to_bundle(self):
        assert StixBundle.from_dict({'objects': []}).type == 'bundle'
        assert StixBundle.from_dict(
            {'type': 'other', 'objects': []}).type == 'other'

    def test_stix_bundle_skips_non_mapping_objects(self):
        bundle = StixBundle.from_dict(
            {'objects': [{'type': 'indicator'}, 'junk', 42]})
        assert bundle.object_types() == Counter({'indicator': 1})

    # -- MispEvent ----------------------------------------------------------

    def test_misp_event_junk_yields_defaults(self):
        for junk in (None, 'junk', [], 5, {'Event': 'nope'}):
            event = MispEvent.from_dict(junk)
            assert event.event == {}
            assert event.info == ''
            assert event.attribute_count() == 0
            assert event.tags == []
            assert event.threat_level_id == ''
            assert 'MISP event' in event.summary()

    def test_misp_event_accepts_bare_event_shape(self):
        event = MispEvent.from_dict(
            {'info': 'bare', 'Attribute': [{'value': 'v'}]})
        assert event.info == 'bare'
        assert event.attribute_values() == ['v']
        assert json.loads(event.to_json())['Event']['info'] == 'bare'

    def test_misp_event_objects_and_tags(self):
        event = MispEvent.from_dict(
            {'Event': {'info': 'i', 'Tag': [{'name': 'a'}, {'name': 'b'},
                                            'junk'],
                       'Object': [{'name': 'file'}, 'junk']}})
        assert event.tags == ['a', 'b']
        assert event.object_count() == 1
        assert event.objects[0]['name'] == 'file'


# ---------------------------------------------------------------------------
# InvestigationSession
# ---------------------------------------------------------------------------

class TestInvestigationSession:

    def test_lookup_step_records_model_and_fields(self):
        client, transport, _ = make_client([ok(IP_PAYLOAD)])
        session = InvestigationSession(client, label='demo')
        result = session.lookup('ip', '8.8.8.8')
        assert isinstance(result, LookupResult)
        assert len(session) == 1
        step = session.step(0)
        assert isinstance(step, SessionStep)
        assert step.method == 'lookup'
        assert step.target == '8.8.8.8'
        assert step.ok is True
        assert step.error == ''
        assert step.field_count == 3
        assert 'ip 8.8.8.8' in step.detail
        assert step.duration >= 0
        assert session.targets() == ['8.8.8.8']
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/lookup/ip/8.8.8.8'

    def test_every_step_method_records(self):
        script = [
            ok(IP_PAYLOAD),                 # lookup
            ok(INVESTIGATE_PAYLOAD),        # investigate
            ok(RISK_PAYLOAD),               # risk
            ok(TIMELINE_PAYLOAD),           # timeline
            ok(DORKS_PAYLOAD),              # dorks
            ok(STIX_PAYLOAD),               # export_stix
            ok(MISP_PAYLOAD),               # export_misp
        ]
        client, transport, _ = make_client(script)
        session = InvestigationSession(client)
        assert session.lookup('ip', '8.8.8.8') is not None
        assert session.investigate('evil.example.com') is not None
        assert session.risk('domain', 'evil.example.com') is not None
        assert session.timeline() is not None
        assert session.dorks('example.com') is not None
        assert session.export_stix('domain', 'evil.example.com') is not None
        assert session.export_misp('domain', 'evil.example.com') is not None
        session.note('closing the loop')
        assert len(session) == 8
        assert len(transport.calls) == 7
        methods = [step.method for step in session]
        assert methods == ['lookup', 'investigate', 'risk', 'timeline',
                           'dorks', 'export_stix', 'export_misp', 'note']
        assert session.ok_count == 8
        assert session.failed_count == 0
        assert session.notes == ['closing the loop']
        # timeline has no target -> not collected; targets() is sorted
        # ('evil.example.com' sorts before 'example.com': 'v' < 'x')
        assert session.targets() == ['8.8.8.8', 'evil.example.com',
                                     'example.com']

    def test_step_details_carry_one_line_summaries(self):
        script = [ok(RISK_PAYLOAD), ok(TIMELINE_PAYLOAD)]
        client, _, _ = make_client(script)
        session = InvestigationSession(client)
        session.risk('domain', 'evil.example.com')
        session.timeline()
        assert session.step(0).detail == 'high (72/100)'
        assert session.step(0).field_count == 1
        assert session.step(1).detail == '2 event(s)'
        assert session.step(1).field_count == 2
        assert session.step(99) is None

    def test_failed_step_records_error_and_continues(self):
        script = [err(404, 'not found'), ok(IP_PAYLOAD)]
        client, transport, _ = make_client(script)
        session = InvestigationSession(client)
        result = session.lookup('ip', '1.2.3.4')
        assert result is None
        assert len(session) == 1
        step = session.step(0)
        assert step.ok is False
        assert step.error == 'NotFoundError: not found (HTTP 404)'
        assert step.field_count == 0
        # the session keeps working after a failure
        session.note('the resolver was down')
        assert session.lookup('ip', '8.8.8.8') is not None
        assert len(session) == 3
        assert session.failed_count == 1
        assert session.ok_count == 2
        assert '1.2.3.4' in session.targets()  # failures are collected too
        assert len(transport.calls) == 2

    def test_strict_mode_raises_after_recording(self):
        client, _, _ = make_client([err(400, 'invalid VIN')])
        session = InvestigationSession(client, strict=True)
        with pytest.raises(BadRequestError):
            session.lookup('vin', 'NOT-A-VIN')
        assert len(session) == 1
        assert session.step(0).ok is False
        assert session.step(0).error == \
            'BadRequestError: invalid VIN (HTTP 400)'

    def test_summary_contains_label_targets_and_failures(self):
        script = [ok(IP_PAYLOAD), ok(INVESTIGATE_PAYLOAD),
                  err(404, 'no stored lookup')]
        client, _, _ = make_client(script)
        session = InvestigationSession(client, label='phishing-2024')
        session.lookup('ip', '8.8.8.8')
        session.investigate('evil.example.com')
        session.export_stix('domain', 'evil.example.com')
        session.note('victim reported 2024-05-01')
        report = session.summary()
        assert 'phishing-2024' in report
        assert '4 step(s): 3 ok, 1 failed' in report
        assert 'targets (2): 8.8.8.8, evil.example.com' in report
        assert '[4] note — ok: victim reported 2024-05-01' in report
        assert 'FAILED' in report
        assert 'NotFoundError: no stored lookup (HTTP 404)' in report

    def test_to_case_creates_case_and_adds_targets(self):
        script = [
            ok(IP_PAYLOAD),                 # lookup 1.2.3.4
            ok(INVESTIGATE_PAYLOAD),        # investigate evil.example.com
            ok(CASE_PAYLOAD),               # POST /api/cases
            ok(CASE_ITEM_PAYLOAD),          # POST /api/cases/7/items
            ok(CASE_ITEM_PAYLOAD),          # POST /api/cases/7/items
        ]
        client, transport, _ = make_client(script)
        session = InvestigationSession(client)
        session.lookup('ip', '1.2.3.4')
        session.investigate('evil.example.com')
        case = session.to_case('Phishing case', 'brand abuse')
        assert case is not None
        assert case.id == 7
        assert case.title == 'Phishing case'
        assert len(transport.calls) == 5
        create_call, first_item, second_item = transport.calls[2:]
        assert create_call['method'] == 'POST'
        assert create_call['url'] == f'{BASE}/api/cases'
        assert create_call['json_body'] == {'name': 'Phishing case',
                                            'description': 'brand abuse'}
        assert first_item['url'] == f'{BASE}/api/cases/7/items'
        assert first_item['json_body'] == {'kind': 'auto',
                                           'target': '1.2.3.4'}
        assert second_item['json_body'] == {'kind': 'auto',
                                            'target': 'evil.example.com'}
        step = session.steps[-1]
        assert step.method == 'to_case'
        assert step.ok is True
        assert step.field_count == 2
        assert step.detail == '#7 Phishing case: 2 item(s)'

    def test_to_case_creation_failure_records_step(self):
        client, _, _ = make_client([err(400, 'case name is required')])
        session = InvestigationSession(client)
        result = session.to_case('')
        assert result is None
        step = session.steps[-1]
        assert step.method == 'to_case'
        assert step.ok is False
        assert step.error == \
            'BadRequestError: case name is required (HTTP 400)'
        assert session.targets() == []  # the case name is not a target

    def test_to_case_creation_failure_strict_raises(self):
        client, _, _ = make_client([err(400, 'case name is required')])
        session = InvestigationSession(client, strict=True)
        with pytest.raises(BadRequestError):
            session.to_case('')
        assert session.steps[-1].ok is False

    def test_to_case_partial_item_failure_is_recorded(self):
        script = [
            ok(IP_PAYLOAD),                 # lookup 8.8.8.8
            ok(INVESTIGATE_PAYLOAD),        # investigate evil.example.com
            ok(CASE_PAYLOAD),               # create case
            ok(CASE_ITEM_PAYLOAD),          # first add ok
            err(400, 'duplicate item'),     # second add fails
        ]
        client, transport, _ = make_client(script)
        session = InvestigationSession(client)
        session.lookup('ip', '8.8.8.8')
        session.investigate('evil.example.com')
        case = session.to_case('Phishing case')
        assert case is not None  # the case exists even with one bad add
        assert len(transport.calls) == 5
        step = session.steps[-1]
        assert step.method == 'to_case'
        assert step.ok is False
        assert 'evil.example.com: BadRequestError: duplicate item' \
            in step.error
        assert step.detail == '#7 Phishing case: 2 item(s)'
        assert session.targets() == ['8.8.8.8', 'evil.example.com']

    def test_to_case_partial_item_failure_strict_raises(self):
        script = [ok(IP_PAYLOAD), ok(CASE_PAYLOAD), err(400, 'duplicate')]
        client, _, _ = make_client(script)
        session = InvestigationSession(client, strict=True)
        session.lookup('ip', '8.8.8.8')
        with pytest.raises(RuntimeError):
            session.to_case('Phishing case')
        assert session.steps[-1].method == 'to_case'
        assert 'duplicate' in session.steps[-1].error

    def test_dump_load_round_trip(self, tmp_path):
        client, _, _ = make_client([ok(IP_PAYLOAD)])
        session = InvestigationSession(client, label='phishing-2024',
                                       strict=False)
        session.lookup('ip', '8.8.8.8')
        session.note('victim reported 2024-05-01')
        receipt_path = session.dump(tmp_path / 'session.json')
        assert receipt_path.exists()
        raw = json.loads(receipt_path.read_text(encoding='utf-8'))
        assert raw['format'] == 'obscuralens-session/1'
        assert raw['label'] == 'phishing-2024'
        assert raw['step_count'] == 2
        loaded = InvestigationSession.load(receipt_path)
        assert loaded.label == 'phishing-2024'
        assert len(loaded) == 2
        assert loaded.notes == ['victim reported 2024-05-01']
        assert loaded.targets() == ['8.8.8.8']
        assert loaded.ok_count == 2
        assert loaded.step(0).method == 'lookup'

    def test_from_dict_without_client_is_read_only(self):
        receipt = {
            'label': 'archived',
            'strict': True,
            'started_at': '2024-06-01T10:00:00',
            'steps': [{'method': 'note', 'ok': True, 'detail': 'hi'}],
            'targets': ['8.8.8.8'],
        }
        session = InvestigationSession.from_dict(receipt)
        assert session.label == 'archived'
        assert session.strict is True
        assert session.started_at == '2024-06-01T10:00:00'
        assert session.notes == ['hi']
        assert session.targets() == ['8.8.8.8']
        with pytest.raises(RuntimeError):
            session.lookup('ip', '8.8.8.8')
        assert 'archived' in session.summary()

    def test_from_dict_junk_yields_empty_session(self):
        for junk in (None, 'junk', [], 5, {'steps': 'nope'}):
            session = InvestigationSession.from_dict(junk)
            assert len(session) == 0
            assert session.targets() == []
            assert session.notes == []
            assert session.to_dict()['step_count'] == 0

    def test_context_manager_closes_session_not_client(self):
        client, transport, _ = make_client([ok(IP_PAYLOAD)])
        with InvestigationSession(client) as session:
            session.lookup('ip', '8.8.8.8')
            assert session.closed is False
        assert session.closed is True
        with pytest.raises(RuntimeError):
            session.note('too late')
        assert '1 step(s)' in session.summary()  # read-only still works
        assert session.to_dict()['step_count'] == 1
        assert client._closed is False  # the client owns its lifecycle
        assert transport.closed is False

    def test_len_iter_repr_and_headlines(self):
        client, _, _ = make_client([ok(IP_PAYLOAD)])
        session = InvestigationSession(client, label='len-demo')
        session.lookup('ip', '8.8.8.8')
        session.note('hello')
        assert len(session) == 2
        assert [step.method for step in session] == ['lookup', 'note']
        assert 'len-demo' in repr(session)
        assert '2 step(s)' in repr(session)
        assert session.steps[0].headline().startswith('lookup 8.8.8.8')
        assert session.steps[0].headline().endswith(
            'ip 8.8.8.8: 3 field(s) from 1 source(s), 0 failed')
        failed = SessionStep(method='lookup', target='x', ok=False,
                             error='Boom: bad')
        assert failed.headline() == 'lookup x — FAILED: Boom: bad'

    def test_clientless_session_step_methods_raise(self):
        session = InvestigationSession()
        with pytest.raises(RuntimeError):
            session.lookup('ip', '8.8.8.8')
        with pytest.raises(RuntimeError):
            session.to_case('x')
        session.note('notes need no client')  # still fine
        assert len(session) == 1

    def test_session_step_round_trip_dict(self):
        step = SessionStep(method='lookup', target='8.8.8.8', ok=True,
                           duration=0.5, field_count=3, detail='d')
        restored = SessionStep.from_dict(step.to_dict())
        assert restored.method == 'lookup'
        assert restored.target == '8.8.8.8'
        assert restored.ok is True
        assert restored.duration == pytest.approx(0.5)
        assert restored.field_count == 3
        assert restored.detail == 'd'
        junk = SessionStep.from_dict(
            {'ok': 'yes', 'duration': 'slow', 'field_count': 1.5})
        assert junk.ok is True
        assert junk.duration == 0.0
        assert junk.field_count == 0


# ---------------------------------------------------------------------------
# Async client (v6 mirrors)
# ---------------------------------------------------------------------------

class TestAsyncClientV6:

    @staticmethod
    def make_async(script, **kwargs):
        transport = StaticTransport(list(script))
        async_client = AsyncObscuraLensClient(
            transport=transport, retries=1, **kwargs)
        return async_client, transport

    def test_await_sensor_lookups(self):
        samples = [
            ('vin', 'vin', '1HGCM82633A004352'),
            ('flight', 'flight', 'BA117'),
            ('mmsi', 'mmsi', '366982610'),
            ('app', 'app', 'left-pad'),
            ('package', 'app', 'left-pad'),
            ('bssid', 'bssid', 'b8:27:eb:aa:bb:cc'),
            ('plate', 'plate', 'B-AB 1234'),
        ]

        async def scenario():
            client, transport = self.make_async(
                [ok(sensor_payload(kind, target, {'a': 1}))
                 for _, kind, target in samples])
            try:
                results = []
                for method, kind, target in samples:
                    result = await getattr(client, method)(target)
                    assert isinstance(result, LookupResult)
                    assert result.kind == kind
                    results.append(result)
                return results, transport
            finally:
                await client.aclose()

        results, transport = asyncio.run(scenario())
        assert len(results) == 7
        assert all(f'/api/lookup/{kind}/' in call['url']
                   for call, (_, kind, _) in zip(transport.calls, samples))

    def test_await_dorks(self):
        async def scenario():
            client, transport = self.make_async([ok(DORKS_PAYLOAD)])
            try:
                report = await client.dorks('example.com', kind='domain')
                return report, transport
            finally:
                await client.aclose()

        report, transport = asyncio.run(scenario())
        assert isinstance(report, DorkReport)
        assert report.detected_kind == 'domain'
        assert transport.calls[0]['params'] == {'target': 'example.com',
                                                'kind': 'domain'}

    def test_await_analytics(self):
        async def scenario():
            client, transport = self.make_async(
                [ok(STATS_PAYLOAD), ok(ANOMALIES_PAYLOAD),
                 ok(CLUSTERS_PAYLOAD), ok(HISTORY_PAYLOAD)])
            try:
                stats = await client.analytics_stats([1, 2, 3], bins=4)
                anomalies = await client.analytics_anomalies(
                    [1, 2, 30], method='zscore', threshold=2.0)
                clusters = await client.analytics_clusters(
                    [[52.0, 13.0], [52.1, 13.1], [52.05, 13.05]],
                    eps_km=10.0, min_points=2)
                history = await client.analytics_history(limit=50)
                return stats, anomalies, clusters, history, transport
            finally:
                await client.aclose()

        stats, anomalies, clusters, history, transport = \
            asyncio.run(scenario())
        assert isinstance(stats, AnalyticsEnvelope)
        assert stats.kind == 'stats'
        assert stats.get('count') == 5
        assert isinstance(anomalies, AnalyticsEnvelope)
        assert anomalies.kind == 'anomalies'
        assert isinstance(clusters, AnalyticsEnvelope)
        assert clusters.kind == 'clusters'
        assert clusters.get('cluster_count') == 1
        assert isinstance(history, AnalyticsEnvelope)
        assert history.kind == 'history'
        assert transport.calls[0]['json_body'] == \
            {'values': [1, 2, 3], 'bins': 4}
        assert transport.calls[1]['json_body'] == \
            {'values': [1, 2, 30], 'method': 'zscore', 'threshold': 2.0}
        assert transport.calls[2]['method'] == 'POST'
        assert transport.calls[2]['url'] == f'{BASE}/api/analytics/clusters'
        assert transport.calls[2]['json_body'] == {
            'points': [[52.0, 13.0], [52.1, 13.1], [52.05, 13.05]],
            'eps_km': 10.0, 'min_points': 2}
        assert transport.calls[3]['params'] == {'limit': 50}

    def test_await_analytics_threshold_rule(self):
        async def scenario():
            client, transport = self.make_async(
                [ok(ANOMALIES_PAYLOAD)] * 2)
            try:
                await client.analytics_anomalies([1], method='mad',
                                                 threshold=2.0)
                await client.analytics_anomalies([1], method='zscore')
                return transport
            finally:
                await client.aclose()

        transport = asyncio.run(scenario())
        assert 'threshold' not in transport.calls[0]['json_body']
        assert 'threshold' not in transport.calls[1]['json_body']

    def test_await_notify(self):
        async def scenario():
            client, transport = self.make_async(
                [ok(NOTIFY_CHANNELS_PAYLOAD),
                 ok({'ok': True, 'channel': dict(CHANNEL_CHAT)}),
                 ok(BROADCAST_PAYLOAD)])
            try:
                channels = await client.notify_channels()
                channel = await client.add_notify_channel(
                    'team-chat', 'telegram', 'bot:chat',
                    events=['lookup'], min_severity='low')
                delivery = await client.notify_broadcast(
                    'watch diff', 'example.com changed NS',
                    severity='high', event_type='watch_diff')
                return channels, channel, delivery, transport
            finally:
                await client.aclose()

        channels, channel, delivery, transport = asyncio.run(scenario())
        assert isinstance(channels, NotifyChannels)
        assert channels.count == 2
        assert isinstance(channel, NotifyChannel)
        assert channel.name == 'team-chat'
        assert isinstance(delivery, NotifyDelivery)
        assert delivery.sent == 2
        assert transport.calls[1]['json_body'] == {
            'name': 'team-chat', 'type': 'telegram', 'target': 'bot:chat',
            'events': ['lookup'], 'min_severity': 'low'}
        assert transport.calls[2]['json_body'] == {
            'title': 'watch diff', 'body': 'example.com changed NS',
            'severity': 'high', 'event_type': 'watch_diff'}

    def test_await_automation(self):
        async def scenario():
            client, transport = self.make_async(
                [ok(AUTOMATION_TASKS_PAYLOAD),
                 ok({'ok': True, 'task': dict(TASK_DAILY)}),
                 ok({'ran': 1, 'results': [{'task': 'daily-watch',
                    'action': 'watch_check', 'ok': True}]})])
            try:
                tasks = await client.automation_tasks()
                task = await client.add_automation_task(
                    'daily-watch', 'watch_check', schedule='daily',
                    at_time='09:00')
                run_due = await client.run_due_automation()
                return tasks, task, run_due, transport
            finally:
                await client.aclose()

        tasks, task, run_due, transport = asyncio.run(scenario())
        assert isinstance(tasks, AutomationTasks)
        assert tasks.count == 2
        assert isinstance(task, AutomationTaskView)
        assert task.schedule == 'daily'
        assert run_due['ran'] == 1
        assert transport.calls[1]['json_body'] == {
            'name': 'daily-watch', 'action': 'watch_check',
            'schedule': 'daily', 'enabled': True, 'at_time': '09:00'}
        assert transport.calls[2]['method'] == 'POST'
        assert transport.calls[2]['url'] == \
            f'{BASE}/api/automation/run-due'

    def test_await_exports(self):
        async def scenario():
            client, transport = self.make_async(
                [ok(STIX_PAYLOAD), ok(MISP_PAYLOAD)])
            try:
                bundle = await client.export_stix('domain', 'example.com')
                event = await client.export_misp('domain', 'example.com')
                return bundle, event, transport
            finally:
                await client.aclose()

        bundle, event, transport = asyncio.run(scenario())
        assert isinstance(bundle, StixBundle)
        assert bundle.indicator_count() == 1
        assert isinstance(event, MispEvent)
        assert event.attribute_count() == 3
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/export/stix/domain/example.com'
        assert transport.calls[1]['url'] == \
            f'{BASE}/api/export/misp/domain/example.com'

    def test_await_export_error_propagates(self):
        async def scenario():
            client, _ = self.make_async([err(404, 'no stored lookup')])
            try:
                await client.export_stix('domain', 'example.com')
            except NotFoundError:
                return 'mapped'
            return 'unmapped'

        assert asyncio.run(scenario()) == 'mapped'

    def test_await_export_unknown_kind_raises(self):
        async def scenario():
            client, transport = self.make_async([])
            try:
                await client.export_stix('carrier-pigeon', 'coo')
            except ValueError:
                return transport
            raise AssertionError('expected ValueError')

        transport = asyncio.run(scenario())
        assert transport.calls == []

    def test_await_set_stream_topics(self):
        async def scenario():
            client, transport = self.make_async(
                [ok({'topics': ['lookup', 'watch'], 'count': 2,
                     'subscriber_count': 0})])
            try:
                result = await client.set_stream_topics('lookup, watch')
                return result, transport
            finally:
                await client.aclose()

        result, transport = asyncio.run(scenario())
        assert transport.calls[0]['json_body'] == \
            {'topics': ['lookup', 'watch']}
        assert result['count'] == 2

    def test_await_session_integration(self):
        async def scenario():
            client, transport = self.make_async(
                [ok(IP_PAYLOAD), ok(INVESTIGATE_PAYLOAD),
                 ok(CASE_PAYLOAD), ok(CASE_ITEM_PAYLOAD),
                 ok(CASE_ITEM_PAYLOAD)])
            try:
                session = InvestigationSession(
                    client.sync_client, label='phishing-2024')
                session.lookup('ip', '8.8.8.8')
                session.investigate('evil.example.com')
                session.note('victim reported 2024-05-01')
                case = session.to_case('Phishing case')
                return session, case, transport
            finally:
                await client.aclose()

        session, case, transport = asyncio.run(scenario())
        assert case is not None and case.id == 7
        assert len(session) == 4
        assert session.ok_count == 4
        assert len(transport.calls) == 5
        assert 'phishing-2024' in session.summary()
        assert 'targets (2): 8.8.8.8, evil.example.com' \
            in session.summary()


# ---------------------------------------------------------------------------
# Package surface (v6)
# ---------------------------------------------------------------------------

class TestPackageSurfaceV6:

    def test_new_names_resolve_from_sdk_package(self):
        import obscuralens.sdk as sdk

        for name in ('InvestigationSession', 'SessionStep', 'DorkReport',
                     'AnalyticsEnvelope', 'NotifyChannel', 'NotifyChannels',
                     'NotifyDelivery', 'AutomationTaskView',
                     'AutomationTasks', 'StixBundle', 'MispEvent'):
            assert name in sdk.__all__
            assert getattr(sdk, name, None) is not None, name

    def test_session_module_is_stdlib_only(self):
        import sys

        before = set(sys.modules)
        import obscuralens.sdk.session  # noqa: F401
        added = {name.split('.')[0] for name in set(sys.modules) - before}
        third_party = {'fastapi', 'uvicorn', 'requests', 'httpx', 'pydantic',
                       'starlette', 'yaml', 'jinja2'}
        assert not (added & third_party)

    def test_client_docstring_mentions_v6(self):
        import obscuralens.sdk.client as client_module

        text = client_module.__doc__
        assert 'analytics' in text
        assert 'STIX' in text
        assert 'InvestigationSession' in text

    def test_sensor_lookup_via_generic_lookup(self):
        client, transport, _ = make_client(
            [ok(sensor_payload('mmsi', '366982610', {'flag': 'US'}))])
        result = client.lookup('mmsi', '366982610')
        assert isinstance(result, LookupResult)
        assert result.get('flag') == 'US'
        assert transport.calls[0]['url'] == \
            f'{BASE}/api/lookup/mmsi/366982610'

"""CVE source readers, merge/provenance and tracker behaviour tests."""

import pytest

from obscuralens.config import config
from obscuralens.trackers import cve_sources
from obscuralens.trackers import cve_tracker as cve_tracker_module
from obscuralens.trackers.cve_tracker import CVETracker

# ---------------------------------------------------------------------------
# Payload builders (shaped like the real provider responses)
# ---------------------------------------------------------------------------

def _metric(key, score, severity, vector, version):
    return {key: [{'cvssData': {
        'baseScore': score,
        'baseSeverity': severity,
        'vectorString': vector,
        'version': version,
    }}]}


V31 = _metric('cvssMetricV31', 9.8, 'CRITICAL', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N', '3.1')
V30 = _metric('cvssMetricV30', 7.5, 'HIGH', 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N', '3.0')
V2 = _metric('cvssMetricV2', 6.8, 'MEDIUM', 'AV:N/AC:L/Au:N/C:P/I:P/A:P', '2.0')
V2_ENTRY_SEVERITY = {
    'cvssMetricV2': [{
        'cvssData': {'baseScore': 6.8, 'vectorString': 'AV:N/AC:L/Au:N', 'version': '2.0'},
        'baseSeverity': 'MEDIUM',
    }],
}


def _nvd_payload(metrics=None, descriptions=None, refs=2, cpes=2):
    return {'vulnerabilities': [{'cve': {
        'id': 'CVE-2021-44228',
        'vulnStatus': 'Analyzed',
        'published': '2021-11-24T17:15:00.000',
        'lastModified': '2022-01-10T06:00:00.000',
        'descriptions': descriptions or
        [{'lang': 'en', 'value': 'Remote code execution in Log4j.'}],
        'metrics': metrics if metrics is not None else V31,
        'weaknesses': [{'description': [{'lang': 'en', 'value': 'CWE-502'}]}],
        'references': [{'url': f'https://example.test/ref/{i}'} for i in range(refs)],
        'configurations': [{'nodes': [
            {'cpeMatch': [{'criteria': f'cpe:2.3:a:apache:log4j:{i}'} for i in range(cpes)]},
        ]}],
    }}]}


OSV = {
    'id': 'CVE-2021-44228',
    'summary': 'Critical RCE in Apache Log4j2',
    'published': '2021-11-24T00:00:00Z',
    'modified': '2021-12-20T00:00:00Z',
    'severity': [
        {'type': 'CVSS_V2', 'score': 'AV:N/AC:L/Au:N'},
        {'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N'},
    ],
    'references': [{'url': 'https://example.test/a', 'type': 'WEB'},
                   {'url': 'https://example.test/b', 'type': 'FIX'}],
    'affected': [
        {'package': {'name': 'log4j', 'ecosystem': 'Maven'}},
        {'package': {'name': 'log4j', 'ecosystem': 'Maven'}},
        {'package': {'name': 'requests', 'ecosystem': 'PyPI'}},
    ],
}

CNA = {
    'containers': {'cna': {
        'title': 'Remote code execution in Apache Log4j2',
        'datePublic': '2021-11-24',
        'descriptions': [{'lang': 'en', 'value': 'JNDI lookup feature RCE.'}],
        'affected': [{'product': 'log4j', 'vendor': 'apache'}],
        'references': [{'url': 'https://example.test/cna'}],
    }},
    'cveMetadata': {
        'datePublished': '2021-11-24T00:00:00',
        'dateUpdated': '2021-12-10T00:00:00',
        'state': 'PUBLISHED',
    },
}

EPSS = {'data': [{'cve': 'CVE-2021-44228', 'epss': '0.97',
                  'percentile': '0.9987', 'date': '2024-06-01'}]}

# CIRCL mirrors the CNA-published CVE 5.1 record (same family as the
# cvelistV2 payload, with cveMetadata carrying state/assigner/dates and no
# numeric CVSS block for this particular CVE - matching the live service).
CIRCL = {
    'dataType': 'CVE_RECORD',
    'dataVersion': '5.1',
    'cveMetadata': {
        'cveId': 'CVE-2021-44228',
        'state': 'PUBLISHED',
        'assignerShortName': 'apache',
        'datePublished': '2021-12-10T00:00:00.000Z',
        'dateUpdated': '2022-01-10T06:00:00.000Z',
    },
    'containers': {'cna': {
        'title': 'Remote code execution in Apache Log4j2',
        'descriptions': [{'lang': 'en', 'value': 'JNDI lookup RCE.'}],
        'metrics': [{'other': {'type': 'unknown',
                               'content': {'other': 'critical'}}}],
        'affected': [{'vendor': 'apache', 'product': 'Apache Log4j2'}],
        'references': [{'url': 'https://example.test/circl'}],
    }},
}


def _all_sources(url, **kwargs):
    """Dispatch any of the five CVE source URLs to a fixture payload."""
    if 'services.nvd.nist.gov' in url:
        return True, _nvd_payload(), ''
    if 'api.osv.dev' in url:
        return True, OSV, ''
    if 'raw.githubusercontent.com' in url:
        return True, CNA, ''
    if 'api.first.org' in url:
        return True, EPSS, ''
    if 'cve.circl.lu' in url:
        return True, CIRCL, ''
    return False, None, f'unexpected url {url}'


@pytest.fixture()
def recording_db(monkeypatch):
    """Replace the tracker's db with a call recorder."""
    calls = []

    class _Db:
        def save_query(self, query_type, query_value, result_data,
                       success=True, error_message=''):
            calls.append({'type': query_type, 'value': query_value,
                          'success': success, 'error': error_message})
            return len(calls)

    monkeypatch.setattr(cve_tracker_module, 'db', _Db())
    return calls


# ---------------------------------------------------------------------------
# NVD reader
# ---------------------------------------------------------------------------

def test_nvd_prefers_v31_metric(fake_http):
    fake_http.json = lambda url, **kw: (True, _nvd_payload(
        metrics={**V31, **V30, **V2}), '')
    out = cve_sources._nvd('CVE-2021-44228')
    assert out['cvss_score'] == 9.8
    assert out['cvss_severity'] == 'CRITICAL'
    assert out['cvss_vector'] == 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N'
    assert out['cvss_version'] == '3.1'


def test_nvd_falls_back_to_v30(fake_http):
    fake_http.json = lambda url, **kw: (True, _nvd_payload(
        metrics={**V30, **V2}), '')
    out = cve_sources._nvd('CVE-2021-44228')
    assert out['cvss_score'] == 7.5
    assert out['cvss_version'] == '3.0'


def test_nvd_falls_back_to_v2(fake_http):
    fake_http.json = lambda url, **kw: (True, _nvd_payload(
        metrics=V2_ENTRY_SEVERITY), '')
    out = cve_sources._nvd('CVE-2021-44228')
    assert out['cvss_score'] == 6.8
    # CVSS v2 keeps baseSeverity on the metric entry, not inside cvssData.
    assert out['cvss_severity'] == 'MEDIUM'
    assert out['cvss_version'] == '2.0'


def test_nvd_description_english_only(fake_http):
    payload = _nvd_payload(descriptions=[
        {'lang': 'es', 'value': 'Ejecucion de codigo'},
        {'lang': 'en', 'value': 'Remote code execution in Log4j.'},
    ])
    fake_http.json = lambda url, **kw: (True, payload, '')
    out = cve_sources._nvd('CVE-2021-44228')
    assert out['description'] == 'Remote code execution in Log4j.'


def test_nvd_no_english_description(fake_http):
    payload = _nvd_payload(descriptions=[{'lang': 'fr', 'value': 'Execution a distance'}])
    fake_http.json = lambda url, **kw: (True, payload, '')
    out = cve_sources._nvd('CVE-2021-44228')
    assert 'description' not in out


def test_nvd_reference_and_cpe_caps(fake_http):
    fake_http.json = lambda url, **kw: (True, _nvd_payload(refs=20, cpes=18), '')
    out = cve_sources._nvd('CVE-2021-44228')
    assert len(out['references']) == 15
    assert out['reference_count'] == 20
    assert len(out['affected_cpes']) == 15
    assert out['cpe_count'] == 18
    assert out['cwe'] == 'CWE-502'
    assert out['vuln_status'] == 'Analyzed'
    assert out['published'].startswith('2021-11-24')
    assert out['last_modified'].startswith('2022-01-10')


def test_nvd_http_failure_returns_empty(fake_http):
    fake_http.json = lambda url, **kw: (False, None, 'timeout')
    assert cve_sources._nvd('CVE-2021-44228') == {}


def test_nvd_sends_api_key_when_configured(fake_http, monkeypatch):
    captured = {}

    def dispatch(url, **kwargs):
        captured['headers'] = kwargs.get('headers')
        return True, _nvd_payload(), ''

    fake_http.json = dispatch
    monkeypatch.setattr(config.api_config, 'nvd_api_key', 'sekret')
    out = cve_sources._nvd('CVE-2021-44228')
    assert captured['headers'] == {'apiKey': 'sekret'}
    assert out['cvss_score'] == 9.8


def test_nvd_keyless_without_configured_key(fake_http, monkeypatch):
    captured = {}

    def dispatch(url, **kwargs):
        captured['headers'] = kwargs.get('headers')
        return True, _nvd_payload(), ''

    fake_http.json = dispatch
    monkeypatch.setattr(config.api_config, 'nvd_api_key', '')
    cve_sources._nvd('CVE-2021-44228')
    assert captured['headers'] is None


# ---------------------------------------------------------------------------
# OSV reader
# ---------------------------------------------------------------------------

def test_osv_packages_deduplicated_and_sorted(fake_http):
    fake_http.json = lambda url, **kw: (True, OSV, '')
    out = cve_sources._osv('CVE-2021-44228')
    assert out['osv_packages'] == ['Maven/log4j', 'PyPI/requests']
    assert out['osv_package_count'] == 2


def test_osv_fields(fake_http):
    fake_http.json = lambda url, **kw: (True, OSV, '')
    out = cve_sources._osv('CVE-2021-44228')
    assert out['osv_summary'] == 'Critical RCE in Apache Log4j2'
    assert out['osv_published'] == '2021-11-24T00:00:00Z'
    assert out['osv_modified'] == '2021-12-20T00:00:00Z'
    # CVSS_V3 wins even when a CVSS_V2 entry comes first.
    assert out['osv_severity_vector'] == 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N'
    assert out['osv_reference_count'] == 2


def test_osv_http_failure_returns_empty(fake_http):
    fake_http.json = lambda url, **kw: (False, None, 'not found')
    assert cve_sources._osv('CVE-2021-44228') == {}


# ---------------------------------------------------------------------------
# cvelist reader
# ---------------------------------------------------------------------------

def test_cvelist_bucket_path_math():
    url = cve_sources._cvelist_url('CVE-2021-44228')
    # Regression: the CNA mirror lives in the cvelistV5 repository
    # (cvelistV2 no longer serves these paths).
    assert 'CVEProject/cvelistV5' in url
    assert '/cves/2021/44xxx/' in url
    assert url.endswith('/cves/2021/44xxx/CVE-2021-44228.json')
    # 1234 // 1000 == 1 -> the '1xxx' bucket.
    assert '/cves/2020/1xxx/' in cve_sources._cvelist_url('CVE-2020-1234')
    assert cve_sources._cvelist_url('nonsense') == ''


def test_cvelist_uses_bucketed_url(fake_http):
    fake_http.json = lambda url, **kw: (True, CNA, '')
    cve_sources._cvelist('CVE-2021-44228')
    urls = [u for kind, u in fake_http.calls if kind == 'json']
    assert any('/cves/2021/44xxx/CVE-2021-44228.json' in u for u in urls)


def test_cvelist_fields(fake_http):
    fake_http.json = lambda url, **kw: (True, CNA, '')
    out = cve_sources._cvelist('CVE-2021-44228')
    assert out['cna_title'] == 'Remote code execution in Apache Log4j2'
    assert out['cna_published'] == '2021-11-24'
    assert out['cna_updated'] == '2021-12-10T00:00:00'
    assert out['cna_state'] == 'PUBLISHED'
    assert out['cna_description'] == 'JNDI lookup feature RCE.'
    assert out['cna_affected_products'] == ['log4j']


def test_cvelist_description_truncated(fake_http):
    payload = {
        'containers': {'cna': {'descriptions': [
            {'lang': 'en', 'value': 'x' * 600}]}},
        'cveMetadata': {'state': 'PUBLISHED'},
    }
    fake_http.json = lambda url, **kw: (True, payload, '')
    out = cve_sources._cvelist('CVE-2021-44228')
    assert len(out['cna_description']) == 500


def test_cvelist_http_failure_returns_empty(fake_http):
    fake_http.json = lambda url, **kw: (False, None, 'http 404')
    assert cve_sources._cvelist('CVE-2021-44228') == {}


# ---------------------------------------------------------------------------
# EPSS reader
# ---------------------------------------------------------------------------

def test_epss_percent_math(fake_http):
    fake_http.json = lambda url, **kw: (True, EPSS, '')
    out = cve_sources._epss('CVE-2021-44228')
    assert out['epss_score'] == 97.0
    assert out['epss_percentile'] == 99.9
    assert out['epss_date'] == '2024-06-01'


def test_epss_bad_values_are_skipped(fake_http):
    payload = {'data': [{'cve': 'CVE-2021-44228', 'epss': 'n/a',
                         'percentile': None, 'date': '2024-06-01'}]}
    fake_http.json = lambda url, **kw: (True, payload, '')
    out = cve_sources._epss('CVE-2021-44228')
    assert 'epss_score' not in out
    assert 'epss_percentile' not in out
    assert out['epss_date'] == '2024-06-01'


def test_epss_http_failure_returns_empty(fake_http):
    fake_http.json = lambda url, **kw: (False, None, 'timeout')
    assert cve_sources._epss('CVE-2021-44228') == {}


# ---------------------------------------------------------------------------
# gather_all: merge, provenance, failure isolation
# ---------------------------------------------------------------------------

def _fake_sources():
    return {
        'alpha': lambda cve: {'description': 'A says', 'cwe': 'CWE-1'},
        'beta': lambda cve: {'description': 'B says', 'osv_packages': ['PyPI/x']},
        'broken': lambda cve: (_ for _ in ()).throw(RuntimeError('boom')),
        'empty': lambda cve: {},
    }


def test_gather_all_invalid_identifier_raises():
    with pytest.raises(ValueError, match='invalid CVE identifier'):
        cve_sources.gather_all('CVE-2021-XX')
    with pytest.raises(ValueError):
        cve_sources.gather_all('nonsense')


def test_gather_all_normalises_identifier(fake_http):
    fake_http.json = _all_sources
    out = cve_sources.gather_all('cve-2021-44228')
    assert out['fields']['cve'] == 'CVE-2021-44228'
    assert out['sources']['nvd']['ok'] is True


def test_gather_all_merges_with_provenance(monkeypatch):
    monkeypatch.setattr(cve_sources, 'FREE_SOURCES', _fake_sources())
    out = cve_sources.gather_all('CVE-2021-44228')

    # Registration order wins conflicts.
    assert out['fields']['description'] == 'A says'
    # Provenance records every provider of a field.
    assert out['provenance']['description'] == ['alpha', 'beta']
    assert out['provenance']['cwe'] == ['alpha']
    # The identifier is injected after the merge.
    assert out['fields']['cve'] == 'CVE-2021-44228'
    # Failure and empty status are reported, never raised.
    assert out['sources']['broken']['ok'] is False
    assert out['sources']['broken']['error'] == 'RuntimeError'
    assert out['sources']['empty']['ok'] is False
    assert out['sources']['alpha']['ok'] is True


def test_gather_all_failure_isolation(monkeypatch):
    monkeypatch.setattr(cve_sources, 'FREE_SOURCES', _fake_sources())
    out = cve_sources.gather_all('CVE-2021-44228')
    assert out['fields']['cwe'] == 'CWE-1'
    assert out['fields']['osv_packages'] == ['PyPI/x']


def test_gather_all_respects_disabled_sources(monkeypatch):
    monkeypatch.setattr(cve_sources, 'FREE_SOURCES', _fake_sources())
    monkeypatch.setattr(config.app_config, 'disabled_sources', ['beta'])
    out = cve_sources.gather_all('CVE-2021-44228')
    assert 'beta' not in out['sources']
    assert out['fields']['description'] == 'A says'


def test_gather_all_nvd_key_override(fake_http):
    captured = []

    def dispatch(url, **kwargs):
        captured.append(kwargs.get('headers'))
        if 'services.nvd.nist.gov' in url:
            return True, _nvd_payload(), ''
        return False, None, 'down'

    fake_http.json = dispatch
    out = cve_sources.gather_all('CVE-2021-44228', {'nvd': 'explicit-key'})
    assert {'apiKey': 'explicit-key'} in captured
    assert out['fields']['cvss_score'] == 9.8
    assert out['fields']['cve'] == 'CVE-2021-44228'


def test_registries_are_consistent():
    assert set(cve_sources.FREE_SOURCES) == {
        'nvd', 'osv', 'cvelist', 'epss', 'circl'}
    assert cve_sources.KEYED_SOURCES == {}
    assert set(cve_sources.SOURCE_CATALOG) == set(cve_sources.FREE_SOURCES)


# ---------------------------------------------------------------------------
# CVETracker
# ---------------------------------------------------------------------------

def test_tracker_success_shape(fake_http, recording_db):
    fake_http.json = _all_sources
    result = CVETracker().track('cve-2021-44228')

    assert result['cve'] == 'CVE-2021-44228'
    assert result['success'] is True
    assert result['sources_ok'] == ['circl', 'cvelist', 'epss', 'nvd', 'osv']
    assert result['sources_failed'] == {}
    assert result['errors'] == []
    assert result['field_count'] > 5
    # The identifier is part of the merged info.
    assert result['info']['cve'] == 'CVE-2021-44228'
    assert result['info']['cvss_score'] == 9.8
    assert result['info']['epss_score'] == 97.0
    assert result['info']['osv_packages'] == ['Maven/log4j', 'PyPI/requests']
    assert result['info']['cna_state'] == 'PUBLISHED'
    # Provenance is surfaced as field_sources.
    assert result['field_sources']['cvss_score'] == ['nvd']
    assert result['field_sources']['epss_score'] == ['epss']
    # Query history got exactly one successful row.
    assert len(recording_db) == 1
    assert recording_db[0]['type'] == 'cve'
    assert recording_db[0]['value'] == 'CVE-2021-44228'
    assert recording_db[0]['success'] is True


def test_tracker_partial_failure_still_succeeds(fake_http, recording_db):
    def dispatch(url, **kwargs):
        if 'api.first.org' in url or 'raw.githubusercontent.com' in url:
            return False, None, 'down'
        return _all_sources(url, **kwargs)

    fake_http.json = dispatch
    result = CVETracker().track('CVE-2021-44228')
    assert result['success'] is True
    assert result['sources_ok'] == ['circl', 'nvd', 'osv']
    # Readers swallow transport errors and return {} - the merged report then
    # records the source as "no data" rather than crashing the scan.
    assert result['sources_failed'] == {'cvelist': 'no data', 'epss': 'no data'}
    assert result['errors'] == ['2 source(s) unavailable']
    assert 'epss_score' not in result['info']
    assert recording_db[0]['success'] is True


def test_tracker_all_sources_failed(fake_http, recording_db):
    fake_http.json = lambda url, **kw: (False, None, 'timeout')
    result = CVETracker().track('CVE-2021-44228')
    assert result['success'] is False
    assert result['errors'] == ['all data sources failed']
    assert result['info'] == {'cve': 'CVE-2021-44228'}
    assert recording_db[0]['success'] is False
    assert recording_db[0]['error'] == 'all data sources failed'


def test_tracker_invalid_identifier_skips_everything(fake_http, recording_db):
    fake_http.json = lambda url, **kw: (True, _nvd_payload(), '')
    result = CVETracker().track('CVE-2021-XX')

    assert result['success'] is False
    assert result['info'] == {}
    assert result['field_count'] == 0
    assert result['sources_ok'] == []
    assert result['errors'] and 'Invalid CVE format' in result['errors'][0]
    assert fake_http.calls == []
    assert recording_db == []


def test_tracker_blank_identifier(fake_http, recording_db):
    result = CVETracker().track('')
    assert result['success'] is False
    assert result['cve'] == ''
    assert recording_db == []


def test_batch_track_preserves_order(fake_http, recording_db):
    fake_http.json = _all_sources
    results = CVETracker().batch_track(
        ['CVE-2021-44228', 'CVE-2021-XX', 'CVE-2020-1234'])

    assert len(results) == 3
    assert results[0]['cve'] == 'CVE-2021-44228'
    assert results[0]['success'] is True
    assert results[1]['success'] is False
    assert results[2]['cve'] == 'CVE-2020-1234'
    assert results[2]['success'] is True
    # Two valid lookups were saved; the invalid one never reached history.
    assert len(recording_db) == 2


def test_tracker_helpers():
    tracker = CVETracker()
    assert tracker.source_names() == ['circl', 'cvelist', 'epss', 'nvd', 'osv']
    assert set(tracker.source_catalog()) == set(cve_sources.SOURCE_CATALOG)
    assert 'keyless' in tracker.source_catalog()['nvd']

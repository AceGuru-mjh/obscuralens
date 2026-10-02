"""File hash source readers, merge/provenance and tracker tests.

All network access is faked: GET-style readers run through the shared
``fake_http`` fixture, and MalwareBazaar's POST endpoint is monkeypatched on
the shared HTTP client (``post_json`` is NOT covered by ``fake_http``).
"""

import pytest

from obscuralens.config import config
from obscuralens.trackers import hash_sources
from obscuralens.trackers.hash_tracker import HashTracker
from obscuralens.utils.http_client import http

# Well-known digests of the empty string (correct lengths by construction).
MD5 = 'd41d8cd98f00b204e9800998ecf8427e'
SHA1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
SHA512 = (
    'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce'
    '47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'
)
SHA224 = 'a' * 56  # sha224 digest length, unsupported by CIRCL hashlookup

MB_ENTRY = {
    'sha256_hash': SHA256,
    'md5_hash': MD5,
    'sha1_hash': SHA1,
    'file_name': 'invoice_2024.exe',
    'file_type': 'exe',
    'file_type_mime': 'application/x-dosexec',
    'file_size': 789456,
    'signature': 'Emotet',
    'first_seen': '2024-01-02 03:04:05',
    'last_seen': '2024-06-07 08:09:10',
    'tags': ['emotet', 'loader'],
    'imphash': '1a2b3c4d5e6f708192a3b4c5d6e7f809',
}
MB_OK_RESPONSE = (True, {'query_status': 'ok', 'data': [MB_ENTRY]}, '')

HL_REPORT = {
    'file-name': 'kernel32.dll',
    'file-size': 12345,
    'file-type': 'application/x-dosexec',
    'SSDEEP': '12288:abcdefgh:ijklmnop',
    'TLSH': 'T1FF7A03BC019F41F19F8E4C3D2A3B4C5D6E7F8',
    'crc32': 'ABCD1234',
}

OTX_REPORT = {
    'indicator': SHA256,
    'whitelist': False,
    'pulse_info': {
        'count': 2,
        'pulses': [
            {'name': 'Emotet campaign Jan', 'created': '2024-03-01T00:00:00',
             'tags': ['emotet', 'banker']},
            {'name': 'Older dropper', 'created': '2023-01-01T00:00:00',
             'tags': ['emotet', 'dropper']},
        ],
    },
}

VT_REPORT = {
    'data': {
        'attributes': {
            'reputation': -12,
            'type_description': 'win32 executable',
            'size': 456789,
            'meaningful_name': 'invoice_2024.exe',
            'magic': 'PE32 executable (GUI) Intel 80386',
            'creation_date': 1580515200,
            'last_analysis_stats': {
                'malicious': 10, 'suspicious': 5, 'undetected': 60,
                'harmless': 10, 'timeout': 15,
            },
            'popular_threat_classification': {
                'suggested_threat_label': 'trojan.emotet/exe',
            },
            'tags': ['exe', 'win32'],
            'md5': MD5, 'sha1': SHA1, 'sha256': SHA256,
        }
    }
}


def _patch_malwarebazaar(monkeypatch, response, captured=None):
    """Route abuse.ch POSTs to a canned (ok, data, error) tuple."""
    def fake_post(url, payload=None, **kwargs):
        if captured is not None:
            captured.append({'url': url, 'payload': payload,
                            'headers': kwargs.get('headers')})
        return response

    monkeypatch.setattr(http, 'post_json', fake_post)
    return fake_post


def _install_keyless_stack(fake_http, monkeypatch, include_vt=False):
    """Canned responses for the keyless sources (and VirusTotal on demand)."""
    seen = {'urls': [], 'vt_headers': None}

    def dispatch(url, **kwargs):
        seen['urls'].append(url)
        if 'hashlookup.circl.eu' in url:
            return (True, HL_REPORT, '')
        if 'otx.alienvault.com' in url:
            return (True, OTX_REPORT, '')
        if 'virustotal.com' in url:
            if not include_vt:
                return (False, None, 'virustotal must not be queried keyless')
            seen['vt_headers'] = kwargs.get('headers')
            return (True, VT_REPORT, '')
        return (False, None, f'unexpected url: {url}')

    fake_http.json = dispatch
    _patch_malwarebazaar(monkeypatch, MB_OK_RESPONSE)
    return seen


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('value, expected', [
    (1580515200, '2020-02-01'),
    (1580515200.0, '2020-02-01'),
    ('1580515200', '2020-02-01'),
    (0, '1970-01-01'),
    (None, None),
    ('not-a-number', None),
    (999999999999999, None),
    (True, None),
])
def test_epoch_to_date(value, expected):
    assert hash_sources._epoch_to_date(value) == expected


@pytest.mark.parametrize('value, expected', [
    (7, 7), (7.9, 7), ('7', 7), (' 7 ', 7), (None, 0), ('x', 0),
    (True, 0), (False, 0), ([1], 0),
])
def test_as_int_coercion(value, expected):
    assert hash_sources._as_int(value) == expected


# ---------------------------------------------------------------------------
# CIRCL hashlookup reader
# ---------------------------------------------------------------------------

def test_hashlookup_routes_by_algorithm(fake_http):
    seen = []

    def dispatch(url, **kwargs):
        seen.append(url)
        return (True, HL_REPORT, '')

    fake_http.json = dispatch
    hash_sources._hashlookup(MD5.upper())
    hash_sources._hashlookup(SHA1)
    hash_sources._hashlookup(SHA256)
    assert seen == [
        f'https://hashlookup.circl.eu/api/hash/md5/{MD5}',
        f'https://hashlookup.circl.eu/api/hash/sha1/{SHA1}',
        f'https://hashlookup.circl.eu/api/hash/sha256/{SHA256}',
    ]


def test_hashlookup_skips_unsupported_algorithms(fake_http):
    fake_http.json = lambda url, **kw: (True, HL_REPORT, '')
    assert hash_sources._hashlookup(SHA512) == {}
    assert hash_sources._hashlookup(SHA224) == {}
    assert hash_sources._hashlookup('not-a-hash') == {}
    assert fake_http.calls == []  # declined locally, no request spent


@pytest.mark.parametrize('payload, expected', [
    ({'file-name': 'kernel32.dll', 'file-size': 12345,
      'file-type': 'application/x-dosexec', 'SSDEEP': '12288:a:b', 'TLSH': 'T1'},
     {'hl_file_name': 'kernel32.dll', 'hl_file_size': 12345,
      'hl_file_type': 'application/x-dosexec', 'ssdeep': '12288:a:b', 'tlsh': 'T1'}),
    ({'FileName': 'wininet.dll', 'FileSize': 999, 'FileType': 'pe32',
      'ssdeep': '3:abc:def', 'tlsh': 'T1234'},
     {'hl_file_name': 'wininet.dll', 'hl_file_size': 999,
      'hl_file_type': 'pe32', 'ssdeep': '3:abc:def', 'tlsh': 'T1234'}),
])
def test_hashlookup_parses_response(fake_http, payload, expected):
    fake_http.json = lambda url, **kw: (True, payload, '')
    out = hash_sources._hashlookup(MD5)
    for field, value in expected.items():
        assert out[field] == value
    assert out['known_file'] is True


@pytest.mark.parametrize('response', [
    (False, None, 'not found'),  # 404: not in the known-file corpus
    (True, {}, ''),              # empty body
    (False, None, 'timeout'),
])
def test_hashlookup_returns_empty_on_miss(fake_http, response):
    fake_http.json = lambda url, **kw: response
    assert hash_sources._hashlookup(SHA256) == {}


# ---------------------------------------------------------------------------
# MalwareBazaar reader
# ---------------------------------------------------------------------------

def test_malwarebazaar_parses_sample_record(monkeypatch):
    captured = []
    _patch_malwarebazaar(monkeypatch, MB_OK_RESPONSE, captured)
    out = hash_sources._malwarebazaar(SHA256)
    assert captured[0]['url'] == 'https://mb-api.abuse.ch/api/v1/'
    assert captured[0]['payload'] == {'query': 'get_info', 'hash': SHA256}
    assert out['malware_family'] == 'Emotet'
    assert out['file_name'] == 'invoice_2024.exe'
    assert out['file_size'] == 789456
    assert out['file_type_mime'] == 'application/x-dosexec'
    assert out['first_seen'] == '2024-01-02 03:04:05'
    assert out['last_seen'] == '2024-06-07 08:09:10'
    assert out['malware_tags'] == ['emotet', 'loader']
    assert out['imphash'] == '1a2b3c4d5e6f708192a3b4c5d6e7f809'
    assert out['mb_sha256'] == SHA256
    assert out['mb_md5'] == MD5
    assert out['mb_sha1'] == SHA1


@pytest.mark.parametrize('response', [
    (True, {'query_status': 'no_result'}, ''),
    (True, {'query_status': 'illegal_hash'}, ''),
    (True, {'query_status': 'ok', 'data': []}, ''),
    (True, {'query_status': 'ok', 'data': 'not-a-list'}, ''),
    (False, None, 'timeout'),
])
def test_malwarebazaar_no_data_yields_empty(monkeypatch, response):
    _patch_malwarebazaar(monkeypatch, response)
    assert hash_sources._malwarebazaar(MD5) == {}


def test_malwarebazaar_keyless_by_default(monkeypatch):
    captured = []
    _patch_malwarebazaar(monkeypatch, MB_OK_RESPONSE, captured)
    out = hash_sources._malwarebazaar(MD5)
    assert captured[0]['headers'] is None
    assert out['malware_family'] == 'Emotet'


def test_malwarebazaar_sends_auth_key_when_configured(monkeypatch):
    captured = []
    _patch_malwarebazaar(monkeypatch, MB_OK_RESPONSE, captured)
    monkeypatch.setattr(config.api_config, 'malwarebazaar_api_key', 'mb-secret')
    out = hash_sources._malwarebazaar(MD5)
    assert captured[0]['headers'] == {'Auth-Key': 'mb-secret'}
    assert out['malware_family'] == 'Emotet'


# ---------------------------------------------------------------------------
# AlienVault OTX reader
# ---------------------------------------------------------------------------

def test_otx_parses_pulses_and_whitelist(fake_http):
    seen = {}

    def dispatch(url, **kwargs):
        seen['url'] = url
        seen['headers'] = kwargs.get('headers')
        return (True, OTX_REPORT, '')

    fake_http.json = dispatch
    out = hash_sources._otx(SHA256)
    assert seen['url'] == (
        f'https://otx.alienvault.com/api/v1/indicators/file/{SHA256}/general')
    assert seen['headers'] is None  # keyless by default
    assert out['otx_pulses'] == 2
    assert out['otx_whitelisted'] is False
    assert out['otx_last_pulse'] == '2024-03-01T00:00:00'
    assert out['otx_tags'] == ['emotet', 'banker', 'dropper']


def test_otx_caps_and_dedupes_tags(fake_http):
    payload = {'pulse_info': {'count': 3, 'pulses': [
        {'name': 'p0', 'created': '2024-03-01T00:00:00',
         'tags': ['a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'dup']},
        {'name': 'p1', 'created': '2024-04-01T00:00:00',
         'tags': ['b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'dup']},
        {'name': 'p2', 'created': '2024-05-01T00:00:00',
         'tags': ['c0', 'c1', 'dup']},
    ]}}
    fake_http.json = lambda url, **kw: (True, payload, '')
    out = hash_sources._otx(SHA256)
    # First-seen order, duplicates dropped, hard cap at 10 entries.
    assert out['otx_tags'] == [
        'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'dup', 'b0', 'b1', 'b2']
    assert out['otx_last_pulse'] == '2024-05-01T00:00:00'
    assert 'otx_whitelisted' not in out


def test_otx_whitelist_only_report(fake_http):
    payload = {'whitelist': True, 'pulse_info': {'count': 0, 'pulses': []}}
    fake_http.json = lambda url, **kw: (True, payload, '')
    out = hash_sources._otx(SHA256)
    assert out == {'otx_pulses': 0, 'otx_whitelisted': True}


@pytest.mark.parametrize('response', [
    (True, {'pulse_info': {'count': 0, 'pulses': []}}, ''),
    (True, {}, ''),
    (False, None, 'timeout'),
])
def test_otx_no_intel_returns_empty(fake_http, response):
    fake_http.json = lambda url, **kw: response
    assert hash_sources._otx(SHA256) == {}


def test_otx_sends_api_key_header_when_configured(fake_http, monkeypatch):
    seen = {}

    def dispatch(url, **kwargs):
        seen['headers'] = kwargs.get('headers')
        return (True, OTX_REPORT, '')

    fake_http.json = dispatch
    monkeypatch.setattr(config.api_config, 'otx_api_key', 'otx-secret')
    out = hash_sources._otx(SHA256)
    assert seen['headers'] == {'X-OTX-API-KEY': 'otx-secret'}
    assert out['otx_pulses'] == 2


# ---------------------------------------------------------------------------
# VirusTotal reader (keyed)
# ---------------------------------------------------------------------------

def test_virustotal_parses_report_and_scores(fake_http):
    seen = {}

    def dispatch(url, **kwargs):
        seen['url'] = url
        seen['headers'] = kwargs.get('headers')
        return (True, VT_REPORT, '')

    fake_http.json = dispatch
    out = hash_sources._virustotal(SHA256, 'vt-secret')
    assert seen['url'] == f'https://www.virustotal.com/api/v3/files/{SHA256}'
    assert seen['headers'] == {'x-apikey': 'vt-secret'}
    assert out['reputation'] == -12
    assert out['vt_type'] == 'win32 executable'
    assert out['vt_size'] == 456789
    assert out['vt_meaningful_name'] == 'invoice_2024.exe'
    assert out['vt_magic'] == 'PE32 executable (GUI) Intel 80386'
    assert out['vt_created'] == '2020-02-01'  # epoch 1580515200, UTC
    assert out['malicious'] == 10
    assert out['suspicious'] == 5
    assert out['vt_threat_label'] == 'trojan.emotet/exe'
    assert out['malicious_score'] == 15  # (10 + 5) / 100 engines * 100


def test_virustotal_without_stats_defaults_to_zero(fake_http):
    payload = {'data': {'attributes': {
        'reputation': 0,
        'type_description': 'text/plain',
        'last_analysis_stats': {},
    }}}
    fake_http.json = lambda url, **kw: (True, payload, '')
    out = hash_sources._virustotal(SHA256, 'k')
    assert out['malicious'] == 0
    assert out['suspicious'] == 0
    assert out['malicious_score'] == 0
    assert out['vt_created'] is None
    assert out['vt_threat_label'] is None


@pytest.mark.parametrize('creation_date', [
    'not-a-timestamp', 999999999999999, None, [1, 2],
])
def test_virustotal_bad_creation_date_is_dropped(fake_http, creation_date):
    payload = {'data': {'attributes': {'creation_date': creation_date}}}
    fake_http.json = lambda url, **kw: (True, payload, '')
    out = hash_sources._virustotal(SHA256, 'k')
    assert out['vt_created'] is None


def test_virustotal_http_failure_returns_empty(fake_http):
    fake_http.json = lambda url, **kw: (False, None, 'http 401')
    assert hash_sources._virustotal(SHA256, 'bad-key') == {}
    fake_http.json = lambda url, **kw: (True, {'data': 'oops'}, '')
    assert hash_sources._virustotal(SHA256, 'k') == {}


# ---------------------------------------------------------------------------
# gather_all: merge, provenance, gating
# ---------------------------------------------------------------------------

def test_gather_all_merges_and_injects_identity(monkeypatch):
    monkeypatch.setattr(hash_sources, 'FREE_SOURCES', {
        'alpha': lambda h: {'malware_family': 'A-family', 'file_size': 100},
        'beta': lambda h: {'malware_family': 'B-family', 'file_name': 'b.exe'},
        'broken': lambda h: (_ for _ in ()).throw(RuntimeError('boom')),
        'empty': lambda h: {},
    })
    out = hash_sources.gather_all(SHA256.upper())

    # Registration order wins conflicts.
    assert out['fields']['malware_family'] == 'A-family'
    assert out['fields']['file_name'] == 'b.exe'
    # Provenance records every provider of a field.
    assert out['provenance']['malware_family'] == ['alpha', 'beta']
    assert out['provenance']['file_name'] == ['beta']
    # Identity fields are injected from the request, lowercased.
    assert out['fields']['hash'] == SHA256
    assert out['fields']['algorithm'] == 'sha256'
    assert 'hash' not in out['provenance']
    assert 'algorithm' not in out['provenance']
    # Failure and empty status are reported, never raised.
    assert out['sources']['broken']['ok'] is False
    assert out['sources']['broken']['error'] == 'RuntimeError'
    assert out['sources']['empty']['ok'] is False
    assert out['sources']['empty']['error'] == 'no data'
    assert out['sources']['alpha']['ok'] is True


def test_gather_all_respects_disabled_sources(monkeypatch):
    monkeypatch.setattr(hash_sources, 'FREE_SOURCES', {
        'alpha': lambda h: {'malware_family': 'A'},
        'beta': lambda h: {'file_name': 'b.exe'},
    })
    monkeypatch.setattr(config.app_config, 'disabled_sources', ['beta'])
    out = hash_sources.gather_all(SHA256)
    assert 'beta' not in out['sources']
    assert 'file_name' not in out['fields']
    assert out['fields']['malware_family'] == 'A'


def test_gather_all_skips_virustotal_without_key(monkeypatch):
    monkeypatch.setattr(hash_sources, 'FREE_SOURCES', {})
    monkeypatch.setattr(hash_sources, '_virustotal', lambda h, k: {'malicious': 1})
    out = hash_sources.gather_all(SHA256)
    assert 'virustotal' not in out['sources']
    assert 'malicious' not in out['fields']


def test_gather_all_runs_virustotal_when_key_present(monkeypatch):
    monkeypatch.setattr(hash_sources, 'FREE_SOURCES', {})
    seen = {}

    def fake_virustotal(h, key):
        seen['hash'] = h
        seen['key'] = key
        return {'malicious': 3}

    monkeypatch.setattr(hash_sources, '_virustotal', fake_virustotal)
    out = hash_sources.gather_all(SHA256, {'virustotal': 'secret'})
    assert seen == {'hash': SHA256, 'key': 'secret'}
    assert out['fields']['malicious'] == 3
    assert out['sources']['virustotal']['ok'] is True
    assert out['provenance']['malicious'] == ['virustotal']


def test_gather_all_includes_plugin_sources(monkeypatch):
    monkeypatch.setattr(hash_sources, 'FREE_SOURCES', {})
    monkeypatch.setattr(
        hash_sources, '_plugin_sources',
        lambda kind: {'extra': lambda h: {'plugin_field': 1}} if kind == 'hash' else {})
    out = hash_sources.gather_all(SHA256)
    assert out['sources']['plugin:extra']['ok'] is True
    assert out['fields']['plugin_field'] == 1
    assert out['provenance']['plugin_field'] == ['plugin:extra']


# ---------------------------------------------------------------------------
# HashTracker
# ---------------------------------------------------------------------------

def test_tracker_sources_catalog():
    catalog = HashTracker.sources()
    assert set(catalog) == {'malwarebazaar', 'hashlookup', 'otx', 'virustotal'}
    assert all(isinstance(v, str) and v for v in catalog.values())


def test_tracker_result_shape_and_history(monkeypatch, tmp_env):
    monkeypatch.setattr('obscuralens.trackers.hash_tracker.gather_all',
                        lambda h, keys=None: {
                            'fields': {'malware_family': 'Emotet', 'known_file': False},
                            'sources': {'malwarebazaar': {'ok': True, 'error': ''},
                                        'hashlookup': {'ok': False, 'error': 'no data'}},
                            'provenance': {'malware_family': ['malwarebazaar'],
                                           'known_file': ['hashlookup']},
                        })
    result = HashTracker().track('11' * 32)
    assert result['hash'] == '11' * 32
    assert result['success'] is True
    assert result['sources_ok'] == ['malwarebazaar']
    assert result['sources_failed'] == {'hashlookup': 'no data'}
    assert result['field_sources']['malware_family'] == ['malwarebazaar']
    assert result['field_count'] == 2
    assert result['errors'] == ['1 source(s) unavailable']

    from obscuralens.database import db
    records = db.search_history('11' * 32)
    assert records[0].query_type == 'hash'
    assert records[0].query_value == '11' * 32


def test_tracker_invalid_hash_rejected_without_db_write(monkeypatch, tmp_env):
    calls = []
    monkeypatch.setattr(
        'obscuralens.trackers.hash_tracker.gather_all',
        lambda h, keys=None: calls.append(h) or
        {'fields': {}, 'sources': {}, 'provenance': {}})

    for bad in ('not-a-hash', '0123456789abcdef0123456789abcdef012', ''):
        result = HashTracker().track(bad)
        assert result['success'] is False
        assert 'invalid hash' in result['errors'][0]
        assert result['sources_ok'] == []
        assert result['sources_failed'] == {}
        assert result['field_count'] == 0
        assert result['info'] == {}
    assert calls == []  # gather_all never ran for invalid input

    from obscuralens.database import db
    assert db.search_history('not-a-hash') == []


def test_tracker_invalid_hash_reports_reason(monkeypatch, tmp_env):
    monkeypatch.setattr('obscuralens.trackers.hash_tracker.gather_all',
                        lambda h, keys=None: {'fields': {}, 'sources': {},
                                              'provenance': {}})
    result = HashTracker().track('0123456789abcdef0123456789abcdef012')
    assert 'Unsupported hash length' in result['errors'][0]
    result = HashTracker().track('')
    assert 'empty' in result['errors'][0]


def test_tracker_normalises_hash_case(monkeypatch, tmp_env):
    monkeypatch.setattr('obscuralens.trackers.hash_tracker.gather_all',
                        lambda h, keys=None: {'fields': {}, 'sources': {},
                                              'provenance': {}})
    result = HashTracker().track(SHA256.upper())
    assert result['hash'] == SHA256

    from obscuralens.database import db
    assert db.search_history(SHA256)[0].query_value == SHA256


def test_tracker_full_stack_merge(fake_http, monkeypatch, tmp_env):
    _install_keyless_stack(fake_http, monkeypatch)
    result = HashTracker().track(SHA256)

    assert result['hash'] == SHA256
    assert result['success'] is True
    assert result['sources_ok'] == ['hashlookup', 'malwarebazaar', 'otx']
    assert result['sources_failed'] == {}
    assert result['errors'] == []
    assert result['info']['malware_family'] == 'Emotet'
    assert result['info']['malware_tags'] == ['emotet', 'loader']
    assert result['info']['known_file'] is True
    assert result['info']['hl_file_name'] == 'kernel32.dll'
    assert result['info']['ssdeep'] == '12288:abcdefgh:ijklmnop'
    assert result['info']['otx_pulses'] == 2
    assert result['info']['otx_whitelisted'] is False
    assert result['info']['hash'] == SHA256
    assert result['info']['algorithm'] == 'sha256'
    # Keyless run: VirusTotal is gated off entirely.
    assert 'virustotal' not in result['sources_ok']
    assert 'virustotal' not in result['sources_failed']
    assert result['field_count'] == 23
    assert result['field_sources']['known_file'] == ['hashlookup']


def test_tracker_layers_virustotal_when_key_configured(fake_http, monkeypatch, tmp_env):
    seen = _install_keyless_stack(fake_http, monkeypatch, include_vt=True)
    monkeypatch.setattr(config.api_config, 'virustotal_api_key', 'vt-secret')
    result = HashTracker().track(SHA256)

    assert seen['vt_headers'] == {'x-apikey': 'vt-secret'}
    assert 'virustotal' in result['sources_ok']
    assert result['info']['malicious'] == 10
    assert result['info']['suspicious'] == 5
    assert result['info']['malicious_score'] == 15
    assert result['info']['vt_created'] == '2020-02-01'
    assert result['info']['vt_threat_label'] == 'trojan.emotet/exe'
    assert result['info']['reputation'] == -12

    from obscuralens.database import db
    assert db.search_history(SHA256)[0].query_type == 'hash'


def test_tracker_isolates_raising_source(monkeypatch, tmp_env):
    monkeypatch.setattr(hash_sources, 'FREE_SOURCES', {
        'good': lambda h: {'malware_family': 'Emotet'},
        'broken': lambda h: (_ for _ in ()).throw(RuntimeError('boom')),
    })
    result = HashTracker().track(MD5)
    assert result['success'] is True
    assert result['sources_ok'] == ['good']
    assert result['sources_failed'] == {'broken': 'RuntimeError'}
    assert result['info']['malware_family'] == 'Emotet'
    assert result['errors'] == ['1 source(s) unavailable']


def test_tracker_all_sources_down(monkeypatch, tmp_env):
    monkeypatch.setattr(hash_sources, 'FREE_SOURCES', {
        'empty': lambda h: {},
    })
    result = HashTracker().track(MD5)
    assert result['success'] is False
    assert result['errors'] == ['all data sources failed']
    assert result['field_count'] == 2  # only injected hash/algorithm remain
    assert result['info']['algorithm'] == 'md5'


def test_batch_track_preserves_order(monkeypatch, tmp_env):
    monkeypatch.setattr(hash_sources, 'FREE_SOURCES', {
        'any': lambda h: {'file_name': f'sample-{h[:8]}'},
    })
    results = HashTracker().batch_track(
        [SHA256, MD5, 'not-a-hash', SHA1], workers=4)
    assert [r['hash'] for r in results] == [SHA256, MD5, 'not-a-hash', SHA1]
    assert results[0]['info']['file_name'] == f'sample-{SHA256[:8]}'
    assert results[1]['info']['file_name'] == f'sample-{MD5[:8]}'
    assert results[2]['success'] is False
    assert 'invalid hash' in results[2]['errors'][0]
    assert results[2]['field_count'] == 0
    assert results[3]['success'] is True


def test_batch_track_skips_blank_entries(monkeypatch, tmp_env):
    monkeypatch.setattr(hash_sources, 'FREE_SOURCES', {'any': lambda h: {'seen': True}})
    results = HashTracker().batch_track(['', '   ', MD5, None], workers=2)
    assert len(results) == 1
    assert results[0]['hash'] == MD5
    assert results[0]['info']['seen'] is True


def test_batch_track_empty_input(monkeypatch, tmp_env):
    monkeypatch.setattr(hash_sources, 'FREE_SOURCES', {'any': lambda h: {'seen': True}})
    assert HashTracker().batch_track([]) == []

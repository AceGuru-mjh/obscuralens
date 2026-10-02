"""Experimental package tests: llm_summary, permutations, crawler, phishing.

All offline: HTTP fakes via conftest fixtures plus module-level monkeypatches
(http.post_json, http.get/get_text, UsernameTracker._check_platform,
time.sleep, data pack loaders). No real network calls anywhere.
"""

import time as time_mod
from datetime import datetime, timedelta, timezone

import pytest

from obscuralens.config import config
from obscuralens.experimental import llm_summary
from obscuralens.experimental import phishing_score as ps
from obscuralens.experimental import username_permutations as up
from obscuralens.experimental import web_crawler as wc
from obscuralens.trackers import username_tracker as ut

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

KEYWORDS = ['login', 'verify', 'secure', 'account', 'update', 'confirm',
            'bank', 'password', 'invoice', 'billing']
POPULAR = ['google.com', 'paypal.com', 'microsoft.com']


@pytest.fixture(autouse=True)
def _experimental_defaults(monkeypatch):
    """Every test starts from: experimental ON, LLM unconfigured."""
    monkeypatch.setattr(config.app_config, 'experimental_features', True)
    monkeypatch.setattr(config.app_config, 'llm_base_url', '')
    monkeypatch.setattr(config.app_config, 'llm_model', 'gpt-4o-mini')
    monkeypatch.setattr(config.api_config, 'llm_api_key', '')


@pytest.fixture()
def exp_off(monkeypatch):
    monkeypatch.setattr(config.app_config, 'experimental_features', False)


@pytest.fixture()
def llm_on(monkeypatch):
    monkeypatch.setattr(config.app_config, 'llm_base_url',
                        'https://llm.example.test/v1')
    monkeypatch.setattr(config.app_config, 'llm_model', 'test-model')
    monkeypatch.setattr(config.api_config, 'llm_api_key', 'sk-test')


class _FakePost:
    """Programmable stand-in for http.post_json."""

    def __init__(self):
        self.calls = []
        self.ok = True
        self.err = ''
        self.data = {
            'choices': [{'message': {'content': 'SUMMARY TEXT'}}],
            'usage': {'prompt_tokens': 10, 'completion_tokens': 5,
                      'total_tokens': 15},
        }

    def __call__(self, url, payload=None, **kwargs):
        self.calls.append({'url': url, 'payload': payload, 'kwargs': kwargs})
        return self.ok, self.data, self.err


@pytest.fixture()
def llm_post(monkeypatch):
    from obscuralens.utils import http_client
    fake = _FakePost()
    monkeypatch.setattr(http_client.http, 'post_json', fake)
    return fake


@pytest.fixture()
def packs(monkeypatch):
    """Fake data packs (popular domains + phishing keywords), cache reset."""

    class _FakeDataPacks:
        def load_data_pack(self, name):
            if name == 'popular_domains':
                return list(POPULAR)
            if name == 'phishing_keywords':
                return list(KEYWORDS)
            return []

    monkeypatch.setattr(ps, '_data_packs', _FakeDataPacks())
    ps._reset_cache()
    yield ps
    ps._reset_cache()


@pytest.fixture()
def sleep_log(monkeypatch):
    log = []
    monkeypatch.setattr(time_mod, 'sleep', lambda seconds: log.append(seconds))
    return log


@pytest.fixture()
def patched_check(monkeypatch):
    """Replace UsernameTracker._check_platform with a recording fake."""
    calls = []

    def fake_check(self, platform, username, deep):
        calls.append((platform['name'], username))
        found = username.endswith('123')
        status = 'found' if found else 'not_found'
        return ut.UsernameResult(
            platform=platform['name'], url=platform['url'].format(username),
            exists=found, status=status,
            confidence='high' if found else 'medium',
            reason='fake verdict', status_code=200 if found else 404,
        )

    monkeypatch.setattr(ut.UsernameTracker, '_check_platform', fake_check)
    return calls


# ---------------------------------------------------------------------------
# llm_summary
# ---------------------------------------------------------------------------

def test_compact_payload_target_and_facts():
    payload = {'ip': '8.8.8.8', 'info': {'country': 'US', 'org': 'Google LLC'}}
    text = llm_summary.compact_payload('ip', payload)
    assert text.startswith('Target (ip): 8.8.8.8')
    assert '- country: US' in text
    assert '- org: Google LLC' in text
    assert 'Facts:' in text


def test_compact_payload_caps_lists_at_five():
    payload = {'ip': '1.1.1.1', 'info': {'ports': [1, 2, 3, 4, 5, 6, 7],
                                         'tags': ('a', 'b', 'c', 'd', 'e', 'f')}}
    text = llm_summary.compact_payload('ip', payload)
    assert '1, 2, 3, 4, 5 (+2 more)' in text
    assert 'a, b, c, d, e (+1 more)' in text
    assert '6, 7' not in text.split('(+2 more)')[0]


def test_compact_payload_sources_and_errors_summary():
    payload = {'domain': 'example.com', 'info': {},
               'sources_ok': ['rdap', 'virustotal'],
               'sources_failed': {'ipinfo': 'invalid key'},
               'errors': ['boom']}
    text = llm_summary.compact_payload('domain', payload)
    assert 'Sources OK: rdap, virustotal' in text
    assert 'Sources failed: ipinfo (invalid key)' in text
    assert 'Errors: boom' in text
    assert '(no info fields collected)' in text


def test_compact_payload_truncates_at_max_chars():
    payload = {'ip': '8.8.8.8', 'info': {f'key{i}': 'x' * 80 for i in range(60)}}
    text = llm_summary.compact_payload('ip', payload, max_chars=500)
    assert len(text) <= 500 + len('\n[truncated]')
    assert text.endswith('[truncated]')


@pytest.mark.parametrize('garbage', [None, '', '!!!', 123, [], {}])
def test_compact_payload_garbage_never_raises(garbage):
    text = llm_summary.compact_payload('ip', garbage)
    assert isinstance(text, str)
    assert 'Target' in text


def test_build_messages_roles_and_content():
    messages = llm_summary.build_messages(
        'username', {'username': 'johndoe', 'info': {'bio': 'hi'}})
    assert [m['role'] for m in messages] == ['system', 'user']
    assert 'OSINT analyst assistant' in messages[0]['content']
    assert 'Summary / Key findings / Confidence / Suggested next steps' \
        in messages[0]['content']
    assert 'johndoe' in messages[1]['content']


def test_llm_configured_flag(monkeypatch):
    assert llm_summary.llm_configured() is False
    monkeypatch.setattr(config.app_config, 'llm_base_url', 'https://x.example/v1')
    assert llm_summary.llm_configured() is False
    monkeypatch.setattr(config.api_config, 'llm_api_key', 'sk')
    assert llm_summary.llm_configured() is True
    assert llm_summary.llm_configured(api_key='k') is True


def test_summarize_not_configured_error():
    result = llm_summary.summarize('ip', {'ip': '8.8.8.8'})
    assert result == {'error': 'llm not configured '
                               '(set app.llm_base_url and the llm api key)'}


def test_summarize_success_openai_shape(llm_on, llm_post):
    payload = {'domain': 'example.com', 'info': {'country': 'US'}}
    result = llm_summary.summarize('domain', payload)
    assert result['summary'] == 'SUMMARY TEXT'
    assert result['model'] == 'test-model'
    assert result['chars'] == len('SUMMARY TEXT')
    assert result['usage']['total_tokens'] == 15

    assert len(llm_post.calls) == 1
    call = llm_post.calls[0]
    assert call['url'] == 'https://llm.example.test/v1/chat/completions'
    body = call['payload']
    assert body['model'] == 'test-model'
    assert body['messages'][0]['role'] == 'system'
    assert 'example.com' in body['messages'][1]['content']
    assert body['temperature'] == 0.2
    assert body['max_tokens'] == 700
    assert call['kwargs']['headers']['Authorization'] == 'Bearer sk-test'


def test_summarize_argument_overrides_config(llm_on, llm_post):
    result = llm_summary.summarize('ip', {'ip': '8.8.8.8'},
                                   base_url='https://other.example/v2/',
                                   model='custom-model', api_key='sk-arg')
    assert result['model'] == 'custom-model'
    assert llm_post.calls[0]['url'] == 'https://other.example/v2/chat/completions'
    assert llm_post.calls[0]['payload']['model'] == 'custom-model'
    assert llm_post.calls[0]['kwargs']['headers']['Authorization'] == 'Bearer sk-arg'


def test_summarize_maps_api_error_payload(llm_on, llm_post):
    llm_post.data = {'error': {'message': 'rate limited, slow down'}}
    assert llm_summary.summarize('ip', {}) == {'error': 'rate limited, slow down'}
    llm_post.data = {'error': 'bad request'}
    assert llm_summary.summarize('ip', {}) == {'error': 'bad request'}


def test_summarize_transport_failure(llm_on, llm_post):
    llm_post.ok, llm_post.err = False, 'timeout'
    assert llm_summary.summarize('ip', {}) == {'error': 'llm request failed: timeout'}


def test_summarize_no_content_error(llm_on, llm_post):
    llm_post.data = {'choices': []}
    assert llm_summary.summarize('ip', {}) == {
        'error': 'llm returned no summary content'}
    llm_post.data = {'unexpected': 'shape'}
    assert llm_summary.summarize('ip', {}) == {
        'error': 'llm returned no summary content'}


def test_summarize_experimental_gate_off(exp_off, llm_on, llm_post):
    assert llm_summary.summarize('ip', {}) == {
        'error': 'experimental features disabled'}
    assert llm_post.calls == []


def test_llm_sections_success_and_error(llm_on, llm_post):
    result = llm_summary.summarize('ip', {'ip': '8.8.8.8'})
    sections = llm_summary.llm_sections(result)
    assert sections[0]['type'] == 'text'
    assert sections[0]['content'] == 'SUMMARY TEXT'
    assert sections[1]['type'] == 'grid'
    assert sections[1]['data']['Model'] == 'test-model'
    assert sections[1]['data']['Total tokens'] == 15

    error_sections = llm_summary.llm_sections({'error': 'nope'})
    assert len(error_sections) == 1
    assert error_sections[0]['type'] == 'text'
    assert 'nope' in error_sections[0]['content']
    assert llm_summary.llm_sections(None)[0]['type'] == 'text'


# ---------------------------------------------------------------------------
# username_permutations
# ---------------------------------------------------------------------------

def test_generate_variants_deterministic_and_deduped():
    first = up.generate_variants('johndoe')
    second = up.generate_variants('johndoe')
    assert first == second
    assert len(first) == len(set(first))
    assert first[0] == 'johndoe'          # exact input first, exactly once
    assert first.count('johndoe') == 1


def test_generate_variants_sanitises_input():
    assert up.generate_variants('JohnDoe')[0] == 'johndoe'
    assert up.generate_variants('John Doe')[0] == 'johndoe'    # space stripped
    assert up.generate_variants('  johndoe!!  ')[0] == 'johndoe'
    assert 'JOHNDOE' in up.generate_variants('johndoe')[:3]    # uppercase form
    for variant in up.generate_variants('john.doe-1_x'):
        assert 3 <= len(variant) <= 30
        assert variant == variant.lower() or variant == 'JOHN.DOE-1_X'.upper()


def test_generate_variants_caps():
    assert len(up.generate_variants('johndoe', 3)) == 3
    assert up.generate_variants('johndoe', 0) == []
    assert len(up.generate_variants('johndoe')) == 48  # config default


def test_generate_variants_config_cap(monkeypatch):
    monkeypatch.setattr(config.app_config, 'permutation_max_candidates', 7)
    assert len(up.generate_variants('johndoe')) == 7


def test_generate_variants_contains_expected_families():
    variants = up.generate_variants('johndoe')
    assert 'j0hnd03' in variants           # full leet (a/e/i/o/s at once)
    assert 'j0hnd0e' in variants           # single o -> 0
    assert 'johndoe.' in variants          # bare separator suffix
    assert 'johndoe123' in variants        # numeric suffix
    assert 'johndoe1990' in variants       # birth-year suffix
    assert 'johndoe2025' in variants       # recent-year suffix
    assert 'realjohndoe' in variants       # prefix
    assert 'thejohndoe' in variants
    assert 'johndoejohndoe' not in variants  # doubles sit beyond the 48 cap
    assert 'johndoejohndoe' in up.generate_variants('johndoe', 60)
    assert 'johndoe_official' not in variants  # word suffixes attach bare
    assert '5arah' in up.generate_variants('sarah')  # single s -> 5
    assert '54r4h' in up.generate_variants('sarah')  # full leet


@pytest.mark.parametrize('garbage', [None, '', 'ab', '!!!', 'x' * 40, 123, []])
def test_generate_variants_garbage(garbage):
    assert up.generate_variants(garbage) == []


def test_scan_variants_uses_first_html_platforms(patched_check, sleep_log):
    rows = up.scan_variants(['johndoe'], max_platforms=5)
    platforms = {row['platform'] for row in rows}
    assert platforms == {'GitHub', 'Twitter', 'Instagram', 'LinkedIn', 'Facebook'}
    assert len(rows) == 5
    assert patched_check[0] == ('GitHub', 'johndoe')


def test_scan_variants_rows_and_summary(patched_check, sleep_log):
    rows = up.scan_variants(['johndoe', 'johndoe123', 'JOHNDOE', 'ab'],
                            max_platforms=2)
    # 'ab' invalid, 'JOHNDOE' deduped onto 'johndoe' -> 2 variants x 2 platforms
    assert len(rows) == 4
    hit = [row for row in rows if row['status'] == 'found']
    assert {row['variant'] for row in hit} == {'johndoe123'}
    assert hit[0]['url'] == 'https://github.com/johndoe123'
    assert hit[0]['http_status'] == 200
    miss = [row for row in rows if row['status'] == 'not_found'][0]
    assert miss['reason'] == 'fake verdict'
    assert miss['confidence'] == 'medium'

    summary = up.permutation_summary(rows)
    assert summary == {'scanned': 4, 'found': 2, 'variants_with_hits': 1}


def test_scan_variants_politeness_sleeps(patched_check, sleep_log):
    up.scan_variants(['johndoe', 'johndoe123', 'johndoex'], max_platforms=2)
    assert len(sleep_log) == 5              # 6 requests -> pause between each
    assert all(0.3 < pause < 0.5 for pause in sleep_log)


def test_scan_variants_unknown_maps_to_error(monkeypatch, sleep_log):
    def fake_check(self, platform, username, deep):
        return ut.UsernameResult(
            platform=platform['name'], url=platform['url'].format(username),
            status='unknown', confidence='low',
            reason='http 200 but no profile evidence', status_code=200)

    monkeypatch.setattr(ut.UsernameTracker, '_check_platform', fake_check)
    rows = up.scan_variants(['johndoe'], max_platforms=1)
    assert rows[0]['status'] == 'error'
    assert 'no profile evidence' in rows[0]['reason']


def test_scan_variants_request_cap(patched_check, sleep_log):
    variants = [f'user{i:02d}' for i in range(40)]
    rows = up.scan_variants(variants, max_platforms=5)
    assert len(rows) == 60                  # 60 // 5 = 12 variants x 5 platforms


def test_scan_variants_platforms_by_name(patched_check, sleep_log):
    rows = up.scan_variants(['johndoe'], platforms=['github', 'reddit'])
    assert {row['platform'] for row in rows} == {'GitHub', 'Reddit'}


def test_scan_variants_platforms_as_dicts(patched_check, sleep_log):
    rows = up.scan_variants(['johndoe'],
                            platforms=[{'name': 'FakeBook',
                                        'url': 'https://fake.test/@{}'}])
    assert len(rows) == 1
    assert rows[0]['platform'] == 'FakeBook'
    assert rows[0]['url'] == 'https://fake.test/@johndoe'


def test_scan_variants_plain_status_fallback(fake_http, fake_response, monkeypatch,
                                         sleep_log):
    monkeypatch.setattr(up, '_load_registry',
                        lambda: (None, list(ut.HTML_PLATFORMS[:2])))
    fake_http.get = lambda url, **kw: fake_response(status_code=404, url=url)
    rows = up.scan_variants(['johndoe'], max_platforms=2)
    assert len(rows) == 2
    assert all(row['status'] == 'not_found' for row in rows)
    assert all(row['http_status'] == 404 for row in rows)


def test_scan_variants_experimental_gate_off(exp_off, patched_check):
    assert up.scan_variants(['johndoe']) == {
        'error': 'experimental features disabled'}
    assert patched_check == []


def test_scan_variants_empty_input(patched_check):
    assert up.scan_variants([]) == []
    assert up.scan_variants(None) == []
    assert up.scan_variants(['!!!', 'ab']) == []
    assert patched_check == []


def test_permutation_summary_shapes():
    assert up.permutation_summary([]) == {
        'scanned': 0, 'found': 0, 'variants_with_hits': 0}
    assert up.permutation_summary(None) == {
        'scanned': 0, 'found': 0, 'variants_with_hits': 0}
    rows = [{'variant': 'a', 'status': 'found'},
            {'variant': 'a', 'status': 'not_found'},
            {'variant': 'b', 'status': 'found'},
            'junk']
    assert up.permutation_summary(rows) == {
        'scanned': 3, 'found': 2, 'variants_with_hits': 2}
    assert up.permutation_summary({'results': rows}) == {
        'scanned': 3, 'found': 2, 'variants_with_hits': 2}


# ---------------------------------------------------------------------------
# web_crawler
# ---------------------------------------------------------------------------

SITE_ROBOTS = 'User-agent: *\nDisallow: /private\n'
BASE_HEADERS = {'Server': 'nginx', 'Content-Type': 'text/html',
                'X-Powered-By': 'PHP/7.4'}
HOME_HTML = (
    '<html><head><title>Example Home</title>'
    '<meta name="generator" content="WordPress 6.2"></head>'
    '<body><img src="/wp-content/logo.png">'
    '<a href="/about">About</a>'
    '<a href="/about#team">About team</a>'
    '<a href="https://www.example.test/contact">Contact</a>'
    '<a href="/private/page">Private</a>'
    '<a href="https://external.example.org/x">External</a>'
    '<a href="mailto:admin@example.test">Mail us</a>'
    '<a href="javascript:void(0)">JS</a>'
    'Contact info@example.test or admin@example.test'
    '</body></html>'
)
ABOUT_HTML = ('<html><head><title>About Us</title></head><body>'
              '<a href="/deep/page">Deep</a><a href="/missing">Missing</a>'
              '</body></html>')
CONTACT_HTML = ('<html><head><title>Contact</title></head><body>'
                'cdn-cgi/beacon script</body></html>')
DEEP_HTML = ('<html><head><title>Deep</title></head><body>'
             '<a href="/about?from=deep">Back</a></body></html>')


@pytest.fixture()
def site(monkeypatch, fake_response):
    """Programmable website: pages dict (url -> response spec) + call log."""
    from obscuralens.utils import http_client

    pages = {
        'https://example.test/robots.txt':
            {'status': 200, 'text': SITE_ROBOTS, 'headers': {}},
        'https://example.test/':
            {'status': 200, 'text': HOME_HTML, 'headers': BASE_HEADERS},
        'https://www.example.test/robots.txt':
            {'status': 200, 'text': SITE_ROBOTS, 'headers': {}},
        'https://example.test/about':
            {'status': 200, 'text': ABOUT_HTML, 'headers': BASE_HEADERS},
        'https://www.example.test/contact':
            {'status': 200, 'text': CONTACT_HTML, 'headers': BASE_HEADERS},
        'https://example.test/deep/page':
            {'status': 200, 'text': DEEP_HTML, 'headers': BASE_HEADERS},
        'https://example.test/private/page':
            {'status': 200, 'text': '<html><title>Private</title></html>',
             'headers': {}},
        'https://example.test/missing':
            {'status': 404, 'text': '<html><title>404</title></html>',
             'headers': {}},
        'https://example.test/about?from=deep':
            {'status': 200, 'text': '<html><title>Deep back</title></html>',
             'headers': {}},
    }
    calls = []

    def fake_get(url, **kwargs):
        calls.append(('get', url))
        page = pages.get(url)
        if page is None:
            raise ConnectionError('no such page: ' + url)
        return fake_response(status_code=page['status'], text=page['text'],
                             headers=page.get('headers') or {},
                             url=page.get('final', url))

    def fake_get_text(url, **kwargs):
        calls.append(('get_text', url))
        page = pages.get(url)
        if page is None:
            return False, '', 'not found'
        return True, page['text'], ''

    monkeypatch.setattr(http_client.http, 'get', fake_get)
    monkeypatch.setattr(http_client.http, 'get_text', fake_get_text)
    return {'pages': pages, 'calls': calls}


def test_crawl_collects_pages_links_emails_tech(site):
    report = wc.crawl('https://example.test/', max_depth=2, max_pages=10, delay=0)
    assert report['page_count'] == 5
    assert report['crawled_urls'] == [
        'https://example.test/', 'https://example.test/about',
        'https://www.example.test/contact', 'https://example.test/deep/page',
        'https://example.test/missing',
    ]
    home = report['pages'][0]
    assert home['title'] == 'Example Home'
    assert home['content_type'] == 'text/html'
    assert home['server'] == 'nginx'
    assert home['links'] == ['https://example.test/about',
                             'https://www.example.test/contact',
                             'https://example.test/private/page']
    assert report['emails'] == ['admin@example.test', 'info@example.test']
    assert report['tech_hints'] == ['Cloudflare', 'PHP/7.4', 'WordPress',
                                    'WordPress 6.2']
    assert report['errors'] == []
    assert report['started'].startswith('20')
    assert report['duration_ms'] >= 0
    assert report['link_count'] == 6   # distinct same-host URLs discovered


def test_crawl_same_host_only_and_www_equivalence(site):
    report = wc.crawl('https://example.test/', max_depth=2, max_pages=10, delay=0)
    hosts = {url.split('/')[2] for url in report['crawled_urls']}
    assert hosts == {'example.test', 'www.example.test'}     # www == same host
    assert report['external_domains'] == ['external.example.org']
    external = report['pages'][0]['external_links']
    assert external == ['https://external.example.org/x']
    # Starting from the www host crawls the non-www pages too.
    www_report = wc.crawl('https://www.example.test/contact', max_depth=1,
                          max_pages=5, delay=0)
    assert www_report['page_count'] == 1


def test_crawl_robots_disallow_honored(site):
    report = wc.crawl('https://example.test/', max_depth=2, max_pages=10, delay=0)
    assert report['robots_skipped'] == ['https://example.test/private/page']
    assert 'https://example.test/private/page' not in report['crawled_urls']
    assert report['page_count'] == 5


def test_crawl_robots_wildcard_rules(site):
    site['pages']['https://example.test/robots.txt']['text'] = (
        'User-agent: *\nDisallow: /*/admin\n')
    blocked = wc.crawl('https://example.test/x/admin/panel', max_depth=1,
                       max_pages=5, delay=0)
    assert blocked['robots_skipped'] == ['https://example.test/x/admin/panel']
    assert blocked['page_count'] == 0
    allowed = wc.crawl('https://example.test/about', max_depth=0,
                       max_pages=5, delay=0)
    assert allowed['page_count'] == 1
    assert allowed['robots_skipped'] == []


def test_crawl_robots_disabled_skips_robots_fetch(site):
    report = wc.crawl('https://example.test/', max_depth=1, max_pages=5,
                      delay=0, respect_robots=False)
    assert not [call for call in site['calls'] if call[0] == 'get_text']
    assert 'https://example.test/private/page' in report['crawled_urls']


def test_crawl_depth_cap(site):
    report = wc.crawl('https://example.test/', max_depth=1, max_pages=10, delay=0)
    assert report['crawled_urls'] == ['https://example.test/',
                                      'https://example.test/about',
                                      'https://www.example.test/contact']
    assert 'https://example.test/deep/page' not in report['crawled_urls']


def test_crawl_page_cap(site):
    report = wc.crawl('https://example.test/', max_depth=2, max_pages=3, delay=0)
    assert report['page_count'] == 3
    assert 'https://example.test/deep/page' not in report['crawled_urls']


def test_crawl_config_defaults_used_when_args_none(site, monkeypatch):
    monkeypatch.setattr(config.app_config, 'crawler_max_depth', 1)
    monkeypatch.setattr(config.app_config, 'crawler_max_pages', 2)
    monkeypatch.setattr(config.app_config, 'crawler_delay', 0.0)
    report = wc.crawl('https://example.test/')
    assert report['page_count'] == 2


def test_crawl_error_page_recorded_not_raised(site):
    del site['pages']['https://example.test/about']
    report = wc.crawl('https://example.test/', max_depth=2, max_pages=10, delay=0)
    assert {'url': 'https://example.test/about',
            'error': 'ConnectionError'} in report['errors']
    assert 'https://example.test/about' in report['crawled_urls']
    assert 'https://example.test/about' not in [
        page['url'] for page in report['pages']]
    # the failed page yields no links, so its subtree is never discovered
    assert report['page_count'] == 2   # crawl continues past the failure


def test_crawl_http_error_status_recorded(site):
    report = wc.crawl('https://example.test/', max_depth=2, max_pages=10, delay=0)
    missing = [page for page in report['pages']
               if page['url'] == 'https://example.test/missing'][0]
    assert missing['status'] == 404
    assert missing['title'] == '404'


def test_crawl_keeps_query_drops_fragment_and_skips_mailto(site):
    home = wc.crawl('https://example.test/', max_depth=1, max_pages=2,
                    delay=0)['pages'][0]
    assert 'https://example.test/about#team' not in home['links']  # fragment gone
    assert home['links'].count('https://example.test/about') == 1
    assert 'mailto:admin@example.test' not in home['links']
    deep_report = wc.crawl('https://example.test/deep/page', max_depth=1,
                           max_pages=5, delay=0)
    assert 'https://example.test/about?from=deep' in deep_report['crawled_urls']


def test_crawl_redirect_final_url_recorded(site):
    site['pages']['https://example.test/']['final'] = 'https://example.test/home'
    report = wc.crawl('https://example.test/', max_depth=0, max_pages=1, delay=0)
    assert report['pages'][0]['url'] == 'https://example.test/'
    assert report['pages'][0]['final_url'] == 'https://example.test/home'


def test_crawl_delay_respected(site, sleep_log):
    report = wc.crawl('https://example.test/', max_depth=1, max_pages=5,
                      delay=0.25)
    assert len(sleep_log) == report['page_count'] + len(report['errors'])
    assert len(sleep_log) == 3          # one polite pause per page fetch
    assert all(0.2 <= pause < 0.3 for pause in sleep_log)


def test_crawl_experimental_gate_off(exp_off, site):
    assert wc.crawl('https://example.test/') == {
        'error': 'experimental features disabled'}
    assert site['calls'] == []


@pytest.mark.parametrize('garbage', [None, '', '!!!', 'ftp://example.com/x',
                                      'example.com', 'http://', 123, []])
def test_crawl_garbage_input(garbage):
    report = wc.crawl(garbage)
    assert isinstance(report, dict)
    assert report.get('error')


def test_parse_robots_groups_and_agents():
    text = ('User-agent: badbot\nDisallow: /\n\n'
            'User-agent: *\nDisallow: /private\n')
    assert wc.parse_robots(text) == ['/private']
    specific = ('User-agent: obscuralens\nDisallow: /only-us\n\n'
                'User-agent: *\nDisallow: /private\n')
    assert wc.parse_robots(specific) == ['/only-us', '/private']
    assert wc.parse_robots('User-agent: *\nAllow: /\nDisallow: /private\n') \
        == ['/private']


def test_parse_robots_comments_and_empty_rules():
    text = ('# top comment\nUser-agent: *  # our group\n'
            'Disallow:  # empty means allow\n'
            'Disallow: /private # inline comment\n')
    assert wc.parse_robots(text) == ['/private']


@pytest.mark.parametrize('garbage', [None, '', 'garbage', 42, []])
def test_parse_robots_garbage(garbage):
    assert wc.parse_robots(garbage) == []


def test_crawl_sections_shape(site):
    report = wc.crawl('https://example.test/', max_depth=2, max_pages=10, delay=0)
    sections = wc.crawl_sections(report)
    assert [section['type'] for section in sections] == [
        'grid', 'table', 'table', 'table', 'table']
    assert sections[0]['title'] == 'Crawl Summary'
    assert sections[0]['data']['Pages crawled'] == 5
    assert sections[1]['title'] == 'Pages'
    assert sections[1]['columns'] == ['URL', 'Status', 'Title', 'Links', 'E-mails']
    assert len(sections[1]['rows']) == 5
    assert sections[2]['title'] == 'E-mail Addresses'
    assert sections[3]['title'] == 'Technology Hints'
    assert sections[4]['title'] == 'External Domains'


def test_crawl_sections_error_shape():
    sections = wc.crawl_sections({'error': 'experimental features disabled'})
    assert len(sections) == 1
    assert sections[0]['type'] == 'text'
    assert 'experimental features disabled' in sections[0]['content']
    assert wc.crawl_sections(None)[0]['type'] == 'text'


# ---------------------------------------------------------------------------
# phishing_score
# ---------------------------------------------------------------------------

def test_phishing_benign_google(packs):
    result = ps.score('google.com')
    assert result['score'] == 0
    assert result['verdict'] == 'benign'
    assert result['reasons'] == []
    assert result['signals']['registered_domain'] == 'google.com'


def test_phishing_keyword_host(packs):
    result = ps.score('secure-login.example.com')
    assert result['score'] == 24                     # two keywords x 12
    assert result['verdict'] == 'suspicious'
    keyword_reasons = [r for r in result['reasons'] if r['id'] == 'keyword']
    assert len(keyword_reasons) == 2
    assert all(r['points'] == 12 for r in keyword_reasons)
    assert 'secure' in keyword_reasons[0]['detail']
    assert 'secure-login.example.com' in keyword_reasons[0]['detail']


def test_phishing_keyword_cap_three(packs):
    result = ps.score('login-verify-secure-account-update.example.com')
    keyword_reasons = [r for r in result['reasons'] if r['id'] == 'keyword']
    assert len(keyword_reasons) == 3                 # capped despite 5 matches
    assert sum(r['points'] for r in keyword_reasons) == 36
    assert 'account' in result['signals']['keywords_matched']
    assert 'update' not in result['signals']['keywords_matched']


def test_phishing_typosquat(packs):
    result = ps.score('goggle.com')
    assert result['score'] == 25
    assert result['verdict'] == 'suspicious'
    reason = result['reasons'][0]
    assert reason['id'] == 'typosquat'
    assert reason['points'] == 25
    assert 'google.com' in reason['detail']
    assert result['signals']['typosquat_of'] == 'google.com'
    assert result['signals']['typosquat_distance'] == 1


def test_phishing_brand_token_in_subdomain(packs):
    result = ps.score('paypal.login.example-secure.com')
    brand = [r for r in result['reasons'] if r['id'] == 'brand_token']
    assert len(brand) == 1
    assert brand[0]['points'] == 30
    assert 'paypal' in brand[0]['detail']
    assert 'example-secure.com' in brand[0]['detail']
    assert result['verdict'] == 'likely-phishing'    # 30 + login + secure


def test_phishing_punycode(packs):
    result = ps.score('xn--80ak6aa92e.com')
    reason = [r for r in result['reasons'] if r['id'] == 'punycode'][0]
    assert reason['points'] == 30
    assert 'xn--80ak6aa92e' in reason['detail']
    assert result['score'] >= 30


def test_phishing_ip_host(packs):
    result = ps.score('http://192.168.1.1/login')
    reason = [r for r in result['reasons'] if r['id'] == 'ip_host'][0]
    assert reason['points'] == 20
    assert '192.168.1.1' in reason['detail']
    path_reason = [r for r in result['reasons'] if r['id'] == 'keyword'][0]
    assert "'login' in path" in path_reason['detail']
    assert result['score'] >= 32


def test_phishing_risky_tld(packs):
    result = ps.score('pay.example.top')
    reason = [r for r in result['reasons'] if r['id'] == 'risky_tld'][0]
    assert reason['points'] == 10
    assert '.top' in reason['detail']
    assert result['score'] == 10
    assert result['verdict'] == 'benign'


def test_phishing_double_extension(packs):
    result = ps.score('http://files.example.com/download/invoice.pdf.exe')
    reason = [r for r in result['reasons'] if r['id'] == 'double_extension'][0]
    assert reason['points'] == 35
    assert 'invoice.pdf.exe' in reason['detail']
    assert result['signals']['double_extension'] == 'invoice.pdf.exe'


def test_phishing_userinfo_url(packs):
    result = ps.score('http://google.com@evil.example.net/login')
    reason = [r for r in result['reasons'] if r['id'] == 'userinfo'][0]
    assert reason['points'] == 25
    assert result['signals']['host'] == 'evil.example.net'
    assert result['signals']['has_userinfo'] is True
    # the same trick on a bare-domain target is not scored
    assert 'userinfo' not in [r['id'] for r in ps.score('google.com')['reasons']]


def test_phishing_host_structural_signals(packs):
    url = 'http://a.b.c.d.example.com:8081/https-check'
    result = ps.score(url)
    ids = {r['id']: r for r in result['reasons']}
    assert ids['subdomain_depth']['points'] == 8
    assert ids['odd_port']['points'] == 8
    assert ':8081' in ids['odd_port']['detail']
    assert result['signals']['subdomain_depth'] == 4

    long_host = 'https-secure-' + 'x' * 40 + '.example.com'
    result = ps.score(long_host)
    ids = {r['id']: r for r in result['reasons']}
    assert ids['https_in_host']['points'] == 15
    assert ids['long_host']['points'] == 6

    result = ps.score('http://a-b-c-d-1-2-3.example.com' + '/x' * 50)
    ids = {r['id']: r for r in result['reasons']}
    assert ids['hyphens']['points'] == 8
    assert ids['digits']['points'] == 6
    assert ids['long_url']['points'] == 5


def test_phishing_young_domain_via_fields(packs):
    five_days = (datetime.now(timezone.utc)
                 - timedelta(days=5)).isoformat()
    result = ps.score('example.com', fields={'created': five_days})
    reason = [r for r in result['reasons'] if r['id'] == 'young_domain'][0]
    assert reason['points'] == 10
    assert 'day' in reason['detail']
    assert result['signals']['domain_age_days'] == 5

    old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    assert 'young_domain' not in [
        r['id'] for r in ps.score('example.com', fields={'created': old})['reasons']]


def test_phishing_score_capped_at_100(packs):
    target = ('http://login.verify.paypal.secure-update.bank.'
              'example-secure.xyz:8081/invoice.pdf.exe')
    result = ps.score(target)
    assert result['score'] == 100
    assert result['verdict'] == 'likely-phishing'


def test_phishing_verdict_boundaries(packs):
    assert ps.score('pay.example.top')['verdict'] == 'benign'          # 10
    assert ps.score('goggle.com')['verdict'] == 'suspicious'           # 25
    assert ps.score('paypal.login.example-secure.com')[
        'verdict'] == 'likely-phishing'                                # 54


def test_phishing_score_url_vs_score_domain(packs):
    assert ps.score_url('http://example.com/login') == ps.score(
        'http://example.com/login')
    assert ps.score_domain('example.com') == ps.score('example.com')
    assert ps.score_domain('goggle.com')['signals']['mode'] == 'domain'
    assert ps.score_url('http://example.com/login')['signals']['mode'] == 'url'


def test_phishing_data_pack_caching_and_refresh(monkeypatch):
    state = {'popular_domains': [], 'phishing_keywords': []}

    class _Switchable:
        def load_data_pack(self, name):
            return list(state.get(name, []))

    monkeypatch.setattr(ps, '_data_packs', _Switchable())
    ps._reset_cache()

    # Empty packs are retried on every call (never cached as empty).
    assert ps.score('login.example.com')['reasons'] == []
    state['phishing_keywords'] = ['login']
    assert [r['id'] for r in ps.score('login.example.com')['reasons']] == ['keyword']

    # Non-empty packs are cached: clearing the loader does not clear signals.
    state['phishing_keywords'] = []
    assert [r['id'] for r in ps.score('login.example.com')['reasons']] == ['keyword']
    ps._reset_cache()                                 # explicit refresh only
    assert ps.score('login.example.com')['reasons'] == []


def test_phishing_silent_without_data_packs(monkeypatch):
    monkeypatch.setattr(ps, '_data_packs', None)
    ps._reset_cache()
    result = ps.score('goggle.com')
    assert result['score'] == 0
    assert result['reasons'] == []
    assert ps.score('login.example.com')['score'] == 0
    ps._reset_cache()


def test_phishing_sections(packs):
    result = ps.score('goggle.com')
    sections = ps.phishing_sections(result)
    assert sections[0]['type'] == 'grid'
    assert sections[0]['title'] == 'Phishing Score (experimental)'
    assert sections[0]['data']['Verdict'] == 'suspicious'
    assert sections[0]['data']['Score'] == '25/100'
    assert sections[1]['type'] == 'table'
    assert sections[1]['columns'] == ['Signal', 'Points', 'Detail']
    assert sections[1]['rows'][0][0] == 'typosquat'

    error = ps.phishing_sections({'error': 'no target provided'})
    assert len(error) == 1
    assert error[0]['type'] == 'text'
    assert 'no target provided' in error[0]['content']
    assert ps.phishing_sections(None)[0]['type'] == 'text'


@pytest.mark.parametrize('garbage', ['', None, '!!!', 'http://', 123, [], {}])
def test_phishing_garbage_never_raises(garbage):
    result = ps.score(garbage)
    assert isinstance(result, dict)
    assert result['score'] == 0
    assert result['verdict'] == 'benign'
    assert isinstance(ps.score_url(garbage), dict)
    assert isinstance(ps.score_domain(garbage), dict)
    assert isinstance(ps.phishing_sections(result), list)


# ---------------------------------------------------------------------------
# cross-module: never raise on garbage
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('garbage', ['', None, '!!!', 'http://', 123, [], {}])
def test_all_public_functions_never_raise_on_garbage(garbage, patched_check,
                                                     sleep_log):
    assert isinstance(llm_summary.compact_payload('ip', garbage), str)
    assert [m['role'] for m in llm_summary.build_messages('ip', garbage)] == \
        ['system', 'user']
    assert isinstance(llm_summary.summarize('ip', garbage), dict)  # unconfigured
    assert isinstance(up.generate_variants(garbage), list)
    assert isinstance(up.scan_variants(garbage), (list, dict))
    assert isinstance(up.permutation_summary(garbage), dict)
    assert isinstance(wc.crawl(garbage), dict)
    assert isinstance(wc.crawl_sections(garbage), list)
    assert isinstance(ps.score(garbage), dict)
    assert isinstance(ps.phishing_sections(garbage), list)
    assert isinstance(llm_summary.llm_sections(garbage), list)

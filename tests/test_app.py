"""Software package (app coordinate) source and tracker tests (v6.0 kind).

Covers the five-ecosystem validator (positive examples across
pypi/npm/crate/docker/github, ecosystem-grammar rejections), the offline
``pack_meta`` ecosystem table, every online registry reader mocked through
``fake_http`` (pypi.org, registry.npmjs.org, crates.io with its
descriptive User-Agent, Docker Hub with library-namespace completion,
api.github.com) plus the OSV.dev POST query (the shared client's
``post_json`` is monkeypatched because ``fake_http`` only covers the GET
side), ``gather_all`` ecosystem filtering and provenance semantics, the
tracker envelope and its failure short-circuits (an invalid coordinate
never touches the network), the shipped rule pack through
``evaluate_rules``, and full-platform registration (CLI parser, web kinds,
MCP tool, batch engine, SDK models).

Everything runs offline: HTTP calls are answered by programmable fakes.
"""

import json

import pytest

from obscuralens import commands
from obscuralens.config import config
from obscuralens.trackers import app_sources as asrc
from obscuralens.trackers.app_tracker import AppTracker
from obscuralens.utils.validators import normalize_app, split_app, validate_app

#: Valid coordinates spanning all five ecosystems (registry grammar shapes).
VALID_APPS = (
    'pypi:requests',
    'npm:@babel/core',
    'npm:lodash',
    'crate:serde',
    'docker:library/nginx',
    'docker:bitnami/kafka',
    'github:psf/requests',
)

#: A realistic pypi.org JSON record (the ``info`` block the API fills).
PYPI_RECORD = {
    'info': {
        'name': 'requests',
        'version': '2.32.3',
        'summary': 'Python HTTP for Humans.',
        'author': 'Kenneth Reitz',
        'author_email': 'me@example.com',
        'license': 'Apache-2.0',
        'maintainer': 'Python Software Foundation',
        'requires_python': '>=3.8',
        'home_page': 'pypi:https://requests.readthedocs.io',
    },
}

#: A realistic registry.npmjs.org package document.
NPM_RECORD = {
    'name': 'lodash',
    'description': 'Lodash modular utilities.',
    'dist-tags': {'latest': '4.17.21'},
    'time': {'modified': '2021-02-20T00:00:00Z',
             'created': '2012-04-28T00:00:00Z'},
    'maintainers': [{'name': 'a'}, {'name': 'b'}],
    'versions': {'1.0.0': {}, '2.0.0': {}, '4.17.21': {}},
    'license': 'MIT',
    'readme': 'Lodash documentation.',
}

#: A realistic crates.io API v1 response.
CRATES_RECORD = {
    'crate': {
        'name': 'serde',
        'description': 'A generic serialization/deserialization framework',
        'max_version': '1.0.210',
        'updated_at': '2024-09-05T00:00:00Z',
        'homepage': 'https://serde.rs',
        'repository': 'https://github.com/serde-rs/serde',
        'documentation': 'https://docs.rs/serde',
        'downloads': 250000000,
        'recent_downloads': 8000000,
    },
    'categories': [{'category': 'development-tools'}],
    'keywords': ['serialization'],
}

#: A realistic Docker Hub v2 repository record.
DOCKERHUB_RECORD = {
    'name': 'nginx',
    'description': 'The official nginx image',
    'last_updated': '2024-10-01T00:00:00Z',
    'full_description': 'Deploy nginx, the high-performance web server.',
    'star_count': 20000,
    'pull_count': 1000000000,
}

#: A realistic api.github.com repository record.
GITHUB_RECORD = {
    'full_name': 'psf/requests',
    'description': 'A simple, yet elegant, HTTP library.',
    'language': 'Python',
    'created_at': '2011-02-13T00:00:00Z',
    'pushed_at': '2024-10-10T00:00:00Z',
    'license': {'spdx_id': 'Apache-2.0'},
    'archived': False,
    'topics': ['http', 'client', 'python'],
    'stargazers_count': 52000,
    'forks_count': 9300,
    'open_issues_count': 200,
}

#: A realistic OSV.dev query answer with two advisories.
OSV_RECORD = {
    'vulns': [
        {'id': 'GHSA-9wx4-j9w7-xxxx',
         'summary': 'Cert verification bypass in verify=False flows',
         'severity': [{'score': '7.5'}]},
        {'id': 'PYSEC-0000-0001',
         'summary': 'Cookie leakage on redirect'},
    ],
}


@pytest.fixture(autouse=True)
def _reset_source_health():
    """Keep persisted source-health streaks from leaking between tests."""
    from obscuralens.health import health
    health.reset()
    yield
    health.reset()


@pytest.fixture()
def failing_post(monkeypatch):
    """
    Fail the shared client's ``post_json`` fast.

    ``fake_http`` patches the GET side (get_json/get/fetch) only; the OSV
    reader POSTs, so tests that fan out a pypi/npm/crate gather need the
    POST side faked too or the sandbox network would be touched.
    """
    from obscuralens.utils import http_client
    calls = []

    def _post_json(url, payload=None, **kwargs):
        calls.append((url, payload))
        return False, None, 'not configured'

    monkeypatch.setattr(http_client.http, 'post_json', _post_json)
    return calls


@pytest.fixture()
def offline_app(fake_http, failing_post):
    """fake_http with every online reader failing (offline pack_meta only)."""
    return fake_http


# --------------------------------------------------------------------------- #
# validate_app / normalize_app / split_app
# --------------------------------------------------------------------------- #

class TestValidateApp:

    @pytest.mark.parametrize('app', VALID_APPS)
    def test_ecosystem_examples_validate(self, app):
        ok, error = validate_app(app)
        assert ok is True
        assert error == ''

    def test_missing_ecosystem_prefix_rejected(self):
        for bare in ('requests', 'serde', '@babel/core', 'library/nginx'):
            ok, error = validate_app(bare)
            assert ok is False
            assert 'expected <ecosystem>:<name>' in error
        assert validate_app('')[0] is False
        assert 'cannot be empty' in validate_app('')[1]

    def test_unknown_ecosystem_rejected(self):
        for unknown in ('ruby:rails', 'gem:rails', 'maven:junit', 'go:errors'):
            ok, error = validate_app(unknown)
            assert ok is False
            assert 'ecosystem in pypi/npm/crate/docker/github' in error

    def test_empty_name_rejected(self):
        for empty in ('pypi:', 'pypi:   ', 'docker:'):
            ok, error = validate_app(empty)
            assert ok is False

    def test_npm_grammar_is_lowercase_only(self):
        # npm names must be lower-case (registry convention).
        assert validate_app('npm:Lodash')[0] is False
        assert 'Invalid npm package name' in validate_app('npm:Lodash')[1]
        # Scoped names keep the lower-case @scope/ prefix.
        assert validate_app('npm:@Babel/core')[0] is False
        assert validate_app('npm:@babel/core')[0] is True

    def test_github_requires_owner_slash_repo(self):
        assert validate_app('github:psfrequests')[0] is False
        assert validate_app('github:/requests')[0] is False
        assert validate_app('github:psf/')[0] is False
        assert validate_app('github:psf/requests')[0] is True

    def test_crate_name_length_limit(self):
        assert validate_app('crate:' + 'a' * 64)[0] is True
        ok, error = validate_app('crate:' + 'a' * 65)
        assert ok is False
        assert 'Invalid crate package name' in error

    def test_docker_references_are_lowercase_paths(self):
        assert validate_app('docker:Library/Nginx')[0] is False
        assert validate_app('docker:bitnami/kafka')[0] is True

    def test_normalize_and_split(self):
        # The ecosystem lower-cases; the name keeps its typed casing.
        assert normalize_app('  PYPI:Requests ') == 'pypi:Requests'
        # Docker namespaces and repositories are lowercase-only on the
        # registry, so an upper-case coordinate is invalid, not normalised.
        assert normalize_app('Docker:bitnami/kafka') == 'docker:bitnami/kafka'
        assert normalize_app('Docker:Bitnami/Kafka') == ''
        assert normalize_app('not-a-coordinate') == ''
        assert normalize_app('') == ''
        assert split_app('docker:bitnami/kafka') == ('docker', 'bitnami/kafka')
        assert split_app('PYPI:requests') == ('pypi', 'requests')
        assert split_app('nope') is None
        assert split_app('ruby:rails') is None


# --------------------------------------------------------------------------- #
# offline pack_meta ecosystem table
# --------------------------------------------------------------------------- #

class TestPackMeta:

    def test_pypi_metadata(self):
        out = asrc._pack_meta('pypi:requests')
        assert out['ecosystem'] == 'pypi'
        assert out['ecosystem_label'] == 'Python Package Index'
        assert out['registry_url'] == 'https://pypi.org/pypi/requests/json'
        assert out['package_name'] == 'requests'
        # PyPI has no namespace; the explicit None is the "ran fine" marker.
        assert out['namespace'] is None
        # name_conventions is a human-readable sentence, not a mapping.
        assert 'letters' in out['name_conventions']
        assert out['mirror_notes']

    def test_docker_library_namespace_completion(self):
        out = asrc._pack_meta('docker:nginx')
        assert out['namespace'] == 'library'
        assert out['package_name'] == 'nginx'
        assert out['registry_url'] == \
            'https://hub.docker.com/v2/repositories/library/nginx/'
        scoped = asrc._pack_meta('docker:bitnami/kafka')
        assert scoped['namespace'] == 'bitnami'
        assert scoped['package_name'] == 'kafka'

    def test_github_owner_repo_split(self):
        out = asrc._pack_meta('github:psf/requests')
        assert out['namespace'] == 'psf'
        assert out['package_name'] == 'requests'
        assert out['registry_url'] == \
            'https://api.github.com/repos/psf/requests'

    def test_npm_scope_split(self):
        out = asrc._pack_meta('npm:@babel/core')
        assert out['namespace'] == '@babel'
        assert out['package_name'] == 'core'
        plain = asrc._pack_meta('npm:lodash')
        assert plain['namespace'] is None
        assert plain['package_name'] == 'lodash'

    def test_garbage_returns_empty(self):
        assert asrc._pack_meta('nope') == {}
        assert asrc._pack_meta('') == {}
        assert asrc._pack_meta(None) == {}
        assert asrc._pack_meta(123) == {}


# --------------------------------------------------------------------------- #
# online registry readers (mocked through fake_http / failing_post)
# --------------------------------------------------------------------------- #

class TestAppSources:

    def test_pypi_record_parses(self, fake_http):
        fake_http.json = lambda url, **kwargs: (True, dict(PYPI_RECORD), '')
        out = asrc._pypi('pypi:requests')
        assert out['name'] == 'requests'
        assert out['version'] == '2.32.3'
        assert out['summary'] == 'Python HTTP for Humans.'
        assert out['author'] == 'Kenneth Reitz'
        assert out['author_email'] == 'me@example.com'
        assert out['license'] == 'Apache-2.0'
        assert out['maintainer'] == 'Python Software Foundation'
        assert out['requires_python'] == '>=3.8'
        # The 'pypi:' scheme marker glued onto home_page strings is stripped.
        assert out['homepage'] == 'https://requests.readthedocs.io'
        assert any('pypi.org/pypi/requests/json' in url
                   for _mode, url in fake_http.calls)

    def test_pypi_project_urls_homepage_fallback(self, fake_http):
        payload = {'info': {'name': 'x', 'project_urls': {
            'Homepage': 'https://example.com/x/',
            'Source': 'https://github.com/x/x'}}}
        fake_http.json = lambda url, **kwargs: (True, payload, '')
        out = asrc._pypi('pypi:x')
        assert out['homepage'] == 'https://example.com/x/'

    def test_pypi_malformed_payloads_return_empty(self, fake_http):
        payloads = (
            {},                       # no info block
            {'info': 'nope'},         # info not a dict
            {'info': {}},             # empty info: nothing survives
            {'unexpected': 'shape'},
        )
        for payload in payloads:
            fake_http.json = lambda url, data=payload, **kw: (True, data, '')
            assert asrc._pypi('pypi:requests') == {}
        # A transport failure degrades the same way.
        fake_http.json = lambda url, **kwargs: (False, None, 'connection reset')
        assert asrc._pypi('pypi:requests') == {}

    def test_npm_document_parses(self, fake_http):
        fake_http.json = lambda url, **kwargs: (True, dict(NPM_RECORD), '')
        out = asrc._npm('npm:lodash')
        assert out['name'] == 'lodash'
        assert out['description'] == 'Lodash modular utilities.'
        assert out['latest_version'] == '4.17.21'
        assert out['updated'] == '2021-02-20T00:00:00Z'
        assert out['created'] == '2012-04-28T00:00:00Z'
        assert out['maintainers_count'] == 2
        assert out['versions_count'] == 3
        assert out['license'] == 'MIT'
        assert out['readme'] == 'Lodash documentation.'
        assert any('registry.npmjs.org/lodash' in url
                   for _mode, url in fake_http.calls)
        # Scoped names keep their slash in the registry URL.
        fake_http.calls.clear()
        fake_http.json = lambda url, **kwargs: (True, dict(NPM_RECORD), '')
        asrc._npm('npm:@babel/core')
        assert any('registry.npmjs.org/@babel/core' in url
                   for _mode, url in fake_http.calls)

    def test_npm_malformed_payloads_return_empty(self, fake_http):
        for payload in ({}, {'dist-tags': 'nope'}, {'time': []}):
            fake_http.json = lambda url, data=payload, **kw: (True, data, '')
            assert asrc._npm('npm:lodash') == {}
        fake_http.json = lambda url, **kwargs: (False, None, 'http 404')
        assert asrc._npm('npm:lodash') == {}

    def test_crates_record_parses_with_descriptive_user_agent(self, fake_http):
        captured = {}

        def _json(url, **kwargs):
            captured['url'] = url
            captured['kwargs'] = kwargs
            return True, dict(CRATES_RECORD), ''

        fake_http.json = _json
        out = asrc._crates('crate:serde')
        assert out['name'] == 'serde'
        assert out['latest_version'] == '1.0.210'
        assert out['updated'] == '2024-09-05T00:00:00Z'
        assert out['homepage'] == 'https://serde.rs'
        assert out['repository'] == 'https://github.com/serde-rs/serde'
        assert out['documentation'] == 'https://docs.rs/serde'
        assert out['downloads'] == 250000000
        assert out['recent_downloads'] == 8000000
        assert out['categories'] == ['development-tools']
        assert out['keywords'] == ['serialization']
        # crates.io policy: automated clients identify themselves.
        assert captured['url'] == 'https://crates.io/api/v1/crates/serde'
        headers = captured['kwargs'].get('headers', {})
        assert 'ObscuraLens' in headers.get('User-Agent', '')

    def test_dockerhub_record_parses_with_library_url(self, fake_http):
        fake_http.json = lambda url, **kwargs: (True, dict(DOCKERHUB_RECORD), '')
        out = asrc._dockerhub('docker:nginx')
        assert out['name'] == 'nginx'
        assert out['description'] == 'The official nginx image'
        assert out['updated'] == '2024-10-01T00:00:00Z'
        assert out['readme'] == 'Deploy nginx, the high-performance web server.'
        assert out['stars'] == 20000
        assert out['pulls'] == 1000000000
        # Single-component references resolve under the library namespace.
        assert any('hub.docker.com/v2/repositories/library/nginx/' in url
                   for _mode, url in fake_http.calls)
        fake_http.calls.clear()
        fake_http.json = lambda url, **kwargs: (True, dict(DOCKERHUB_RECORD), '')
        asrc._dockerhub('docker:bitnami/kafka')
        assert any('hub.docker.com/v2/repositories/bitnami/kafka/' in url
                   for _mode, url in fake_http.calls)

    def test_github_record_parses(self, fake_http):
        record = dict(GITHUB_RECORD)
        record['archived'] = True
        fake_http.json = lambda url, **kwargs: (True, record, '')
        out = asrc._github('github:psf/requests')
        assert out['full_name'] == 'psf/requests'
        assert out['description'] == 'A simple, yet elegant, HTTP library.'
        assert out['language'] == 'Python'
        assert out['created'] == '2011-02-13T00:00:00Z'
        assert out['pushed'] == '2024-10-10T00:00:00Z'
        assert out['license'] == 'Apache-2.0'
        assert out['archived'] is True
        assert out['topics_count'] == 3
        assert out['stars'] == 52000
        assert out['forks'] == 9300
        assert out['open_issues'] == 200
        assert any('api.github.com/repos/psf/requests' in url
                   for _mode, url in fake_http.calls)

    def test_github_license_noassertion_filtered(self, fake_http):
        record = dict(GITHUB_RECORD)
        record['license'] = {'spdx_id': 'NOASSERTION'}
        fake_http.json = lambda url, **kwargs: (True, record, '')
        out = asrc._github('github:psf/requests')
        assert 'license' not in out
        # A missing license block stays absent too.
        record['license'] = None
        fake_http.json = lambda url, **kwargs: (True, record, '')
        assert 'license' not in asrc._github('github:psf/requests')

    def test_osv_query_parses(self, monkeypatch):
        from obscuralens.utils import http_client
        calls = []

        def _post_json(url, payload=None, **kwargs):
            calls.append((url, payload))
            return True, dict(OSV_RECORD), ''

        monkeypatch.setattr(http_client.http, 'post_json', _post_json)
        out = asrc._osv('pypi:requests')
        assert out['vulnerabilities_count'] == 2
        assert out['vulnerability_ids'][0]['id'] == 'GHSA-9wx4-j9w7-xxxx'
        assert out['vulnerability_ids'][0]['severity'] == '7.5'
        assert out['vulnerability_ids'][1]['id'] == 'PYSEC-0000-0001'
        # The query carries the package name and OSV's ecosystem spelling.
        assert calls[0][0] == 'https://api.osv.dev/v1/query'
        assert calls[0][1] == {'package': {'name': 'requests',
                                           'ecosystem': 'PyPI'}}

    def test_osv_ecosystem_spellings(self, monkeypatch):
        from obscuralens.utils import http_client
        calls = []

        def _post_json(url, payload=None, **kwargs):
            calls.append((url, payload))
            return True, {'vulns': []}, ''

        monkeypatch.setattr(http_client.http, 'post_json', _post_json)
        asrc._osv('npm:lodash')
        asrc._osv('crate:serde')
        assert calls[0][1]['package']['ecosystem'] == 'npm'
        assert calls[0][1]['package']['name'] == 'lodash'
        assert calls[1][1]['package']['ecosystem'] == 'crates.io'
        assert calls[1][1]['package']['name'] == 'serde'

    def test_osv_caps_records_but_not_the_count(self, monkeypatch):
        from obscuralens.utils import http_client
        record = {'vulns': [{'id': f'GHSA-{i:04d}', 'summary': 's'}
                            for i in range(9)]}
        monkeypatch.setattr(http_client.http, 'post_json',
                            lambda url, payload=None, **kw: (True, record, ''))
        out = asrc._osv('pypi:requests')
        assert out['vulnerabilities_count'] == 9
        assert len(out['vulnerability_ids']) == 5

    def test_osv_failures_and_non_queryable_ecosystems(self, monkeypatch):
        from obscuralens.utils import http_client
        calls = []

        def _post_json(url, payload=None, **kwargs):
            calls.append((url, payload))
            return False, None, 'http 500'

        monkeypatch.setattr(http_client.http, 'post_json', _post_json)
        assert asrc._osv('pypi:requests') == {}      # transport failure
        # A non-dict answer degrades the same way.
        monkeypatch.setattr(http_client.http, 'post_json',
                            lambda url, payload=None, **kw: (True, 'nope', ''))
        assert asrc._osv('pypi:requests') == {}
        calls.clear()   # everything below must not touch the network at all
        # docker and github coordinates are not OSV-queryable by name: the
        # reader answers {} before any POST happens.
        assert asrc._osv('docker:library/nginx') == {}
        assert asrc._osv('github:psf/requests') == {}
        assert calls == []

    def test_wrong_ecosystem_readers_return_empty_without_calls(self, fake_http):
        assert asrc._pypi('npm:lodash') == {}
        assert asrc._npm('pypi:requests') == {}
        assert asrc._crates('pypi:requests') == {}
        assert asrc._dockerhub('github:psf/requests') == {}
        assert asrc._github('docker:nginx') == {}
        assert fake_http.calls == []


# --------------------------------------------------------------------------- #
# gather_all merge semantics
# --------------------------------------------------------------------------- #

class TestAppGather:

    def test_gather_pypi_schedules_meta_pypi_and_osv(self, fake_http,
                                                     failing_post):
        fake_http.json = lambda url, **kwargs: (True, dict(PYPI_RECORD), '')
        out = asrc.gather_all('pypi:requests')
        assert set(out['sources']) == {'pack_meta', 'pypi', 'osv'}
        assert out['sources']['pack_meta']['ok'] is True
        assert out['sources']['pypi']['ok'] is True
        # pack_meta answers even though the (faked) OSV POST failed.
        assert out['sources']['osv']['ok'] is False
        assert out['fields']['app'] == 'pypi:requests'
        assert 'app' not in out['provenance']  # the identifier is not sourced
        assert out['provenance']['ecosystem'] == ['pack_meta']
        assert out['provenance']['version'] == ['pypi']
        assert out['fields']['package_name'] == 'requests'

    def test_gather_docker_schedules_only_dockerhub(self, fake_http,
                                                    failing_post):
        out = asrc.gather_all('docker:library/nginx')
        assert set(out['sources']) == {'pack_meta', 'dockerhub'}
        assert 'osv' not in out['sources']
        assert out['fields']['app'] == 'docker:library/nginx'

    def test_gather_github_runs_github_without_osv(self, fake_http,
                                                    failing_post):
        out = asrc.gather_all('github:psf/requests')
        assert set(out['sources']) == {'pack_meta', 'github'}
        # The ecosystem filter means the other registries are never asked.
        assert 'pypi' not in out['sources']
        assert 'dockerhub' not in out['sources']
        assert out['fields']['registry_url'] == \
            'https://api.github.com/repos/psf/requests'

    def test_gather_offline_meta_carries_the_report(self, offline_app):
        out = asrc.gather_all('crate:serde')
        assert set(out['sources']) == {'pack_meta', 'crates', 'osv'}
        assert out['sources']['pack_meta']['ok'] is True
        assert out['sources']['crates']['ok'] is False
        assert out['fields']['ecosystem'] == 'crate'
        assert out['fields']['ecosystem_label'] == 'crates.io (Rust)'
        assert out['fields']['app'] == 'crate:serde'

    def test_gather_unparseable_raises_valueerror(self):
        with pytest.raises(ValueError):
            asrc.gather_all('requests')
        with pytest.raises(ValueError):
            asrc.gather_all('')
        with pytest.raises(ValueError):
            asrc.gather_all('ruby:rails')

    def test_gather_respects_disabled_sources(self, offline_app, monkeypatch):
        monkeypatch.setattr(config.app_config, 'disabled_sources', ['osv'])
        out = asrc.gather_all('pypi:requests')
        assert 'osv' not in out['sources']
        assert set(out['sources']) == {'pack_meta', 'pypi'}


# --------------------------------------------------------------------------- #
# AppTracker envelope
# --------------------------------------------------------------------------- #

class TestAppTracker:

    def test_track_envelope_and_merged_fields(self, offline_app):
        result = AppTracker().track('pypi:requests')
        assert set(result) == {'app', 'info', 'field_sources', 'sources_ok',
                               'sources_failed', 'field_count', 'success',
                               'errors'}
        assert result['app'] == 'pypi:requests'
        assert result['success'] is True  # offline pack_meta carries it
        assert result['sources_ok'] == ['pack_meta']
        assert set(result['sources_failed']) == {'pypi', 'osv'}
        assert result['field_count'] >= 7
        assert result['info']['app'] == 'pypi:requests'
        assert result['info']['ecosystem'] == 'pypi'
        assert result['field_sources']['ecosystem'] == ['pack_meta']

    def test_track_invalid_short_circuits_without_network(self, fake_http,
                                                          failing_post):
        for bad in ('requests', 'ruby:rails', 'npm:Lodash', ''):
            result = AppTracker().track(bad)
            assert result['success'] is False
            assert result['sources_ok'] == []
            assert result['field_count'] == 0
            assert result['errors']
        assert fake_http.calls == []   # no GET ever left the machine
        assert failing_post == []      # and no POST either

    def test_track_normalises_prefix_case(self, offline_app):
        result = AppTracker().track('  PYPI:Requests ')
        assert result['app'] == 'pypi:Requests'
        assert result['info']['app'] == 'pypi:Requests'
        assert result['info']['ecosystem'] == 'pypi'

    def test_track_writes_query_history(self, offline_app, tmp_env):
        AppTracker().track('pypi:requests')
        from obscuralens.database import db
        record = db.get_query_by_id(
            db.search_history('pypi:requests')[0].id)
        assert record.query_type == 'app'
        assert record.query_value == 'pypi:requests'
        assert record.success is True

    def test_batch_track_preserves_order_and_isolates_failures(self,
                                                               offline_app):
        results = AppTracker().batch_track(
            ['pypi:requests', 'garbage', 'github:psf/requests'])
        assert len(results) == 3
        assert [r['success'] for r in results] == [True, False, True]
        assert results[1]['field_count'] == 0
        assert results[2]['app'] == 'github:psf/requests'

    def test_source_names_and_source_catalog(self):
        tracker = AppTracker()
        assert tracker.source_names() == ['crates', 'dockerhub', 'github',
                                          'npm', 'osv', 'pack_meta', 'pypi']
        catalog = tracker.source_catalog()
        assert set(catalog) == {'pack_meta', 'pypi', 'npm', 'crates',
                                'dockerhub', 'github', 'osv'}
        assert all(catalog.values())  # every source has a description


# --------------------------------------------------------------------------- #
# rule pack
# --------------------------------------------------------------------------- #

class TestAppRules:

    def test_app_pack_loads_with_rules(self):
        from obscuralens.rules import load_pack
        pack = load_pack('app')
        assert pack is not None
        assert pack.kind == 'app'
        assert pack.rule_count >= 10
        assert {rule.id for rule in pack.rules} >= {'APP-001', 'APP-002',
                                                    'APP-011'}

    def test_vulnerability_rule_hits(self):
        from obscuralens.rules import evaluate_rules
        fields = {'ecosystem': 'pypi', 'vulnerabilities_count': 3,
                  'license': 'Apache-2.0', 'description': 'HTTP library'}
        evaluation = evaluate_rules('app', fields)
        assert 'APP-001' in evaluation.matched_ids
        assert evaluation.score >= 30
        assert evaluation.band != 'clean'
        # A clean, licensed, well-documented package hits the positive rule
        # instead (a description is required or APP-007 "no description"
        # legitimately fires -- missing metadata counts as empty).
        clean = evaluate_rules('app', {'ecosystem': 'pypi',
                                       'vulnerabilities_count': 0,
                                       'license': 'MIT',
                                       'description': 'Popular HTTP client'})
        assert 'APP-001' not in clean.matched_ids
        assert 'APP-007' not in clean.matched_ids
        assert 'APP-011' in clean.matched_ids
        assert clean.band == 'clean'

    def test_maintenance_rules_hit(self):
        from datetime import datetime, timedelta, timezone

        from obscuralens.rules import evaluate_rules
        stale = (datetime.now(timezone.utc) - timedelta(days=1000)) \
            .strftime('%Y-%m-%dT%H:%M:%S')
        evaluation = evaluate_rules(
            'app', {'archived': True, 'updated': stale,
                    'recent_downloads': 12, 'stars': 3})
        for rule_id in ('APP-002', 'APP-004', 'APP-005', 'APP-006'):
            assert rule_id in evaluation.matched_ids, rule_id
        # Missing metadata counts as empty for the license/description rules.
        sparse = evaluate_rules('app', {})
        assert 'APP-003' in sparse.matched_ids
        assert 'APP-007' in sparse.matched_ids


# --------------------------------------------------------------------------- #
# platform registration (CLI / web / MCP / batch / SDK)
# --------------------------------------------------------------------------- #

class TestAppRegistration:

    def test_cli_kinds_and_app_subcommand_parse(self, capsys):
        assert 'app' in commands.KINDS
        assert 'app' in commands._VALIDATORS
        assert commands._HANDLERS['app'] is commands._cmd_app
        parser = commands.build_parser()
        args = parser.parse_args(['app', 'pypi:requests'])
        assert args.command == 'app'
        assert args.target == 'pypi:requests'
        # An invalid coordinate is rejected before any tracker runs.
        assert commands.run(['app', 'nope']) == 2
        assert 'Error' in capsys.readouterr().err

    def test_cli_app_json_output(self, monkeypatch, capsys):
        result = {
            'app': 'pypi:requests', 'info': {'ecosystem': 'pypi',
                                             'package_name': 'requests'},
            'field_sources': {'ecosystem': ['pack_meta']},
            'sources_ok': ['pack_meta'], 'sources_failed': {},
            'field_count': 2, 'success': True, 'errors': [],
        }

        class FakeTracker:
            def track(self, target, **kwargs):
                return dict(result)

        monkeypatch.setattr(commands, '_tracker', lambda kind: FakeTracker())
        assert commands.run(['app', 'pypi:requests', '-f', 'json']) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['app'] == 'pypi:requests'
        assert payload['info']['ecosystem'] == 'pypi'

    def test_cli_app_table_output(self, monkeypatch, capsys):
        result = {
            'app': 'pypi:requests',
            'info': {'ecosystem': 'pypi',
                     'ecosystem_label': 'Python Package Index',
                     'package_name': 'requests'},
            'field_sources': {}, 'sources_ok': ['pack_meta'],
            'sources_failed': {}, 'field_count': 3, 'success': True,
            'errors': [],
        }

        class FakeTracker:
            def track(self, target, **kwargs):
                return dict(result)

        monkeypatch.setattr(commands, '_tracker', lambda kind: FakeTracker())
        assert commands.run(['app', 'pypi:requests']) == 0
        out = capsys.readouterr().out
        assert 'Python Package Index' in out
        assert 'IDENTITY' in out.upper()

    def test_web_app_kinds_include_app(self):
        web_app = pytest.importorskip('obscuralens.web.app')
        assert 'app' in web_app.KINDS
        assert 'app' in web_app._VALIDATORS
        assert 'app' in web_app._TRACKERS
        assert web_app._TARGET_KEY['app'] == 'app'
        assert web_app._KIND_INFO['app']['example'] == 'pypi:requests'

    def test_mcp_app_lookup_tool_compacts_result(self, monkeypatch):
        from obscuralens import mcp_server
        from obscuralens.trackers import AppTracker as tracker_class

        result = {
            'app': 'pypi:requests', 'info': {'ecosystem': 'pypi'},
            'field_sources': {'ecosystem': ['pack_meta'],
                              'package_name': ['pack_meta']},
            'sources_ok': ['pack_meta'], 'sources_failed': {},
            'field_count': 2, 'success': True, 'errors': [],
        }
        monkeypatch.setattr(tracker_class, 'track',
                            lambda self, target: dict(result))
        payload = mcp_server.call_tool('app_lookup',
                                       {'app': 'pypi:requests'})
        assert payload['app'] == 'pypi:requests'
        assert payload['success'] is True
        assert payload['provenance_counts'] == {'ecosystem': 1,
                                                'package_name': 1}

        tools = mcp_server.handle_request(
            {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}
        )['result']['tools']
        assert 'app_lookup' in {tool['name'] for tool in tools}
        assert len(tools) == 40

    def test_batch_and_sdk_kinds_include_app(self):
        from obscuralens.advanced.batch import SUPPORTED_KINDS
        from obscuralens.sdk.models import KINDS as SDK_KINDS
        from obscuralens.sdk.models import TARGET_KEYS
        assert 'app' in SUPPORTED_KINDS
        assert 'app' in SDK_KINDS
        assert TARGET_KEYS['app'] == 'app'

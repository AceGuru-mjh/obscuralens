"""
Software package / application intelligence sources (v6.0).

An app coordinate answers "what is this software": ``<ecosystem>:<name>``
where the ecosystem is one of pypi, npm, crate, docker or github. The
ecosystem decides which registries are queried, so a lookup never wastes a
request on a registry that cannot know the name (a ``pypi:`` coordinate
never touches npm). This module mixes one offline metadata source with six
keyless online APIs:

* ``pack_meta``  - offline ecosystem metadata (no data pack, pure built-in
                   table): registry URL template, package-name conventions,
                   known mirror notes, namespace and package name slices,
                   so every report starts with the ground truth of how the
                   ecosystem spells and hosts things.
* ``pypi``       - GET ``pypi.org/pypi/{name}/json``: version, summary,
                   author, license, homepage and Python requirements.
* ``npm``        - GET ``registry.npmjs.org/{name}``: latest version,
                   description, license, maintainers, version count and the
                   last-modified/created timestamps.
* ``crates``     - GET ``crates.io/api/v1/crates/{name}`` with a
                   descriptive User-Agent (crates.io policy): downloads,
                   recent downloads, latest version, repository links,
                   categories and keywords.
* ``dockerhub``  - GET ``hub.docker.com/v2/repositories/{ns}/{repo}/``:
                   star count, pull count, last update and the README.
* ``github``     - GET ``api.github.com/repos/{owner}/{repo}``: stars,
                   forks, issues, language, license, archive state and
                   timestamps.
* ``osv``        - POST ``api.osv.dev/v1/query``: known vulnerabilities for
                   the package (PyPI / npm / crates.io ecosystems; Docker
                   Hub and GitHub coordinates are not OSV-queryable without
                   a digest, so the reader answers {} for them).

Every provider is queried independently; results are merged field-by-field
so a single flaky source cannot blank out the whole report. Field provenance
is tracked: ``gather_all`` returns which source(s) supplied each value, so a
report can show exactly where a fact came from. ``gather_all`` also filters
the task list by ecosystem: only ``pack_meta``, the one matching registry
source and (when applicable) ``osv`` are scheduled - the other registry
readers are not merely failing, they are never asked.
"""

import concurrent.futures as futures
from typing import Any, Dict, List, Optional, Tuple

from ..config import config
from ..health import health
from ..utils.helpers import fanout_workers
from ..utils.http_client import http
from ..utils.validators import split_app

#: Registry-derived strings (descriptions, readmes, summaries) capped for
#: report sanity; registry blobs can run to megabytes.
_MAX_TEXT_CHARS = 400

#: OSV vulnerability records reported per lookup (IDs, summaries and
#: severities only - the full advisory text belongs to the CVE kind).
_MAX_VULN_RECORDS = 5

#: Built-in ecosystem metadata table: ecosystem -> registry description.
#: This is deliberately NOT a data pack: five ecosystems are a compile-time
#: fact of the module, not curated data that grows over time.
_ECOSYSTEM_META: Dict[str, Dict[str, str]] = {
    'pypi': {
        'label': 'Python Package Index',
        'registry': 'https://pypi.org/pypi/{name}/json',
        'conventions': (
            'Package names are letters, digits, dots, underscores and '
            'dashes; the registry resolves names case-insensitively and '
            'treats - and _ as equivalent'),
        'mirrors': (
            'pypi.org is the canonical index; mirrors such as '
            'files.pythonhosted.org host the artifacts themselves'),
    },
    'npm': {
        'label': 'npm registry',
        'registry': 'https://registry.npmjs.org/{name}',
        'conventions': (
            'Package names are lower-case letters, digits, dots, '
            'underscores and dashes, optionally under an @scope/ prefix'),
        'mirrors': (
            'registry.npmjs.org is the canonical registry; mirrors such as '
            'yarnpkg.com proxy it for lockfile resolution'),
    },
    'crate': {
        'label': 'crates.io (Rust)',
        'registry': 'https://crates.io/api/v1/crates/{name}',
        'conventions': (
            'Crate names are up to 64 alphanumerics, dashes and '
            'underscores; the registry treats - and _ as equivalent'),
        'mirrors': (
            'crates.io is the canonical index; static.crates.io hosts the '
            'artifacts and the sparse index lives at index.crates.io'),
    },
    'docker': {
        'label': 'Docker Hub',
        'registry': 'https://hub.docker.com/v2/repositories/{namespace}/{repo}/',
        'conventions': (
            'Image references are lower-case namespace/repo paths; '
            'official images live under the library/ namespace'),
        'mirrors': (
            'hub.docker.com is the canonical registry; quay.io, '
            'ghcr.io and registry.k8s.io are separate registries, not '
            'mirrors of it'),
    },
    'github': {
        'label': 'GitHub repository',
        'registry': 'https://api.github.com/repos/{owner}/{repo}',
        'conventions': (
            'Repository coordinates are owner/repo; owner names allow '
            'alphanumerics and single dashes, repo names also allow dots '
            'and underscores'),
        'mirrors': (
            'api.github.com is the canonical REST endpoint; the GraphQL '
            'endpoint serves the same data for batch queries'),
    },
}

#: Reader name -> the ecosystem it serves. ``gather_all`` schedules exactly
#: one of these per lookup (plus pack_meta and, when applicable, osv).
_ECOSYSTEM_SOURCE: Dict[str, str] = {
    'pypi': 'pypi',
    'npm': 'npm',
    'crate': 'crates',
    'docker': 'dockerhub',
    'github': 'github',
}

#: OSV ecosystem spellings for the package ecosystems OSV can query. Docker
#: Hub is listed because OSV *names* the ecosystem, but image coordinates
#: are only queryable by digest - the reader therefore answers {} for
#: docker and github names (see ``_OSV_QUERYABLE``).
_OSV_ECOSYSTEMS: Dict[str, str] = {
    'pypi': 'PyPI',
    'npm': 'npm',
    'crate': 'crates.io',
    'docker': 'Docker Hub',
}

#: Ecosystems whose plain package names OSV can query by name (the github
#: kind is not an OSV package ecosystem at all and Docker Hub entries are
#: addressed by image digest, which an app coordinate does not carry).
_OSV_QUERYABLE: Tuple[str, ...] = ('pypi', 'npm', 'crate')


# ---------------------------------------------------------------------------
# Small parsing helpers shared by the readers
# ---------------------------------------------------------------------------

def _app_parts(app_value: Any) -> Optional[Tuple[str, str]]:
    """
    Coerce ``'pypi:requests'``, ``'PYPI:Requests'`` or a bare coordinate
    into ``(ecosystem, name)``; ``None`` when unparseable.

    Readers accept the raw tracker input so they stay usable standalone
    (notebooks, plugins, quick shell experiments).
    """
    if not isinstance(app_value, str):
        return None
    return split_app(app_value)


def _clean_text(value: Any, cap: int = _MAX_TEXT_CHARS) -> str:
    """Trimmed string of ``value`` truncated to ``cap`` characters; '' if empty."""
    if not isinstance(value, str):
        return ''
    return value.strip()[:cap]


def _strip_pypi_url_prefix(url: str) -> str:
    """
    Drop the ``'pypi:'`` scheme marker the PyPI JSON API sometimes glues
    onto home-page / project-URL strings before a real URL.
    """
    cleaned = url.strip()
    if cleaned.lower().startswith('pypi:'):
        cleaned = cleaned[5:].strip()
    return cleaned


def _docker_slices(name: str) -> Tuple[str, str]:
    """
    Split a docker reference into ``(namespace, repo)``.

    Single-component references (``nginx``) are Docker Hub official images
    and live under the implicit ``library`` namespace.
    """
    if '/' in name:
        namespace, _, repo = name.rpartition('/')
        return namespace or 'library', repo
    return 'library', name


# ---------------------------------------------------------------------------
# Source readers: each returns a normalised dict, or {} on failure.
# ---------------------------------------------------------------------------

def _pack_meta(app_value: Any) -> Dict[str, Any]:
    """
    Offline ecosystem metadata - the always-available ground truth.

    Derives everything the coordinate itself encodes, no registry involved:

    * ``ecosystem``        - the lower-case ecosystem (pypi/npm/crate/...).
    * ``ecosystem_label``  - human name ("Python Package Index").
    * ``registry_url``     - the registry REST endpoint template, filled
                             with this package's name (informational: the
                             online readers hit the same endpoints).
    * ``namespace``        - docker namespace / github owner / npm @scope,
                             '' when the ecosystem has none.
    * ``package_name``     - the name slice without namespace.
    * ``name_conventions`` - how the ecosystem spells package names.
    * ``mirror_notes``     - which mirrors exist for the ecosystem.
    """
    parts = _app_parts(app_value)
    if parts is None:
        return {}
    ecosystem, name = parts
    meta = _ECOSYSTEM_META[ecosystem]

    namespace = ''
    package_name = name
    registry_url = meta['registry']
    if ecosystem == 'docker':
        namespace, repo = _docker_slices(name)
        package_name = repo
        registry_url = meta['registry'].format(namespace=namespace, repo=repo)
    elif ecosystem == 'github':
        owner, _, repo = name.partition('/')
        namespace = owner
        package_name = repo
        registry_url = meta['registry'].format(owner=owner, repo=repo)
    elif ecosystem == 'npm' and name.startswith('@'):
        scope, _, package = name.partition('/')
        namespace = scope
        package_name = package
        registry_url = meta['registry'].format(name=name)
    else:
        registry_url = meta['registry'].format(name=name)

    out: Dict[str, Any] = {
        'ecosystem': ecosystem,
        'ecosystem_label': meta['label'],
        'registry_url': registry_url,
        'namespace': namespace,
        'package_name': package_name,
        'name_conventions': meta['conventions'],
        'mirror_notes': meta['mirrors'],
    }
    if not namespace:
        # A missing namespace is an EXPECTED outcome for three of the five
        # ecosystems, not a failure: answer with an explicit empty value so
        # source health records the execution as OK while the merge layer
        # drops the field from the report.
        out['namespace'] = None
    return out


def _pypi(app_value: Any) -> Dict[str, Any]:
    """
    pypi.org JSON API (keyless): the canonical PyPI project record.

    Endpoint: ``GET https://pypi.org/pypi/{name}/json``. The response wraps
    the project in ``{'info': {...}, 'releases': {...}}``; the info record
    carries name, version, summary, author, license, homepage and the
    required Python version. Home-page strings sometimes arrive with a
    ``'pypi:'`` marker glued in front of the URL, which is stripped here.
    The API carries no last-updated timestamp, so no ``updated`` field is
    reported for PyPI packages.
    """
    parts = _app_parts(app_value)
    if parts is None or parts[0] != 'pypi':
        return {}
    _ecosystem, name = parts

    ok, data, _err = http.get_json(f"https://pypi.org/pypi/{name}/json")
    if not ok or not isinstance(data, dict):
        return {}
    info = data.get('info')
    if not isinstance(info, dict):
        return {}

    out: Dict[str, Any] = {}
    for api_key, field in (
        ('name', 'name'),
        ('version', 'version'),
        ('summary', 'summary'),
        ('author', 'author'),
        ('author_email', 'author_email'),
        ('license', 'license'),
        ('maintainer', 'maintainer'),
        ('requires_python', 'requires_python'),
    ):
        value = _clean_text(info.get(api_key))
        if value:
            out[field] = value

    for url_field in ('home_page', 'project_url'):
        raw = info.get(url_field)
        if isinstance(raw, str):
            url = _strip_pypi_url_prefix(raw)
            if url:
                out.setdefault('homepage', url[:_MAX_TEXT_CHARS])

    project_urls = info.get('project_urls')
    if isinstance(project_urls, dict):
        for label in ('Homepage', 'Source', 'Source Code', 'Repository'):
            raw = project_urls.get(label)
            if isinstance(raw, str):
                url = _strip_pypi_url_prefix(raw)
                if url:
                    out.setdefault('homepage', url[:_MAX_TEXT_CHARS])
                    break
    return out


def _npm(app_value: Any) -> Dict[str, Any]:
    """
    registry.npmjs.org (keyless): the full npm package document.

    Endpoint: ``GET https://registry.npmjs.org/{name}`` (scoped names keep
    their slash - the registry routes them verbatim). The document carries
    ``dist-tags.latest``, ``time.modified`` / ``time.created``,
    ``maintainers``, the full ``versions`` map, ``license`` and the README.
    Missing packages answer 404, which is a clean "no data" here.
    """
    parts = _app_parts(app_value)
    if parts is None or parts[0] != 'npm':
        return {}
    _ecosystem, name = parts

    ok, data, _err = http.get_json(f"https://registry.npmjs.org/{name}")
    if not ok or not isinstance(data, dict):
        return {}

    out: Dict[str, Any] = {}
    value = _clean_text(data.get('name'))
    if value:
        out['name'] = value
    value = _clean_text(data.get('description'))
    if value:
        out['description'] = value

    dist_tags = data.get('dist-tags')
    if isinstance(dist_tags, dict):
        value = _clean_text(dist_tags.get('latest'))
        if value:
            out['latest_version'] = value

    times = data.get('time')
    if isinstance(times, dict):
        for api_key, field in (('modified', 'updated'), ('created', 'created')):
            value = _clean_text(times.get(api_key))
            if value:
                out[field] = value

    maintainers = data.get('maintainers')
    if isinstance(maintainers, list):
        out['maintainers_count'] = len(maintainers)
    versions = data.get('versions')
    if isinstance(versions, dict):
        out['versions_count'] = len(versions)

    value = _clean_text(data.get('license'))
    if value:
        out['license'] = value
    readme = _clean_text(data.get('readme'))
    if readme:
        out['readme'] = readme
    return out


def _crates(app_value: Any) -> Dict[str, Any]:
    """
    crates.io API v1 (keyless, custom User-Agent): the Rust crate record.

    Endpoint: ``GET https://crates.io/api/v1/crates/{name}``. crates.io
    policy asks automated clients to identify themselves with a contact URL
    in the User-Agent, so this reader sends one (the shared HTTP client
    default stays untouched for every other source). The response carries
    ``crate`` (description, downloads, recent_downloads, max_version,
    updated_at, homepage, repository, documentation) plus ``categories``
    and ``keywords`` lists.
    """
    parts = _app_parts(app_value)
    if parts is None or parts[0] != 'crate':
        return {}
    _ecosystem, name = parts

    headers = {
        'User-Agent': 'ObscuraLens package intelligence '
                      '(https://github.com/AceGuru-mjh/obscuralens)',
    }
    ok, data, _err = http.get_json(
        f"https://crates.io/api/v1/crates/{name}", headers=headers)
    if not ok or not isinstance(data, dict):
        return {}
    crate = data.get('crate')
    if not isinstance(crate, dict):
        return {}

    out: Dict[str, Any] = {}
    for api_key, field in (
        ('name', 'name'),
        ('description', 'description'),
        ('max_version', 'latest_version'),
        ('updated_at', 'updated'),
        ('homepage', 'homepage'),
        ('repository', 'repository'),
        ('documentation', 'documentation'),
    ):
        value = _clean_text(crate.get(api_key))
        if value:
            out[field] = value
    for api_key, field in (
        ('downloads', 'downloads'),
        ('recent_downloads', 'recent_downloads'),
    ):
        raw = crate.get(api_key)
        if isinstance(raw, int) and not isinstance(raw, bool):
            out[field] = raw

    categories = data.get('categories')
    if isinstance(categories, list):
        labels = [_clean_text(c.get('category') if isinstance(c, dict) else c, 40)
                  for c in categories]
        out['categories'] = [label for label in labels if label][:8]
    keywords = data.get('keywords')
    if isinstance(keywords, list):
        labels = [_clean_text(k, 40) for k in keywords]
        out['keywords'] = [label for label in labels if label][:8]
    return out


def _dockerhub(app_value: Any) -> Dict[str, Any]:
    """
    Docker Hub v2 repository API (keyless): the public image record.

    Endpoint: ``GET https://hub.docker.com/v2/repositories/{namespace}/{repo}/``
    (single-component names resolve under the ``library`` namespace, which
    this reader fills in). The record carries name, description, star and
    pull counts, the last update timestamp and the full description
    (README), truncated here for report sanity.
    """
    parts = _app_parts(app_value)
    if parts is None or parts[0] != 'docker':
        return {}
    _ecosystem, name = parts
    namespace, repo = _docker_slices(name)

    ok, data, _err = http.get_json(
        f"https://hub.docker.com/v2/repositories/{namespace}/{repo}/")
    if not ok or not isinstance(data, dict):
        return {}

    out: Dict[str, Any] = {}
    for api_key, field in (
        ('name', 'name'),
        ('description', 'description'),
        ('last_updated', 'updated'),
    ):
        value = _clean_text(data.get(api_key))
        if value:
            out[field] = value
    full = _clean_text(data.get('full_description'))
    if full:
        out['readme'] = full
    for api_key, field in (
        ('star_count', 'stars'),
        ('pull_count', 'pulls'),
    ):
        raw = data.get(api_key)
        if isinstance(raw, int) and not isinstance(raw, bool):
            out[field] = raw
    return out


def _github(app_value: Any) -> Dict[str, Any]:
    """
    GitHub REST API v3 (keyless): the public repository record.

    Endpoint: ``GET https://api.github.com/repos/{owner}/{repo}``. The
    record carries full name, description, stargazers/forks/open-issue
    counts, primary language, license SPDX id, creation and last-push
    timestamps, the archived flag and the repository topic list. Anonymous
    requests are rate limited to 60/hour, which degrades to a clean "no
    data" rather than an error.
    """
    parts = _app_parts(app_value)
    if parts is None or parts[0] != 'github':
        return {}
    _ecosystem, name = parts
    owner, _, repo = name.partition('/')
    if not owner or not repo:
        return {}

    ok, data, _err = http.get_json(
        f"https://api.github.com/repos/{owner}/{repo}")
    if not ok or not isinstance(data, dict):
        return {}

    out: Dict[str, Any] = {}
    for api_key, field in (
        ('full_name', 'full_name'),
        ('description', 'description'),
        ('language', 'language'),
        ('created_at', 'created'),
        ('pushed_at', 'pushed'),
    ):
        value = _clean_text(data.get(api_key))
        if value:
            out[field] = value

    license_block = data.get('license')
    if isinstance(license_block, dict):
        value = _clean_text(license_block.get('spdx_id'))
        if value and value != 'NOASSERTION':
            out['license'] = value

    archived = data.get('archived')
    if isinstance(archived, bool):
        out['archived'] = archived
    topics = data.get('topics')
    if isinstance(topics, list):
        out['topics_count'] = len(topics)
    for api_key, field in (
        ('stargazers_count', 'stars'),
        ('forks_count', 'forks'),
        ('open_issues_count', 'open_issues'),
    ):
        raw = data.get(api_key)
        if isinstance(raw, int) and not isinstance(raw, bool):
            out[field] = raw
    return out


def _osv(app_value: Any) -> Dict[str, Any]:
    """
    OSV.dev vulnerability query (keyless): known CVEs for the package.

    Endpoint: ``POST https://api.osv.dev/v1/query`` with
    ``{"package": {"name": ..., "ecosystem": ...}}`` (a ``version`` key is
    added when one is known; app coordinates carry no version, so the query
    asks for every affected version and reports the total). Only the PyPI,
    npm and crates.io ecosystems are queryable by plain package name: a
    GitHub coordinate is not an OSV package ecosystem and Docker Hub
    entries are addressed by image digest, so this reader answers ``{}``
    for those (``gather_all`` does not even schedule it).
    """
    parts = _app_parts(app_value)
    if parts is None:
        return {}
    ecosystem, name = parts
    if ecosystem not in _OSV_QUERYABLE:
        return {}

    payload = {
        'package': {
            'name': name,
            'ecosystem': _OSV_ECOSYSTEMS[ecosystem],
        },
    }
    ok, data, _err = http.post_json('https://api.osv.dev/v1/query', payload)
    if not ok or not isinstance(data, dict):
        return {}

    vulns = data.get('vulns')
    if not isinstance(vulns, list):
        return {}

    out: Dict[str, Any] = {'vulnerabilities_count': len(vulns)}
    records: List[Dict[str, Any]] = []
    for vuln in vulns[:_MAX_VULN_RECORDS]:
        if not isinstance(vuln, dict):
            continue
        record: Dict[str, Any] = {}
        value = _clean_text(vuln.get('id'), 60)
        if value:
            record['id'] = value
        value = _clean_text(vuln.get('summary'), 120)
        if value:
            record['summary'] = value
        severity_block = vuln.get('severity')
        if isinstance(severity_block, list) and severity_block:
            first = severity_block[0]
            if isinstance(first, dict):
                value = _clean_text(first.get('score'), 60)
                if value:
                    record['severity'] = value
        if record:
            records.append(record)
    if records:
        out['vulnerability_ids'] = records
    return out


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

FREE_SOURCES: Dict[str, Any] = {
    'pack_meta': _pack_meta,
    'pypi': _pypi,
    'npm': _npm,
    'crates': _crates,
    'dockerhub': _dockerhub,
    'github': _github,
    'osv': _osv,
}

# Package intelligence is fully keyless today (GitHub raises its rate limit
# with a token, but the existing 'github' service key covers that use case
# if a future reader wants it); the registry stays here so future keyed
# sources slot in without touching the tracker or the CLI.
KEYED_SOURCES: Dict[str, Any] = {}

# Human-readable metadata used by `obscuralens sources` and the README.
SOURCE_CATALOG = {
    'pack_meta': 'Offline ecosystem metadata: registry URL, name rules, mirrors',
    'pypi': 'pypi.org JSON record: version, summary, author, license (keyless)',
    'npm': 'registry.npmjs.org document: latest version, license, timestamps (keyless)',
    'crates': 'crates.io API: downloads, latest version, categories (keyless)',
    'dockerhub': 'Docker Hub v2 repository record: stars, pulls, README (keyless)',
    'github': 'api.github.com repository record: stars, forks, archive state (keyless)',
    'osv': 'OSV.dev vulnerability query: known CVEs for the package (keyless)',
}


def _keep(value: Any) -> bool:
    # A package with no vulnerabilities (vulnerabilities_count == 0) is a
    # real answer, so only None / '' / [] / {} count as "no data". The
    # pack_meta reader also uses an explicit None value as the "ran fine,
    # no namespace" marker, which this same rule filters out.
    return value is not None and value != '' and value != [] and value != {}


def _plugin_sources(kind: str) -> Dict[str, Any]:
    """Extra sources contributed by user plugins (lazy import avoids cycles)."""
    try:
        from .. import plugins
    except ImportError:
        return {}
    getter = getattr(plugins, 'plugin_sources_named', None) or plugins.plugin_sources
    return getter(kind)


def gather_all(app_value: Any, keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Query every applicable package source in parallel and merge the results.

    The task list is ecosystem-filtered: ``pack_meta`` always runs, exactly
    one registry reader runs (the one matching the coordinate's ecosystem)
    and ``osv`` runs only for the PyPI / npm / crates.io ecosystems. The
    other registry readers are not scheduled at all - a ``pypi:`` lookup
    never asks npm for anything.

    Args:
        app_value: package coordinate such as ``'pypi:requests'``,
            ``'npm:@babel/core'``, ``'crate:serde'``,
            ``'docker:library/nginx'`` or ``'github:owner/repo'``
        keys: optional {service: api_key} map - unused today, accepted for
            interface compatibility with the other source modules

    Returns:
        {
          'fields': merged_field_dict (always includes 'app'),
          'sources': {name: {'ok': bool, 'error': str}},
          'provenance': {field: [source, ...]},
        }

    Raises:
        ValueError: when the value does not parse as an app coordinate.
    """
    keys = keys or {}
    parts = _app_parts(app_value)
    if parts is None:
        raise ValueError(f"invalid app coordinate: {app_value!r}")
    ecosystem, _name = parts
    app = f"{ecosystem}:{_name}"

    tasks: Dict[str, Any] = {}

    applicable = ['pack_meta', _ECOSYSTEM_SOURCE[ecosystem]]
    if ecosystem in _OSV_QUERYABLE:
        applicable.append('osv')

    for name in applicable:
        fn = FREE_SOURCES.get(name)
        if fn and config.is_source_enabled(name) and health.source_allowed(name):
            tasks[name] = (lambda f=fn: f(app))

    for name, fn in _plugin_sources('app').items():
        source_name = f"plugin:{name}"
        if config.is_source_enabled(source_name) and health.source_allowed(source_name):
            tasks[source_name] = (lambda f=fn: f(app))

    results: Dict[str, Dict[str, Any]] = {}
    status: Dict[str, Dict[str, Any]] = {}

    if tasks:
        with futures.ThreadPoolExecutor(max_workers=fanout_workers(len(tasks))) as ex:
            future_map = {ex.submit(fn): name for name, fn in tasks.items()}
            for future in futures.as_completed(future_map):
                name = future_map[future]
                try:
                    data = future.result() or {}
                    results[name] = data
                    status[name] = {'ok': bool(data), 'error': '' if data else 'no data'}
                except Exception as e:  # a broken source must not kill the scan
                    results[name] = {}
                    status[name] = {'ok': False, 'error': type(e).__name__}

    health.record_batch('app', status)

    merged: Dict[str, Any] = {}
    provenance: Dict[str, List[str]] = {}

    # Source order sets priority for conflicting values; earlier wins, so
    # the offline ecosystem metadata beats the online registry records on
    # conflict (they agree by construction, but the point stands).
    for name in tasks:
        for key, value in (results.get(name) or {}).items():
            if not _keep(value):
                continue
            provenance.setdefault(key, []).append(name)
            merged.setdefault(key, value)

    # The identifier itself is part of the answer, whatever the sources did:
    # the canonical <ecosystem>:<name> form every consumer expects.
    merged['app'] = app

    return {'fields': merged, 'sources': status, 'provenance': provenance}

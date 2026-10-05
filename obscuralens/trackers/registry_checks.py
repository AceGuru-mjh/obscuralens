"""
Offline integrity checks for the username platform registry.

The username sweep is the single largest hand-maintained asset in the project:
112 platform entries spread across two registries (101 HTML in
``username_tracker.HTML_PLATFORMS`` + ``username_sources.HTML_PLATFORMS``, and
11 JSON-API specs in ``username_sources.API_PLATFORMS``), plus three satellite
tables keyed by platform name (``EXTRACTORS``, ``HTML_VERDICT_RULES``,
``SOURCE_CATALOG``).

Those tables rot silently. A platform renames its profile path, a 200/404 split
starts answering 200 for everyone, an extractor is left pointing at a platform
that was removed - and the sweep keeps returning confident-looking verdicts
built on a rule that no longer describes the site. Every username checker in
this space has the same failure mode, and the ones that stay trustworthy are
the ones that can *prove* their rules are still shaped correctly.

Live verification of a rule needs the network and a known-good/known-bad
account pair per platform, which cannot run in CI. These checks are the offline
half: they validate everything that is structurally checkable without a single
request - key sets, types, placeholder arity, URL well-formedness, cross-table
referential integrity, name hygiene and callable signatures. Run them in CI and
a malformed or orphaned entry fails the build at the commit that introduced it
instead of degrading verdicts in the field for months.

Everything here is pure stdlib and offline.

Usage::

    from obscuralens.trackers.registry_checks import check_username_registry

    report = check_username_registry()
    report['ok']            # False when any error-severity finding exists
    report['errors']        # [{'check', 'platform', 'message'}, ...]
    report['warnings']
    report['counts']        # {'platforms': 112, 'html': 101, 'api': 11, ...}
"""

import inspect
import re
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

__all__ = [
    'CHECKS',
    'Finding',
    'check_username_registry',
    'registry_entries',
    'satellite_tables',
]

#: Severity that makes :func:`check_username_registry` report ``ok=False``.
ERROR = 'error'
#: Severity for hygiene problems that do not break a lookup.
WARNING = 'warning'

#: The exact key set an HTML platform entry must have.
_HTML_KEYS = frozenset({'name', 'url'})
#: Keys every JSON-API spec must define.
_API_REQUIRED = frozenset({'api_url', 'url', 'verdict', 'extract'})
#: Optional JSON-API spec keys, with the type each must hold.
_API_OPTIONAL: Dict[str, type] = {'err_verdicts': dict,
                                  'verdict_takes_username': bool}
#: An HTML verdict rule is called as ``rule(username, body, low, response)``.
_HTML_RULE_PARAMS = ('username', 'body', 'low', 'response')

_NAME_RE = re.compile(r'^\S(?:.*\S)?$')
_DOUBLE_SPACE = re.compile(r'\s\s+')

Finding = Dict[str, str]


# --------------------------------------------------------------------------- #
# registry access
# --------------------------------------------------------------------------- #

def registry_entries() -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, Any]]]:
    """
    The username registries as the tracker actually sees them.

    Returns:
        ``(html, api)`` where *html* is the union the tracker builds at import
        time (its own table plus the extra one in ``username_sources``, in that
        order) and *api* is ``API_PLATFORMS``.  Importing through the tracker
        rather than re-deriving the union keeps this honest about what runs.
    """
    from . import username_sources as sources
    from . import username_tracker as tracker

    html = list(tracker.HTML_PLATFORMS) + list(sources.HTML_PLATFORMS)
    return html, dict(sources.API_PLATFORMS)


#: Names of the satellite tables keyed by platform name.
TABLE_NAMES = ('EXTRACTORS', 'HTML_VERDICT_RULES', 'SOURCE_CATALOG')


def satellite_tables() -> Dict[str, Dict[str, Any]]:
    """
    Snapshots of the platform-keyed satellite tables.

    Returned as a dict of dicts so a caller (or a test) can substitute a
    synthetic set without monkeypatching ``username_sources``.
    """
    from . import username_sources as sources

    return {name: dict(getattr(sources, name)) for name in TABLE_NAMES}


def _finding(check: str, severity: str, platform: str, message: str) -> Finding:
    return {'check': check, 'severity': severity,
            'platform': platform, 'message': message}


def _is_url_template(value: Any) -> bool:
    """A str holding exactly one ``{}`` username placeholder."""
    return isinstance(value, str) and value.count('{}') == 1


def _callable_or_template(value: Any) -> bool:
    """API specs may build their URL with a function instead of a template."""
    return callable(value) or _is_url_template(value)


# --------------------------------------------------------------------------- #
# individual checks
# --------------------------------------------------------------------------- #
# Each takes the registries and returns findings, so a single check can be
# exercised in isolation and new checks can be appended to CHECKS without
# touching the runner.

def check_html_entry_shape(html: List[Dict[str, Any]],
                           api: Dict[str, Any],
                           tables: Dict[str, Dict[str, Any]]) -> List[Finding]:
    """HTML entries carry exactly ``name`` and ``url``, both non-empty strings."""
    out: List[Finding] = []
    for position, entry in enumerate(html):
        label = str(entry.get('name') or f'<entry #{position}>') if isinstance(entry, dict) \
            else f'<entry #{position}>'
        if not isinstance(entry, dict):
            out.append(_finding('html_entry_shape', ERROR, label,
                                f'entry is a {type(entry).__name__}, not a dict'))
            continue
        keys = set(entry)
        if keys != _HTML_KEYS:
            missing = sorted(_HTML_KEYS - keys)
            unexpected = sorted(keys - _HTML_KEYS)
            detail = []
            if missing:
                detail.append(f'missing {missing}')
            if unexpected:
                detail.append(f'unexpected {unexpected}')
            out.append(_finding('html_entry_shape', ERROR, label,
                                '; '.join(detail)))
            continue
        for key in ('name', 'url'):
            value = entry.get(key)
            if not isinstance(value, str) or not value.strip():
                out.append(_finding('html_entry_shape', ERROR, label,
                                    f'{key} must be a non-empty string, '
                                    f'got {value!r}'))
    return out


def check_name_hygiene(html: List[Dict[str, Any]],
                       api: Dict[str, Any],
                       tables: Dict[str, Dict[str, Any]]) -> List[Finding]:
    """Platform names are used as dict keys and displayed verbatim."""
    out: List[Finding] = []
    for name in _all_names(html, api):
        if not isinstance(name, str):
            out.append(_finding('name_hygiene', ERROR, repr(name),
                                f'name is a {type(name).__name__}, not a str'))
            continue
        if name != name.strip():
            out.append(_finding('name_hygiene', WARNING, repr(name),
                                'name has leading or trailing whitespace'))
        elif _DOUBLE_SPACE.search(name):
            out.append(_finding('name_hygiene', WARNING, name,
                                'name contains a run of whitespace'))
        elif not _NAME_RE.match(name):
            out.append(_finding('name_hygiene', WARNING, repr(name),
                                'name is empty or whitespace-only'))
    return out


def check_duplicates(html: List[Dict[str, Any]],
                     api: Dict[str, Any],
                     tables: Dict[str, Dict[str, Any]]) -> List[Finding]:
    """
    No platform may be registered twice.

    The tracker unions the two HTML tables and then layers the API registry on
    top, so a duplicate means one entry silently shadows the other - the sweep
    reports one platform while two rules compete. Case-insensitive collisions
    are reported as warnings, since they are usually a re-registration rather
    than a genuinely distinct platform.
    """
    out: List[Finding] = []
    names: List[str] = []
    for entry in html:
        if isinstance(entry, dict) and isinstance(entry.get('name'), str):
            names.append(entry['name'])
    names.extend(api)

    seen: Dict[str, int] = {}
    for name in names:
        seen[name] = seen.get(name, 0) + 1
    for name, count in sorted(seen.items()):
        if count > 1:
            out.append(_finding('duplicates', ERROR, name,
                                f'registered {count} times'))

    lowered: Dict[str, List[str]] = {}
    for name in dict.fromkeys(names):
        lowered.setdefault(name.strip().lower(), []).append(name)
    for key, variants in sorted(lowered.items()):
        if len(variants) > 1:
            out.append(_finding('duplicates', WARNING, ', '.join(variants),
                                'names differ only by case or whitespace '
                                f'(all map to {key!r})'))
    return out


def check_url_templates(html: List[Dict[str, Any]],
                        api: Dict[str, Any],
                        tables: Dict[str, Dict[str, Any]]) -> List[Finding]:
    """Every profile URL is an http(s) template with exactly one placeholder.

    HTML entries must carry a plain string template. JSON-API specs may build
    either URL with a callable instead (Bluesky resolves its handle first), so
    a callable is accepted there and checked by
    :func:`check_api_spec_shape` / :func:`check_callable_values`.
    """
    out: List[Finding] = []
    # (platform, field, value, callable_allowed)
    targets: List[Tuple[str, str, Any, bool]] = []
    for entry in html:
        if isinstance(entry, dict):
            targets.append((str(entry.get('name') or '?'), 'url',
                            entry.get('url'), False))
    for name, spec in api.items():
        if isinstance(spec, dict):
            targets.append((name, 'url', spec.get('url'), True))
            targets.append((name, 'api_url', spec.get('api_url'), True))

    for platform, field, value, callable_allowed in targets:
        if callable(value):
            if callable_allowed:
                continue
            out.append(_finding('url_templates', ERROR, platform,
                                f'{field} must be a str template for an HTML '
                                'platform, got a callable'))
            continue
        if not isinstance(value, str):
            out.append(_finding('url_templates', ERROR, platform,
                                f'{field} must be a str or a callable, '
                                f'got {type(value).__name__}'))
            continue
        count = value.count('{}')
        if count != 1:
            out.append(_finding('url_templates', ERROR, platform,
                                f'{field} must contain exactly one {{}} '
                                f'placeholder, found {count}: {value}'))
            continue
        parsed = urlparse(value.replace('{}', 'placeholder'))
        if parsed.scheme not in ('http', 'https'):
            out.append(_finding('url_templates', ERROR, platform,
                                f'{field} scheme must be http or https, '
                                f'got {parsed.scheme!r}: {value}'))
        elif not parsed.netloc:
            out.append(_finding('url_templates', ERROR, platform,
                                f'{field} has no host: {value}'))
        elif '.' not in parsed.netloc:
            out.append(_finding('url_templates', WARNING, platform,
                                f'{field} host {parsed.netloc!r} has no dot'))
    return out


def check_duplicate_urls(html: List[Dict[str, Any]],
                         api: Dict[str, Any],
                         tables: Dict[str, Dict[str, Any]]) -> List[Finding]:
    """Two platforms sharing a profile URL means one of them is wrong."""
    out: List[Finding] = []
    owners: Dict[str, List[str]] = {}
    for entry in html:
        if isinstance(entry, dict) and isinstance(entry.get('url'), str):
            owners.setdefault(entry['url'], []).append(str(entry.get('name')))
    for name, spec in api.items():
        if isinstance(spec, dict) and isinstance(spec.get('url'), str):
            owners.setdefault(spec['url'], []).append(name)
    for url, platforms in sorted(owners.items()):
        if len(platforms) > 1:
            out.append(_finding('duplicate_urls', ERROR, ', '.join(platforms),
                                f'share the profile URL {url}'))
    return out


def check_api_spec_shape(html: List[Dict[str, Any]],
                         api: Dict[str, Any],
                         tables: Dict[str, Dict[str, Any]]) -> List[Finding]:
    """JSON-API specs define the required keys with usable values."""
    out: List[Finding] = []
    for name, spec in api.items():
        if not isinstance(spec, dict):
            out.append(_finding('api_spec_shape', ERROR, name,
                                f'spec is a {type(spec).__name__}, not a dict'))
            continue
        keys = set(spec)
        missing = sorted(_API_REQUIRED - keys)
        if missing:
            out.append(_finding('api_spec_shape', ERROR, name,
                                f'spec is missing required key(s) {missing}'))
        unknown = sorted(keys - _API_REQUIRED - set(_API_OPTIONAL))
        if unknown:
            out.append(_finding('api_spec_shape', WARNING, name,
                                f'spec has unrecognised key(s) {unknown}; '
                                'the loader ignores them'))
        for key, expected in _API_OPTIONAL.items():
            if key in spec and not isinstance(spec[key], expected):
                out.append(_finding('api_spec_shape', ERROR, name,
                                    f'{key} must be a '
                                    f'{expected.__name__}, got '
                                    f'{type(spec[key]).__name__}'))
        for key in ('verdict', 'extract'):
            value = spec.get(key)
            if key in spec and not callable(value):
                out.append(_finding('api_spec_shape', ERROR, name,
                                    f'{key} must be callable, got '
                                    f'{type(value).__name__}'))
        err_verdicts = spec.get('err_verdicts')
        if isinstance(err_verdicts, dict):
            # username_tracker consults this with `err_map.get(err) is False`,
            # an identity test: only an explicit False does anything. A truthy
            # or non-bool value is silently dead config, so a non-bool is an
            # error (almost certainly a typo for False) and a True is a warning.
            for key, value in err_verdicts.items():
                if not isinstance(key, str):
                    out.append(_finding(
                        'api_spec_shape', ERROR, name,
                        f'err_verdicts keys must be the transport-error str '
                        f'the client returns; {key!r} is a '
                        f'{type(key).__name__}'))
                elif not isinstance(value, bool):
                    out.append(_finding(
                        'api_spec_shape', ERROR, name,
                        f'err_verdicts[{key!r}] must be a bool, got '
                        f'{type(value).__name__} ({value!r}); the tracker '
                        'compares with `is False`, so this entry is inert'))
                elif value is True:
                    out.append(_finding(
                        'api_spec_shape', WARNING, name,
                        f'err_verdicts[{key!r}] is True, which the tracker '
                        'ignores - only False declares an error as a miss'))
    return out


def check_cross_references(html: List[Dict[str, Any]],
                           api: Dict[str, Any],
                           tables: Dict[str, Dict[str, Any]]) -> List[Finding]:
    """
    Satellite tables must not reference a platform that is not registered.

    An orphaned ``EXTRACTORS`` / ``HTML_VERDICT_RULES`` / ``SOURCE_CATALOG``
    key is the signature of a platform that was renamed or removed without
    cleaning up after it: the entry is dead code, and if the platform still
    exists under a new name the rule silently stopped applying.
    """
    registered = set(_all_names(html, api))
    out: List[Finding] = []
    for table in TABLE_NAMES:
        for key in tables.get(table, {}):
            if key not in registered:
                out.append(_finding('cross_references', ERROR, str(key),
                                    f'{table} references a platform that is '
                                    'not in the HTML or API registry'))
    return out


def check_callable_values(html: List[Dict[str, Any]],
                          api: Dict[str, Any],
                          tables: Dict[str, Dict[str, Any]]) -> List[Finding]:
    """Extractors and HTML verdict rules are callable with the expected arity."""
    out: List[Finding] = []
    for name, function in tables.get('EXTRACTORS', {}).items():
        if not callable(function):
            out.append(_finding('callable_values', ERROR, str(name),
                                'EXTRACTORS value is not callable'))
    for name, rule in tables.get('HTML_VERDICT_RULES', {}).items():
        if not callable(rule):
            out.append(_finding('callable_values', ERROR, str(name),
                                'HTML_VERDICT_RULES value is not callable'))
            continue
        problem = _signature_problem(rule, _HTML_RULE_PARAMS)
        if problem:
            out.append(_finding('callable_values', ERROR, str(name),
                                f'HTML verdict rule {problem}'))
    for name, spec in api.items():
        if not isinstance(spec, dict):
            continue
        for key in ('verdict', 'extract'):
            function = spec.get(key)
            if callable(function):
                problem = _signature_problem(function, ('data',))
                if problem:
                    out.append(_finding('callable_values', WARNING, name,
                                        f'API {key} {problem}'))
    return out


def _signature_problem(function: Callable[..., Any],
                       expected: Tuple[str, ...]) -> Optional[str]:
    """
    Why *function* cannot be called with *expected* positional names, or None.

    Only a genuine mismatch is reported: ``*args``-style signatures and
    signatures with defaults accept the call, so they are fine. Builtins and
    C callables without introspectable signatures are skipped rather than
    guessed at.
    """
    try:
        signature = inspect.signature(function)
    except (TypeError, ValueError):
        return None
    accepts_var_positional = any(
        p.kind is inspect.Parameter.VAR_POSITIONAL
        for p in signature.parameters.values())
    if accepts_var_positional:
        return None
    positional = [
        p for p in signature.parameters.values()
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY,
                      inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    required = [p for p in positional if p.default is inspect.Parameter.empty]
    if len(required) > len(expected):
        names = ', '.join(p.name for p in required)
        return (f'requires {len(required)} positional argument(s) ({names}) '
                f'but is called with {len(expected)}')
    if len(positional) < len(expected):
        return (f'accepts {len(positional)} positional argument(s) but is '
                f'called with {len(expected)}')
    return None


def check_source_catalog_coverage(html: List[Dict[str, Any]],
                                  api: Dict[str, Any],
                                  tables: Dict[str, Dict[str, Any]]) -> List[Finding]:
    """
    Report on ``SOURCE_CATALOG`` coverage as a warning, never an error.

    The catalog is documented as human-readable metadata for a subset of
    platforms, so partial coverage is by design; the count is surfaced so a
    shrinking catalog is visible rather than silent.
    """
    registered = list(dict.fromkeys(_all_names(html, api)))
    catalog = tables.get('SOURCE_CATALOG', {})
    covered = [name for name in registered if name in catalog]
    total = len(registered)
    if total and len(covered) * 2 < total:
        return [_finding('source_catalog_coverage', WARNING, '',
                         f'SOURCE_CATALOG describes {len(covered)} of {total} '
                         'registered platforms')]
    return []


def _all_names(html: List[Dict[str, Any]],
               api: Dict[str, Any]) -> List[str]:
    """Every registered platform name, HTML tables first, in order."""
    names: List[Any] = [entry.get('name') for entry in html
                        if isinstance(entry, dict)]
    names.extend(api)
    return [name for name in names if name is not None]


#: The checks :func:`check_username_registry` runs, in report order.  Each is
#: ``(html, api, tables) -> findings`` so it can be exercised in isolation.
CHECKS: Tuple[Callable[..., List[Finding]], ...] = (
    check_html_entry_shape,
    check_name_hygiene,
    check_duplicates,
    check_url_templates,
    check_duplicate_urls,
    check_api_spec_shape,
    check_cross_references,
    check_callable_values,
    check_source_catalog_coverage,
)


# --------------------------------------------------------------------------- #
# runner
# --------------------------------------------------------------------------- #

def check_username_registry(
        html: Optional[List[Dict[str, Any]]] = None,
        api: Optional[Dict[str, Any]] = None,
        tables: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Validate the username platform registry offline.

    Args:
        html: HTML platform entries; defaults to the union the tracker builds.
        api: JSON-API specs; defaults to ``username_sources.API_PLATFORMS``.
        tables: the platform-keyed satellite tables; defaults to
            :func:`satellite_tables`.  All three are injectable so a synthetic
            registry can be checked without monkeypatching the real one.

    Returns:
        ``{'ok': bool, 'errors': [...], 'warnings': [...], 'findings': [...],
        'counts': {...}}`` where each finding is
        ``{'check', 'severity', 'platform', 'message'}``. ``ok`` is False only
        when at least one error-severity finding exists; warnings are hygiene
        notes that never fail a build.
    """
    if html is None or api is None:
        live_html, live_api = registry_entries()
        html = live_html if html is None else html
        api = live_api if api is None else api
    if tables is None:
        tables = satellite_tables()

    findings: List[Finding] = []
    for check in CHECKS:
        try:
            findings.extend(check(html, api, tables))
        except Exception as exc:  # a broken check must not hide the others
            findings.append(_finding(check.__name__, ERROR, '',
                                     f'check raised {type(exc).__name__}: {exc}'))

    errors = [f for f in findings if f['severity'] == ERROR]
    warnings = [f for f in findings if f['severity'] == WARNING]
    names = list(dict.fromkeys(_all_names(html, api)))
    return {
        'ok': not errors,
        'errors': errors,
        'warnings': warnings,
        'findings': findings,
        'counts': {
            'platforms': len(names),
            'html_entries': len(html),
            'api_entries': len(api),
            'errors': len(errors),
            'warnings': len(warnings),
            'checks_run': len(CHECKS),
        },
    }

"""
CVE (Common Vulnerabilities and Exposures) intelligence sources.

Every provider is queried independently and results are merged field-by-field
so a single flaky source cannot blank out the whole report. All four sources
are keyless:

* ``nvd``        - NVD 2.0 REST API: description, CVSS, CWE, references, CPEs.
                   An optional NVD API key (config service ``nvd``) raises the
                   rate limit but is never required.
* ``osv``        - Google OSV.dev: package-level impact and severity vectors.
* ``cvelist``  - The CVEProject cvelistV5 GitHub repository (raw JSON),
                   i.e. the authoritative CNA-published record.
* ``epss``       - FIRST.org EPSS: probability the vuln is exploited soon.

Field provenance is tracked: ``gather_all`` returns which source(s) supplied
each value, so a report can show exactly where a fact came from.
"""

import concurrent.futures as futures
from typing import Any, Dict, List, Optional

from ..config import config
from ..health import health
from ..utils.http_client import http
from ..utils.validators import normalize_cve

# Caps keep merged payloads small even for monster CVEs (Log4Shell-class
# records carry hundreds of references and CPE criteria).
_MAX_REFERENCES = 15
_MAX_CPES = 15
_MAX_PACKAGES = 15
_MAX_PRODUCTS = 15
_MAX_DESCRIPTION_CHARS = 500

# Metric families in quality order: V3.1 beats V3.0 beats V2.
_NVD_METRIC_KEYS = ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2')


# ---------------------------------------------------------------------------
# Small parsing helpers shared by the readers
# ---------------------------------------------------------------------------

def _clean_id(cve_id: str) -> str:
    """Best-effort uppercase of a CVE id for URL interpolation."""
    return (cve_id or '').strip().upper()


def _english_value(entries: Optional[List[Dict[str, Any]]]) -> Optional[str]:
    """
    Return the ``value`` of the first ``lang == 'en'`` entry.

    NVD, OSV and cvelist all describe things in many languages; only the
    English text is kept so reports stay readable.
    """
    for entry in entries or []:
        if isinstance(entry, dict) and entry.get('lang') == 'en':
            value = entry.get('value')
            if value:
                return value
    return None


def _best_cvss(metrics: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Pick the highest-quality CVSS metric from an NVD ``metrics`` block.

    Preference order: cvssMetricV31 > cvssMetricV30 > cvssMetricV2. CVSS v2
    records keep ``baseSeverity`` on the metric entry rather than inside
    ``cvssData``, so both locations are honoured.
    """
    for key in _NVD_METRIC_KEYS:
        entries = (metrics or {}).get(key) or []
        if not entries:
            continue
        entry = entries[0] if isinstance(entries[0], dict) else {}
        data = entry.get('cvssData') or {}
        severity = data.get('baseSeverity') or entry.get('baseSeverity')
        return {
            'cvss_score': data.get('baseScore'),
            'cvss_severity': severity,
            'cvss_vector': data.get('vectorString'),
            'cvss_version': data.get('version'),
        }
    return {}


# ---------------------------------------------------------------------------
# Source readers: each returns a normalised dict, or {} on failure.
# ---------------------------------------------------------------------------

def _nvd(cve_id: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    NVD 2.0 REST API (keyless; optional key for higher rate limits).

    Endpoint: ``GET /rest/json/cves/2.0?cveId=<id>`` with an ``apiKey``
    header when a key is configured for the ``nvd`` service.
    """
    cve_id = _clean_id(cve_id)
    if not cve_id:
        return {}

    key = api_key or config.get_api_key('nvd')
    headers = {'apiKey': key} if key else None

    ok, d, _ = http.get_json(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
        headers=headers)
    if not ok or not d:
        return {}

    vulns = d.get('vulnerabilities') or []
    if not vulns:
        return {}
    cve = (vulns[0] or {}).get('cve') or {}
    if not cve:
        return {}

    out: Dict[str, Any] = {}

    description = _english_value(cve.get('descriptions'))
    if description:
        out['description'] = description
    if cve.get('published'):
        out['published'] = cve['published']
    if cve.get('lastModified'):
        out['last_modified'] = cve['lastModified']
    if cve.get('vulnStatus'):
        out['vuln_status'] = cve['vulnStatus']

    out.update(_best_cvss(cve.get('metrics')))

    weaknesses = cve.get('weaknesses') or []
    for weakness in weaknesses:
        cwe = _english_value((weakness or {}).get('description'))
        if cwe:
            out['cwe'] = cwe
            break

    references = [ref.get('url') for ref in (cve.get('references') or [])
                  if isinstance(ref, dict) and ref.get('url')]
    if references:
        out['references'] = references[:_MAX_REFERENCES]
        out['reference_count'] = len(references)

    cpes: List[str] = []
    for configuration in cve.get('configurations') or []:
        for node in (configuration or {}).get('nodes') or []:
            for match in (node or {}).get('cpeMatch') or []:
                criteria = (match or {}).get('criteria')
                if criteria:
                    cpes.append(criteria)
    if cpes:
        out['affected_cpes'] = cpes[:_MAX_CPES]
        out['cpe_count'] = len(cpes)

    return out


def _osv(cve_id: str) -> Dict[str, Any]:
    """
    Google OSV.dev per-vulnerability record (keyless).

    Endpoint: ``GET /v1/vulns/<id>``. OSV is package-centric: the same CVE
    appears once per affected ecosystem/package, so packages are
    de-duplicated and sorted for a stable, comparable field.
    """
    cve_id = _clean_id(cve_id)
    if not cve_id:
        return {}

    ok, d, _ = http.get_json(f"https://api.osv.dev/v1/vulns/{cve_id}")
    if not ok or not d:
        return {}

    out: Dict[str, Any] = {}

    if d.get('summary'):
        out['osv_summary'] = d['summary']
    if d.get('published'):
        out['osv_published'] = d['published']
    if d.get('modified'):
        out['osv_modified'] = d['modified']

    for entry in d.get('severity') or []:
        if not isinstance(entry, dict):
            continue
        score = entry.get('score')
        if entry.get('type') == 'CVSS_V3' and score:
            out['osv_severity_vector'] = score
            break
        if 'osv_severity_vector' not in out and score:
            out['osv_severity_vector'] = score

    packages: List[str] = []
    for affected in d.get('affected') or []:
        package = (affected or {}).get('package') or {}
        ecosystem = package.get('ecosystem')
        name = package.get('name')
        if ecosystem and name:
            packages.append(f"{ecosystem}/{name}")
    packages = sorted(set(packages))
    if packages:
        out['osv_packages'] = packages[:_MAX_PACKAGES]
        out['osv_package_count'] = len(packages)

    references = d.get('references') or []
    if references:
        out['osv_reference_count'] = len(references)

    return out


def _cvelist_url(cve_id: str) -> str:
    """
    Build the raw GitHub URL for a cvelist record.

    The repository buckets records by ``<sequence>//1000``:
    ``CVE-2021-44228`` lives in ``cves/2021/44xxx/CVE-2021-44228.json``.
    Returns an empty string for malformed identifiers.
    """
    parts = _clean_id(cve_id).split('-')
    if len(parts) != 3 or not (parts[1].isdigit() and parts[2].isdigit()):
        return ''
    bucket = int(parts[2]) // 1000
    return (f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main"
            f"/cves/{parts[1]}/{bucket}xxx/{parts[0]}-{parts[1]}-{parts[2]}.json")


def _cvelist(cve_id: str) -> Dict[str, Any]:
    """
    CVEProject cvelistV5 raw JSON (keyless), the CNA-published record.

    This is the fastest public mirror of the record NVD eventually enriches:
    title, publication state and the affected product list, straight from the
    assigning CNA before any analyst re-analysis.
    """
    cve_id = _clean_id(cve_id)
    parts = cve_id.split('-')
    if len(parts) != 3 or not parts[2].isdigit():
        return {}

    ok, d, _ = http.get_json(_cvelist_url(cve_id))
    if not ok or not d:
        return {}

    cna = ((d.get('containers') or {}).get('cna')) or {}
    meta = d.get('cveMetadata') or {}
    out: Dict[str, Any] = {}

    if cna.get('title'):
        out['cna_title'] = cna['title']
    if cna.get('datePublic'):
        out['cna_published'] = cna['datePublic']
    elif meta.get('datePublished'):
        out['cna_published'] = meta['datePublished']
    if meta.get('dateUpdated'):
        out['cna_updated'] = meta['dateUpdated']
    if meta.get('state'):
        out['cna_state'] = meta['state']

    description = _english_value(cna.get('descriptions'))
    if description:
        out['cna_description'] = description[:_MAX_DESCRIPTION_CHARS]

    products: List[str] = []
    for affected in cna.get('affected') or []:
        product = (affected or {}).get('product')
        if product:
            products.append(product)
    if products:
        out['cna_affected_products'] = products[:_MAX_PRODUCTS]

    return out


def _percent(value: Any) -> Optional[float]:
    """
    Rescale a 0..1 probability (EPSS style) to a 0..100 percentage.

    Returns ``None`` for missing or non-numeric values instead of raising,
    so a malformed field never fails the whole source.
    """
    try:
        return round(float(value) * 100, 1)
    except (TypeError, ValueError):
        return None


def _epss(cve_id: str) -> Dict[str, Any]:
    """
    FIRST.org EPSS scores (keyless).

    Endpoint: ``GET /data/v1/epss?cve=<id>``. EPSS is a probability
    (0..1) that a vulnerability gets exploited in the wild within 30 days;
    it is rescaled to a 0..100 percentage for reporting.
    """
    cve_id = _clean_id(cve_id)
    if not cve_id:
        return {}

    ok, d, _ = http.get_json(f"https://api.first.org/data/v1/epss?cve={cve_id}")
    if not ok or not d:
        return {}

    entries = d.get('data') or []
    if not entries:
        return {}
    entry = entries[0] if isinstance(entries[0], dict) else {}

    out: Dict[str, Any] = {}
    epss = _percent(entry.get('epss'))
    if epss is not None:
        out['epss_score'] = epss
    percentile = _percent(entry.get('percentile'))
    if percentile is not None:
        out['epss_percentile'] = percentile
    if entry.get('date'):
        out['epss_date'] = entry['date']
    return out


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

FREE_SOURCES: Dict[str, Any] = {
    'nvd': _nvd,
    'osv': _osv,
    'cvelist': _cvelist,
    'epss': _epss,
}

# All CVE sources are keyless. NVD's optional key is read from the config
# service ``nvd`` inside the reader itself (see ``_nvd``), so this registry
# stays empty but keeps the familiar module shape.
KEYED_SOURCES: Dict[str, Any] = {}

# Human-readable metadata used by `obscuralens sources` and the README.
SOURCE_CATALOG = {
    'nvd': 'NVD 2.0: description, CVSS, CWE, references, CPEs (keyless; optional key)',
    'osv': 'Google OSV.dev: affected packages and severity vector (keyless)',
    'cvelist': 'CVEProject cvelistV5 raw CNA record (keyless)',
    'epss': 'FIRST.org EPSS exploitation probability (keyless)',
}


def _keep(value: Any) -> bool:
    # A 0.0 EPSS score or a 0 reference count is a real answer, so only
    # None / '' / [] / {} count as "no data".
    return value is not None and value != '' and value != [] and value != {}


def _plugin_sources(kind: str) -> Dict[str, Any]:
    """Extra sources contributed by user plugins (lazy import avoids cycles)."""
    try:
        from .. import plugins
    except ImportError:
        return {}
    getter = getattr(plugins, 'plugin_sources_named', None) or plugins.plugin_sources
    return getter(kind)


def gather_all(cve_id: str, keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Query every applicable CVE source in parallel and merge the results.

    Args:
        cve_id: CVE identifier (any case); normalised before use
        keys: optional {service: api_key} map; an ``nvd`` key overrides the
            configured one, all other CVE sources are keyless

    Returns:
        {
          'fields': merged_field_dict (always includes 'cve'),
          'sources': {name: {'ok': bool, 'error': str}},
          'provenance': {field: [source, ...]},
        }

    Raises:
        ValueError: when the identifier is not a valid CVE id.
    """
    keys = keys or {}
    cve = normalize_cve(cve_id)
    if not cve:
        raise ValueError(f"invalid CVE identifier: {cve_id!r}")

    tasks: Dict[str, Any] = {}

    for name, fn in FREE_SOURCES.items():
        if config.is_source_enabled(name) and health.source_allowed(name):
            tasks[name] = (lambda f=fn: f(cve))

    for name, fn in _plugin_sources('cve').items():
        source_name = f"plugin:{name}"
        if config.is_source_enabled(source_name) and health.source_allowed(source_name):
            tasks[source_name] = (lambda f=fn: f(cve))

    # NVD is keyless but honours an optional key: an explicit key here wins
    # over the one the reader would read from config on its own.
    nvd_key = keys.get('nvd')
    if nvd_key and 'nvd' in tasks:
        tasks['nvd'] = (lambda k=nvd_key: _nvd(cve, k))

    results: Dict[str, Dict[str, Any]] = {}
    status: Dict[str, Dict[str, Any]] = {}

    if tasks:
        with futures.ThreadPoolExecutor(max_workers=min(len(tasks), 12)) as ex:
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

    health.record_batch('cve', status)

    merged: Dict[str, Any] = {}
    provenance: Dict[str, List[str]] = {}

    # Source order sets priority for conflicting values; earlier wins.
    for name in tasks:
        for key, value in (results.get(name) or {}).items():
            if not _keep(value):
                continue
            provenance.setdefault(key, []).append(name)
            merged.setdefault(key, value)

    # The identifier itself is part of the answer, whatever the sources did.
    merged['cve'] = cve

    return {'fields': merged, 'sources': status, 'provenance': provenance}

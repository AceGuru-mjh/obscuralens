"""
Pipeline engine for ObscuraLens v4.0.

A pipeline is a YAML document of the shape::

    name: domain-review
    description: Enrich a domain and pivot to its infrastructure
    variables:
      target: example.com
    steps:
      - lookup: $target            # kind auto-detected
      - lookup:
          kind: ip
          target: 8.8.8.8
      - risk: true                 # score every gathered result
      - timeline: true             # build the event timeline
      - correlate: true            # correlate against local db history
      - assert:
          field: abuse_confidence
          op: '>='
          value: 50
          message: address flagged by AbuseIPDB
      - notify:                    # v6.0 part 4: fan out to channels
          title: escalation
          body: 3 sources flagged the address
          severity: high
      - export:                    # v6.0 part 4: STIX/MISP from the run
          format: stix
          path: case-$target.json
      - output:
          format: table            # table | json | markdown
          path: ''                 # optional file (relative -> report_dir)

``$var`` / ``${var}`` tokens are interpolated everywhere from the merged
variables (caller-supplied values win over the file's defaults).

Execution rules:
  * ``lookup`` resolves the kind (auto via ``investigate.detect_kind`` plus
    the v4 validators), runs the matching tracker and stores the payload
    under ``results[kind]``.
  * ``risk`` / ``timeline`` / ``correlate`` import the correlation package
    lazily and defensively: a missing module records a warning and the step
    is skipped instead of crashing the run.
  * ``assert`` evaluates a condition against the first result that carries
    the field (dotted paths supported); passing assertions become findings.
  * ``notify`` (v6.0 part 4) broadcasts a message through the automation
    notification centre; the bare shorthand ``- notify: true`` summarises
    the run itself. The step record carries a machine-readable ``output``
    dict (``sent`` / ``failed`` / ``skipped`` / ``total``).
  * ``export`` (v6.0 part 4) turns the run's last lookup result into a
    STIX 2.1 bundle or a MISP core-format event - returned in the step
    ``output`` and optionally dumped under ``report_dir``.
  * ``output`` renders table/json/markdown text, optionally writes it to a
    file (relative paths land under ``app_config.report_dir``) and never
    raises on I/O errors - they are recorded in ``report['errors']``.
  * Unknown steps record an error and the run continues.
"""

import importlib
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import yaml

from ..config import config

# Actions a pipeline step may declare (exactly one per step). v6.0 part 4
# added the notify/export sharing steps.
ACTIONS = ('lookup', 'risk', 'timeline', 'correlate', 'assert', 'notify',
           'export', 'output')

# Output formats understood by the `output` step.
PIPELINE_FORMATS = ('table', 'json', 'markdown')

# Export formats understood by the v6.0 `export` step.
EXPORT_FORMATS = ('stix', 'misp')

# Assertion operators. Ordering operators compare numerically when both
# sides parse as numbers, otherwise as strings.
ASSERT_OPS = ('==', '!=', '>', '>=', '<', '<=', 'in', 'contains', 'exists')

# kind -> (importable module, tracker class). The five core kinds live in
# the trackers package; v4 kinds are separate modules owned by other agents
# and are imported defensively (a missing module simply disables the kind).
# v6.0 part 4 added bssid so the shipped geofence example pipeline runs.
TRACKER_MAP: Dict[str, Tuple[str, str]] = {
    'ip': ('obscuralens.trackers', 'IPTracker'),
    'phone': ('obscuralens.trackers', 'PhoneTracker'),
    'username': ('obscuralens.trackers', 'UsernameTracker'),
    'email': ('obscuralens.trackers', 'EmailTracker'),
    'domain': ('obscuralens.trackers', 'DomainTracker'),
    'crypto': ('obscuralens.trackers.crypto_tracker', 'CryptoTracker'),
    'hash': ('obscuralens.trackers.hash_tracker', 'HashTracker'),
    'url': ('obscuralens.trackers.url_tracker', 'URLTracker'),
    'cve': ('obscuralens.trackers.cve_tracker', 'CVETracker'),
    'asn': ('obscuralens.trackers.asn_tracker', 'ASNTracker'),
    'bssid': ('obscuralens.trackers.bssid_tracker', 'BSSIDTracker'),
}

# $var and ${var} tokens. Variable names follow Python identifier rules.
_TOKEN_RE = re.compile(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)')

# Sentinel for "field not present" (distinct from a stored None/False).
_MISSING = object()


class PipelineError(ValueError):
    """Raised for structurally invalid pipeline files or specifications."""


# --------------------------------------------------------------------------- #
# discovery / loading
# --------------------------------------------------------------------------- #

def shipped_pipelines_dir() -> Path:
    """Repository folder with the example pipelines shipped with ObscuraLens."""
    # .../obscuralens/pipelines/engine.py -> repo root -> pipelines/examples
    return Path(__file__).resolve().parents[2] / 'pipelines' / 'examples'


def _validate_spec(spec: Any) -> Dict[str, Any]:
    """Validate a pipeline mapping, raising PipelineError with a clear reason."""
    if not isinstance(spec, dict):
        raise PipelineError('pipeline definition must be a mapping')
    name = spec.get('name')
    if not isinstance(name, str) or not name.strip():
        raise PipelineError("pipeline is missing a 'name' string")
    steps = spec.get('steps')
    if not isinstance(steps, list):
        raise PipelineError("pipeline 'steps' must be a list")
    for number, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            raise PipelineError(f'step {number} must be a mapping')
    variables = spec.get('variables')
    if variables is not None and not isinstance(variables, dict):
        raise PipelineError("pipeline 'variables' must be a mapping")
    return spec


def load_pipeline(path: Union[str, Path]) -> Dict[str, Any]:
    """Load and validate a pipeline YAML file."""
    file_path = Path(path)
    if not file_path.is_file():
        raise PipelineError(f'pipeline file not found: {file_path}')
    try:
        text = file_path.read_text(encoding='utf-8')
    except OSError as e:
        raise PipelineError(f'cannot read pipeline file {file_path}: {e}') from e
    try:
        spec = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise PipelineError(f'invalid YAML in {file_path}: {e}') from e
    return _validate_spec(spec)


def _describe_pipeline(file_path: Path) -> Dict[str, Any]:
    """Summarise one pipeline file for `pipeline list` (never raises)."""
    name = file_path.stem
    description = ''
    steps = 0
    try:
        data = yaml.safe_load(file_path.read_text(encoding='utf-8'))
    except (OSError, yaml.YAMLError):
        data = None
    if isinstance(data, dict):
        if isinstance(data.get('name'), str) and data['name'].strip():
            name = data['name'].strip()
        if isinstance(data.get('description'), str):
            description = data['description']
        if isinstance(data.get('steps'), list):
            steps = len(data['steps'])
    return {'name': name, 'description': description,
            'path': str(file_path), 'steps': steps}


def list_pipelines(folder: Optional[Union[str, Path]] = None) -> List[Dict[str, Any]]:
    """
    Discover pipelines on disk.

    With ``folder`` the scan is limited to that directory. Otherwise both
    ``app_config.pipeline_dir`` and the repository's shipped
    ``pipelines/examples`` folder are scanned (duplicates removed). A missing
    folder simply contributes nothing; the result is sorted by name.
    """
    if folder is not None:
        folders = [Path(folder)]
    else:
        folders = [Path(config.app_config.pipeline_dir), shipped_pipelines_dir()]
    entries: Dict[str, Dict[str, Any]] = {}
    for directory in folders:
        try:
            if not directory.is_dir():
                continue
            candidates = sorted(directory.glob('*.yaml')) + sorted(directory.glob('*.yml'))
        except OSError:
            continue
        for file_path in candidates:
            if not file_path.is_file():
                continue
            key = str(file_path.resolve())
            if key not in entries:
                entries[key] = _describe_pipeline(file_path)
    return sorted(entries.values(), key=lambda entry: entry['name'])


# --------------------------------------------------------------------------- #
# variables and trackers
# --------------------------------------------------------------------------- #

def _interpolate_string(text: str, variables: Dict[str, Any],
                        warnings: Optional[List[str]]) -> str:
    """Replace $var / ${var} tokens; missing variables become '' + warning."""

    def replace(match: 're.Match[str]') -> str:
        name = match.group(1) or match.group(2)
        if name in variables:
            return str(variables[name])
        if warnings is not None:
            message = f"variable '{name}' is not defined"
            if message not in warnings:
                warnings.append(message)
        return ''

    return _TOKEN_RE.sub(replace, text)


def _interpolate(value: Any, variables: Dict[str, Any],
                 warnings: Optional[List[str]] = None) -> Any:
    """Recursively interpolate $var tokens in strings, dicts and lists."""
    if isinstance(value, str):
        return _interpolate_string(value, variables, warnings)
    if isinstance(value, dict):
        return {key: _interpolate(item, variables, warnings)
                for key, item in value.items()}
    if isinstance(value, list):
        return [_interpolate(item, variables, warnings) for item in value]
    return value


def resolve_trackers() -> Dict[str, Any]:
    """Import every available tracker class (missing v4 modules are skipped)."""
    resolved: Dict[str, Any] = {}
    for kind, (module_name, class_name) in TRACKER_MAP.items():
        try:
            module = importlib.import_module(module_name)
            resolved[kind] = getattr(module, class_name)
        except (ImportError, AttributeError):
            continue
    return resolved


def _as_runner(obj: Any) -> Callable[[str], Dict[str, Any]]:
    """Normalise a tracker class / instance / callable into (target)->payload."""
    if isinstance(obj, type):  # a tracker class
        instance = obj()
        return lambda target: instance.track(target)
    track = getattr(obj, 'track', None)
    if callable(track):        # a tracker instance or duck-typed object
        return lambda target: track(target)
    if callable(obj):          # a plain callable(target) -> payload
        return obj
    raise TypeError(f'not a usable tracker: {obj!r}')


def _runners(trackers: Optional[Dict[str, Any]]) -> Dict[str, Callable[[str], Dict[str, Any]]]:
    """Build the kind -> runner map, preferring injected test trackers."""
    if trackers:
        return {str(kind).lower(): _as_runner(obj)
                for kind, obj in trackers.items()}
    return {kind: _as_runner(cls) for kind, cls in resolve_trackers().items()}


def _detect_kind(target: str) -> Optional[str]:
    """detect_kind plus the v4 kinds via validators (all defensive)."""
    try:
        from ..investigate import detect_kind
        kind = detect_kind(target)
    except ImportError:
        kind = None
    except Exception:
        kind = None
    if kind:
        return kind
    try:
        from ..utils.validators import (
            validate_asn,
            validate_crypto_address,
            validate_cve,
            validate_hash,
            validate_url,
        )
    except ImportError:
        return None
    for validator, kind_name in (
            (validate_url, 'url'),
            (validate_crypto_address, 'crypto'),
            (validate_hash, 'hash'),
            (validate_cve, 'cve'),
            (validate_asn, 'asn')):
        try:
            if validator(target)[0]:
                return kind_name
        except Exception:
            continue
    return None


# --------------------------------------------------------------------------- #
# assertion helpers
# --------------------------------------------------------------------------- #

def _traverse(container: Any, path: str) -> Any:
    """Walk a dotted path through nested dicts; _MISSING when it breaks."""
    current: Any = container
    for part in path.split('.'):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return _MISSING
    return current


def _lookup_field(payload: Dict[str, Any], field: str) -> Any:
    """Resolve a (dotted) field, falling back to the payload's 'info' block."""
    value = _traverse(payload, field)
    if value is _MISSING:
        value = _traverse(payload, f'info.{field}')
    return value


def _to_number(value: Any) -> Optional[float]:
    """Float value for numbers and numeric strings; None otherwise."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _eq(actual: Any, expected: Any) -> bool:
    if actual == expected:
        return True
    actual_num, expected_num = _to_number(actual), _to_number(expected)
    if actual_num is not None and expected_num is not None:
        return actual_num == expected_num
    if isinstance(actual, str) or isinstance(expected, str):
        return str(actual).strip() == str(expected).strip()
    return False


def _in(actual: Any, expected: Any) -> bool:
    if isinstance(expected, (list, tuple, set)):
        values = list(expected)
        if actual in values:
            return True
        actual_num = _to_number(actual)
        if actual_num is None:
            return False
        return any(_to_number(item) == actual_num for item in values)
    if isinstance(expected, str) and isinstance(actual, str):
        return actual in expected
    return False


def _contains(actual: Any, expected: Any) -> bool:
    if isinstance(actual, str):
        return str(expected) in actual
    if isinstance(actual, (list, tuple, set)):
        if expected in actual:
            return True
        expected_num = _to_number(expected)
        if expected_num is None:
            return False
        return any(_to_number(item) == expected_num for item in actual)
    if isinstance(actual, dict):
        return str(expected) in actual
    return False


def _compare(actual: Any, op: str, expected: Any) -> bool:
    """Evaluate one assertion operator."""
    if op == 'exists':
        return bool(actual is not _MISSING) == bool(expected)
    if op == 'in':
        return _in(actual, expected)
    if op == 'contains':
        return _contains(actual, expected)
    if op == '==':
        return _eq(actual, expected)
    if op == '!=':
        return not _eq(actual, expected)
    actual_num, expected_num = _to_number(actual), _to_number(expected)
    if actual_num is not None and expected_num is not None:
        left: Any = actual_num
        right: Any = expected_num
    else:
        left, right = str(actual), str(expected)
    if op == '>':
        return left > right
    if op == '>=':
        return left >= right
    if op == '<':
        return left < right
    if op == '<=':
        return left <= right
    return False


# --------------------------------------------------------------------------- #
# step handlers (each mutates the report and returns (ok, detail))
# --------------------------------------------------------------------------- #

def _lookup_failed(report: Dict[str, Any], detail: str) -> Tuple[bool, str]:
    """Record a lookup failure in the report errors and finish the step."""
    report['errors'].append(detail)
    return False, detail


def _step_lookup(report: Dict[str, Any], runners: Dict[str, Callable],
                 spec: Any) -> Tuple[bool, str]:
    if isinstance(spec, dict):
        kind = str(spec.get('kind') or 'auto').strip().lower()
        target = spec.get('target')
    else:
        kind, target = 'auto', spec
    if target is None or not str(target).strip():
        return _lookup_failed(report, 'lookup step is missing a target')
    target = str(target).strip()
    if kind == 'auto':
        kind = _detect_kind(target)
        if kind is None:
            return _lookup_failed(
                report, f'cannot determine kind for target {target!r}')
    runner = runners.get(kind)
    if runner is None:
        return _lookup_failed(report, f'no tracker available for kind {kind!r}')
    try:
        payload = runner(target)
    except Exception as e:
        return _lookup_failed(
            report, f'{kind} {target}: tracker failed ({type(e).__name__})')
    if not isinstance(payload, dict):
        return _lookup_failed(
            report, f'{kind} {target}: tracker returned {type(payload).__name__}')
    report['results'][kind] = payload
    ok_sources = payload.get('sources_ok') or []
    detail = f'{kind} {target}: {len(ok_sources)} source(s) ok'
    return bool(payload.get('success', True)), detail


def _step_risk(report: Dict[str, Any]) -> Tuple[bool, str]:
    try:
        from ..correlation.risk import attach_risk
    except ImportError:
        report['warnings'].append(
            'correlation.risk is unavailable - skipping risk scoring')
        return False, 'risk module unavailable'
    scored = 0
    for kind, payload in list(report['results'].items()):
        try:
            updated = attach_risk(kind, payload)
        except TypeError:
            # Alternate signature: attach_risk(payload).
            try:
                updated = attach_risk(payload)
            except Exception as e:
                report['errors'].append(f'risk {kind}: {type(e).__name__}')
                continue
        except Exception as e:
            report['errors'].append(f'risk {kind}: {type(e).__name__}')
            continue
        if isinstance(updated, dict):
            report['results'][kind] = updated
        scored += 1
    return True, f'risk scores attached to {scored} result(s)'


def _timeline_payloads(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Current results in the {'kind', 'value', 'payload'} record shape."""
    return [{'kind': kind, 'value': _target_of(kind, payload), 'payload': payload}
            for kind, payload in (report.get('results') or {}).items()
            if isinstance(payload, dict)]


def _step_timeline(report: Dict[str, Any]) -> Tuple[bool, str]:
    try:
        from ..correlation.timeline import build_timeline
    except ImportError:
        report['warnings'].append(
            'correlation.timeline is unavailable - skipping timeline build')
        return False, 'timeline module unavailable'
    try:
        timeline = build_timeline(_timeline_payloads(report))
    except TypeError:
        # Alternate signature: build_timeline(results_dict).
        try:
            timeline = build_timeline(report['results'])
        except Exception as e:
            report['errors'].append(f'timeline: {type(e).__name__}')
            return False, 'timeline build failed'
    except Exception as e:
        report['errors'].append(f'timeline: {type(e).__name__}')
        return False, 'timeline build failed'
    report['timeline'] = timeline
    if isinstance(timeline, dict):
        count = timeline.get('count')
        if not isinstance(count, int):
            count = len(timeline.get('events') or [])
    elif hasattr(timeline, '__len__'):
        count = len(timeline)
    else:
        count = 0
    return True, f'timeline built with {count} event(s)'


def _step_correlate(report: Dict[str, Any]) -> Tuple[bool, str]:
    try:
        from ..correlation.engine import build_graph, history_records
    except ImportError:
        report['warnings'].append(
            'correlation.engine is unavailable - skipping correlation')
        return False, 'correlation module unavailable'
    correlation: Dict[str, Any] = {}
    parts: List[str] = []
    history: Any = None
    try:
        history = history_records()
        parts.append('history')
    except TypeError:
        # Alternate signature: history_records(results).
        try:
            history = history_records(report['results'])
            parts.append('history')
        except Exception as e:
            report['errors'].append(f'correlation history: {type(e).__name__}')
    except Exception as e:
        report['errors'].append(f'correlation history: {type(e).__name__}')
    correlation['history'] = history
    # The graph covers the current run's results plus the stored history so
    # pivots between the investigation and previous lookups become visible.
    records = _timeline_payloads(report)
    if isinstance(history, list):
        records = records + [row for row in history if isinstance(row, dict)]
    try:
        correlation['graph'] = build_graph(records)
        parts.append('graph')
    except TypeError:
        # Alternate signature: build_graph(results_dict).
        try:
            correlation['graph'] = build_graph(report['results'])
            parts.append('graph')
        except Exception as e:
            report['errors'].append(f'correlation graph: {type(e).__name__}')
    except Exception as e:
        report['errors'].append(f'correlation graph: {type(e).__name__}')
    report['correlation'] = correlation
    return bool(parts), 'correlated: ' + (', '.join(parts) if parts else 'nothing')


def _step_assert(report: Dict[str, Any], spec: Any) -> Tuple[bool, str]:
    if not isinstance(spec, dict):
        return False, 'assert step must be a mapping'
    field = str(spec.get('field') or '')
    op = str(spec.get('op') or '').strip()
    expected = spec.get('value')
    message = str(spec.get('message') or '')
    if not field:
        return False, 'assert step is missing a field'
    if op not in ASSERT_OPS:
        report['errors'].append(f'unknown assert op {op!r}')
        return False, f'unknown assert op {op!r}'
    actual: Any = _MISSING
    for payload in report['results'].values():
        actual = _lookup_field(payload, field)
        if actual is not _MISSING:
            break
    # 'exists: false' asserts absence, so a missing field is a pass, not a
    # lookup problem; every other operator needs the field to be present.
    asserting_absence = op == 'exists' and not expected
    if actual is _MISSING and not asserting_absence:
        report['warnings'].append(
            f'assert field {field!r} not found in any result')
        return False, f'field {field!r} not found in any result'
    if _compare(actual, op, expected):
        report['findings'].append({
            'field': field, 'op': op, 'value': expected,
            'actual': actual, 'message': message,
        })
        return True, f'assertion passed: {message or field}'
    failed = f'assertion failed: {field} {op} {expected!r} (actual {actual!r})'
    report['warnings'].append(failed)
    return False, failed


def _target_of(kind: str, payload: Dict[str, Any]) -> str:
    """Best-effort target string for a result payload (kind key first)."""
    for key in (kind, 'address', 'phone_number', 'target'):
        value = payload.get(key)
        if value not in (None, ''):
            return str(value)
    return ''


def _field_count(payload: Dict[str, Any]) -> int:
    if isinstance(payload.get('field_count'), int):
        return payload['field_count']
    info = payload.get('info')
    return len(info) if isinstance(info, dict) else 0


def _render_table(report: Dict[str, Any]) -> str:
    headers = ('kind', 'target', 'success', 'fields')
    rows: List[List[str]] = []
    for kind, payload in (report.get('results') or {}).items():
        rows.append([
            str(kind),
            _target_of(kind, payload),
            'yes' if bool(payload.get('success', True)) else 'no',
            str(_field_count(payload)),
        ])
    if not rows:
        rows = [['(no results)', '', '', '']]
    widths = [max(len(str(row[index]))
                  for row in [list(headers)] + rows)
              for index in range(len(headers))]

    def fmt(row: List[str]) -> str:
        return '  '.join(str(cell).ljust(widths[index])
                         for index, cell in enumerate(row))

    lines = [fmt(list(headers)), '  '.join('-' * width for width in widths)]
    lines += [fmt(row) for row in rows]
    return '\n'.join(lines)


def _render_markdown(report: Dict[str, Any]) -> str:
    lines: List[str] = [f"# Pipeline: {report.get('name', '')}", '']
    description = report.get('description') or ''
    if description:
        lines += [str(description), '']
    lines += ['## Results', '']
    results = report.get('results') or {}
    if results:
        for kind, payload in results.items():
            success = bool(payload.get('success', True))
            lines.append(
                f'- **{kind}** `{_target_of(kind, payload)}` - '
                f'{_field_count(payload)} field(s), success: {success}')
    else:
        lines.append('_(no results)_')
    lines.append('')
    findings = report.get('findings') or []
    lines += [f'## Findings ({len(findings)})', '']
    if findings:
        for finding in findings:
            lines.append(
                f"- **{finding.get('field')}** {finding.get('op')} "
                f"{finding.get('value')!r} (actual {finding.get('actual')!r})"
                f" - {finding.get('message') or ''}".rstrip())
    else:
        lines.append('_(no findings)_')
    lines.append('')
    for title, entries in (('Errors', report.get('errors') or ()),
                           ('Warnings', report.get('warnings') or ())):
        if entries:
            lines += [f'## {title}', ''] + [f'- {entry}' for entry in entries] + ['']
    return '\n'.join(lines).rstrip() + '\n'


def _render_json(report: Dict[str, Any]) -> str:
    # The report is serialised before this output step is appended, so the
    # rendering can never include itself (no recursion).
    return json.dumps(report, indent=2, default=str)


def _shorten(text: str, limit: int = 600) -> str:
    text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + f'... ({len(text) - limit} more characters)'


def _resolve_output_path(path: str) -> Path:
    """Absolute output path; relative paths land under app_config.report_dir."""
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = Path(config.app_config.report_dir) / candidate
    return candidate


def _step_output(report: Dict[str, Any], spec: Any) -> Tuple[bool, str]:
    if isinstance(spec, str):  # tolerate `- output: table`
        fmt, path = spec, ''
    elif isinstance(spec, dict):
        fmt = str(spec.get('format') or 'table').strip().lower()
        path = str(spec.get('path') or '').strip()
    else:
        fmt, path = 'table', ''
    if fmt not in PIPELINE_FORMATS:
        report['errors'].append(
            f'unknown output format {fmt!r} (expected one of {PIPELINE_FORMATS})')
        return False, f'unknown output format {fmt!r}'
    if fmt == 'table':
        text = _render_table(report)
    elif fmt == 'json':
        text = _render_json(report)
    else:
        text = _render_markdown(report)
    prefix = ''
    ok = True
    if path:
        target_path = _resolve_output_path(path)
        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_text(text, encoding='utf-8')
            prefix = f'written to {target_path}; '
        except OSError as e:
            report['errors'].append(
                f'cannot write output file {target_path}: {e}')
            ok = False
            prefix = f'write to {target_path} failed; '
    return ok, prefix + _shorten(text)


def _action_of(step: Dict[str, Any]) -> Optional[str]:
    for key in step:
        if key in ACTIONS:
            return key
    return None


# --------------------------------------------------------------------------- #
# v6.0 part 4: notify / export steps (each mutates the report and returns
# (ok, detail, output) - the output dict is attached to the step record)
# --------------------------------------------------------------------------- #

def _run_summary_lines(report: Dict[str, Any]) -> Tuple[str, str]:
    """A (title, body) pair summarising the run so far."""
    name = str(report.get('name') or 'pipeline')
    steps = report.get('steps') or []
    results = report.get('results') or {}
    findings = report.get('findings') or []
    errors = report.get('errors') or []
    title = f'ObscuraLens pipeline {name} finished'
    body = (f"{len(steps)} step(s) executed, {len(results)} lookup result(s), "
            f"{len(findings)} finding(s), {len(errors)} error(s).")
    if findings:
        headlines = '; '.join(
            str(item.get('message') or item.get('field') or '')
            for item in findings[:5])
        if headlines:
            body += f' Findings: {headlines}.'
    return title, body


def _step_notify(report: Dict[str, Any],
                 spec: Any) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Broadcast one message through the automation notification centre.

    ``spec`` is either ``true`` (the shorthand: the run's own summary
    becomes the message) or a mapping with ``title`` / ``body`` and the
    optional ``severity`` (default ``info``) and ``event_type`` (default
    ``pipeline``). Per-channel filters - event subscriptions, severity
    floors, quiet hours, dedup - decide what actually leaves the machine.

    Returns:
        ``(ok, detail, output)`` where ``output`` is ``{'sent', 'failed',
        'skipped', 'total'}``; a total delivery failure (every contacted
        channel failed) is recorded in ``report['errors']``, while
        filter-based skips and an empty channel list are successes.
    """
    try:
        from ..automation import notifications
    except ImportError:
        report['warnings'].append(
            'automation.notifications is unavailable - skipping notify step')
        return False, 'notify module unavailable', {'sent': 0, 'failed': 0,
                                                    'skipped': 0, 'total': 0}
    if spec is True or spec is None:
        title, body = _run_summary_lines(report)
        severity, event_type = 'info', 'pipeline'
    elif isinstance(spec, dict):
        title = str(spec.get('title') or '').strip()
        body = str(spec.get('body') or '')
        if not title:
            title, body = _run_summary_lines(report)
        severity = str(spec.get('severity') or 'info').strip().lower() \
            or 'info'
        event_type = str(spec.get('event_type') or 'pipeline').strip().lower() \
            or 'pipeline'
    else:  # tolerate `- notify: <text>` - the text is the title
        title, body = str(spec), ''
        severity, event_type = 'info', 'pipeline'
    try:
        result = notifications.broadcast(event_type, title, body,
                                         severity=severity)
    except Exception as e:  # a broken notify layer never kills the run
        detail = f'notify failed ({type(e).__name__})'
        report['errors'].append(detail)
        return False, detail, {'sent': 0, 'failed': 1, 'skipped': 0,
                               'total': 1}
    sent = int(result.get('sent') or 0)
    failed = len(result.get('failed') or [])
    skipped = int(result.get('skipped') or 0)
    total = int(result.get('total') or 0)
    output = {'sent': sent, 'failed': failed, 'skipped': skipped,
              'total': total}
    if total == 0:
        return True, 'no channels configured - notification skipped', output
    if sent == 0 and failed > 0:
        reasons = '; '.join(
            f"{item.get('channel')}: {item.get('error')}"
            for item in (result.get('failed') or [])[:3])
        detail = f'notify failed on all {total} channel(s): {reasons}'
        report['errors'].append(detail)
        return False, detail, output
    detail = f'notified {sent}/{total} channel(s), {skipped} skipped'
    if failed:
        detail += f', {failed} failed'
    return True, detail, output


def _last_lookup(report: Dict[str, Any]) -> Optional[Tuple[str, str,
                                                           Dict[str, Any]]]:
    """
    The run's most recent lookup as ``(kind, target, payload)``.

    ``results`` is an insertion-ordered dict, so the newest lookup is the
    last key; a re-lookup of the same kind overwrites in place and stays
    "last" - exactly the result an export should describe.
    """
    results = report.get('results') or {}
    for kind in reversed(list(results)):
        payload = results[kind]
        if isinstance(payload, dict):
            return str(kind), _target_of(str(kind), payload), payload
    return None


def _step_export(report: Dict[str, Any],
                 spec: Any) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Turn the run's last lookup result into a STIX bundle or MISP event.

    ``spec`` is a mapping with ``format`` (``stix`` or ``misp``; the only
    required key), optional ``kind`` / ``target`` overrides (default: the
    last lookup's kind and target) and an optional ``path`` - relative
    paths land under ``app_config.report_dir`` exactly like ``output``
    steps. Without ``path`` the document is only returned inside the
    step's ``output`` dict (``document`` key) for the caller to consume.

    Returns:
        ``(ok, detail, output)`` with ``{'format', 'kind', 'target',
        'objects', 'path', 'bytes', 'document'}``; a missing lookup, an
        unknown format or a failed write lands in ``report['errors']``.
    """
    if not isinstance(spec, dict):
        spec = {'format': str(spec or '').strip().lower()}
    fmt = str(spec.get('format') or '').strip().lower()
    if fmt not in EXPORT_FORMATS:
        detail = (f'unknown export format {fmt!r} '
                  f'(expected one of {EXPORT_FORMATS})')
        report['errors'].append(detail)
        return False, detail, {}
    last = _last_lookup(report)
    if last is None:
        detail = 'no lookup result to export - run a lookup step first'
        report['errors'].append(detail)
        return False, detail, {}
    kind, target, payload = last
    kind = str(spec.get('kind') or kind).strip().lower() or kind
    target = str(spec.get('target') or target).strip() or target
    try:
        if fmt == 'stix':
            from ..export.stix import build_bundle, dump_bundle
            document = build_bundle(kind, target, payload)
            objects = len(document.get('objects') or [])
            writer: Callable[[Dict[str, Any], Any], Dict[str, Any]] = \
                dump_bundle
        else:
            from ..export.misp import build_misp_event, dump_event
            document = build_misp_event(kind, target, payload)
            objects = len((document.get('Event') or {}).get('Attribute')
                          or [])
            writer = dump_event
    except ImportError as e:
        detail = f'export.{fmt} module unavailable ({e})'
        report['warnings'].append(detail)
        return False, detail, {}
    except Exception as e:  # a hostile envelope never kills the run
        detail = f'{fmt} export failed ({type(e).__name__})'
        report['errors'].append(detail)
        return False, detail, {}
    output: Dict[str, Any] = {'format': fmt, 'kind': kind, 'target': target,
                              'objects': objects, 'path': '', 'bytes': 0,
                              'document': document}
    prefix = ''
    ok = True
    path = str(spec.get('path') or '').strip()
    if path:
        target_path = _resolve_output_path(path)
        try:
            written = writer(document, target_path)
            if not written.get('ok'):
                raise OSError(str(written.get('error') or 'write failed'))
            output['path'] = str(written.get('path') or target_path)
            output['bytes'] = int(written.get('bytes') or 0)
            prefix = f"written to {output['path']}; "
        except OSError as e:
            detail = f'cannot write export file {target_path}: {e}'
            report['errors'].append(detail)
            return False, detail, output
    detail = (prefix + f'{fmt} export for {kind} {target}: '
              f'{objects} object(s)')
    return ok, detail, output


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #

def run_pipeline(path_or_dict: Union[str, Path, Dict[str, Any]],
                 variables: Optional[Dict[str, Any]] = None,
                 trackers: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Execute a pipeline and return a report dict.

    Args:
        path_or_dict: YAML file path or an already-loaded spec mapping.
        variables: caller overrides; they win over the file's `variables`.
        trackers: optional ``{kind: tracker}`` map (classes, instances or
            plain callables) so tests can run pipelines fully offline.

    Raises:
        PipelineError: the file/spec is structurally invalid.
    """
    if isinstance(path_or_dict, (str, Path)):
        spec = load_pipeline(path_or_dict)
    else:
        spec = _validate_spec(path_or_dict)

    merged: Dict[str, Any] = {}
    file_variables = spec.get('variables')
    if isinstance(file_variables, dict):
        merged.update(file_variables)
    if variables:
        merged.update(variables)

    warnings: List[str] = []
    errors: List[str] = []
    report: Dict[str, Any] = {
        'name': spec.get('name'),
        'description': str(spec.get('description') or ''),
        'started': _now_iso(),
        'finished': None,
        'duration_ms': None,
        'steps': [],
        'results': {},
        'findings': [],
        'timeline': None,
        'correlation': None,
        'errors': errors,
        'warnings': warnings,
    }
    started = time.time()
    runners = _runners(trackers)

    for number, raw_step in enumerate(spec.get('steps') or [], start=1):
        step = _interpolate(dict(raw_step), merged, warnings)
        action = _action_of(step)
        if action is None:
            first_key = next(iter(step), '?')
            detail = (f"unknown action {first_key!r} "
                      f"(expected one of {', '.join(ACTIONS)})")
            errors.append(f'step {number}: {detail}')
            report['steps'].append(
                {'step': number, 'action': first_key, 'ok': False, 'detail': detail})
            continue
        extras = [key for key in step if key in ACTIONS and key != action]
        if extras:
            warnings.append(
                f'step {number}: multiple action keys {sorted(step.keys())}; '
                f"using {action!r}")
        spec_value = step[action]
        if action in ('risk', 'timeline', 'correlate', 'notify',
                      'export') and not spec_value:
            # `risk: false` etc. disables the step instead of running it.
            report['steps'].append(
                {'step': number, 'action': action, 'ok': True,
                 'detail': 'skipped (disabled)'})
            continue
        # v6.0 part 4: notify/export handlers also return a machine-
        # readable output dict that is attached to the step record.
        output: Optional[Dict[str, Any]] = None
        if action == 'lookup':
            ok, detail = _step_lookup(report, runners, spec_value)
        elif action == 'risk':
            ok, detail = _step_risk(report)
        elif action == 'timeline':
            ok, detail = _step_timeline(report)
        elif action == 'correlate':
            ok, detail = _step_correlate(report)
        elif action == 'assert':
            ok, detail = _step_assert(report, spec_value)
        elif action == 'notify':
            ok, detail, output = _step_notify(report, spec_value)
        elif action == 'export':
            ok, detail, output = _step_export(report, spec_value)
        else:  # action == 'output'
            ok, detail = _step_output(report, spec_value)
        entry = {'step': number, 'action': action, 'ok': ok, 'detail': detail}
        if output is not None:
            entry['output'] = output
        report['steps'].append(entry)

    report['finished'] = _now_iso()
    report['duration_ms'] = round((time.time() - started) * 1000, 1)
    return report


def pipeline_sections(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Report sections for a pipeline run (summary grid, steps, findings)."""
    sections: List[Dict[str, Any]] = [{
        'title': 'Pipeline Summary', 'type': 'grid', 'data': {
            'Pipeline': report.get('name'),
            'Description': report.get('description') or '(none)',
            'Started': report.get('started'),
            'Finished': report.get('finished'),
            'Duration (ms)': report.get('duration_ms'),
            'Steps': len(report.get('steps') or []),
            'Results': len(report.get('results') or {}),
            'Findings': len(report.get('findings') or []),
            'Errors': len(report.get('errors') or []),
            'Warnings': len(report.get('warnings') or []),
        },
    }]
    sections.append({
        'title': 'Pipeline Steps', 'type': 'table',
        'columns': ['#', 'Action', 'OK', 'Detail'],
        'rows': [[step.get('step'), step.get('action'),
                  'yes' if step.get('ok') else 'no', step.get('detail')]
                 for step in report.get('steps') or []],
    })
    findings = report.get('findings') or []
    if findings:
        sections.append({
            'title': f'Findings ({len(findings)})', 'type': 'table',
            'columns': ['Field', 'Op', 'Expected', 'Actual', 'Message'],
            'rows': [[finding.get('field'), finding.get('op'),
                      finding.get('value'), finding.get('actual'),
                      finding.get('message') or '']
                     for finding in findings],
        })
    errors = report.get('errors') or []
    if errors:
        sections.append({
            'title': 'Pipeline Errors', 'type': 'table', 'columns': ['Error'],
            'rows': [[error] for error in errors],
        })
    warnings = report.get('warnings') or []
    if warnings:
        sections.append({
            'title': 'Pipeline Warnings', 'type': 'table', 'columns': ['Warning'],
            'rows': [[warning] for warning in warnings],
        })
    return sections


def save_pipeline(name: str, spec_dict: Optional[Dict[str, Any]] = None,
                  folder: Optional[Union[str, Path]] = None) -> str:
    """
    Write a pipeline YAML template (used by ``pipeline init``).

    Returns the path of the file written; raises PipelineError for an
    invalid name or specification.
    """
    name = str(name or '').strip()
    if not name:
        raise PipelineError('pipeline name must be a non-empty string')
    spec = dict(spec_dict or {})
    spec['name'] = name
    spec.setdefault('description', '')
    spec.setdefault('variables', {})
    spec.setdefault('steps', [])
    _validate_spec(spec)
    directory = (Path(folder) if folder is not None
                 else Path(config.app_config.pipeline_dir))
    directory.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r'[^0-9A-Za-z_.-]+', '-', name.lower()).strip('-') or 'pipeline'
    path = directory / f'{slug}.yaml'
    with open(path, 'w', encoding='utf-8') as handle:
        yaml.safe_dump(spec, handle, default_flow_style=False, sort_keys=False)
    return str(path)

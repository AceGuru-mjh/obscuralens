"""
LLM narrative summaries (EXPERIMENTAL).

Opt-in module: turns a finished tracker payload into a human-readable analyst
narrative through any OpenAI-compatible ``/chat/completions`` endpoint
(OpenAI itself, LM Studio, Ollama's OpenAI shim, vLLM, ...).

Configuration (resolution order: explicit arguments, then config):
    * ``app.llm_base_url``      e.g. ``https://api.openai.com/v1``
    * ``app.llm_model``         e.g. ``gpt-4o-mini``
    * the ``llm`` API key       ``config.get_api_key('llm')`` / secrets.yaml

Requires ``app.experimental_features`` to be enabled; ``summarize()`` refuses
to run otherwise. Every public function returns error dictionaries instead of
raising so a broken endpoint can never crash a scan.

The request itself goes through the shared :mod:`obscuralens.utils.http_client`
client (``http.post_json``), inheriting timeouts, proxy support and metrics.
"""

from typing import Any, Dict, List, Optional

from ..config import config
from ..utils.http_client import http

__all__ = [
    'compact_payload',
    'build_messages',
    'summarize',
    'llm_configured',
    'llm_sections',
]

# Keys a tracker result uses for its primary target, most specific first.
_TARGET_KEYS = (
    'ip', 'domain', 'username', 'email', 'url', 'phone', 'hash', 'cve',
    'asn', 'address', 'crypto',
)

_SYSTEM_PROMPT = (
    'You are an OSINT analyst assistant. Be factual and concise, cite source '
    'names from the provided data, and do not speculate beyond the data. '
    'Output exactly 4 short sections with these headings: Summary / Key '
    'findings / Confidence / Suggested next steps.'
)

# Presentation caps so a huge payload becomes a cheap prompt.
_MAX_LIST_ITEMS = 5
_MAX_VALUE_CHARS = 200
_MAX_SOURCE_ITEMS = 12


def _target_of(kind: str, payload: Dict[str, Any]) -> str:
    """Best-effort 'what was scanned' line for the payload."""
    if not isinstance(payload, dict):
        return f'Target kind: {kind}'
    for key in _TARGET_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return f'Target ({kind}): {value.strip()[:120]}'
        if isinstance(value, (int, float)):
            return f'Target ({kind}): {value}'
    return f'Target kind: {kind}'


def _render_value(value: Any) -> Optional[str]:
    """Render one field value compactly; None when it carries no information."""
    if value is None or value == '' or value == [] or value == {}:
        return None
    if isinstance(value, bool):
        return 'yes' if value else 'no'
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        items = [str(item)[:_MAX_VALUE_CHARS] for item in value[:_MAX_LIST_ITEMS]]
        extra = len(value) - _MAX_LIST_ITEMS
        text = ', '.join(items)
        if extra > 0:
            text += f' (+{extra} more)'
        return text or None
    if isinstance(value, dict):
        items = [f'{key}={val}' for key, val in list(value.items())[:_MAX_LIST_ITEMS]]
        extra = len(value) - _MAX_LIST_ITEMS
        text = ', '.join(items)
        if extra > 0:
            text += f' (+{extra} more)'
        return text or None
    return str(value)[:_MAX_VALUE_CHARS]


def compact_payload(kind: str, payload: Any, max_chars: int = 6000) -> str:
    """
    EXPERIMENTAL: flatten a tracker payload into a compact plain-text digest.

    Structure: a target line, key/value fact lines (lists capped at 5 items),
    a sources summary and any errors. Plain text only - no JSON dumping, so
    the model reads a document instead of escaping noise.

    Never raises; garbage input degrades to a minimal two-line digest.
    """
    lines: List[str] = [_target_of(str(kind or 'unknown'), payload or {})]
    if not isinstance(payload, dict):
        lines.append('(no data)')
        return '\n'.join(lines)

    info = payload.get('info')
    if isinstance(info, dict) and info:
        lines.append('')
        lines.append('Facts:')
        for key, value in info.items():
            rendered = _render_value(value)
            if rendered is not None:
                lines.append(f'- {key}: {rendered}')
    else:
        lines.append('(no info fields collected)')

    sources_ok = payload.get('sources_ok')
    if isinstance(sources_ok, (list, tuple)) and sources_ok:
        shown = [str(s) for s in sources_ok[:_MAX_SOURCE_ITEMS]]
        extra = len(sources_ok) - _MAX_SOURCE_ITEMS
        text = ', '.join(shown)
        if extra > 0:
            text += f' (+{extra} more)'
        lines.append('')
        lines.append(f'Sources OK: {text}')

    sources_failed = payload.get('sources_failed')
    if isinstance(sources_failed, dict) and sources_failed:
        parts = [f'{name} ({err})' for name, err in list(sources_failed.items())
                 [:_MAX_SOURCE_ITEMS]]
        lines.append(f'Sources failed: {"; ".join(parts)}')

    errors = payload.get('errors')
    if isinstance(errors, (list, tuple)) and errors:
        lines.append(f'Errors: {"; ".join(str(e) for e in errors[:_MAX_SOURCE_ITEMS])}')

    text = '\n'.join(lines)
    limit = int(max_chars) if isinstance(max_chars, int) and max_chars > 0 else 6000
    if len(text) > limit:
        text = text[:limit] + '\n[truncated]'
    return text


def build_messages(kind: str, payload: Any) -> List[Dict[str, str]]:
    """
    EXPERIMENTAL: build the chat message list for a summarisation request.

    Returns a system message (analyst persona + 4-section output contract)
    and a user message carrying :func:`compact_payload`.
    """
    return [
        {'role': 'system', 'content': _SYSTEM_PROMPT},
        {'role': 'user', 'content': compact_payload(kind, payload)},
    ]


def llm_configured(base_url: Optional[str] = None,
                   api_key: Optional[str] = None) -> bool:
    """
    EXPERIMENTAL: whether an LLM endpoint + key are usable right now.

    Explicit arguments win over ``app.llm_base_url`` and the ``llm`` API key.
    """
    url = base_url or config.app_config.llm_base_url
    key = api_key or config.get_api_key('llm')
    return bool(url and key)


def summarize(kind: str, payload: Any, base_url: Optional[str] = None,
              model: Optional[str] = None, api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    EXPERIMENTAL: produce a narrative summary of a tracker payload.

    Args:
        kind: tracker kind label ('ip', 'domain', 'username', ...).
        payload: the tracker result dict.
        base_url: OpenAI-compatible root (``.../v1``); defaults to config.
        model: model name; defaults to ``app.llm_model``.
        api_key: bearer token; defaults to the ``llm`` service key.

    Returns:
        ``{'summary': str, 'model': str, 'usage': dict, 'chars': int}`` on
        success, otherwise ``{'error': '<why>'}`` (missing configuration,
        disabled experimental features, transport failure or API error -
        OpenAI-style ``{'error': {'message': ...}}`` payloads are mapped to
        their message text). Never raises.
    """
    if not config.app_config.experimental_features:
        return {'error': 'experimental features disabled'}

    resolved_url = (base_url or config.app_config.llm_base_url or '').strip()
    resolved_key = api_key or config.get_api_key('llm') or ''
    resolved_model = (model or config.app_config.llm_model or '').strip()
    if not resolved_url or not resolved_key:
        return {'error': 'llm not configured (set app.llm_base_url and the llm api key)'}
    if not resolved_model:
        resolved_model = 'gpt-4o-mini'

    endpoint = resolved_url.rstrip('/') + '/chat/completions'
    request_body: Dict[str, Any] = {
        'model': resolved_model,
        'messages': build_messages(kind, payload),
        'temperature': 0.2,
        'max_tokens': 700,
    }
    headers = {
        'Authorization': f'Bearer {resolved_key}',
        'Content-Type': 'application/json',
    }

    try:
        ok, data, err = http.post_json(endpoint, request_body, headers=headers)
    except Exception as e:  # defensive: transport layer misbehaviour
        return {'error': f'llm request failed: {type(e).__name__}'}

    if not ok:
        return {'error': f'llm request failed: {err or "unknown error"}'}
    if not isinstance(data, dict):
        return {'error': 'llm returned an unexpected response shape'}

    api_error = data.get('error')
    if isinstance(api_error, dict):
        message = api_error.get('message')
        if message:
            return {'error': str(message)}
        return {'error': 'llm api returned an error'}
    if isinstance(api_error, str) and api_error:
        return {'error': api_error}

    content: Optional[str] = None
    choices = data.get('choices')
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        message = choices[0].get('message')
        if isinstance(message, dict) and isinstance(message.get('content'), str):
            content = message['content']
    if not content:
        return {'error': 'llm returned no summary content'}

    usage = data.get('usage')
    if not isinstance(usage, dict):
        usage = {}
    return {
        'summary': content,
        'model': resolved_model,
        'usage': usage,
        'chars': len(content),
    }


def llm_sections(result: Any) -> List[Dict[str, Any]]:
    """
    EXPERIMENTAL: report sections for a :func:`summarize` result.

    Always returns a list understood by the reporting layer: a text section
    with the narrative plus a small grid (model / usage / size), or a text
    section explaining why the summary is unavailable.
    """
    if not isinstance(result, dict):
        return [{'title': 'LLM Summary', 'type': 'text',
                 'content': 'LLM summary unavailable: malformed result.'}]
    if result.get('error'):
        return [{'title': 'LLM Summary', 'type': 'text',
                 'content': f"LLM summary unavailable: {result['error']}"}]

    summary = result.get('summary') or ''
    sections: List[Dict[str, Any]] = [{
        'title': 'LLM Summary (experimental)',
        'type': 'text',
        'content': summary or '(empty summary)',
    }]

    usage = result.get('usage') if isinstance(result.get('usage'), dict) else {}
    grid: Dict[str, Any] = {
        'Model': result.get('model', ''),
        'Characters': result.get('chars', len(summary)),
    }
    for key, label in (('prompt_tokens', 'Prompt tokens'),
                       ('completion_tokens', 'Completion tokens'),
                       ('total_tokens', 'Total tokens')):
        if usage.get(key) is not None:
            grid[label] = usage[key]
    if len(grid) > 1 or grid.get('Model'):
        sections.append({'title': 'LLM Details', 'type': 'grid', 'data': grid})
    return sections

"""
Example ObscuraLens plugin: the full SDK v2 showcase.

This is the "everything at once" example from ``docs/plugins.md``. It
declares one of each pluginable piece:

* ``PLUGIN_META``   — the manifest (api 2).
* ``SOURCES``       — an offline IP source (v1 contract, unchanged).
* ``COMMANDS``      — ``note`` prints a canned note for a target.
* ``REPORT_SECTIONS`` — ``notes`` renders a "PLUGIN NOTES" block for IP
  lookups; ``render`` receives the result envelope and returns lines.
* ``TOOLS``         — ``demo_echo`` is an MCP-shaped tool handler taking an
  ``arguments`` dict and returning a dict.
* ``ANALYTICS``     — ``demo_wordcount`` is a pure ``run(payload) -> dict``
  analytics hook.

None of these pieces are wired into the platform pipelines yet — they are
queryable through the loader registries (``plugin_report_sections()``,
``plugin_tools()``, ``plugin_analytics()``) and this file doubles as the
reference for their exact shapes. Validate it with::

    obscuralens plugins check plugins-examples/example_full.py
"""

import ipaddress

PLUGIN_META = {
    'name': 'obscuralens-example-full',
    'version': '2.0.0',
    'author': 'ObscuraLens contributors',
    'description': 'Showcase plugin: sources + commands + sections + tools + analytics.',
    'license': 'MIT',
    'url': 'https://github.com/AceGuru-mjh/ObscuraLens',
    'requires_api': 2,
}


# --- SOURCES (v1 contract) ---------------------------------------------------

def demo_full_ip_note(target: str) -> dict:
    """Return a deterministic note for special-use IP ranges."""
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        return {}

    notes = {
        '10.0.0.0/8': 'RFC 1918 private range',
        '172.16.0.0/12': 'RFC 1918 private range',
        '192.168.0.0/16': 'RFC 1918 private range',
        '127.0.0.0/8': 'loopback',
    }
    for network, note in notes.items():
        if address in ipaddress.ip_network(network):
            return {'full_ip_note': note, 'full_ip_version': address.version}
    return {'full_ip_note': 'globally routable address'}


SOURCES = {'ip': {'demo_full_ip_note': demo_full_ip_note}}


# --- COMMANDS ----------------------------------------------------------------

def note(args, ctx) -> int:
    """Print the same canned note the source would merge into a report."""
    target = getattr(args, 'target', '') or ''
    fields = demo_full_ip_note(target)
    if not fields:
        print(f'{target}: no note (not an IP address)')
        return 1
    print(f'{target}: {fields["full_ip_note"]}')
    return 0


COMMANDS = {
    'note': {
        'description': 'print the demo IP classification note for a target',
        'handler': note,
        'arguments': [
            {'name': 'target', 'help': 'IP address to classify',
             'required': True},
        ],
    },
}


# --- REPORT_SECTIONS ---------------------------------------------------------

def render_notes(envelope: dict) -> list:
    """Render the "PLUGIN NOTES" block for an IP lookup envelope."""
    target = envelope.get('target') or envelope.get('ip') or '?'
    fields = envelope.get('fields') or {}
    note = fields.get('full_ip_note') or 'no plugin note merged'
    return [
        f'PLUGIN NOTES ({target})',
        f'note: {note}',
        'rendered by the example_full showcase plugin',
    ]


REPORT_SECTIONS = {
    'notes': {
        'title': 'Plugin Notes',
        'kinds': ('ip',),
        'render': render_notes,
    },
}


# --- TOOLS (MCP-shaped) ------------------------------------------------------

def demo_echo(arguments: dict) -> dict:
    """Echo the arguments back with a wrapper envelope."""
    return {'tool': 'demo_echo', 'echo': dict(arguments or {})}


TOOLS = {
    'demo_echo': {
        'description': 'echo its arguments back (demo plugin tool)',
        'handler': demo_echo,
    },
}


# --- ANALYTICS ---------------------------------------------------------------

def demo_wordcount(payload: dict) -> dict:
    """Count words in payload['text'] — a pure, offline analytics hook."""
    text = (payload or {}).get('text') or ''
    words = [word for word in str(text).split() if word]
    return {'words': len(words), 'characters': len(str(text))}


ANALYTICS = {
    'demo_wordcount': {
        'description': 'count words and characters in payload["text"]',
        'run': demo_wordcount,
    },
}

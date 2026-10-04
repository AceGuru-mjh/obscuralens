"""
Example ObscuraLens plugin: plugin commands and the runtime context.

This is the "commands" example from ``docs/plugins.md``. It defines two CLI
commands that become available as::

    obscuralens plugins run hello --name Ada
    obscuralens plugins run db-peek --limit 20

``hello`` shows the argument declaration format (an option with a default).
``db-peek`` shows the interesting half of the SDK: the handler receives a
:class:`obscuralens.plugins.PluginContext` and reads the number of stored
history rows through ``ctx.db`` — a lazy handle to the platform database, so
a plugin never imports ObscuraLens internals itself.

Every handler is called as ``handler(args, ctx)`` where ``args`` is an
``argparse.Namespace`` built from the declared arguments and must return the
process exit code (an int). Note that this plugin deliberately declares no
``SOURCES``: a v2 plugin does not need to be a data source to be useful.

Validate it with::

    obscuralens plugins check plugins-examples/example_commands.py
"""

PLUGIN_META = {
    'name': 'obscuralens-example-commands',
    'version': '1.0.0',
    'author': 'ObscuraLens contributors',
    'description': 'Demo plugin commands (hello, db-peek) using PluginContext.',
    'license': 'MIT',
    'url': 'https://github.com/AceGuru-mjh/ObscuraLens',
    'requires_api': 2,
}


def hello(args, ctx) -> int:
    """Print a greeting; demonstrates a plugin option with a default."""
    name = getattr(args, 'name', 'world') or 'world'
    print(f'Hello, {name}!')
    print('(from the example_commands demo plugin)')
    return 0


def db_peek(args, ctx) -> int:
    """Count stored history rows through the lazy ``ctx.db`` handle."""
    limit = getattr(args, 'limit', 100) or 100
    try:
        limit = max(1, min(int(limit), 1000))
    except (TypeError, ValueError):
        limit = 100

    rows = ctx.db.get_history(limit=limit)
    print(f'history rows (most recent {limit}): {len(rows)}')

    kinds = {}
    for row in rows:
        kind = getattr(row, 'query_type', None) or 'unknown'
        kinds[kind] = kinds.get(kind, 0) + 1
    for kind in sorted(kinds):
        print(f'  {kind}: {kinds[kind]}')
    return 0


COMMANDS = {
    'hello': {
        'description': 'print a greeting from a plugin',
        'handler': hello,
        'arguments': [
            {'name': '--name', 'help': 'who to greet (default: world)',
             'required': False, 'default': 'world'},
        ],
    },
    'db-peek': {
        'description': 'count stored history rows via the plugin context',
        'handler': db_peek,
        'arguments': [
            {'name': '--limit', 'help': 'rows to inspect (default: 100)',
             'required': False, 'default': 100},
        ],
    },
}

# Plugins

ObscuraLens can load extra data sources — and, since plugin SDK v2, CLI
commands, report sections, MCP tools and analytics hooks — from plain Python
files: no packaging, no entry points, no restart of the installation. Drop a
file into a plugins directory and the next scan picks it up.

Plugin SDK v2 is **fully backward compatible**: every v1 plugin (a file with
only a `SOURCES` dict) loads exactly as it did before, with the same
merge/provenance behaviour and the same error isolation. The new pieces are
strictly optional and independently validated — a plugin that gets one piece
wrong still loads, the malformed piece is dropped and the reason is recorded.

## Where plugins are read from

`obscuralens.plugins.plugin_paths()` returns the directories that are scanned,
in priority order. Only directories that already exist are returned.

| Priority | Directory | Typical use |
|---|---|---|
| 1 | `<project_root>/plugins` | plugins shipped with a checkout |
| 2 | `<config_dir>/plugins` | per-user or per-machine plugins |

`<config_dir>` is whatever `OBSCURALENS_CONFIG_DIR`, a local `./config` folder
or the per-user configuration directory resolves to (see
`obscuralens/config.py`).

Within each directory the loader looks at `*.py` files only (non-recursive):

- files whose names start with `_` are ignored, so helper modules can live
  next to plugins;
- every file is imported under a unique internal module name, so two plugins
  in different directories may share the same file name;
- **source names** use last-wins semantics: when two plugins register the
  same source name, the plugin found later in the scan wins (later file name
  alphabetically, and above all the later directory — a per-user plugin
  overrides a project-level one);
- **plugin commands, tools and analytics names** use first-wins semantics:
  the earliest plugin in the scan keeps the name and the later plugin's
  surface records a collision error. Dropping a new file next to an existing
  one can therefore never silently swap an installed command.

## The v1 `SOURCES` contract (unchanged)

A data-source plugin is any scanned `.py` file that defines a module-level
`SOURCES` dictionary:

```python
SOURCES = {
    'ip': {'my_ip_source': lookup_ip},
    'domain': {'my_domain_source': lookup_domain},
}
```

- Supported kinds are the full platform registry: `ip`, `phone`, `username`,
  `email`, `domain`, `url`, `crypto`, `hash`, `cve`, `asn`, `mac`, `iban`,
  `imei`, `coords`, `vin`, `flight`, `mmsi`, `app`, `bssid` and `plate`. Any
  other kind, and any entry that is not a callable, is silently ignored.
- Each source is a callable that receives the target as a single string and
  returns a `dict` of fields, exactly like the built-in source readers.
- Return `{}` when the source has nothing to say (no hit, network failure,
  unsupported target) and never raise for ordinary errors. Unexpected
  exceptions are still caught and isolated per source by the trackers, so one
  misbehaving plugin cannot break a scan.
- Values can be strings, numbers, lists or nested dictionaries, as long as
  the report layer can render them. Use a distinctive field prefix (for
  example `example_note`) to avoid overwriting fields that built-in sources
  produce.

A file with neither `SOURCES` nor any v2 feature is reported as broken
(`SOURCES is missing or not a dict`) — exactly as in v1. A v2 plugin that
declares commands, sections, tools or analytics does **not** need `SOURCES`
at all.

The loader checks the `config.app_config.enable_plugins` flag (default
`True`). Set it to `false` under the `app` section of `config/config.yaml` to
switch plugin loading off; `load_plugins()` then returns an empty list and
every v2 registry is empty too.

## How plugin names appear in results

`plugin_sources('ip')` returns the plugin's own, unprefixed names:

```python
from obscuralens.plugins import plugin_sources

plugin_sources('ip')
# {'network_note': <function network_note at 0x...>}
```

When a tracker merges plugin output into a report, each source is prefixed
with `plugin:<file>:<name>`, where `<file>` is the plugin file name without
the `.py` extension. A source called `network_note` defined in
`plugins/example_ip_note.py` therefore appears in results as:

```text
plugin:example_ip_note:network_note
```

## Plugin SDK v2 overview

A v2 plugin may declare any combination of six module-level pieces:

| Piece | Attribute | Purpose | Merged how |
|---|---|---|---|
| manifest | `PLUGIN_META` (dict) | name/version/author/api gate | per plugin |
| data sources | `SOURCES` (dict) | the v1 contract | last-wins |
| commands | `COMMANDS` (dict) | `obscuralens plugins run <name>` | first-wins |
| report sections | `REPORT_SECTIONS` (dict) | extra report blocks | all kept |
| MCP tools | `TOOLS` (dict) | tool handlers for assistants | first-wins |
| analytics hooks | `ANALYTICS` (dict) | pure functions | first-wins |

All pieces are optional and validated independently by
`obscuralens.plugins.contracts.extract_plugin_surface()`. Wrong shapes are
dropped and recorded in `PluginSurface.errors` as `(piece, reason)` tuples —
never an exception. The loader stores the validated surface on
`PluginInfo.surface`, and the merged registries are queryable:

```python
from obscuralens import plugins

plugins.plugin_commands()         # {'hello': {'description', 'handler', 'arguments', 'plugin'}, ...}
plugins.plugin_report_sections()  # [{'name', 'title', 'kinds', 'render', 'safe_render', 'plugin'}, ...]
plugins.plugin_tools()            # {'demo_echo': {'description', 'handler', 'plugin'}, ...}
plugins.plugin_analytics()        # {'demo_wordcount': {'description', 'run', 'plugin'}, ...}
plugins.plugin_meta_list()        # [PluginMeta(...), ...] in scan order
```

### API version gating

`PLUGIN_META['requires_api']` declares the plugin API version a plugin was
written for; the platform supports `SUPPORTED_PLUGIN_API = 2`. A plugin that
asks for a newer API (for example a future `requires_api: 3`) still has its
`SOURCES` loaded — the v1 data contract is forever supported — but its v2
features are skipped and an `('api', 'requires_api 3 > 2')` error is recorded,
so newer plugins degrade gracefully instead of crashing older installations.
A plugin **without** `PLUGIN_META` is a v1 plugin: it gets a synthesized
manifest (name = file stem, version `'1.0.0'`, `requires_api 1`).

### The manifest: `PLUGIN_META`

```python
PLUGIN_META = {
    'name': 'my-org-ip-enrichment',   # display name (default: file stem)
    'version': '1.4.0',               # free-form, semver recommended
    'author': 'Alice Example',
    'description': 'Adds two offline enrichment sources.',
    'license': 'MIT',                 # SPDX id or license name
    'url': 'https://github.com/alice/ol-plugin',
    'requires_api': 2,                # plugin API version (default 2)
}
```

All scalar fields are string-coerced; a non-int `requires_api` falls back to
1 and is reported as a validation error by `plugins check`.

### Commands: `COMMANDS`

```python
def hello(args, ctx) -> int:
    """Handlers receive (argparse.Namespace, PluginContext) and return the exit code."""
    print(f'Hello, {args.name}!')
    return 0


COMMANDS = {
    'hello': {
        'description': 'print a greeting',
        'handler': hello,
        'arguments': [
            {'name': '--name', 'help': 'who to greet',
             'required': False, 'default': 'world'},
            {'name': 'target', 'help': 'a positional target', 'required': True},
        ],
    },
}
```

- `handler(args, ctx) -> int`: the return value becomes the process exit code
  (`None` counts as 0).
- `arguments` is a list of dicts with `name` (a positional identifier or an
  option spelling like `--name`), `help`, `required` (bool, default False),
  `default`, and optionally `choices` (a list of allowed values).
- Options may contain hyphens (`--db-peek` becomes the dest `db_peek`);
  positional names must be identifiers.
- Run a command with `obscuralens plugins run hello --name Ada` — the CLI
  builds an argparse parser from the declared arguments, forwards everything
  after the command name, and prints unrecognised extras as a warning.

### Report sections: `REPORT_SECTIONS`

```python
def render_notes(envelope: dict) -> list:
    """Renderers receive the result envelope and return a list of lines."""
    target = envelope.get('target') or '?'
    return [f'PLUGIN NOTE for {target}']


REPORT_SECTIONS = {
    'notes': {
        'title': 'Plugin Notes',     # section heading
        'kinds': ('ip', 'domain'),   # or 'all' (the default)
        'render': render_notes,
    },
}
```

- `kinds` restricts the section to envelopes whose `kind` matches; a section
  whose kinds do not cover the envelope declines politely (`[]`).
- `render` **must never raise**: the loader installs a `safe_render` wrapper
  that catches exceptions, tolerates bare strings and non-list returns, and
  substitutes a visible one-line error instead of breaking the report.
- Render one programmatically with
  `plugins.render_report_section('notes', envelope)` (bare name: first plugin
  wins; qualified `'plugin_file:notes'` form always reaches the right one).

### MCP tools: `TOOLS`

```python
def demo_echo(arguments: dict) -> dict:
    return {'echo': dict(arguments or {})}


TOOLS = {
    'demo_echo': {
        'description': 'echo its arguments back',
        'handler': demo_echo,      # handler(arguments: dict) -> dict
    },
}
```

Tools are validated and queryable through `plugin_tools()`; exposing them on
the MCP server is planned follow-up work — the contract ships now so plugin
authors can write against a stable surface.

### Analytics hooks: `ANALYTICS`

```python
def demo_wordcount(payload: dict) -> dict:
    text = str((payload or {}).get('text', ''))
    return {'words': len(text.split()), 'characters': len(text)}


ANALYTICS = {
    'demo_wordcount': {
        'description': 'count words and characters in payload["text"]',
        'run': demo_wordcount,     # run(payload: dict) -> dict, pure function
    },
}
```

Analytics hooks must be pure functions: no platform state, no I/O, no
exceptions for ordinary errors. Query them with `plugin_analytics()`.

## The `PluginContext` reference

Command handlers receive a fresh `PluginContext` as their second argument.
Every handle is resolved **lazily on first access**, so a plugin that only
prints a greeting never touches the database, the cache or the metrics
registry.

| Property | Type | Resolves to | Notes |
|---|---|---|---|
| `ctx.config` | `ConfigManager` | `obscuralens.config.config` | live config: `app_config`, service keys |
| `ctx.db` | `DatabaseManager` | `obscuralens.database.db` | `get_history()`, `search_history()`, ... |
| `ctx.cache` | `HttpCache` | `obscuralens.core.cache.cache` | `get(namespace, key)` / `set(...)` / `clear()` |
| `ctx.metrics` | `NetworkMetrics` | `obscuralens.core.metrics.metrics` | `snapshot()` for request/cache/failure counters |
| `ctx.http` | `PluginHTTP` | wrapper over the platform HTTP client | `get(url, params=None)` and `get_text(...)`: never raise, return `None` on failure |
| `ctx.temp_dir` | `Path` | `<system temp>/obscuralens-plugins` | created on first access, then cached |

```python
def db_peek(args, ctx) -> int:
    rows = ctx.db.get_history(limit=args.limit)
    print(f'{len(rows)} history rows')
    return 0
```

`ctx.http` shares the platform client's timeouts, retries, proxy settings,
rate limiting, response cache and metrics — a plugin cannot accidentally
bypass them with a raw `requests` call.

## The `plugins` CLI

```
obscuralens plugins list                    # loaded plugins + v2 surface summary
obscuralens plugins reload                  # rescan the plugin directories
obscuralens plugins check <file>            # validate one plugin file (linter)
obscuralens plugins run <command> [args...] # run a plugin command
```

### `plugins list`

The familiar table (name, kinds, sources, error, path) gains a `version` and
a `v2` column summarising each plugin's manifest and piece counts, e.g.
`api 2: 1 cmd, 1 sec, 1 tools, 1 analytics`. In JSON format every row keeps
its v1 keys and gains `meta` (the manifest dict) and `surface`
(`commands`/`report_sections`/`tools`/`analytics` name lists plus `errors`).
Surface problems and the available command list are printed to stderr, so
stdout stays machine-parseable.

### `plugins check <file>` — the plugin authoring linter

Loads one file in isolation (under a throw-away module name, cleaned out of
`sys.modules` afterwards — a check never pollutes the real plugin cache) and
reports everything the production loader would find:

```text
$ obscuralens plugins check plugins-examples/example_full.py
plugin file: plugins-examples/example_full.py
ok: yes
meta: obscuralens-example-full 2.0.0 (api 2) by ObscuraLens contributors
      Showcase plugin: sources + commands + sections + tools + analytics.
      license: MIT
      url: https://github.com/AceGuru-mjh/ObscuraLens
sources: ip: demo_full_ip_note
commands: note (print the demo IP classification note for a target)
report sections: notes [Plugin Notes] kinds=ip
tools: demo_echo (echo its arguments back (demo plugin tool))
analytics: demo_wordcount (count words and characters in payload["text"])
errors: (none)
```

Exit code 0 when the file is valid, 1 when it is not (syntax error, dropped
pieces, or a `requires_api` newer than this platform). `--format json`
returns the full machine-readable report.

### `plugins run <command> [args...]`

Dispatches a plugin command by name. Everything after the command name is
forwarded to the plugin's own argparse parser (built from its declared
arguments):

```text
$ obscuralens plugins run hello --name Ada
Hello, Ada!
(from the example_commands demo plugin)
```

Unknown commands exit 2 and list the known ones; the handler's return value
becomes the exit code.

## Error isolation and reloading

Plugin loading is lazy and cached; `loaded_plugins()` returns the cached
`PluginInfo` list and `load_plugins()` scans only on first use. A plugin that
raises while importing (syntax error, missing dependency, ...) or that
defines a missing or malformed `SOURCES` mapping (and no v2 features) is
skipped and recorded with a non-empty `error` in its `PluginInfo`; all other
plugins still load, and no exception ever escapes the loader.

`PluginInfo` carries:

| Field | Meaning |
|---|---|
| `name` | plugin file name without `.py` (the stem) |
| `path` | absolute path of the plugin file |
| `kinds` | sorted list of supported kinds it registers |
| `sources` | `{kind: [sorted source names]}` |
| `error` | empty on success, otherwise the failure description |
| `surface` | the validated v2 surface (`None` when the import failed) |

`reload_plugins()` (equivalent to `load_plugins(force=True)`) rescans both
directories and refreshes `sys.modules`, so a newly added or fixed plugin is
picked up without restarting the process. The v2 registries are rebuilt on
every rescan.

## The shipped example plugins

Three documented, fully offline examples live in
[`plugins-examples/`](../plugins-examples/) at the repository root. Copy them
into your own plugin directory (or add the directory to `plugin_paths()` in
tests) to try them out.

### 1. `example_source_pack.py` — a v2 source pack

The smallest useful v2 plugin: a `PLUGIN_META` manifest plus two
deterministic offline sources — `demo_ip_info` (classifies an IP with the
standard library) and `demo_domain_tags` (pseudo-tags from the domain shape).
It demonstrates provenance merging: its fields use `demo_ip_*` /
`demo_domain_*` prefixes, so they flow through the same merge machinery as
built-in sources and appear attributed to
`plugin:example_source_pack:demo_ip_info` without ever overwriting built-in
fields.

### 2. `example_commands.py` — commands and `PluginContext`

Defines `COMMANDS` with two entries: `hello` (an option with a default,
`obscuralens plugins run hello --name Ada`) and `db-peek` (counts stored
history rows through the lazy `ctx.db` handle). It deliberately declares no
`SOURCES` — proof that a v2 plugin does not need to be a data source.

### 3. `example_full.py` — the showcase

One of everything: `SOURCES` (`demo_full_ip_note`), `COMMANDS` (`note`),
`REPORT_SECTIONS` (`notes`, rendering a "PLUGIN NOTES" block for IP lookups
via the kind gate), `TOOLS` (`demo_echo`) and `ANALYTICS`
(`demo_wordcount`). Use it as the reference for every piece's exact shape.

Validate all three with:

```console
$ obscuralens plugins check plugins-examples/example_source_pack.py
$ obscuralens plugins check plugins-examples/example_commands.py
$ obscuralens plugins check plugins-examples/example_full.py
```

## A complete v2 plugin skeleton

Copy this skeleton, delete the pieces you do not need, and validate with
`obscuralens plugins check <file>`:

```python
"""One-line description of my plugin."""

PLUGIN_META = {
    'name': 'my-plugin',
    'version': '1.0.0',
    'author': 'Your Name',
    'description': 'What this plugin adds.',
    'license': 'MIT',
    'url': 'https://example.com/my-plugin',
    'requires_api': 2,
}


# --- data sources (optional, v1 contract) ----------------------------------

def my_ip_source(target: str) -> dict:
    """Return fields, {} when nothing to say; never raise."""
    return {'my_note': f'seen {target}'}


SOURCES = {'ip': {'my_source': my_ip_source}}


# --- commands (optional) ----------------------------------------------------

def my_command(args, ctx) -> int:
    print('doing something useful')
    return 0


COMMANDS = {
    'my-command': {
        'description': 'does something useful',
        'handler': my_command,
        'arguments': [
            {'name': '--verbose', 'help': 'chatty output', 'required': False},
        ],
    },
}


# --- report sections (optional) --------------------------------------------

def my_section(envelope: dict) -> list:
    return ['MY PLUGIN section line']


REPORT_SECTIONS = {
    'my-section': {'title': 'My Plugin', 'kinds': ('ip',), 'render': my_section},
}


# --- MCP tools (optional) ---------------------------------------------------

def my_tool(arguments: dict) -> dict:
    return {'ok': True}


TOOLS = {'my-tool': {'description': 'a demo tool', 'handler': my_tool}}


# --- analytics hooks (optional) ---------------------------------------------

def my_analytics(payload: dict) -> dict:
    return {'count': len(payload)}


ANALYTICS = {'my-analytics': {'description': 'counts payload keys',
                              'run': my_analytics}}
```

## Shell completion

The CLI ships generated completions for bash, zsh and fish, driven by the
real command table (commands, nested subcommands, positionals and option
value sets such as `--format` and `--kind`):

```console
$ obscuralens completion bash
$ obscuralens completion zsh
$ obscuralens completion fish
```

The script is always printed to stdout; an install hint goes to stderr (use
`--stdout` to silence it, or `-o FILE` to write the script to a file).
Exit code 1 on an unknown shell.

Install per shell:

| Shell | Command | Location |
|---|---|---|
| bash | `obscuralens completion bash \| sudo tee /etc/bash_completion.d/obscuralens >/dev/null` | `/etc/bash_completion.d/obscuralens` |
| bash (user) | `obscuralens completion bash > ~/.local/share/bash-completion/completions/obscuralens` | `~/.local/share/bash-completion/completions/` |
| zsh | `obscuralens completion zsh > ~/.zsh/completions/_obscuralens` | `~/.zsh/completions/_obscuralens` (must be on `$fpath`) |
| fish | `obscuralens completion fish > ~/.config/fish/completions/obscuralens.fish` | `~/.config/fish/completions/obscuralens.fish` |

For zsh make sure the directory is on `$fpath` before `compinit` runs, e.g.
in `~/.zshrc`:

```zsh
fpath=(~/.zsh/completions $fpath)
autoload -Uz compinit && compinit
```

The scripts are regenerated from the live parser, so they always cover the
commands your installation knows (including plugin commands after a reload —
rerun the generator if you add or remove plugins). The generator never
crashes on argparse internals drift: it degrades to an empty command tree
with a captured warning.

## Plugin authoring checklist

1. **Start from the skeleton** (or from `plugins-examples/example_full.py`)
   and delete the pieces you do not need.
2. **Declare `PLUGIN_META`** with a stable `name`, a real `version` and
   `requires_api: 2`.
3. **Prefix your fields** (`myorg_*`) so you never overwrite built-in
   sources' fields; return `{}` when you have nothing to say.
4. **Never raise for ordinary errors** — in sources, renderers, tools and
   analytics alike. Return `{}`, `[]` or an error dict instead.
5. **Keep handlers honest**: commands return an int exit code, tools return
   a dict, analytics stays pure.
6. **Use `ctx` handles lazily** — do not import ObscuraLens internals
   yourself; `ctx.db`/`ctx.config`/`ctx.cache`/`ctx.metrics`/`ctx.http` are
   resolved only when touched.
7. **Validate before installing**: `obscuralens plugins check <file>` must
   print `ok: yes` and no errors.
8. **Install**: copy the file into `<config_dir>/plugins/` (or
   `<project_root>/plugins/`), then `obscuralens plugins reload` and confirm
   with `obscuralens plugins list`.
9. **Re-check collisions**: if `plugins list` reports a command/tool
   collision error, rename yours — first-wins means the earlier plugin kept
   the name.
10. **Regenerate completions** if your plugin adds commands users should be
    able to tab-complete: `obscuralens completion bash > ...` after a reload.

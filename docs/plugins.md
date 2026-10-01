# Plugins

ObscuraLens can load extra data sources from plain Python files: no packaging,
no entry points, no restart of the installation. Drop a file into a plugins
directory and the next scan picks it up.

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
- when two plugins register the same source name, the plugin found later in
  the scan wins: later file name (alphabetical) inside one directory, and
  above all the later directory. A per-user plugin therefore overrides a
  project-level plugin with the same source name.

## The `SOURCES` contract

A plugin is any scanned `.py` file that defines a module-level `SOURCES`
dictionary:

```python
SOURCES = {
    'ip': {'my_ip_source': lookup_ip},
    'domain': {'my_domain_source': lookup_domain},
}
```

- Supported kinds: `ip`, `phone`, `username`, `email` and `domain`. Any other
  kind, and any entry that is not a callable, is silently ignored.
- Each source is a callable that receives the target as a single string and
  returns a `dict` of fields, exactly like the built-in source readers.
- Return `{}` when the source has nothing to say (no hit, network failure,
  unsupported target) and never raise for ordinary errors. Unexpected
  exceptions are still caught and isolated per source by the trackers, so one
  misbehaving plugin cannot break a scan.
- Values can be strings, numbers, lists or nested dictionaries, as long as the
  report layer can render them. Use a distinctive field prefix (for example
  `example_note`) to avoid overwriting fields that built-in sources produce.

The loader checks the `config.app_config.enable_plugins` flag (default
`True`). Set it to `false` under the `app` section of `config/config.yaml` to
switch plugin loading off; `load_plugins()` then returns an empty list.

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

## Error isolation and reloading

Plugin loading is lazy and cached; `loaded_plugins()` returns the cached
`PluginInfo` list and `load_plugins()` scans only on first use. A plugin that
raises while importing (syntax error, missing dependency, ...) or that defines
a missing or malformed `SOURCES` mapping is skipped and recorded with a
non-empty `error` in its `PluginInfo`; all other plugins still load, and no
exception ever escapes the loader.

`PluginInfo` carries:

| Field | Meaning |
|---|---|
| `name` | plugin file name without `.py` (the stem) |
| `path` | absolute path of the plugin file |
| `kinds` | sorted list of supported kinds it registers |
| `sources` | `{kind: [sorted source names]}` |
| `error` | empty on success, otherwise the failure description |

`reload_plugins()` (equivalent to `load_plugins(force=True)`) rescans both
directories and refreshes `sys.modules`, so a newly added or fixed plugin is
picked up without restarting the process.

## Worked example: a "network note" plugin

Save the following as `plugins/example_ip_note.py` (the project-level
directory, so it is shared with the checkout). This example is intentionally
offline: it classifies special-use IP ranges with the standard library and
makes no network calls.

```python
"""
Example ObscuraLens plugin: a static "network note" for IP addresses.

This is documentation, not production code. It performs no network calls and
returns canned text based on the standard library's `ipaddress` module, so it
is safe to run offline. Copy it into your plugins directory and replace the
`SOURCES` mapping with your own readers.
"""

import ipaddress

# Special-use networks and the note they should produce.
NETWORK_NOTES = {
    '10.0.0.0/8': 'RFC 1918 private network',
    '172.16.0.0/12': 'RFC 1918 private network',
    '192.168.0.0/16': 'RFC 1918 private network',
    '100.64.0.0/10': 'Carrier-grade NAT (RFC 6598)',
    '127.0.0.0/8': 'Loopback',
    '169.254.0.0/16': 'Link-local (APIPA)',
    '224.0.0.0/4': 'Multicast',
    '240.0.0.0/4': 'Reserved',
}


def network_note(target: str) -> dict:
    """Return a note describing the IP range, or {} when unknown."""
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        return {}

    for network, note in NETWORK_NOTES.items():
        if address in ipaddress.ip_network(network):
            return {
                'network_note': note,
                'network_note_version': address.version,
            }
    return {}


SOURCES = {'ip': {'network_note': network_note}}
```

After saving the file, run an IP lookup. The report shows the extra fields
under the source name `plugin:example_ip_note:network_note`, for example:

```text
plugin:example_ip_note:network_note          RFC 1918 private network
plugin:example_ip_note:network_note_version  4
```

Fields flow through the same merge and provenance machinery as built-in
sources: a plugin field appears only when the plugin returns it, and other
sources are never affected when it returns `{}`.

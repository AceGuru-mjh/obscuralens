"""
Example ObscuraLens plugin: a deterministic offline source pack.

This is the "v2 meta'd SOURCES plugin" example from ``docs/plugins.md``. It
demonstrates the smallest useful SDK v2 plugin: a ``PLUGIN_META`` manifest
plus two completely offline data sources that behave exactly like built-in
readers — they receive the target as a string, return a ``dict`` of fields,
return ``{}`` when they have nothing to say and never raise for ordinary
errors.

Because the returned fields use distinctive prefixes (``demo_ip_*`` and
``demo_domain_*``), they flow through the same merge and provenance
machinery as built-in sources: each field appears in reports attributed to
``plugin:example_source_pack:<source>`` and never overwrites a field that a
built-in source already produced.

Copy this file into one of your plugin directories (see
``obscuralens.plugins.plugin_paths()``) and run::

    obscuralens ip 8.8.8.8
    obscuralens domain example.com

to see the demo fields merged into the reports, or validate it with::

    obscuralens plugins check plugins-examples/example_source_pack.py
"""

import ipaddress

PLUGIN_META = {
    'name': 'obscuralens-example-source-pack',
    'version': '1.2.0',
    'author': 'ObscuraLens contributors',
    'description': 'Two deterministic offline demo sources (ip + domain).',
    'license': 'MIT',
    'url': 'https://github.com/AceGuru-mjh/ObscuraLens',
    'requires_api': 2,
}

# Simple tags the domain source reports for a few well-known suffixes.
_DOMAIN_TAGS = {
    '.org': 'non-commercial registry',
    '.edu': 'accredited education registry',
    '.gov': 'united states government',
    '.io': 'tech-startup favourite',
    '.dev': 'developer hosting',
    '.local': 'link-local, not globally resolvable',
}


def demo_ip_info(target: str) -> dict:
    """Classify an IP address offline (deterministic, never networked)."""
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        return {}  # not an IP: stay quiet, exactly like a built-in reader

    octets = str(address).split('.') if address.version == 4 else []
    info = {
        'demo_ip_version': address.version,
        'demo_ip_is_global': address.is_global,
        'demo_ip_is_private': address.is_private,
        'demo_ip_is_multicast': address.is_multicast,
    }
    if octets:
        info['demo_ip_first_octet'] = int(octets[0])
    if address.version == 6:
        info['demo_ip_teredo'] = address.teredo is not None
    return info


def demo_domain_tags(target: str) -> dict:
    """Return deterministic pseudo-tags derived from the domain shape."""
    domain = (target or '').strip().lower()
    if not domain or domain.endswith('.') or ' ' in domain:
        return {}

    tags = []
    for suffix, note in _DOMAIN_TAGS.items():
        if domain.endswith(suffix):
            tags.append(note)
    labels = domain.split('.')
    if len(labels) >= 3:
        tags.append('multi-label host name')
    if labels[-1].startswith('xn--'):
        tags.append('punycode top label')

    fields = {'demo_domain_label_count': len(labels)}
    if tags:
        fields['demo_domain_tags'] = tags
    return fields


SOURCES = {
    'ip': {'demo_ip_info': demo_ip_info},
    'domain': {'demo_domain_tags': demo_domain_tags},
}

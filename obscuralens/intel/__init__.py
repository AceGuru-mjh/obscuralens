"""
Threat intelligence: Tor exit/relay lookups and blocklist feed checks.

The package is keyless and offline-friendly: every public function degrades
to a safe default instead of raising, so trackers and the CLI can layer
threat-intel context onto any IP report without new failure modes.
"""

from .feeds import check_ip, feeds_sections, feeds_status, intel_sections
from .tor import is_tor_exit, load_exit_nodes, relay_details, tor_sections

__all__ = [
    'check_ip',
    'feeds_sections',
    'feeds_status',
    'intel_sections',
    'is_tor_exit',
    'load_exit_nodes',
    'relay_details',
    'tor_sections',
]

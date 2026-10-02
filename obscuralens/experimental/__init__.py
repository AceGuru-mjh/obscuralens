"""
Experimental features package for ObscuraLens v4.0 (EXPERIMENTAL).

Opt-in modules that trade guarantees for capability. None of them are wired
into the default CLI paths; callers decide when to enable them and are
expected to check ``config.app_config.experimental_features`` semantics:

* ``llm_summary``          - narrative summaries via an OpenAI-compatible API.
* ``username_permutations`` - username variant generation + platform sweep.
* ``web_crawler``          - bounded, robots-aware same-domain crawler.
* ``phishing_score``       - explainable heuristic phishing likelihood score.

Every public function is defensive: it returns error dictionaries instead of
raising, so an experimental feature can never take down a scan.

Modules are imported lazily (PEP 562) so ``import obscuralens.experimental``
stays cheap and a broken optional dependency cannot break the package import.
"""

import importlib
from typing import Any

__all__ = [
    'llm_summary',
    'username_permutations',
    'web_crawler',
    'phishing_score',
]

_SUBMODULES = frozenset(__all__)


def __getattr__(name: str) -> Any:
    """Lazy-import a submodule on first attribute access."""
    if name in _SUBMODULES:
        return importlib.import_module(f'{__name__}.{name}')
    raise AttributeError(f'module {__name__!r} has no attribute {name!r}')


def __dir__() -> list:
    return sorted(set(globals()) | _SUBMODULES)

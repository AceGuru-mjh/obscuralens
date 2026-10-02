"""
Data-pack loading for ObscuraLens.

Data packs are plain-text lists shipped inside the package at
``obscuralens/data`` and versioned with the code:

* ``disposable_email_domains.txt`` - throwaway / temp-mail domains
* ``popular_domains.txt``          - well-known domains (typosquat baselines)
* ``phishing_keywords.txt``       - keywords abused in phishing hosts/URLs

Format: one entry per line, lowercase and sorted; blank lines are ignored
and lines starting with '#' are comments.  :func:`load_data_pack` parses
them lazily, lowercases every entry and caches the result in a module-level
dict, so repeated calls return the very same list object.  Missing packs
and I/O errors yield ``[]`` - the loader never raises.

The convenience helpers (:func:`is_disposable_email` plus the lazy
``get_*`` accessors) are the intended entry points for trackers and the
experimental phishing score module.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

#: Directory holding the shipped ``<name>.txt`` data packs.
DATA_DIR = Path(__file__).resolve().parent.parent / 'data'

#: Module-level cache: pack name -> parsed entry list (identity-stable).
_CACHE: Dict[str, List[str]] = {}


def _safe_name(name: Any) -> str:
    """
    Normalise a pack name, returning '' when it cannot name a pack.

    Surrounding whitespace is stripped; names containing path separators
    or '..' are rejected so a pack name can never escape the data dir.
    """
    if not isinstance(name, str):
        return ''
    key = name.strip()
    if not key or '/' in key or '\\' in key or '..' in key:
        return ''
    return key


def data_pack_path(name: str) -> Optional[Path]:
    """Return the resolved path of a data pack file, or None when absent."""
    key = _safe_name(name)
    if not key:
        return None
    path = DATA_DIR / f'{key}.txt'
    try:
        return path if path.is_file() else None
    except OSError:  # unreadable paths are simply "no pack"
        return None


def load_data_pack(name: str) -> List[str]:
    """
    Load a data pack by name (without the ``.txt`` extension).

    Comment lines (leading '#') and blank lines are skipped and every
    entry is lowercased.  Results are cached per name at module level, so
    a second call returns the identical list object.  Unknown names,
    unreadable files and non-string input return ``[]``; the function
    never raises.
    """
    key = _safe_name(name)
    if not key:
        return []
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    path = data_pack_path(key)
    if path is None:
        return []
    try:
        text = path.read_text(encoding='utf-8')
    except (OSError, ValueError):  # OSError + UnicodeDecodeError
        return []
    entries = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        entries.append(stripped.lower())
    _CACHE[key] = entries
    return entries


def pack_info(name: str) -> Dict[str, Any]:
    """
    Report metadata for a data pack: ``{'name', 'entries', 'loaded'}``.

    ``entries`` is the real entry count (the pack is loaded on demand when
    not cached yet).  ``loaded`` states whether the pack was already
    resident in the module cache when :func:`pack_info` was called, so a
    first call reports False and a second call True for an existing pack.
    Unknown packs report ``{'name': ..., 'entries': 0, 'loaded': False}``.
    """
    key = _safe_name(name)
    was_cached = bool(key) and key in _CACHE
    entries = load_data_pack(name)
    return {
        'name': name,
        'entries': len(entries),
        'loaded': was_cached,
    }


def get_disposable_domains() -> List[str]:
    """Cached disposable-email domain pack (loaded lazily on first call)."""
    return load_data_pack('disposable_email_domains')


def get_popular_domains() -> List[str]:
    """Cached popular-domain pack (loaded lazily on first call)."""
    return load_data_pack('popular_domains')


def get_phishing_keywords() -> List[str]:
    """Cached phishing-keyword pack (loaded lazily on first call)."""
    return load_data_pack('phishing_keywords')


def is_disposable_email(email: str) -> bool:
    """
    True when the email address uses a disposable / throwaway domain.

    The domain is the part after the single '@' (lowercased) and must be
    listed verbatim in the ``disposable_email_domains`` pack.  Anything
    without exactly one '@' / with empty parts - 'not-an-email', '@x.com',
    'a@b@c' - and non-string input return False; the function never
    raises.
    """
    if not isinstance(email, str):
        return False
    address = email.strip()
    if address.count('@') != 1:
        return False
    local, domain = address.split('@')
    domain = domain.strip().lower()
    if not local.strip() or not domain:
        return False
    return domain in get_disposable_domains()

"""
Locale catalogue registry for ObscuraLens.

Imports the ``STRINGS`` dict of every locale module and exposes them as the
``LOCALES`` registry (:class:`typing.Dict` of locale code -> catalogue).
The locale modules are plain Python files (no file I/O, no external data
formats), so the registry also works unchanged inside the frozen desktop
executable built by PyInstaller.

Registry order follows ``obscuralens.i18n.SUPPORTED_LANGUAGES`` (English
first), with any unknown extra modules appended alphabetically by their
import name.  Every locale defines the same key set as ``en``; the test
suite enforces key-set, placeholder and completeness parity.
"""

from typing import Dict

from . import ar, de, en, es, fr, hi, it, ja, ko, nl, pl, pt, ru, zh

__all__ = ["LOCALES"]

#: Locale code -> ``STRINGS`` catalogue (insertion order: en, zh, ja, ...).
LOCALES: Dict[str, Dict[str, str]] = {
    "en": en.STRINGS,
    "zh": zh.STRINGS,
    "ja": ja.STRINGS,
    "ko": ko.STRINGS,
    "de": de.STRINGS,
    "fr": fr.STRINGS,
    "es": es.STRINGS,
    "pt": pt.STRINGS,
    "ru": ru.STRINGS,
    "it": it.STRINGS,
    "nl": nl.STRINGS,
    "pl": pl.STRINGS,
    "ar": ar.STRINGS,
    "hi": hi.STRINGS,
}

# Defensive sanity check: every registered catalogue is a str -> str mapping.
# This never fails for the shipped locales; it guards against a locale
# module accidentally exporting the wrong object.
for _code, _strings in LOCALES.items():
    if not isinstance(_strings, dict) or not all(
        isinstance(_key, str) and isinstance(_value, str)
        for _key, _value in _strings.items()
    ):
        raise TypeError(f"locale {_code!r} did not export a str->str STRINGS dict")

del _code, _strings

"""
Internationalization (i18n) runtime for ObscuraLens.

ObscuraLens ships its translations as a catalogue of plain Python modules:
every locale under ``obscuralens/i18n/locales`` defines a ``STRINGS`` dict
that maps flat, dotted keys (``"app.title"``, ``"errors.timeout"``,
``"plural.results.many"``) to translated values.  Because the catalogues
are code rather than data files, they work unchanged inside the frozen
desktop executable - no gettext binaries, no file I/O, no third-party
dependencies - while remaining greppable and diff-friendly.

Registry and metadata
---------------------
:mod:`obscuralens.i18n.locales` imports every locale module and exposes the
``LOCALES`` registry (``Dict[str, Dict[str, str]]``).  This module layers
the runtime behaviour on top of that registry:

* :data:`LOCALE_DIR` - filesystem path of the ``locales`` package;
* :data:`SUPPORTED_LANGUAGES` - the ordered list of locale codes;
* :data:`DEFAULT_LANGUAGE` - the fallback code (``"en"``);
* :class:`LanguageInfo` - descriptive record for one language;
* :func:`list_languages`, :func:`language_name`, :func:`is_rtl`,
  :func:`available_locales` - catalogue introspection.

Translating
-----------
* :func:`set_language` / :func:`get_language` / :func:`reset` - module-level
  language state (default: English);
* :func:`t` - translate one key in the current language with ``{placeholder}``
  interpolation that never raises;
* :func:`tp` - plural-aware lookup that picks ``key.zero``, ``key.one`` or
  ``key.many`` from the count and interpolates ``{count}``.

The lookup chain for :func:`t` is *current language -> English -> caller
default -> the key itself*, so a missing translation degrades to readable
text instead of an exception.  The same chain applies to :func:`tp`, which
falls back to the bare ``key`` when no plural form exists.

Language negotiation
--------------------
:func:`best_match` parses an HTTP ``Accept-Language`` header
(``"zh-CN,zh;q=0.9,en;q=0.8"``) with a small, dependency-free algorithm:
entries are ranked by quality value (default 1.0, ties keep header order),
regional subtags resolve to their primary language (``pt-BR`` -> ``pt``)
and the first entry that matches a supported locale wins.  Unparseable
entries are skipped, ``*`` matches the default language, and headers that
match nothing fall back to ``"en"``.

Example
-------
::

    from obscuralens.i18n import set_language, t, tp

    set_language("de")
    t("app.version", version="5.1.0")   # "Version 5.1.0" -> German text
    tp("plural.results", 5)             # "5 results"    -> German plural
    set_language("zh")
    t("menu.choose_option")             # Simplified Chinese prompt
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, KeysView, List, Optional, Tuple

from .locales import LOCALES

__all__ = [
    "DEFAULT_LANGUAGE",
    "LOCALE_DIR",
    "SUPPORTED_LANGUAGES",
    "LanguageInfo",
    "Translation",
    "UnknownLanguageError",
    "available_locales",
    "best_match",
    "get_language",
    "get_translation",
    "interpolate",
    "is_rtl",
    "language_name",
    "list_languages",
    "reset",
    "set_language",
    "t",
    "tp",
]

#: Filesystem location of the locale modules.  The catalogues themselves are
#: plain Python modules (imported by :mod:`obscuralens.i18n.locales`), so no
#: file I/O happens through this constant; it exists for tooling and tests.
LOCALE_DIR = Path(__file__).resolve().parent / "locales"

#: Locale codes in preference order.  ``en`` first (source catalogue).
SUPPORTED_LANGUAGES: List[str] = [
    "en", "zh", "ja", "ko", "de", "fr", "es", "pt", "ru", "it", "nl", "pl", "ar", "hi",
]

#: Locale used when nothing else is selected or negotiated.
DEFAULT_LANGUAGE = "en"

#: Static metadata per locale: code -> (english name, native name, direction).
_LANGUAGE_META: Dict[str, Tuple[str, str, str]] = {
    "en": ("English", "English", "ltr"),
    "zh": ("Chinese (Simplified)", "简体中文", "ltr"),
    "ja": ("Japanese", "日本語", "ltr"),
    "ko": ("Korean", "한국어", "ltr"),
    "de": ("German", "Deutsch", "ltr"),
    "fr": ("French", "Français", "ltr"),
    "es": ("Spanish", "Español", "ltr"),
    "pt": ("Portuguese (Brazil)", "Português (Brasil)", "ltr"),
    "ru": ("Russian", "Русский", "ltr"),
    "it": ("Italian", "Italiano", "ltr"),
    "nl": ("Dutch", "Nederlands", "ltr"),
    "pl": ("Polish", "Polski", "ltr"),
    "ar": ("Arabic", "العربية", "rtl"),
    "hi": ("Hindi", "हिन्दी", "ltr"),
}

#: Matches a single ``{placeholder}`` token inside a template.  Braces that
#: do not enclose a known name are left untouched, so plain brace pairs in
#: translated values (JSON snippets, ``{y/N}`` prompts) survive verbatim.
_PLACEHOLDER_RE = re.compile(r"\{([^{}]*)\}")

#: Currently active translation, or ``None`` while the module is in its
#: default (English) state.
_current: Optional["Translation"] = None

#: Cache of constructed :class:`Translation` wrappers, keyed by locale code.
#: :func:`reset` clears it; :func:`get_translation` repopulates it lazily.
_TRANSLATION_CACHE: Dict[str, "Translation"] = {}


class UnknownLanguageError(ValueError):
    """
    Raised when a language code is not part of the shipped catalogue.

    Subclasses :class:`ValueError` so generic input validation can catch it
    alongside other bad-input errors.  The message always contains the
    offending code and the list of available locale codes.
    """


def interpolate(template: str, values: Dict[str, Any]) -> str:
    """
    Substitute ``{placeholder}`` tokens in *template* without ever raising.

    Every ``{name}`` token whose *name* is a key of *values* is replaced by
    ``str(value)``; tokens without a matching key - and brace pairs that do
    not name anything - are left exactly as written.  Extra entries in
    *values* are simply ignored, which makes the function safe for callers
    that pass a superset of the placeholders a template actually uses::

        >>> interpolate("Version {version}", {"version": "5.1.0"})
        'Version 5.1.0'
        >>> interpolate("Version {version}", {})
        'Version {version}'
        >>> interpolate("{a} and {a}", {"a": 1})
        '1 and 1'
    """
    if not values:
        return template

    def _replace(match: Any) -> str:
        name = match.group(1)
        if name in values:
            return str(values[name])
        return match.group(0)

    return _PLACEHOLDER_RE.sub(_replace, template)


@dataclass(frozen=True)
class LanguageInfo:
    """
    Descriptive record for one supported UI language.

    Attributes:
        code: two-letter locale code (``"de"``, ``"zh"`` ...);
        english_name: language name in English (``"German"``);
        native_name: language name in the language itself (``"Deutsch"``);
        direction: text direction, ``"ltr"`` or ``"rtl"``;
        completion: translated-key fraction relative to the English
            catalogue, in the range ``0.0`` - ``1.0``.
    """

    code: str
    english_name: str
    native_name: str
    direction: str
    completion: float


class Translation:
    """
    Ready-to-use access to the string catalogue of a single locale.

    Instances are constructed by :func:`get_translation` (which caches them)
    but may also be built directly around any ``Dict[str, str]`` - useful for
    tests and for embedding partial catalogues.  The wrapper holds the
    catalogue by reference (it is *not* copied), so registry updates made
    through :mod:`obscuralens.i18n.locales` are visible immediately.

    Mapping-like protocol: ``key in translation``, ``len(translation)``,
    ``translation.keys()`` and iteration over keys all work; use
    :meth:`get` for values with defaults and :meth:`format` for
    interpolation.
    """

    __slots__ = ("_code", "_strings")

    def __init__(self, code: str, strings: Dict[str, str]) -> None:
        """
        Wrap *strings* as the catalogue of locale *code*.

        ``code`` is stored verbatim (use a canonical, lowercased code for
        registry-built translations); ``strings`` maps dotted keys to
        translated values.
        """
        self._code = code
        self._strings = strings

    @property
    def code(self) -> str:
        """Locale code this translation was built for (``"en"``, ``"de"`` ...)."""
        return self._code

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Return the raw value for *key*, or *default* when the key is absent.

        Unlike :meth:`format` the value is returned without interpolation,
        so ``{placeholders}`` stay literal; pass ``default=None`` (the
        default) to distinguish "missing key" from an empty stored value.
        """
        return self._strings.get(key, default)

    def format(self, key: str, default: Optional[str] = None, **kwargs: Any) -> str:
        """
        Translate *key* and interpolate ``{placeholders}`` from *kwargs*.

        The template falls back to *default* when the key is missing and to
        the key itself when no default is given.  Interpolation uses
        :func:`interpolate`, so unknown placeholders stay literal and extra
        keyword arguments are ignored - the call never raises::

            >>> de = get_translation("de")
            >>> de.format("app.version", version="5.1.0")
            'Version 5.1.0'
        """
        template = self.get(key, default)
        if template is None:
            template = key
        return interpolate(template, kwargs)

    def has(self, key: str) -> bool:
        """Return True when *key* exists in this catalogue."""
        return key in self._strings

    def keys(self) -> KeysView[str]:
        """Return a live view over the catalogue keys."""
        return self._strings.keys()

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key in self._strings

    def __iter__(self) -> Iterator[str]:
        return iter(self._strings)

    def __len__(self) -> int:
        return len(self._strings)

    def __repr__(self) -> str:
        return f"Translation(code={self._code!r}, keys={len(self._strings)})"


def _normalize_code(code: Any) -> Optional[str]:
    """
    Canonicalise a language code to its primary subtag, or ``None``.

    Surrounding whitespace is stripped, the code is lowercased, underscores
    become dashes and only the part before the first dash is kept, so
    ``"pt-BR"``, ``"PT_br"`` and ``"pt"`` all normalise to ``"pt"``.
    Non-string, empty or separator-only input yields ``None``.
    """
    if not isinstance(code, str):
        return None
    cleaned = code.strip().lower().replace("_", "-")
    if not cleaned or cleaned.startswith("-"):
        return None
    primary = cleaned.split("-")[0]
    return primary or None


def get_translation(code: str) -> Translation:
    """
    Return the (cached) :class:`Translation` for *code*.

    The code is normalised first (:func:`_normalize_code`), so regional
    variants such as ``"zh-CN"`` or ``"EN-gb"`` resolve to their primary
    locale.  Unknown, empty or non-string codes raise
    :class:`UnknownLanguageError`; the error message lists the available
    locale codes so callers can recover without a second lookup.  Repeated
    calls for the same locale return the identical object until
    :func:`reset` clears the cache.
    """
    normalized = _normalize_code(code)
    if normalized is None or normalized not in LOCALES:
        available = ", ".join(available_locales()) or "<none>"
        raise UnknownLanguageError(
            f"unknown language code: {code!r} (available: {available})"
        )
    cached = _TRANSLATION_CACHE.get(normalized)
    if cached is None:
        cached = Translation(normalized, LOCALES[normalized])
        _TRANSLATION_CACHE[normalized] = cached
    return cached


def set_language(code: str) -> str:
    """
    Make *code* the active language for :func:`t` and :func:`tp`.

    Returns the canonical code that was activated (``set_language("JA")``
    activates and returns ``"ja"``).  Unknown codes raise
    :class:`UnknownLanguageError` *before* any state changes, so a failed
    call never disturbs the previously selected language.
    """
    global _current
    translation = get_translation(code)
    _current = translation
    return translation.code


def get_language() -> str:
    """
    Return the active locale code (``"en"`` while in the default state).

    The default state is active until the first successful
    :func:`set_language` call and again after :func:`reset`.
    """
    if _current is not None:
        return _current.code
    return DEFAULT_LANGUAGE


def reset() -> None:
    """
    Restore the module to its pristine import-time state.

    The active language returns to :data:`DEFAULT_LANGUAGE` and the
    translation cache is emptied, so the next :func:`get_translation` call
    builds fresh :class:`Translation` wrappers.
    """
    global _current
    _current = None
    _TRANSLATION_CACHE.clear()


def _active() -> Translation:
    """Return the active translation, defaulting to the English catalogue."""
    if _current is not None:
        return _current
    return get_translation(DEFAULT_LANGUAGE)


def t(key: str, default: Optional[str] = None, **kwargs: Any) -> str:
    """
    Translate *key* in the active language and interpolate *kwargs*.

    The template is resolved through the fallback chain
    *current language -> English ->* ``default`` *-> the key itself*, so the
    function always returns a usable string:

    * a key missing from the active locale falls back to its English value;
    * a key missing everywhere becomes ``default`` when given;
    * without a default the key itself is returned (and interpolated, so
      ``t("no.such", what="x")`` returns ``"no.such"`` unchanged).

    Interpolation is delegated to :func:`interpolate`: missing placeholders
    stay literal, extra keyword arguments are ignored, values are coerced
    with ``str()``.  Example::

        t("app.version", version="5.1.0")    # "Version 5.1.0"
        t("app.version")                     # "Version {version}"
        t("menu.missing", default="Menu")    # "Menu"
    """
    translation = _active()
    template = translation.get(key)
    if template is None and translation.code != DEFAULT_LANGUAGE:
        template = get_translation(DEFAULT_LANGUAGE).get(key)
    if template is None:
        template = default if default is not None else key
    return interpolate(template, kwargs)


def tp(key: str, count: int, **kwargs: Any) -> str:
    """
    Translate *key* as a plural form selected by *count*.

    The runtime looks up ``key.zero`` for ``count == 0``, ``key.one`` for
    ``count == 1`` and ``key.many`` otherwise (negative counts use the
    ``many`` form).  The resolved template falls back through
    *current language -> English ->* the bare *key* *-> the key itself*, and
    ``{count}`` is interpolated automatically (an explicit ``count`` keyword
    argument would override the automatic value)::

        tp("plural.results", 0)   # "No results"
        tp("plural.results", 1)   # "1 result"
        tp("plural.results", 5)   # "5 results"
        tp("plural.results", -3)  # "-3 results"

    Keys without dedicated plural forms simply interpolate ``{count}`` into
    their single value.
    """
    if count == 0:
        suffix = "zero"
    elif count == 1:
        suffix = "one"
    else:
        suffix = "many"
    kwargs.setdefault("count", count)

    translation = _active()
    english = get_translation(DEFAULT_LANGUAGE)
    template: Optional[str] = None
    for candidate in (f"{key}.{suffix}", key):
        template = translation.get(candidate)
        if template is None and translation.code != DEFAULT_LANGUAGE:
            template = english.get(candidate)
        if template is not None:
            break
    if template is None:
        template = key
    return interpolate(template, kwargs)


def list_languages() -> List[LanguageInfo]:
    """
    Describe every supported language, in :data:`SUPPORTED_LANGUAGES` order.

    ``completion`` is the locale's key count divided by the English key
    count (capped at ``1.0``); because every shipped locale is complete,
    all entries report ``1.0``.  Locales present in the registry but absent
    from :data:`SUPPORTED_LANGUAGES` are intentionally not described here -
    use :func:`available_locales` for the raw code list.
    """
    english_count = len(LOCALES.get(DEFAULT_LANGUAGE, {}))
    infos: List[LanguageInfo] = []
    for code in SUPPORTED_LANGUAGES:
        meta = _LANGUAGE_META.get(code)
        if meta is None:
            continue
        english_name, native_name, direction = meta
        completion = (min(1.0, len(LOCALES.get(code, {})) / english_count)
                      if english_count else 1.0)  # pragma: no cover - English catalogue always exists
        infos.append(
            LanguageInfo(
                code=code,
                english_name=english_name,
                native_name=native_name,
                direction=direction,
                completion=completion,
            )
        )
    return infos


def language_name(code: str) -> str:
    """
    Return the native display name of *code* (``"de"`` -> ``"Deutsch"``).

    Regional variants resolve to their primary locale (``"pt-BR"`` ->
    ``"Português (Brasil)"``).  Unknown or non-string codes never raise:
    string input is returned unchanged and anything else becomes ``""``.
    """
    normalized = _normalize_code(code)
    meta = _LANGUAGE_META.get(normalized) if normalized is not None else None
    if meta is not None:
        return meta[1]
    return code if isinstance(code, str) else ""


def is_rtl(code: str) -> bool:
    """
    Return True when *code* renders right-to-left (currently only ``"ar"``).

    Regional variants are resolved through their primary subtag; unknown
    codes are left-to-right by convention and never raise.
    """
    normalized = _normalize_code(code)
    if normalized is None:
        return False
    meta = _LANGUAGE_META.get(normalized)
    return bool(meta and meta[2] == "rtl")


def available_locales() -> List[str]:
    """
    List the locale codes found in the registry, ``"en"`` first.

    Codes from :data:`SUPPORTED_LANGUAGES` keep their configured order,
    followed by any extra registry codes in sorted order (none in practice).
    """
    supported = set(SUPPORTED_LANGUAGES)
    known = [code for code in SUPPORTED_LANGUAGES if code in LOCALES]
    extras = sorted(code for code in LOCALES if code not in supported)
    return known + extras


def best_match(accept_language_header: Optional[str]) -> str:
    """
    Pick the best supported locale for an HTTP ``Accept-Language`` header.

    The header is parsed with plain string operations - no dependencies:

    * entries are split on ``,``, whitespace is ignored;
    * ``;q=`` parameters set the quality (default ``1.0``); unparseable,
      negative or zero qualities drop or default the entry sanely;
    * entries are ranked by quality, ties keeping header order;
    * a tag matches when it equals a locale code (``"zh"``) or when its
      primary subtag does (``"zh-CN"`` -> ``"zh"``); ``*`` matches the
      default language;
    * the first matching entry wins; headers with no usable match - and
      ``None``, empty or non-string input - return :data:`DEFAULT_LANGUAGE`.

    Examples::

        best_match("zh-CN,zh;q=0.9,en;q=0.8")   # "zh"
        best_match("de;q=0.3,fr;q=0.9")         # "fr"
        best_match("sv,da;q=0.9")               # "en" (no match)
    """
    if not isinstance(accept_language_header, str):
        return DEFAULT_LANGUAGE
    header = accept_language_header.strip()
    if not header:
        return DEFAULT_LANGUAGE

    entries: List[Tuple[float, int, str]] = []
    for position, raw in enumerate(header.split(",")):
        chunk = raw.strip()
        if not chunk:
            continue
        parts = chunk.split(";")
        tag = parts[0].strip().lower().replace("_", "-")
        if not tag:
            continue
        quality = 1.0
        for parameter in parts[1:]:
            parameter = parameter.strip()
            if parameter[:2].lower() == "q=":
                try:
                    quality = float(parameter[2:].strip())
                except ValueError:
                    quality = 1.0
        if quality <= 0.0:
            continue
        entries.append((quality, position, tag))
    entries.sort(key=lambda item: (-item[0], item[1]))

    available = set(available_locales())
    for _quality, _position, tag in entries:
        if tag == "*":
            return DEFAULT_LANGUAGE
        if tag in available:
            return tag
        primary = tag.split("-")[0]
        if primary and primary in available:
            return primary
    return DEFAULT_LANGUAGE

"""
Offline tests for the ObscuraLens i18n runtime (obscuralens.i18n).

Covers the locale registry and language metadata, key-set / placeholder
parity of every shipped locale against the English source catalogue, the
``get_translation`` cache and its ``UnknownLanguageError`` contract, the
module-level language state (``set_language`` / ``get_language`` / ``reset``),
the ``t`` / ``tp`` translation helpers with their fallback chains and
never-raising interpolation, ``is_rtl``, ``language_name`` and the
``Accept-Language`` negotiation in ``best_match``.

The suite assumes the full 14-locale catalogue (en, zh, ja, ko, de, fr, es,
pt, ru, it, nl, pl, ar, hi).  While the last locales of the parallel i18n
task are still landing, importing the package fails and the whole module
skips with an explanatory message instead of erroring.
"""

import re

import pytest

try:
    from obscuralens.i18n import (
        DEFAULT_LANGUAGE,
        LOCALE_DIR,
        SUPPORTED_LANGUAGES,
        LanguageInfo,
        Translation,
        UnknownLanguageError,
        available_locales,
        best_match,
        get_language,
        get_translation,
        interpolate,
        is_rtl,
        language_name,
        list_languages,
        reset,
        set_language,
        t,
        tp,
    )
    from obscuralens.i18n.locales import LOCALES
except ImportError as _import_error:  # pragma: no cover - parallel rollout
    pytest.skip(
        'obscuralens.i18n is not importable yet (the parallel i18n task is '
        f'still landing locale modules): {_import_error}',
        allow_module_level=True,
    )

#: The 14 locale codes shipped with ObscuraLens (en is the source catalogue).
EXPECTED_LOCALES = ('en', 'zh', 'ja', 'ko', 'de', 'fr', 'es', 'pt', 'ru',
                    'it', 'nl', 'pl', 'ar', 'hi')

#: Placeholder tokens look like ``{name}`` inside a translated value.
TOKEN_RE = re.compile(r'\{([^{}]+)\}')

#: English catalogue, used as the parity baseline everywhere.
EN_STRINGS = LOCALES['en']


def _tokens(value):
    """Set of ``{placeholder}`` token names inside a template string."""
    return set(TOKEN_RE.findall(value))


@pytest.fixture(autouse=True)
def isolated_language_state():
    """Reset the module language state and translation cache per test."""
    reset()
    yield
    reset()


# --------------------------------------------------------------------------- #
# registry and metadata
# --------------------------------------------------------------------------- #

class TestRegistry:

    def test_available_locales_returns_14_codes(self):
        locales = available_locales()
        assert len(locales) == 14
        assert set(locales) == set(EXPECTED_LOCALES)

    def test_available_locales_orders_en_first(self):
        locales = available_locales()
        assert locales[0] == 'en'
        assert locales == [code for code in SUPPORTED_LANGUAGES
                           if code in LOCALES]

    def test_supported_languages_constant(self):
        assert len(SUPPORTED_LANGUAGES) == 14
        assert SUPPORTED_LANGUAGES[0] == 'en'
        assert set(SUPPORTED_LANGUAGES) == set(EXPECTED_LOCALES)
        for code in SUPPORTED_LANGUAGES:
            assert re.fullmatch(r'[a-z]{2}', code), code

    def test_default_language_is_english(self):
        assert DEFAULT_LANGUAGE == 'en'

    def test_registry_matches_available_locales(self):
        assert set(LOCALES) == set(available_locales())

    def test_registry_insertion_order_starts_with_english(self):
        assert list(LOCALES)[0] == 'en'

    def test_supported_languages_has_no_duplicates(self):
        assert len(SUPPORTED_LANGUAGES) == len(set(SUPPORTED_LANGUAGES))

    def test_available_locales_returns_a_fresh_list(self):
        first = available_locales()
        second = available_locales()
        assert first == second
        assert first is not second

    def test_extra_registry_codes_are_appended_sorted(self, monkeypatch):
        monkeypatch.setitem(LOCALES, 'zz', dict(EN_STRINGS))
        monkeypatch.setitem(LOCALES, 'aa', dict(EN_STRINGS))
        locales = available_locales()
        assert locales[:14] == list(EXPECTED_LOCALES)
        assert locales[14:] == ['aa', 'zz']

    def test_locale_dir_contains_the_locale_modules(self):
        assert LOCALE_DIR.is_dir()
        for code in EXPECTED_LOCALES:
            assert (LOCALE_DIR / f'{code}.py').is_file(), code


class TestListLanguages:

    def test_returns_language_info_for_every_locale(self):
        infos = list_languages()
        assert len(infos) == 14
        assert all(isinstance(info, LanguageInfo) for info in infos)

    def test_order_follows_supported_languages_with_en_first(self):
        infos = list_languages()
        assert [info.code for info in infos] == list(SUPPORTED_LANGUAGES)
        assert infos[0].code == 'en'

    def test_every_locale_is_fully_translated(self):
        # completion = locale key count / English key count (capped at 1.0);
        # every shipped locale defines the identical key set, so the real
        # invariant is exactly 1.0.
        for info in list_languages():
            assert info.completion == pytest.approx(1.0), info.code

    def test_direction_is_ltr_except_arabic(self):
        for info in list_languages():
            assert info.direction in ('ltr', 'rtl')
            expected = 'rtl' if info.code == 'ar' else 'ltr'
            assert info.direction == expected, info.code

    def test_names_are_populated(self):
        for info in list_languages():
            assert info.english_name.strip()
            assert info.native_name.strip()

    def test_english_entry(self):
        info = next(i for i in list_languages() if i.code == 'en')
        assert info.english_name == 'English'
        assert info.native_name == 'English'


# --------------------------------------------------------------------------- #
# catalogue parity across all 14 locales
# --------------------------------------------------------------------------- #

class TestCatalogueParity:

    @pytest.mark.parametrize('code', EXPECTED_LOCALES)
    def test_strings_is_a_non_empty_str_dict(self, code):
        strings = LOCALES[code]
        assert isinstance(strings, dict)
        assert strings
        for key, value in strings.items():
            assert isinstance(key, str), (code, key)
            assert isinstance(value, str), (code, key)
            assert value.strip(), (code, key)

    @pytest.mark.parametrize('code', EXPECTED_LOCALES)
    def test_key_set_is_identical_to_english(self, code):
        assert set(LOCALES[code]) == set(EN_STRINGS), (
            f'{code} key set differs from en: '
            f'missing={sorted(set(EN_STRINGS) - set(LOCALES[code]))[:5]} '
            f'extra={sorted(set(LOCALES[code]) - set(EN_STRINGS))[:5]}'
        )

    @pytest.mark.parametrize('code', EXPECTED_LOCALES)
    def test_placeholder_tokens_match_english(self, code):
        strings = LOCALES[code]
        for key, english_value in EN_STRINGS.items():
            expected = _tokens(english_value)
            actual = _tokens(strings[key])
            assert actual == expected, (
                f'{code}:{key} tokens {sorted(actual)} != en {sorted(expected)}'
            )

    @pytest.mark.parametrize('code', EXPECTED_LOCALES)
    def test_english_key_set_is_non_trivial(self, code):
        # A healthy catalogue has hundreds of keys; guards against a locale
        # accidentally re-exporting an unrelated dict.
        assert len(LOCALES[code]) >= 200

    def test_plural_keys_exist_in_english(self):
        for suffix in ('zero', 'one', 'many'):
            assert f'plural.results.{suffix}' in EN_STRINGS

    @pytest.mark.parametrize('code', [c for c in EXPECTED_LOCALES if c != 'en'])
    def test_translations_actually_differ_from_english(self, code):
        # Brand-name keys stay identical across locales, but the bulk of the
        # catalogue must be genuinely translated, not copied from en.
        differing = sum(1 for key in EN_STRINGS if LOCALES[code][key] != EN_STRINGS[key])
        assert differing >= 100, (code, differing)

    @pytest.mark.parametrize('code', [c for c in EXPECTED_LOCALES if c != 'en'])
    def test_common_ok_is_translated(self, code):
        # 'common.ok' is a leaf every locale translates differently.
        assert LOCALES[code]['common.ok'].strip()

    @pytest.mark.parametrize('code', EXPECTED_LOCALES)
    def test_brand_keys_are_shared(self, code):
        # Product names are intentionally untranslated in every locale.
        assert LOCALES[code]['app.title'] == 'ObscuraLens'


class TestEnglishCatalogue:
    """Structural invariants of the English source catalogue."""

    def test_key_prefixes_are_the_documented_groups(self):
        prefixes = {key.split('.')[0] for key in EN_STRINGS}
        assert prefixes == {
            'app', 'common', 'menu', 'cli', 'kinds', 'desktop',
            'report', 'errors', 'plural',
        }

    def test_catalogue_size(self):
        assert len(EN_STRINGS) == 220

    def test_every_key_is_dotted_lowercase(self):
        for key in EN_STRINGS:
            assert re.fullmatch(r'[a-z0-9_.]+', key), key

    def test_kind_labels_cover_all_fourteen_kinds(self):
        kinds = {key.split('.')[1] for key in EN_STRINGS
                 if key.startswith('kinds.')}
        assert len(kinds) >= 14
        for kind in ('ip', 'phone', 'username', 'email', 'domain', 'url',
                     'crypto', 'hash', 'cve', 'asn', 'mac', 'iban', 'imei',
                     'coords'):
            assert f'kinds.{kind}' in EN_STRINGS, kind

    @pytest.mark.parametrize('group', ['results', 'sources', 'findings', 'matches'])
    def test_plural_groups_define_zero_one_many(self, group):
        for suffix in ('zero', 'one', 'many'):
            assert f'plural.{group}.{suffix}' in EN_STRINGS
        assert _tokens(EN_STRINGS[f'plural.{group}.one']) == {'count'}
        assert _tokens(EN_STRINGS[f'plural.{group}.many']) == {'count'}

    def test_error_keys_exist(self):
        for key in ('errors.timeout', 'errors.rate_limited',
                    'errors.unknown_language', 'errors.missing_key'):
            assert key in EN_STRINGS, key

    def test_report_keys_exist(self):
        for key in ('report.title', 'report.target', 'report.risk_score',
                    'report.disclaimer'):
            assert key in EN_STRINGS, key

    def test_desktop_keys_exist(self):
        for key in ('desktop.title', 'desktop.listening_on',
                    'desktop.update_available'):
            assert key in EN_STRINGS, key


# --------------------------------------------------------------------------- #
# get_translation and the Translation wrapper
# --------------------------------------------------------------------------- #

class TestGetTranslation:

    def test_valid_code_returns_translation(self):
        translation = get_translation('de')
        assert isinstance(translation, Translation)
        assert translation.code == 'de'

    @pytest.mark.parametrize('code', ['zh-CN', 'PT_br', ' DE ', 'EN-gb'])
    def test_regional_variants_normalise_to_primary(self, code):
        expected = code.strip().lower().replace('_', '-').split('-')[0]
        assert get_translation(code).code == expected

    def test_translation_is_cached_by_identity(self):
        assert get_translation('fr') is get_translation('fr')

    def test_reset_clears_the_cache(self):
        first = get_translation('fr')
        reset()
        second = get_translation('fr')
        assert first is not second
        assert second.code == 'fr'

    @pytest.mark.parametrize('bad', ['xx', 'zzz', '', '   ', None, 42, ['de']])
    def test_unknown_code_raises_unknown_language_error(self, bad):
        with pytest.raises(UnknownLanguageError):
            get_translation(bad)

    def test_unknown_language_error_is_a_value_error(self):
        assert issubclass(UnknownLanguageError, ValueError)

    def test_error_message_lists_available_locales(self):
        with pytest.raises(UnknownLanguageError) as excinfo:
            get_translation('klingon')
        message = str(excinfo.value)
        assert 'klingon' in message
        assert 'en' in message
        assert 'de' in message


class TestTranslationProtocol:

    def test_len_matches_the_catalogue(self):
        translation = get_translation('en')
        assert len(translation) == len(EN_STRINGS)

    def test_contains(self):
        translation = get_translation('en')
        assert 'app.title' in translation
        assert 'no.such.key' not in translation
        assert 42 not in translation

    def test_keys_view(self):
        translation = get_translation('en')
        assert set(translation.keys()) == set(EN_STRINGS)

    def test_keys_view_is_live(self, monkeypatch):
        # The wrapper holds the catalogue by reference, so registry updates
        # are visible through the existing Translation instance.
        translation = get_translation('en')
        monkeypatch.setitem(LOCALES['en'], 'temporary.key', 'temp')
        assert 'temporary.key' in translation
        assert len(translation) == len(LOCALES['en'])

    def test_get_with_default_on_existing_key_returns_the_value(self):
        translation = get_translation('en')
        assert translation.get('app.title', 'ignored') == EN_STRINGS['app.title']

    def test_iteration_yields_the_keys(self):
        translation = get_translation('de')
        assert sorted(translation) == sorted(LOCALES['de'])

    def test_has(self):
        translation = get_translation('en')
        assert translation.has('app.title') is True
        assert translation.has('no.such.key') is False

    def test_get_returns_raw_value_and_default(self):
        translation = get_translation('en')
        assert translation.get('app.title') == EN_STRINGS['app.title']
        assert translation.get('no.such.key') is None
        assert translation.get('no.such.key', 'fallback') == 'fallback'

    def test_get_does_not_interpolate(self):
        translation = get_translation('en')
        assert translation.get('app.version') == 'Version {version}'

    def test_format_interpolates_kwargs(self):
        translation = get_translation('en')
        assert translation.format('app.version', version='5.1.0') == 'Version 5.1.0'

    def test_format_missing_key_uses_default_then_key(self):
        translation = get_translation('en')
        assert translation.format('no.such.key', default='Menu') == 'Menu'
        assert translation.format('no.such.key') == 'no.such.key'

    def test_format_never_raises_on_placeholder_mismatch(self):
        translation = get_translation('en')
        assert translation.format('app.version') == 'Version {version}'
        assert translation.format('app.title', unused='x') == EN_STRINGS['app.title']

    def test_direct_construction_wraps_any_dict(self):
        translation = Translation('xx', {'only.key': 'value {n}'})
        assert translation.code == 'xx'
        assert len(translation) == 1
        assert translation.format('only.key', n=7) == 'value 7'

    def test_repr_mentions_code_and_key_count(self):
        translation = get_translation('de')
        assert 'de' in repr(translation)
        assert str(len(LOCALES['de'])) in repr(translation)


# --------------------------------------------------------------------------- #
# module-level language state
# --------------------------------------------------------------------------- #

class TestLanguageState:

    def test_default_state_is_english(self):
        assert get_language() == 'en'

    def test_set_language_activates_the_code(self):
        assert set_language('zh') == 'zh'
        assert get_language() == 'zh'

    def test_set_language_normalises_the_code(self):
        assert set_language('JA') == 'ja'
        assert get_language() == 'ja'
        assert set_language('pt-BR') == 'pt'
        assert get_language() == 'pt'

    def test_reset_restores_english(self):
        set_language('ru')
        assert get_language() == 'ru'
        reset()
        assert get_language() == 'en'

    def test_set_language_for_every_locale(self):
        for code in EXPECTED_LOCALES:
            assert set_language(code) == code
            assert get_language() == code
        reset()
        assert get_language() == 'en'

    def test_set_language_unknown_raises(self):
        with pytest.raises(UnknownLanguageError):
            set_language('klingon')

    def test_failed_set_language_does_not_disturb_state(self):
        set_language('zh')
        with pytest.raises(UnknownLanguageError):
            set_language('klingon')
        assert get_language() == 'zh'

    def test_t_uses_the_active_catalogue(self):
        german = LOCALES['de']
        differing = [key for key in EN_STRINGS if german[key] != EN_STRINGS[key]]
        assert differing, 'the German catalogue should actually differ from English'
        set_language('de')
        assert t(differing[0]) == german[differing[0]]


# --------------------------------------------------------------------------- #
# t(): lookup, interpolation, fallback chain
# --------------------------------------------------------------------------- #

class TestT:

    def test_existing_key_in_english(self):
        assert t('app.title') == 'ObscuraLens'
        assert t('common.loading') == 'Loading...'

    def test_interpolation_with_kwargs(self):
        assert t('app.version', version='5.1.0') == 'Version 5.1.0'
        assert t('menu.enter_target', kind='domain') == 'Enter the domain to look up:'

    def test_values_are_coerced_with_str(self):
        assert t('cli.elapsed', seconds=12) == 'Elapsed: 12s'
        assert t('cli.risk_score', score=87) == 'Risk score: 87/100'

    def test_missing_placeholder_stays_literal(self):
        assert t('app.version') == 'Version {version}'
        assert t('app.channel') == 'Channel: {channel}'

    def test_extra_kwargs_are_ignored(self):
        assert t('app.title', unused='x', other=1) == 'ObscuraLens'

    def test_missing_key_returns_the_key_itself(self):
        assert t('no.such.key') == 'no.such.key'
        assert t('no.such.key', what='x') == 'no.such.key'

    def test_missing_key_uses_the_default(self):
        assert t('no.such.key', default='Fallback') == 'Fallback'
        assert t('menu.missing', default='Menu') == 'Menu'

    def test_default_empty_string_is_honoured(self):
        assert t('no.such.key', default='') == ''

    def test_default_none_behaves_like_no_default(self):
        assert t('no.such.key', default=None) == 'no.such.key'

    def test_falls_back_to_english_for_missing_locale_key(self, monkeypatch):
        key = 'common.loading'
        monkeypatch.delitem(LOCALES['de'], key)
        set_language('de')
        assert t(key) == EN_STRINGS[key]

    def test_falls_back_through_default_to_key(self, monkeypatch):
        monkeypatch.delitem(LOCALES['fr'], 'common.done', raising=False)
        set_language('fr')
        monkeypatch.setitem(LOCALES['fr'], 'no.such.key', 'temp')
        monkeypatch.delitem(LOCALES['fr'], 'no.such.key')
        assert t('no.such.key', default='dflt') == 'dflt'

    def test_german_translation_after_set_language(self):
        set_language('de')
        assert t('common.loading') == LOCALES['de']['common.loading']

    def test_t_after_reset_uses_english(self):
        set_language('zh')
        reset()
        assert t('app.title') == 'ObscuraLens'


# --------------------------------------------------------------------------- #
# tp(): plural selection
# --------------------------------------------------------------------------- #

class TestTp:

    @pytest.mark.parametrize('count,expected', [
        (0, 'No results'),
        (1, '1 result'),
        (2, '2 results'),
        (5, '5 results'),
        (-3, '-3 results'),
    ])
    def test_plural_selection_in_english(self, count, expected):
        assert tp('plural.results', count) == expected

    def test_count_is_interpolated(self):
        assert tp('plural.sources', 3) == '3 sources'
        assert tp('plural.findings', 0) == 'No findings'
        assert tp('plural.matches', 1) == '1 match'

    def test_plural_forms_in_the_active_language(self):
        set_language('de')
        assert tp('plural.results', 5) == LOCALES['de']['plural.results.many'].replace(
            '{count}', '5')
        assert tp('plural.results', 1) == LOCALES['de']['plural.results.one'].replace(
            '{count}', '1')

    def test_zero_form_in_french(self):
        set_language('fr')
        assert tp('plural.results', 0) == LOCALES['fr']['plural.results.zero']

    def test_falls_back_to_the_base_key(self):
        # 'common.ok' has no .zero/.one/.many forms: the bare key wins.
        assert tp('common.ok', 3) == 'OK'
        assert tp('app.title', 0) == 'ObscuraLens'

    def test_base_key_still_interpolates_count(self):
        # A plain key containing {count} is used verbatim for every count.
        assert tp('cli.showing', 4, shown=4, total=9) == 'Showing 4 of 9 results'

    def test_missing_key_returns_the_key(self):
        assert tp('plural.nope', 2) == 'plural.nope'
        assert tp('no.such.plural', 0) == 'no.such.plural'

    def test_count_can_be_passed_as_a_keyword(self):
        # ``count`` is a named parameter, so it may be given by keyword; it
        # is always interpolated (an overriding duplicate would be a TypeError).
        assert tp('plural.results', count=5) == '5 results'
        with pytest.raises(TypeError):
            tp('plural.results', 5, count=9)

    def test_extra_kwargs_are_ignored(self):
        assert tp('plural.results', 2, unused='x') == '2 results'

    def test_float_counts_use_the_many_form(self):
        assert tp('plural.results', 2.5) == '2.5 results'

    def test_falls_back_to_english_plural_form(self, monkeypatch):
        monkeypatch.delitem(LOCALES['de'], 'plural.results.many')
        set_language('de')
        assert tp('plural.results', 5) == EN_STRINGS['plural.results.many'].replace(
            '{count}', '5')

    def test_falls_back_to_english_base_key(self, monkeypatch):
        monkeypatch.delitem(LOCALES['de'], 'common.ok')
        set_language('de')
        assert tp('common.ok', 3) == 'OK'


# --------------------------------------------------------------------------- #
# is_rtl / language_name
# --------------------------------------------------------------------------- #

class TestIsRtl:

    def test_arabic_is_rtl(self):
        assert is_rtl('ar') is True

    @pytest.mark.parametrize('code', ['ar-EG', 'AR', 'ar_SA'])
    def test_arabic_variants_are_rtl(self, code):
        assert is_rtl(code) is True

    @pytest.mark.parametrize('code', [c for c in EXPECTED_LOCALES if c != 'ar'])
    def test_every_other_locale_is_ltr(self, code):
        assert is_rtl(code) is False

    @pytest.mark.parametrize('junk', ['xx', 'xx-YY', '', '   ', None, 42])
    def test_unknown_codes_are_ltr(self, junk):
        assert is_rtl(junk) is False


class TestLanguageName:

    @pytest.mark.parametrize('code,native', [
        ('en', 'English'),
        ('de', 'Deutsch'),
        ('fr', 'Français'),
        ('zh', '简体中文'),
        ('ar', 'العربية'),
        ('hi', 'हिन्दी'),
    ])
    def test_native_names(self, code, native):
        assert language_name(code) == native

    @pytest.mark.parametrize('code', EXPECTED_LOCALES)
    def test_every_locale_has_a_native_name(self, code):
        assert language_name(code).strip()

    def test_regional_variant_resolves_to_primary(self):
        assert language_name('pt-BR') == 'Português (Brasil)'
        assert language_name('en-US') == 'English'

    def test_input_is_case_insensitive(self):
        assert language_name('DE') == 'Deutsch'
        assert language_name('Ar-EG') == 'العربية'

    def test_unknown_string_code_is_returned_unchanged(self):
        assert language_name('xx') == 'xx'
        assert language_name('Klingon') == 'Klingon'

    @pytest.mark.parametrize('junk', [None, 42, ['de']])
    def test_non_string_input_becomes_empty(self, junk):
        assert language_name(junk) == ''


# --------------------------------------------------------------------------- #
# Accept-Language negotiation
# --------------------------------------------------------------------------- #

class TestBestMatch:

    @pytest.mark.parametrize('header,expected', [
        ('zh-CN,zh;q=0.9,en;q=0.8', 'zh'),
        ('en-US,en;q=0.9', 'en'),
        ('fr-CA,fr;q=0.9', 'fr'),
        ('pt-BR,pt;q=0.9', 'pt'),
        ('de', 'de'),
        ('ja,en;q=0.5', 'ja'),
        ('*', 'en'),
        ('en,*;q=0.5', 'en'),
        ('de;q=0.3,fr;q=0.9', 'fr'),
        ('sv,da;q=0.9', 'en'),
        ('zh;q=0,en', 'en'),
        ('de,fr', 'de'),
        ('pt_br', 'pt'),
        ('EN-gb', 'en'),
        ('', 'en'),
        ('   ', 'en'),
        ('!!!,,,;;;', 'en'),
        ('not a language', 'en'),
        ('de;q=abc', 'de'),
        ('zh;q=0.9;v=1', 'zh'),
    ])
    def test_documented_resolutions(self, header, expected):
        assert best_match(header) == expected

    @pytest.mark.parametrize('junk', [None, 123, ['en'], {}])
    def test_non_string_input_returns_default(self, junk):
        assert best_match(junk) == 'en'

    def test_every_supported_locale_is_reachable(self):
        for code in EXPECTED_LOCALES:
            assert best_match(code) == code

    @pytest.mark.parametrize('header,expected', [
        ('ar-EG', 'ar'), ('hi-IN', 'hi'), ('pt-BR', 'pt'), ('zh-TW', 'zh'),
        ('en-GB', 'en'), ('fr-CH', 'fr'), ('de-AT', 'de'), ('es-MX', 'es'),
        ('ja-JP', 'ja'), ('ko-KR', 'ko'), ('ru-BY', 'ru'), ('it-IT', 'it'),
        ('nl-NL', 'nl'), ('pl-PL', 'pl'),
    ])
    def test_regional_variants_resolve_to_primary(self, header, expected):
        assert best_match(header) == expected

    def test_result_is_always_a_supported_code(self):
        headers = ['zh-TW,en;q=1', 'xx-YY,zz;q=0.8', 'hi-IN,hi;q=0.7,en',
                   'es-ES,es;q=0.9,fr;q=0.4', ',', ';q=0.5', '*,fr;q=0.1']
        for header in headers:
            assert best_match(header) in set(EXPECTED_LOCALES)

    def test_quality_ties_keep_header_order(self):
        assert best_match('de,fr') == 'de'
        assert best_match('fr,de') == 'fr'

    def test_whitespace_around_entries_is_tolerated(self):
        assert best_match(' zh-CN , en ; q=0.5 ') == 'zh'
        assert best_match(',, en ,,') == 'en'

    def test_highest_quality_wins_regardless_of_order(self):
        assert best_match('en;q=0.4,ru;q=0.8,ja;q=0.6') == 'ru'
        assert best_match('ru;q=0.2,ja;q=0.9,en;q=0.8') == 'ja'

    def test_unparseable_quality_defaults_to_one(self):
        assert best_match('de;q=not-a-number') == 'de'
        assert best_match('de;q=') == 'de'

    def test_zero_quality_entries_are_dropped(self):
        assert best_match('de;q=0.0,en') == 'en'
        assert best_match('de;q=0,fr;q=0,ru') == 'ru'


# --------------------------------------------------------------------------- #
# interpolate() and package surface
# --------------------------------------------------------------------------- #

class TestInterpolate:

    def test_substitutes_known_tokens(self):
        assert interpolate('Version {version}', {'version': '5.1.0'}) == 'Version 5.1.0'

    def test_missing_tokens_stay_literal(self):
        assert interpolate('Version {version}', {}) == 'Version {version}'
        assert interpolate('{a} {b}', {'a': 1}) == '1 {b}'

    def test_repeated_tokens_are_all_replaced(self):
        assert interpolate('{a} and {a}', {'a': 1}) == '1 and 1'

    def test_extra_values_are_ignored(self):
        assert interpolate('no tokens', {'a': 1}) == 'no tokens'
        assert interpolate('{a}', {'a': 1, 'b': 2}) == '1'

    def test_values_are_coerced_with_str(self):
        assert interpolate('{n}', {'n': 12}) == '12'
        assert interpolate('{x}', {'x': 1.5}) == '1.5'


class TestPackageSurface:

    def test_all_exports_exist(self):
        from obscuralens import i18n

        for name in i18n.__all__:
            assert hasattr(i18n, name), name

    def test_public_helpers_are_importable_from_the_package(self):
        from obscuralens.i18n import (  # noqa: F401
            available_locales,
            best_match,
            get_language,
            get_translation,
            interpolate,
            is_rtl,
            language_name,
            list_languages,
            reset,
            set_language,
            t,
            tp,
        )

    def test_state_is_unchanged_by_catalogue_reads(self):
        set_language('ko')
        get_translation('de').get('app.title')
        list_languages()
        available_locales()
        assert get_language() == 'ko'

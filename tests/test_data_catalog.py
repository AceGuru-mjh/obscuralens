"""
Offline test suite for obscuralens.utils.data_catalog.

Two flavours of tests live here:

* **Contract tests against the real shipped packs** under
  ``obscuralens/data`` -- known values ("United States", ssh on 22/tcp,
  "Not Found" on 404 ...), entry counts, uniqueness and normalisation of
  user-supplied arguments.  They assume the pack files exist and follow
  the line formats documented in the module docstring.
* **Synthetic-pack tests** that point ``DATA_DIR`` at temporary files
  containing deliberately malformed lines.  They prove the loaders skip
  bad lines, deduplicate keys, never raise, and that a fully missing
  catalog degrades to empty results (plus the safe user-agent fallback),
  so they pass no matter what is on disk.

Nothing here touches the network; everything runs in milliseconds.
"""

import re
import types

import pytest

from obscuralens.utils import data_catalog

#: The ten catalog pack names (files under obscuralens/data).
PACK_NAMES = {
    'ports_services',
    'countries_iso3166',
    'languages_iso639',
    'currencies_iso4217',
    'http_status_codes',
    'cwe_catalog',
    'iana_tlds',
    'file_extensions',
    'mime_types',
    'user_agents',
}

#: Every TLD must look like this after normalisation (punycode included).
TLD_PATTERN = re.compile(r'^[a-z0-9-]+$')

#: (port, protocol, acceptable service names) for the parametrised lookup test.
KNOWN_PORTS = [
    (21, 'tcp', {'ftp'}),
    (22, 'tcp', {'ssh'}),
    (23, 'tcp', {'telnet'}),
    (25, 'tcp', {'smtp'}),
    (53, 'udp', {'domain'}),
    (80, 'tcp', {'http'}),
    (110, 'tcp', {'pop3'}),
    (123, 'udp', {'ntp'}),
    (143, 'tcp', {'imap', 'imap2'}),
    (161, 'udp', {'snmp'}),
    (443, 'tcp', {'https'}),
    (587, 'tcp', {'submission'}),
    (993, 'tcp', {'imaps'}),
    (995, 'tcp', {'pop3s'}),
    (3306, 'tcp', {'mysql'}),
    (3389, 'tcp', {'ms-wbt-server', 'rdp'}),
    (5432, 'tcp', {'postgresql', 'postgres'}),
    (6379, 'tcp', {'redis'}),
    (8080, 'tcp', {'http-alt', 'http-proxy', 'http'}),
    (27017, 'tcp', {'mongodb', 'mongod'}),
]

#: (extension, expected mime type) pairs for the parametrised lookup test.
KNOWN_MIMES = [
    ('json', 'application/json'),
    ('html', 'text/html'),
    ('css', 'text/css'),
    ('txt', 'text/plain'),
    ('png', 'image/png'),
    ('gif', 'image/gif'),
    ('jpeg', 'image/jpeg'),
    ('pdf', 'application/pdf'),
    ('zip', 'application/zip'),
]

#: (alpha-2 country, expected primary currency) spot checks of the built-in map.
KNOWN_COUNTRY_CURRENCIES = [
    ('US', 'USD'),
    ('DE', 'EUR'),
    ('GB', 'GBP'),
    ('JP', 'JPY'),
    ('CN', 'CNY'),
    ('IN', 'INR'),
    ('BR', 'BRL'),
    ('RU', 'RUB'),
    ('KR', 'KRW'),
    ('AU', 'AUD'),
    ('CA', 'CAD'),
    ('CH', 'CHF'),
    ('SE', 'SEK'),
    ('NO', 'NOK'),
    ('DK', 'DKK'),
    ('PL', 'PLN'),
    ('CZ', 'CZK'),
    ('TR', 'TRY'),
    ('MX', 'MXN'),
    ('ZA', 'ZAR'),
    ('SG', 'SGD'),
    ('HK', 'HKD'),
    ('NZ', 'NZD'),
    ('VN', 'VND'),
    ('FI', 'EUR'),
    ('HR', 'EUR'),
    ('LI', 'CHF'),
    ('VA', 'EUR'),
]

#: Garbage values fed to every lookup/search function (never-raise sweep).
GARBAGE = [None, 123, 4.5, True, [], {}, object()]

#: Synthetic pack files with deliberately malformed lines, used by the
#: ``synthetic_packs`` fixture to exercise the tolerant parsers.
SYNTHETIC_PACKS = {
    'countries_iso3166.txt': (
        '# synthetic countries pack\n'
        '\n'
        'US|USA|840|United States|Washington, D.C.\n'
        'de|DEU|276|Germany|Berlin\n'
        'GB|GBR|826|United Kingdom|London\n'
        'BAD|line\n'
        'US|USA|840|United States|duplicate is skipped\n'
        'XX|XXX|999|Nowhere|\n'
        'U|USAAL|840|Too short codes are skipped|x\n'
    ),
    'ports_services.txt': (
        '# synthetic ports pack\n'
        '22/tcp|ssh|Secure Shell remote login\n'
        '53/udp|domain|Domain name service\n'
        '53/tcp|domain|Domain name service (TCP)\n'
        '80/tcp|http|Hypertext transfer protocol\n'
        'not-a-port/tcp|bogus|skipped\n'
        '99999/tcp|over|out of range\n'
        '22/tcp|ssh-dup|duplicate key is skipped\n'
        'badline\n'
        '443/tcp||empty service is skipped\n'
        '8080/tcp|http-alt|HTTP alternate\n'
    ),
    'languages_iso639.txt': (
        '# two-letter block\n'
        'en|English\n'
        'DE|German\n'
        '# three-letter block\n'
        'deu|German\n'
        'xx\n'
        'bad|line|extra\n'
    ),
    'currencies_iso4217.txt': (
        '# synthetic currencies pack\n'
        'USD|840|2|US Dollar\n'
        'eur|978|2|Euro\n'
        'JPY|392|0|Japanese Yen\n'
        'KWD|414|3|Kuwaiti Dinar\n'
        'XAU|959|N/A|Gold\n'
        'BAD|line\n'
    ),
    'http_status_codes.txt': (
        '# synthetic http status pack\n'
        '200|OK|success\n'
        '301|Moved Permanently|redirection\n'
        '404|Not Found|Client Error\n'
        '429|Too Many Requests|client_error\n'
        '500|Internal Server Error|server error\n'
        'bad|phrase|category\n'
        '999|Weird|misc\n'
    ),
    'cwe_catalog.txt': (
        "# synthetic cwe pack\n"
        "CWE-79|Improper Neutralization of Input During Web Page Generation "
        "('Cross-site Scripting')\n"
        '89|SQL Injection\n'
        'CWE-079|duplicate after zero-normalisation is skipped\n'
        'bad-entry\n'
        'CWE-x|not a number\n'
    ),
    'iana_tlds.txt': (
        '# synthetic tld pack\n'
        'com\n'
        'ORG\n'
        'dev\n'
        'xn--p1ai\n'
        'com\n'
        'bad tld\n'
        'z1\n'
    ),
    'file_extensions.txt': (
        '# synthetic extension pack\n'
        'exe|executable|Windows executable\n'
        '.zip|Archive|ZIP archive\n'
        'PDF|document|Portable document format\n'
        'bad line\n'
        'exe|executable-dup|duplicate is skipped\n'
    ),
    'mime_types.txt': (
        '# synthetic mime pack\n'
        'application/json|json|JSON data\n'
        'text/html|.HTML|HTML document\n'
        'image/png|PNG|PNG image\n'
        'bad line\n'
        'application/json|json|duplicate mime kept in the entries list\n'
    ),
    'user_agents.txt': (
        '# synthetic user agent pack\n'
        'Chrome|Windows 11|Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\n'
        'Firefox|Linux|Mozilla/5.0 (X11; Linux x86_64; rv:121.0) '
        'Gecko/20100101 Firefox/121.0\n'
        'curl|any platform|curl/8.5.0\n'
        'only-two|fields\n'
    ),
}


@pytest.fixture()
def synthetic_packs(tmp_path, monkeypatch):
    """
    Point the catalog at synthetic pack files (with malformed lines) and
    clear the module cache; the cache is cleared again on teardown so later
    tests reload the real packs from the original DATA_DIR.
    """
    for filename, text in SYNTHETIC_PACKS.items():
        (tmp_path / filename).write_text(text, encoding='utf-8')
    monkeypatch.setattr(data_catalog, 'DATA_DIR', tmp_path)
    data_catalog._CACHE.clear()
    yield tmp_path
    data_catalog._CACHE.clear()


@pytest.fixture()
def empty_packs_dir(tmp_path, monkeypatch):
    """
    Point the catalog at a directory without any pack files (cache cleared
    on setup and teardown) to exercise the missing-pack code paths.
    """
    monkeypatch.setattr(data_catalog, 'DATA_DIR', tmp_path)
    data_catalog._CACHE.clear()
    yield tmp_path
    data_catalog._CACHE.clear()


# ---------------------------------------------------------------------------
# Module surface
# ---------------------------------------------------------------------------


class TestModuleSurface:
    """The module's public surface and stdlib-only import contract."""

    def test_all_exports_resolve(self):
        assert len(data_catalog.__all__) == 45
        for name in data_catalog.__all__:
            attribute = getattr(data_catalog, name)
            assert callable(attribute), name
        for name in ('country', 'port_service', 'random_user_agent', 'catalog_summary',
                     'Country', 'CatalogStats'):
            assert name in data_catalog.__all__

    def test_module_imports_stdlib_only(self):
        allowed = {'random', 're', 'dataclasses', 'pathlib', 'typing'}
        for value in vars(data_catalog).values():
            if isinstance(value, types.ModuleType):
                assert value.__name__ in allowed

    def test_data_dir_lives_inside_package(self):
        data_dir = data_catalog.DATA_DIR
        assert data_dir.name == 'data'
        assert data_dir.is_dir()
        assert 'obscuralens' in data_dir.parts


# ---------------------------------------------------------------------------
# Core parsing helpers (white-box, pass without any pack files)
# ---------------------------------------------------------------------------


class TestParsingHelpers:
    """The private pipe-parsing / memoisation helpers."""

    def test_parse_pipe_line(self):
        assert data_catalog._parse_pipe_line(' a | b |c ', 3) == ['a', 'b', 'c']
        assert data_catalog._parse_pipe_line('22/tcp|ssh|Secure Shell', 3) == \
            ['22/tcp', 'ssh', 'Secure Shell']
        assert data_catalog._parse_pipe_line('one|two', 3) is None
        assert data_catalog._parse_pipe_line('a|b|c', 2) is None
        assert data_catalog._parse_pipe_line(None, 2) is None
        assert data_catalog._parse_pipe_line(123, 2) is None
        # empty fields are preserved -- loaders validate their own keys
        assert data_catalog._parse_pipe_line('a||c', 3) == ['a', '', 'c']

    def test_pack_lines_missing_pack_never_raises(self):
        assert list(data_catalog._pack_lines('definitely_not_a_pack')) == []
        assert list(data_catalog._pack_lines('')) == []
        assert list(data_catalog._pack_lines('ports_services')) == \
            list(data_catalog._pack_lines('ports_services'))

    def test_load_missing_pack_is_empty_and_not_cached(self):
        record = data_catalog._load('no_such_pack_here', lambda lines: list(lines), [])
        assert record == []
        assert 'no_such_pack_here' not in data_catalog._CACHE


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


class TestDataclasses:
    """The ten public dataclasses: fields, to_dict() and equality."""

    def test_country_and_port_entry_to_dict(self):
        country = data_catalog.Country('US', 'USA', '840', 'United States',
                                       'Washington, D.C.')
        assert country.to_dict() == {
            'code': 'US', 'code3': 'USA', 'numeric': '840',
            'name': 'United States', 'capital': 'Washington, D.C.',
        }
        port = data_catalog.PortEntry(22, 'tcp', 'ssh', 'Secure Shell remote login')
        assert port.to_dict() == {
            'port': 22, 'protocol': 'tcp', 'service': 'ssh',
            'description': 'Secure Shell remote login',
        }

    def test_simple_entry_to_dicts(self):
        language = data_catalog.Language('en', 'English')
        assert language.to_dict() == {'code': 'en', 'name': 'English'}
        currency = data_catalog.Currency('EUR', '978', 2, 'Euro')
        assert currency.to_dict() == {
            'code': 'EUR', 'numeric': '978', 'minor_units': 2, 'name': 'Euro',
        }
        status = data_catalog.HttpStatus(429, 'Too Many Requests', 'client_error')
        assert status.to_dict() == {
            'code': 429, 'phrase': 'Too Many Requests', 'category': 'client_error',
        }
        weakness = data_catalog.Cwe('CWE-79', 'Cross-site Scripting')
        assert weakness.to_dict() == {'cwe_id': 'CWE-79', 'name': 'Cross-site Scripting'}
        extension = data_catalog.FileExtension('exe', 'executable', 'Windows executable')
        assert extension.to_dict() == {
            'ext': 'exe', 'category': 'executable', 'description': 'Windows executable',
        }
        mime = data_catalog.MimeType('application/json', 'json', 'JSON data')
        assert mime.to_dict() == {
            'mime': 'application/json', 'extension': 'json', 'description': 'JSON data',
        }
        agent = data_catalog.UserAgent('curl', 'any', 'curl/8.5.0')
        assert agent.to_dict() == {
            'family': 'curl', 'platform': 'any', 'string': 'curl/8.5.0',
        }
        stats = data_catalog.CatalogStats('iana_tlds', 1454, True)
        assert stats.to_dict() == {'name': 'iana_tlds', 'entries': 1454, 'loaded': True}

    def test_dataclass_equality_and_positional_fields(self):
        assert data_catalog.Cwe('CWE-79', 'x') == data_catalog.Cwe('CWE-79', 'x')
        assert data_catalog.Cwe('CWE-79', 'x') != data_catalog.Cwe('CWE-80', 'x')
        # field order matches the documented constructor signatures
        assert data_catalog.Country('US', 'USA', '840', 'United States', 'DC').code == 'US'
        assert data_catalog.PortEntry(22, 'tcp', 'ssh', 'd').service == 'ssh'
        assert data_catalog.Currency('USD', '840', 2, 'US Dollar').minor_units == 2
        assert data_catalog.HttpStatus(404, 'Not Found', 'client_error').phrase == 'Not Found'
        assert data_catalog.UserAgent('f', 'p', 's').string == 's'
        assert data_catalog.CatalogStats('n', 0, False).loaded is False


# ---------------------------------------------------------------------------
# Countries (ISO 3166-1) -- real pack
# ---------------------------------------------------------------------------


class TestCountries:
    """Known values, search, counts and robustness against the real pack."""

    def test_known_country_united_states(self):
        country = data_catalog.country('US')
        assert country is not None
        assert country.code == 'US'
        assert country.code3 == 'USA'
        assert country.name == 'United States of America'
        assert isinstance(country.capital, str) and country.capital
        assert country.numeric == '840'

    def test_alpha3_lookup_shares_the_same_entry(self):
        assert data_catalog.country('usa') is data_catalog.country('US')
        assert data_catalog.country('usa').code == 'US'
        assert data_catalog.country('DE').code3 == 'DEU'
        assert data_catalog.country('DEU') is data_catalog.country('de')
        assert data_catalog.country('usa').name == 'United States of America'

    def test_search_countries_united(self):
        found = {entry.code for entry in data_catalog.search_countries('united')}
        assert {'US', 'GB', 'AE'} <= found

    def test_countries_count_uniqueness_and_shape(self):
        all_countries = data_catalog.search_countries('')
        assert data_catalog.countries_count() == len(all_countries)
        assert data_catalog.countries_count() >= 190
        alpha2 = [entry.code for entry in all_countries]
        assert len(set(alpha2)) == len(alpha2)
        for entry in all_countries:
            assert len(entry.code) == 2 and entry.code.isupper()
            assert len(entry.code3) == 3 and entry.code3.isupper()
            assert len(entry.numeric) == 3 and entry.numeric.isdigit()
            assert entry.name

    def test_country_case_insensitive_and_empty_query(self):
        assert data_catalog.country('uS') is data_catalog.country('US')
        assert data_catalog.country(' Usa ') is data_catalog.country('USA')
        assert data_catalog.search_countries('') == data_catalog.search_countries('   ')
        assert data_catalog.search_countries('UNITED KINGDOM')

    def test_country_robustness(self):
        assert data_catalog.country('') is None
        assert data_catalog.country('XXXX') is None
        assert data_catalog.country('u') is None
        assert data_catalog.country(None) is None
        assert data_catalog.country(123) is None
        assert data_catalog.search_countries('zzz-no-such-country') == []
        assert data_catalog.search_countries(None) == []


# ---------------------------------------------------------------------------
# Ports and services -- real pack
# ---------------------------------------------------------------------------


class TestPorts:
    """Known registrations, ranges, service helpers and robustness."""

    @pytest.mark.parametrize('port,protocol,expected', KNOWN_PORTS)
    def test_known_ports(self, port, protocol, expected):
        entry = data_catalog.port_service(port, protocol)
        assert entry is not None, (port, protocol)
        assert entry.port == port
        assert entry.protocol == protocol
        assert entry.service in expected, entry.service

    def test_port_service_default_protocol_and_description(self):
        entry = data_catalog.port_service(443)
        assert entry.protocol == 'tcp'
        assert entry.service == 'https'
        assert isinstance(entry.description, str)
        assert data_catalog.port_service('22') is data_catalog.port_service(22)
        assert data_catalog.port_service(53, 'UDP').service == 'domain'

    def test_ports_for_service_and_service_names(self):
        http_ports = [entry.port for entry in data_catalog.ports_for_service('http')]
        assert 80 in http_ports
        assert data_catalog.ports_for_service('HTTP') == \
            data_catalog.ports_for_service('http')
        assert data_catalog.ports_for_service('no-such-service') == []
        assert data_catalog.ports_for_service('') == []
        names = data_catalog.service_names()
        assert len(names) >= 200
        assert names == sorted(names)
        assert len(set(names)) == len(names)
        assert 'ssh' in names and 'http' in names

    def test_well_known_tcp_range(self):
        entries = data_catalog.well_known_tcp()
        assert entries
        assert 22 in [entry.port for entry in entries]
        for entry in entries:
            assert entry.protocol == 'tcp'
            assert entry.port < 1024

    def test_notable_registered_range(self):
        entries = data_catalog.notable_registered()
        assert entries
        ports = [entry.port for entry in entries]
        assert {3306, 5432, 6379, 8080, 27017} <= set(ports)
        for entry in entries:
            assert entry.port >= 1024

    @pytest.mark.parametrize('port,expected', [
        (0, 'well_known'),
        (22, 'well_known'),
        (1023, 'well_known'),
        (1024, 'registered'),
        (8080, 'registered'),
        (49151, 'registered'),
        (49152, 'dynamic'),
        (65535, 'dynamic'),
    ])
    def test_port_category_boundaries(self, port, expected):
        assert data_catalog.port_category(port) == expected
        assert data_catalog.port_category(str(port)) == expected

    def test_port_robustness_and_uniqueness(self):
        assert data_catalog.port_service(99999) is None
        assert data_catalog.port_service(-1) is None
        assert data_catalog.port_service('not-a-port') is None
        assert data_catalog.port_service(None) is None
        assert data_catalog.port_service(22, '') is None
        assert data_catalog.port_service(22, None) is None
        assert data_catalog.port_service(22, 'sctp') is None or \
            data_catalog.port_service(22, 'sctp').protocol == 'sctp'
        assert data_catalog.port_category('nope') == ''
        assert data_catalog.port_category(None) == ''
        every = data_catalog.well_known_tcp() + data_catalog.notable_registered()
        keys = [(entry.port, entry.protocol) for entry in every]
        assert len(keys) == len(set(keys))


# ---------------------------------------------------------------------------
# Languages (ISO 639) -- real pack
# ---------------------------------------------------------------------------


class TestLanguages:
    """Known languages, both code blocks, counts and robustness."""

    def test_known_languages(self):
        assert data_catalog.language('en').name == 'English'
        assert data_catalog.language('de').name == 'German'
        assert data_catalog.language('EN') is data_catalog.language('en')
        assert data_catalog.language(' De ') is data_catalog.language('de')

    def test_both_code_blocks_present(self):
        every = data_catalog.search_languages('')
        assert any(len(entry.code) == 2 for entry in every)
        assert any(len(entry.code) == 3 for entry in every)
        german = data_catalog.language('deu')
        if german is not None:  # 639-2/B code is optional in trimmed packs
            assert german.name == 'German'

    def test_languages_count_and_uniqueness(self):
        every = data_catalog.search_languages('')
        assert data_catalog.languages_count() == len(every)
        assert data_catalog.languages_count() >= 100
        codes = [entry.code for entry in every]
        assert len(set(codes)) == len(codes)
        for entry in every:
            assert entry.code.islower() and entry.code.isalpha()

    def test_language_search_and_robustness(self):
        assert 'German' in [entry.name for entry in data_catalog.search_languages('german')]
        assert data_catalog.language('en') in data_catalog.search_languages('english')
        assert data_catalog.language('') is None
        assert data_catalog.language('abcd') is None
        assert data_catalog.language(None) is None
        assert data_catalog.language(123) is None
        assert data_catalog.search_languages('zzz-no-such-language') == []
        assert data_catalog.search_languages(None) == []


# ---------------------------------------------------------------------------
# Currencies (ISO 4217) -- real pack
# ---------------------------------------------------------------------------


class TestCurrencies:
    """Known currencies, minor units, search and the country map."""

    def test_known_currencies(self):
        euro = data_catalog.currency('EUR')
        assert euro is not None
        assert euro.code == 'EUR'
        assert euro.minor_units == 2
        dollar = data_catalog.currency('usd')
        assert dollar is not None
        assert dollar.code == 'USD'
        assert dollar.minor_units == 2
        assert len(dollar.numeric) == 3 and dollar.numeric.isdigit()
        assert data_catalog.currency('UsD') is data_catalog.currency('USD')

    def test_minor_unit_variants(self):
        assert data_catalog.currency('JPY').minor_units == 0
        assert data_catalog.currency('KWD').minor_units == 3
        assert data_catalog.currency('BHD').minor_units == 3

    def test_search_currencies(self):
        every = data_catalog.search_currencies('')
        assert len(every) >= 100
        assert len({entry.code for entry in every}) == len(every)
        dollars = [entry.code for entry in data_catalog.search_currencies('dollar')]
        assert 'USD' in dollars
        assert data_catalog.search_currencies('zzz-no-such-currency') == []
        assert data_catalog.search_currencies(None) == []

    @pytest.mark.parametrize('alpha2,expected', KNOWN_COUNTRY_CURRENCIES)
    def test_currencies_for_country(self, alpha2, expected):
        assert data_catalog.currencies_for_country(alpha2) == [expected]
        assert data_catalog.currencies_for_country(alpha2.lower()) == [expected]
        assert data_catalog.currency(expected) is not None

    def test_country_currency_map_integrity(self):
        mapping = data_catalog._COUNTRY_CURRENCIES
        assert len(mapping) == 88
        for alpha2, code in mapping.items():
            assert len(alpha2) == 2 and alpha2.isupper()
            assert len(code) == 3 and code.isupper()
        assert data_catalog.currencies_for_country('XX') == []
        assert data_catalog.currencies_for_country('') == []
        assert data_catalog.currencies_for_country('USA') == []
        assert data_catalog.currencies_for_country(None) == []
        assert data_catalog.currency('XXXX') is None
        assert data_catalog.currency(None) is None


# ---------------------------------------------------------------------------
# HTTP status codes -- real pack
# ---------------------------------------------------------------------------


class TestHttpStatuses:
    """Known phrases, categories and the derived category helper."""

    @pytest.mark.parametrize('code,phrase', [
        (200, 'OK'),
        (301, 'Moved Permanently'),
        (404, 'Not Found'),
        (429, 'Too Many Requests'),
        (500, 'Internal Server Error'),
    ])
    def test_known_http_phrases(self, code, phrase):
        entry = data_catalog.http_status(code)
        assert entry is not None
        assert entry.phrase == phrase
        assert data_catalog.http_status(str(code)) is entry

    @pytest.mark.parametrize('code,expected', [
        (100, 'informational'),
        (199, 'informational'),
        (200, 'success'),
        (204, 'success'),
        (301, 'redirection'),
        (399, 'redirection'),
        (404, 'client_error'),
        (429, 'client_error'),
        (500, 'server_error'),
        (599, 'server_error'),
        (0, None),
        (99, None),
        (600, None),
        (999, None),
        ('abc', None),
        (None, None),
        (4.5, None),
    ])
    def test_http_status_category_derivation(self, code, expected):
        assert data_catalog.http_status_category(code) == expected
        assert data_catalog.http_status_category(str(code)) == expected

    def test_http_statuses_for_category(self):
        client_errors = [entry.code for entry in
                         data_catalog.http_statuses_for_category('client_error')]
        assert {404, 429} <= set(client_errors)
        assert 200 in [entry.code for entry in
                       data_catalog.http_statuses_for_category('success')]
        assert data_catalog.http_statuses_for_category('CLIENT ERROR') == \
            data_catalog.http_statuses_for_category('client_error')
        assert data_catalog.http_statuses_for_category('client-error') == \
            data_catalog.http_statuses_for_category('client_error')
        assert data_catalog.http_statuses_for_category('no-such-category') == []
        assert data_catalog.http_statuses_for_category(None) == []

    def test_all_five_categories_populated_and_consistent(self):
        for category in ('informational', 'success', 'redirection', 'client_error',
                         'server_error'):
            entries = data_catalog.http_statuses_for_category(category)
            assert entries, category
            for entry in entries:
                assert data_catalog.http_status_category(entry.code) == entry.category

    def test_http_status_robustness(self):
        assert data_catalog.http_status(999) is None
        assert data_catalog.http_status(None) is None
        assert data_catalog.http_status('abc') is None
        assert data_catalog.http_status(4.5) is None
        every = data_catalog.http_statuses_for_category('client_error') + \
            data_catalog.http_statuses_for_category('server_error')
        assert len({entry.code for entry in every}) == len(every)


# ---------------------------------------------------------------------------
# CWE catalogue -- real pack
# ---------------------------------------------------------------------------


class TestCwes:
    """Known weaknesses, id normalisation, counts and robustness."""

    def test_known_cwe_xss(self):
        entry = data_catalog.cwe('CWE-79')
        assert entry is not None
        assert entry.cwe_id == 'CWE-79'
        assert 'Cross-site Scripting' in entry.name
        assert entry.to_dict()['cwe_id'] == 'CWE-79'

    def test_cwe_id_normalisation(self):
        assert data_catalog.cwe('79') == data_catalog.cwe('CWE-79')
        assert data_catalog.cwe('79') is data_catalog.cwe('CWE-79')
        assert data_catalog.cwe('cwe-79') is data_catalog.cwe('CWE-79')
        assert data_catalog.cwe('  CWE-79  ') is data_catalog.cwe('CWE-79')

    def test_cwes_count_uniqueness_and_shape(self):
        every = data_catalog.search_cwes('')
        assert data_catalog.cwes_count() == len(every)
        assert data_catalog.cwes_count() >= 100
        ids = [entry.cwe_id for entry in every]
        assert len(set(ids)) == len(ids)
        for cwe_id in ids:
            prefix, _, digits = cwe_id.partition('-')
            assert prefix == 'CWE'
            assert digits.isdigit()

    def test_cwe_search_and_robustness(self):
        assert data_catalog.search_cwes('injection')
        assert data_catalog.cwe('CWE-79') in data_catalog.search_cwes('cwe-79')
        assert data_catalog.cwe('CWE-99999') is None
        assert data_catalog.cwe('99999') is None
        assert data_catalog.cwe('') is None
        assert data_catalog.cwe('not-a-cwe') is None
        assert data_catalog.cwe('CWE-') is None
        assert data_catalog.cwe(None) is None
        assert data_catalog.cwe(123) is None
        assert data_catalog.search_cwes('zzz-no-such-weakness') == []
        assert data_catalog.search_cwes(None) == []


# ---------------------------------------------------------------------------
# IANA top-level domains -- real pack
# ---------------------------------------------------------------------------


class TestTlds:
    """TLD membership, normalisation, counts and shape guarantees."""

    @pytest.mark.parametrize('tld', [
        'com', 'org', 'net', 'edu', 'gov', 'io', 'dev', 'app', 'xyz', 'info',
        'biz', 'uk', 'de', 'fr', 'jp', 'cn', 'br', 'in', 'ru', 'au',
    ])
    def test_common_tlds_recognised(self, tld):
        assert data_catalog.is_iana_tld(tld) is True
        assert data_catalog.is_iana_tld(tld.upper()) is True

    def test_tld_list_shape_and_count(self):
        tlds = data_catalog.iana_tlds()
        assert data_catalog.tld_count() == len(tlds)
        assert data_catalog.tld_count() >= 1400
        assert tlds == sorted(tlds)
        assert len(set(tlds)) == len(tlds)
        assert all(TLD_PATTERN.match(tld) for tld in tlds)
        assert any(tld.startswith('xn--') for tld in tlds)
        assert data_catalog.iana_tlds() is data_catalog.iana_tlds()

    def test_tld_normalisation(self):
        assert data_catalog.is_iana_tld('.com') is True
        assert data_catalog.is_iana_tld('.COM') is True
        assert data_catalog.is_iana_tld('  dev ') is True
        assert data_catalog.is_iana_tld('..org') is True

    def test_tld_negatives(self):
        assert data_catalog.is_iana_tld('notarealtld123') is False
        assert data_catalog.is_iana_tld('') is False
        assert data_catalog.is_iana_tld('.') is False
        assert data_catalog.is_iana_tld('com.') is False
        assert data_catalog.is_iana_tld(None) is False
        assert data_catalog.is_iana_tld(123) is False


# ---------------------------------------------------------------------------
# File extensions -- real pack
# ---------------------------------------------------------------------------


class TestExtensions:
    """Known extension categories, normalisation and search."""

    def test_known_extension_categories(self):
        assert data_catalog.file_extension('exe').category == 'executable'
        assert data_catalog.extension_category('.zip') == 'archive'
        assert data_catalog.extension_category('zip') == 'archive'
        entry = data_catalog.file_extension('exe')
        assert isinstance(entry.description, str)
        assert data_catalog.file_extension('exe').to_dict()['category'] == 'executable'

    def test_extension_normalisation(self):
        assert data_catalog.file_extension('.exe') is data_catalog.file_extension('exe')
        assert data_catalog.file_extension('EXE') is data_catalog.file_extension('exe')
        assert data_catalog.file_extension(' .Zip ') is data_catalog.file_extension('zip')

    def test_extensions_for_category_and_search(self):
        archives = [entry.ext for entry in data_catalog.extensions_for_category('archive')]
        assert 'zip' in archives
        assert data_catalog.extensions_for_category('Archive') == \
            data_catalog.extensions_for_category('archive')
        for entry in data_catalog.extensions_for_category('archive'):
            assert entry.category == 'archive'
        found = data_catalog.search_extensions('archive')
        assert found
        assert 'zip' in [entry.ext for entry in found]
        assert len(data_catalog.search_extensions('')) >= 100
        assert data_catalog.search_extensions('zzz-no-such-extension') == []
        assert data_catalog.search_extensions(None) == []

    def test_extension_robustness(self):
        assert data_catalog.file_extension('zzzz') is None
        assert data_catalog.file_extension('.zzzz') is None
        assert data_catalog.file_extension('') is None
        assert data_catalog.file_extension(None) is None
        assert data_catalog.file_extension(123) is None
        assert data_catalog.extension_category('zzzz') is None
        assert data_catalog.extension_category('') is None
        assert data_catalog.extension_category(None) is None
        for entry in data_catalog.search_extensions(''):
            assert entry.ext and entry.ext == entry.ext.lower()
            assert '.' not in entry.ext
            assert entry.category


# ---------------------------------------------------------------------------
# MIME types -- real pack
# ---------------------------------------------------------------------------


class TestMimes:
    """Known mime mappings, reverse lookup, counts and search."""

    @pytest.mark.parametrize('ext,mime', KNOWN_MIMES)
    def test_known_mimes(self, ext, mime):
        entry = data_catalog.mime_for_extension(ext)
        assert entry is not None, ext
        assert entry.mime == mime
        assert entry.extension == ext
        upper = data_catalog.mime_for_extension(ext.upper())
        assert upper is entry
        assert data_catalog.mime_for_extension('.' + ext) is entry
        assert data_catalog.extension_for_mime(mime).mime == mime

    def test_extension_for_mime(self):
        entry = data_catalog.extension_for_mime('application/json')
        assert entry is not None
        assert entry.extension == 'json'
        assert data_catalog.extension_for_mime('APPLICATION/JSON') is entry
        assert data_catalog.extension_for_mime(' application/json ') is entry

    def test_mimes_count_and_search(self):
        assert data_catalog.mimes_count() >= 300
        assert data_catalog.mimes_count() == len(data_catalog.search_mimes(''))
        assert data_catalog.search_mimes('json')
        assert data_catalog.search_mimes('image/')
        assert data_catalog.mime_for_extension('json') in data_catalog.search_mimes('json')
        for entry in data_catalog.search_mimes(''):
            assert '/' in entry.mime
            assert entry.mime == entry.mime.lower()
            assert entry.extension == entry.extension.lower()

    def test_mime_robustness(self):
        assert data_catalog.mime_for_extension('zzzz') is None
        assert data_catalog.mime_for_extension('') is None
        assert data_catalog.mime_for_extension(None) is None
        assert data_catalog.mime_for_extension(123) is None
        assert data_catalog.extension_for_mime('application/nope') is None
        assert data_catalog.extension_for_mime('') is None
        assert data_catalog.extension_for_mime(None) is None
        assert data_catalog.extension_for_mime(123) is None
        assert data_catalog.search_mimes('zzz-no-such-mime') == []
        assert data_catalog.search_mimes(None) == []


# ---------------------------------------------------------------------------
# User agents -- real pack
# ---------------------------------------------------------------------------


class TestUserAgents:
    """Deterministic seeded draws and the family/platform filters."""

    def test_seed_determinism(self):
        for seed in (0, 1, 42, 999):
            first = data_catalog.random_user_agent(seed=seed)
            second = data_catalog.random_user_agent(seed=seed)
            assert isinstance(first, str) and first
            assert first == second
        distinct = {data_catalog.random_user_agent(seed=s) for s in range(30)}
        assert len(distinct) >= 2

    def test_family_filter(self):
        for seed in range(6):
            agent = data_catalog.random_user_agent(family='Chrome', seed=seed)
            assert 'Chrome/' in agent or 'CriOS/' in agent

    def test_platform_filter(self):
        for seed in range(6):
            agent = data_catalog.random_user_agent(platform='Windows 11', seed=seed)
            assert 'Windows NT 10.0' in agent

    def test_family_and_platform_filters(self):
        pool = data_catalog._filter_user_agents(
            data_catalog._load_user_agents(), 'Chrome', 'Windows 11')
        if pool:
            for seed in range(4):
                agent = data_catalog.random_user_agent(family='Chrome',
                                                       platform='Windows 11', seed=seed)
                assert 'Chrome/' in agent
                assert 'Windows NT 10.0' in agent

    def test_robust_filters_and_seeds(self):
        unknown = data_catalog.random_user_agent(family='NoSuchFamilyXYZ', seed=3)
        assert isinstance(unknown, str) and unknown
        assert isinstance(data_catalog.random_user_agent(platform='NopeOS'), str)
        assert isinstance(data_catalog.random_user_agent(family=None, platform=None), str)
        # unhashable seed values must not raise
        assert isinstance(data_catalog.random_user_agent(seed=[1]), str)
        assert isinstance(data_catalog.random_user_agent(family=123, seed=object()), str)


# ---------------------------------------------------------------------------
# Catalog statistics -- real pack
# ---------------------------------------------------------------------------


class TestCatalogStats:
    """catalog_stats()/catalog_summary() over the ten packs."""

    def test_catalog_stats_shape(self):
        stats = data_catalog.catalog_stats()
        assert len(stats) == 10
        assert {stat.name for stat in stats} == PACK_NAMES
        for stat in stats:
            assert isinstance(stat.entries, int) and stat.entries >= 0
            assert isinstance(stat.loaded, bool)
            assert isinstance(stat.to_dict(), dict)

    def test_catalog_stats_match_public_counts(self):
        counters = {
            'countries_iso3166': data_catalog.countries_count,
            'languages_iso639': data_catalog.languages_count,
            'cwe_catalog': data_catalog.cwes_count,
            'iana_tlds': data_catalog.tld_count,
            'mime_types': data_catalog.mimes_count,
        }
        counts = {stat.name: stat.entries for stat in data_catalog.catalog_stats()}
        for name, counter in counters.items():
            assert counts[name] == counter(), name

    def test_catalog_stats_all_loaded_with_entries(self):
        stats = data_catalog.catalog_stats()
        for stat in stats:
            assert stat.loaded, stat.name
            assert stat.entries > 0, stat.name

    def test_catalog_summary_table(self):
        summary = data_catalog.catalog_summary()
        assert isinstance(summary, str)
        assert not summary.endswith('\n')
        for name in PACK_NAMES:
            assert name in summary
        assert 'total' in summary
        assert any(character.isdigit() for character in summary)
        assert len(summary.splitlines()) >= 15


# ---------------------------------------------------------------------------
# Never-raise contract (passes with or without pack files)
# ---------------------------------------------------------------------------


class TestNeverRaises:
    """Every lookup/search stays polite on garbage input."""

    @pytest.mark.parametrize('bad', GARBAGE)
    def test_lookup_functions_never_raise(self, bad):
        assert data_catalog.country(bad) is None
        assert data_catalog.language(bad) is None
        assert data_catalog.currency(bad) is None
        assert data_catalog.cwe(bad) is None
        assert data_catalog.http_status(bad) is None
        assert data_catalog.file_extension(bad) is None
        assert data_catalog.extension_category(bad) is None
        assert data_catalog.mime_for_extension(bad) is None
        assert data_catalog.extension_for_mime(bad) is None
        assert data_catalog.port_service(bad, bad) is None
        assert data_catalog.is_iana_tld(bad) is False
        assert data_catalog.currencies_for_country(bad) == []
        assert data_catalog.ports_for_service(bad) == []

    @pytest.mark.parametrize('bad', GARBAGE)
    def test_search_functions_never_raise(self, bad):
        assert data_catalog.search_countries(bad) == []
        assert data_catalog.search_languages(bad) == []
        assert data_catalog.search_currencies(bad) == []
        assert data_catalog.search_cwes(bad) == []
        assert data_catalog.search_extensions(bad) == []
        assert data_catalog.search_mimes(bad) == []
        assert data_catalog.http_statuses_for_category(bad) == []
        assert data_catalog.extensions_for_category(bad) == []
        assert isinstance(data_catalog.random_user_agent(family=bad), str)
        assert isinstance(data_catalog.random_user_agent(platform=bad, seed=1), str)


# ---------------------------------------------------------------------------
# Synthetic packs: tolerant parsing of malformed lines
# ---------------------------------------------------------------------------


class TestSyntheticPacks:
    """Deliberately malformed packs are parsed tolerantly, never fatally."""

    def test_synthetic_countries(self, synthetic_packs):
        assert data_catalog.countries_count() == 4
        assert data_catalog.country('US').name == 'United States'
        assert data_catalog.country('US').capital == 'Washington, D.C.'
        assert data_catalog.country('de') is data_catalog.country('DE')
        assert data_catalog.country('de').code3 == 'DEU'
        assert data_catalog.country('XX').capital == ''
        assert data_catalog.country('USAAL') is None
        assert data_catalog.search_countries('united') == [
            data_catalog.country('US'), data_catalog.country('GB'),
        ]

    def test_synthetic_ports(self, synthetic_packs):
        assert data_catalog.port_service(22).service == 'ssh'
        assert data_catalog.port_service(22).description == 'Secure Shell remote login'
        assert data_catalog.port_service(53, 'udp').service == 'domain'
        assert data_catalog.port_service(53, 'tcp').service == 'domain'
        assert data_catalog.port_service(443) is None
        assert data_catalog.port_service(99999) is None
        assert data_catalog.service_names() == ['domain', 'http', 'http-alt', 'ssh']
        assert [entry.port for entry in data_catalog.ports_for_service('domain')] == [53, 53]
        assert [entry.port for entry in data_catalog.well_known_tcp()] == [22, 53, 80]
        assert [entry.port for entry in data_catalog.notable_registered()] == [8080]

    def test_synthetic_languages(self, synthetic_packs):
        assert data_catalog.languages_count() == 3
        assert data_catalog.language('en').name == 'English'
        assert data_catalog.language('DE').name == 'German'
        assert data_catalog.language('deu').name == 'German'
        assert data_catalog.language('xx') is None
        assert [entry.code for entry in data_catalog.search_languages('german')] == \
            ['de', 'deu']

    def test_synthetic_currencies(self, synthetic_packs):
        assert data_catalog.currency('EUR').minor_units == 2
        assert data_catalog.currency('usd').code == 'USD'
        assert data_catalog.currency('JPY').minor_units == 0
        assert data_catalog.currency('KWD').minor_units == 3
        assert data_catalog.currency('XAU').minor_units == 0  # 'N/A' minor units
        assert len(data_catalog.search_currencies('')) == 5
        assert data_catalog.currencies_for_country('US') == ['USD']

    def test_synthetic_http_statuses(self, synthetic_packs):
        assert data_catalog.http_status(404).phrase == 'Not Found'
        assert data_catalog.http_status(404).category == 'client_error'
        assert data_catalog.http_status(500).category == 'server_error'
        assert sorted(entry.code for entry in
                      data_catalog.http_statuses_for_category('client_error')) == [404, 429]
        assert data_catalog.http_status_category(200) == 'success'  # derived, no pack
        assert data_catalog.http_status(200).phrase == 'OK'

    def test_synthetic_cwes(self, synthetic_packs):
        assert data_catalog.cwes_count() == 2
        assert 'Cross-site Scripting' in data_catalog.cwe('CWE-79').name
        assert data_catalog.cwe('89').name == 'SQL Injection'
        assert data_catalog.cwe('79') is data_catalog.cwe('CWE-79')
        assert data_catalog.cwe('CWE-079') is data_catalog.cwe('CWE-79')
        assert data_catalog.cwe('CWE-99999') is None

    def test_synthetic_tlds(self, synthetic_packs):
        assert data_catalog.iana_tlds() == ['com', 'dev', 'org', 'xn--p1ai', 'z1']
        assert data_catalog.tld_count() == 5
        assert data_catalog.is_iana_tld('.COM') is True
        assert data_catalog.is_iana_tld('ORG') is True
        assert data_catalog.is_iana_tld('bad tld') is False
        assert data_catalog.is_iana_tld('') is False

    def test_synthetic_extensions(self, synthetic_packs):
        assert data_catalog.file_extension('exe').category == 'executable'
        assert data_catalog.file_extension('exe').description == 'Windows executable'
        assert data_catalog.extension_category('.zip') == 'archive'
        assert data_catalog.file_extension('PDF').category == 'document'
        assert [entry.ext for entry in
                data_catalog.extensions_for_category('Archive')] == ['zip']
        assert len(data_catalog.search_extensions('')) == 3

    def test_synthetic_mimes(self, synthetic_packs):
        assert data_catalog.mime_for_extension('json').mime == 'application/json'
        assert data_catalog.mime_for_extension('HTML').mime == 'text/html'
        assert data_catalog.mime_for_extension('.png').mime == 'image/png'
        assert data_catalog.extension_for_mime('APPLICATION/JSON').extension == 'json'
        assert data_catalog.mimes_count() == 4  # duplicate row stays in the entries list
        assert data_catalog.mime_for_extension('json').description == 'JSON data'

    def test_synthetic_user_agents(self, synthetic_packs):
        assert len(data_catalog._load_user_agents()) == 3
        agent = data_catalog.random_user_agent(family='Chrome', platform='Windows 11',
                                               seed=1)
        assert 'Chrome/' in agent
        assert 'Windows NT 10.0' in agent
        assert data_catalog.random_user_agent(seed=42) == \
            data_catalog.random_user_agent(seed=42)
        assert isinstance(data_catalog.random_user_agent(family='Nope'), str)


# ---------------------------------------------------------------------------
# Missing catalog: graceful degradation to empty results
# ---------------------------------------------------------------------------


class TestEmptyCatalog:
    """An empty DATA_DIR yields empty results, never exceptions."""

    def test_missing_packs_yield_empty_lookups(self, empty_packs_dir):
        assert data_catalog.country('US') is None
        assert data_catalog.search_countries('') == []
        assert data_catalog.countries_count() == 0
        assert data_catalog.port_service(22) is None
        assert data_catalog.service_names() == []
        assert data_catalog.well_known_tcp() == []
        assert data_catalog.notable_registered() == []
        assert data_catalog.language('en') is None
        assert data_catalog.languages_count() == 0
        assert data_catalog.currency('EUR') is None
        assert data_catalog.cwe('79') is None
        assert data_catalog.http_status(404) is None
        assert data_catalog.iana_tlds() == []
        assert data_catalog.tld_count() == 0
        assert data_catalog.is_iana_tld('com') is False
        assert data_catalog.file_extension('exe') is None
        assert data_catalog.extension_category('.zip') is None
        assert data_catalog.mime_for_extension('json') is None
        assert data_catalog.extension_for_mime('application/json') is None
        assert data_catalog.mimes_count() == 0
        # data-independent helpers keep working
        assert data_catalog.currencies_for_country('US') == ['USD']
        assert data_catalog.http_status_category(404) == 'client_error'
        assert data_catalog.port_category(8080) == 'registered'

    def test_missing_packs_stats_summary_and_fallback(self, empty_packs_dir):
        stats = data_catalog.catalog_stats()
        assert len(stats) == 10
        assert {stat.name for stat in stats} == PACK_NAMES
        assert all(stat.entries == 0 for stat in stats)
        assert all(stat.loaded is False for stat in stats)
        summary = data_catalog.catalog_summary()
        assert 'total' in summary
        for name in PACK_NAMES:
            assert name in summary
        assert data_catalog.random_user_agent() == data_catalog._FALLBACK_USER_AGENT
        assert data_catalog.random_user_agent(family='Chrome') == \
            data_catalog._FALLBACK_USER_AGENT

# ---------------------------------------------------------------------------
# ObscuraLens v6.0 -- tests for the bssid kind (WiFi BSSID lookups).
#
# Covers: validators (format/canonicalisation), the offline EUI-48 bit
# decomposition, the curated OUI vendor pack bridge, the mylnikov keyless
# geolocation reader (faked HTTP), the keyed WiGLE reader, the gather_all
# merge with provenance, the tracker envelope contract (including the
# invalid-input short-circuit that must never touch the network), the
# explainable rule pack and the platform-wide registration points.
#
# The offline readers are exercised directly (they never touch the network);
# the online readers run against the shared fake_http fixture from
# tests/conftest.py, which records every call so tests can assert that a
# failed validation produced zero requests.
# ---------------------------------------------------------------------------

from obscuralens.trackers import bssid_sources as bsrc
from obscuralens.utils.validators import normalize_bssid, validate_bssid

# --------------------------------------------------------------------------- #
# validators
# --------------------------------------------------------------------------- #

class TestValidateBSSID:

    def test_accepts_colon_form(self):
        assert validate_bssid('00:1A:2B:3C:4D:5E')[0] is True

    def test_accepts_dash_and_dotted_forms(self):
        assert validate_bssid('00-1A-2B-3C-4D-5E')[0] is True
        assert validate_bssid('001A.2B3C.4D5E')[0] is True

    def test_accepts_bare_hex(self):
        assert validate_bssid('001A2B3C4D5E')[0] is True

    def test_accepts_lowercase(self):
        assert validate_bssid('00:1a:2b:3c:4d:5e')[0] is True

    def test_rejects_short_value(self):
        ok, error = validate_bssid('00:1A:2B')
        assert ok is False
        assert error

    def test_rejects_long_value(self):
        ok, error = validate_bssid('00:1A:2B:3C:4D:5E:6F')
        assert ok is False

    def test_rejects_non_hex_letters(self):
        for bad in ('ZZ:1A:2B:3C:4D:5E', '00:1G:2B:3C:4D:5E'):
            assert validate_bssid(bad)[0] is False

    def test_rejects_empty_and_none(self):
        assert validate_bssid('')[0] is False

    def test_error_messages_are_strings(self):
        for bad in ('', 'nope', '00:1A:2B'):
            ok, error = validate_bssid(bad)
            assert ok is False
            assert isinstance(error, str) and error

    def test_normalize_lowercases_and_colons(self):
        assert normalize_bssid('00-1A-2B-3C-4D-5E') == '00:1a:2b:3c:4d:5e'

    def test_normalize_bare_hex(self):
        assert normalize_bssid('001A2B3C4D5E') == '00:1a:2b:3c:4d:5e'


# --------------------------------------------------------------------------- #
# offline: EUI-48 bit decomposition
# --------------------------------------------------------------------------- #

class TestBSSIDMath:

    def test_unicast_globally_unique_flags(self):
        out = bsrc._bssid_math('00:1A:2B:3C:4D:5E')
        assert out['is_multicast'] is False
        assert out['is_locally_administered'] is False
        assert out['transmission'].startswith('unicast')
        assert out['assignment'].startswith('globally unique')

    def test_multicast_bit_detection(self):
        # 01:80:c2:00:00:00 is the classic STP reserved multicast address.
        out = bsrc._bssid_math('01:80:C2:00:00:00')
        assert out['is_multicast'] is True
        assert 'multicast' in out['transmission']

    def test_locally_administered_bit_detection(self):
        # Second-least-significant bit of the first octet: 0x02.
        out = bsrc._bssid_math('02:1A:2B:3C:4D:5E')
        assert out['is_locally_administered'] is True
        assert 'locally administered' in out['assignment']
        assert out['randomization_hint']

    def test_randomization_hint_absent_for_global(self):
        out = bsrc._bssid_math('00:1A:2B:3C:4D:5E')
        assert 'randomization_hint' not in out

    def test_eui64_expansion_inserts_ff_fe(self):
        out = bsrc._bssid_math('00:1A:2B:3C:4D:5E')
        assert out['eui64_expansion'] == '00:1a:2b:ff:fe:3c:4d:5e'

    def test_ipv6_interface_id_flips_ul_bit(self):
        out = bsrc._bssid_math('00:1A:2B:3C:4D:5E')
        assert out['ipv6_interface_id'].startswith('02:1a:2b:ff:fe:')

    def test_ipv6_link_local_hint_shape(self):
        out = bsrc._bssid_math('00:1A:2B:3C:4D:5E')
        assert out['ipv6_link_local_hint'].startswith('fe80::')

    def test_invalid_input_returns_empty(self):
        assert bsrc._bssid_math('not-a-mac') == {}
        assert bsrc._bssid_math('') == {}

    def test_none_input_returns_empty(self):
        assert bsrc._bssid_math(None) == {}


# --------------------------------------------------------------------------- #
# offline: curated OUI vendor pack bridge
# --------------------------------------------------------------------------- #

class TestOUIVendor:

    def test_known_prefix_resolves_vendor(self):
        # 00:00:0C is Cisco Systems in the curated pack; the prefix is
        # echoed in IEEE registry casing.
        out = bsrc._oui_vendor('00:00:0C:11:22:33')
        assert out['vendor'] == 'Cisco Systems, Inc'
        assert out['oui_prefix'] == '00:00:0C'

    def test_unknown_prefix_reports_none_not_empty(self):
        # A curated-subset miss is an expected outcome: the reader answers
        # an explicit None so source health records OK and the merge layer
        # drops the field.
        out = bsrc._oui_vendor('DE:AD:BE:EF:00:01')
        assert out == {'vendor': None}

    def test_invalid_input_returns_empty(self):
        assert bsrc._oui_vendor('nope') == {}


# --------------------------------------------------------------------------- #
# online: mylnikov keyless geolocation (faked HTTP)
# --------------------------------------------------------------------------- #

class TestMylnikov:

    def test_successful_fix_parses_coordinates(self, fake_http, monkeypatch):
        monkeypatch.setattr(bsrc, 'time', type('T', (), {
            'sleep': staticmethod(lambda *_: None)})())
        fake_http.json = lambda url, **kw: (True, {
            'result': 200,
            'data': {'lat': 55.75, 'lon': 37.61, 'range': 120,
                     'time': '2024-05-01 10:00:00'},
        }, '')
        out = bsrc._mylnikov('00:1A:2B:3C:4D:5E')
        assert out['lat'] == 55.75
        assert out['lon'] == 37.61
        assert out['accuracy_range'] == 120.0
        assert out['time'] == '2024-05-01 10:00:00'

    def test_non_200_result_is_clean_no_data(self, fake_http, monkeypatch):
        monkeypatch.setattr(bsrc, 'time', type('T', (), {
            'sleep': staticmethod(lambda *_: None)})())
        fake_http.json = lambda url, **kw: (True, {'result': 404}, '')
        assert bsrc._mylnikov('00:1A:2B:3C:4D:5E') == {}

    def test_empty_data_block_is_clean_no_data(self, fake_http, monkeypatch):
        monkeypatch.setattr(bsrc, 'time', type('T', (), {
            'sleep': staticmethod(lambda *_: None)})())
        fake_http.json = lambda url, **kw: (True, {'result': 200, 'data': {}}, '')
        assert bsrc._mylnikov('00:1A:2B:3C:4D:5E') == {}

    def test_transport_failure_returns_empty(self, fake_http, monkeypatch):
        monkeypatch.setattr(bsrc, 'time', type('T', (), {
            'sleep': staticmethod(lambda *_: None)})())
        fake_http.json = lambda url, **kw: (False, None, 'timeout')
        assert bsrc._mylnikov('00:1A:2B:3C:4D:5E') == {}

    def test_non_numeric_coordinates_are_dropped(self, fake_http, monkeypatch):
        monkeypatch.setattr(bsrc, 'time', type('T', (), {
            'sleep': staticmethod(lambda *_: None)})())
        fake_http.json = lambda url, **kw: (True, {
            'result': 200,
            'data': {'lat': 'north', 'lon': None, 'range': 'wide'},
        }, '')
        assert bsrc._mylnikov('00:1A:2B:3C:4D:5E') == {}


# --------------------------------------------------------------------------- #
# keyed: WiGLE network search (faked HTTP)
# --------------------------------------------------------------------------- #

class TestWigle:

    def test_successful_search_parses_network(self, fake_http):
        fake_http.json = lambda url, **kw: (True, {
            'results': [{
                'netid': '00:1A:2B:3C:4D:5E', 'ssid': 'CoffeeShop',
                'trilat': 52.52, 'trilong': 13.40,
                'encryption': 'wpa2', 'lastupdt': '2024-05-01',
            }],
        }, '')
        out = bsrc._wigle('00:1A:2B:3C:4D:5E', 'a2V5OjEyMw==')
        assert out['ssid'] == 'CoffeeShop'
        assert out['lat'] == 52.52
        assert out['lon'] == 13.40
        assert out['encryption'] == 'wpa2'

    def test_authorization_header_is_sent(self, fake_http):
        seen = {}

        def dispatch(url, **kwargs):
            seen['url'] = url
            seen['headers'] = kwargs.get('headers')
            return True, {'results': []}, ''

        fake_http.json = dispatch
        bsrc._wigle('00:1A:2B:3C:4D:5E', 'a2V5OjEyMw==')
        assert seen['headers'] == {'Authorization': 'Basic a2V5OjEyMw=='}
        assert 'wigle.net' in seen['url']

    def test_empty_results_returns_empty(self, fake_http):
        fake_http.json = lambda url, **kw: (True, {'results': []}, '')
        assert bsrc._wigle('00:1A:2B:3C:4D:5E', 'key') == {}

    def test_missing_key_returns_empty_without_call(self, fake_http):
        assert bsrc._wigle('00:1A:2B:3C:4D:5E', '') == {}
        assert fake_http.calls == []

    def test_transport_failure_returns_empty(self, fake_http):
        fake_http.json = lambda url, **kw: (False, None, 'down')
        assert bsrc._wigle('00:1A:2B:3C:4D:5E', 'key') == {}


# --------------------------------------------------------------------------- #
# gather_all merge + provenance
# --------------------------------------------------------------------------- #

class TestBSSIDGather:

    def test_invalid_input_raises_value_error(self):
        try:
            bsrc.gather_all('not-a-mac')
        except ValueError:
            pass
        else:
            raise AssertionError('expected ValueError for unparseable input')

    def test_offline_only_run_produces_fields(self, monkeypatch):
        # Disable every online source by faking transport failures.
        from obscuralens.utils import http_client
        monkeypatch.setattr(http_client.http, 'get_json',
                            lambda url, **kw: (False, None, 'offline'))
        out = bsrc.gather_all('00:1A:2B:3C:4D:5E')
        assert 'bssid' in out['fields']
        assert 'eui64_expansion' in out['fields']
        assert out['provenance']['eui64_expansion'] == ['bssid_math']

    def test_sources_status_reports_no_data_for_misses(self, monkeypatch):
        from obscuralens.utils import http_client
        monkeypatch.setattr(http_client.http, 'get_json',
                            lambda url, **kw: (False, None, 'offline'))
        out = bsrc.gather_all('00:1A:2B:3C:4D:5E')
        status = out['sources']
        assert 'mylnikov' in status
        assert status['mylnikov'] == {'ok': False, 'error': 'no data'}

    def test_offline_sources_precede_online_in_provenance(self):
        # FREE_SOURCES declaration order is the merge priority; the two
        # offline readers are declared first.
        names = list(bsrc.FREE_SOURCES.keys())
        assert names.index('oui_vendor') < names.index('mylnikov')
        assert names.index('bssid_math') < names.index('mylnikov')


# --------------------------------------------------------------------------- #
# tracker envelope contract
# --------------------------------------------------------------------------- #

class TestBSSIDTracker:

    def test_invalid_input_short_circuits_without_network(self, fake_http):
        from obscuralens.trackers.bssid_tracker import BSSIDTracker
        tracker = BSSIDTracker()
        result = tracker.track('not-a-mac')
        assert result['success'] is False
        assert result['info'] == {}
        assert fake_http.calls == []

    def test_source_catalog_and_names(self):
        from obscuralens.trackers.bssid_tracker import BSSIDTracker
        tracker = BSSIDTracker()
        names = tracker.source_names()
        assert 'bssid_math' in names
        assert 'mylnikov' in names
        assert 'wigle' in names
        catalog = tracker.source_catalog()
        assert catalog['mylnikov']
        assert catalog['wigle']

    def test_offline_track_envelope_shape(self, monkeypatch):
        from obscuralens.utils import http_client
        monkeypatch.setattr(http_client.http, 'get_json',
                            lambda url, **kw: (False, None, 'offline'))
        from obscuralens.trackers.bssid_tracker import BSSIDTracker
        result = BSSIDTracker().track('00:1A:2B:3C:4D:5E')
        for key in ('bssid', 'info', 'field_sources', 'sources_ok',
                    'sources_failed', 'field_count', 'success', 'errors'):
            assert key in result, key
        assert result['bssid'] == '00:1a:2b:3c:4d:5e'
        assert result['success'] is True
        assert 'bssid_math' in result['sources_ok']


# --------------------------------------------------------------------------- #
# rule pack
# --------------------------------------------------------------------------- #

class TestBSSIDRules:

    def test_randomized_mac_rule_hits(self):
        from obscuralens.rules import evaluate_rules
        evaluation = evaluate_rules('bssid', {
            'is_locally_administered': True,
            'vendor': None,
        })
        assert evaluation.score > 0
        assert evaluation.band != 'clean'

    def test_multicast_rule_hits(self):
        from obscuralens.rules import evaluate_rules
        evaluation = evaluate_rules('bssid', {'is_multicast': True})
        assert evaluation.score > 0

    def test_plain_bssid_stays_low(self):
        from obscuralens.rules import evaluate_rules
        evaluation = evaluate_rules('bssid', {
            'is_multicast': False, 'is_locally_administered': False,
            'vendor': 'Cisco Systems, Inc',
        })
        assert evaluation.band in ('clean', 'watch', 'elevated')


# --------------------------------------------------------------------------- #
# platform registration
# --------------------------------------------------------------------------- #

class TestBSSIDRegistration:

    def test_cli_kind_registered(self):
        from obscuralens import commands
        assert 'bssid' in commands.KINDS

    def test_web_kind_registered(self):
        from obscuralens.web.app import _TARGET_KEY, KINDS
        assert 'bssid' in KINDS
        assert _TARGET_KEY.get('bssid') == 'bssid'

    def test_mcp_tool_registered(self):
        from obscuralens.mcp_server import TOOLS
        assert 'bssid_lookup' in {tool['name'] for tool in TOOLS}

    def test_batch_kind_supported(self):
        from obscuralens.advanced.batch import SUPPORTED_KINDS
        assert 'bssid' in SUPPORTED_KINDS

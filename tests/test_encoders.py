"""
Offline tests for the experimental polyglot encoder workbench.

`obscuralens/experimental/encoders.py` backs the analyst toolbox - the
`obscuralens tools encode|decode` CLI commands and the `/api/tools/encode`
and `/api/tools/decode` REST endpoints - but shipped with no test coverage at
all.  Everything here is pure stdlib and offline.

The module documents three contracts, and these tests pin all of them:

1. every scheme in ``SCHEMES`` round-trips (Morse excepted - it is case-less
   by design, see ``TestMorse``);
2. individual decoders raise ``ValueError`` with a clear message on malformed
   input, and never leak another exception type;
3. the aggregate entry points (``encode_all`` / ``decode_auto``) swallow those
   ``ValueError``s and simply skip the failing scheme, so an analyst firing the
   magic decoder at arbitrary garbage gets a shorter list, never a crash.
"""

import base64
import hashlib
import re
import zlib

import pytest

from obscuralens.experimental import encoders as enc

SCHEME_NAMES = list(enc.SCHEMES)

# A representative payload: mixed case, a space and digits, so it exercises
# letter-shifting schemes (ROT13/Caesar) as well as the byte-oriented ones.
SAMPLE = 'ObscuraLens OSINT 42'


# --------------------------------------------------------------------------- #
# registry shape
# --------------------------------------------------------------------------- #

class TestSchemeRegistry:
    def test_every_scheme_has_the_four_required_keys(self):
        for name, scheme in enc.SCHEMES.items():
            assert set(scheme) == {'label', 'description', 'encode', 'decode'}, name
            assert callable(scheme['encode']), name
            assert callable(scheme['decode']), name
            assert isinstance(scheme['label'], str) and scheme['label'], name
            assert isinstance(scheme['description'], str) and scheme['description'], name

    def test_registry_order_is_stable_and_documented(self):
        # `encode_all` returns results in registry order and `decode_auto`
        # breaks score ties by it, so the order is part of the observable
        # contract - pin it rather than re-deriving it from the same source.
        assert SCHEME_NAMES == [
            'hex', 'base32', 'base64', 'base85', 'url_percent', 'html_entity',
            'rot13', 'caesar', 'binary', 'decimal', 'reversed', 'morse', 'gzip',
        ]

    def test_scheme_names_are_unique_snake_case_identifiers(self):
        # They are used as CLI/JSON keys and dict lookups, so the shape matters.
        assert len(set(SCHEME_NAMES)) == len(SCHEME_NAMES)
        assert all(re.fullmatch(r'[a-z][a-z0-9_]*', name) for name in SCHEME_NAMES)

    def test_exports_resolve(self):
        for name in enc.__all__:
            assert hasattr(enc, name), name

    def test_morse_table_covers_letters_digits_and_punctuation(self):
        table = enc.MORSE_TABLE
        for ch in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789':
            assert ch in table, ch
        # ITU punctuation is included, so '!' and '?' are encodable.
        assert '!' in table and '?' in table and '.' in table


# --------------------------------------------------------------------------- #
# round-trips
# --------------------------------------------------------------------------- #

# Morse is excluded: it has no case, so a round-trip returns uppercase.
ROUND_TRIP_SCHEMES = [n for n in SCHEME_NAMES if n != 'morse']


class TestRoundTrips:
    @pytest.mark.parametrize('scheme', ROUND_TRIP_SCHEMES)
    def test_encode_then_decode_restores_the_input(self, scheme):
        encoded = enc.SCHEMES[scheme]['encode'](SAMPLE)
        assert isinstance(encoded, str)
        assert enc.SCHEMES[scheme]['decode'](encoded) == SAMPLE

    @pytest.mark.parametrize('scheme', ROUND_TRIP_SCHEMES)
    def test_round_trip_survives_unicode(self, scheme):
        text = 'caf\u00e9 \u4e2d\u6587 \U0001f50d'
        encoded = enc.SCHEMES[scheme]['encode'](text)
        assert enc.SCHEMES[scheme]['decode'](encoded) == text

    @pytest.mark.parametrize('scheme', ROUND_TRIP_SCHEMES)
    def test_round_trip_survives_punctuation_and_markup(self, scheme):
        text = '<script>alert("x&y")</script> 100% @ #/'
        encoded = enc.SCHEMES[scheme]['encode'](text)
        assert enc.SCHEMES[scheme]['decode'](encoded) == text

    @pytest.mark.parametrize('scheme', ROUND_TRIP_SCHEMES)
    def test_encoding_actually_changes_the_payload(self, scheme):
        # html_entity leaves markup-free text alone by design; every other
        # scheme must visibly transform it or it is not doing its job.
        encoded = enc.SCHEMES[scheme]['encode'](SAMPLE)
        if scheme == 'html_entity':
            pytest.skip('html_entity only escapes markup characters')
        assert encoded != SAMPLE

    def test_decoders_tolerate_wrapped_input(self):
        # Analysts paste base64 out of PEM blocks and mail clients, so the
        # byte-oriented decoders squash whitespace before decoding.
        wrapped = 'T2JzY3VyYUxl\nbnMgT1NJ\nTlQgNDI='
        assert enc.base64_decode(wrapped) == SAMPLE
        hexed = ' '.join(enc.hex_encode(SAMPLE)[i:i + 2] for i
                         in range(0, len(enc.hex_encode(SAMPLE)), 2))
        assert enc.hex_decode(hexed) == SAMPLE

    def test_base64_urlsafe_alphabet_is_accepted(self):
        # The documented URL-safe fallback: -/_ remapped onto +//.
        raw = b'\xfb\xff\xfe' * 8
        urlsafe = base64.urlsafe_b64encode(raw).decode('ascii')
        assert '-' in urlsafe or '_' in urlsafe
        assert enc.base64_decode(urlsafe) == raw.decode('utf-8', errors='replace')

    def test_base85_accepts_adobe_framing(self):
        raw = b'payload here'
        framed = '<~' + base64.a85encode(raw).decode('ascii') + '~>'
        assert enc.base85_decode(framed) == raw.decode('ascii')

    def test_base32_is_case_insensitive(self):
        encoded = enc.base32_encode(SAMPLE)
        assert enc.base32_decode(encoded.lower()) == SAMPLE

    def test_gzip_armor_is_base64_of_zlib(self):
        encoded = enc.gzip_encode(SAMPLE)
        assert zlib.decompress(base64.b64decode(encoded)).decode() == SAMPLE


# --------------------------------------------------------------------------- #
# decoder error contracts
# --------------------------------------------------------------------------- #

MALFORMED = {
    'hex_decode': ['zz', 'abc', 'a', ''],         # non-hex, odd length, empty
    'base32_decode': ['!!!', '1111', 'A===='],     # outside alphabet / bad pad
    'base64_decode': ['!!!!', '@@@@'],
    'base85_decode': ['', 'a', '!'],               # empty / truncated hunk
    'binary_decode': ['notbits', '012', '2'],
    'decimal_decode': ['x', '999999999999'],
    'gzip_decode': ['!!!!', 'not-zlib'],
    'morse_decode': ['abc', 'plain text'],
}


class TestDecoderErrorContracts:
    @pytest.mark.parametrize('name,payloads', sorted(MALFORMED.items()))
    def test_malformed_input_raises_value_error(self, name, payloads):
        decoder = getattr(enc, name)
        for payload in payloads:
            with pytest.raises(ValueError):
                decoder(payload)

    @pytest.mark.parametrize('name,payloads', sorted(MALFORMED.items()))
    def test_the_error_message_is_helpful(self, name, payloads):
        decoder = getattr(enc, name)
        for payload in payloads:
            with pytest.raises(ValueError) as info:
                decoder(payload)
            message = str(info.value)
            assert message, f'{name}({payload!r}) raised with no message'
            assert len(message) > 8, message

    def test_no_decoder_leaks_a_non_value_error(self):
        # decode_auto only catches ValueError/UnicodeError, so any other
        # exception escaping a decoder would surface to the analyst as a crash.
        probes = ['', ' ', '!', 'a', 'zz', '\x00', '\ufffd', 'é', '~', '<~',
                  '%', '%2', '&#', '0' * 400, 'eN', '....', '----', '/ / /']
        for name, scheme in enc.SCHEMES.items():
            for probe in probes:
                try:
                    scheme['decode'](probe)
                except (ValueError, UnicodeError):
                    pass
                except Exception as exc:  # pragma: no cover - failure path
                    pytest.fail(f'{name}.decode({probe!r}) leaked '
                                f'{type(exc).__name__}: {exc}')

    @pytest.mark.parametrize('payload', ['a', '!', '0', 'z', '.', 'x', '%'])
    def test_base85_rejects_a_one_character_payload(self, payload):
        # Regression: b85decode silently drops an incomplete trailing hunk, so
        # a single character decoded to '' and reported success while base32
        # and base64 validate up front. base85_encode only ever emits '' for
        # '', so empty output from non-empty input is always garbage.
        with pytest.raises(ValueError, match='zero bytes'):
            enc.base85_decode(payload)

    def test_base85_partial_hunks_still_decode(self):
        # 2-4 characters are not an error: b85 emits the whole bytes a partial
        # hunk can represent, and an incomplete trailing byte degrades to the
        # U+FFFD replacement character via errors='replace'.
        assert enc.base85_decode('ab') == 'q'
        assert enc.base85_decode('abc') == 'qa'
        assert '\ufffd' in enc.base85_decode('abcd')

    def test_hex_tolerates_an_optional_0x_prefix(self):
        # Documented tolerance, pinned so it is not mistaken for a bug.
        assert enc.hex_decode('0x41') == 'A'
        assert enc.hex_decode('0X4f62') == 'Ob'

    def test_empty_input_is_an_error_for_the_armored_schemes(self):
        for name in ('base32_decode', 'base64_decode', 'base85_decode'):
            with pytest.raises(ValueError, match='empty'):
                getattr(enc, name)('')

    @pytest.mark.parametrize('name', [n for n in dir(enc)
                                      if n.endswith(('_encode', '_decode'))
                                      and callable(getattr(enc, n))
                                      and not n.startswith('_')])
    def test_non_string_input_raises_value_error(self, name):
        function = getattr(enc, name)
        if 'xor' in name:
            pytest.skip('xor helpers take a second argument; covered below')
        with pytest.raises(ValueError, match='must be a string'):
            function(123)
        with pytest.raises(ValueError, match='must be a string'):
            function(None)


# --------------------------------------------------------------------------- #
# Caesar / ROT13 / reversal
# --------------------------------------------------------------------------- #

class TestCaesarAndRot13:
    @pytest.mark.parametrize('shift', list(range(26)))
    def test_every_shift_round_trips(self, shift):
        assert enc.caesar_decode(enc.caesar_encode(SAMPLE, shift), shift) == SAMPLE

    def test_shift_wraps_beyond_the_alphabet(self):
        assert enc.caesar_encode(SAMPLE, 29) == enc.caesar_encode(SAMPLE, 3)
        assert enc.caesar_encode(SAMPLE, -23) == enc.caesar_encode(SAMPLE, 3)

    def test_default_shift_is_three(self):
        assert enc.caesar_encode(SAMPLE) == enc.caesar_encode(SAMPLE, 3)

    def test_case_is_preserved_and_digits_untouched(self):
        out = enc.caesar_encode('AbC 123', 1)
        assert out == 'BcD 123'

    def test_rot13_is_self_inverse(self):
        assert enc.rot13_encode(enc.rot13_encode(SAMPLE)) == SAMPLE

    def test_rot13_matches_a_shift_of_thirteen(self):
        assert enc.rot13_encode(SAMPLE) == enc.caesar_encode(SAMPLE, 13)

    def test_rot13_leaves_digits_and_punctuation_alone(self):
        assert enc.rot13_encode('42! @#') == '42! @#'

    def test_reversal_is_self_inverse(self):
        assert enc.reversed_decode(enc.reversed_encode(SAMPLE)) == SAMPLE
        assert enc.reversed_encode('abc') == 'cba'


# --------------------------------------------------------------------------- #
# Morse
# --------------------------------------------------------------------------- #

class TestMorse:
    def test_letters_separate_by_space_and_words_by_slash(self):
        assert enc.morse_encode('SOS') == '... --- ...'
        assert enc.morse_encode('A B') == '.- / -...'

    def test_decode_recovers_uppercase_text(self):
        assert enc.morse_decode('... --- ...') == 'SOS'

    def test_round_trip_is_case_insensitive_by_design(self):
        # Morse has no case, so the round-trip uppercases. Pinned so the lossy
        # behaviour stays a documented property rather than a surprise.
        assert enc.morse_decode(enc.morse_encode(SAMPLE)) == SAMPLE.upper()

    def test_digits_round_trip(self):
        assert enc.morse_decode(enc.morse_encode('12345')) == '12345'

    def test_itu_punctuation_is_encodable(self):
        assert enc.morse_encode('!') == '-.-.--'
        assert enc.morse_decode('-.-.--') == '!'

    def test_unencodable_characters_are_skipped_not_fatal(self):
        # Characters outside the table are dropped, and the rest still encode.
        assert enc.morse_encode('A\u00e9B') == enc.morse_encode('AB')

    def test_text_with_nothing_encodable_raises(self):
        with pytest.raises(ValueError, match='no Morse-encodable'):
            enc.morse_encode('')
        with pytest.raises(ValueError, match='no Morse-encodable'):
            enc.morse_encode('\u4e2d\u6587')

    def test_decode_without_symbols_raises(self):
        with pytest.raises(ValueError, match='no Morse symbols'):
            enc.morse_decode('plain text')

    def test_unknown_sequences_decode_to_a_placeholder(self):
        # Documented tolerance: an unrecognised run becomes '?' rather than
        # raising, so a partially-corrupt payload stays readable.
        assert '?' in enc.morse_decode('.-.-.-.-.-.-')


# --------------------------------------------------------------------------- #
# XOR (keyed, outside SCHEMES)
# --------------------------------------------------------------------------- #

class TestXorKey:
    def test_round_trip_with_a_single_character_key(self):
        payload = 'secret payload'
        encoded = enc.xor_key_encode(payload, 'k')
        assert enc.xor_key_decode(encoded, 'k') == payload

    def test_round_trip_with_a_multi_character_key(self):
        payload = 'exfiltrated credentials 2026'
        encoded = enc.xor_key_encode(payload, 'key0')
        assert enc.xor_key_decode(encoded, 'key0') == payload

    def test_output_is_hexadecimal(self):
        encoded = enc.xor_key_encode('abc', 'k')
        assert all(c in '0123456789abcdef' for c in encoded)
        assert len(encoded) == 6  # 3 bytes -> 6 hex digits

    def test_the_wrong_key_does_not_recover_the_plaintext(self):
        encoded = enc.xor_key_encode('secret payload', 'k')
        assert enc.xor_key_decode(encoded, 'j') != 'secret payload'

    def test_xor_is_not_a_no_op(self):
        assert enc.xor_key_encode('abc', 'k') != 'abc'

    def test_non_hex_payload_raises(self):
        with pytest.raises(ValueError, match='hexadecimal'):
            enc.xor_key_decode('zzzz', 'k')

    def test_odd_hex_length_raises(self):
        with pytest.raises(ValueError, match='odd hex length'):
            enc.xor_key_decode('abc', 'k')

    def test_empty_key_raises(self):
        with pytest.raises(ValueError, match='key must not be empty'):
            enc.xor_key_encode('abc', '')
        with pytest.raises(ValueError, match='key must not be empty'):
            enc.xor_key_decode('6162', '')

    def test_uppercase_hex_is_accepted(self):
        encoded = enc.xor_key_encode('abc', 'k')
        assert enc.xor_key_decode(encoded.upper(), 'k') == 'abc'


# --------------------------------------------------------------------------- #
# encode_all
# --------------------------------------------------------------------------- #

class TestEncodeAll:
    def test_returns_one_entry_per_scheme(self):
        result = enc.encode_all(SAMPLE)
        assert set(result) == set(SCHEME_NAMES)

    def test_values_match_the_individual_encoders(self):
        result = enc.encode_all(SAMPLE)
        for name in SCHEME_NAMES:
            assert result[name] == enc.SCHEMES[name]['encode'](SAMPLE), name

    def test_preserves_registry_order(self):
        assert list(enc.encode_all(SAMPLE)) == SCHEME_NAMES

    def test_a_failing_scheme_is_skipped_not_fatal(self):
        # Morse raises on text with nothing encodable; the aggregate must drop
        # just that scheme.
        result = enc.encode_all('\u4e2d\u6587')
        assert 'morse' not in result
        assert 'base64' in result

    def test_empty_input_still_encodes(self):
        result = enc.encode_all('')
        assert result['hex'] == ''
        assert result['base64'] == ''
        assert 'morse' not in result

    def test_non_string_raises(self):
        with pytest.raises(ValueError, match='must be a string'):
            enc.encode_all(42)


# --------------------------------------------------------------------------- #
# decode_auto - the magic decoder
# --------------------------------------------------------------------------- #

class TestDecodeAuto:
    def test_finds_the_scheme_that_produced_the_blob(self):
        for scheme in ('hex', 'base64', 'base32', 'binary', 'decimal', 'gzip'):
            blob = enc.SCHEMES[scheme]['encode']('the quick brown fox')
            candidates = enc.decode_auto(blob)
            recovered = [c for c in candidates
                         if c['result'] == 'the quick brown fox']
            assert recovered, f'{scheme} blob was not recovered'
            assert scheme in {c['scheme'] for c in recovered}

    def test_candidate_shape(self):
        candidates = enc.decode_auto(enc.base64_encode('the quick brown fox'))
        assert candidates
        for candidate in candidates:
            assert set(candidate) == {'scheme', 'result', 'score', 'note'}
            assert candidate['scheme'] in SCHEME_NAMES
            assert isinstance(candidate['result'], str) and candidate['result']
            assert 0 <= candidate['score'] <= 100
            assert isinstance(candidate['note'], str) and candidate['note']

    def test_results_are_sorted_best_first(self):
        candidates = enc.decode_auto(enc.base64_encode('the quick brown fox'))
        scores = [c['score'] for c in candidates]
        assert scores == sorted(scores, reverse=True)

    def test_the_true_scheme_outranks_a_no_op(self):
        blob = enc.base64_encode('the quick brown fox jumps over the lazy dog')
        candidates = enc.decode_auto(blob)
        by_scheme = {c['scheme']: c for c in candidates}
        assert 'base64' in by_scheme
        # A scheme that returns the input unchanged is weak evidence and must
        # be annotated as such, and must not outrank the real decode.
        noops = [c for c in candidates if c['result'] == blob]
        for noop in noops:
            assert 'identical to input' in noop['note']
            assert noop['score'] <= by_scheme['base64']['score']

    def test_unreadable_decodes_are_filtered_out(self):
        # Nothing a scheme produces from random hex should pass the 90%
        # printable floor as confident text.
        candidates = enc.decode_auto('deadbeefcafebabe' * 6)
        for candidate in candidates:
            ratio = enc._printable_ratio(candidate['result'])
            assert ratio >= enc._MIN_PRINTABLE

    def test_blank_and_non_string_input_yield_no_candidates(self):
        assert enc.decode_auto('') == []
        assert enc.decode_auto('   ') == []
        assert enc.decode_auto('\n\t') == []
        assert enc.decode_auto(None) == []
        assert enc.decode_auto(12345) == []

    def test_candidate_list_is_capped(self):
        candidates = enc.decode_auto(enc.base64_encode('the quick brown fox'))
        assert len(candidates) <= enc._MAX_DECODE_CANDIDATES

    def test_arbitrary_garbage_never_raises(self):
        for blob in ['\x00\x01\x02', '!!!!!', 'a' * 5000, '\ufffd' * 50,
                     '%%%zzz', '<script>alert(1)</script>']:
            assert isinstance(enc.decode_auto(blob), list)


# --------------------------------------------------------------------------- #
# scoring heuristics
# --------------------------------------------------------------------------- #

class TestScoringHeuristics:
    def test_printable_ratio_bounds(self):
        assert enc._printable_ratio('') == 0.0
        assert enc._printable_ratio('abc') == 1.0
        assert enc._printable_ratio('ab\x00') == pytest.approx(2 / 3)

    def test_replacement_characters_count_as_non_printable(self):
        # str.isprintable() says U+FFFD is printable; the helper must not, or a
        # failed errors='replace' decode would masquerade as readable text.
        assert '\ufffd'.isprintable() is True
        assert enc._printable_ratio('\ufffd\ufffd') == 0.0
        assert enc._printable_ratio('a\ufffd') == 0.5

    def test_score_prefers_english_over_binary_garbage(self):
        english = enc._score_result('the quick brown fox and the lazy dog')
        garbage = enc._score_result('\x00\x01\x02\x03\x04\x05')
        assert english > garbage
        assert english > 50

    def test_score_is_within_bounds(self):
        for text in ['', 'abc', 'the and of', '\x00\xff', 'x' * 500]:
            assert 0 <= enc._score_result(text) <= 100

    def test_score_of_empty_text_is_zero(self):
        assert enc._score_result('') == 0


# --------------------------------------------------------------------------- #
# hash_all
# --------------------------------------------------------------------------- #

class TestHashAll:
    ALGORITHMS = ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
                  'sha3_256', 'sha3_512', 'blake2s', 'blake2b')

    def test_returns_every_algorithm_plus_crc32(self):
        result = enc.hash_all('abc')
        assert set(result) == set(self.ALGORITHMS) | {'crc32'}

    def test_digests_match_plain_hashlib(self):
        # The digests are emitted so they can be pasted into a hash-lookup
        # service, so they must be exactly the standard values. This also pins
        # that `usedforsecurity=False` (added for bandit B324) changed nothing.
        result = enc.hash_all('abc')
        for name in self.ALGORITHMS:
            assert result[name] == hashlib.new(name, b'abc').hexdigest(), name

    def test_known_digests(self):
        result = enc.hash_all('abc')
        assert result['md5'] == '900150983cd24fb0d6963f7d28e17f72'
        assert result['sha1'] == 'a9993e364706816aba3e25717850c26c9cd0d89d'
        assert result['sha256'] == (
            'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

    def test_crc32_is_eight_hex_digits(self):
        result = enc.hash_all('abc')
        assert len(result['crc32']) == 8
        assert int(result['crc32'], 16) == zlib.crc32(b'abc') & 0xFFFFFFFF

    def test_all_digests_are_lowercase_hex(self):
        for name, digest in enc.hash_all('ObscuraLens').items():
            assert digest == digest.lower(), name
            assert all(c in '0123456789abcdef' for c in digest), name

    def test_empty_string_is_allowed_and_meaningful(self):
        result = enc.hash_all('')
        assert result['md5'] == hashlib.md5(b'').hexdigest()
        assert result['sha256'] == hashlib.sha256(b'').hexdigest()

    def test_unicode_is_hashed_as_utf8(self):
        assert enc.hash_all('\u4e2d\u6587')['sha256'] == \
            hashlib.sha256('\u4e2d\u6587'.encode('utf-8')).hexdigest()

    def test_non_string_raises(self):
        with pytest.raises(ValueError, match='must be a string'):
            enc.hash_all(None)
        with pytest.raises(ValueError, match='must be a string'):
            enc.hash_all(b'bytes')

    def test_result_order_is_stable(self):
        assert list(enc.hash_all('abc')) == list(enc.hash_all('abc'))


# --------------------------------------------------------------------------- #
# integration with the surfaces that expose the toolbox
# --------------------------------------------------------------------------- #

class TestToolboxSurfaces:
    def test_encode_all_output_feeds_decode_auto(self):
        # The documented workflow: encode a secret every way, then confirm the
        # magic decoder can pull it back out of at least one form.
        secret = 'the password is hunter2 and the token expires'
        for name in ('hex', 'base64', 'base32', 'gzip', 'binary', 'decimal'):
            blob = enc.encode_all(secret)[name]
            candidates = enc.decode_auto(blob)
            assert any(c['result'] == secret for c in candidates), name

    def test_scheme_encode_matches_encode_all_for_every_scheme(self):
        result = enc.encode_all(SAMPLE)
        for name in SCHEME_NAMES:
            assert enc.SCHEMES[name]['encode'](SAMPLE) == result[name]

"""Email/DNS source tests."""

from datetime import datetime, timedelta, timezone

import pytest

from obscuralens.trackers import email_sources as es


def _dns_dispatch(rules):
    """Build a fake get_json that answers URL fragments."""
    def fake(url, **kwargs):
        for fragment, payload in rules.items():
            if fragment in url:
                return True, payload, ''
        return False, None, 'not found'
    return fake


def _answer(rtype, data):
    return {'Status': 0, 'Answer': [{'name': 'x.', 'type': rtype, 'data': data}]}


def test_mx_priority_sorting(fake_http):
    fake_http.json = lambda url, **kw: (True, {'Status': 0, 'Answer': [
        {'type': 15, 'data': '20 mx2.example.com.'},
        {'type': 15, 'data': '10 mx1.example.com.'},
    ]}, '')
    assert es._mx_records('example.com') == ['mx1.example.com', 'mx2.example.com']


def test_dns_records_full_posture(fake_http):
    rules = {
        'type=MX': {'Status': 0, 'Answer': [
            {'type': 15, 'data': '10 mail.example.com.'}]},
        'type=AAAA': _answer(28, '2606:2800:220:1:248:1893:25c8:1946'),
        'type=A': _answer(1, '93.184.216.34'),
        'type=NS': _answer(2, 'ns1.example.com.'),
        'type=SOA': _answer(6, 'ns1.example.com. hostmaster.example.com. 1 2 3 4 5'),
        'type=CAA': _answer(257, '0 issue "letsencrypt.org"'),
        'type=DNSKEY': _answer(48, '257 3 13 abcdef=='),
        'name=_dmarc.example.com': _answer(16, '"v=DMARC1; p=reject"'),
        'default._domainkey': _answer(16, '"v=DKIM1; p=MIIBIjANBgkq"'),
        'google._domainkey': _answer(16, '"v=DKIM1; p="'),
        'type=TXT': {'Status': 0, 'Answer': [
            {'type': 16, 'data': '"v=spf1 include:_spf.example.com -all"'},
            {'type': 16, 'data': '"google-site-verification=abc"'},
        ]},
    }
    fake_http.json = _dns_dispatch(rules)
    out = es._dns_records('example.com')

    assert out['mx_records'] == ['mail.example.com']
    assert out['a_records'] == ['93.184.216.34']
    assert out['aaaa_records'] == ['2606:2800:220:1:248:1893:25c8:1946']
    assert out['ns_records'] == ['ns1.example.com']
    assert out['caa_records'] == ['0 issue "letsencrypt.org"']
    assert out['dnssec'] is True
    assert out['dmarc_policy'] == 'reject'
    assert out['spf_third_party'] is True
    assert out['txt_records'] == ['google-site-verification=abc']
    # Only the selector with a real key counts; empty p= is an anti-abuse stub.
    assert out['dkim_selectors'] == ['default']


def test_null_mx_detected(fake_http):
    fake_http.json = lambda url, **kw: (True, {'Status': 0, 'Answer': [
        {'type': 15, 'data': '0 .'}]}, '')
    out = es._dns_records('example.com')
    assert out.get('null_mx') is True
    assert 'mx_records' not in out


def test_domain_rdap_computes_age(fake_http):
    created = (datetime.now(timezone.utc) - timedelta(days=1000)).strftime(
        '%Y-%m-%dT%H:%M:%SZ')
    expires = (datetime.now(timezone.utc) + timedelta(days=365)).strftime(
        '%Y-%m-%dT%H:%M:%SZ')
    fake_http.json = lambda url, **kw: (True, {
        'handle': 'H1', 'ldhName': 'EXAMPLE.COM',
        'status': ['active'],
        'events': [
            {'eventAction': 'registration', 'eventDate': created},
            {'eventAction': 'expiration', 'eventDate': expires},
        ],
        'entities': [{'roles': ['registrar'], 'vcardArray': ['vcard', [
            ['fn', {}, 'text', 'Example Registrar']]]}],
        'nameservers': [{'ldhName': 'NS1.EXAMPLE.COM.'}],
    }, '')
    out = es._domain_rdap('example.com')
    assert out['registrar'] == 'Example Registrar'
    assert 990 <= out['domain_age_days'] <= 1001
    assert 360 <= out['expires_in_days'] <= 366
    assert out['nameservers'] == ['NS1.EXAMPLE.COM']


def test_pattern_analysis(fake_http):
    out = es._pattern_analysis('john12345@gmail.com', 'john12345', 'gmail.com')
    assert out['is_webmail'] is True
    assert out['has_digits'] is True
    assert out['digit_count'] == 5
    assert out['looks_generated'] is True


class TestGravatarDigest:
    """Gravatar's URL scheme *is* MD5 - the digest must stay canonical.

    MD5 here is a protocol requirement, not a security choice, so it is called
    with ``usedforsecurity=False`` (bandit B324). These pin that the flag did
    not change a single byte of the digest, and that the normalisation Gravatar
    specifies - trim, then lowercase - is still applied before hashing.
    """

    @staticmethod
    def _captured_url(fake_http, status=200):
        """Run `_gravatar` against a fake transport and return the requested URL."""
        captured = {}

        def _fetch(url, **kwargs):
            captured['url'] = url
            return status, '', ''

        fake_http.fetch = _fetch
        return captured

    @staticmethod
    def _digest_of(url):
        return url.rstrip('/').split('/')[-1].split('?')[0]

    def test_digest_is_the_canonical_md5_of_the_address(self, fake_http):
        import hashlib
        captured = self._captured_url(fake_http)
        es._gravatar('user@example.com')
        expected = hashlib.md5(b'user@example.com').hexdigest()
        assert self._digest_of(captured['url']) == expected

    def test_email_is_trimmed_and_lowercased_before_hashing(self, fake_http):
        import hashlib
        captured = self._captured_url(fake_http)
        es._gravatar('  MiXeD@Example.COM  ')
        assert self._digest_of(captured['url']) == \
            hashlib.md5(b'mixed@example.com').hexdigest()

    def test_digest_is_32_lowercase_hex(self, fake_http):
        import re
        captured = self._captured_url(fake_http)
        es._gravatar('a@b.co')
        assert re.fullmatch(r'[0-9a-f]{32}', self._digest_of(captured['url']))

    def test_the_md5_flag_does_not_alter_the_digest(self, fake_http):
        # `usedforsecurity=False` is an annotation; prove it is not a behaviour
        # change by recomputing the digest the plain way.
        import hashlib
        captured = self._captured_url(fake_http)
        es._gravatar('flag.check@example.org')
        plain = hashlib.md5(b'flag.check@example.org').hexdigest()
        flagged = hashlib.md5(b'flag.check@example.org',
                              usedforsecurity=False).hexdigest()
        assert plain == flagged
        assert self._digest_of(captured['url']) == plain

    @pytest.mark.parametrize('status,expected', [
        (200, True), (404, False), (500, 'unknown'), (0, 'unknown'),
    ])
    def test_verdict_mapping_is_unchanged(self, fake_http, status, expected):
        captured = self._captured_url(fake_http, status=status)
        result = es._gravatar('v@example.com')
        assert result['gravatar'] is expected or result['gravatar'] == expected
        assert 'url' in captured

    def test_network_failure_reports_unknown_not_absent(self, fake_http):
        # Gravatar is blocked from some networks; a transport error must not be
        # reported as "this address has no avatar".
        fake_http.fetch = lambda url, **kw: (0, '', 'timeout')
        result = es._gravatar('down@example.com')
        assert result['gravatar'] == 'unknown'
        assert result['gravatar_error'] == 'timeout'

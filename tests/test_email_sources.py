"""Email/DNS source tests."""

from datetime import datetime, timedelta, timezone

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

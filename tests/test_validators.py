"""Input validator tests."""

from obscuralens.utils.validators import (
    validate_domain,
    validate_email,
    validate_ip,
    validate_phone,
    validate_username,
)


def test_ip_valid_and_invalid():
    assert validate_ip('8.8.8.8')[0] is True
    assert validate_ip('2001:4860:4860::8888')[0] is True
    assert validate_ip('999.999.999.999')[0] is False
    assert validate_ip('')[0] is False


def test_email_valid_and_invalid():
    assert validate_email('user@example.com')[0] is True
    assert validate_email('user+tag@sub.example.co.uk')[0] is True
    assert validate_email('not-an-email')[0] is False
    assert validate_email('a@b')[0] is False


def test_phone_valid_and_invalid():
    assert validate_phone('+14155552671')[0] is True
    assert validate_phone('+1 (415) 555-2671')[0] is True
    assert validate_phone('12')[0] is False
    assert validate_phone('+1234567890123456')[0] is False


def test_username_valid_and_invalid():
    assert validate_username('valid_user')[0] is True
    assert validate_username('ab')[0] is False
    assert validate_username('bad name')[0] is False
    assert validate_username('x' * 31)[0] is False


def test_domain_valid_and_invalid():
    assert validate_domain('example.com')[0] is True
    assert validate_domain('sub.example.co.uk')[0] is True
    assert validate_domain('-bad.example')[0] is False
    assert validate_domain('no_underscores.example')[0] is False
    assert validate_domain('')[0] is False

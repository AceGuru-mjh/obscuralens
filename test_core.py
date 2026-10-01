#!/usr/bin/env python
"""
ObscuraLens Core Functionality Test

Verifies every tracker against live data sources, then checks reporting,
visualisation and persistence. Run from the project root.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from obscuralens.trackers import IPTracker, PhoneTracker, UsernameTracker, EmailTracker
from obscuralens.database import db
from obscuralens.config import config
from obscuralens.reporting import ReportGenerator
from obscuralens.visualization import ChartGenerator
from obscuralens.utils import (
    SYM_OK, SYM_FAIL, print_section, print_subsection, print_table,
    validate_ip, validate_email, validate_phone, validate_username,
)

PASSED: list = []
FAILED: list = []


def check(name, ok, detail=""):
    (PASSED if ok else FAILED).append(name)
    mark = SYM_OK if ok else SYM_FAIL
    print(f"  {mark} {name}: {detail}")
    return ok


def count_fields(result):
    return result.get('field_count', 0)


def test_config():
    print_section("Configuration & API Keys")
    check("config loads", bool(config.app_config.log_level),
          f"log_level={config.app_config.log_level}, "
          f"format={config.app_config.output_format}")
    check("database path", bool(config.db_config.sqlite_path),
          config.db_config.sqlite_path)
    configured = [s for s, v in config.configured_services().items() if v]
    check("keyed services", True,
          f"{len(configured)} configured"
          + (f" ({', '.join(configured)})" if configured else " (keyless mode)"))


def test_validators():
    print_section("Input Validators")
    cases = [
        ("valid IPv4", validate_ip("8.8.8.8"), True),
        ("invalid IPv4", validate_ip("999.999.999.999"), False),
        ("valid IPv6", validate_ip("2001:4860:4860::8888"), True),
        ("valid email", validate_email("user@example.com"), True),
        ("invalid email", validate_email("not-an-email"), False),
        ("valid phone", validate_phone("+14155552671"), True),
        ("short phone", validate_phone("12"), False),
        ("valid username", validate_username("valid_user"), True),
        ("short username", validate_username("ab"), False),
    ]
    for name, (ok, _err), expected in cases:
        check(name, ok == expected, f"got={ok} expected={expected}")


def test_database():
    print_section("Database")
    try:
        qid = db.save_query('test', 'unit_test_value', {'info': {'a': 1, 'b': 2}})
        check("save query", qid > 0, f"id={qid}")
        check("count fields", db.count_fields('{"info":{"a":1,"b":2}}') == 2,
              "counted 2 fields")
        history = db.get_history(limit=5)
        check("get history", len(history) > 0, f"{len(history)} records")
        found = db.search_history('unit_test')
        check("search history", len(found) > 0, f"{len(found)} matches")
        stats = db.get_statistics()
        check("statistics", stats['total_queries'] > 0,
              f"total={stats['total_queries']} rate={stats['success_rate']}%")
        deleted = db.clear_history('test')
        check("clear by type", deleted > 0, f"{deleted} deleted")
    except Exception as e:
        check("database", False, f"{type(e).__name__}: {e}")


def test_ip_tracker():
    print_section("IP Tracker (8 free/keyless sources)")
    tracker = IPTracker()
    try:
        result = tracker.track("8.8.8.8")
        if not result['success']:
            check("IP track", False, "all sources failed")
            return

        info = result['info']
        check("IP success", result['success'],
              f"{len(result['sources_ok'])} sources, {count_fields(result)} fields")
        check("sources used", len(result['sources_ok']) >= 4,
              ', '.join(result['sources_ok']))
        if result['sources_failed']:
            print(f"      unavailable: {result['sources_failed']}")

        # Data quality assertions on well-known values for 8.8.8.8.
        check("country correct", info.get('country') == 'United States',
              str(info.get('country')))
        check("ASN = Google AS15169",
              '15169' in str(info.get('asn') or '') or '15169' in str(info.get('asn_full') or ''),
              f"asn={info.get('asn')} org={info.get('org')}")
        check("reverse DNS", bool(info.get('reverse_dns')),
              str(info.get('reverse_dns')))
        check("coordinates", bool(info.get('latitude') and info.get('longitude')),
              f"{info.get('latitude')}, {info.get('longitude')}")
        check("RDAP registration", bool(info.get('rdap_name') or info.get('rdap_org')),
              f"name={info.get('rdap_name')} org={info.get('rdap_org')}")
        check("RDAP abuse contact", bool(info.get('rdap_abuse_email')),
              str(info.get('rdap_abuse_email')))
        check("RDAP CIDR", bool(info.get('rdap_cidr')), str(info.get('rdap_cidr')))
        check("timezone", bool(info.get('timezone')), str(info.get('timezone')))
        check("field volume > 20", count_fields(result) > 20,
              f"{count_fields(result)} fields")

        own = tracker.get_own_ip()
        check("own IP", bool(own) and own.count('.') == 3, own)
    except Exception as e:
        check("IP tracker", False, f"{type(e).__name__}: {e}")


def test_ip_own_and_batch():
    print_section("IP Batch Lookup")
    try:
        results = IPTracker().batch_track(["1.1.1.1", "9.9.9.9", "208.67.222.222"])
        ok = [r for r in results if r['success']]
        check("batch count", len(results) == 3, f"{len(results)} results")
        check("batch success", len(ok) == 3,
              "; ".join(f"{r['ip']}={r['field_count']}f" for r in results))
        check("batch order preserved",
              [r['ip'] for r in results] == ["1.1.1.1", "9.9.9.9", "208.67.222.222"],
              "inputs returned in order")
    except Exception as e:
        check("IP batch", False, f"{type(e).__name__}: {e}")


def test_phone_tracker():
    print_section("Phone Tracker")
    tracker = PhoneTracker()
    try:
        result = tracker.track("+14155552671", "US")
        if not result['success']:
            check("phone parse", False, "libphonenumber rejected input")
            return

        info = result['info']
        check("phone success", result['success'], f"{count_fields(result)} fields")
        check("E.164", info.get('e164') == '+14155552671', str(info.get('e164')))
        check("US region", info.get('region_code') == 'US', str(info.get('region_code')))
        check("valid flag", info.get('valid_format') is True, str(info.get('valid_format')))
        check("number type", bool(info.get('type')), str(info.get('type')))
        check("timezones", bool(info.get('timezones')),
              str(info.get('timezones'))[:60])
        check("field volume > 8", count_fields(result) > 8, f"{count_fields(result)} fields")

        # Toll-free number should surface the toll-free flag and hint.
        tf = tracker.track("+18005551234", "US")
        check("toll-free detection", tf['info'].get('is_toll_free') is True,
              f"is_toll_free={tf['info'].get('is_toll_free')}")

        bad = tracker.track("12", "US")
        check("invalid number handled", not bad['success'],
              f"success={bad['success']}")
    except Exception as e:
        check("phone tracker", False, f"{type(e).__name__}: {e}")


def test_email_tracker():
    print_section("Email Tracker")
    tracker = EmailTracker()
    try:
        result = tracker.track("test@gmail.com")
        if not result['success']:
            check("email lookup", False, "all sources failed")
            return

        info = result['info']
        check("email success", result['success'],
              f"{len(result['sources_ok'])} sources, {count_fields(result)} fields")
        check("sources used", len(result['sources_ok']) >= 3,
              ', '.join(result['sources_ok']))
        if result['sources_failed']:
            print(f"      unavailable: {result['sources_failed']}")

        check("domain", info.get('domain') == 'gmail.com', str(info.get('domain')))
        check("MX records", len(info.get('mx_records') or []) >= 1,
              f"{info.get('mx_count')} MX hosts")
        check("SPF present", bool(info.get('spf_record')),
              (info.get('spf_record') or '')[:50])
        check("DMARC present", bool(info.get('dmarc_record')),
              f"policy={info.get('dmarc_policy')}")
        check("webmail detected", info.get('is_webmail') is True,
              str(info.get('is_webmail')))
        check("disposable checked", info.get('disposable') is False,
              f"disposable={info.get('disposable')}")
        check("field volume > 8", count_fields(result) > 8, f"{count_fields(result)} fields")

        corp = tracker.track("test@google.com")
        check("corporate domain RDAP",
              bool(corp['info'].get('domain_created') or corp['info'].get('registrar')),
              f"created={corp['info'].get('domain_created')} "
              f"registrar={corp['info'].get('registrar')}")
    except Exception as e:
        check("email tracker", False, f"{type(e).__name__}: {e}")


def test_username_tracker():
    print_section("Username Tracker (honest three-state detection)")
    tracker = UsernameTracker()
    try:
        result = tracker.track("github")
        check("scan completed", result['success'],
              f"{result['found_count']} confirmed / "
              f"{result.get('not_found_count', 0)} ruled out / "
              f"{result.get('unknown_count', 0)} inconclusive, "
              f"{result['total_fields']} profile fields")

        found = [r for r in result['results'] if r.get('status') == 'found']
        check("confirmed hits", len(found) >= 2,
              f"{len(found)} confident hits: "
              f"{', '.join(r['platform'] for r in found[:8])}")

        with_profile = [r for r in found if r.get('profile')]
        check("profiles on hits", len(with_profile) == len(found) and len(found) > 0,
              f"{len(with_profile)}/{len(found)} hits carry profile data")

        if with_profile:
            sample = with_profile[0]
            keys = ', '.join(sorted(sample['profile'].keys())[:8])
            print(f"      sample [{sample['platform']}]: {keys} "
                  f"({sample.get('reason')})")

        # No false positives: a random handle must produce zero confident hits.
        bogus = tracker.track("zzq7x_nonexistent_user_9931")
        bogus_hits = [r for r in bogus['results'] if r.get('status') == 'found']
        check("no false positives", len(bogus_hits) == 0,
              f"{len(bogus_hits)} confident hits on bogus handle "
              f"(ruled out {bogus.get('not_found_count')}, "
              f"inconclusive {bogus.get('unknown_count')})")

        fast = tracker.track("github", deep=False)
        check("fast mode", fast['total_fields'] == 0,
              f"{fast['found_count']} hits, 0 profile fields as expected")
    except Exception as e:
        check("username tracker", False, f"{type(e).__name__}: {e}")


def test_reporting():
    print_section("Report Generation (5 formats)")
    gen = ReportGenerator()
    sections = [
        {'title': 'Location', 'type': 'grid',
         'data': {'IP': '8.8.8.8', 'Country': 'United States', 'City': 'Mountain View'}},
        {'title': 'Sources', 'type': 'table',
         'columns': ['Source', 'Status'],
         'rows': [['ipwho.is', 'OK'], ['rdap', 'OK']]},
        {'title': 'Notes', 'type': 'text', 'content': 'All sources responded normally.'},
    ]
    data = {'sections': sections}
    try:
        for label, fn in [
            ("HTML", lambda: gen.generate_html_report(data, "Unit Report")),
            ("JSON", lambda: gen.generate_json_report(data, "Unit Report")),
            ("Markdown", lambda: gen.generate_markdown_report(data, "Unit Report")),
            ("CSV", lambda: gen.generate_csv_report(
                [{'ip': '8.8.8.8', 'country': 'US'}], 'unit_test.csv')),
            ("PDF", lambda: gen.generate_pdf_report(data, "Unit Report")),
        ]:
            path = fn()
            ok = os.path.exists(path) and not path.startswith("ReportLab")
            check(f"{label} report", ok, path)
    except Exception as e:
        check("report generation", False, f"{type(e).__name__}: {e}")


def test_visualization():
    print_section("Data Visualization")
    gen = ChartGenerator()
    try:
        checks = [
            ("pie chart",
             gen.create_pie_chart({'US': 10, 'DE': 5, 'CN': 8},
                                  "Countries", "unit_pie.png")),
            ("bar chart",
             gen.create_bar_chart({'ip': 5, 'phone': 3, 'email': 7},
                                 "Query types", "Type", "Count", "unit_bar.png")),
            ("horizontal bar",
             gen.create_bar_chart({'a': 3, 'b': 6}, "H", "K", "V", "unit_hbar.png",
                                  horizontal=True)),
            ("threat gauge", gen.create_threat_gauge(72, "unit_gauge.png")),
            ("dashboard",
             gen.create_statistics_dashboard({
                 'total_queries': 25, 'success_rate': 92.5,
                 'recent_queries_7d': 8,
                 'queries_by_type': {'ip': 10, 'phone': 5, 'email': 10},
             }, "unit_dashboard.png")),
        ]
        for label, path in checks:
            check(label, os.path.exists(path), path)
    except Exception as e:
        check("visualization", False, f"{type(e).__name__}: {e}")


def test_cli_imports():
    print_section("CLI Wiring")
    try:
        from obscuralens.cli import ObscuraLensCLI, LABELS, _rows_from_fields
        cli = ObscuraLensCLI()
        check("CLI instantiates", cli is not None, "ObscuraLensCLI()")

        rows = _rows_from_fields({'country': 'US', 'city': '', 'is_eu': False,
                                  'ports': [80, 443]})
        labels = [r[0] for r in rows]
        check("field filtering", 'City' not in labels and 'Country' in labels,
              f"kept {labels}")
        check("list rendering", any('80, 443' in r[1] for r in rows),
              "ports rendered as list")
        check("label map", LABELS.get('rdap_abuse_email') == 'Abuse Email',
              f"{len(LABELS)} labels defined")
    except Exception as e:
        check("CLI wiring", False, f"{type(e).__name__}: {e}")


def main():
    print("\n" + "=" * 62)
    print("ObscuraLens Core Functionality Test")
    print("=" * 62)

    test_config()
    test_validators()
    test_database()
    test_ip_tracker()
    test_ip_own_and_batch()
    test_phone_tracker()
    test_email_tracker()
    test_username_tracker()
    test_reporting()
    test_visualization()
    test_cli_imports()

    print("\n" + "=" * 62)
    print(f"Results: {len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        print("\nFailed:")
        for name in FAILED:
            print(f"  - {name}")
    print("=" * 62)

    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())

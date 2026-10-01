"""
ObscuraLens CLI Interface
Menu-driven OSINT console with multi-source aggregation.
"""

import json
import os
import re
import sys
from typing import Any, Dict, List

from .config import SERVICES, config
from .core.cache import cache
from .core.metrics import metrics
from .database import db
from .investigate import detect_kind, investigate, to_mermaid
from .reporting import (
    ReportGenerator,
    domain_sections,
    email_sections,
    ip_sections,
    phone_sections,
    username_sections,
)
from .trackers import (
    DomainTracker,
    EmailTracker,
    IPTracker,
    PhoneTracker,
    UsernameTracker,
)
from .utils import (
    BOX_BL,
    BOX_BR,
    BOX_DIV,
    BOX_H,
    BOX_TL,
    BOX_TR,
    BOX_V,
    SYM_OK,
    Colors,
    clear_screen,
    confirm_action,
    get_input,
    print_banner,
    print_error,
    print_info,
    print_json,
    print_section,
    print_subsection,
    print_success,
    print_table,
    print_warning,
    validate_domain,
    validate_email,
    validate_ip,
    validate_phone,
    validate_username,
)
from .utils.formatting import (
    LABELS as LABELS,  # noqa: F401 - re-exported for backwards compatibility
)
from .utils.formatting import (
    fmt_value as _fmt_value,
)
from .utils.formatting import (
    label as _label,  # noqa: F401 - re-exported for backwards compatibility
)
from .utils.formatting import (
    rows_from_fields as _rows_from_fields,
)
from .visualization import ChartGenerator
from .watchlist import watchlist

# Field rendering helpers (LABELS, _label, _fmt_value, _rows_from_fields)
# are imported from obscuralens.utils.formatting above.


class ObscuraLensCLI:
    """ObscuraLens Command Line Interface"""

    def __init__(self):
        self.ip_tracker = IPTracker()
        self.phone_tracker = PhoneTracker()
        self.username_tracker = UsernameTracker()
        self.email_tracker = EmailTracker()
        self.domain_tracker = DomainTracker()
        self.chart_gen = ChartGenerator()
        self.report_gen = ReportGenerator()

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self) -> None:
        clear_screen()
        print_banner()

        while True:
            self.show_main_menu()
            choice = input(f"\n{Colors.GREEN}[ + ] Select Option: {Colors.RESET}").strip()

            handlers = {
                '1': self.ip_tracker_menu,
                '2': self.phone_tracker_menu,
                '3': self.username_tracker_menu,
                '4': self.email_tracker_menu,
                '5': self.domain_tracker_menu,
                '6': self.batch_operations_menu,
                '7': self.history_menu,
                '8': self.statistics_menu,
                '9': self.settings_menu,
                '10': self.api_status_menu,
                '11': self.watchlist_menu,
                '12': self.investigate_menu,
                '0': self.exit_program,
            }
            action = handlers.get(choice)
            if action is None:
                print_error("Invalid option. Please try again.")
                input("\nPress Enter to continue...")
                continue
            if choice == '0':
                return
            action()

    def show_main_menu(self) -> None:
        items = [
            ('1', 'IP Tracker'),
            ('2', 'Phone Number Tracker'),
            ('3', 'Username Tracker'),
            ('4', 'Email Tracker'),
            ('5', 'Domain Tracker'),
            ('6', 'Batch Operations'),
            ('7', 'Query History'),
            ('8', 'Statistics'),
            ('9', 'Settings'),
            ('10', 'API Key Status'),
            ('11', 'Watchlist'),
            ('12', 'Universal Investigate'),
            ('0', 'Exit'),
        ]
        width = 58
        line = BOX_H * width
        print(f"\n{Colors.CYAN}{BOX_TL}{line}{BOX_TR}{Colors.RESET}")
        print(f"{Colors.CYAN}{BOX_V}{Colors.RESET}{'MAIN MENU':^58}{Colors.CYAN}{BOX_V}{Colors.RESET}")
        print(f"{Colors.CYAN}{BOX_DIV}{line}{Colors.RESET}")
        for num, text in items:
            print(f"{Colors.CYAN}{BOX_V}{Colors.RESET}  [{num}] {text:<52}{Colors.CYAN}{BOX_V}{Colors.RESET}")
        print(f"{Colors.CYAN}{BOX_BL}{line}{BOX_BR}{Colors.RESET}")

    # ------------------------------------------------------------------
    # IP
    # ------------------------------------------------------------------

    def ip_tracker_menu(self) -> None:
        clear_screen()
        print_section("IP TRACKER")

        print(f"  {Colors.CYAN}[1]{Colors.RESET} Track a single IP")
        print(f"  {Colors.CYAN}[2]{Colors.RESET} Show my own public IP")
        print(f"  {Colors.CYAN}[0]{Colors.RESET} Back")

        choice = input(f"\n{Colors.GREEN}Select: {Colors.RESET}").strip()
        if choice == '0':
            return
        if choice == '2':
            self.show_own_ip()
            return

        ip = get_input("Enter IP address")
        is_valid, error = validate_ip(ip)
        if not is_valid:
            print_error(error)
            input("\nPress Enter to continue...")
            return

        print_info(f"Querying all data sources for {ip}...")
        result = self.ip_tracker.track(ip)

        if result['success']:
            self.display_ip_results(result)
            self.offer_ip_extras(result)
        else:
            print_error("Every data source failed.")
            for name, err in result.get('sources_failed', {}).items():
                print(f"  {Colors.RED}{name}:{Colors.RESET} {err}")

        input("\nPress Enter to continue...")

    def show_own_ip(self) -> None:
        try:
            ip = self.ip_tracker.get_own_ip()
        except Exception as e:
            print_error(f"Could not determine public IP: {type(e).__name__}")
            input("\nPress Enter to continue...")
            return

        print_success(f"Your public IP: {ip}")
        if confirm_action("Run a full lookup on it?"):
            print_info(f"Querying all data sources for {ip}...")
            result = self.ip_tracker.track(ip)
            if result['success']:
                self.display_ip_results(result)
                self.offer_ip_extras(result)
            else:
                print_error("Every data source failed.")
        input("\nPress Enter to continue...")

    def display_ip_results(self, result: Dict[str, Any]) -> None:
        info = result.get('info', {})

        print_subsection("Summary")
        print(f"  {Colors.CYAN}Sources OK:{Colors.RESET}     {len(result['sources_ok'])}"
              f"  {Colors.CYAN}Fields collected:{Colors.RESET} {result['field_count']}")
        print(f"  {Colors.CYAN}Sources used:{Colors.RESET}    {', '.join(result['sources_ok'])}")

        failed = result.get('sources_failed', {})
        if failed:
            print(f"  {Colors.YELLOW}Unavailable:{Colors.RESET}     "
                  + ', '.join(f"{k} ({v})" for k, v in failed.items()))

        # Headline facts first.
        headline = {}
        for key in ('reverse_dns', 'country', 'country_code', 'region', 'city',
                    'postal', 'latitude', 'longitude', 'timezone', 'asn', 'org',
                    'isp', 'is_proxy'):
            if info.get(key) not in (None, '', [], {}, False):
                headline[key] = info[key]

        if headline:
            print_subsection("Location & Network")
            print_table(_rows_from_fields(headline))

            if info.get('latitude') and info.get('longitude'):
                maps = f"https://www.google.com/maps/@{info['latitude']},{info['longitude']},8z"
                print(f"\n  {Colors.GREEN}Google Maps:{Colors.RESET} {maps}")
                print(f"  {Colors.GREEN}OpenStreetMap:{Colors.RESET} "
                      f"https://www.openstreetmap.org/?mlat={info['latitude']}"
                      f"&mlon={info['longitude']}#map=10/{info['latitude']}/{info['longitude']}")

        # Everything else.
        rest = {k: v for k, v in info.items() if k not in headline}
        if rest:
            print_subsection("All Collected Fields")
            print_table(_rows_from_fields(rest))

        if info.get('coordinates_by_source'):
            print_subsection("Coordinates By Source")
            print_table([[c['source'], f"{c['lat']}, {c['lon']}"]
                         for c in info['coordinates_by_source']])
            print_warning("Sources disagree; the IP is likely geolocated to a "
                          "datacentre or the block is announced in several regions.")

        if info.get('city_disagreement'):
            print_warning(f"Cities reported across sources: "
                          f"{', '.join(info['city_disagreement'])}")

    def offer_ip_extras(self, result: Dict[str, Any]) -> None:
        """Offer report export and charting for a completed IP lookup."""
        print_subsection("Export")
        print("  [1] Save JSON report")
        print("  [2] Save HTML report")
        print("  [3] Save PDF report")
        print("  [4] Plot coordinates by source")
        print("  [5] Show field sources")
        print("  [0] Skip")

        choice = input(f"\n{Colors.GREEN}Select: {Colors.RESET}").strip()
        if choice == '0':
            return

        ip = result.get('ip', 'target')
        sections = self._ip_report_sections(result)

        try:
            if choice in ('1', '2', '3'):
                method = {'1': self.report_gen.generate_json_report,
                          '2': self.report_gen.generate_html_report,
                          '3': self.report_gen.generate_pdf_report}[choice]
                path = method({'ip': ip, 'sections': sections},
                              f"IP Report - {ip}")
                if os.path.exists(path):
                    print_success(f"Report saved: {path}")
                else:
                    print_warning(f"Report not written: {path}")
            elif choice == '4':
                coords = result['info'].get('coordinates_by_source') or []
                if not coords:
                    print_warning("No per-source coordinates available.")
                else:
                    path = self.chart_gen.create_bar_chart(
                        {c['source']: abs(float(c['lat'])) for c in coords},
                        f"Latitude by source ({ip})",
                        "Source", "|latitude|", f"lat_{ip}.png")
                    print_success(f"Chart saved: {path}")
            elif choice == '5':
                self.show_field_sources(result)
        except Exception as e:
            print_error(f"Export failed: {type(e).__name__}: {e}")

    @staticmethod
    def _ip_report_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Shape an IP result into report sections (shared builder)."""
        return ip_sections(result)

    # ------------------------------------------------------------------
    # Phone
    # ------------------------------------------------------------------

    def phone_tracker_menu(self) -> None:
        clear_screen()
        print_section("PHONE NUMBER TRACKER")

        phone = get_input("Enter phone number (e.g., +6281xxxxxxxxx)")
        region = get_input("Default region code (e.g. ID, US)", required=False) or "ID"

        is_valid, error = validate_phone(phone)
        if not is_valid:
            print_error(error)
            input("\nPress Enter to continue...")
            return

        print_info(f"Parsing {phone}...")
        result = self.phone_tracker.track(phone, region)

        if result['success']:
            self.display_phone_results(result)
            if confirm_action("\nSave report?"):
                sections = phone_sections(result)
                path = self.report_gen.generate_json_report(
                    {'phone': phone, 'info': result['info'], 'sections': sections},
                    f"Phone Report - {phone}")
                print_success(f"Report saved: {path}")
        else:
            print_error("Could not parse the number.")
            for name, err in result.get('sources_failed', {}).items():
                print(f"  {Colors.RED}{name}:{Colors.RESET} {err}")

        input("\nPress Enter to continue...")

    def display_phone_results(self, result: Dict[str, Any]) -> None:
        info = result.get('info', {})
        headline = {}
        for key in ('international', 'e164', 'type', 'country_code', 'region_code',
                    'carrier', 'location', 'valid_format', 'possible',
                    'is_mobile', 'is_voip', 'is_toll_free', 'number_length'):
            if info.get(key) not in (None, '', [], {}, False):
                headline[key] = info[key]

        print_subsection("Summary")
        print(f"  {Colors.CYAN}Fields collected:{Colors.RESET} {result['field_count']}")
        if headline:
            print_table(_rows_from_fields(headline))

        rest = {k: v for k, v in info.items() if k not in headline}
        if rest:
            print_subsection("All Collected Fields")
            print_table(_rows_from_fields(rest))

        if info.get('hints'):
            print_subsection("Analyst Notes")
            for hint in info['hints']:
                print_warning(hint)

    # ------------------------------------------------------------------
    # Username
    # ------------------------------------------------------------------

    def username_tracker_menu(self) -> None:
        clear_screen()
        print_section("USERNAME TRACKER")

        username = get_input("Enter username")
        is_valid, error = validate_username(username)
        if not is_valid:
            print_error(error)
            input("\nPress Enter to continue...")
            return

        deep = config.app_config.deep_username_scan
        print_info(f"Scanning {len(self.username_tracker.platforms)} platforms for "
                   f"{username} (deep={deep})...")
        result = self.username_tracker.track(username, deep=deep)

        if result['success']:
            self.display_username_results(result)
            if confirm_action("\nSave report?"):
                path = self.report_gen.generate_json_report(
                    {'username': username, 'results': result['results'],
                     'sections': username_sections(result)},
                    f"Username Report - {username}")
                print_success(f"Report saved: {path}")
        else:
            print_error("Scan failed.")

        input("\nPress Enter to continue...")

    def display_username_results(self, result: Dict[str, Any]) -> None:
        print_subsection("Summary")
        print(f"  {Colors.CYAN}Confirmed:{Colors.RESET}    {result['found_count']}"
              f"/{result['total_checked']} platforms")
        print(f"  {Colors.CYAN}Ruled out:{Colors.RESET}    {result.get('not_found_count', 0)}")
        print(f"  {Colors.CYAN}Inconclusive:{Colors.RESET} {result.get('unknown_count', 0)} "
              f"(bot-wall or identical page, not counted as hits)")
        print(f"  {Colors.CYAN}Profile fields collected:{Colors.RESET} {result['total_fields']}")

        found = [r for r in result['results'] if r.get('status') == 'found']
        missing = [r for r in result['results'] if r.get('status') == 'not_found']
        unknown = [r for r in result['results'] if r.get('status') not in ('found', 'not_found')]

        if found:
            print_subsection(f"Confirmed ({len(found)})")
            for r in found:
                name = r.get('profile', {}).get('name') or '?'
                conf = r.get('confidence', '')
                print(f"\n  {Colors.GREEN}{SYM_OK} {r['platform']}{Colors.RESET} "
                      f"{Colors.WHITE}{name}{Colors.RESET} "
                      f"{Colors.CYAN}[{conf}]{Colors.RESET}")
                print(f"    {Colors.CYAN}URL:{Colors.RESET} {r['url']}")
                print(f"    {Colors.CYAN}Why:{Colors.RESET} {r.get('reason', '')}")

                profile = r.get('profile') or {}
                if not profile:
                    print_warning("profile details unavailable")
                    continue
                for key, value in profile.items():
                    if key in ('name',):
                        continue
                    rendered = _fmt_value(key, value)
                    if len(rendered) > 110:
                        rendered = rendered[:107] + '...'
                    print(f"    {Colors.CYAN}{_label(key)}:{Colors.RESET} {rendered}")

        if missing:
            print_subsection(f"Ruled Out ({len(missing)})")
            print_table([[r['platform'], r.get('reason', '-')]
                         for r in missing],
                        headers=['Platform', 'Reason'])

        if unknown:
            print_subsection(f"Inconclusive ({len(unknown)}) - not hits")
            print_table([[r['platform'], r.get('reason', '-'),
                          r['status_code'] or r.get('error', '-')]
                         for r in unknown],
                        headers=['Platform', 'Reason', 'HTTP'])

    # ------------------------------------------------------------------
    # Email
    # ------------------------------------------------------------------

    def email_tracker_menu(self) -> None:
        clear_screen()
        print_section("EMAIL TRACKER")

        email = get_input("Enter email address")
        is_valid, error = validate_email(email)
        if not is_valid:
            print_error(error)
            input("\nPress Enter to continue...")
            return

        print_info(f"Querying data sources for {email}...")
        result = self.email_tracker.track(email)

        if result['success']:
            self.display_email_results(result)
            if confirm_action("\nSave report?"):
                path = self.report_gen.generate_json_report(
                    {'email': email, 'info': result['info'],
                     'sections': email_sections(result)},
                    f"Email Report - {email}")
                print_success(f"Report saved: {path}")
        else:
            print_error("All data sources failed.")
            for name, err in result.get('sources_failed', {}).items():
                print(f"  {Colors.RED}{name}:{Colors.RESET} {err}")

        input("\nPress Enter to continue...")

    def display_email_results(self, result: Dict[str, Any]) -> None:
        info = result.get('info', {})

        print_subsection("Summary")
        print(f"  {Colors.CYAN}Sources OK:{Colors.RESET}     {len(result['sources_ok'])}"
              f"  {Colors.CYAN}Fields collected:{Colors.RESET} {result['field_count']}")
        print(f"  {Colors.CYAN}Sources used:{Colors.RESET}    {', '.join(result['sources_ok'])}")

        failed = result.get('sources_failed', {})
        if failed:
            print(f"  {Colors.YELLOW}Unavailable:{Colors.RESET}     "
                  + ', '.join(f"{k} ({v})" for k, v in failed.items()))

        headline = {}
        for key in ('email', 'domain', 'valid_format', 'mx_exists', 'mx_count',
                    'is_webmail', 'disposable', 'openpgp', 'gravatar',
                    'domain_created', 'domain_expires', 'registrar'):
            if info.get(key) not in (None, '', [], {}, False):
                headline[key] = info[key]
        if headline:
            print_subsection("Key Facts")
            print_table(_rows_from_fields(headline))

        breaches = info.get('hibp_breaches')
        if breaches:
            print_subsection(f"Data Breaches ({len(breaches)})")
            rows = []
            for b in breaches:
                classes = ', '.join(b.get('data_classes') or [])
                rows.append([
                    b.get('name', '?'),
                    b.get('date', '?'),
                    f"{b.get('pwn_count', 0):,}" if b.get('pwn_count') else '?',
                    classes[:80],
                ])
            print_table(rows, headers=['Breach', 'Date', 'Accounts', 'Data Exposed'])
            if info.get('hibp_classes'):
                print_info("All exposed data types: "
                           + ', '.join(info['hibp_classes']))
        elif info.get('hibp_breached') is False:
            print_success("No data breaches found (HaveIBeenPwned)")

        pastes = info.get('pastes')
        if pastes:
            print_subsection(f"Pastes ({len(pastes)})")
            print_table([[p.get('date', '?'), p.get('entries', '?')]
                         for p in pastes], headers=['Date', 'Entries'])

        rest = {k: v for k, v in info.items()
                if k not in headline
                and k not in ('hibp_breaches', 'pastes')}
        if rest:
            print_subsection("All Collected Fields")
            print_table(_rows_from_fields(rest))

    # ------------------------------------------------------------------
    # Domain
    # ------------------------------------------------------------------

    def domain_tracker_menu(self) -> None:
        clear_screen()
        print_section("DOMAIN TRACKER")

        domain = get_input("Enter domain (e.g., example.com)")
        is_valid, error = validate_domain(domain)
        if not is_valid:
            print_error(error)
            input("\nPress Enter to continue...")
            return

        print_info(f"Querying registration, DNS, CT and HTTP sources for {domain}...")
        result = self.domain_tracker.track(domain)

        if result['success']:
            self.display_domain_results(result)
            self.offer_domain_extras(result)
        else:
            print_error("Every data source failed.")
            for name, err in result.get('sources_failed', {}).items():
                print(f"  {Colors.RED}{name}:{Colors.RESET} {err}")

        input("\nPress Enter to continue...")

    def display_domain_results(self, result: Dict[str, Any]) -> None:
        info = result.get('info', {})

        print_subsection("Summary")
        print(f"  {Colors.CYAN}Sources OK:{Colors.RESET}     {len(result['sources_ok'])}"
              f"  {Colors.CYAN}Fields collected:{Colors.RESET} {result['field_count']}")
        print(f"  {Colors.CYAN}Sources used:{Colors.RESET}    {', '.join(result['sources_ok'])}")

        failed = result.get('sources_failed', {})
        if failed:
            print(f"  {Colors.YELLOW}Unavailable:{Colors.RESET}     "
                  + ', '.join(f"{k} ({v})" for k, v in failed.items()))

        headline = {}
        for key in ('domain', 'registrar', 'domain_created', 'domain_age_days',
                    'domain_expires', 'expires_in_days', 'nameservers', 'dnssec',
                    'mx_count', 'spf_record', 'dmarc_policy', 'dkim_selectors',
                    'http_status', 'server', 'http_title', 'ct_certificates',
                    'robots_txt'):
            if info.get(key) not in (None, '', [], {}, False):
                headline[key] = info[key]
        if headline:
            print_subsection("Key Facts")
            print_table(_rows_from_fields(headline))

        subdomains = info.get('ct_subdomains')
        if subdomains:
            print_subsection(f"Subdomains From Certificate Transparency ({len(subdomains)})")
            print_table([[name] for name in subdomains[:40]],
                        headers=['Subdomain'])
            if len(subdomains) > 40:
                print_info(f"... and {len(subdomains) - 40} more")

        missing = info.get('missing_security_headers')
        if missing:
            print_warning("Missing security headers: " + ', '.join(missing))

        rest = {k: v for k, v in info.items()
                if k not in headline
                and k not in ('ct_subdomains', 'security_headers')}
        if rest:
            print_subsection("All Collected Fields")
            print_table(_rows_from_fields(rest))

    def offer_domain_extras(self, result: Dict[str, Any]) -> None:
        """Offer report export, subdomain list and provenance for a domain."""
        print_subsection("Export")
        print("  [1] Save JSON report")
        print("  [2] Save HTML report")
        print("  [3] Save Markdown report")
        print("  [4] Show field sources")
        print("  [0] Skip")

        choice = input(f"\n{Colors.GREEN}Select: {Colors.RESET}").strip()
        if choice == '0':
            return

        domain = result.get('domain', 'target')
        sections = self._domain_report_sections(result)

        try:
            if choice in ('1', '2', '3'):
                method = {'1': self.report_gen.generate_json_report,
                          '2': self.report_gen.generate_html_report,
                          '3': self.report_gen.generate_markdown_report}[choice]
                path = method({'domain': domain, 'sections': sections},
                              f"Domain Report - {domain}")
                print_success(f"Report saved: {path}")
            elif choice == '4':
                self.show_field_sources(result)
        except Exception as e:
            print_error(f"Export failed: {type(e).__name__}: {e}")

    @staticmethod
    def _domain_report_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Shape a domain result into report sections (shared builder)."""
        return domain_sections(result)

    def show_field_sources(self, result: Dict[str, Any]) -> None:
        """Print which source supplied each field."""
        provenance = result.get('field_sources') or {}
        if not provenance:
            print_warning("No provenance data for this result.")
            return
        print_subsection("Field Sources")
        print_table([[field, ', '.join(sources)]
                     for field, sources in sorted(provenance.items())],
                    headers=['Field', 'Source(s)'])

    # ------------------------------------------------------------------
    # Batch
    # ------------------------------------------------------------------

    def batch_operations_menu(self) -> None:
        clear_screen()
        print_section("BATCH OPERATIONS")
        print("  Targets are read one per line; a blank line ends the list.")
        print(f"  {Colors.CYAN}[1]{Colors.RESET} Batch IP lookup")
        print(f"  {Colors.CYAN}[2]{Colors.RESET} Batch phone lookup")
        print(f"  {Colors.CYAN}[3]{Colors.RESET} Batch username scan")
        print(f"  {Colors.CYAN}[4]{Colors.RESET} Batch email lookup")
        print(f"  {Colors.CYAN}[5]{Colors.RESET} Batch domain lookup")
        print(f"  {Colors.CYAN}[0]{Colors.RESET} Back")

        choice = input(f"\n{Colors.GREEN}Select: {Colors.RESET}").strip()
        runner = {
            '1': self.batch_ip_tracking,
            '2': self.batch_phone_tracking,
            '3': self.batch_username_tracking,
            '4': self.batch_email_tracking,
            '5': self.batch_domain_tracking,
        }.get(choice)
        if runner:
            runner()

    def _read_targets(self, prompt: str) -> List[str]:
        print_info(prompt)
        targets = []
        while True:
            value = input().strip()
            if not value:
                break
            targets.append(value)
        return targets

    def batch_ip_tracking(self) -> None:
        ips = self._read_targets("Enter IP addresses:")
        if not ips:
            print_warning("No IPs entered.")
            return

        print_info(f"Looking up {len(ips)} IPs across all sources...")
        results = self.ip_tracker.batch_track(ips)

        print_subsection("Results")
        print_table([
            [r['ip'],
             len(r['sources_ok']),
             r['field_count'],
             r['info'].get('country', '-'),
             r['info'].get('city', '-'),
             r['info'].get('org', '-')]
            for r in results
        ], headers=['IP', 'Sources', 'Fields', 'Country', 'City', 'Organisation'])

        self._maybe_chart_ips(results)
        self._maybe_export_batch('ip', results)

    def batch_phone_tracking(self) -> None:
        phones = self._read_targets("Enter phone numbers:")
        if not phones:
            print_warning("No numbers entered.")
            return
        region = get_input("Default region code", required=False) or "ID"

        print_info(f"Parsing {len(phones)} numbers...")
        results = self.phone_tracker.batch_track(phones, region)

        print_subsection("Results")
        print_table([
            [r['phone_number'],
             r['info'].get('international', '-'),
             r['info'].get('type', '-'),
             r['info'].get('region_code', '-'),
             r['info'].get('carrier', '-'),
             _fmt_value('valid_format', r['info'].get('valid_format', False))]
            for r in results
        ], headers=['Input', 'International', 'Type', 'Region', 'Carrier', 'Valid'])

        self._maybe_export_batch('phone', results)

    def batch_username_tracking(self) -> None:
        usernames = self._read_targets("Enter usernames:")
        if not usernames:
            print_warning("No usernames entered.")
            return

        print_info(f"Scanning {len(usernames)} usernames...")
        results = []
        for name in usernames:
            result = self.username_tracker.track(name)
            results.append(result)
            found = [r['platform'] for r in result['results']
                     if r.get('status') == 'found']
            print_success(f"{name}: found on {len(found)} platforms "
                          f"({', '.join(found[:6])}{'...' if len(found) > 6 else ''})")

        self._maybe_export_batch('username', results)

    def batch_email_tracking(self) -> None:
        emails = self._read_targets("Enter email addresses:")
        if not emails:
            print_warning("No addresses entered.")
            return

        print_info(f"Looking up {len(emails)} addresses...")
        results = self.email_tracker.batch_track(emails)

        print_subsection("Results")
        print_table([
            [r['email'],
             r['info'].get('valid_format', '-'),
             _fmt_value('mx_exists', r['info'].get('mx_exists', False)),
             _fmt_value('disposable', r['info'].get('disposable', '-')),
             r['info'].get('registrar', '-'),
             r['info'].get('hibp_breach_count', '-')]
            for r in results
        ], headers=['Email', 'Valid', 'MX', 'Disposable', 'Registrar', 'Breaches'])

        self._maybe_export_batch('email', results)

    def batch_domain_tracking(self) -> None:
        domains = self._read_targets("Enter domains:")
        if not domains:
            print_warning("No domains entered.")
            return

        print_info(f"Looking up {len(domains)} domains across registration, "
                   f"DNS, CT and HTTP sources...")
        results = self.domain_tracker.batch_track(domains)

        print_subsection("Results")
        print_table([
            [r['domain'],
             len(r['sources_ok']),
             r['field_count'],
             r['info'].get('registrar', '-'),
             r['info'].get('domain_age_days', '-'),
             _fmt_value('dnssec', r['info'].get('dnssec', False)),
             r['info'].get('http_status', '-')]
            for r in results
        ], headers=['Domain', 'Sources', 'Fields', 'Registrar', 'Age (days)',
                    'DNSSEC', 'HTTP'])

        self._maybe_export_batch('domain', results)

    def _maybe_chart_ips(self, results: List[Dict[str, Any]]) -> None:
        if not confirm_action("\nPlot country distribution?"):
            return
        counts: Dict[str, int] = {}
        for r in results:
            country = r['info'].get('country')
            if country:
                counts[country] = counts.get(country, 0) + 1
        if not counts:
            print_warning("No country data to plot.")
            return
        path = self.chart_gen.create_pie_chart(
            counts, "Targets by country", "batch_countries.png")
        print_success(f"Chart saved: {path}")

    def _maybe_export_batch(self, kind: str, results: List[Dict[str, Any]]) -> None:
        if not confirm_action("\nSave batch results?"):
            return
        print("  [1] JSON    [2] HTML    [3] Markdown    [4] CSV")
        choice = input(f"{Colors.GREEN}Format: {Colors.RESET}").strip()
        method = {
            '1': self.report_gen.generate_json_report,
            '2': self.report_gen.generate_html_report,
            '3': self.report_gen.generate_markdown_report,
        }.get(choice)
        try:
            if method:
                path = method({kind: results}, f"Batch {kind} report")
                print_success(f"Report saved: {path}")
            elif choice == '4':
                rows = []
                for r in results:
                    info = r.get('info', {})
                    rows.append({
                        'target': r.get(kind) or r.get('ip') or r.get('email')
                                  or r.get('phone_number') or r.get('username'),
                        'country': info.get('country', ''),
                        'city': info.get('city', ''),
                        'org': info.get('org', ''),
                        'carrier': info.get('carrier', ''),
                        'valid': info.get('valid_format', ''),
                        'fields': r.get('field_count', 0),
                    })
                path = self.report_gen.generate_csv_report(rows, f"batch_{kind}.csv")
                print_success(f"CSV saved: {path}")
        except Exception as e:
            print_error(f"Export failed: {type(e).__name__}: {e}")

    # ------------------------------------------------------------------
    # History / statistics
    # ------------------------------------------------------------------

    def history_menu(self) -> None:
        clear_screen()
        print_section("QUERY HISTORY")
        print("  [1] Recent queries")
        print("  [2] Search history")
        print("  [3] Clear history")
        print("  [0] Back")

        choice = input(f"\n{Colors.GREEN}Select: {Colors.RESET}").strip()
        if choice == '1':
            self.view_recent_queries()
        elif choice == '2':
            self.search_history()
        elif choice == '3':
            if confirm_action("Clear all query history?"):
                count = db.clear_history()
                print_success(f"Cleared {count} records")
                input("\nPress Enter to continue...")

    def view_recent_queries(self) -> None:
        history = db.get_history(limit=25)
        if not history:
            print_warning("No query history yet.")
            input("\nPress Enter to continue...")
            return

        print_subsection("Recent Queries")
        print_table([
            [r.id, r.query_type, r.query_value,
             db.count_fields(r.result_data),
             'ok' if r.success else 'failed',
             r.created_at]
            for r in history
        ], headers=['ID', 'Type', 'Value', 'Fields', 'Status', 'When'])

        choice = input(f"\n{Colors.GREEN}Inspect which record? (blank to skip): {Colors.RESET}").strip()
        if choice.isdigit():
            self.show_record(db.get_query_by_id(int(choice)))
        input("\nPress Enter to continue...")

    def search_history(self) -> None:
        term = get_input("Enter search term")
        results = db.search_history(term)
        if not results:
            print_warning("No matching queries.")
            input("\nPress Enter to continue...")
            return
        print_subsection(f"Results for '{term}'")
        print_table([[r.id, r.query_type, r.query_value, r.created_at] for r in results],
                    headers=['ID', 'Type', 'Value', 'When'])
        choice = input(f"\n{Colors.GREEN}Inspect which record? (blank to skip): {Colors.RESET}").strip()
        if choice.isdigit():
            self.show_record(db.get_query_by_id(int(choice)))
        input("\nPress Enter to continue...")

    def show_record(self, record) -> None:
        if record is None:
            print_warning("Record not found.")
            return
        print_subsection(f"Record #{record.id} - {record.query_type} {record.query_value}")
        print_json(json.loads(record.result_data))

    def statistics_menu(self) -> None:
        clear_screen()
        print_section("STATISTICS")
        stats = db.get_statistics()

        print_subsection("Overview")
        print_table([
            ['Total queries', stats['total_queries']],
            ['Success rate', f"{stats['success_rate']}%"],
            ['Queries in last 7 days', stats['recent_queries_7d']],
        ], headers=['Metric', 'Value'])

        if stats['queries_by_type']:
            print_subsection("Queries by Type")
            print_table([[k, v] for k, v in stats['queries_by_type'].items()],
                        headers=['Type', 'Count'])
            if confirm_action("\nGenerate dashboard chart?"):
                path = self.chart_gen.create_statistics_dashboard(stats)
                print_success(f"Dashboard saved: {path}")

        cache_stats = cache.stats()
        print_subsection("Response Cache")
        print_table([
            ['Enabled', _fmt_value('x', cache_stats['enabled'])],
            ['Entries', cache_stats['entries']],
            ['Fresh', cache_stats['fresh']],
            ['Hits / misses', f"{cache_stats['hits']} / {cache_stats['misses']}"],
            ['Default TTL', f"{cache_stats['default_ttl']}s"],
            ['Location', cache_stats['path']],
        ], headers=['Metric', 'Value'])

        net = metrics.snapshot()
        print_subsection("Network (this session)")
        print_table([
            ['HTTP requests', net['requests']],
            ['Cache hit rate', f"{net['cache_hit_rate']}%"],
            ['Failures / timeouts', f"{net['failures']} / {net['timeouts']}"],
            ['Sources used / failed', f"{net['sources_used']} / {net['sources_failed']}"],
        ], headers=['Metric', 'Value'])

        input("\nPress Enter to continue...")

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------

    def settings_menu(self) -> None:
        clear_screen()
        print_section("SETTINGS")
        print("  [1] View configuration")
        print("  [2] Configure API keys")
        print("  [3] Output format")
        print("  [4] Toggle history saving")
        print("  [5] Toggle deep username scan")
        print("  [6] Request timeout")
        print("  [7] Toggle response cache")
        print("  [8] Per-host request rate")
        print("  [9] Proxy URL")
        print("  [10] Clear response cache")
        print("  [0] Back")

        choice = input(f"\n{Colors.GREEN}Select: {Colors.RESET}").strip()
        if choice == '1':
            self.view_configuration()
        elif choice == '2':
            self.configure_api_keys()
        elif choice == '3':
            self.set_output_format()
        elif choice == '4':
            self.toggle_history()
        elif choice == '5':
            self.toggle_deep_scan()
        elif choice == '6':
            self.set_timeout()
        elif choice == '7':
            self.toggle_cache()
        elif choice == '8':
            self.set_rate_limit()
        elif choice == '9':
            self.set_proxy()
        elif choice == '10':
            self.clear_cache()

    def view_configuration(self) -> None:
        print_subsection("Application Settings")
        app = config.app_config
        print_table([
            ['Debug mode', _fmt_value('x', app.debug)],
            ['Log level', app.log_level],
            ['Output format', app.output_format],
            ['Save history', _fmt_value('x', app.save_history)],
            ['Deep username scan', _fmt_value('x', app.deep_username_scan)],
            ['Parallel sources', _fmt_value('x', app.parallel_sources)],
            ['Request timeout', f"{app.request_timeout}s"],
            ['Response cache', _fmt_value('x', app.cache_enabled)],
            ['Cache TTL', f"{app.cache_ttl}s"],
            ['Requests per second', app.requests_per_second],
            ['Proxy', app.proxy or '(none)'],
            ['Max history entries', app.max_history_entries],
            ['User agent', app.user_agent],
            ['Database', config.db_config.sqlite_path],
        ], headers=['Setting', 'Value'])

        print_subsection("API Keys")
        print_table([[s, 'configured' if v else 'not configured']
                     for s, v in config.configured_services().items()],
                    headers=['Service', 'Status'])

        print_info("Use option 2 to add keys, or set OBSCURALENS_<SERVICE>_API_KEY "
                   "environment variables.")
        input("\nPress Enter to continue...")

    def configure_api_keys(self) -> None:
        print_subsection("Configure API Keys")
        print_info("Leave blank to skip a service. Keys are stored in "
                   "config/secrets.yaml with owner-only permissions.")

        for service in SERVICES:
            current = config.get_api_key(service)
            if current:
                masked = f"{'*' * 8}{current[-4:]}"
                print(f"\n  {Colors.CYAN}{service}:{Colors.RESET} {masked} (configured)")
                if not confirm_action(f"  Replace {service} key?"):
                    continue
            value = input(f"  {service} API key: ").strip()
            if value:
                config.set_api_key(service, value)
                print_success(f"{service} key saved")

        config.save_secrets()
        print_success("Secrets written to config/secrets.yaml")
        input("\nPress Enter to continue...")

    def api_status_menu(self) -> None:
        clear_screen()
        print_section("API KEY STATUS")
        print("  Unkeyed sources always run. Keyed sources add extra fields.")

        rows = []
        for service in SERVICES:
            configured = config.is_configured(service)
            rows.append([service,
                         'yes' if configured else 'no',
                         'active' if configured else 'inactive'])
        print_table(rows, headers=['Service', 'Key Set', 'Status'])

        print_info("Keyless sources for IP: ipwhois.app, ipwho.is, freeipapi, "
                   "ip-api.com, db-ip.com, iplocation.net, Shodan InternetDB, "
                   "reverse DNS, RDAP")
        print_info("Keyless sources for email: MX/A/AAAA/NS/SOA/CAA/TXT, SPF, "
                   "DMARC, DKIM, DNSSEC, disposable check, OpenPGP, domain RDAP, "
                   "Gravatar")
        print_info("Keyless sources for domain: RDAP, DNS, Cert Spotter "
                   "(Certificate Transparency), HTTP headers")
        input("\nPress Enter to continue...")

    def set_output_format(self) -> None:
        print_subsection("Output Format")
        print("  [1] Table    [2] JSON    [3] CSV")
        choice = input(f"{Colors.GREEN}Select: {Colors.RESET}").strip()
        fmt = {'1': 'table', '2': 'json', '3': 'csv'}.get(choice)
        if fmt:
            config.app_config.output_format = fmt
            config.save_config()
            print_success(f"Output format set to {fmt}")
        input("\nPress Enter to continue...")

    def toggle_history(self) -> None:
        config.app_config.save_history = not config.app_config.save_history
        config.save_config()
        state = "enabled" if config.app_config.save_history else "disabled"
        print_success(f"History saving {state}")
        input("\nPress Enter to continue...")

    def toggle_deep_scan(self) -> None:
        config.app_config.deep_username_scan = not config.app_config.deep_username_scan
        config.save_config()
        state = "on" if config.app_config.deep_username_scan else "off"
        print_success(f"Deep username scan {state} "
                      f"(profile details {'collected' if state == 'on' else 'skipped'})")
        input("\nPress Enter to continue...")

    def set_timeout(self) -> None:
        raw = get_input("Request timeout in seconds", required=False)
        try:
            value = int(raw)
            if not 5 <= value <= 300:
                raise ValueError
        except ValueError:
            print_error("Enter a number between 5 and 300.")
            input("\nPress Enter to continue...")
            return
        config.app_config.request_timeout = value
        config.save_config()
        print_success(f"Request timeout set to {value}s (applies to new runs)")
        input("\nPress Enter to continue...")

    def toggle_cache(self) -> None:
        config.app_config.cache_enabled = not config.app_config.cache_enabled
        config.save_config()
        state = "enabled" if config.app_config.cache_enabled else "disabled"
        print_success(f"Response cache {state}")
        input("\nPress Enter to continue...")

    def set_rate_limit(self) -> None:
        raw = get_input("Requests per second per host (0 disables, e.g. 8)",
                        required=False)
        if raw == '':
            print_info("No change.")
            input("\nPress Enter to continue...")
            return
        try:
            value = float(raw)
            if value < 0 or value > 100:
                raise ValueError
        except ValueError:
            print_error("Enter a number between 0 and 100.")
            input("\nPress Enter to continue...")
            return
        config.app_config.requests_per_second = value
        config.save_config()
        print_success(f"Rate limit set to {value}/s per host")
        input("\nPress Enter to continue...")

    def set_proxy(self) -> None:
        raw = get_input("Proxy URL (e.g. http://127.0.0.1:8080, blank clears)",
                        required=False)
        config.app_config.proxy = raw.strip()
        config.save_config()
        if raw.strip():
            print_success(f"Proxy set to {raw.strip()}")
        else:
            print_success("Proxy cleared")
        input("\nPress Enter to continue...")

    def clear_cache(self) -> None:
        if not confirm_action("Delete all cached HTTP responses?"):
            return
        removed = cache.clear()
        print_success(f"Removed {removed} cached responses")
        input("\nPress Enter to continue...")

    # ------------------------------------------------------------------
    # Watchlist / universal investigation
    # ------------------------------------------------------------------

    def watchlist_menu(self) -> None:
        clear_screen()
        print_section("WATCHLIST")
        entries = watchlist.list()
        if entries:
            print_table([
                [e.id, e.target, e.kind, e.label or '-', e.snapshots,
                 e.last_checked or 'never']
                for e in entries
            ], headers=['ID', 'Target', 'Kind', 'Label', 'Snapshots',
                        'Last Checked'])
        else:
            print_warning("No watched targets yet.")

        print("\n  [1] Add target    [2] Run check    [3] Remove    [0] Back")
        choice = input(f"{Colors.GREEN}Select: {Colors.RESET}").strip()

        if choice == '1':
            target = get_input("Target to watch")
            label = get_input("Label", required=False)
            try:
                watch_id = watchlist.add(target, label=label)
                print_success(f"Watching #{watch_id}: {target}")
            except ValueError as e:
                print_error(str(e))
        elif choice == '2':
            raw = get_input("Watch ID or target (blank = all)", required=False)
            identifier = int(raw) if raw.isdigit() else (raw or None)
            diffs = watchlist.check(identifier)
            if not diffs:
                print_warning("No matching watch entries.")
            else:
                print_subsection("Results")
                print_table([
                    [d.watch_id, d.target, 'yes' if d.is_first else 'no',
                     len(d.added), len(d.removed), len(d.changed),
                     'ok' if d.success else f"error: {d.error}"]
                    for d in diffs
                ], headers=['ID', 'Target', 'First', 'Added', 'Removed',
                            'Changed', 'Status'])
                rows = []
                for d in diffs:
                    for field, value in d.added.items():
                        rows.append([d.target, 'added', field, '', value])
                    for field, value in d.removed.items():
                        rows.append([d.target, 'removed', field, value, ''])
                    for field, change in d.changed.items():
                        rows.append([d.target, 'changed', field,
                                     change.get('from'), change.get('to')])
                if rows:
                    print_subsection("Changes")
                    print_table(rows, headers=['Target', 'Change', 'Field',
                                               'From', 'To'])
        elif choice == '3':
            raw = get_input("Watch ID or target")
            identifier = int(raw) if raw.isdigit() else raw
            removed = watchlist.remove(identifier)
            if removed:
                print_success(f"Removed {removed} watch entry")
            else:
                print_warning("No matching watch entry.")

        input("\nPress Enter to continue...")

    def investigate_menu(self) -> None:
        clear_screen()
        print_section("UNIVERSAL INVESTIGATE")

        target = get_input("Enter IP / domain / email / phone / username")
        kind = detect_kind(target)
        if kind is None:
            print_error(f"Cannot determine target type: {target!r}")
            input("\nPress Enter to continue...")
            return

        pivot = confirm_action(
            f"Detected {kind}. Follow related pivots "
            f"(email->domain, domain->A, ip->PTR)?")
        print_info(f"Investigating {target}...")
        payload = investigate(target, pivot=pivot)

        displayers = {
            'ip': self.display_ip_results,
            'phone': self.display_phone_results,
            'username': self.display_username_results,
            'email': self.display_email_results,
            'domain': self.display_domain_results,
        }
        for kind_name in payload.get('order', []):
            result = payload['results'].get(kind_name)
            if result:
                print_section(f"{kind_name.upper()} RESULT")
                displayers[kind_name](result)

        if payload.get('entities'):
            print_subsection("Entities")
            print_table([[e['type'], e['value'], e['role']]
                         for e in payload['entities']],
                        headers=['Type', 'Value', 'Role'])

        if payload.get('errors'):
            for error in payload['errors']:
                print_warning(error)

        if confirm_action("\nSave Mermaid graph?"):
            filename = re.sub(r'[^A-Za-z0-9._-]', '_', target) + '.mmd'
            path = self.report_gen.output_dir / filename
            path.write_text(to_mermaid(payload), encoding='utf-8')
            print_success(f"Graph saved: {path}")

        input("\nPress Enter to continue...")

    def exit_program(self) -> None:
        print_info("Thank you for using ObscuraLens.")
        print_info("Stay ethical: only investigate targets you are authorised to research.")
        sys.exit(0)


def main() -> None:
    if len(sys.argv) > 1:
        from .commands import run
        sys.exit(run(sys.argv[1:]))
    try:
        ObscuraLensCLI().run()
    except KeyboardInterrupt:
        print("\n")
        print_info("Exiting ObscuraLens...")
        sys.exit(0)


if __name__ == '__main__':
    main()

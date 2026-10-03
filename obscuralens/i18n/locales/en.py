"""
English locale for ObscuraLens.

Language: English
Native name: English
Direction: ltr
Locale code: en
Translators: ObscuraLens contributors

This is the canonical (source) catalogue: every other locale module under
``obscuralens/i18n/locales`` defines the exact same key set, keeps every
``{placeholder}`` token verbatim and translates each English value in full.
Completion percentages reported by ``obscuralens.i18n.list_languages`` are
computed against the key count of this module.

Editing rules:
* one flat ``"prefix.key": "value"`` entry per line of the catalogue;
* keep the ``{placeholder}`` tokens exactly as written in this file;
* long sentences are wrapped inside parentheses (implicit concatenation);
* the ``plural.*`` keys are chosen by ``tp()`` through the ``.zero`` /``.one``
  / ``.many`` suffixes and the count is interpolated as ``{count}``.
"""

STRINGS = {

    # --- app -------------------------------------------------------------------

    "app.title": "ObscuraLens",
    "app.tagline": (
        "Multi-source OSINT investigation console"
    ),
    "app.version": "Version {version}",
    "app.channel": "Channel: {channel}",

    "app.description": (
        "ObscuraLens aggregates intelligence from dozens of public sources "
        "across fourteen target kinds, correlates the findings, scores the "
        "overall risk and renders shareable investigation reports."
    ),
    "app.copyright": (
        "Copyright (c) {year} the ObscuraLens contributors"
    ),
    "app.license": "Released under the MIT License",
    "app.website": "Project homepage: {url}",

    "app.edition": "Desktop edition",
    "app.console_edition": "Console edition",

    # --- common ----------------------------------------------------------------

    # Buttons and short answers.
    "common.ok": "OK",
    "common.cancel": "Cancel",
    "common.yes": "Yes",
    "common.no": "No",
    "common.back": "Back",
    "common.quit": "Quit",
    "common.exit": "Exit",

    # Status words.
    "common.loading": "Loading...",
    "common.done": "Done",
    "common.error": "Error",
    "common.warning": "Warning",
    "common.info": "Information",
    "common.none": "None",
    "common.unknown": "Unknown",

    # Generic nouns.
    "common.all": "All",
    "common.source": "Source",
    "common.sources": "Sources",
    "common.target": "Target",
    "common.kind": "Kind",
    "common.results": "Results",
    "common.summary": "Summary",
    "common.details": "Details",

    # Navigation and actions.
    "common.continue": "Continue",
    "common.confirm": "Confirm",
    "common.help": "Help",
    "common.settings": "Settings",
    "common.language": "Language",
    "common.about": "About",

    "common.search": "Search",
    "common.save": "Save",
    "common.export": "Export",
    "common.copy": "Copy",
    "common.retry": "Retry",
    "common.refresh": "Refresh",
    "common.close": "Close",
    "common.open": "Open",
    "common.select": "Select",
    "common.selected": "Selected",

    # Table columns and data attributes.
    "common.name": "Name",
    "common.status": "Status",
    "common.value": "Value",
    "common.total": "Total",

    "common.average": "Average",
    "common.date": "Date",
    "common.time": "Time",
    "common.duration": "Duration",
    "common.count": "Count",
    "common.page": "Page",
    "common.actions": "Actions",

    "common.filter": "Filter",
    "common.sort": "Sort",

    # Flags and qualifiers.
    "common.enabled": "Enabled",
    "common.disabled": "Disabled",
    "common.optional": "Optional",
    "common.required": "Required",
    "common.default": "Default",
    "common.overview": "Overview",

    # Relative time words.
    "common.today": "Today",
    "common.yesterday": "Yesterday",
    "common.now": "Now",

    # Release channels.
    "common.beta": "Beta",
    "common.stable": "Stable",
    "common.nightly": "Nightly",

    # --- menu ------------------------------------------------------------------

    "menu.main_title": "ObscuraLens - Main Menu",
    "menu.choose_option": "Choose an option:",

    "menu.invalid_choice": (
        "Invalid choice '{choice}', please try again."
    ),
    "menu.select_kind": "Select the target kind:",
    "menu.enter_target": "Enter the {kind} to look up:",

    "menu.lookup": "Single lookup",
    "menu.investigate": "Full investigation",
    "menu.watchlist": "Watchlist",
    "menu.cases": "Case manager",
    "menu.tools": "Tools",

    "menu.tools_title": "Tools",
    "menu.watchlist_title": "Watchlist",
    "menu.cases_title": "Case manager",
    "menu.settings_title": "Settings",
    "menu.settings_menu": "Settings",

    "menu.language_menu": "Change language",
    "menu.language_changed": "Language changed to {language}.",
    "menu.returning_to_main": "Returning to the main menu...",

    "menu.exit_prompt": (
        "Are you sure you want to exit? (y/N)"
    ),
    "menu.goodbye": "Goodbye!",

    # --- cli -------------------------------------------------------------------

    "cli.usage_hint": (
        "Usage: obscuralens <command> [options]"
    ),
    "cli.try_help": (
        "Run 'obscuralens --help' for usage."
    ),
    "cli.unknown_command": "Unknown command: {command}",
    "cli.target_prompt": "Enter a target:",
    "cli.detected": "Detected kind: {kind}",

    "cli.starting_lookup": "Looking up {target} ({kind})...",
    "cli.fetching": "Fetching {source}...",
    "cli.aggregating": (
        "Aggregating results from {count} sources..."
    ),
    "cli.elapsed": "Elapsed: {seconds}s",
    "cli.risk_score": "Risk score: {score}/100",

    "cli.output_format": "Output format: {format}",

    "cli.format_json": "JSON",
    "cli.format_table": "Table",
    "cli.format_csv": "CSV",
    "cli.provenance": "Field provenance",
    "cli.field_sources": "Field sources",

    "cli.no_results": (
        "No results found for '{target}'."
    ),
    "cli.lookup_failed": (
        "Lookup failed for '{target}': {reason}"
    ),
    "cli.sources_ok": (
        "{count} source(s) responded successfully."
    ),
    "cli.sources_failed": (
        "{count} source(s) failed to respond."
    ),

    "cli.showing": "Showing {shown} of {total} results",
    "cli.sorting_by": "Sorted by {field}",
    "cli.filtering_by": "Filtered by {field}",

    "cli.saved_report": "Report saved to {path}",
    "cli.output_saved": "Output written to {path}",
    "cli.history": "Recent lookups",

    "cli.empty_history": "No recent lookups.",
    "cli.confirm_clear_history": "Clear lookup history? (y/N)",

    # --- kinds -----------------------------------------------------------------

    "kinds.ip": "IP address",
    "kinds.phone": "Phone number",
    "kinds.username": "Username",

    "kinds.email": "Email address",
    "kinds.domain": "Domain",
    "kinds.url": "URL",

    "kinds.crypto": "Crypto address",
    "kinds.hash": "File hash",

    "kinds.cve": "CVE identifier",
    "kinds.asn": "AS number",
    "kinds.mac": "MAC address",
    "kinds.iban": "IBAN",
    "kinds.imei": "IMEI",
    "kinds.coords": "Coordinates",

    "kinds.unknown_kind": "Unknown kind",
    "kinds.detected_kind": "Detected kind: {kind}",
    "kinds.select_hint": "Choose 1-{count} to select a kind",
    "kinds.kind_list_title": "Supported target kinds",

    # --- desktop ---------------------------------------------------------------

    "desktop.title": "ObscuraLens Desktop",
    "desktop.beta_notice": (
        "This is a beta build of the ObscuraLens desktop edition. Some "
        "features are still evolving, and automated nightly builds may be "
        "less stable than tagged releases."
    ),

    "desktop.starting": "Starting the local server...",
    "desktop.listening_on": "Listening on http://{host}:{port}",
    "desktop.ready": "Ready.",
    "desktop.launch_hint": "Press Ctrl+C to stop the server.",
    "desktop.shutdown": "Shutting down...",

    "desktop.opening_browser": "Opening the web interface...",
    "desktop.browser_opened": (
        "Opened {browser}; if it did not start, visit {url} manually."
    ),
    "desktop.browser_failed": (
        "Could not open a web browser: {reason}"
    ),

    "desktop.server_stopped": "Server stopped.",
    "desktop.port_in_use": (
        "Port {port} is already in use; trying {alternative} instead."
    ),
    "desktop.single_instance": (
        "ObscuraLens is already running; activating the existing window."
    ),

    "desktop.checking_updates": "Checking for updates...",
    "desktop.update_available": (
        "Update available: {version} (current: {current})."
    ),
    "desktop.update_check_failed": (
        "Update check failed: {reason}"
    ),
    "desktop.up_to_date": (
        "You are running the latest version ({version})."
    ),
    "desktop.downloading_update": (
        "Downloading update {version} ({percent}%)..."
    ),
    "desktop.update_downloaded": (
        "Update downloaded; restart to apply {version}."
    ),
    "desktop.nightly_channel": (
        "Nightly channel: builds are refreshed every night."
    ),

    "desktop.diagnostics": "Diagnostics",
    "desktop.diagnostics_title": "Desktop diagnostics",

    "desktop.diagnostics_ok": "All {count} checks passed.",
    "desktop.diagnostics_failed": "{failed} of {count} checks failed.",

    "desktop.copy_diagnostics": (
        "Copy diagnostics to the clipboard?"
    ),
    "desktop.diagnostics_copied": (
        "Diagnostics copied to the clipboard."
    ),

    "desktop.data_dir": (
        "Desktop data directory: {path}"
    ),
    "desktop.cache_dir": "Cache directory: {path}",
    "desktop.log_file": "Log file: {path}",

    # --- report ----------------------------------------------------------------

    "report.title": "Investigation report",
    "report.generated": "Generated: {date}",
    "report.target": "Target: {target} ({kind})",
    "report.footer": (
        "Generated by ObscuraLens v{version} on {date}"
    ),
    "report.page": "Page {page} of {total}",

    "report.sections": "Sections",
    "report.table_of_contents": "Table of contents",

    "report.executive_summary": "Executive summary",
    "report.findings": "Findings",
    "report.timeline": "Timeline",
    "report.correlations": "Correlations",
    "report.sources_section": "Sources",
    "report.appendix": "Appendix: raw source data",

    "report.risk_score": (
        "Risk score: {score}/100 ({label})"
    ),
    "report.confidence": "Confidence: {level}",

    "report.no_findings": (
        "No findings recorded for this target."
    ),
    "report.field": "Field",
    "report.value": "Value",
    "report.source_column": "Source",

    "report.disclaimer": (
        "This report is generated from publicly available information for "
        "investigative reference only. Findings should be independently "
        "verified before being acted upon; the authors accept no liability "
        "for misuse."
    ),

    # --- errors ----------------------------------------------------------------

    "errors.network": (
        "Network error while contacting {source}: {reason}"
    ),
    "errors.timeout": (
        "Request to {source} timed out after {seconds}s."
    ),
    "errors.rate_limited": (
        "Rate limited by {source}; retrying in {seconds}s."
    ),
    "errors.malformed_response": (
        "Malformed response from {source}: {reason}"
    ),
    "errors.ssl_error": (
        "SSL verification failed for {source}: {reason}"
    ),

    "errors.invalid_input": "Invalid input: {reason}",
    "errors.invalid_format": (
        "Unsupported output format: '{format}'"
    ),
    "errors.not_found": "Not found: {target}",
    "errors.no_sources": (
        "No sources are configured for kind '{kind}'."
    ),
    "errors.source_unavailable": (
        "Source '{source}' is unavailable."
    ),
    "errors.disabled_source": (
        "Source '{source}' is disabled in the configuration."
    ),

    "errors.config_missing": (
        "Configuration key '{key}' is missing."
    ),

    "errors.database": "Database error: {reason}",
    "errors.permission_denied": "Permission denied: {path}",
    "errors.disk_full": (
        "Not enough disk space to write {path}."
    ),
    "errors.offline": "Working offline; {source} skipped.",
    "errors.interrupted": "Interrupted by the user.",
    "errors.unexpected": (
        "An unexpected error occurred: {reason}"
    ),

    "errors.unknown_language": "Unknown language code: '{code}'",
    "errors.missing_key": "Missing translation key: '{key}'",

    # --- plural ----------------------------------------------------------------

    # Plural-aware keys consumed by tp(): the runtime picks .zero, .one or
    # .many from the count and always interpolates {count} into the result.
    "plural.results.zero": "No results",
    "plural.results.one": "{count} result",
    "plural.results.many": "{count} results",

    "plural.sources.zero": "No sources",
    "plural.sources.one": "{count} source",
    "plural.sources.many": "{count} sources",

    "plural.findings.zero": "No findings",
    "plural.findings.one": "{count} finding",
    "plural.findings.many": "{count} findings",

    "plural.matches.zero": "No matches",
    "plural.matches.one": "{count} match",
    "plural.matches.many": "{count} matches",
}

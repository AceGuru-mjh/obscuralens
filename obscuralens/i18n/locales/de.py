"""
German locale for ObscuraLens.

Language: German
Native name: Deutsch
Direction: ltr
Locale code: de
Translators: ObscuraLens contributors

Dies ist das deutsche Sprachpaket: wie jedes andere Locale unter
``obscuralens/i18n/locales`` definiert es exakt dieselbe Schlüsselmenge wie
der englische Quellkatalog (``en.py``), behält sämtliche ``{placeholder}``
-Token wörtlich bei und übersetzt jeden englischen Wert vollständig. Der
von ``obscuralens.i18n.list_languages`` gemeldete Fertigstellungsgrad wird
anhand der Schlüsselanzahl des englischen Moduls berechnet.

Bearbeitungsregeln:
* ein flacher Eintrag pro Zeile im Format ``"praefix.schluessel": "wert"``;
* ``{placeholder}``-Token exakt wie in der englischen Datei belassen;
* lange Sätze werden in Klammern per impliziter Konkatenation umbrochen;
* die ``plural.*``-Schlüssel wählt ``tp()`` über die Suffixe ``.zero`` /
  ``.one`` / ``.many``, die Anzahl wird immer als ``{count}`` eingesetzt.
"""

STRINGS = {

    # --- app -------------------------------------------------------------------

    "app.title": "ObscuraLens",
    "app.tagline": (
        "Konsole für OSINT-Untersuchungen mit mehreren Quellen"
    ),
    "app.version": "Version {version}",
    "app.channel": "Kanal: {channel}",

    "app.description": (
        "ObscuraLens bündelt Erkenntnisse aus Dutzenden öffentlicher Quellen "
        "über vierzehn Zielarten hinweg, korreliert die Funde, bewertet das "
        "Gesamtrisiko und erzeugt teilbare Untersuchungsberichte."
    ),
    "app.copyright": (
        "Copyright (c) {year} die ObscuraLens-Mitwirkenden"
    ),
    "app.license": "Veröffentlicht unter der MIT-Lizenz",
    "app.website": "Projektseite: {url}",

    "app.edition": "Desktop-Edition",
    "app.console_edition": "Konsolen-Edition",

    # --- common ----------------------------------------------------------------

    # Schaltflächen und kurze Antworten.
    "common.ok": "OK",
    "common.cancel": "Abbrechen",
    "common.yes": "Ja",
    "common.no": "Nein",
    "common.back": "Zurück",
    "common.quit": "Beenden",
    "common.exit": "Verlassen",

    # Statuswörter.
    "common.loading": "Wird geladen...",
    "common.done": "Fertig",
    "common.error": "Fehler",
    "common.warning": "Warnung",
    "common.info": "Information",
    "common.none": "Keine",
    "common.unknown": "Unbekannt",

    # Allgemeine Substantive.
    "common.all": "Alle",
    "common.source": "Quelle",
    "common.sources": "Quellen",
    "common.target": "Ziel",
    "common.kind": "Art",
    "common.results": "Ergebnisse",
    "common.summary": "Zusammenfassung",
    "common.details": "Details",

    # Navigation und Aktionen.
    "common.continue": "Fortfahren",
    "common.confirm": "Bestätigen",
    "common.help": "Hilfe",
    "common.settings": "Einstellungen",
    "common.language": "Sprache",
    "common.about": "Über",

    "common.search": "Suchen",
    "common.save": "Speichern",
    "common.export": "Exportieren",
    "common.copy": "Kopieren",
    "common.retry": "Erneut versuchen",
    "common.refresh": "Aktualisieren",
    "common.close": "Schließen",
    "common.open": "Öffnen",
    "common.select": "Auswählen",
    "common.selected": "Ausgewählt",

    # Tabellenspalten und Datenattribute.
    "common.name": "Name",
    "common.status": "Status",
    "common.value": "Wert",
    "common.total": "Gesamt",

    "common.average": "Durchschnitt",
    "common.date": "Datum",
    "common.time": "Zeit",
    "common.duration": "Dauer",
    "common.count": "Anzahl",
    "common.page": "Seite",
    "common.actions": "Aktionen",

    "common.filter": "Filtern",
    "common.sort": "Sortieren",

    # Schalter und Einschränkungen.
    "common.enabled": "Aktiviert",
    "common.disabled": "Deaktiviert",
    "common.optional": "Optional",
    "common.required": "Erforderlich",
    "common.default": "Standard",
    "common.overview": "Überblick",

    # Relative Zeitwörter.
    "common.today": "Heute",
    "common.yesterday": "Gestern",
    "common.now": "Jetzt",

    # Veröffentlichungskanäle.
    "common.beta": "Beta",
    "common.stable": "Stabil",
    "common.nightly": "Nightly",

    # --- menu ------------------------------------------------------------------

    "menu.main_title": "ObscuraLens - Hauptmenü",
    "menu.choose_option": "Option wählen:",

    "menu.invalid_choice": (
        "Ungültige Auswahl „{choice}“, bitte erneut versuchen."
    ),
    "menu.select_kind": "Zielart wählen:",
    "menu.enter_target": "Bitte {kind} zum Nachschlagen eingeben:",

    "menu.lookup": "Einzelabfrage",
    "menu.investigate": "Vollständige Untersuchung",
    "menu.watchlist": "Beobachtungsliste",
    "menu.cases": "Fallverwaltung",
    "menu.tools": "Werkzeuge",

    "menu.tools_title": "Werkzeuge",
    "menu.watchlist_title": "Beobachtungsliste",
    "menu.cases_title": "Fallverwaltung",
    "menu.settings_title": "Einstellungen",
    "menu.settings_menu": "Einstellungen",

    "menu.language_menu": "Sprache ändern",
    "menu.language_changed": "Sprache auf {language} geändert.",
    "menu.returning_to_main": "Rückkehr zum Hauptmenü...",

    "menu.exit_prompt": (
        "Wirklich beenden? (y/N)"
    ),
    "menu.goodbye": "Auf Wiedersehen!",

    # --- cli -------------------------------------------------------------------

    "cli.usage_hint": (
        "Aufruf: obscuralens <Befehl> [Optionen]"
    ),
    "cli.try_help": (
        "'obscuralens --help' zeigt die Verwendung."
    ),
    "cli.unknown_command": "Unbekannter Befehl: {command}",
    "cli.target_prompt": "Ziel eingeben:",
    "cli.detected": "Erkannte Art: {kind}",

    "cli.starting_lookup": "Schlage {target} ({kind}) nach...",
    "cli.fetching": "Rufe {source} ab...",
    "cli.aggregating": (
        "Fasse Ergebnisse von {count} Quellen zusammen..."
    ),
    "cli.elapsed": "Dauer: {seconds}s",
    "cli.risk_score": "Risikobewertung: {score}/100",

    "cli.output_format": "Ausgabeformat: {format}",

    "cli.format_json": "JSON",
    "cli.format_table": "Tabelle",
    "cli.format_csv": "CSV",
    "cli.provenance": "Herkunft der Felder",
    "cli.field_sources": "Feldquellen",

    "cli.no_results": (
        "Keine Ergebnisse für „{target}“ gefunden."
    ),
    "cli.lookup_failed": (
        "Abfrage für „{target}“ fehlgeschlagen: {reason}"
    ),
    "cli.sources_ok": (
        "{count} Quelle(n) haben erfolgreich geantwortet."
    ),
    "cli.sources_failed": (
        "{count} Quelle(n) haben nicht geantwortet."
    ),

    "cli.showing": "Zeige {shown} von {total} Ergebnissen",
    "cli.sorting_by": "Sortiert nach {field}",
    "cli.filtering_by": "Gefiltert nach {field}",

    "cli.saved_report": "Bericht unter {path} gespeichert",
    "cli.output_saved": "Ausgabe nach {path} geschrieben",
    "cli.history": "Letzte Abfragen",

    "cli.empty_history": "Keine letzten Abfragen.",
    "cli.confirm_clear_history": "Abfrageverlauf löschen? (y/N)",

    # --- kinds -----------------------------------------------------------------

    "kinds.ip": "IP-Adresse",
    "kinds.phone": "Telefonnummer",
    "kinds.username": "Benutzername",

    "kinds.email": "E-Mail-Adresse",
    "kinds.domain": "Domain",
    "kinds.url": "URL",

    "kinds.crypto": "Krypto-Adresse",
    "kinds.hash": "Datei-Hash",

    "kinds.cve": "CVE-Kennung",
    "kinds.asn": "AS-Nummer",
    "kinds.mac": "MAC-Adresse",
    "kinds.iban": "IBAN",
    "kinds.imei": "IMEI",
    "kinds.coords": "Koordinaten",

    "kinds.unknown_kind": "Unbekannte Art",
    "kinds.detected_kind": "Erkannte Art: {kind}",
    "kinds.select_hint": "1-{count} wählen, um eine Art auszuwählen",
    "kinds.kind_list_title": "Unterstützte Zielarten",

    # --- desktop ---------------------------------------------------------------

    "desktop.title": "ObscuraLens Desktop",
    "desktop.beta_notice": (
        "Dies ist ein Beta-Build der ObscuraLens-Desktop-Edition. Einige "
        "Funktionen befinden sich noch in Entwicklung, und automatische "
        "Nightly-Builds können weniger stabil sein als getaggte Releases."
    ),

    "desktop.starting": "Starte den lokalen Server...",
    "desktop.listening_on": "Lausche auf http://{host}:{port}",
    "desktop.ready": "Bereit.",
    "desktop.launch_hint": "Strg+C beendet den Server.",
    "desktop.shutdown": "Fahre herunter...",

    "desktop.opening_browser": "Öffne die Weboberfläche...",
    "desktop.browser_opened": (
        "{browser} wurde geöffnet; falls er nicht startete, rufen Sie {url} manuell auf."
    ),
    "desktop.browser_failed": (
        "Konnte keinen Webbrowser öffnen: {reason}"
    ),

    "desktop.server_stopped": "Server gestoppt.",
    "desktop.port_in_use": (
        "Port {port} ist bereits belegt; versuche stattdessen {alternative}."
    ),
    "desktop.single_instance": (
        "ObscuraLens läuft bereits; aktiviere das vorhandene Fenster."
    ),

    "desktop.checking_updates": "Prüfe auf Updates...",
    "desktop.update_available": (
        "Update verfügbar: {version} (aktuell: {current})."
    ),
    "desktop.update_check_failed": (
        "Update-Prüfung fehlgeschlagen: {reason}"
    ),
    "desktop.up_to_date": (
        "Sie verwenden die neueste Version ({version})."
    ),
    "desktop.downloading_update": (
        "Lade Update {version} herunter ({percent}%)..."
    ),
    "desktop.update_downloaded": (
        "Update heruntergeladen; zum Anwenden von {version} neu starten."
    ),
    "desktop.nightly_channel": (
        "Nightly-Kanal: Builds werden jede Nacht aktualisiert."
    ),

    "desktop.diagnostics": "Diagnose",
    "desktop.diagnostics_title": "Desktop-Diagnose",

    "desktop.diagnostics_ok": "Alle {count} Prüfungen bestanden.",
    "desktop.diagnostics_failed": "{failed} von {count} Prüfungen fehlgeschlagen.",

    "desktop.copy_diagnostics": (
        "Diagnose in die Zwischenablage kopieren?"
    ),
    "desktop.diagnostics_copied": (
        "Diagnose in die Zwischenablage kopiert."
    ),

    "desktop.data_dir": (
        "Desktop-Datenverzeichnis: {path}"
    ),
    "desktop.cache_dir": "Cache-Verzeichnis: {path}",
    "desktop.log_file": "Protokolldatei: {path}",

    # --- report ----------------------------------------------------------------

    "report.title": "Untersuchungsbericht",
    "report.generated": "Erstellt: {date}",
    "report.target": "Ziel: {target} ({kind})",
    "report.footer": (
        "Erstellt von ObscuraLens v{version} am {date}"
    ),
    "report.page": "Seite {page} von {total}",

    "report.sections": "Abschnitte",
    "report.table_of_contents": "Inhaltsverzeichnis",

    "report.executive_summary": "Management-Zusammenfassung",
    "report.findings": "Feststellungen",
    "report.timeline": "Chronologie",
    "report.correlations": "Korrelationen",
    "report.sources_section": "Quellen",
    "report.appendix": "Anhang: Rohdaten der Quellen",

    "report.risk_score": (
        "Risikobewertung: {score}/100 ({label})"
    ),
    "report.confidence": "Konfidenz: {level}",

    "report.no_findings": (
        "Für dieses Ziel sind keine Feststellungen erfasst."
    ),
    "report.field": "Feld",
    "report.value": "Wert",
    "report.source_column": "Quelle",

    "report.disclaimer": (
        "Dieser Bericht wird aus öffentlich verfügbaren Informationen erzeugt "
        "und dient ausschließlich als Referenz für Untersuchungen. Feststellungen "
        "sollten vor einer Maßnahme unabhängig verifiziert werden; die Autoren "
        "haften nicht für Missbrauch."
    ),

    # --- errors ----------------------------------------------------------------

    "errors.network": (
        "Netzwerkfehler beim Kontaktieren von {source}: {reason}"
    ),
    "errors.timeout": (
        "Anfrage an {source} nach {seconds}s abgebrochen (Timeout)."
    ),
    "errors.rate_limited": (
        "Begrenzung durch {source}; erneuter Versuch in {seconds}s."
    ),
    "errors.malformed_response": (
        "Fehlerhafte Antwort von {source}: {reason}"
    ),
    "errors.ssl_error": (
        "SSL-Verifikation für {source} fehlgeschlagen: {reason}"
    ),

    "errors.invalid_input": "Ungültige Eingabe: {reason}",
    "errors.invalid_format": (
        "Nicht unterstütztes Ausgabeformat: „{format}“"
    ),
    "errors.not_found": "Nicht gefunden: {target}",
    "errors.no_sources": (
        "Für die Art „{kind}“ sind keine Quellen konfiguriert."
    ),
    "errors.source_unavailable": (
        "Quelle „{source}“ ist nicht verfügbar."
    ),
    "errors.disabled_source": (
        "Quelle „{source}“ ist in der Konfiguration deaktiviert."
    ),

    "errors.config_missing": (
        "Konfigurationsschlüssel „{key}“ fehlt."
    ),

    "errors.database": "Datenbankfehler: {reason}",
    "errors.permission_denied": "Zugriff verweigert: {path}",
    "errors.disk_full": (
        "Zu wenig Speicherplatz, um {path} zu schreiben."
    ),
    "errors.offline": "Arbeite offline; {source} übersprungen.",
    "errors.interrupted": "Vom Benutzer unterbrochen.",
    "errors.unexpected": (
        "Ein unerwarteter Fehler ist aufgetreten: {reason}"
    ),

    "errors.unknown_language": "Unbekannter Sprachcode: „{code}“",
    "errors.missing_key": "Fehlender Übersetzungsschlüssel: „{key}“",

    # --- plural ----------------------------------------------------------------

    # Pluralfähige Schlüssel für tp(): die Laufzeit wählt anhand der Anzahl
    # .zero, .one oder .many und setzt die Anzahl immer als {count} ein.
    "plural.results.zero": "Keine Ergebnisse",
    "plural.results.one": "{count} Ergebnis",
    "plural.results.many": "{count} Ergebnisse",

    "plural.sources.zero": "Keine Quellen",
    "plural.sources.one": "{count} Quelle",
    "plural.sources.many": "{count} Quellen",

    "plural.findings.zero": "Keine Feststellungen",
    "plural.findings.one": "{count} Feststellung",
    "plural.findings.many": "{count} Feststellungen",

    "plural.matches.zero": "Keine Treffer",
    "plural.matches.one": "{count} Treffer",
    "plural.matches.many": "{count} Treffer",
}

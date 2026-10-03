"""
Dutch locale for ObscuraLens.

Language: Dutch
Native name: Nederlands
Direction: ltr
Locale code: nl
Translators: ObscuraLens contributors

Dit is de Nederlandse vertaalcatalogus: net als elke andere locale onder
``obscuralens/i18n/locales`` definieert deze module exact dezelfde
sleutelverzameling als de Engelse broncatalogus (``en.py``), behoudt alle
``{placeholder}``-tokens letterlijk en vertaalt elke Engelse waarde volledig.
Het voltooiingspercentage dat ``obscuralens.i18n.list_languages`` rapporteert,
wordt berekend op basis van het aantal sleutels van de Engelse module.

Bewerkingsregels:
* één vlakke invoer per catalogusregel in het formaat ``"prefix.sleutel":
  "waarde"``;
* ``{placeholder}``-tokens exact laten staan zoals in het Engelse bestand;
* lange zinnen worden binnen haakjes over meerdere regels verdeeld (impliciete
  aaneenschakeling);
* de ``plural.*``-sleutels worden door ``tp()`` gekozen via de achtervoegsels
  ``.zero`` / ``.one`` / ``.many``; het aantal wordt altijd als ``{count}``
  ingevuld.
"""

STRINGS = {

    # --- app -------------------------------------------------------------------

    "app.title": "ObscuraLens",
    "app.tagline": (
        "Console voor OSINT-onderzoek met meerdere bronnen"
    ),
    "app.version": "Versie {version}",
    "app.channel": "Kanaal: {channel}",

    "app.description": (
        "ObscuraLens bundelt inlichtingen uit tientallen openbare bronnen over "
        "veertien soorten doelwitten, correleert de bevindingen, berekent een "
        "totale risicoscore en genereert deelbare onderzoeksrapporten."
    ),
    "app.copyright": (
        "Copyright (c) {year} de ObscuraLens-bijdragers"
    ),
    "app.license": "Uitgebracht onder de MIT-licentie",
    "app.website": "Projectpagina: {url}",

    "app.edition": "Desktop-editie",
    "app.console_edition": "Console-editie",

    # --- common ----------------------------------------------------------------

    # Knoppen en korte antwoorden.
    "common.ok": "OK",
    "common.cancel": "Annuleren",
    "common.yes": "Ja",
    "common.no": "Nee",
    "common.back": "Terug",
    "common.quit": "Stoppen",
    "common.exit": "Afsluiten",

    # Statuswoorden.
    "common.loading": "Laden...",
    "common.done": "Klaar",
    "common.error": "Fout",
    "common.warning": "Waarschuwing",
    "common.info": "Informatie",
    "common.none": "Geen",
    "common.unknown": "Onbekend",

    # Algemene zelfstandige naamwoorden.
    "common.all": "Alle",
    "common.source": "Bron",
    "common.sources": "Bronnen",
    "common.target": "Doelwit",
    "common.kind": "Soort",
    "common.results": "Resultaten",
    "common.summary": "Samenvatting",
    "common.details": "Details",

    # Navigatie en acties.
    "common.continue": "Doorgaan",
    "common.confirm": "Bevestigen",
    "common.help": "Help",
    "common.settings": "Instellingen",
    "common.language": "Taal",
    "common.about": "Over",

    "common.search": "Zoeken",
    "common.save": "Opslaan",
    "common.export": "Exporteren",
    "common.copy": "Kopiëren",
    "common.retry": "Opnieuw proberen",
    "common.refresh": "Vernieuwen",
    "common.close": "Sluiten",
    "common.open": "Openen",
    "common.select": "Selecteren",
    "common.selected": "Geselecteerd",

    # Tabelkolommen en gegevenskenmerken.
    "common.name": "Naam",
    "common.status": "Status",
    "common.value": "Waarde",
    "common.total": "Totaal",

    "common.average": "Gemiddelde",
    "common.date": "Datum",
    "common.time": "Tijd",
    "common.duration": "Duur",
    "common.count": "Aantal",
    "common.page": "Pagina",
    "common.actions": "Acties",

    "common.filter": "Filteren",
    "common.sort": "Sorteren",

    # Vlaggen en kwalificaties.
    "common.enabled": "Ingeschakeld",
    "common.disabled": "Uitgeschakeld",
    "common.optional": "Optioneel",
    "common.required": "Vereist",
    "common.default": "Standaard",
    "common.overview": "Overzicht",

    # Relatieve tijdsaanduidingen.
    "common.today": "Vandaag",
    "common.yesterday": "Gisteren",
    "common.now": "Nu",

    # Releasekanalen.
    "common.beta": "Beta",
    "common.stable": "Stabiel",
    "common.nightly": "Nightly",

    # --- menu ------------------------------------------------------------------

    "menu.main_title": "ObscuraLens - Hoofdmenu",
    "menu.choose_option": "Kies een optie:",

    "menu.invalid_choice": (
        "Ongeldige keuze '{choice}', probeer het opnieuw."
    ),
    "menu.select_kind": "Selecteer het soort doelwit:",
    "menu.enter_target": "Voer het doelwit in (type: {kind}):",

    "menu.lookup": "Losse opzoeking",
    "menu.investigate": "Volledig onderzoek",
    "menu.watchlist": "Observatielijst",
    "menu.cases": "Zaakbeheer",
    "menu.tools": "Hulpmiddelen",

    "menu.tools_title": "Hulpmiddelen",
    "menu.watchlist_title": "Observatielijst",
    "menu.cases_title": "Zaakbeheer",
    "menu.settings_title": "Instellingen",
    "menu.settings_menu": "Instellingen",

    "menu.language_menu": "Taal wijzigen",
    "menu.language_changed": "Taal gewijzigd naar {language}.",
    "menu.returning_to_main": "Terug naar het hoofdmenu...",

    "menu.exit_prompt": (
        "Weet u zeker dat u wilt afsluiten? (y/N)"
    ),
    "menu.goodbye": "Tot ziens!",

    # --- cli -------------------------------------------------------------------

    "cli.usage_hint": (
        "Gebruik: obscuralens <opdracht> [opties]"
    ),
    "cli.try_help": (
        "Voer 'obscuralens --help' uit voor het gebruik."
    ),
    "cli.unknown_command": "Onbekende opdracht: {command}",
    "cli.target_prompt": "Voer een doelwit in:",
    "cli.detected": "Gedetecteerd soort: {kind}",

    "cli.starting_lookup": "{target} ({kind}) wordt opgezocht...",
    "cli.fetching": "{source} wordt opgehaald...",
    "cli.aggregating": (
        "Resultaten van {count} bronnen worden samengevoegd..."
    ),
    "cli.elapsed": "Verstreken tijd: {seconds}s",
    "cli.risk_score": "Risicoscore: {score}/100",

    "cli.output_format": "Uitvoerindeling: {format}",

    "cli.format_json": "JSON",
    "cli.format_table": "Tabel",
    "cli.format_csv": "CSV",
    "cli.provenance": "Herkomst van velden",
    "cli.field_sources": "Veldbronnen",

    "cli.no_results": (
        "Geen resultaten gevonden voor '{target}'."
    ),
    "cli.lookup_failed": (
        "Opzoeken van '{target}' is mislukt: {reason}"
    ),
    "cli.sources_ok": (
        "{count} bron(nen) hebben succesvol gereageerd."
    ),
    "cli.sources_failed": (
        "{count} bron(nen) hebben niet gereageerd."
    ),

    "cli.showing": "{shown} van {total} resultaten worden weergegeven",
    "cli.sorting_by": "Gesorteerd op {field}",
    "cli.filtering_by": "Gefilterd op {field}",

    "cli.saved_report": "Rapport opgeslagen in {path}",
    "cli.output_saved": "Uitvoer weggeschreven naar {path}",
    "cli.history": "Recente opzoekopdrachten",

    "cli.empty_history": "Geen recente opzoekopdrachten.",
    "cli.confirm_clear_history": "Zoekgeschiedenis wissen? (y/N)",

    # --- kinds -----------------------------------------------------------------

    "kinds.ip": "IP-adres",
    "kinds.phone": "Telefoonnummer",
    "kinds.username": "Gebruikersnaam",

    "kinds.email": "E-mailadres",
    "kinds.domain": "Domeinnaam",
    "kinds.url": "URL",

    "kinds.crypto": "Cryptoadres",
    "kinds.hash": "Bestandshash",

    "kinds.cve": "CVE-identificatie",
    "kinds.asn": "AS-nummer",
    "kinds.mac": "MAC-adres",
    "kinds.iban": "IBAN",
    "kinds.imei": "IMEI",
    "kinds.coords": "Coördinaten",

    "kinds.unknown_kind": "Onbekend soort",
    "kinds.detected_kind": "Gedetecteerd soort: {kind}",
    "kinds.select_hint": "Kies 1-{count} om een soort te selecteren",
    "kinds.kind_list_title": "Ondersteunde soorten doelwitten",

    # --- desktop ---------------------------------------------------------------

    "desktop.title": "ObscuraLens Desktop",
    "desktop.beta_notice": (
        "Dit is een bètaversie van de desktop-editie van ObscuraLens. Sommige "
        "functies zijn nog volop in ontwikkeling en geautomatiseerde "
        "nightly-builds kunnen minder stabiel zijn dan getagde releases."
    ),

    "desktop.starting": "De lokale server wordt gestart...",
    "desktop.listening_on": "Luistert op http://{host}:{port}",
    "desktop.ready": "Gereed.",
    "desktop.launch_hint": "Druk op Ctrl+C om de server te stoppen.",
    "desktop.shutdown": "Afsluiten...",

    "desktop.opening_browser": "De webinterface wordt geopend...",
    "desktop.browser_opened": (
        "{browser} geopend; als deze niet gestart is, ga dan handmatig naar "
        "{url}."
    ),
    "desktop.browser_failed": (
        "Kon geen webbrowser openen: {reason}"
    ),

    "desktop.server_stopped": "Server gestopt.",
    "desktop.port_in_use": (
        "Poort {port} is al in gebruik; {alternative} wordt geprobeerd."
    ),
    "desktop.single_instance": (
        "ObscuraLens draait al; het bestaande venster wordt geactiveerd."
    ),

    "desktop.checking_updates": "Controleren op updates...",
    "desktop.update_available": (
        "Update beschikbaar: {version} (huidige: {current})."
    ),
    "desktop.update_check_failed": (
        "Updatecontrole mislukt: {reason}"
    ),
    "desktop.up_to_date": (
        "U gebruikt de nieuwste versie ({version})."
    ),
    "desktop.downloading_update": (
        "Update {version} wordt gedownload ({percent}%)..."
    ),
    "desktop.update_downloaded": (
        "Update gedownload; herstart om {version} toe te passen."
    ),
    "desktop.nightly_channel": (
        "Nightly-kanaal: builds worden elke nacht ververst."
    ),

    "desktop.diagnostics": "Diagnostiek",
    "desktop.diagnostics_title": "Desktop-diagnostiek",

    "desktop.diagnostics_ok": "Alle {count} controles geslaagd.",
    "desktop.diagnostics_failed": "{failed} van {count} controles mislukt.",

    "desktop.copy_diagnostics": (
        "Diagnostiek naar het klembord kopiëren?"
    ),
    "desktop.diagnostics_copied": (
        "Diagnostiek naar het klembord gekopieerd."
    ),

    "desktop.data_dir": (
        "Gegevensmap van de desktop-editie: {path}"
    ),
    "desktop.cache_dir": "Cachemap: {path}",
    "desktop.log_file": "Logbestand: {path}",

    # --- report ----------------------------------------------------------------

    "report.title": "Onderzoeksrapport",
    "report.generated": "Gegenereerd: {date}",
    "report.target": "Doelwit: {target} ({kind})",
    "report.footer": (
        "Gegenereerd door ObscuraLens v{version} op {date}"
    ),
    "report.page": "Pagina {page} van {total}",

    "report.sections": "Secties",
    "report.table_of_contents": "Inhoudsopgave",

    "report.executive_summary": "Managementsamenvatting",
    "report.findings": "Bevindingen",
    "report.timeline": "Tijdlijn",
    "report.correlations": "Correlaties",
    "report.sources_section": "Bronnen",
    "report.appendix": "Bijlage: ruwe brongegevens",

    "report.risk_score": (
        "Risicoscore: {score}/100 ({label})"
    ),
    "report.confidence": "Zekerheid: {level}",

    "report.no_findings": (
        "Er zijn geen bevindingen vastgelegd voor dit doelwit."
    ),
    "report.field": "Veld",
    "report.value": "Waarde",
    "report.source_column": "Bron",

    "report.disclaimer": (
        "Dit rapport is samengesteld uit publiek beschikbare informatie en "
        "dient uitsluitend als naslagwerk bij onderzoeken. Bevindingen moeten "
        "onafhankelijk worden geverifieerd voordat er naar wordt gehandeld; de "
        "auteurs aanvaarden geen aansprakelijkheid voor misbruik."
    ),

    # --- errors ----------------------------------------------------------------

    "errors.network": (
        "Netwerkfout bij het benaderen van {source}: {reason}"
    ),
    "errors.timeout": (
        "Verzoek aan {source} is na {seconds}s verlopen."
    ),
    "errors.rate_limited": (
        "Snelheidslimiet bereikt bij {source}; nieuwe poging over {seconds}s."
    ),
    "errors.malformed_response": (
        "Onjuist opgebouwd antwoord van {source}: {reason}"
    ),
    "errors.ssl_error": (
        "SSL-verificatie voor {source} mislukt: {reason}"
    ),

    "errors.invalid_input": "Ongeldige invoer: {reason}",
    "errors.invalid_format": (
        "Niet-ondersteunde uitvoerindeling: '{format}'"
    ),
    "errors.not_found": "Niet gevonden: {target}",
    "errors.no_sources": (
        "Er zijn geen bronnen geconfigureerd voor soort '{kind}'."
    ),
    "errors.source_unavailable": (
        "Bron '{source}' is niet beschikbaar."
    ),
    "errors.disabled_source": (
        "Bron '{source}' staat uitgeschakeld in de configuratie."
    ),

    "errors.config_missing": (
        "Configuratiesleutel '{key}' ontbreekt."
    ),

    "errors.database": "Databasefout: {reason}",
    "errors.permission_denied": "Toegang geweigerd: {path}",
    "errors.disk_full": (
        "Onvoldoende schijfruimte om {path} te schrijven."
    ),
    "errors.offline": "Werkt offline; {source} overgeslagen.",
    "errors.interrupted": "Onderbroken door de gebruiker.",
    "errors.unexpected": (
        "Er is een onverwachte fout opgetreden: {reason}"
    ),

    "errors.unknown_language": "Onbekende taalcode: '{code}'",
    "errors.missing_key": "Ontbrekende vertaalsleutel: '{key}'",

    # --- plural ----------------------------------------------------------------

    # Meervoudsgevoelige sleutels voor tp(): de runtime kiest .zero, .one of
    # .many op basis van het aantal en vult het aantal altijd in als {count}.
    "plural.results.zero": "Geen resultaten",
    "plural.results.one": "{count} resultaat",
    "plural.results.many": "{count} resultaten",

    "plural.sources.zero": "Geen bronnen",
    "plural.sources.one": "{count} bron",
    "plural.sources.many": "{count} bronnen",

    "plural.findings.zero": "Geen bevindingen",
    "plural.findings.one": "{count} bevinding",
    "plural.findings.many": "{count} bevindingen",

    "plural.matches.zero": "Geen overeenkomsten",
    "plural.matches.one": "{count} overeenkomst",
    "plural.matches.many": "{count} overeenkomsten",
}

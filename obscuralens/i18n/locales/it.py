"""
Italian locale for ObscuraLens.

Language: Italian
Native name: Italiano
Direction: ltr
Locale code: it
Translators: ObscuraLens contributors

Questo è il catalogo italiano: come ogni altro locale in
``obscuralens/i18n/locales`` definisce esattamente lo stesso insieme di chiavi
del catalogo sorgente inglese (``en.py``), conserva letteralmente tutti i token
``{placeholder}`` e traduce integralmente ogni valore inglese. La percentuale
di completamento riportata da ``obscuralens.i18n.list_languages`` è calcolata
rispetto al numero di chiavi del modulo inglese.

Regole di modifica:
* una voce piatta per riga nel formato ``"prefisso.chiave": "valore"``;
* mantenere i token ``{placeholder}`` esattamente come nel file inglese;
* le frasi lunghe vengono spezzate dentro parentesi (concatenazione implicita);
* le chiavi ``plural.*`` vengono scelte da ``tp()`` tramite i suffissi ``.zero``
  / ``.one`` / ``.many`` e il conteggio viene sempre interpolato come
  ``{count}``.
"""

STRINGS = {

    # --- app -------------------------------------------------------------------

    "app.title": "ObscuraLens",
    "app.tagline": (
        "Console di investigazione OSINT multi-fonte"
    ),
    "app.version": "Versione {version}",
    "app.channel": "Canale: {channel}",

    "app.description": (
        "ObscuraLens aggrega informazioni da decine di fonti pubbliche su "
        "quattordici tipi di obiettivo, correla i risultati, assegna un "
        "punteggio al rischio complessivo e genera report di investigazione "
        "condivisibili."
    ),
    "app.copyright": (
        "Copyright (c) {year} i contributori di ObscuraLens"
    ),
    "app.license": "Rilasciato sotto la licenza MIT",
    "app.website": "Sito del progetto: {url}",

    "app.edition": "Edizione desktop",
    "app.console_edition": "Edizione console",

    # --- common ----------------------------------------------------------------

    # Pulsanti e risposte brevi.
    "common.ok": "OK",
    "common.cancel": "Annulla",
    "common.yes": "Sì",
    "common.no": "No",
    "common.back": "Indietro",
    "common.quit": "Esci",
    "common.exit": "Termina",

    # Parole di stato.
    "common.loading": "Caricamento...",
    "common.done": "Fatto",
    "common.error": "Errore",
    "common.warning": "Avviso",
    "common.info": "Informazione",
    "common.none": "Nessuno",
    "common.unknown": "Sconosciuto",

    # Sostantivi generici.
    "common.all": "Tutti",
    "common.source": "Fonte",
    "common.sources": "Fonti",
    "common.target": "Obiettivo",
    "common.kind": "Tipo",
    "common.results": "Risultati",
    "common.summary": "Riepilogo",
    "common.details": "Dettagli",

    # Navigazione e azioni.
    "common.continue": "Continua",
    "common.confirm": "Conferma",
    "common.help": "Aiuto",
    "common.settings": "Impostazioni",
    "common.language": "Lingua",
    "common.about": "Informazioni",

    "common.search": "Cerca",
    "common.save": "Salva",
    "common.export": "Esporta",
    "common.copy": "Copia",
    "common.retry": "Riprova",
    "common.refresh": "Aggiorna",
    "common.close": "Chiudi",
    "common.open": "Apri",
    "common.select": "Seleziona",
    "common.selected": "Selezionato",

    # Colonne delle tabelle e attributi dei dati.
    "common.name": "Nome",
    "common.status": "Stato",
    "common.value": "Valore",
    "common.total": "Totale",

    "common.average": "Media",
    "common.date": "Data",
    "common.time": "Ora",
    "common.duration": "Durata",
    "common.count": "Conteggio",
    "common.page": "Pagina",
    "common.actions": "Azioni",

    "common.filter": "Filtra",
    "common.sort": "Ordina",

    # Indicatori e qualificatori.
    "common.enabled": "Attivato",
    "common.disabled": "Disattivato",
    "common.optional": "Opzionale",
    "common.required": "Obbligatorio",
    "common.default": "Predefinito",
    "common.overview": "Panoramica",

    # Parole di tempo relativo.
    "common.today": "Oggi",
    "common.yesterday": "Ieri",
    "common.now": "Adesso",

    # Canali di rilascio.
    "common.beta": "Beta",
    "common.stable": "Stabile",
    "common.nightly": "Nightly",

    # --- menu ------------------------------------------------------------------

    "menu.main_title": "ObscuraLens - Menu principale",
    "menu.choose_option": "Scegli un'opzione:",

    "menu.invalid_choice": (
        "Scelta '{choice}' non valida, riprova."
    ),
    "menu.select_kind": "Seleziona il tipo di obiettivo:",
    "menu.enter_target": "Inserisci l'obiettivo di tipo {kind} da cercare:",

    "menu.lookup": "Ricerca singola",
    "menu.investigate": "Investigazione completa",
    "menu.watchlist": "Lista di osservazione",
    "menu.cases": "Gestore dei casi",
    "menu.tools": "Strumenti",

    "menu.tools_title": "Strumenti",
    "menu.watchlist_title": "Lista di osservazione",
    "menu.cases_title": "Gestore dei casi",
    "menu.settings_title": "Impostazioni",
    "menu.settings_menu": "Impostazioni",

    "menu.language_menu": "Cambia lingua",
    "menu.language_changed": "Lingua impostata su {language}.",
    "menu.returning_to_main": "Ritorno al menu principale...",

    "menu.exit_prompt": (
        "Vuoi davvero uscire? (y/N)"
    ),
    "menu.goodbye": "Arrivederci!",

    # --- cli -------------------------------------------------------------------

    "cli.usage_hint": (
        "Uso: obscuralens <comando> [opzioni]"
    ),
    "cli.try_help": (
        "Esegui 'obscuralens --help' per l'utilizzo."
    ),
    "cli.unknown_command": "Comando sconosciuto: {command}",
    "cli.target_prompt": "Inserisci un obiettivo:",
    "cli.detected": "Tipo rilevato: {kind}",

    "cli.starting_lookup": "Ricerca di {target} ({kind}) in corso...",
    "cli.fetching": "Recupero di {source}...",
    "cli.aggregating": (
        "Aggregazione dei risultati da {count} fonti..."
    ),
    "cli.elapsed": "Tempo trascorso: {seconds}s",
    "cli.risk_score": "Punteggio di rischio: {score}/100",

    "cli.output_format": "Formato di output: {format}",

    "cli.format_json": "JSON",
    "cli.format_table": "Tabella",
    "cli.format_csv": "CSV",
    "cli.provenance": "Provenienza dei campi",
    "cli.field_sources": "Fonti dei campi",

    "cli.no_results": (
        "Nessun risultato trovato per '{target}'."
    ),
    "cli.lookup_failed": (
        "Ricerca non riuscita per '{target}': {reason}"
    ),
    "cli.sources_ok": (
        "{count} fonte/i hanno risposto correttamente."
    ),
    "cli.sources_failed": (
        "{count} fonte/i non hanno risposto."
    ),

    "cli.showing": "Visualizzazione di {shown} risultati su {total}",
    "cli.sorting_by": "Ordinato per {field}",
    "cli.filtering_by": "Filtrato per {field}",

    "cli.saved_report": "Report salvato in {path}",
    "cli.output_saved": "Output scritto in {path}",
    "cli.history": "Ricerche recenti",

    "cli.empty_history": "Nessuna ricerca recente.",
    "cli.confirm_clear_history": "Cancellare la cronologia delle ricerche? (y/N)",

    # --- kinds -----------------------------------------------------------------

    "kinds.ip": "Indirizzo IP",
    "kinds.phone": "Numero di telefono",
    "kinds.username": "Nome utente",

    "kinds.email": "Indirizzo e-mail",
    "kinds.domain": "Dominio",
    "kinds.url": "URL",

    "kinds.crypto": "Indirizzo crypto",
    "kinds.hash": "Hash del file",

    "kinds.cve": "Identificativo CVE",
    "kinds.asn": "Numero AS",
    "kinds.mac": "Indirizzo MAC",
    "kinds.iban": "IBAN",
    "kinds.imei": "IMEI",
    "kinds.coords": "Coordinate",

    "kinds.unknown_kind": "Tipo sconosciuto",
    "kinds.detected_kind": "Tipo rilevato: {kind}",
    "kinds.select_hint": "Scegli 1-{count} per selezionare un tipo",
    "kinds.kind_list_title": "Tipi di obiettivo supportati",

    # --- desktop ---------------------------------------------------------------

    "desktop.title": "ObscuraLens Desktop",
    "desktop.beta_notice": (
        "Questa è una build beta dell'edizione desktop di ObscuraLens. Alcune "
        "funzionalità sono ancora in evoluzione e le build notturne automatiche "
        "possono essere meno stabili dei rilasci con tag."
    ),

    "desktop.starting": "Avvio del server locale...",
    "desktop.listening_on": "In ascolto su http://{host}:{port}",
    "desktop.ready": "Pronto.",
    "desktop.launch_hint": "Premi Ctrl+C per arrestare il server.",
    "desktop.shutdown": "Arresto in corso...",

    "desktop.opening_browser": "Apertura dell'interfaccia web...",
    "desktop.browser_opened": (
        "{browser} aperto; se non si è avviato, visita manualmente {url}."
    ),
    "desktop.browser_failed": (
        "Impossibile aprire un browser web: {reason}"
    ),

    "desktop.server_stopped": "Server arrestato.",
    "desktop.port_in_use": (
        "La porta {port} è già in uso; provo con {alternative}."
    ),
    "desktop.single_instance": (
        "ObscuraLens è già in esecuzione; attivo la finestra esistente."
    ),

    "desktop.checking_updates": "Verifica degli aggiornamenti...",
    "desktop.update_available": (
        "Aggiornamento disponibile: {version} (attuale: {current})."
    ),
    "desktop.update_check_failed": (
        "Verifica degli aggiornamenti non riuscita: {reason}"
    ),
    "desktop.up_to_date": (
        "Stai usando la versione più recente ({version})."
    ),
    "desktop.downloading_update": (
        "Download dell'aggiornamento {version} ({percent}%)..."
    ),
    "desktop.update_downloaded": (
        "Aggiornamento scaricato; riavvia per applicare {version}."
    ),
    "desktop.nightly_channel": (
        "Canale nightly: le build vengono aggiornate ogni notte."
    ),

    "desktop.diagnostics": "Diagnostica",
    "desktop.diagnostics_title": "Diagnostica del desktop",

    "desktop.diagnostics_ok": "Tutti i {count} controlli superati.",
    "desktop.diagnostics_failed": "{failed} controlli su {count} non superati.",

    "desktop.copy_diagnostics": (
        "Copiare la diagnostica negli appunti?"
    ),
    "desktop.diagnostics_copied": (
        "Diagnostica copiata negli appunti."
    ),

    "desktop.data_dir": (
        "Directory dati del desktop: {path}"
    ),
    "desktop.cache_dir": "Directory della cache: {path}",
    "desktop.log_file": "File di log: {path}",

    # --- report ----------------------------------------------------------------

    "report.title": "Report di investigazione",
    "report.generated": "Generato: {date}",
    "report.target": "Obiettivo: {target} ({kind})",
    "report.footer": (
        "Generato da ObscuraLens v{version} il {date}"
    ),
    "report.page": "Pagina {page} di {total}",

    "report.sections": "Sezioni",
    "report.table_of_contents": "Indice",

    "report.executive_summary": "Sintesi esecutiva",
    "report.findings": "Riscontri",
    "report.timeline": "Cronologia",
    "report.correlations": "Correlazioni",
    "report.sources_section": "Fonti",
    "report.appendix": "Appendice: dati grezzi delle fonti",

    "report.risk_score": (
        "Punteggio di rischio: {score}/100 ({label})"
    ),
    "report.confidence": "Confidenza: {level}",

    "report.no_findings": (
        "Nessun riscontro registrato per questo obiettivo."
    ),
    "report.field": "Campo",
    "report.value": "Valore",
    "report.source_column": "Fonte",

    "report.disclaimer": (
        "Questo report è generato a partire da informazioni pubblicamente "
        "disponibili e ha solo valore di riferimento per le investigazioni. I "
        "riscontri dovrebbero essere verificati in modo indipendente prima di "
        "agire; gli autori non si assumono alcuna responsabilità per un uso "
        "improprio."
    ),

    # --- errors ----------------------------------------------------------------

    "errors.network": (
        "Errore di rete durante il contatto con {source}: {reason}"
    ),
    "errors.timeout": (
        "La richiesta a {source} è scaduta dopo {seconds}s."
    ),
    "errors.rate_limited": (
        "Limite di richieste imposto da {source}; nuovo tentativo tra {seconds}s."
    ),
    "errors.malformed_response": (
        "Risposta non valida da {source}: {reason}"
    ),
    "errors.ssl_error": (
        "Verifica SSL non riuscita per {source}: {reason}"
    ),

    "errors.invalid_input": "Input non valido: {reason}",
    "errors.invalid_format": (
        "Formato di output non supportato: '{format}'"
    ),
    "errors.not_found": "Non trovato: {target}",
    "errors.no_sources": (
        "Nessuna fonte configurata per il tipo '{kind}'."
    ),
    "errors.source_unavailable": (
        "La fonte '{source}' non è disponibile."
    ),
    "errors.disabled_source": (
        "La fonte '{source}' è disattivata nella configurazione."
    ),

    "errors.config_missing": (
        "La chiave di configurazione '{key}' è mancante."
    ),

    "errors.database": "Errore del database: {reason}",
    "errors.permission_denied": "Permesso negato: {path}",
    "errors.disk_full": (
        "Spazio su disco insufficiente per scrivere {path}."
    ),
    "errors.offline": "Modalità offline; {source} saltata.",
    "errors.interrupted": "Interrotto dall'utente.",
    "errors.unexpected": (
        "Si è verificato un errore imprevisto: {reason}"
    ),

    "errors.unknown_language": "Codice lingua sconosciuto: '{code}'",
    "errors.missing_key": "Chiave di traduzione mancante: '{key}'",

    # --- plural ----------------------------------------------------------------

    # Chiavi plurali usate da tp(): il runtime sceglie .zero, .one o .many in
    # base al conteggio e interpola sempre {count} nel risultato.
    "plural.results.zero": "Nessun risultato",
    "plural.results.one": "{count} risultato",
    "plural.results.many": "{count} risultati",

    "plural.sources.zero": "Nessuna fonte",
    "plural.sources.one": "{count} fonte",
    "plural.sources.many": "{count} fonti",

    "plural.findings.zero": "Nessun riscontro",
    "plural.findings.one": "{count} riscontro",
    "plural.findings.many": "{count} riscontri",

    "plural.matches.zero": "Nessuna corrispondenza",
    "plural.matches.one": "{count} corrispondenza",
    "plural.matches.many": "{count} corrispondenze",
}

"""
Polish locale for ObscuraLens.

Language: Polish
Native name: Polski
Direction: ltr
Locale code: pl
Translators: ObscuraLens contributors

To jest polski katalog tłumaczeń: podobnie jak każdy inny moduł w katalogu
``obscuralens/i18n/locales`` definiuje dokładnie ten sam zestaw kluczy co
angielski katalog źródłowy (``en.py``), zachowuje wszystkie tokeny
``{placeholder}`` dosłownie i tłumaczy każdą angielską wartość w całości.
Procent kompletności raportowany przez ``obscuralens.i18n.list_languages``
jest wyliczany na podstawie liczby kluczy modułu angielskiego.

Zasady edycji:
* jeden płaski wpis na wiersz katalogu w formacie ``"prefiks.klucz": "wartość"``;
* tokeny ``{placeholder}`` zachowuj dokładnie tak, jak w pliku angielskim;
* długie zdania są łamane wewnątrz nawiasów (niejawna konkatenacja);
* klucze ``plural.*`` wybiera funkcja ``tp()`` na podstawie sufiksów ``.zero``
  / ``.one`` / ``.many``, a liczba jest zawsze wstawiana jako ``{count}``.
"""

STRINGS = {

    # --- app -------------------------------------------------------------------

    "app.title": "ObscuraLens",
    "app.tagline": (
        "Konsola do wieloźródłowych analiz OSINT"
    ),
    "app.version": "Wersja {version}",
    "app.channel": "Kanał: {channel}",

    "app.description": (
        "ObscuraLens agreguje dane z dziesiątek publicznych źródeł dla "
        "czternastu rodzajów celów, ustala korelacje między ustaleniami, "
        "ocenia łączne ryzyko i generuje raporty śledcze gotowe do "
        "udostępnienia."
    ),
    "app.copyright": (
        "Copyright (c) {year} współtwórcy ObscuraLens"
    ),
    "app.license": "Wydano na licencji MIT",
    "app.website": "Strona projektu: {url}",

    "app.edition": "Edycja desktopowa",
    "app.console_edition": "Edycja konsolowa",

    # --- common ----------------------------------------------------------------

    # Przyciski i krótkie odpowiedzi.
    "common.ok": "OK",
    "common.cancel": "Anuluj",
    "common.yes": "Tak",
    "common.no": "Nie",
    "common.back": "Wstecz",
    "common.quit": "Zakończ",
    "common.exit": "Wyjdź",

    # Słowa stanu.
    "common.loading": "Wczytywanie...",
    "common.done": "Gotowe",
    "common.error": "Błąd",
    "common.warning": "Ostrzeżenie",
    "common.info": "Informacja",
    "common.none": "Brak",
    "common.unknown": "Nieznany",

    # Rzeczowniki ogólne.
    "common.all": "Wszystkie",
    "common.source": "Źródło",
    "common.sources": "Źródła",
    "common.target": "Cel",
    "common.kind": "Rodzaj",
    "common.results": "Wyniki",
    "common.summary": "Podsumowanie",
    "common.details": "Szczegóły",

    # Nawigacja i akcje.
    "common.continue": "Kontynuuj",
    "common.confirm": "Potwierdź",
    "common.help": "Pomoc",
    "common.settings": "Ustawienia",
    "common.language": "Język",
    "common.about": "O programie",

    "common.search": "Szukaj",
    "common.save": "Zapisz",
    "common.export": "Eksportuj",
    "common.copy": "Kopiuj",
    "common.retry": "Ponów",
    "common.refresh": "Odśwież",
    "common.close": "Zamknij",
    "common.open": "Otwórz",
    "common.select": "Wybierz",
    "common.selected": "Wybrane",

    # Kolumny tabel i atrybuty danych.
    "common.name": "Nazwa",
    "common.status": "Status",
    "common.value": "Wartość",
    "common.total": "Razem",

    "common.average": "Średnia",
    "common.date": "Data",
    "common.time": "Czas",
    "common.duration": "Czas trwania",
    "common.count": "Liczba",
    "common.page": "Strona",
    "common.actions": "Akcje",

    "common.filter": "Filtruj",
    "common.sort": "Sortuj",

    # Flagi i kwalifikatory.
    "common.enabled": "Włączone",
    "common.disabled": "Wyłączone",
    "common.optional": "Opcjonalne",
    "common.required": "Wymagane",
    "common.default": "Domyślne",
    "common.overview": "Przegląd",

    # Słowa czasu względnego.
    "common.today": "Dzisiaj",
    "common.yesterday": "Wczoraj",
    "common.now": "Teraz",

    # Kanały wydawnicze.
    "common.beta": "Beta",
    "common.stable": "Stabilna",
    "common.nightly": "Nightly",

    # --- menu ------------------------------------------------------------------

    "menu.main_title": "ObscuraLens - Menu główne",
    "menu.choose_option": "Wybierz opcję:",

    "menu.invalid_choice": (
        "Nieprawidłowy wybór '{choice}', spróbuj ponownie."
    ),
    "menu.select_kind": "Wybierz rodzaj celu:",
    "menu.enter_target": "Podaj {kind} do wyszukania:",

    "menu.lookup": "Pojedyncze zapytanie",
    "menu.investigate": "Pełne śledztwo",
    "menu.watchlist": "Lista obserwowanych",
    "menu.cases": "Menedżer spraw",
    "menu.tools": "Narzędzia",

    "menu.tools_title": "Narzędzia",
    "menu.watchlist_title": "Lista obserwowanych",
    "menu.cases_title": "Menedżer spraw",
    "menu.settings_title": "Ustawienia",
    "menu.settings_menu": "Ustawienia",

    "menu.language_menu": "Zmień język",
    "menu.language_changed": "Język zmieniono na {language}.",
    "menu.returning_to_main": "Powrót do menu głównego...",

    "menu.exit_prompt": (
        "Na pewno chcesz wyjść? (y/N)"
    ),
    "menu.goodbye": "Do zobaczenia!",

    # --- cli -------------------------------------------------------------------

    "cli.usage_hint": (
        "Użycie: obscuralens <polecenie> [opcje]"
    ),
    "cli.try_help": (
        "Uruchom 'obscuralens --help', aby poznać sposób użycia."
    ),
    "cli.unknown_command": "Nieznane polecenie: {command}",
    "cli.target_prompt": "Podaj cel:",
    "cli.detected": "Wykryty rodzaj: {kind}",

    "cli.starting_lookup": "Wyszukiwanie {target} ({kind})...",
    "cli.fetching": "Pobieranie danych z {source}...",
    "cli.aggregating": (
        "Agregacja wyników z {count} źródeł..."
    ),
    "cli.elapsed": "Czas trwania: {seconds}s",
    "cli.risk_score": "Ocena ryzyka: {score}/100",

    "cli.output_format": "Format wyjściowy: {format}",

    "cli.format_json": "JSON",
    "cli.format_table": "Tabela",
    "cli.format_csv": "CSV",
    "cli.provenance": "Pochodzenie pól",
    "cli.field_sources": "Źródła pól",

    "cli.no_results": (
        "Nie znaleziono wyników dla '{target}'."
    ),
    "cli.lookup_failed": (
        "Wyszukiwanie '{target}' nie powiodło się: {reason}"
    ),
    "cli.sources_ok": (
        "Liczba źródeł, które odpowiedziały pomyślnie: {count}."
    ),
    "cli.sources_failed": (
        "Liczba źródeł, które nie odpowiedziały: {count}."
    ),

    "cli.showing": "Wyświetlanie {shown} z {total} wyników",
    "cli.sorting_by": "Posortowano według {field}",
    "cli.filtering_by": "Odfiltrowano według {field}",

    "cli.saved_report": "Raport zapisano w {path}",
    "cli.output_saved": "Wynik zapisano do {path}",
    "cli.history": "Ostatnie zapytania",

    "cli.empty_history": "Brak ostatnich zapytań.",
    "cli.confirm_clear_history": "Wyczyścić historię zapytań? (y/N)",

    # --- kinds -----------------------------------------------------------------

    "kinds.ip": "Adres IP",
    "kinds.phone": "Numer telefonu",
    "kinds.username": "Nazwa użytkownika",

    "kinds.email": "Adres e-mail",
    "kinds.domain": "Domena",
    "kinds.url": "URL",

    "kinds.crypto": "Adres krypto",
    "kinds.hash": "Skrót pliku",

    "kinds.cve": "Identyfikator CVE",
    "kinds.asn": "Numer AS",
    "kinds.mac": "Adres MAC",
    "kinds.iban": "IBAN",
    "kinds.imei": "IMEI",
    "kinds.coords": "Współrzędne",

    "kinds.unknown_kind": "Nieznany rodzaj",
    "kinds.detected_kind": "Wykryty rodzaj: {kind}",
    "kinds.select_hint": "Wybierz 1-{count}, aby wybrać rodzaj",
    "kinds.kind_list_title": "Obsługiwane rodzaje celów",

    # --- desktop ---------------------------------------------------------------

    "desktop.title": "ObscuraLens Desktop",
    "desktop.beta_notice": (
        "To jest wersja beta edycji desktopowej ObscuraLens. Część funkcji "
        "jest jeszcze w rozwoju, a automatyczne nocne kompilacje mogą być "
        "mniej stabilne niż oznaczone wydania."
    ),

    "desktop.starting": "Uruchamianie lokalnego serwera...",
    "desktop.listening_on": "Nasłuchiwanie na http://{host}:{port}",
    "desktop.ready": "Gotowe.",
    "desktop.launch_hint": "Naciśnij Ctrl+C, aby zatrzymać serwer.",
    "desktop.shutdown": "Zamykanie...",

    "desktop.opening_browser": "Otwieranie interfejsu WWW...",
    "desktop.browser_opened": (
        "Otwarto {browser}; jeśli się nie uruchomił, przejdź ręcznie pod "
        "adres {url}."
    ),
    "desktop.browser_failed": (
        "Nie udało się otworzyć przeglądarki: {reason}"
    ),

    "desktop.server_stopped": "Serwer zatrzymany.",
    "desktop.port_in_use": (
        "Port {port} jest już zajęty; próba użycia {alternative}."
    ),
    "desktop.single_instance": (
        "ObscuraLens jest już uruchomiony; aktywowanie istniejącego okna."
    ),

    "desktop.checking_updates": "Sprawdzanie aktualizacji...",
    "desktop.update_available": (
        "Dostępna aktualizacja: {version} (bieżąca: {current})."
    ),
    "desktop.update_check_failed": (
        "Sprawdzenie aktualizacji nie powiodło się: {reason}"
    ),
    "desktop.up_to_date": (
        "Korzystasz z najnowszej wersji ({version})."
    ),
    "desktop.downloading_update": (
        "Pobieranie aktualizacji {version} ({percent}%)..."
    ),
    "desktop.update_downloaded": (
        "Aktualizacja pobrana; uruchom ponownie, aby zastosować {version}."
    ),
    "desktop.nightly_channel": (
        "Kanał nightly: kompilacje są odświeżane każdej nocy."
    ),

    "desktop.diagnostics": "Diagnostyka",
    "desktop.diagnostics_title": "Diagnostyka wersji desktopowej",

    "desktop.diagnostics_ok": "Wszystkie sprawdzenia ({count}) zakończyły się powodzeniem.",
    "desktop.diagnostics_failed": "{failed} z {count} sprawdzeń zakończyło się niepowodzeniem.",

    "desktop.copy_diagnostics": (
        "Skopiować diagnostykę do schowka?"
    ),
    "desktop.diagnostics_copied": (
        "Diagnostyka została skopiowana do schowka."
    ),

    "desktop.data_dir": (
        "Katalog danych wersji desktopowej: {path}"
    ),
    "desktop.cache_dir": "Katalog pamięci podręcznej: {path}",
    "desktop.log_file": "Plik dziennika: {path}",

    # --- report ----------------------------------------------------------------

    "report.title": "Raport ze śledztwa",
    "report.generated": "Wygenerowano: {date}",
    "report.target": "Cel: {target} ({kind})",
    "report.footer": (
        "Wygenerowano przez ObscuraLens v{version} dnia {date}"
    ),
    "report.page": "Strona {page} z {total}",

    "report.sections": "Sekcje",
    "report.table_of_contents": "Spis treści",

    "report.executive_summary": "Streszczenie dla kierownictwa",
    "report.findings": "Ustalenia",
    "report.timeline": "Oś czasu",
    "report.correlations": "Korelacje",
    "report.sources_section": "Źródła",
    "report.appendix": "Dodatek: surowe dane źródłowe",

    "report.risk_score": (
        "Ocena ryzyka: {score}/100 ({label})"
    ),
    "report.confidence": "Pewność: {level}",

    "report.no_findings": (
        "Brak zarejestrowanych ustaleń dla tego celu."
    ),
    "report.field": "Pole",
    "report.value": "Wartość",
    "report.source_column": "Źródło",

    "report.disclaimer": (
        "Niniejszy raport został wygenerowany na podstawie publicznie "
        "dostępnych informacji i służy wyłącznie jako materiał pomocniczy dla "
        "śledztw. Ustalenia należy niezależnie zweryfikować przed podjęciem "
        "jakichkolwiek działań; autorzy nie ponoszą odpowiedzialności za "
        "nadużycia."
    ),

    # --- errors ----------------------------------------------------------------

    "errors.network": (
        "Błąd sieci podczas łączenia z {source}: {reason}"
    ),
    "errors.timeout": (
        "Limit czasu żądania do {source} przekroczony po {seconds}s."
    ),
    "errors.rate_limited": (
        "Ograniczenie częstotliwości żądań od {source}; ponowna próba za {seconds}s."
    ),
    "errors.malformed_response": (
        "Wadliwa odpowiedź od {source}: {reason}"
    ),
    "errors.ssl_error": (
        "Weryfikacja SSL dla {source} nie powiodła się: {reason}"
    ),

    "errors.invalid_input": "Nieprawidłowe dane wejściowe: {reason}",
    "errors.invalid_format": (
        "Nieobsługiwany format wyjściowy: '{format}'"
    ),
    "errors.not_found": "Nie znaleziono: {target}",
    "errors.no_sources": (
        "Brak skonfigurowanych źródeł dla rodzaju '{kind}'."
    ),
    "errors.source_unavailable": (
        "Źródło '{source}' jest niedostępne."
    ),
    "errors.disabled_source": (
        "Źródło '{source}' jest wyłączone w konfiguracji."
    ),

    "errors.config_missing": (
        "Brak klucza konfiguracji '{key}'."
    ),

    "errors.database": "Błąd bazy danych: {reason}",
    "errors.permission_denied": "Odmowa dostępu: {path}",
    "errors.disk_full": (
        "Za mało miejsca na dysku, aby zapisać {path}."
    ),
    "errors.offline": "Praca w trybie offline; pominięto {source}.",
    "errors.interrupted": "Przerwane przez użytkownika.",
    "errors.unexpected": (
        "Wystąpił nieoczekiwany błąd: {reason}"
    ),

    "errors.unknown_language": "Nieznany kod języka: '{code}'",
    "errors.missing_key": "Brakujący klucz tłumaczenia: '{key}'",

    # --- plural ----------------------------------------------------------------

    # Klucze z obsługą liczby mnogiej dla tp(): środowisko wykonawcze wybiera
    # .zero, .one lub .many w zależności od liczby i zawsze wstawia ją jako
    # {count}.
    "plural.results.zero": "Brak wyników",
    "plural.results.one": "{count} wynik",
    "plural.results.many": "{count} wyników",

    "plural.sources.zero": "Brak źródeł",
    "plural.sources.one": "{count} źródło",
    "plural.sources.many": "{count} źródeł",

    "plural.findings.zero": "Brak ustaleń",
    "plural.findings.one": "{count} ustalenie",
    "plural.findings.many": "{count} ustaleń",

    "plural.matches.zero": "Brak dopasowań",
    "plural.matches.one": "{count} dopasowanie",
    "plural.matches.many": "{count} dopasowań",
}

"""
Russian locale for ObscuraLens.

Language: Russian
Native name: Русский
Direction: ltr
Locale code: ru
Translators: ObscuraLens contributors

Это русская локаль: как и все прочие локали в ``obscuralens/i18n/locales``,
она задаёт точно то же множество ключей, что и исходный английский каталог
(``en.py``), дословно сохраняет токены ``{placeholder}`` и полностью
переводит каждое английское значение. Процент завершённости, который
сообщает ``obscuralens.i18n.list_languages``, вычисляется по количеству
ключей английского модуля.

Правила редактирования:
* одна плоская запись на строку в формате ``"префикс.ключ": "значение"``;
* токены ``{placeholder}`` сохраняются в точности как в английском файле;
* длинные предложения переносятся внутри скобок (неявная конкатенация);
* ключи ``plural.*`` выбираются функцией ``tp()`` по суффиксам ``.zero`` /
  ``.one`` / ``.many``; поскольку упрощённая трёхчастная модель множественного
  числа не различает формы 2-4, форма ``.many`` использует безопасную запись
  «Всего …: {count}».
"""

STRINGS = {

    # --- app -------------------------------------------------------------------

    "app.title": "ObscuraLens",
    "app.tagline": (
        "Консоль OSINT-расследований по множеству источников"
    ),
    "app.version": "Версия {version}",
    "app.channel": "Канал: {channel}",

    "app.description": (
        "ObscuraLens собирает данные из десятков открытых источников по "
        "четырнадцати типам целей, сопоставляет полученные результаты, "
        "оценивает общий уровень риска и формирует отчёты о расследовании, "
        "которыми можно делиться."
    ),
    "app.copyright": (
        "Copyright (c) {year} участники ObscuraLens"
    ),
    "app.license": "Распространяется по лицензии MIT",
    "app.website": "Домашняя страница проекта: {url}",

    "app.edition": "Настольная версия",
    "app.console_edition": "Консольная версия",

    # --- common ----------------------------------------------------------------

    # Кнопки и короткие ответы.
    "common.ok": "OK",
    "common.cancel": "Отмена",
    "common.yes": "Да",
    "common.no": "Нет",
    "common.back": "Назад",
    "common.quit": "Выйти",
    "common.exit": "Выход",

    # Слова состояния.
    "common.loading": "Загрузка...",
    "common.done": "Готово",
    "common.error": "Ошибка",
    "common.warning": "Предупреждение",
    "common.info": "Информация",
    "common.none": "Нет",
    "common.unknown": "Неизвестно",

    # Общие существительные.
    "common.all": "Все",
    "common.source": "Источник",
    "common.sources": "Источники",
    "common.target": "Цель",
    "common.kind": "Тип",
    "common.results": "Результаты",
    "common.summary": "Сводка",
    "common.details": "Подробности",

    # Навигация и действия.
    "common.continue": "Продолжить",
    "common.confirm": "Подтвердить",
    "common.help": "Справка",
    "common.settings": "Настройки",
    "common.language": "Язык",
    "common.about": "О программе",

    "common.search": "Поиск",
    "common.save": "Сохранить",
    "common.export": "Экспорт",
    "common.copy": "Копировать",
    "common.retry": "Повторить",
    "common.refresh": "Обновить",
    "common.close": "Закрыть",
    "common.open": "Открыть",
    "common.select": "Выбрать",
    "common.selected": "Выбрано",

    # Столбцы таблиц и атрибуты данных.
    "common.name": "Название",
    "common.status": "Статус",
    "common.value": "Значение",
    "common.total": "Всего",

    "common.average": "Среднее",
    "common.date": "Дата",
    "common.time": "Время",
    "common.duration": "Длительность",
    "common.count": "Количество",
    "common.page": "Страница",
    "common.actions": "Действия",

    "common.filter": "Фильтр",
    "common.sort": "Сортировка",

    # Признаки и уточнения.
    "common.enabled": "Включено",
    "common.disabled": "Отключено",
    "common.optional": "Необязательно",
    "common.required": "Обязательно",
    "common.default": "По умолчанию",
    "common.overview": "Обзор",

    # Слова относительного времени.
    "common.today": "Сегодня",
    "common.yesterday": "Вчера",
    "common.now": "Сейчас",

    # Каналы выпусков.
    "common.beta": "Бета",
    "common.stable": "Стабильная",
    "common.nightly": "Ночная",

    # --- menu ------------------------------------------------------------------

    "menu.main_title": "ObscuraLens - Главное меню",
    "menu.choose_option": "Выберите пункт:",

    "menu.invalid_choice": (
        "Недопустимый выбор «{choice}», попробуйте ещё раз."
    ),
    "menu.select_kind": "Выберите тип цели:",
    "menu.enter_target": "Введите {kind} для поиска:",

    "menu.lookup": "Разовый запрос",
    "menu.investigate": "Полное расследование",
    "menu.watchlist": "Список наблюдения",
    "menu.cases": "Менеджер дел",
    "menu.tools": "Инструменты",

    "menu.tools_title": "Инструменты",
    "menu.watchlist_title": "Список наблюдения",
    "menu.cases_title": "Менеджер дел",
    "menu.settings_title": "Настройки",
    "menu.settings_menu": "Настройки",

    "menu.language_menu": "Смена языка",
    "menu.language_changed": "Язык изменён на {language}.",
    "menu.returning_to_main": "Возврат в главное меню...",

    "menu.exit_prompt": (
        "Действительно выйти? (y/N)"
    ),
    "menu.goodbye": "До свидания!",

    # --- cli -------------------------------------------------------------------

    "cli.usage_hint": (
        "Использование: obscuralens <команда> [параметры]"
    ),
    "cli.try_help": (
        "Запустите 'obscuralens --help' для справки."
    ),
    "cli.unknown_command": "Неизвестная команда: {command}",
    "cli.target_prompt": "Введите цель:",
    "cli.detected": "Определённый тип: {kind}",

    "cli.starting_lookup": "Поиск {target} ({kind})...",
    "cli.fetching": "Получение данных из {source}...",
    "cli.aggregating": (
        "Агрегация результатов из {count} источников..."
    ),
    "cli.elapsed": "Затрачено: {seconds} с",
    "cli.risk_score": "Оценка риска: {score}/100",

    "cli.output_format": "Формат вывода: {format}",

    "cli.format_json": "JSON",
    "cli.format_table": "Таблица",
    "cli.format_csv": "CSV",
    "cli.provenance": "Происхождение полей",
    "cli.field_sources": "Источники полей",

    "cli.no_results": (
        "Для «{target}» результаты не найдены."
    ),
    "cli.lookup_failed": (
        "Не удалось выполнить поиск «{target}»: {reason}"
    ),
    "cli.sources_ok": (
        "{count} источник(ов) ответили успешно."
    ),
    "cli.sources_failed": (
        "{count} источник(ов) не ответили."
    ),

    "cli.showing": "Показано {shown} из {total} результатов",
    "cli.sorting_by": "Отсортировано по {field}",
    "cli.filtering_by": "Отфильтровано по {field}",

    "cli.saved_report": "Отчёт сохранён в {path}",
    "cli.output_saved": "Вывод записан в {path}",
    "cli.history": "Недавние запросы",

    "cli.empty_history": "Недавних запросов нет.",
    "cli.confirm_clear_history": "Очистить историю запросов? (y/N)",

    # --- kinds -----------------------------------------------------------------

    "kinds.ip": "IP-адрес",
    "kinds.phone": "Номер телефона",
    "kinds.username": "Имя пользователя",

    "kinds.email": "Адрес электронной почты",
    "kinds.domain": "Домен",
    "kinds.url": "URL",

    "kinds.crypto": "Адрес криптовалюты",
    "kinds.hash": "Хеш файла",

    "kinds.cve": "Идентификатор CVE",
    "kinds.asn": "Номер AS",
    "kinds.mac": "MAC-адрес",
    "kinds.iban": "IBAN",
    "kinds.imei": "IMEI",
    "kinds.coords": "Координаты",

    "kinds.unknown_kind": "Неизвестный тип",
    "kinds.detected_kind": "Определённый тип: {kind}",
    "kinds.select_hint": "Нажмите 1-{count}, чтобы выбрать тип",
    "kinds.kind_list_title": "Поддерживаемые типы целей",

    # --- desktop ---------------------------------------------------------------

    "desktop.title": "ObscuraLens Desktop",
    "desktop.beta_notice": (
        "Это бета-сборка настольной версии ObscuraLens. Некоторые функции "
        "всё ещё развиваются, а автоматические ночные сборки могут быть "
        "менее стабильными, чем релизы с тегами."
    ),

    "desktop.starting": "Запуск локального сервера...",
    "desktop.listening_on": "Ожидание соединений на http://{host}:{port}",
    "desktop.ready": "Готово.",
    "desktop.launch_hint": "Нажмите Ctrl+C, чтобы остановить сервер.",
    "desktop.shutdown": "Завершение работы...",

    "desktop.opening_browser": "Открытие веб-интерфейса...",
    "desktop.browser_opened": (
        "Браузер {browser} открыт; если он не запустился, откройте {url} вручную."
    ),
    "desktop.browser_failed": (
        "Не удалось открыть веб-браузер: {reason}"
    ),

    "desktop.server_stopped": "Сервер остановлен.",
    "desktop.port_in_use": (
        "Порт {port} уже занят; пробуем {alternative}."
    ),
    "desktop.single_instance": (
        "ObscuraLens уже запущен; активируется существующее окно."
    ),

    "desktop.checking_updates": "Проверка обновлений...",
    "desktop.update_available": (
        "Доступно обновление: {version} (текущая: {current})."
    ),
    "desktop.update_check_failed": (
        "Не удалось проверить обновления: {reason}"
    ),
    "desktop.up_to_date": (
        "Вы используете последнюю версию ({version})."
    ),
    "desktop.downloading_update": (
        "Загрузка обновления {version} ({percent}%)..."
    ),
    "desktop.update_downloaded": (
        "Обновление загружено; перезапустите приложение для применения {version}."
    ),
    "desktop.nightly_channel": (
        "Ночной канал: сборки обновляются каждую ночь."
    ),

    "desktop.diagnostics": "Диагностика",
    "desktop.diagnostics_title": "Диагностика настольной версии",

    "desktop.diagnostics_ok": "Все {count} проверок пройдены.",
    "desktop.diagnostics_failed": "{failed} из {count} проверок не пройдены.",

    "desktop.copy_diagnostics": (
        "Скопировать данные диагностики в буфер обмена?"
    ),
    "desktop.diagnostics_copied": (
        "Данные диагностики скопированы в буфер обмена."
    ),

    "desktop.data_dir": (
        "Каталог данных настольной версии: {path}"
    ),
    "desktop.cache_dir": "Каталог кэша: {path}",
    "desktop.log_file": "Файл журнала: {path}",

    # --- report ----------------------------------------------------------------

    "report.title": "Отчёт о расследовании",
    "report.generated": "Создан: {date}",
    "report.target": "Цель: {target} ({kind})",
    "report.footer": (
        "Создано ObscuraLens v{version} {date}"
    ),
    "report.page": "Страница {page} из {total}",

    "report.sections": "Разделы",
    "report.table_of_contents": "Оглавление",

    "report.executive_summary": "Краткое резюме",
    "report.findings": "Результаты расследования",
    "report.timeline": "Хронология",
    "report.correlations": "Корреляции",
    "report.sources_section": "Источники",
    "report.appendix": "Приложение: необработанные данные источников",

    "report.risk_score": (
        "Оценка риска: {score}/100 ({label})"
    ),
    "report.confidence": "Достоверность: {level}",

    "report.no_findings": (
        "Для этой цели результаты расследования не зафиксированы."
    ),
    "report.field": "Поле",
    "report.value": "Значение",
    "report.source_column": "Источник",

    "report.disclaimer": (
        "Этот отчёт составлен на основе общедоступной информации и "
        "предназначен исключительно для справки при расследовании. Перед "
        "принятием мер результаты следует независимо проверить; авторы не "
        "несут ответственности за неправомерное использование."
    ),

    # --- errors ----------------------------------------------------------------

    "errors.network": (
        "Сетевая ошибка при обращении к {source}: {reason}"
    ),
    "errors.timeout": (
        "Запрос к {source} истёк по тайм-ауту через {seconds} с."
    ),
    "errors.rate_limited": (
        "Источник {source} ограничил частоту запросов; повтор через {seconds} с."
    ),
    "errors.malformed_response": (
        "Некорректный ответ от {source}: {reason}"
    ),
    "errors.ssl_error": (
        "Не удалось проверить SSL-сертификат {source}: {reason}"
    ),

    "errors.invalid_input": "Недопустимые входные данные: {reason}",
    "errors.invalid_format": (
        "Неподдерживаемый формат вывода: «{format}»"
    ),
    "errors.not_found": "Не найдено: {target}",
    "errors.no_sources": (
        "Для типа «{kind}» не настроено ни одного источника."
    ),
    "errors.source_unavailable": (
        "Источник «{source}» недоступен."
    ),
    "errors.disabled_source": (
        "Источник «{source}» отключён в настройках."
    ),

    "errors.config_missing": (
        "Отсутствует ключ конфигурации «{key}»."
    ),

    "errors.database": "Ошибка базы данных: {reason}",
    "errors.permission_denied": "Доступ запрещён: {path}",
    "errors.disk_full": (
        "Недостаточно места на диске для записи {path}."
    ),
    "errors.offline": "Работа в автономном режиме; {source} пропущен.",
    "errors.interrupted": "Прервано пользователем.",
    "errors.unexpected": (
        "Произошла непредвиденная ошибка: {reason}"
    ),

    "errors.unknown_language": "Неизвестный код языка: «{code}»",
    "errors.missing_key": "Отсутствует ключ перевода: «{key}»",

    # --- plural ----------------------------------------------------------------

    # Ключи множественного числа для tp(): среда выполнения выбирает .zero,
    # .one или .many по количеству и всегда подставляет {count}.
    "plural.results.zero": "Нет результатов",
    "plural.results.one": "{count} результат",
    "plural.results.many": "Всего результатов: {count}",

    "plural.sources.zero": "Нет источников",
    "plural.sources.one": "{count} источник",
    "plural.sources.many": "Всего источников: {count}",

    "plural.findings.zero": "Нет результатов расследования",
    "plural.findings.one": "{count} результат расследования",
    "plural.findings.many": "Всего результатов расследования: {count}",

    "plural.matches.zero": "Нет совпадений",
    "plural.matches.one": "{count} совпадение",
    "plural.matches.many": "Всего совпадений: {count}",
}

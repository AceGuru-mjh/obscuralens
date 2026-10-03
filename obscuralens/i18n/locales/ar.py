"""
Arabic locale for ObscuraLens.

Language: Arabic
Native name: العربية
Direction: rtl
Locale code: ar
Translators: ObscuraLens contributors

هذا هو الدليل العربي للترجمات: مثل كل ملف لغة آخر ضمن
``obscuralens/i18n/locales`` يعرّف هذا الموديول نفس مجموعة المفاتيح الموجودة
في الدليل المصدر الإنجليزي (``en.py``)، ويُبقي جميع رموز ``{placeholder}``
كما هي حرفيًا، ويترجم كل قيمة إنجليزية ترجمة كاملة. تُحسب نسبة الاكتمال
التي يعرضها ``obscuralens.i18n.list_languages`` بالنسبة إلى عدد مفاتيح
الموديول الإنجليزي.

قواعد التحرير:
* عنصر واحد مسطّح في كل سطر من الدليل بالصيغة ``"prefix.key": "value"``؛
* إبقاء رموز ``{placeholder}`` تمامًا كما هي في الملف الإنجليزي؛
* تُكسر الجُمل الطويلة داخل الأقواس (دمج ضمني)؛
* تختار الدالة ``tp()`` مفاتيح ``plural.*`` عبر اللواحق ``.zero`` / ``.one``
  / ``.many``، ويُدرج العدد دائمًا بوصفه ``{count}``.
"""

STRINGS = {

    # --- app -------------------------------------------------------------------

    "app.title": "ObscuraLens",
    "app.tagline": (
        "وحدة تحكم للتحقيقات OSINT متعددة المصادر"
    ),
    "app.version": "الإصدار {version}",
    "app.channel": "القناة: {channel}",

    "app.description": (
        "يجمع ObscuraLens المعلومات الاستخبارية من عشرات المصادر العامة عبر "
        "أربعة عشر نوعًا من الأهداف، ويربط النتائج ببعضها، ويقيّم درجة الخطر "
        "الإجمالية، وينشئ تقارير تحقيق قابلة للمشاركة."
    ),
    "app.copyright": (
        "حقوق النشر (c) {year} مساهمو ObscuraLens"
    ),
    "app.license": "صدر بموجب رخصة MIT",
    "app.website": "الصفحة الرئيسية للمشروع: {url}",

    "app.edition": "نسخة سطح المكتب",
    "app.console_edition": "نسخة سطر الأوامر",

    # --- common ----------------------------------------------------------------

    # أزرار وإجابات قصيرة.
    "common.ok": "موافق",
    "common.cancel": "إلغاء",
    "common.yes": "نعم",
    "common.no": "لا",
    "common.back": "رجوع",
    "common.quit": "إنهاء",
    "common.exit": "خروج",

    # كلمات الحالة.
    "common.loading": "جارٍ التحميل...",
    "common.done": "تم",
    "common.error": "خطأ",
    "common.warning": "تحذير",
    "common.info": "معلومات",
    "common.none": "لا شيء",
    "common.unknown": "غير معروف",

    # أسماء عامة.
    "common.all": "الكل",
    "common.source": "المصدر",
    "common.sources": "المصادر",
    "common.target": "الهدف",
    "common.kind": "النوع",
    "common.results": "النتائج",
    "common.summary": "الملخص",
    "common.details": "التفاصيل",

    # التنقل والإجراءات.
    "common.continue": "متابعة",
    "common.confirm": "تأكيد",
    "common.help": "مساعدة",
    "common.settings": "الإعدادات",
    "common.language": "اللغة",
    "common.about": "حول",

    "common.search": "بحث",
    "common.save": "حفظ",
    "common.export": "تصدير",
    "common.copy": "نسخ",
    "common.retry": "إعادة المحاولة",
    "common.refresh": "تحديث",
    "common.close": "إغلاق",
    "common.open": "فتح",
    "common.select": "تحديد",
    "common.selected": "المحدد",

    # أعمدة الجداول وسمات البيانات.
    "common.name": "الاسم",
    "common.status": "الحالة",
    "common.value": "القيمة",
    "common.total": "الإجمالي",

    "common.average": "المتوسط",
    "common.date": "التاريخ",
    "common.time": "الوقت",
    "common.duration": "المدة",
    "common.count": "العدد",
    "common.page": "صفحة",
    "common.actions": "الإجراءات",

    "common.filter": "تصفية",
    "common.sort": "ترتيب",

    # مؤشرات وصفات.
    "common.enabled": "مفعّل",
    "common.disabled": "معطّل",
    "common.optional": "اختياري",
    "common.required": "مطلوب",
    "common.default": "افتراضي",
    "common.overview": "نظرة عامة",

    # كلمات الوقت النسبي.
    "common.today": "اليوم",
    "common.yesterday": "أمس",
    "common.now": "الآن",

    # قنوات الإصدار.
    "common.beta": "بيتا",
    "common.stable": "مستقر",
    "common.nightly": "ليلي",

    # --- menu ------------------------------------------------------------------

    "menu.main_title": "ObscuraLens - القائمة الرئيسية",
    "menu.choose_option": "اختر خيارًا:",

    "menu.invalid_choice": (
        "اختيار غير صالح '{choice}'، حاول مرة أخرى."
    ),
    "menu.select_kind": "حدد نوع الهدف:",
    "menu.enter_target": "أدخل {kind} المراد البحث عنه:",

    "menu.lookup": "بحث فردي",
    "menu.investigate": "تحقيق شامل",
    "menu.watchlist": "قائمة المراقبة",
    "menu.cases": "مدير الحالات",
    "menu.tools": "الأدوات",

    "menu.tools_title": "الأدوات",
    "menu.watchlist_title": "قائمة المراقبة",
    "menu.cases_title": "مدير الحالات",
    "menu.settings_title": "الإعدادات",
    "menu.settings_menu": "الإعدادات",

    "menu.language_menu": "تغيير اللغة",
    "menu.language_changed": "تم تغيير اللغة إلى {language}.",
    "menu.returning_to_main": "العودة إلى القائمة الرئيسية...",

    "menu.exit_prompt": (
        "هل تريد بالتأكيد الخروج؟ (y/N)"
    ),
    "menu.goodbye": "إلى اللقاء!",

    # --- cli -------------------------------------------------------------------

    "cli.usage_hint": (
        "الاستخدام: obscuralens <أمر> [خيارات]"
    ),
    "cli.try_help": (
        "شغّل 'obscuralens --help' لمعرفة طريقة الاستخدام."
    ),
    "cli.unknown_command": "أمر غير معروف: {command}",
    "cli.target_prompt": "أدخل هدفًا:",
    "cli.detected": "النوع المكتشف: {kind}",

    "cli.starting_lookup": "جارٍ البحث عن {target} ({kind})...",
    "cli.fetching": "جارٍ الجلب من {source}...",
    "cli.aggregating": (
        "جارٍ تجميع النتائج من {count} من المصادر..."
    ),
    "cli.elapsed": "الوقت المنقضي: {seconds} ثانية",
    "cli.risk_score": "درجة الخطر: {score}/100",

    "cli.output_format": "صيغة الإخراج: {format}",

    "cli.format_json": "JSON",
    "cli.format_table": "جدول",
    "cli.format_csv": "CSV",
    "cli.provenance": "أصل الحقول",
    "cli.field_sources": "مصادر الحقول",

    "cli.no_results": (
        "لم يتم العثور على نتائج لـ '{target}'."
    ),
    "cli.lookup_failed": (
        "فشل البحث عن '{target}': {reason}"
    ),
    "cli.sources_ok": (
        "استجاب {count} من المصادر بنجاح."
    ),
    "cli.sources_failed": (
        "لم يستجب {count} من المصادر."
    ),

    "cli.showing": "النتائج المعروضة: {shown} من أصل {total}",
    "cli.sorting_by": "مرتب حسب {field}",
    "cli.filtering_by": "مصفّى حسب {field}",

    "cli.saved_report": "تم حفظ التقرير في {path}",
    "cli.output_saved": "تمت كتابة المخرجات في {path}",
    "cli.history": "آخر عمليات البحث",

    "cli.empty_history": "لا توجد عمليات بحث حديثة.",
    "cli.confirm_clear_history": "هل تريد مسح سجل عمليات البحث؟ (y/N)",

    # --- kinds -----------------------------------------------------------------

    "kinds.ip": "عنوان IP",
    "kinds.phone": "رقم الهاتف",
    "kinds.username": "اسم المستخدم",

    "kinds.email": "عنوان البريد الإلكتروني",
    "kinds.domain": "النطاق",
    "kinds.url": "عنوان URL",

    "kinds.crypto": "عنوان العملات المشفرة",
    "kinds.hash": "بصمة الملف",

    "kinds.cve": "معرّف CVE",
    "kinds.asn": "رقم AS",
    "kinds.mac": "عنوان MAC",
    "kinds.iban": "IBAN",
    "kinds.imei": "IMEI",
    "kinds.coords": "الإحداثيات",

    "kinds.unknown_kind": "نوع غير معروف",
    "kinds.detected_kind": "النوع المكتشف: {kind}",
    "kinds.select_hint": "اختر رقمًا من 1 إلى {count} لتحديد النوع",
    "kinds.kind_list_title": "أنواع الأهداف المدعومة",

    # --- desktop ---------------------------------------------------------------

    "desktop.title": "ObscuraLens Desktop",
    "desktop.beta_notice": (
        "هذه نسخة تجريبية (بيتا) من نسخة سطح المكتب لـ ObscuraLens. بعض "
        "الميزات لا تزال قيد التطوير، وقد تكون الإصدارات الليلية التلقائية "
        "أقل استقرارًا من الإصدارات الموسومة."
    ),

    "desktop.starting": "جارٍ تشغيل الخادم المحلي...",
    "desktop.listening_on": "الاستماع على http://{host}:{port}",
    "desktop.ready": "جاهز.",
    "desktop.launch_hint": "اضغط Ctrl+C لإيقاف الخادم.",
    "desktop.shutdown": "جارٍ الإيقاف...",

    "desktop.opening_browser": "جارٍ فتح واجهة الويب...",
    "desktop.browser_opened": (
        "تم فتح {browser}؛ إذا لم يبدأ التشغيل، انتقل إلى {url} يدويًا."
    ),
    "desktop.browser_failed": (
        "تعذّر فتح متصفح الويب: {reason}"
    ),

    "desktop.server_stopped": "تم إيقاف الخادم.",
    "desktop.port_in_use": (
        "المنفذ {port} قيد الاستخدام بالفعل؛ سيتم تجربة {alternative} بدلًا منه."
    ),
    "desktop.single_instance": (
        "ObscuraLens يعمل بالفعل؛ يجري تنشيط النافذة الموجودة."
    ),

    "desktop.checking_updates": "جارٍ التحقق من وجود تحديثات...",
    "desktop.update_available": (
        "يتوفر تحديث: {version} (الحالي: {current})."
    ),
    "desktop.update_check_failed": (
        "فشل التحقق من التحديثات: {reason}"
    ),
    "desktop.up_to_date": (
        "أنت تستخدم أحدث إصدار ({version})."
    ),
    "desktop.downloading_update": (
        "جارٍ تنزيل التحديث {version} ({percent}%)..."
    ),
    "desktop.update_downloaded": (
        "تم تنزيل التحديث؛ أعد التشغيل لتطبيق {version}."
    ),
    "desktop.nightly_channel": (
        "القناة الليلية: تُحدَّث الإصدارات كل ليلة."
    ),

    "desktop.diagnostics": "التشخيص",
    "desktop.diagnostics_title": "تشخيص نسخة سطح المكتب",

    "desktop.diagnostics_ok": "نجحت جميع الفحوصات البالغ عددها {count}.",
    "desktop.diagnostics_failed": "فشل {failed} من إجمالي {count} من الفحوصات.",

    "desktop.copy_diagnostics": (
        "هل تريد نسخ التشخيص إلى الحافظة؟"
    ),
    "desktop.diagnostics_copied": (
        "تم نسخ التشخيص إلى الحافظة."
    ),

    "desktop.data_dir": (
        "دليل بيانات سطح المكتب: {path}"
    ),
    "desktop.cache_dir": "دليل الذاكرة المؤقتة: {path}",
    "desktop.log_file": "ملف السجل: {path}",

    # --- report ----------------------------------------------------------------

    "report.title": "تقرير التحقيق",
    "report.generated": "تاريخ الإنشاء: {date}",
    "report.target": "الهدف: {target} ({kind})",
    "report.footer": (
        "أنشئ بواسطة ObscuraLens v{version} بتاريخ {date}"
    ),
    "report.page": "صفحة {page} من {total}",

    "report.sections": "الأقسام",
    "report.table_of_contents": "جدول المحتويات",

    "report.executive_summary": "الملخص التنفيذي",
    "report.findings": "النتائج",
    "report.timeline": "التسلسل الزمني",
    "report.correlations": "الارتباطات",
    "report.sources_section": "المصادر",
    "report.appendix": "الملحق: البيانات الخام من المصادر",

    "report.risk_score": (
        "درجة الخطر: {score}/100 ({label})"
    ),
    "report.confidence": "درجة الثقة: {level}",

    "report.no_findings": (
        "لم تُسجَّل أي نتائج لهذا الهدف."
    ),
    "report.field": "الحقل",
    "report.value": "القيمة",
    "report.source_column": "المصدر",

    "report.disclaimer": (
        "أُنشئ هذا التقرير من معلومات متاحة للعامة وهو مخصص للاسترشاد في "
        "التحقيقات فقط. يجب التحقق من النتائج بشكل مستقل قبل اتخاذ أي إجراء "
        "بناءً عليها؛ ولا يتحمل المؤلفون أي مسؤولية عن سوء الاستخدام."
    ),

    # --- errors ----------------------------------------------------------------

    "errors.network": (
        "خطأ في الشبكة أثناء الاتصال بـ {source}: {reason}"
    ),
    "errors.timeout": (
        "انتهت مهلة الطلب إلى {source} بعد {seconds} ثانية."
    ),
    "errors.rate_limited": (
        "فرض {source} حدًا للمعدل؛ ستتم إعادة المحاولة بعد {seconds} ثانية."
    ),
    "errors.malformed_response": (
        "استجابة غير سليمة من {source}: {reason}"
    ),
    "errors.ssl_error": (
        "فشل التحقق من SSL لـ {source}: {reason}"
    ),

    "errors.invalid_input": "مدخلات غير صالحة: {reason}",
    "errors.invalid_format": (
        "صيغة إخراج غير مدعومة: '{format}'"
    ),
    "errors.not_found": "غير موجود: {target}",
    "errors.no_sources": (
        "لا توجد مصادر مهيَّأة للنوع '{kind}'."
    ),
    "errors.source_unavailable": (
        "المصدر '{source}' غير متاح."
    ),
    "errors.disabled_source": (
        "المصدر '{source}' معطَّل في الإعدادات."
    ),

    "errors.config_missing": (
        "مفتاح الإعدادات '{key}' مفقود."
    ),

    "errors.database": "خطأ في قاعدة البيانات: {reason}",
    "errors.permission_denied": "تم رفض الإذن: {path}",
    "errors.disk_full": (
        "لا توجد مساحة كافية على القرص لكتابة {path}."
    ),
    "errors.offline": "العمل دون اتصال؛ تم تخطي {source}.",
    "errors.interrupted": "تمت المقاطعة بواسطة المستخدم.",
    "errors.unexpected": (
        "حدث خطأ غير متوقع: {reason}"
    ),

    "errors.unknown_language": "رمز لغة غير معروف: '{code}'",
    "errors.missing_key": "مفتاح ترجمة مفقود: '{key}'",

    # --- plural ----------------------------------------------------------------

    # مفاتيح الجمع التي تستهلكها tp(): يختار وقت التشغيل .zero أو .one أو
    # .many وفقًا للعدد ويُدرج {count} دائمًا في النتيجة.
    "plural.results.zero": "لا توجد نتائج",
    "plural.results.one": "{count} نتيجة",
    "plural.results.many": "{count} نتائج",

    "plural.sources.zero": "لا توجد مصادر",
    "plural.sources.one": "{count} مصدر",
    "plural.sources.many": "{count} مصادر",

    "plural.findings.zero": "لا توجد نتائج",
    "plural.findings.one": "{count} نتيجة",
    "plural.findings.many": "{count} نتائج",

    "plural.matches.zero": "لا توجد تطابقات",
    "plural.matches.one": "{count} تطابق",
    "plural.matches.many": "{count} تطابقات",
}

"""
Hindi locale for ObscuraLens.

Language: Hindi
Native name: हिन्दी
Direction: ltr
Locale code: hi
Translators: ObscuraLens contributors

यह हिन्दी अनुवाद-सूची है: ``obscuralens/i18n/locales`` के प्रत्येक अन्य लोकेल
की तरह यह मॉड्यूल अंग्रेज़ी स्रोत सूची (``en.py``) के ठीक उन्हीं कुंजियों को
परिभाषित करता है, प्रत्येक ``{placeholder}`` टोकन को यथावत् रखता है और हर
अंग्रेज़ी मान का पूरा अनुवाद करता है। ``obscuralens.i18n.list_languages``
द्वारा रिपोर्ट की गई पूर्णता प्रतिशतता अंग्रेज़ी मॉड्यूल की कुंजियों की
संख्या के आधार पर गणना की जाती है।

संपादन नियम:
* सूची की प्रत्येक पंक्ति में एक फ़्लैट प्रविष्टि ``"prefix.key": "value"``;
* ``{placeholder}`` टोकन अंग्रेज़ी फ़ाइल के अनुरूप यथावत् रखें;
* लंबे वाक्य कोष्ठकों में लंबाई से तोड़े जाते हैं (अंतर्निहित संयोजन);
* ``plural.*`` कुंजियों को ``tp()`` ``.zero`` / ``.one`` / ``.many``
  प्रत्ययों से चुनता है और गिनती सदैव ``{count}`` के रूप में रखी जाती है।
"""

STRINGS = {

    # --- app -------------------------------------------------------------------

    "app.title": "ObscuraLens",
    "app.tagline": (
        "बहु-स्रोत OSINT जांच कंसोल"
    ),
    "app.version": "संस्करण {version}",
    "app.channel": "चैनल: {channel}",

    "app.description": (
        "ObscuraLens चौदह प्रकार के लक्ष्यों पर दर्जनों सार्वजनिक स्रोतों से "
        "सूचनाएँ एकत्र करता है, निष्कर्षों में परस्पर संबंध स्थापित करता है, "
        "समग्र जोखिम का अंकन करता है और साझा करने योग्य जांच रिपोर्ट बनाता है."
    ),
    "app.copyright": (
        "कॉपीराइट (c) {year} ObscuraLens योगदानकर्ता"
    ),
    "app.license": "MIT लाइसेंस के अंतर्गत जारी",
    "app.website": "प्रोजेक्ट मुख्य पृष्ठ: {url}",

    "app.edition": "डेस्कटॉप संस्करण",
    "app.console_edition": "कंसोल संस्करण",

    # --- common ----------------------------------------------------------------

    # बटन और छोटे उत्तर.
    "common.ok": "ठीक है",
    "common.cancel": "रद्द करें",
    "common.yes": "हाँ",
    "common.no": "नहीं",
    "common.back": "वापस",
    "common.quit": "समाप्त करें",
    "common.exit": "बाहर निकलें",

    # स्थिति शब्द.
    "common.loading": "लोड हो रहा है...",
    "common.done": "पूर्ण",
    "common.error": "त्रुटि",
    "common.warning": "चेतावनी",
    "common.info": "सूचना",
    "common.none": "कोई नहीं",
    "common.unknown": "अज्ञात",

    # सामान्य संज्ञाएँ.
    "common.all": "सभी",
    "common.source": "स्रोत",
    "common.sources": "स्रोत",
    "common.target": "लक्ष्य",
    "common.kind": "प्रकार",
    "common.results": "परिणाम",
    "common.summary": "सारांश",
    "common.details": "विवरण",

    # नेविगेशन और क्रियाएँ.
    "common.continue": "जारी रखें",
    "common.confirm": "पुष्टि करें",
    "common.help": "सहायता",
    "common.settings": "सेटिंग्स",
    "common.language": "भाषा",
    "common.about": "के बारे में",

    "common.search": "खोजें",
    "common.save": "सहेजें",
    "common.export": "निर्यात करें",
    "common.copy": "कॉपी करें",
    "common.retry": "पुनः प्रयास करें",
    "common.refresh": "रिफ़्रेश करें",
    "common.close": "बंद करें",
    "common.open": "खोलें",
    "common.select": "चुनें",
    "common.selected": "चयनित",

    # तालिका कॉलम और डेटा विशेषताएँ.
    "common.name": "नाम",
    "common.status": "स्थिति",
    "common.value": "मान",
    "common.total": "कुल",

    "common.average": "औसत",
    "common.date": "तारीख़",
    "common.time": "समय",
    "common.duration": "अवधि",
    "common.count": "संख्या",
    "common.page": "पृष्ठ",
    "common.actions": "क्रियाएँ",

    "common.filter": "फ़िल्टर करें",
    "common.sort": "क्रमबद्ध करें",

    # फ़्लैग और विशेषक.
    "common.enabled": "सक्रिय",
    "common.disabled": "निष्क्रिय",
    "common.optional": "वैकल्पिक",
    "common.required": "आवश्यक",
    "common.default": "डिफ़ॉल्ट",
    "common.overview": "अवलोकन",

    # सापेक्ष समय शब्द.
    "common.today": "आज",
    "common.yesterday": "बीता कल",
    "common.now": "अभी",

    # रिलीज़ चैनल.
    "common.beta": "बीटा",
    "common.stable": "स्थिर",
    "common.nightly": "नाइटली",

    # --- menu ------------------------------------------------------------------

    "menu.main_title": "ObscuraLens - मुख्य मेनू",
    "menu.choose_option": "एक विकल्प चुनें:",

    "menu.invalid_choice": (
        "अमान्य विकल्प '{choice}', कृपया पुनः प्रयास करें."
    ),
    "menu.select_kind": "लक्ष्य का प्रकार चुनें:",
    "menu.enter_target": "खोजने के लिए {kind} दर्ज करें:",

    "menu.lookup": "एकल खोज",
    "menu.investigate": "पूर्ण जांच",
    "menu.watchlist": "निगरानी सूची",
    "menu.cases": "केस प्रबंधक",
    "menu.tools": "उपकरण",

    "menu.tools_title": "उपकरण",
    "menu.watchlist_title": "निगरानी सूची",
    "menu.cases_title": "केस प्रबंधक",
    "menu.settings_title": "सेटिंग्स",
    "menu.settings_menu": "सेटिंग्स",

    "menu.language_menu": "भाषा बदलें",
    "menu.language_changed": "भाषा {language} में बदल गई.",
    "menu.returning_to_main": "मुख्य मेनू पर लौट रहे हैं...",

    "menu.exit_prompt": (
        "क्या आप वाकई बाहर निकलना चाहते हैं? (y/N)"
    ),
    "menu.goodbye": "अलविदा!",

    # --- cli -------------------------------------------------------------------

    "cli.usage_hint": (
        "उपयोग: obscuralens <कमांड> [विकल्प]"
    ),
    "cli.try_help": (
        "उपयोग जानने के लिए 'obscuralens --help' चलाएँ."
    ),
    "cli.unknown_command": "अज्ञात कमांड: {command}",
    "cli.target_prompt": "एक लक्ष्य दर्ज करें:",
    "cli.detected": "पहचाना गया प्रकार: {kind}",

    "cli.starting_lookup": "{target} ({kind}) खोजा जा रहा है...",
    "cli.fetching": "{source} से डेटा प्राप्त किया जा रहा है...",
    "cli.aggregating": (
        "{count} स्रोतों के परिणाम एकत्र किए जा रहे हैं..."
    ),
    "cli.elapsed": "व्यतीत समय: {seconds} सेकंड",
    "cli.risk_score": "जोखिम स्कोर: {score}/100",

    "cli.output_format": "आउटपुट प्रारूप: {format}",

    "cli.format_json": "JSON",
    "cli.format_table": "तालिका",
    "cli.format_csv": "CSV",
    "cli.provenance": "फ़ील्ड स्रोत-जानकारी",
    "cli.field_sources": "फ़ील्ड स्रोत",

    "cli.no_results": (
        "'{target}' के लिए कोई परिणाम नहीं मिला."
    ),
    "cli.lookup_failed": (
        "'{target}' के लिए खोज विफल: {reason}"
    ),
    "cli.sources_ok": (
        "{count} स्रोतों ने सफलतापूर्वक उत्तर दिया."
    ),
    "cli.sources_failed": (
        "{count} स्रोतों ने उत्तर नहीं दिया."
    ),

    "cli.showing": "{total} में से {shown} परिणाम दिखाए जा रहे हैं",
    "cli.sorting_by": "{field} के अनुसार क्रमबद्ध",
    "cli.filtering_by": "{field} के अनुसार फ़िल्टर किया गया",

    "cli.saved_report": "रिपोर्ट {path} में सहेजी गई",
    "cli.output_saved": "आउटपुट {path} पर लिखा गया",
    "cli.history": "हाल की खोजें",

    "cli.empty_history": "कोई हाल की खोज नहीं.",
    "cli.confirm_clear_history": "खोज इतिहास साफ़ करें? (y/N)",

    # --- kinds -----------------------------------------------------------------

    "kinds.ip": "IP पता",
    "kinds.phone": "फ़ोन नंबर",
    "kinds.username": "उपयोगकर्ता नाम",

    "kinds.email": "ईमेल पता",
    "kinds.domain": "डोमेन",
    "kinds.url": "URL",

    "kinds.crypto": "क्रिप्टो पता",
    "kinds.hash": "फ़ाइल हैश",

    "kinds.cve": "CVE पहचानकर्ता",
    "kinds.asn": "AS नंबर",
    "kinds.mac": "MAC पता",
    "kinds.iban": "IBAN",
    "kinds.imei": "IMEI",
    "kinds.coords": "निर्देशांक",

    "kinds.unknown_kind": "अज्ञात प्रकार",
    "kinds.detected_kind": "पहचाना गया प्रकार: {kind}",
    "kinds.select_hint": "प्रकार चुनने के लिए 1-{count} में से एक चुनें",
    "kinds.kind_list_title": "समर्थित लक्ष्य प्रकार",

    # --- desktop ---------------------------------------------------------------

    "desktop.title": "ObscuraLens डेस्कटॉप",
    "desktop.beta_notice": (
        "यह ObscuraLens डेस्कटॉप संस्करण की एक बीटा बिल्ड है. कुछ सुविधाएँ अभी "
        "भी विकसित हो रही हैं, और स्वचालित नाइटली बिल्ड टैग किए गए रिलीज़ की "
        "तुलना में कम स्थिर हो सकती हैं."
    ),

    "desktop.starting": "स्थानीय सर्वर प्रारंभ हो रहा है...",
    "desktop.listening_on": "http://{host}:{port} पर सुन रहा है",
    "desktop.ready": "तैयार.",
    "desktop.launch_hint": "सर्वर रोकने के लिए Ctrl+C दबाएँ.",
    "desktop.shutdown": "बंद किया जा रहा है...",

    "desktop.opening_browser": "वेब इंटरफ़ेस खोला जा रहा है...",
    "desktop.browser_opened": (
        "{browser} खोल दिया गया; यदि वह प्रारंभ नहीं हुआ तो {url} स्वयं खोलें."
    ),
    "desktop.browser_failed": (
        "वेब ब्राउज़र नहीं खोला जा सका: {reason}"
    ),

    "desktop.server_stopped": "सर्वर रुक गया.",
    "desktop.port_in_use": (
        "पोर्ट {port} पहले से उपयोग में है; इसके स्थान पर {alternative} आज़माया जा रहा है."
    ),
    "desktop.single_instance": (
        "ObscuraLens पहले से चल रहा है; मौजूदा विंडो सक्रिय की जा रही है."
    ),

    "desktop.checking_updates": "अपडेट के लिए जाँच हो रही है...",
    "desktop.update_available": (
        "अपडेट उपलब्ध: {version} (वर्तमान: {current})."
    ),
    "desktop.update_check_failed": (
        "अपडेट जाँच विफल: {reason}"
    ),
    "desktop.up_to_date": (
        "आप नवीनतम संस्करण ({version}) चला रहे हैं."
    ),
    "desktop.downloading_update": (
        "अपडेट {version} डाउनलोड हो रहा है ({percent}%)..."
    ),
    "desktop.update_downloaded": (
        "अपडेट डाउनलोड हो गया; {version} लागू करने के लिए पुनः प्रारंभ करें."
    ),
    "desktop.nightly_channel": (
        "नाइटली चैनल: बिल्ड हर रात नवीनीकृत होते हैं."
    ),

    "desktop.diagnostics": "डायग्नोस्टिक्स",
    "desktop.diagnostics_title": "डेस्कटॉप डायग्नोस्टिक्स",

    "desktop.diagnostics_ok": "सभी {count} जाँचें सफल रहीं.",
    "desktop.diagnostics_failed": "{count} जाँचों में से {failed} विफल रहीं.",

    "desktop.copy_diagnostics": (
        "डायग्नोस्टिक्स को क्लिपबोर्ड पर कॉपी करें?"
    ),
    "desktop.diagnostics_copied": (
        "डायग्नोस्टिक्स क्लिपबोर्ड पर कॉपी किए गए."
    ),

    "desktop.data_dir": (
        "डेस्कटॉप डेटा निर्देशिका: {path}"
    ),
    "desktop.cache_dir": "कैश निर्देशिका: {path}",
    "desktop.log_file": "लॉग फ़ाइल: {path}",

    # --- report ----------------------------------------------------------------

    "report.title": "जांच रिपोर्ट",
    "report.generated": "निर्मित: {date}",
    "report.target": "लक्ष्य: {target} ({kind})",
    "report.footer": (
        "ObscuraLens v{version} द्वारा {date} को निर्मित"
    ),
    "report.page": "{total} में से पृष्ठ {page}",

    "report.sections": "अनुभाग",
    "report.table_of_contents": "विषय-सूची",

    "report.executive_summary": "कार्यकारी सारांश",
    "report.findings": "निष्कर्ष",
    "report.timeline": "समयरेखा",
    "report.correlations": "सहसंबंध",
    "report.sources_section": "स्रोत",
    "report.appendix": "परिशिष्ट: कच्चा स्रोत डेटा",

    "report.risk_score": (
        "जोखिम स्कोर: {score}/100 ({label})"
    ),
    "report.confidence": "विश्वास स्तर: {level}",

    "report.no_findings": (
        "इस लक्ष्य के लिए कोई निष्कर्ष दर्ज नहीं किया गया."
    ),
    "report.field": "फ़ील्ड",
    "report.value": "मान",
    "report.source_column": "स्रोत",

    "report.disclaimer": (
        "यह रिपोर्ट सार्वजनिक रूप से उपलब्ध सूचनाओं से तैयार की गई है और केवल "
        "जांच संदर्भ के लिए है. निष्कर्षों पर कार्रवाई करने से पहले उनकी स्वतंत्र "
        "पुष्टि की जानी चाहिए; दुरुपयोग के लिए लेखक कोई दायित्व स्वीकार नहीं करते."
    ),

    # --- errors ----------------------------------------------------------------

    "errors.network": (
        "{source} से संपर्क करते समय नेटवर्क त्रुटि: {reason}"
    ),
    "errors.timeout": (
        "{source} का अनुरोध {seconds} सेकंड बाद समय-सीमा समाप्त हुआ."
    ),
    "errors.rate_limited": (
        "{source} द्वारा दर सीमित की गई; {seconds} सेकंड बाद पुनः प्रयास."
    ),
    "errors.malformed_response": (
        "{source} से विकृत प्रतिक्रिया: {reason}"
    ),
    "errors.ssl_error": (
        "{source} के लिए SSL सत्यापन विफल: {reason}"
    ),

    "errors.invalid_input": "अमान्य इनपुट: {reason}",
    "errors.invalid_format": (
        "असमर्थित आउटपुट प्रारूप: '{format}'"
    ),
    "errors.not_found": "नहीं मिला: {target}",
    "errors.no_sources": (
        "प्रकार '{kind}' के लिए कोई स्रोत विन्यस्त नहीं है."
    ),
    "errors.source_unavailable": (
        "स्रोत '{source}' अनुपलब्ध है."
    ),
    "errors.disabled_source": (
        "स्रोत '{source}' विन्यास में निष्क्रिय है."
    ),

    "errors.config_missing": (
        "विन्यास कुंजी '{key}' अनुपस्थित है."
    ),

    "errors.database": "डेटाबेस त्रुटि: {reason}",
    "errors.permission_denied": "अनुमति अस्वीकृत: {path}",
    "errors.disk_full": (
        "{path} लिखने के लिए पर्याप्त डिस्क स्थान नहीं है."
    ),
    "errors.offline": "ऑफ़लाइन कार्यरत; {source} छोड़ दिया गया.",
    "errors.interrupted": "उपयोगकर्ता द्वारा बाधित.",
    "errors.unexpected": (
        "एक अप्रत्याशित त्रुटि हुई: {reason}"
    ),

    "errors.unknown_language": "अज्ञात भाषा कोड: '{code}'",
    "errors.missing_key": "अनुपस्थित अनुवाद कुंजी: '{key}'",

    # --- plural ----------------------------------------------------------------

    # tp() द्वारा उपयोग की जाने वाली बहुवचन-सक्षम कुंजियाँ: रनटाइम गिनती के
    # आधार पर .zero / .one / .many चुनता है और गिनती सदैव {count} रूप में रखता है.
    "plural.results.zero": "कोई परिणाम नहीं",
    "plural.results.one": "{count} परिणाम",
    "plural.results.many": "{count} परिणाम",

    "plural.sources.zero": "कोई स्रोत नहीं",
    "plural.sources.one": "{count} स्रोत",
    "plural.sources.many": "{count} स्रोत",

    "plural.findings.zero": "कोई निष्कर्ष नहीं",
    "plural.findings.one": "{count} निष्कर्ष",
    "plural.findings.many": "{count} निष्कर्ष",

    "plural.matches.zero": "कोई मिलान नहीं",
    "plural.matches.one": "{count} मिलान",
    "plural.matches.many": "{count} मिलान",
}

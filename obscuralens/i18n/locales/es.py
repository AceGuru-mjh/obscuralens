"""
Spanish locale for ObscuraLens.

Language: Spanish
Native name: Español
Direction: ltr
Locale code: es
Translators: ObscuraLens contributors

Este es el catálogo en español: al igual que el resto de locales de
``obscuralens/i18n/locales``, define exactamente el mismo conjunto de claves
que el catálogo fuente en inglés (``en.py``), conserva los tokens
``{placeholder}`` tal cual y traduce por completo cada valor en inglés. El
porcentaje de finalización que informa ``obscuralens.i18n.list_languages``
se calcula con respecto al número de claves del módulo en inglés.

Reglas de edición:
* una entrada plana por línea con el formato ``"prefijo.clave": "valor"``;
* conservar los tokens ``{placeholder}`` exactamente como en el archivo en
  inglés;
* las frases largas se envuelven entre paréntesis (concatenación implícita);
* las claves ``plural.*`` las elige ``tp()`` mediante los sufijos ``.zero``
  / ``.one`` / ``.many``, y el recuento siempre se interpola como ``{count}``.
"""

STRINGS = {

    # --- app -------------------------------------------------------------------

    "app.title": "ObscuraLens",
    "app.tagline": (
        "Consola de investigación OSINT multifuente"
    ),
    "app.version": "Versión {version}",
    "app.channel": "Canal: {channel}",

    "app.description": (
        "ObscuraLens agrega inteligencia de docenas de fuentes públicas en "
        "catorce tipos de objetivo, correlaciona los hallazgos, puntúa el "
        "riesgo global y genera informes de investigación compartibles."
    ),
    "app.copyright": (
        "Copyright (c) {year} los colaboradores de ObscuraLens"
    ),
    "app.license": "Publicado bajo la Licencia MIT",
    "app.website": "Página del proyecto: {url}",

    "app.edition": "Edición de escritorio",
    "app.console_edition": "Edición de consola",

    # --- common ----------------------------------------------------------------

    # Botones y respuestas cortas.
    "common.ok": "Aceptar",
    "common.cancel": "Cancelar",
    "common.yes": "Sí",
    "common.no": "No",
    "common.back": "Atrás",
    "common.quit": "Salir",
    "common.exit": "Salir",

    # Palabras de estado.
    "common.loading": "Cargando...",
    "common.done": "Completado",
    "common.error": "Error",
    "common.warning": "Advertencia",
    "common.info": "Información",
    "common.none": "Ninguno",
    "common.unknown": "Desconocido",

    # Sustantivos genéricos.
    "common.all": "Todos",
    "common.source": "Fuente",
    "common.sources": "Fuentes",
    "common.target": "Objetivo",
    "common.kind": "Tipo",
    "common.results": "Resultados",
    "common.summary": "Resumen",
    "common.details": "Detalles",

    # Navegación y acciones.
    "common.continue": "Continuar",
    "common.confirm": "Confirmar",
    "common.help": "Ayuda",
    "common.settings": "Configuración",
    "common.language": "Idioma",
    "common.about": "Acerca de",

    "common.search": "Buscar",
    "common.save": "Guardar",
    "common.export": "Exportar",
    "common.copy": "Copiar",
    "common.retry": "Reintentar",
    "common.refresh": "Actualizar",
    "common.close": "Cerrar",
    "common.open": "Abrir",
    "common.select": "Seleccionar",
    "common.selected": "Seleccionado",

    # Columnas de tabla y atributos de datos.
    "common.name": "Nombre",
    "common.status": "Estado",
    "common.value": "Valor",
    "common.total": "Total",

    "common.average": "Promedio",
    "common.date": "Fecha",
    "common.time": "Hora",
    "common.duration": "Duración",
    "common.count": "Cantidad",
    "common.page": "Página",
    "common.actions": "Acciones",

    "common.filter": "Filtrar",
    "common.sort": "Ordenar",

    # Indicadores y calificativos.
    "common.enabled": "Activado",
    "common.disabled": "Desactivado",
    "common.optional": "Opcional",
    "common.required": "Obligatorio",
    "common.default": "Predeterminado",
    "common.overview": "Descripción general",

    # Palabras de tiempo relativo.
    "common.today": "Hoy",
    "common.yesterday": "Ayer",
    "common.now": "Ahora",

    # Canales de publicación.
    "common.beta": "Beta",
    "common.stable": "Estable",
    "common.nightly": "Nightly",

    # --- menu ------------------------------------------------------------------

    "menu.main_title": "ObscuraLens - Menú principal",
    "menu.choose_option": "Elija una opción:",

    "menu.invalid_choice": (
        "Opción «{choice}» no válida, inténtelo de nuevo."
    ),
    "menu.select_kind": "Seleccione el tipo de objetivo:",
    "menu.enter_target": "Introduzca el {kind} a buscar:",

    "menu.lookup": "Búsqueda única",
    "menu.investigate": "Investigación completa",
    "menu.watchlist": "Lista de seguimiento",
    "menu.cases": "Gestor de casos",
    "menu.tools": "Herramientas",

    "menu.tools_title": "Herramientas",
    "menu.watchlist_title": "Lista de seguimiento",
    "menu.cases_title": "Gestor de casos",
    "menu.settings_title": "Configuración",
    "menu.settings_menu": "Configuración",

    "menu.language_menu": "Cambiar idioma",
    "menu.language_changed": "Idioma cambiado a {language}.",
    "menu.returning_to_main": "Volviendo al menú principal...",

    "menu.exit_prompt": (
        "¿Seguro que desea salir? (y/N)"
    ),
    "menu.goodbye": "¡Hasta pronto!",

    # --- cli -------------------------------------------------------------------

    "cli.usage_hint": (
        "Uso: obscuralens <comando> [opciones]"
    ),
    "cli.try_help": (
        "Ejecute 'obscuralens --help' para ver el uso."
    ),
    "cli.unknown_command": "Comando desconocido: {command}",
    "cli.target_prompt": "Introduzca un objetivo:",
    "cli.detected": "Tipo detectado: {kind}",

    "cli.starting_lookup": "Buscando {target} ({kind})...",
    "cli.fetching": "Obteniendo {source}...",
    "cli.aggregating": (
        "Agregando resultados de {count} fuentes..."
    ),
    "cli.elapsed": "Tiempo transcurrido: {seconds}s",
    "cli.risk_score": "Puntuación de riesgo: {score}/100",

    "cli.output_format": "Formato de salida: {format}",

    "cli.format_json": "JSON",
    "cli.format_table": "Tabla",
    "cli.format_csv": "CSV",
    "cli.provenance": "Procedencia de los campos",
    "cli.field_sources": "Fuentes de los campos",

    "cli.no_results": (
        "No se encontraron resultados para «{target}»."
    ),
    "cli.lookup_failed": (
        "Error al buscar «{target}»: {reason}"
    ),
    "cli.sources_ok": (
        "{count} fuente(s) respondieron correctamente."
    ),
    "cli.sources_failed": (
        "{count} fuente(s) no respondieron."
    ),

    "cli.showing": "Mostrando {shown} de {total} resultados",
    "cli.sorting_by": "Ordenado por {field}",
    "cli.filtering_by": "Filtrado por {field}",

    "cli.saved_report": "Informe guardado en {path}",
    "cli.output_saved": "Salida escrita en {path}",
    "cli.history": "Búsquedas recientes",

    "cli.empty_history": "No hay búsquedas recientes.",
    "cli.confirm_clear_history": "¿Borrar el historial de búsquedas? (y/N)",

    # --- kinds -----------------------------------------------------------------

    "kinds.ip": "Dirección IP",
    "kinds.phone": "Número de teléfono",
    "kinds.username": "Nombre de usuario",

    "kinds.email": "Dirección de correo electrónico",
    "kinds.domain": "Dominio",
    "kinds.url": "URL",

    "kinds.crypto": "Dirección de criptomoneda",
    "kinds.hash": "Hash de archivo",

    "kinds.cve": "Identificador CVE",
    "kinds.asn": "Número AS",
    "kinds.mac": "Dirección MAC",
    "kinds.iban": "IBAN",
    "kinds.imei": "IMEI",
    "kinds.coords": "Coordenadas",

    "kinds.unknown_kind": "Tipo desconocido",
    "kinds.detected_kind": "Tipo detectado: {kind}",
    "kinds.select_hint": "Elija 1-{count} para seleccionar un tipo",
    "kinds.kind_list_title": "Tipos de objetivo admitidos",

    # --- desktop ---------------------------------------------------------------

    "desktop.title": "ObscuraLens Desktop",
    "desktop.beta_notice": (
        "Esta es una versión beta de la edición de escritorio de ObscuraLens. "
        "Algunas funciones siguen evolucionando, y las compilaciones nocturnas "
        "automáticas pueden ser menos estables que las versiones etiquetadas."
    ),

    "desktop.starting": "Iniciando el servidor local...",
    "desktop.listening_on": "Escuchando en http://{host}:{port}",
    "desktop.ready": "Listo.",
    "desktop.launch_hint": "Pulse Ctrl+C para detener el servidor.",
    "desktop.shutdown": "Apagando...",

    "desktop.opening_browser": "Abriendo la interfaz web...",
    "desktop.browser_opened": (
        "{browser} abierto; si no se inició, visite {url} manualmente."
    ),
    "desktop.browser_failed": (
        "No se pudo abrir un navegador web: {reason}"
    ),

    "desktop.server_stopped": "Servidor detenido.",
    "desktop.port_in_use": (
        "El puerto {port} ya está en uso; se probará {alternative} en su lugar."
    ),
    "desktop.single_instance": (
        "ObscuraLens ya se está ejecutando; activando la ventana existente."
    ),

    "desktop.checking_updates": "Comprobando actualizaciones...",
    "desktop.update_available": (
        "Actualización disponible: {version} (actual: {current})."
    ),
    "desktop.update_check_failed": (
        "Error al comprobar actualizaciones: {reason}"
    ),
    "desktop.up_to_date": (
        "Está usando la versión más reciente ({version})."
    ),
    "desktop.downloading_update": (
        "Descargando la actualización {version} ({percent}%)..."
    ),
    "desktop.update_downloaded": (
        "Actualización descargada; reinicie para aplicar {version}."
    ),
    "desktop.nightly_channel": (
        "Canal nightly: las compilaciones se actualizan cada noche."
    ),

    "desktop.diagnostics": "Diagnóstico",
    "desktop.diagnostics_title": "Diagnóstico de escritorio",

    "desktop.diagnostics_ok": "Las {count} comprobaciones se superaron.",
    "desktop.diagnostics_failed": "{failed} de {count} comprobaciones fallaron.",

    "desktop.copy_diagnostics": (
        "¿Copiar el diagnóstico al portapapeles?"
    ),
    "desktop.diagnostics_copied": (
        "Diagnóstico copiado en el portapapeles."
    ),

    "desktop.data_dir": (
        "Directorio de datos de escritorio: {path}"
    ),
    "desktop.cache_dir": "Directorio de caché: {path}",
    "desktop.log_file": "Archivo de registro: {path}",

    # --- report ----------------------------------------------------------------

    "report.title": "Informe de investigación",
    "report.generated": "Generado: {date}",
    "report.target": "Objetivo: {target} ({kind})",
    "report.footer": (
        "Generado por ObscuraLens v{version} el {date}"
    ),
    "report.page": "Página {page} de {total}",

    "report.sections": "Secciones",
    "report.table_of_contents": "Índice",

    "report.executive_summary": "Resumen ejecutivo",
    "report.findings": "Hallazgos",
    "report.timeline": "Cronología",
    "report.correlations": "Correlaciones",
    "report.sources_section": "Fuentes",
    "report.appendix": "Anexo: datos brutos de las fuentes",

    "report.risk_score": (
        "Puntuación de riesgo: {score}/100 ({label})"
    ),
    "report.confidence": "Confianza: {level}",

    "report.no_findings": (
        "No hay hallazgos registrados para este objetivo."
    ),
    "report.field": "Campo",
    "report.value": "Valor",
    "report.source_column": "Fuente",

    "report.disclaimer": (
        "Este informe se genera a partir de información disponible "
        "públicamente y sirve únicamente como referencia de investigación. "
        "Los hallazgos deben verificarse de forma independiente antes de "
        "actuar; los autores no se hacen responsables de un uso indebido."
    ),

    # --- errors ----------------------------------------------------------------

    "errors.network": (
        "Error de red al contactar con {source}: {reason}"
    ),
    "errors.timeout": (
        "La solicitud a {source} caducó tras {seconds}s."
    ),
    "errors.rate_limited": (
        "Límite de peticiones impuesto por {source}; reintento en {seconds}s."
    ),
    "errors.malformed_response": (
        "Respuesta mal formada de {source}: {reason}"
    ),
    "errors.ssl_error": (
        "Error de verificación SSL para {source}: {reason}"
    ),

    "errors.invalid_input": "Entrada no válida: {reason}",
    "errors.invalid_format": (
        "Formato de salida no admitido: «{format}»"
    ),
    "errors.not_found": "No encontrado: {target}",
    "errors.no_sources": (
        "No hay fuentes configuradas para el tipo «{kind}»."
    ),
    "errors.source_unavailable": (
        "La fuente «{source}» no está disponible."
    ),
    "errors.disabled_source": (
        "La fuente «{source}» está desactivada en la configuración."
    ),

    "errors.config_missing": (
        "Falta la clave de configuración «{key}»."
    ),

    "errors.database": "Error de base de datos: {reason}",
    "errors.permission_denied": "Permiso denegado: {path}",
    "errors.disk_full": (
        "No hay espacio suficiente en disco para escribir {path}."
    ),
    "errors.offline": "Trabajando sin conexión; {source} omitido.",
    "errors.interrupted": "Interrumpido por el usuario.",
    "errors.unexpected": (
        "Ocurrió un error inesperado: {reason}"
    ),

    "errors.unknown_language": "Código de idioma desconocido: «{code}»",
    "errors.missing_key": "Falta la clave de traducción: «{key}»",

    # --- plural ----------------------------------------------------------------

    # Claves de plural consumidas por tp(): el tiempo de ejecución elige
    # .zero, .one o .many según el recuento e interpola siempre {count}.
    "plural.results.zero": "Sin resultados",
    "plural.results.one": "{count} resultado",
    "plural.results.many": "{count} resultados",

    "plural.sources.zero": "Sin fuentes",
    "plural.sources.one": "{count} fuente",
    "plural.sources.many": "{count} fuentes",

    "plural.findings.zero": "Sin hallazgos",
    "plural.findings.one": "{count} hallazgo",
    "plural.findings.many": "{count} hallazgos",

    "plural.matches.zero": "Sin coincidencias",
    "plural.matches.one": "{count} coincidencia",
    "plural.matches.many": "{count} coincidencias",
}

"""
Portuguese (Brazil) locale for ObscuraLens.

Language: Portuguese (Brazil)
Native name: Português (Brasil)
Direction: ltr
Locale code: pt
Translators: ObscuraLens contributors

Este é o catálogo em português do Brasil: como todos os outros locales de
``obscuralens/i18n/locales``, ele define exatamente o mesmo conjunto de
chaves do catálogo-fonte em inglês (``en.py``), preserva os tokens
``{placeholder}`` exatamente como estão e traduz integralmente cada valor
em inglês. O percentual de conclusão relatado por
``obscuralens.i18n.list_languages`` é calculado em relação à quantidade de
chaves do módulo em inglês.

Regras de edição:
* uma entrada plana por linha no formato ``"prefixo.chave": "valor"``;
* preserve os tokens ``{placeholder}`` exatamente como no arquivo em inglês;
* frases longas são quebradas dentro de parênteses (concatenação implícita);
* as chaves ``plural.*`` são escolhidas por ``tp()`` pelos sufixos ``.zero``
  / ``.one`` / ``.many``, e a contagem sempre é interpolada como ``{count}``.
"""

STRINGS = {

    # --- app -------------------------------------------------------------------

    "app.title": "ObscuraLens",
    "app.tagline": (
        "Console de investigação OSINT de múltiplas fontes"
    ),
    "app.version": "Versão {version}",
    "app.channel": "Canal: {channel}",

    "app.description": (
        "O ObscuraLens agrega inteligência de dezenas de fontes públicas em "
        "quatorze tipos de alvo, correlaciona os achados, pontua o risco "
        "geral e gera relatórios de investigação compartilháveis."
    ),
    "app.copyright": (
        "Copyright (c) {year} os contribuidores do ObscuraLens"
    ),
    "app.license": "Publicado sob a Licença MIT",
    "app.website": "Página do projeto: {url}",

    "app.edition": "Edição desktop",
    "app.console_edition": "Edição de console",

    # --- common ----------------------------------------------------------------

    # Botões e respostas curtas.
    "common.ok": "OK",
    "common.cancel": "Cancelar",
    "common.yes": "Sim",
    "common.no": "Não",
    "common.back": "Voltar",
    "common.quit": "Sair",
    "common.exit": "Sair",

    # Palavras de estado.
    "common.loading": "Carregando...",
    "common.done": "Concluído",
    "common.error": "Erro",
    "common.warning": "Aviso",
    "common.info": "Informação",
    "common.none": "Nenhum",
    "common.unknown": "Desconhecido",

    # Substantivos genéricos.
    "common.all": "Todos",
    "common.source": "Fonte",
    "common.sources": "Fontes",
    "common.target": "Alvo",
    "common.kind": "Tipo",
    "common.results": "Resultados",
    "common.summary": "Resumo",
    "common.details": "Detalhes",

    # Navegação e ações.
    "common.continue": "Continuar",
    "common.confirm": "Confirmar",
    "common.help": "Ajuda",
    "common.settings": "Configurações",
    "common.language": "Idioma",
    "common.about": "Sobre",

    "common.search": "Pesquisar",
    "common.save": "Salvar",
    "common.export": "Exportar",
    "common.copy": "Copiar",
    "common.retry": "Tentar novamente",
    "common.refresh": "Atualizar",
    "common.close": "Fechar",
    "common.open": "Abrir",
    "common.select": "Selecionar",
    "common.selected": "Selecionado",

    # Colunas de tabela e atributos de dados.
    "common.name": "Nome",
    "common.status": "Status",
    "common.value": "Valor",
    "common.total": "Total",

    "common.average": "Média",
    "common.date": "Data",
    "common.time": "Hora",
    "common.duration": "Duração",
    "common.count": "Quantidade",
    "common.page": "Página",
    "common.actions": "Ações",

    "common.filter": "Filtrar",
    "common.sort": "Ordenar",

    # Indicadores e qualificadores.
    "common.enabled": "Ativado",
    "common.disabled": "Desativado",
    "common.optional": "Opcional",
    "common.required": "Obrigatório",
    "common.default": "Padrão",
    "common.overview": "Visão geral",

    # Palavras de tempo relativo.
    "common.today": "Hoje",
    "common.yesterday": "Ontem",
    "common.now": "Agora",

    # Canais de lançamento.
    "common.beta": "Beta",
    "common.stable": "Estável",
    "common.nightly": "Nightly",

    # --- menu ------------------------------------------------------------------

    "menu.main_title": "ObscuraLens - Menu principal",
    "menu.choose_option": "Escolha uma opção:",

    "menu.invalid_choice": (
        "Opção '{choice}' inválida, tente novamente."
    ),
    "menu.select_kind": "Selecione o tipo de alvo:",
    "menu.enter_target": "Digite o {kind} a pesquisar:",

    "menu.lookup": "Consulta única",
    "menu.investigate": "Investigação completa",
    "menu.watchlist": "Lista de monitoramento",
    "menu.cases": "Gerenciador de casos",
    "menu.tools": "Ferramentas",

    "menu.tools_title": "Ferramentas",
    "menu.watchlist_title": "Lista de monitoramento",
    "menu.cases_title": "Gerenciador de casos",
    "menu.settings_title": "Configurações",
    "menu.settings_menu": "Configurações",

    "menu.language_menu": "Alterar idioma",
    "menu.language_changed": "Idioma alterado para {language}.",
    "menu.returning_to_main": "Voltando ao menu principal...",

    "menu.exit_prompt": (
        "Tem certeza de que deseja sair? (y/N)"
    ),
    "menu.goodbye": "Até logo!",

    # --- cli -------------------------------------------------------------------

    "cli.usage_hint": (
        "Uso: obscuralens <comando> [opções]"
    ),
    "cli.try_help": (
        "Execute 'obscuralens --help' para ver o uso."
    ),
    "cli.unknown_command": "Comando desconhecido: {command}",
    "cli.target_prompt": "Digite um alvo:",
    "cli.detected": "Tipo detectado: {kind}",

    "cli.starting_lookup": "Consultando {target} ({kind})...",
    "cli.fetching": "Obtendo {source}...",
    "cli.aggregating": (
        "Agregando resultados de {count} fontes..."
    ),
    "cli.elapsed": "Tempo decorrido: {seconds}s",
    "cli.risk_score": "Pontuação de risco: {score}/100",

    "cli.output_format": "Formato de saída: {format}",

    "cli.format_json": "JSON",
    "cli.format_table": "Tabela",
    "cli.format_csv": "CSV",
    "cli.provenance": "Procedência dos campos",
    "cli.field_sources": "Fontes dos campos",

    "cli.no_results": (
        "Nenhum resultado encontrado para '{target}'."
    ),
    "cli.lookup_failed": (
        "Falha na consulta de '{target}': {reason}"
    ),
    "cli.sources_ok": (
        "{count} fonte(s) responderam com sucesso."
    ),
    "cli.sources_failed": (
        "{count} fonte(s) não responderam."
    ),

    "cli.showing": "Exibindo {shown} de {total} resultados",
    "cli.sorting_by": "Ordenado por {field}",
    "cli.filtering_by": "Filtrado por {field}",

    "cli.saved_report": "Relatório salvo em {path}",
    "cli.output_saved": "Saída gravada em {path}",
    "cli.history": "Consultas recentes",

    "cli.empty_history": "Nenhuma consulta recente.",
    "cli.confirm_clear_history": "Apagar o histórico de consultas? (y/N)",

    # --- kinds -----------------------------------------------------------------

    "kinds.ip": "Endereço IP",
    "kinds.phone": "Número de telefone",
    "kinds.username": "Nome de usuário",

    "kinds.email": "Endereço de e-mail",
    "kinds.domain": "Domínio",
    "kinds.url": "URL",

    "kinds.crypto": "Endereço de criptomoeda",
    "kinds.hash": "Hash de arquivo",

    "kinds.cve": "Identificador CVE",
    "kinds.asn": "Número AS",
    "kinds.mac": "Endereço MAC",
    "kinds.iban": "IBAN",
    "kinds.imei": "IMEI",
    "kinds.coords": "Coordenadas",

    "kinds.unknown_kind": "Tipo desconhecido",
    "kinds.detected_kind": "Tipo detectado: {kind}",
    "kinds.select_hint": "Escolha 1-{count} para selecionar um tipo",
    "kinds.kind_list_title": "Tipos de alvo suportados",

    # --- desktop ---------------------------------------------------------------

    "desktop.title": "ObscuraLens Desktop",
    "desktop.beta_notice": (
        "Este é um build beta da edição desktop do ObscuraLens. Alguns "
        "recursos ainda estão evoluindo, e builds noturnos automáticos podem "
        "ser menos estáveis que versões marcadas."
    ),

    "desktop.starting": "Iniciando o servidor local...",
    "desktop.listening_on": "Ouvindo em http://{host}:{port}",
    "desktop.ready": "Pronto.",
    "desktop.launch_hint": "Pressione Ctrl+C para parar o servidor.",
    "desktop.shutdown": "Encerrando...",

    "desktop.opening_browser": "Abrindo a interface web...",
    "desktop.browser_opened": (
        "{browser} aberto; se não iniciou, acesse {url} manualmente."
    ),
    "desktop.browser_failed": (
        "Não foi possível abrir um navegador: {reason}"
    ),

    "desktop.server_stopped": "Servidor interrompido.",
    "desktop.port_in_use": (
        "A porta {port} já está em uso; tentando {alternative} em vez dela."
    ),
    "desktop.single_instance": (
        "O ObscuraLens já está em execução; ativando a janela existente."
    ),

    "desktop.checking_updates": "Verificando atualizações...",
    "desktop.update_available": (
        "Atualização disponível: {version} (atual: {current})."
    ),
    "desktop.update_check_failed": (
        "Falha ao verificar atualizações: {reason}"
    ),
    "desktop.up_to_date": (
        "Você está na versão mais recente ({version})."
    ),
    "desktop.downloading_update": (
        "Baixando a atualização {version} ({percent}%)..."
    ),
    "desktop.update_downloaded": (
        "Atualização baixada; reinicie para aplicar {version}."
    ),
    "desktop.nightly_channel": (
        "Canal nightly: os builds são atualizados toda noite."
    ),

    "desktop.diagnostics": "Diagnóstico",
    "desktop.diagnostics_title": "Diagnóstico do desktop",

    "desktop.diagnostics_ok": "Todas as {count} verificações passaram.",
    "desktop.diagnostics_failed": "{failed} de {count} verificações falharam.",

    "desktop.copy_diagnostics": (
        "Copiar o diagnóstico para a área de transferência?"
    ),
    "desktop.diagnostics_copied": (
        "Diagnóstico copiado para a área de transferência."
    ),

    "desktop.data_dir": (
        "Diretório de dados do desktop: {path}"
    ),
    "desktop.cache_dir": "Diretório de cache: {path}",
    "desktop.log_file": "Arquivo de log: {path}",

    # --- report ----------------------------------------------------------------

    "report.title": "Relatório de investigação",
    "report.generated": "Gerado em: {date}",
    "report.target": "Alvo: {target} ({kind})",
    "report.footer": (
        "Gerado pelo ObscuraLens v{version} em {date}"
    ),
    "report.page": "Página {page} de {total}",

    "report.sections": "Seções",
    "report.table_of_contents": "Sumário",

    "report.executive_summary": "Resumo executivo",
    "report.findings": "Achados",
    "report.timeline": "Linha do tempo",
    "report.correlations": "Correlações",
    "report.sources_section": "Fontes",
    "report.appendix": "Apêndice: dados brutos das fontes",

    "report.risk_score": (
        "Pontuação de risco: {score}/100 ({label})"
    ),
    "report.confidence": "Confiança: {level}",

    "report.no_findings": (
        "Nenhum achado registrado para este alvo."
    ),
    "report.field": "Campo",
    "report.value": "Valor",
    "report.source_column": "Fonte",

    "report.disclaimer": (
        "Este relatório é gerado a partir de informações publicamente "
        "disponíveis apenas como referência de investigação. Os achados "
        "devem ser verificados de forma independente antes de qualquer ação; "
        "os autores não se responsabilizam por uso indevido."
    ),

    # --- errors ----------------------------------------------------------------

    "errors.network": (
        "Erro de rede ao contatar {source}: {reason}"
    ),
    "errors.timeout": (
        "A solicitação para {source} expirou após {seconds}s."
    ),
    "errors.rate_limited": (
        "Limite de requisições excedido em {source}; nova tentativa em {seconds}s."
    ),
    "errors.malformed_response": (
        "Resposta malformada de {source}: {reason}"
    ),
    "errors.ssl_error": (
        "Falha na verificação SSL para {source}: {reason}"
    ),

    "errors.invalid_input": "Entrada inválida: {reason}",
    "errors.invalid_format": (
        "Formato de saída não suportado: '{format}'"
    ),
    "errors.not_found": "Não encontrado: {target}",
    "errors.no_sources": (
        "Nenhuma fonte configurada para o tipo '{kind}'."
    ),
    "errors.source_unavailable": (
        "A fonte '{source}' está indisponível."
    ),
    "errors.disabled_source": (
        "A fonte '{source}' está desativada na configuração."
    ),

    "errors.config_missing": (
        "A chave de configuração '{key}' está ausente."
    ),

    "errors.database": "Erro de banco de dados: {reason}",
    "errors.permission_denied": "Permissão negada: {path}",
    "errors.disk_full": (
        "Espaço em disco insuficiente para gravar {path}."
    ),
    "errors.offline": "Trabalhando offline; {source} ignorado.",
    "errors.interrupted": "Interrompido pelo usuário.",
    "errors.unexpected": (
        "Ocorreu um erro inesperado: {reason}"
    ),

    "errors.unknown_language": "Código de idioma desconhecido: '{code}'",
    "errors.missing_key": "Chave de tradução ausente: '{key}'",

    # --- plural ----------------------------------------------------------------

    # Chaves de plural consumidas por tp(): o tempo de execução escolhe
    # .zero, .one ou .many conforme a contagem e interpola sempre {count}.
    "plural.results.zero": "Nenhum resultado",
    "plural.results.one": "{count} resultado",
    "plural.results.many": "{count} resultados",

    "plural.sources.zero": "Nenhuma fonte",
    "plural.sources.one": "{count} fonte",
    "plural.sources.many": "{count} fontes",

    "plural.findings.zero": "Nenhum achado",
    "plural.findings.one": "{count} achado",
    "plural.findings.many": "{count} achados",

    "plural.matches.zero": "Nenhuma correspondência",
    "plural.matches.one": "{count} correspondência",
    "plural.matches.many": "{count} correspondências",
}

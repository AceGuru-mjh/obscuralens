"""
French locale for ObscuraLens.

Language: French
Native name: Français
Direction: ltr
Locale code: fr
Translators: ObscuraLens contributors

Voici le catalogue français : comme tous les autres fichiers de langue de
``obscuralens/i18n/locales``, il définit exactement le même ensemble de clés
que le catalogue source anglais (``en.py``), conserve les jetons
``{placeholder}`` tels quels et traduit intégralement chaque valeur
anglaise. Le taux d'achèvement signalé par
``obscuralens.i18n.list_languages`` est calculé par rapport au nombre de
clés du module anglais.

Règles d'édition :
* une entrée plate par ligne au format ``"prefixe.cle": "valeur"`` ;
* conserver les jetons ``{placeholder}`` exactement comme dans le fichier
  anglais ;
* les phrases longues sont repliées entre parenthèses (concaténation
  implicite) ;
* les clés ``plural.*`` sont choisies par ``tp()`` via les suffixes
  ``.zero`` / ``.one`` / ``.many``, le nombre étant toujours interpolé sous
  la forme ``{count}``.
"""

STRINGS = {

    # --- app -------------------------------------------------------------------

    "app.title": "ObscuraLens",
    "app.tagline": (
        "Console d'enquête OSINT multi-sources"
    ),
    "app.version": "Version {version}",
    "app.channel": "Canal : {channel}",

    "app.description": (
        "ObscuraLens agrège des renseignements issus de dizaines de sources "
        "publiques sur quatorze types de cibles, met en corrélation les "
        "découvertes, évalue le risque global et produit des rapports "
        "d'enquête partageables."
    ),
    "app.copyright": (
        "Copyright (c) {year} les contributeurs d'ObscuraLens"
    ),
    "app.license": "Publié sous licence MIT",
    "app.website": "Page du projet : {url}",

    "app.edition": "Édition bureau",
    "app.console_edition": "Édition console",

    # --- common ----------------------------------------------------------------

    # Boutons et réponses courtes.
    "common.ok": "OK",
    "common.cancel": "Annuler",
    "common.yes": "Oui",
    "common.no": "Non",
    "common.back": "Retour",
    "common.quit": "Quitter",
    "common.exit": "Sortir",

    # Mots d'état.
    "common.loading": "Chargement...",
    "common.done": "Terminé",
    "common.error": "Erreur",
    "common.warning": "Avertissement",
    "common.info": "Information",
    "common.none": "Aucun",
    "common.unknown": "Inconnu",

    # Noms génériques.
    "common.all": "Tous",
    "common.source": "Source",
    "common.sources": "Sources",
    "common.target": "Cible",
    "common.kind": "Type",
    "common.results": "Résultats",
    "common.summary": "Résumé",
    "common.details": "Détails",

    # Navigation et actions.
    "common.continue": "Continuer",
    "common.confirm": "Confirmer",
    "common.help": "Aide",
    "common.settings": "Paramètres",
    "common.language": "Langue",
    "common.about": "À propos",

    "common.search": "Rechercher",
    "common.save": "Enregistrer",
    "common.export": "Exporter",
    "common.copy": "Copier",
    "common.retry": "Réessayer",
    "common.refresh": "Actualiser",
    "common.close": "Fermer",
    "common.open": "Ouvrir",
    "common.select": "Sélectionner",
    "common.selected": "Sélectionné",

    # Colonnes de tableau et attributs de données.
    "common.name": "Nom",
    "common.status": "Statut",
    "common.value": "Valeur",
    "common.total": "Total",

    "common.average": "Moyenne",
    "common.date": "Date",
    "common.time": "Heure",
    "common.duration": "Durée",
    "common.count": "Nombre",
    "common.page": "Page",
    "common.actions": "Actions",

    "common.filter": "Filtrer",
    "common.sort": "Trier",

    # Indicateurs et qualificatifs.
    "common.enabled": "Activé",
    "common.disabled": "Désactivé",
    "common.optional": "Facultatif",
    "common.required": "Requis",
    "common.default": "Par défaut",
    "common.overview": "Vue d'ensemble",

    # Mots de temps relatif.
    "common.today": "Aujourd'hui",
    "common.yesterday": "Hier",
    "common.now": "Maintenant",

    # Canaux de publication.
    "common.beta": "Bêta",
    "common.stable": "Stable",
    "common.nightly": "Nightly",

    # --- menu ------------------------------------------------------------------

    "menu.main_title": "ObscuraLens - Menu principal",
    "menu.choose_option": "Choisissez une option :",

    "menu.invalid_choice": (
        "Choix « {choice} » invalide, veuillez réessayer."
    ),
    "menu.select_kind": "Sélectionnez le type de cible :",
    "menu.enter_target": "Saisissez le {kind} à rechercher :",

    "menu.lookup": "Recherche unique",
    "menu.investigate": "Enquête complète",
    "menu.watchlist": "Liste de surveillance",
    "menu.cases": "Gestionnaire d'affaires",
    "menu.tools": "Outils",

    "menu.tools_title": "Outils",
    "menu.watchlist_title": "Liste de surveillance",
    "menu.cases_title": "Gestionnaire d'affaires",
    "menu.settings_title": "Paramètres",
    "menu.settings_menu": "Paramètres",

    "menu.language_menu": "Changer de langue",
    "menu.language_changed": "Langue changée en {language}.",
    "menu.returning_to_main": "Retour au menu principal...",

    "menu.exit_prompt": (
        "Voulez-vous vraiment quitter ? (y/N)"
    ),
    "menu.goodbye": "Au revoir !",

    # --- cli -------------------------------------------------------------------

    "cli.usage_hint": (
        "Utilisation : obscuralens <commande> [options]"
    ),
    "cli.try_help": (
        "Lancez 'obscuralens --help' pour l'aide."
    ),
    "cli.unknown_command": "Commande inconnue : {command}",
    "cli.target_prompt": "Saisissez une cible :",
    "cli.detected": "Type détecté : {kind}",

    "cli.starting_lookup": "Recherche de {target} ({kind})...",
    "cli.fetching": "Récupération de {source}...",
    "cli.aggregating": (
        "Agrégation des résultats de {count} sources..."
    ),
    "cli.elapsed": "Durée : {seconds} s",
    "cli.risk_score": "Score de risque : {score}/100",

    "cli.output_format": "Format de sortie : {format}",

    "cli.format_json": "JSON",
    "cli.format_table": "Tableau",
    "cli.format_csv": "CSV",
    "cli.provenance": "Provenance des champs",
    "cli.field_sources": "Sources des champs",

    "cli.no_results": (
        "Aucun résultat trouvé pour « {target} »."
    ),
    "cli.lookup_failed": (
        "Échec de la recherche pour « {target} » : {reason}"
    ),
    "cli.sources_ok": (
        "{count} source(s) ont répondu avec succès."
    ),
    "cli.sources_failed": (
        "{count} source(s) n'ont pas répondu."
    ),

    "cli.showing": "Affichage de {shown} résultats sur {total}",
    "cli.sorting_by": "Trié par {field}",
    "cli.filtering_by": "Filtré par {field}",

    "cli.saved_report": "Rapport enregistré dans {path}",
    "cli.output_saved": "Sortie écrite dans {path}",
    "cli.history": "Recherches récentes",

    "cli.empty_history": "Aucune recherche récente.",
    "cli.confirm_clear_history": "Effacer l'historique des recherches ? (y/N)",

    # --- kinds -----------------------------------------------------------------

    "kinds.ip": "Adresse IP",
    "kinds.phone": "Numéro de téléphone",
    "kinds.username": "Nom d'utilisateur",

    "kinds.email": "Adresse e-mail",
    "kinds.domain": "Domaine",
    "kinds.url": "URL",

    "kinds.crypto": "Adresse de cryptomonnaie",
    "kinds.hash": "Empreinte de fichier",

    "kinds.cve": "Identifiant CVE",
    "kinds.asn": "Numéro AS",
    "kinds.mac": "Adresse MAC",
    "kinds.iban": "IBAN",
    "kinds.imei": "IMEI",
    "kinds.coords": "Coordonnées",

    "kinds.unknown_kind": "Type inconnu",
    "kinds.detected_kind": "Type détecté : {kind}",
    "kinds.select_hint": "Choisissez 1-{count} pour sélectionner un type",
    "kinds.kind_list_title": "Types de cibles pris en charge",

    # --- desktop ---------------------------------------------------------------

    "desktop.title": "ObscuraLens Desktop",
    "desktop.beta_notice": (
        "Ceci est une version bêta de l'édition bureau d'ObscuraLens. "
        "Certaines fonctionnalités évoluent encore, et les builds nocturnes "
        "automatiques peuvent être moins stables que les versions publiées."
    ),

    "desktop.starting": "Démarrage du serveur local...",
    "desktop.listening_on": "Écoute sur http://{host}:{port}",
    "desktop.ready": "Prêt.",
    "desktop.launch_hint": "Appuyez sur Ctrl+C pour arrêter le serveur.",
    "desktop.shutdown": "Arrêt en cours...",

    "desktop.opening_browser": "Ouverture de l'interface web...",
    "desktop.browser_opened": (
        "{browser} ouvert ; s'il n'a pas démarré, visitez {url} manuellement."
    ),
    "desktop.browser_failed": (
        "Impossible d'ouvrir un navigateur web : {reason}"
    ),

    "desktop.server_stopped": "Serveur arrêté.",
    "desktop.port_in_use": (
        "Le port {port} est déjà utilisé ; essai sur {alternative} à la place."
    ),
    "desktop.single_instance": (
        "ObscuraLens est déjà en cours d'exécution ; activation de la fenêtre existante."
    ),

    "desktop.checking_updates": "Vérification des mises à jour...",
    "desktop.update_available": (
        "Mise à jour disponible : {version} (actuelle : {current})."
    ),
    "desktop.update_check_failed": (
        "Échec de la vérification des mises à jour : {reason}"
    ),
    "desktop.up_to_date": (
        "Vous utilisez la dernière version ({version})."
    ),
    "desktop.downloading_update": (
        "Téléchargement de la mise à jour {version} ({percent} %)..."
    ),
    "desktop.update_downloaded": (
        "Mise à jour téléchargée ; redémarrez pour appliquer {version}."
    ),
    "desktop.nightly_channel": (
        "Canal nightly : les builds sont actualisés chaque nuit."
    ),

    "desktop.diagnostics": "Diagnostics",
    "desktop.diagnostics_title": "Diagnostics de l'édition bureau",

    "desktop.diagnostics_ok": "Les {count} vérifications ont réussi.",
    "desktop.diagnostics_failed": "{failed} vérifications sur {count} ont échoué.",

    "desktop.copy_diagnostics": (
        "Copier les diagnostics dans le presse-papiers ?"
    ),
    "desktop.diagnostics_copied": (
        "Diagnostics copiés dans le presse-papiers."
    ),

    "desktop.data_dir": (
        "Répertoire de données de l'édition bureau : {path}"
    ),
    "desktop.cache_dir": "Répertoire du cache : {path}",
    "desktop.log_file": "Fichier journal : {path}",

    # --- report ----------------------------------------------------------------

    "report.title": "Rapport d'enquête",
    "report.generated": "Généré le : {date}",
    "report.target": "Cible : {target} ({kind})",
    "report.footer": (
        "Généré par ObscuraLens v{version} le {date}"
    ),
    "report.page": "Page {page} sur {total}",

    "report.sections": "Sections",
    "report.table_of_contents": "Table des matières",

    "report.executive_summary": "Résumé exécutif",
    "report.findings": "Constats",
    "report.timeline": "Chronologie",
    "report.correlations": "Corrélations",
    "report.sources_section": "Sources",
    "report.appendix": "Annexe : données brutes des sources",

    "report.risk_score": (
        "Score de risque : {score}/100 ({label})"
    ),
    "report.confidence": "Confiance : {level}",

    "report.no_findings": (
        "Aucun constat enregistré pour cette cible."
    ),
    "report.field": "Champ",
    "report.value": "Valeur",
    "report.source_column": "Source",

    "report.disclaimer": (
        "Ce rapport est généré à partir d'informations publiquement "
        "disponibles, à titre de référence pour l'enquête uniquement. Les "
        "constats doivent être vérifiés indépendamment avant toute action ; "
        "les auteurs déclinent toute responsabilité en cas d'abus."
    ),

    # --- errors ----------------------------------------------------------------

    "errors.network": (
        "Erreur réseau lors du contact de {source} : {reason}"
    ),
    "errors.timeout": (
        "La requête vers {source} a expiré après {seconds} s."
    ),
    "errors.rate_limited": (
        "Limité par {source} ; nouvelle tentative dans {seconds} s."
    ),
    "errors.malformed_response": (
        "Réponse mal formée de {source} : {reason}"
    ),
    "errors.ssl_error": (
        "Échec de la vérification SSL pour {source} : {reason}"
    ),

    "errors.invalid_input": "Entrée invalide : {reason}",
    "errors.invalid_format": (
        "Format de sortie non pris en charge : « {format} »"
    ),
    "errors.not_found": "Introuvable : {target}",
    "errors.no_sources": (
        "Aucune source n'est configurée pour le type « {kind} »."
    ),
    "errors.source_unavailable": (
        "La source « {source} » est indisponible."
    ),
    "errors.disabled_source": (
        "La source « {source} » est désactivée dans la configuration."
    ),

    "errors.config_missing": (
        "La clé de configuration « {key} » est manquante."
    ),

    "errors.database": "Erreur de base de données : {reason}",
    "errors.permission_denied": "Accès refusé : {path}",
    "errors.disk_full": (
        "Espace disque insuffisant pour écrire {path}."
    ),
    "errors.offline": "Mode hors ligne ; {source} ignoré.",
    "errors.interrupted": "Interrompu par l'utilisateur.",
    "errors.unexpected": (
        "Une erreur inattendue s'est produite : {reason}"
    ),

    "errors.unknown_language": "Code de langue inconnu : « {code} »",
    "errors.missing_key": "Clé de traduction manquante : « {key} »",

    # --- plural ----------------------------------------------------------------

    # Clés au pluriel utilisées par tp() : l'exécution choisit .zero, .one
    # ou .many selon le nombre et interpole toujours {count}.
    "plural.results.zero": "Aucun résultat",
    "plural.results.one": "{count} résultat",
    "plural.results.many": "{count} résultats",

    "plural.sources.zero": "Aucune source",
    "plural.sources.one": "{count} source",
    "plural.sources.many": "{count} sources",

    "plural.findings.zero": "Aucun constat",
    "plural.findings.one": "{count} constat",
    "plural.findings.many": "{count} constats",

    "plural.matches.zero": "Aucune correspondance",
    "plural.matches.one": "{count} correspondance",
    "plural.matches.many": "{count} correspondances",
}

"""
Japanese locale for ObscuraLens.

Language: Japanese
Native name: 日本語
Direction: ltr
Locale code: ja
Translators: ObscuraLens contributors

本ファイルは日本語ロケールです。``obscuralens/i18n/locales`` 配下の他の
ロケールと同様、英語の基準カタログ（``en.py``）とまったく同じキー集合を
定義し、``{placeholder}`` トークンをそのまま維持したうえで、すべての
英語値を完全な日本語訳へ変換しています。
``obscuralens.i18n.list_languages`` が報告する完了率は、英語モジュールの
キー数を基準に算出されます。

編集ルール：
* カタログの各エントリは 1 行に 1 件、``"prefix.key": "value"`` 形式；
* ``{placeholder}`` トークンは英語ファイルと完全に同じ表記を維持；
* 長い文は括弧内の暗黙的文字列連結で折り返します；
* ``plural.*`` キーは ``tp()`` が ``.zero`` / ``.one`` / ``.many`` の
  接尾辞で選択し、件数は常に ``{count}`` として補間されます。
"""

STRINGS = {

    # --- app -------------------------------------------------------------------

    "app.title": "ObscuraLens",
    "app.tagline": (
        "マルチソース OSINT 調査コンソール"
    ),
    "app.version": "バージョン {version}",
    "app.channel": "チャンネル：{channel}",

    "app.description": (
        "ObscuraLens は数十の公開ソースから得た情報を 14 種類の対象にわた"
        "って集約し、調査結果を相互に関連付けてリスクを評価し、共有可能な"
        "調査レポートを生成します。"
    ),
    "app.copyright": (
        "Copyright (c) {year} ObscuraLens コントリビューター"
    ),
    "app.license": "MIT ライセンスの下で公開",
    "app.website": "プロジェクトのホームページ：{url}",

    "app.edition": "デスクトップ版",
    "app.console_edition": "コンソール版",

    # --- common ----------------------------------------------------------------

    # ボタンと短い応答。
    "common.ok": "OK",
    "common.cancel": "キャンセル",
    "common.yes": "はい",
    "common.no": "いいえ",
    "common.back": "戻る",
    "common.quit": "終了",
    "common.exit": "退出",

    # 状態を表す語。
    "common.loading": "読み込み中...",
    "common.done": "完了",
    "common.error": "エラー",
    "common.warning": "警告",
    "common.info": "情報",
    "common.none": "なし",
    "common.unknown": "不明",

    # 汎用の名詞。
    "common.all": "すべて",
    "common.source": "ソース",
    "common.sources": "ソース",
    "common.target": "対象",
    "common.kind": "種類",
    "common.results": "結果",
    "common.summary": "概要",
    "common.details": "詳細",

    # ナビゲーションと操作。
    "common.continue": "続行",
    "common.confirm": "確認",
    "common.help": "ヘルプ",
    "common.settings": "設定",
    "common.language": "言語",
    "common.about": "バージョン情報",

    "common.search": "検索",
    "common.save": "保存",
    "common.export": "エクスポート",
    "common.copy": "コピー",
    "common.retry": "再試行",
    "common.refresh": "更新",
    "common.close": "閉じる",
    "common.open": "開く",
    "common.select": "選択",
    "common.selected": "選択済み",

    # 表の列とデータ属性。
    "common.name": "名前",
    "common.status": "状態",
    "common.value": "値",
    "common.total": "合計",

    "common.average": "平均",
    "common.date": "日付",
    "common.time": "時刻",
    "common.duration": "所要時間",
    "common.count": "件数",
    "common.page": "ページ",
    "common.actions": "操作",

    "common.filter": "絞り込み",
    "common.sort": "並べ替え",

    # フラグと修飾語。
    "common.enabled": "有効",
    "common.disabled": "無効",
    "common.optional": "任意",
    "common.required": "必須",
    "common.default": "デフォルト",
    "common.overview": "全体像",

    # 相対的な時間の語。
    "common.today": "今日",
    "common.yesterday": "昨日",
    "common.now": "現在",

    # リリースチャンネル。
    "common.beta": "ベータ",
    "common.stable": "安定版",
    "common.nightly": "ナイトリー",

    # --- menu ------------------------------------------------------------------

    "menu.main_title": "ObscuraLens - メインメニュー",
    "menu.choose_option": "オプションを選択してください：",

    "menu.invalid_choice": (
        "無効な選択「{choice}」です。もう一度お試しください。"
    ),
    "menu.select_kind": "対象の種類を選択してください：",
    "menu.enter_target": "検索する{kind}を入力してください：",

    "menu.lookup": "単一検索",
    "menu.investigate": "完全調査",
    "menu.watchlist": "ウォッチリスト",
    "menu.cases": "ケース管理",
    "menu.tools": "ツール",

    "menu.tools_title": "ツール",
    "menu.watchlist_title": "ウォッチリスト",
    "menu.cases_title": "ケース管理",
    "menu.settings_title": "設定",
    "menu.settings_menu": "設定",

    "menu.language_menu": "言語の変更",
    "menu.language_changed": "言語を{language}に変更しました。",
    "menu.returning_to_main": "メインメニューに戻っています...",

    "menu.exit_prompt": (
        "本当に終了しますか？(y/N)"
    ),
    "menu.goodbye": "さようなら！",

    # --- cli -------------------------------------------------------------------

    "cli.usage_hint": (
        "使用法：obscuralens <コマンド> [オプション]"
    ),
    "cli.try_help": (
        "使用法を確認するには 'obscuralens --help' を実行してください。"
    ),
    "cli.unknown_command": "不明なコマンド：{command}",
    "cli.target_prompt": "対象を入力してください：",
    "cli.detected": "検出された種類：{kind}",

    "cli.starting_lookup": "{target}（{kind}）を検索しています...",
    "cli.fetching": "{source} を取得しています...",
    "cli.aggregating": (
        "{count} 件のソースからの結果を集約しています..."
    ),
    "cli.elapsed": "経過時間：{seconds} 秒",
    "cli.risk_score": "リスクスコア：{score}/100",

    "cli.output_format": "出力形式：{format}",

    "cli.format_json": "JSON",
    "cli.format_table": "テーブル",
    "cli.format_csv": "CSV",
    "cli.provenance": "フィールドの出所",
    "cli.field_sources": "フィールドの出所",

    "cli.no_results": (
        "「{target}」の結果は見つかりませんでした。"
    ),
    "cli.lookup_failed": (
        "「{target}」の検索に失敗しました：{reason}"
    ),
    "cli.sources_ok": (
        "{count} 件のソースが正常に応答しました。"
    ),
    "cli.sources_failed": (
        "{count} 件のソースが応答しませんでした。"
    ),

    "cli.showing": "全 {total} 件中 {shown} 件の結果を表示しています",
    "cli.sorting_by": "{field} で並べ替えました",
    "cli.filtering_by": "{field} で絞り込みました",

    "cli.saved_report": "レポートを {path} に保存しました",
    "cli.output_saved": "出力を {path} に書き込みました",
    "cli.history": "最近の検索",

    "cli.empty_history": "最近の検索はありません。",
    "cli.confirm_clear_history": "検索履歴を消去しますか？(y/N)",

    # --- kinds -----------------------------------------------------------------

    "kinds.ip": "IP アドレス",
    "kinds.phone": "電話番号",
    "kinds.username": "ユーザー名",

    "kinds.email": "メールアドレス",
    "kinds.domain": "ドメイン",
    "kinds.url": "URL",

    "kinds.crypto": "暗号資産アドレス",
    "kinds.hash": "ファイルハッシュ",

    "kinds.cve": "CVE 識別子",
    "kinds.asn": "AS 番号",
    "kinds.mac": "MAC アドレス",
    "kinds.iban": "IBAN",
    "kinds.imei": "IMEI",
    "kinds.coords": "座標",

    "kinds.unknown_kind": "不明な種類",
    "kinds.detected_kind": "検出された種類：{kind}",
    "kinds.select_hint": "1-{count} を入力して種類を選択してください",
    "kinds.kind_list_title": "サポート対象の種類",

    # --- desktop ---------------------------------------------------------------

    "desktop.title": "ObscuraLens デスクトップ",
    "desktop.beta_notice": (
        "これは ObscuraLens デスクトップ版のベータビルドです。一部の機能は"
        "まだ開発中であり、自動ビルドされるナイトリー版はタグ付きリリース"
        "ほど安定していない可能性があります。"
    ),

    "desktop.starting": "ローカルサーバーを起動しています...",
    "desktop.listening_on": "http://{host}:{port} で待機しています",
    "desktop.ready": "準備完了。",
    "desktop.launch_hint": "Ctrl+C でサーバーを停止します。",
    "desktop.shutdown": "シャットダウンしています...",

    "desktop.opening_browser": "Web インターフェースを開いています...",
    "desktop.browser_opened": (
        "{browser} を開きました。起動しない場合は {url} に手動でアクセスしてください。"
    ),
    "desktop.browser_failed": (
        "Web ブラウザーを開けませんでした：{reason}"
    ),

    "desktop.server_stopped": "サーバーを停止しました。",
    "desktop.port_in_use": (
        "ポート {port} は既に使用中です。代わりに {alternative} を試します。"
    ),
    "desktop.single_instance": (
        "ObscuraLens は既に起動しています。既存のウィンドウをアクティブ化します。"
    ),

    "desktop.checking_updates": "更新を確認しています...",
    "desktop.update_available": (
        "更新が利用可能です：{version}（現在：{current}）。"
    ),
    "desktop.update_check_failed": (
        "更新の確認に失敗しました：{reason}"
    ),
    "desktop.up_to_date": (
        "最新バージョン（{version}）を実行しています。"
    ),
    "desktop.downloading_update": (
        "更新 {version}（{percent}%）をダウンロードしています..."
    ),
    "desktop.update_downloaded": (
        "更新をダウンロードしました。再起動すると {version} が適用されます。"
    ),
    "desktop.nightly_channel": (
        "ナイトリーチャンネル：ビルドは毎晩更新されます。"
    ),

    "desktop.diagnostics": "診断",
    "desktop.diagnostics_title": "デスクトップ診断",

    "desktop.diagnostics_ok": "全 {count} 件のチェックが成功しました。",
    "desktop.diagnostics_failed": "{count} 件中 {failed} 件のチェックが失敗しました。",

    "desktop.copy_diagnostics": (
        "診断情報をクリップボードにコピーしますか？"
    ),
    "desktop.diagnostics_copied": (
        "診断情報をクリップボードにコピーしました。"
    ),

    "desktop.data_dir": (
        "デスクトップデータディレクトリ：{path}"
    ),
    "desktop.cache_dir": "キャッシュディレクトリ：{path}",
    "desktop.log_file": "ログファイル：{path}",

    # --- report ----------------------------------------------------------------

    "report.title": "調査レポート",
    "report.generated": "生成日時：{date}",
    "report.target": "対象：{target}（{kind}）",
    "report.footer": (
        "ObscuraLens v{version} により {date} に生成"
    ),
    "report.page": "全 {total} ページ中 {page} ページ",

    "report.sections": "セクション",
    "report.table_of_contents": "目次",

    "report.executive_summary": "エグゼクティブサマリー",
    "report.findings": "調査結果",
    "report.timeline": "タイムライン",
    "report.correlations": "相関",
    "report.sources_section": "ソース",
    "report.appendix": "付録：ソースの生データ",

    "report.risk_score": (
        "リスクスコア：{score}/100（{label}）"
    ),
    "report.confidence": "信頼度：{level}",

    "report.no_findings": (
        "この対象の調査結果は記録されていません。"
    ),
    "report.field": "フィールド",
    "report.value": "値",
    "report.source_column": "ソース",

    "report.disclaimer": (
        "本レポートは公開情報に基づいて生成されており、調査の参考資料として"
        "のみ提供されます。対応する前に各調査結果を独自に検証してください。"
        "作者は悪用に対して一切の責任を負いません。"
    ),

    # --- errors ----------------------------------------------------------------

    "errors.network": (
        "{source} への接続中にネットワークエラーが発生しました：{reason}"
    ),
    "errors.timeout": (
        "{source} へのリクエストが {seconds} 秒でタイムアウトしました。"
    ),
    "errors.rate_limited": (
        "{source} にレート制限されました。{seconds} 秒後に再試行します。"
    ),
    "errors.malformed_response": (
        "{source} からの応答の形式が不正です：{reason}"
    ),
    "errors.ssl_error": (
        "{source} の SSL 検証に失敗しました：{reason}"
    ),

    "errors.invalid_input": "無効な入力：{reason}",
    "errors.invalid_format": (
        "サポートされていない出力形式：'{format}'"
    ),
    "errors.not_found": "見つかりません：{target}",
    "errors.no_sources": (
        "種類「{kind}」にソースが設定されていません。"
    ),
    "errors.source_unavailable": (
        "ソース「{source}」は利用できません。"
    ),
    "errors.disabled_source": (
        "ソース「{source}」は設定で無効化されています。"
    ),

    "errors.config_missing": (
        "設定キー「{key}」が存在しません。"
    ),

    "errors.database": "データベースエラー：{reason}",
    "errors.permission_denied": "アクセスが拒否されました：{path}",
    "errors.disk_full": (
        "{path} を書き込むためのディスク容量が不足しています。"
    ),
    "errors.offline": "オフラインモードで動作中です。{source} をスキップしました。",
    "errors.interrupted": "ユーザーによって中断されました。",
    "errors.unexpected": (
        "予期しないエラーが発生しました：{reason}"
    ),

    "errors.unknown_language": "不明な言語コード：'{code}'",
    "errors.missing_key": "翻訳キーがありません：'{key}'",

    # --- plural ----------------------------------------------------------------

    # tp() が消費する複数形キー：実行時は件数に応じて .zero、.one、
    # .many を選択し、常に {count} として件数を補間します。
    "plural.results.zero": "結果なし",
    "plural.results.one": "{count} 件の結果",
    "plural.results.many": "{count} 件の結果",

    "plural.sources.zero": "ソースなし",
    "plural.sources.one": "{count} 件のソース",
    "plural.sources.many": "{count} 件のソース",

    "plural.findings.zero": "調査結果なし",
    "plural.findings.one": "{count} 件の調査結果",
    "plural.findings.many": "{count} 件の調査結果",

    "plural.matches.zero": "一致なし",
    "plural.matches.one": "{count} 件の一致",
    "plural.matches.many": "{count} 件の一致",
}

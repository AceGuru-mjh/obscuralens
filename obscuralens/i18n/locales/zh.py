"""
Chinese (Simplified) locale for ObscuraLens.

Language: Chinese (Simplified)
Native name: 简体中文
Direction: ltr
Locale code: zh
Translators: ObscuraLens contributors

本文件是简体中文语言包：与 ``obscuralens/i18n/locales`` 下的其他语言包
一样，它定义与英文源目录（``en.py``）完全相同的键集合，逐字保留
``{placeholder}`` 标记，并提供每个英文值的完整简体中文翻译。
``obscuralens.i18n.list_languages`` 报告的完成度以英文模块的键数量为基准
计算得出。

编辑规则：
* 目录中的每个条目占用一行，格式为 ``"前缀.键": "值"``；
* ``{placeholder}`` 标记必须与英文文件中的写法完全一致；
* 较长的句子使用括号内的隐式字符串拼接换行；
* ``plural.*`` 键由 ``tp()`` 依据 ``.zero`` / ``.one`` / ``.many`` 后缀
  选择，并自动将计数插值为 ``{count}``。
"""

STRINGS = {

    # --- app -------------------------------------------------------------------

    "app.title": "ObscuraLens",
    "app.tagline": (
        "多源 OSINT 调查控制台"
    ),
    "app.version": "版本 {version}",
    "app.channel": "通道：{channel}",

    "app.description": (
        "ObscuraLens 从数十个公开来源聚合情报，覆盖十四种目标类型，"
        "对调查发现进行关联分析、评估整体风险，并生成可共享的调查报告。"
    ),
    "app.copyright": (
        "版权所有 (c) {year} ObscuraLens 贡献者"
    ),
    "app.license": "依据 MIT 许可证发布",
    "app.website": "项目主页：{url}",

    "app.edition": "桌面版",
    "app.console_edition": "控制台版",

    # --- common ----------------------------------------------------------------

    # 按钮与简短应答。
    "common.ok": "确定",
    "common.cancel": "取消",
    "common.yes": "是",
    "common.no": "否",
    "common.back": "返回",
    "common.quit": "退出",
    "common.exit": "离开",

    # 状态词。
    "common.loading": "加载中...",
    "common.done": "完成",
    "common.error": "错误",
    "common.warning": "警告",
    "common.info": "信息",
    "common.none": "无",
    "common.unknown": "未知",

    # 通用名词。
    "common.all": "全部",
    "common.source": "来源",
    "common.sources": "来源",
    "common.target": "目标",
    "common.kind": "类型",
    "common.results": "结果",
    "common.summary": "摘要",
    "common.details": "详情",

    # 导航与操作。
    "common.continue": "继续",
    "common.confirm": "确认",
    "common.help": "帮助",
    "common.settings": "设置",
    "common.language": "语言",
    "common.about": "关于",

    "common.search": "搜索",
    "common.save": "保存",
    "common.export": "导出",
    "common.copy": "复制",
    "common.retry": "重试",
    "common.refresh": "刷新",
    "common.close": "关闭",
    "common.open": "打开",
    "common.select": "选择",
    "common.selected": "已选择",

    # 表格列与数据属性。
    "common.name": "名称",
    "common.status": "状态",
    "common.value": "值",
    "common.total": "总计",

    "common.average": "平均",
    "common.date": "日期",
    "common.time": "时间",
    "common.duration": "耗时",
    "common.count": "数量",
    "common.page": "页码",
    "common.actions": "操作",

    "common.filter": "筛选",
    "common.sort": "排序",

    # 标志与限定词。
    "common.enabled": "已启用",
    "common.disabled": "已禁用",
    "common.optional": "可选",
    "common.required": "必填",
    "common.default": "默认",
    "common.overview": "概览",

    # 相对时间词。
    "common.today": "今天",
    "common.yesterday": "昨天",
    "common.now": "现在",

    # 发布通道。
    "common.beta": "测试版",
    "common.stable": "稳定版",
    "common.nightly": "每夜版",

    # --- menu ------------------------------------------------------------------

    "menu.main_title": "ObscuraLens - 主菜单",
    "menu.choose_option": "请选择一个选项：",

    "menu.invalid_choice": (
        "无效的选择“{choice}”，请重试。"
    ),
    "menu.select_kind": "请选择目标类型：",
    "menu.enter_target": "请输入要查询的{kind}：",

    "menu.lookup": "单项查询",
    "menu.investigate": "完整调查",
    "menu.watchlist": "监视列表",
    "menu.cases": "案件管理",
    "menu.tools": "工具",

    "menu.tools_title": "工具",
    "menu.watchlist_title": "监视列表",
    "menu.cases_title": "案件管理",
    "menu.settings_title": "设置",
    "menu.settings_menu": "设置",

    "menu.language_menu": "更改语言",
    "menu.language_changed": "语言已切换为{language}。",
    "menu.returning_to_main": "正在返回主菜单...",

    "menu.exit_prompt": (
        "确定要退出吗？(y/N)"
    ),
    "menu.goodbye": "再见！",

    # --- cli -------------------------------------------------------------------

    "cli.usage_hint": (
        "用法：obscuralens <命令> [选项]"
    ),
    "cli.try_help": (
        "运行 'obscuralens --help' 查看用法。"
    ),
    "cli.unknown_command": "未知命令：{command}",
    "cli.target_prompt": "请输入目标：",
    "cli.detected": "检测到的类型：{kind}",

    "cli.starting_lookup": "正在查询 {target}（{kind}）...",
    "cli.fetching": "正在获取 {source}...",
    "cli.aggregating": (
        "正在汇总来自 {count} 个来源的结果..."
    ),
    "cli.elapsed": "耗时：{seconds} 秒",
    "cli.risk_score": "风险评分：{score}/100",

    "cli.output_format": "输出格式：{format}",

    "cli.format_json": "JSON",
    "cli.format_table": "表格",
    "cli.format_csv": "CSV",
    "cli.provenance": "字段来源",
    "cli.field_sources": "字段来源",

    "cli.no_results": (
        "未找到“{target}”的相关结果。"
    ),
    "cli.lookup_failed": (
        "查询“{target}”失败：{reason}"
    ),
    "cli.sources_ok": (
        "{count} 个来源成功响应。"
    ),
    "cli.sources_failed": (
        "{count} 个来源响应失败。"
    ),

    "cli.showing": "正在显示 {total} 条结果中的 {shown} 条",
    "cli.sorting_by": "按 {field} 排序",
    "cli.filtering_by": "按 {field} 筛选",

    "cli.saved_report": "报告已保存至 {path}",
    "cli.output_saved": "输出已写入 {path}",
    "cli.history": "最近查询",

    "cli.empty_history": "暂无最近查询。",
    "cli.confirm_clear_history": "确定清空查询历史吗？(y/N)",

    # --- kinds -----------------------------------------------------------------

    "kinds.ip": "IP 地址",
    "kinds.phone": "电话号码",
    "kinds.username": "用户名",

    "kinds.email": "电子邮箱地址",
    "kinds.domain": "域名",
    "kinds.url": "URL",

    "kinds.crypto": "加密货币地址",
    "kinds.hash": "文件哈希",

    "kinds.cve": "CVE 编号",
    "kinds.asn": "AS 编号",
    "kinds.mac": "MAC 地址",
    "kinds.iban": "IBAN",
    "kinds.imei": "IMEI",
    "kinds.coords": "坐标",

    "kinds.unknown_kind": "未知类型",
    "kinds.detected_kind": "检测到的类型：{kind}",
    "kinds.select_hint": "输入 1-{count} 选择一种类型",
    "kinds.kind_list_title": "支持的目标类型",

    # --- desktop ---------------------------------------------------------------

    "desktop.title": "ObscuraLens 桌面版",
    "desktop.beta_notice": (
        "这是 ObscuraLens 桌面版的测试构建。部分功能仍在完善中，而自动"
        "生成的每夜构建可能不如正式发布版本稳定。"
    ),

    "desktop.starting": "正在启动本地服务器...",
    "desktop.listening_on": "正在监听 http://{host}:{port}",
    "desktop.ready": "就绪。",
    "desktop.launch_hint": "按 Ctrl+C 停止服务器。",
    "desktop.shutdown": "正在关闭...",

    "desktop.opening_browser": "正在打开网页界面...",
    "desktop.browser_opened": (
        "已打开 {browser}；如果未自动启动，请手动访问 {url}。"
    ),
    "desktop.browser_failed": (
        "无法打开网页浏览器：{reason}"
    ),

    "desktop.server_stopped": "服务器已停止。",
    "desktop.port_in_use": (
        "端口 {port} 已被占用；改为尝试 {alternative}。"
    ),
    "desktop.single_instance": (
        "ObscuraLens 已在运行；正在激活现有窗口。"
    ),

    "desktop.checking_updates": "正在检查更新...",
    "desktop.update_available": (
        "有可用更新：{version}（当前版本：{current}）。"
    ),
    "desktop.update_check_failed": (
        "检查更新失败：{reason}"
    ),
    "desktop.up_to_date": (
        "您正在使用最新版本（{version}）。"
    ),
    "desktop.downloading_update": (
        "正在下载更新 {version}（{percent}%）..."
    ),
    "desktop.update_downloaded": (
        "更新已下载；重启后即可应用 {version}。"
    ),
    "desktop.nightly_channel": (
        "每夜通道：构建版本每晚更新。"
    ),

    "desktop.diagnostics": "诊断",
    "desktop.diagnostics_title": "桌面版诊断",

    "desktop.diagnostics_ok": "全部 {count} 项检查已通过。",
    "desktop.diagnostics_failed": "{count} 项检查中有 {failed} 项失败。",

    "desktop.copy_diagnostics": (
        "将诊断信息复制到剪贴板吗？"
    ),
    "desktop.diagnostics_copied": (
        "诊断信息已复制到剪贴板。"
    ),

    "desktop.data_dir": (
        "桌面版数据目录：{path}"
    ),
    "desktop.cache_dir": "缓存目录：{path}",
    "desktop.log_file": "日志文件：{path}",

    # --- report ----------------------------------------------------------------

    "report.title": "调查报告",
    "report.generated": "生成时间：{date}",
    "report.target": "目标：{target}（{kind}）",
    "report.footer": (
        "由 ObscuraLens v{version} 于 {date} 生成"
    ),
    "report.page": "第 {page} 页，共 {total} 页",

    "report.sections": "章节",
    "report.table_of_contents": "目录",

    "report.executive_summary": "执行摘要",
    "report.findings": "调查发现",
    "report.timeline": "时间线",
    "report.correlations": "关联分析",
    "report.sources_section": "来源",
    "report.appendix": "附录：原始来源数据",

    "report.risk_score": (
        "风险评分：{score}/100（{label}）"
    ),
    "report.confidence": "置信度：{level}",

    "report.no_findings": (
        "尚未记录该目标的任何调查发现。"
    ),
    "report.field": "字段",
    "report.value": "值",
    "report.source_column": "来源",

    "report.disclaimer": (
        "本报告基于公开可得的信息生成，仅供调查参考。在采取行动之前，"
        "应对各项调查发现进行独立核实；作者对任何滥用行为不承担责任。"
    ),

    # --- errors ----------------------------------------------------------------

    "errors.network": (
        "联系 {source} 时发生网络错误：{reason}"
    ),
    "errors.timeout": (
        "对 {source} 的请求在 {seconds} 秒后超时。"
    ),
    "errors.rate_limited": (
        "被 {source} 限流；将在 {seconds} 秒后重试。"
    ),
    "errors.malformed_response": (
        "来自 {source} 的响应格式错误：{reason}"
    ),
    "errors.ssl_error": (
        "对 {source} 的 SSL 证书校验失败：{reason}"
    ),

    "errors.invalid_input": "无效输入：{reason}",
    "errors.invalid_format": (
        "不支持的输出格式：“{format}”"
    ),
    "errors.not_found": "未找到：{target}",
    "errors.no_sources": (
        "没有为类型“{kind}”配置任何来源。"
    ),
    "errors.source_unavailable": (
        "来源“{source}”当前不可用。"
    ),
    "errors.disabled_source": (
        "来源“{source}”已在配置中被禁用。"
    ),

    "errors.config_missing": (
        "缺少配置项“{key}”。"
    ),

    "errors.database": "数据库错误：{reason}",
    "errors.permission_denied": "权限被拒绝：{path}",
    "errors.disk_full": (
        "磁盘空间不足，无法写入 {path}。"
    ),
    "errors.offline": "处于离线模式；已跳过 {source}。",
    "errors.interrupted": "已被用户中断。",
    "errors.unexpected": (
        "发生意外错误：{reason}"
    ),

    "errors.unknown_language": "未知的语言代码：“{code}”",
    "errors.missing_key": "缺少翻译键：“{key}”",

    # --- plural ----------------------------------------------------------------

    # 由 tp() 消费的复数键：运行时根据数量选择 .zero、.one 或 .many，
    # 并始终将计数插值为 {count}。
    "plural.results.zero": "没有结果",
    "plural.results.one": "{count} 条结果",
    "plural.results.many": "{count} 条结果",

    "plural.sources.zero": "没有来源",
    "plural.sources.one": "{count} 个来源",
    "plural.sources.many": "{count} 个来源",

    "plural.findings.zero": "没有调查发现",
    "plural.findings.one": "{count} 项调查发现",
    "plural.findings.many": "{count} 项调查发现",

    "plural.matches.zero": "没有匹配项",
    "plural.matches.one": "{count} 个匹配项",
    "plural.matches.many": "{count} 个匹配项",
}

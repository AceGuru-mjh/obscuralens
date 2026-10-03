"""
Korean locale for ObscuraLens.

Language: Korean
Native name: 한국어
Direction: ltr
Locale code: ko
Translators: ObscuraLens contributors

이 파일은 한국어 로케일입니다. ``obscuralens/i18n/locales`` 아래의 다른
로케일과 마찬가지로 영어 기준 카탈로그(``en.py``)와 완전히 동일한 키
집합을 정의하고, ``{placeholder}`` 토큰을 그대로 유지한 채 모든 영어
값을 완전한 한국어 번역으로 제공합니다.
``obscuralens.i18n.list_languages``가 보고하는 완성도는 영어 모듈의
키 수를 기준으로 계산됩니다.

편집 규칙:
* 카탈로그의 각 항목은 한 줄에 하나씩 ``"prefix.key": "value"`` 형식；
* ``{placeholder}`` 토큰은 영어 파일과 정확히 같은 표기를 유지；
* 긴 문장은 괄호 안 암시적 문자열 연결로 줄바꿈합니다；
* ``plural.*`` 키는 ``tp()``가 ``.zero`` / ``.one`` / ``.many`` 접미사로
  선택하며 개수는 항상 ``{count}``로 보간됩니다.
"""

STRINGS = {

    # --- app -------------------------------------------------------------------

    "app.title": "ObscuraLens",
    "app.tagline": (
        "다중 소스 OSINT 조사 콘솔"
    ),
    "app.version": "버전 {version}",
    "app.channel": "채널: {channel}",

    "app.description": (
        "ObscuraLens는 수십 개의 공개 소스에서 정보를 수집하여 14가지 대상"
        " 유형에 걸쳐 조사 결과를 상호 연관 분석하고, 위험도를 평가하며, 공유"
        " 가능한 조사 보고서를 생성합니다."
    ),
    "app.copyright": (
        "Copyright (c) {year} ObscuraLens 기여자"
    ),
    "app.license": "MIT 라이선스에 따라 배포됨",
    "app.website": "프로젝트 홈페이지: {url}",

    "app.edition": "데스크톱 에디션",
    "app.console_edition": "콘솔 에디션",

    # --- common ----------------------------------------------------------------

    # 버튼과 간단한 응답.
    "common.ok": "확인",
    "common.cancel": "취소",
    "common.yes": "예",
    "common.no": "아니요",
    "common.back": "뒤로",
    "common.quit": "종료",
    "common.exit": "나가기",

    # 상태를 나타내는 말.
    "common.loading": "불러오는 중...",
    "common.done": "완료",
    "common.error": "오류",
    "common.warning": "경고",
    "common.info": "정보",
    "common.none": "없음",
    "common.unknown": "알 수 없음",

    # 일반 명사.
    "common.all": "전체",
    "common.source": "소스",
    "common.sources": "소스",
    "common.target": "대상",
    "common.kind": "유형",
    "common.results": "결과",
    "common.summary": "요약",
    "common.details": "세부 정보",

    # 탐색과 조작.
    "common.continue": "계속",
    "common.confirm": "확인",
    "common.help": "도움말",
    "common.settings": "설정",
    "common.language": "언어",
    "common.about": "정보",

    "common.search": "검색",
    "common.save": "저장",
    "common.export": "내보내기",
    "common.copy": "복사",
    "common.retry": "다시 시도",
    "common.refresh": "새로 고침",
    "common.close": "닫기",
    "common.open": "열기",
    "common.select": "선택",
    "common.selected": "선택됨",

    # 표 열과 데이터 속성.
    "common.name": "이름",
    "common.status": "상태",
    "common.value": "값",
    "common.total": "합계",

    "common.average": "평균",
    "common.date": "날짜",
    "common.time": "시간",
    "common.duration": "소요 시간",
    "common.count": "개수",
    "common.page": "페이지",
    "common.actions": "작업",

    "common.filter": "필터",
    "common.sort": "정렬",

    # 플래그와 수식어.
    "common.enabled": "활성화됨",
    "common.disabled": "비활성화됨",
    "common.optional": "선택 사항",
    "common.required": "필수",
    "common.default": "기본값",
    "common.overview": "개요",

    # 상대 시간 표현.
    "common.today": "오늘",
    "common.yesterday": "어제",
    "common.now": "지금",

    # 릴리스 채널.
    "common.beta": "베타",
    "common.stable": "안정",
    "common.nightly": "나이틀리",

    # --- menu ------------------------------------------------------------------

    "menu.main_title": "ObscuraLens - 메인 메뉴",
    "menu.choose_option": "옵션을 선택하세요:",

    "menu.invalid_choice": (
        "잘못된 선택 '{choice}'입니다. 다시 시도하세요."
    ),
    "menu.select_kind": "대상 유형을 선택하세요:",
    "menu.enter_target": "조사할 {kind}을(를) 입력하세요:",

    "menu.lookup": "단일 조회",
    "menu.investigate": "전체 조사",
    "menu.watchlist": "감시 목록",
    "menu.cases": "케이스 관리",
    "menu.tools": "도구",

    "menu.tools_title": "도구",
    "menu.watchlist_title": "감시 목록",
    "menu.cases_title": "케이스 관리",
    "menu.settings_title": "설정",
    "menu.settings_menu": "설정",

    "menu.language_menu": "언어 변경",
    "menu.language_changed": "언어가 {language}(으)로 변경되었습니다.",
    "menu.returning_to_main": "메인 메뉴로 돌아갑니다...",

    "menu.exit_prompt": (
        "정말 종료하시겠습니까? (y/N)"
    ),
    "menu.goodbye": "안녕히 가세요!",

    # --- cli -------------------------------------------------------------------

    "cli.usage_hint": (
        "사용법: obscuralens <명령> [옵션]"
    ),
    "cli.try_help": (
        "사용법을 보려면 'obscuralens --help'를 실행하세요."
    ),
    "cli.unknown_command": "알 수 없는 명령: {command}",
    "cli.target_prompt": "대상을 입력하세요:",
    "cli.detected": "감지된 유형: {kind}",

    "cli.starting_lookup": "{target}({kind})을(를) 조회하는 중...",
    "cli.fetching": "{source}을(를) 가져오는 중...",
    "cli.aggregating": (
        "{count}개 소스의 결과를 집계하는 중..."
    ),
    "cli.elapsed": "경과 시간: {seconds}초",
    "cli.risk_score": "위험 점수: {score}/100",

    "cli.output_format": "출력 형식: {format}",

    "cli.format_json": "JSON",
    "cli.format_table": "표",
    "cli.format_csv": "CSV",
    "cli.provenance": "필드 출처",
    "cli.field_sources": "필드 출처",

    "cli.no_results": (
        "'{target}'에 대한 결과가 없습니다."
    ),
    "cli.lookup_failed": (
        "'{target}' 조회 실패: {reason}"
    ),
    "cli.sources_ok": (
        "{count}개 소스가 정상 응답했습니다."
    ),
    "cli.sources_failed": (
        "{count}개 소스가 응답하지 않았습니다."
    ),

    "cli.showing": "전체 {total}개 중 {shown}개 결과 표시 중",
    "cli.sorting_by": "{field} 기준으로 정렬됨",
    "cli.filtering_by": "{field} 기준으로 필터링됨",

    "cli.saved_report": "보고서가 {path}에 저장되었습니다",
    "cli.output_saved": "출력이 {path}에 기록되었습니다",
    "cli.history": "최근 조회",

    "cli.empty_history": "최근 조회가 없습니다.",
    "cli.confirm_clear_history": "조회 기록을 지우시겠습니까? (y/N)",

    # --- kinds -----------------------------------------------------------------

    "kinds.ip": "IP 주소",
    "kinds.phone": "전화 번호",
    "kinds.username": "사용자 이름",

    "kinds.email": "이메일 주소",
    "kinds.domain": "도메인",
    "kinds.url": "URL",

    "kinds.crypto": "암호화폐 주소",
    "kinds.hash": "파일 해시",

    "kinds.cve": "CVE 식별자",
    "kinds.asn": "AS 번호",
    "kinds.mac": "MAC 주소",
    "kinds.iban": "IBAN",
    "kinds.imei": "IMEI",
    "kinds.coords": "좌표",

    "kinds.unknown_kind": "알 수 없는 유형",
    "kinds.detected_kind": "감지된 유형: {kind}",
    "kinds.select_hint": "유형을 선택하려면 1-{count} 중에서 고르세요",
    "kinds.kind_list_title": "지원되는 대상 유형",

    # --- desktop ---------------------------------------------------------------

    "desktop.title": "ObscuraLens 데스크톱",
    "desktop.beta_notice": (
        "이것은 ObscuraLens 데스크톱 에디션의 베타 빌드입니다. 일부 기능은"
        " 아직 개발 중이며, 자동화된 나이틀리 빌드는 태그가 지정된 릴리스"
        "만큼 안정적이지 않을 수 있습니다."
    ),

    "desktop.starting": "로컬 서버를 시작하는 중...",
    "desktop.listening_on": "http://{host}:{port}에서 수신 대기 중",
    "desktop.ready": "준비 완료.",
    "desktop.launch_hint": "Ctrl+C를 눌러 서버를 중지하세요.",
    "desktop.shutdown": "종료하는 중...",

    "desktop.opening_browser": "웹 인터페이스를 여는 중...",
    "desktop.browser_opened": (
        "{browser}을(를) 열었습니다. 시작되지 않으면 {url}에 직접 접속하세요."
    ),
    "desktop.browser_failed": (
        "웹 브라우저를 열 수 없습니다: {reason}"
    ),

    "desktop.server_stopped": "서버가 중지되었습니다.",
    "desktop.port_in_use": (
        "포트 {port}이(가) 이미 사용 중입니다. 대신 {alternative}을(를) 시도합니다."
    ),
    "desktop.single_instance": (
        "ObscuraLens가 이미 실행 중입니다. 기존 창을 활성화합니다."
    ),

    "desktop.checking_updates": "업데이트 확인 중...",
    "desktop.update_available": (
        "업데이트 가능: {version} (현재: {current})."
    ),
    "desktop.update_check_failed": (
        "업데이트 확인 실패: {reason}"
    ),
    "desktop.up_to_date": (
        "최신 버전({version})을 사용 중입니다."
    ),
    "desktop.downloading_update": (
        "업데이트 {version}({percent}%) 다운로드 중..."
    ),
    "desktop.update_downloaded": (
        "업데이트가 다운로드되었습니다. 재시작하면 {version}이(가) 적용됩니다."
    ),
    "desktop.nightly_channel": (
        "나이틀리 채널: 빌드는 매일 밤 갱신됩니다."
    ),

    "desktop.diagnostics": "진단",
    "desktop.diagnostics_title": "데스크톱 진단",

    "desktop.diagnostics_ok": "전체 {count}개 확인이 통과했습니다.",
    "desktop.diagnostics_failed": "{count}개 확인 중 {failed}개가 실패했습니다.",

    "desktop.copy_diagnostics": (
        "진단 정보를 클립보드에 복사하시겠습니까?"
    ),
    "desktop.diagnostics_copied": (
        "진단 정보가 클립보드에 복사되었습니다."
    ),

    "desktop.data_dir": (
        "데스크톱 데이터 디렉터리: {path}"
    ),
    "desktop.cache_dir": "캐시 디렉터리: {path}",
    "desktop.log_file": "로그 파일: {path}",

    # --- report ----------------------------------------------------------------

    "report.title": "조사 보고서",
    "report.generated": "생성됨: {date}",
    "report.target": "대상: {target} ({kind})",
    "report.footer": (
        "ObscuraLens v{version}, {date}에 생성됨"
    ),
    "report.page": "전체 {total} 페이지 중 {page} 페이지",

    "report.sections": "섹션",
    "report.table_of_contents": "목차",

    "report.executive_summary": "요약 보고",
    "report.findings": "조사 결과",
    "report.timeline": "타임라인",
    "report.correlations": "상관 관계",
    "report.sources_section": "소스",
    "report.appendix": "부록: 원본 소스 데이터",

    "report.risk_score": (
        "위험 점수: {score}/100 ({label})"
    ),
    "report.confidence": "신뢰도: {level}",

    "report.no_findings": (
        "이 대상에 대해 기록된 조사 결과가 없습니다."
    ),
    "report.field": "필드",
    "report.value": "값",
    "report.source_column": "소스",

    "report.disclaimer": (
        "이 보고서는 공개적으로 이용 가능한 정보를 기반으로 생성되었으며 조사"
        " 참고 자료로만 사용해야 합니다. 조치를 취하기 전에 각 조사 결과를 독립"
        "적으로 검증해야 합니다. 작성자는 오용에 대한 책임을 지지 않습니다."
    ),

    # --- errors ----------------------------------------------------------------

    "errors.network": (
        "{source}에 연결하는 중 네트워크 오류 발생: {reason}"
    ),
    "errors.timeout": (
        "{source}에 대한 요청이 {seconds}초 후 시간 초과되었습니다."
    ),
    "errors.rate_limited": (
        "{source}의 요청 제한에 걸렸습니다. {seconds}초 후 재시도합니다."
    ),
    "errors.malformed_response": (
        "{source}의 응답 형식이 잘못되었습니다: {reason}"
    ),
    "errors.ssl_error": (
        "{source}에 대한 SSL 검증 실패: {reason}"
    ),

    "errors.invalid_input": "잘못된 입력: {reason}",
    "errors.invalid_format": (
        "지원되지 않는 출력 형식: '{format}'"
    ),
    "errors.not_found": "찾을 수 없음: {target}",
    "errors.no_sources": (
        "유형 '{kind}'에 대해 구성된 소스가 없습니다."
    ),
    "errors.source_unavailable": (
        "소스 '{source}'를 사용할 수 없습니다."
    ),
    "errors.disabled_source": (
        "소스 '{source}'가 구성에서 비활성화되었습니다."
    ),

    "errors.config_missing": (
        "구성 키 '{key}'가 없습니다."
    ),

    "errors.database": "데이터베이스 오류: {reason}",
    "errors.permission_denied": "권한이 거부되었습니다: {path}",
    "errors.disk_full": (
        "{path}을(를) 쓸 디스크 공간이 부족합니다."
    ),
    "errors.offline": "오프라인 모드로 작동 중입니다. {source}을(를) 건너뛰었습니다.",
    "errors.interrupted": "사용자가 중단했습니다.",
    "errors.unexpected": (
        "예기치 않은 오류가 발생했습니다: {reason}"
    ),

    "errors.unknown_language": "알 수 없는 언어 코드: '{code}'",
    "errors.missing_key": "누락된 번역 키: '{key}'",

    # --- plural ----------------------------------------------------------------

    # tp()가 사용하는 복수형 키: 실행 시 개수에 따라 .zero, .one, .many를
    # 선택하며 개수는 항상 {count}로 보간됩니다.
    "plural.results.zero": "결과 없음",
    "plural.results.one": "결과 {count}개",
    "plural.results.many": "결과 {count}개",

    "plural.sources.zero": "소스 없음",
    "plural.sources.one": "소스 {count}개",
    "plural.sources.many": "소스 {count}개",

    "plural.findings.zero": "조사 결과 없음",
    "plural.findings.one": "조사 결과 {count}개",
    "plural.findings.many": "조사 결과 {count}개",

    "plural.matches.zero": "일치 항목 없음",
    "plural.matches.one": "일치 {count}개",
    "plural.matches.many": "일치 {count}개",
}

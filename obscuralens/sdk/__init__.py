"""
ObscuraLens Python SDK — sync and async clients for the ObscuraLens REST API.

The SDK talks to the JSON API exposed by ``obscuralens serve`` (FastAPI,
v5.x): the 14 tracker kinds, investigations, risk scoring, timelines,
correlation, threat intel, cases, the watchlist, graph exports, history,
runtime settings, API-key management, the analyst toolbox, HTML reports,
pattern-of-life analysis, webhook alerts and batch lookups — one typed
method per endpoint.

Stdlib only (urllib under the hood), Python 3.9+, transports injectable,
fully offline-testable via :class:`StaticTransport`.

Quickstart::

    from obscuralens.sdk import ObscuraLensClient

    with ObscuraLensClient("http://127.0.0.1:8000") as client:
        result = client.ip("8.8.8.8")
        print(result.summary())          # "ip 8.8.8.8: 14 field(s) ..."
        print(result.get("country"))     # merged field access
        report = client.risk("domain", "example.com")
        if report.is_high_or_worse():
            print(report.explain())      # weighted risk signals

Async::

    import asyncio
    from obscuralens.sdk import AsyncObscuraLensClient

    async def main():
        async with AsyncObscuraLensClient() as client:
            result = await client.lookup("domain", "example.com")
            ok = await client.ping()
            return result.summary(), ok

    asyncio.run(main())

Every error derives from :exc:`obscuralens.sdk.exceptions.SdkError`;
connection problems retry with exponential backoff and ``Retry-After``
honouring before raising. See ``docs/api.md`` for the server-side
reference of each endpoint.
"""

from .async_client import AsyncObscuraLensClient
from .client import ObscuraLensClient
from .exceptions import (
    ApiError,
    BadRequestError,
    MalformedResponseError,
    NotFoundError,
    RateLimitError,
    SdkError,
    ServerError,
    TimeoutError,
    TransportError,
)
from .models import (
    AlertConfig,
    AlertEntry,
    BatchEntry,
    BatchProgress,
    Case,
    CaseItem,
    CaseNote,
    CorrelationCluster,
    CorrelationResult,
    DiffReport,
    HistoryItem,
    HistoryResult,
    IntelVerdict,
    InvestigationReport,
    KindInfo,
    LookupResult,
    PairComparison,
    PatternFinding,
    PatternReport,
    Provenance,
    RiskReport,
    ServiceKey,
    SourceHealthEntry,
    SourceStatus,
    StatsSummary,
    Timeline,
    TimelineEvent,
    ToolboxResult,
    WatchDiff,
    WatchEntry,
)
from .transport import (
    SDK_USER_AGENT,
    SDK_VERSION,
    Response,
    StaticTransport,
    Transport,
    UrllibTransport,
)

__all__ = [
    'ObscuraLensClient',
    'AsyncObscuraLensClient',
    'Transport',
    'UrllibTransport',
    'StaticTransport',
    'Response',
    'SDK_USER_AGENT',
    'SDK_VERSION',
    'SdkError',
    'TransportError',
    'TimeoutError',
    'ApiError',
    'BadRequestError',
    'NotFoundError',
    'RateLimitError',
    'ServerError',
    'MalformedResponseError',
    'LookupResult',
    'RiskReport',
    'Timeline',
    'TimelineEvent',
    'CorrelationCluster',
    'CorrelationResult',
    'PairComparison',
    'Case',
    'CaseItem',
    'CaseNote',
    'WatchEntry',
    'WatchDiff',
    'DiffReport',
    'SourceStatus',
    'SourceHealthEntry',
    'StatsSummary',
    'InvestigationReport',
    'ToolboxResult',
    'KindInfo',
    'ServiceKey',
    'HistoryItem',
    'HistoryResult',
    'AlertEntry',
    'AlertConfig',
    'PatternFinding',
    'PatternReport',
    'BatchEntry',
    'BatchProgress',
    'IntelVerdict',
    'Provenance',
]

"""
ObscuraLens Python SDK — sync and async clients for the ObscuraLens REST API.

The SDK talks to the JSON API exposed by ``obscuralens serve`` (FastAPI,
v6.x): the 20 tracker kinds (including the six v6.0 sensors ``vin`` /
``flight`` / ``mmsi`` / ``app`` / ``bssid`` / ``plate``), investigations,
risk scoring, timelines, correlation, threat intel, cases, the watchlist,
graph exports, history, runtime settings, API-key management, the analyst
toolbox (with the dork builder), HTML reports, pattern-of-life analysis,
webhook alerts and batch lookups — plus the v6.0 surface: the nine
analytics endpoints, notification channels and broadcasts, the automation
scheduler, the STIX 2.1 / MISP intelligence-sharing exports and the
live-stream topic declaration. One typed method per endpoint, and
:class:`~obscuralens.sdk.session.InvestigationSession` layers a fluent,
step-recording workflow on top.

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

Guided sessions (v6.0)::

    from obscuralens.sdk import InvestigationSession

    with ObscuraLensClient() as client, \
            InvestigationSession(client, label="phishing-2024") as session:
        session.lookup("ip", "1.2.3.4")
        session.note("victim reported 2024-05-01")
        print(session.summary())          # multi-step report
        session.dump("session.json")      # JSON receipt

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
    AnalyticsEnvelope,
    AutomationTasks,
    AutomationTaskView,
    BatchEntry,
    BatchProgress,
    Case,
    CaseItem,
    CaseNote,
    CorrelationCluster,
    CorrelationResult,
    DiffReport,
    DorkReport,
    HistoryItem,
    HistoryResult,
    IntelVerdict,
    InvestigationReport,
    KindInfo,
    LookupResult,
    MispEvent,
    NotifyChannel,
    NotifyChannels,
    NotifyDelivery,
    PairComparison,
    PatternFinding,
    PatternReport,
    Provenance,
    RiskReport,
    ServiceKey,
    SourceHealthEntry,
    SourceStatus,
    StatsSummary,
    StixBundle,
    Timeline,
    TimelineEvent,
    ToolboxResult,
    WatchDiff,
    WatchEntry,
)
from .session import InvestigationSession, SessionStep
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
    'InvestigationSession',
    'SessionStep',
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
    'DorkReport',
    'AnalyticsEnvelope',
    'NotifyChannel',
    'NotifyChannels',
    'NotifyDelivery',
    'AutomationTaskView',
    'AutomationTasks',
    'StixBundle',
    'MispEvent',
]

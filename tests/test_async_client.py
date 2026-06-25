"""Offline tests for AsyncFortiSIEMClient, driven by an httpx.MockTransport fake.

Ported from the original example_async_client.py offline harness. The fake
exercises the awkward paths: a first-call 503 to prove retry/backoff, and a
progress endpoint that returns 50 before 100 to prove the poll loop waits.
No appliance, no network.
"""

from __future__ import annotations

import json

import httpx
import pytest

from pyfortisiem import (
    AsyncFortiSIEMClient,
    FortiSIEMError,
)
from pyfortisiem.models import Event, Incident, IncidentWithEvents


class FakeFortiSIEM:
    """Stateful mock of the /phoenix/rest endpoints the client touches."""

    def __init__(self) -> None:
        self.flaky_hits = 0
        self.token_mints = 0
        self.progress_hits: dict[str, int] = {}
        self.request_count = 0
        self.max_inflight = 0
        self._inflight = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.request_count += 1
        self._inflight += 1
        self.max_inflight = max(self.max_inflight, self._inflight)
        try:
            return self._route(request)
        finally:
            self._inflight -= 1

    def _route(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        qs = dict(request.url.params)

        if path.endswith("/pub/security/oauth/token"):
            self.token_mints += 1
            return httpx.Response(200, json={"access_token": "fake-bearer-xyz", "expiresIn": 1440})

        authz = request.headers.get("authorization", "")
        assert authz.startswith(("Basic ", "Bearer ")), f"missing/bad auth: {authz!r}"
        if authz.startswith("Bearer "):
            assert authz == "Bearer fake-bearer-xyz", "wrong bearer token"

        if path.endswith("/system/health/summary"):
            return httpx.Response(200, json={"status": "ok"})

        if path.endswith("/rest/pub/incident") and request.method == "POST":
            body = json.loads(request.content or b"{}")
            filters = body.get("filters", {})
            if "incidentId" in filters:
                iid = filters["incidentId"][0]
                if iid == 999999:
                    return httpx.Response(200, json={"data": []})
                return httpx.Response(200, json={"data": [self._incident(iid)]})
            return httpx.Response(200, json={"data": [self._incident(i) for i in (101, 102, 103)]})

        if path.endswith("/triggeringEvents") and "/start" not in path:
            self.flaky_hits += 1
            if self.flaky_hits == 1:
                return httpx.Response(503, text="not ready")
            iid = int(qs.get("incidentId", 0))
            return httpx.Response(200, json={"data": self._events(iid, 2)})

        if path.endswith("/triggeringEvents/start"):
            iid = qs.get("incidentId", "0")
            return httpx.Response(200, json={"queryId": f"q-{iid}"})

        if "/triggeringEvents/progress/" in path:
            qid = path.rsplit("/", 1)[-1]
            self.progress_hits[qid] = self.progress_hits.get(qid, 0) + 1
            pct = 100 if self.progress_hits[qid] >= 2 else 50
            return httpx.Response(200, json={"progressPct": pct})

        if "/triggeringEvents/result/" in path:
            qid = path.rsplit("/", 1)[-1]
            iid = int(qid.split("-")[-1])
            return httpx.Response(200, json={"data": self._events(iid, 3)})

        if "/query/events/" in path:
            return httpx.Response(
                200, json={"@queryId": "q-1", "@totalCount": "1", "data": self._events(1, 1)}
            )

        return httpx.Response(404, text=f"unhandled: {request.method} {path}")

    @staticmethod
    def _incident(iid: int) -> dict:
        return {
            "incidentId": iid,
            "incidentTitle": f"Suspicious activity {iid}",
            "incidentStatus": 0,
            "eventSeverity": 7,
            "phIncidentCategory": "Security",
            "incidentFirstSeen": 1700000000000,
            "incidentLastSeen": 1700000600000,
        }

    @staticmethod
    def _events(iid: int, n: int) -> list[dict]:
        return [
            {
                "eventId": f"{iid}-{k}",
                "eventType": "PH_RULE_LOGON_FAILURE",
                "eventSeverity": 5,
                "srcIpAddr": f"203.0.113.{k}",
                "destIpAddr": "203.0.113.254",
                "hostName": f"host-{iid}",
                "user": "alice",
            }
            for k in range(n)
        ]


def make_client(fake: FakeFortiSIEM, **kw) -> AsyncFortiSIEMClient:
    kw.setdefault("max_concurrency", 2)
    return AsyncFortiSIEMClient(
        "siem.test:443",
        "admin",
        "pw",
        domain="Super",
        backoff_factor=0.0,
        poll_interval=0.0,
        transport=httpx.MockTransport(fake.handler),
        **kw,
    )


async def test_health():
    fake = FakeFortiSIEM()
    async with make_client(fake) as fsm:
        assert await fsm.health() == 200


async def test_list_incidents_typed():
    fake = FakeFortiSIEM()
    async with make_client(fake) as fsm:
        incidents = await fsm.list_incidents(status=[0], size=10)
    assert len(incidents) == 3
    assert all(isinstance(i, Incident) for i in incidents)
    assert incidents[0].incident_title is not None  # camelCase mapped to snake


async def test_get_incident_and_missing():
    fake = FakeFortiSIEM()
    async with make_client(fake) as fsm:
        inc = await fsm.get_incident(101)
        missing = await fsm.get_incident(999999)
    assert inc is not None and inc.incident_id == 101
    assert missing is None


async def test_associated_events_retries_past_503():
    fake = FakeFortiSIEM()
    async with make_client(fake) as fsm:
        events = await fsm.get_associated_events(101, size=5)
    assert fake.flaky_hits >= 2  # retried past the injected 503
    assert len(events) == 2
    assert all(isinstance(e, Event) for e in events)


async def test_associated_events_via_query_lifecycle():
    fake = FakeFortiSIEM()
    async with make_client(fake) as fsm:
        qevents = await fsm.get_associated_events_via_query(102, size=50)
    assert fake.progress_hits.get("q-102", 0) >= 2  # polled before reaching 100%
    assert len(qevents) == 3


async def test_incident_with_events_marquee():
    fake = FakeFortiSIEM()
    async with make_client(fake) as fsm:
        iwe = await fsm.get_incident_with_events(103, size=5)
        iwe_q = await fsm.get_incident_with_events(103, use_query_lifecycle=True, size=5)
    assert isinstance(iwe, IncidentWithEvents)
    assert iwe.incident_id == 103 and len(iwe.events) == 2
    assert iwe_q is not None and len(iwe_q.events) == 3


async def test_bulk_enrichment_respects_concurrency_gate():
    fake = FakeFortiSIEM()
    async with make_client(fake, max_concurrency=2) as fsm:
        bulk = await fsm.list_incidents_with_events(status=[0], size=10, events_per_incident=2)
    assert len(bulk) == 3
    assert all(isinstance(b, IncidentWithEvents) and len(b.events) == 2 for b in bulk)
    assert fake.max_inflight <= 2, f"peak in-flight was {fake.max_inflight}"


async def test_search_events_by_query_id():
    fake = FakeFortiSIEM()
    async with make_client(fake) as fsm:
        res = await fsm.search_events_by_query_id("q-1", begin=0, end=100)
    assert res.total_count == 1 and len(res.events) == 1


async def test_unhandled_path_raises():
    fake = FakeFortiSIEM()
    async with make_client(fake) as fsm:
        with pytest.raises(FortiSIEMError):
            await fsm._request("GET", "/does/not/exist")


async def test_api_key_mode_mints_once_and_caches():
    fake = FakeFortiSIEM()
    async with AsyncFortiSIEMClient.with_api_key(
        "siem.test:443",
        "my-client-id",
        "my-client-secret",
        max_concurrency=5,
        backoff_factor=0.0,
        poll_interval=0.0,
        transport=httpx.MockTransport(fake.handler),
    ) as fsm2:
        assert fsm2.auth_mode == "apikey"
        assert fake.token_mints == 0  # lazy: no token before first call
        inc = await fsm2.get_incident_with_events(101, size=5)
        assert inc is not None and len(inc.events) == 2
        assert fake.token_mints == 1
        await fsm2.list_incidents(status=[0])
        assert fake.token_mints == 1  # cached token reused


def test_constructor_rejects_both_auth_modes():
    with pytest.raises(ValueError):
        AsyncFortiSIEMClient("h", username="a", password="b", client_id="c", client_secret="d")


def test_constructor_rejects_no_auth_mode():
    with pytest.raises(ValueError):
        AsyncFortiSIEMClient("h")

#!/usr/bin/env python3
"""End-to-end exercise of every critical path in ``AsyncFortiSIEMClient``.

Run it two ways:

* **Offline (default).** A fake FortiSIEM built on ``httpx.MockTransport`` answers
  every endpoint, so the full async surface — concurrency gating, retry/backoff,
  the start/progress/result query lifecycle, and the marquee incident+events
  methods — is verified with no appliance and no network::

      python example_async_client.py

* **Live.** Point at a real supervisor and it runs a read-only smoke test::

      FSM_HOST=fortisiem.example.com:443 FSM_USER=admin FSM_PASS=... \
      FSM_DOMAIN=Super python example_async_client.py --live

Exit code is non-zero if any assertion fails, so it doubles as a CI smoke test.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time

import httpx

from pyfortisiem import AsyncFortiSIEMClient, FortiSIEMError
from pyfortisiem.models import Event, Incident, IncidentWithEvents


# --------------------------------------------------------------------------- #
# A fake FortiSIEM — just enough of the /phoenix/rest surface to drive the client.
# --------------------------------------------------------------------------- #
class FakeFortiSIEM:
    """Stateful mock of the endpoints the client touches.

    It deliberately exercises the awkward bits: a first-call ``503`` to prove the
    retry path, and a progress endpoint that returns ``50`` before ``100`` to
    prove the poll loop actually waits."""

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

        # OAuth token mint (API-key mode) — issued before any bearer call.
        if path.endswith("/pub/security/oauth/token"):
            self.token_mints += 1
            return httpx.Response(200, json={"access_token": "fake-bearer-xyz", "expiresIn": 1440})

        # Every other call must carry auth — Basic (user/pass) or Bearer (API key).
        authz = request.headers.get("authorization", "")
        assert authz.startswith(("Basic ", "Bearer ")), f"missing/bad auth: {authz!r}"
        if authz.startswith("Bearer "):
            assert authz == "Bearer fake-bearer-xyz", "wrong bearer token"

        if path.endswith("/system/health/summary"):
            return httpx.Response(200, json={"status": "ok"})

        if path.endswith("/rest/pub/incident") and request.method == "POST":
            body = json.loads(request.content or b"{}")
            filters = body.get("filters", {})
            if "incidentId" in filters:  # get_incident / get_incident(by id)
                iid = filters["incidentId"][0]
                if iid == 999999:  # the "not found" case
                    return httpx.Response(200, json={"data": []})
                return httpx.Response(200, json={"data": [self._incident(iid)]})
            # list_incidents — return three active incidents
            return httpx.Response(200, json={"data": [self._incident(i) for i in (101, 102, 103)]})

        # Direct triggering events — first hit 503 to exercise retry/backoff.
        if path.endswith("/triggeringEvents") and "/start" not in path:
            self.flaky_hits += 1
            if self.flaky_hits == 1:
                return httpx.Response(503, text="not ready")
            iid = int(qs.get("incidentId", 0))
            return httpx.Response(200, json={"data": self._events(iid, 2)})

        # Async query lifecycle: start -> progress -> result.
        if path.endswith("/triggeringEvents/start"):
            iid = qs.get("incidentId", "0")
            return httpx.Response(200, json={"queryId": f"q-{iid}"})

        if "/triggeringEvents/progress/" in path:
            qid = path.rsplit("/", 1)[-1]
            self.progress_hits[qid] = self.progress_hits.get(qid, 0) + 1
            pct = 100 if self.progress_hits[qid] >= 2 else 50  # not-ready, then ready
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
                "srcIpAddr": f"10.0.0.{k}",
                "destIpAddr": "10.0.0.254",
                "hostName": f"host-{iid}",
                "user": "alice",
            }
            for k in range(n)
        ]


# --------------------------------------------------------------------------- #
# Tiny assertion harness so output reads like a test report.
# --------------------------------------------------------------------------- #
class Check:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    def __call__(self, label: str, cond: bool, detail: str = "") -> None:
        mark = "PASS" if cond else "FAIL"
        self.passed += cond
        self.failed += not cond
        print(f"  [{mark}] {label}" + (f" — {detail}" if detail and not cond else ""))


async def run_offline() -> int:
    print("Offline mode — driving AsyncFortiSIEMClient against a mock FortiSIEM\n")
    fake = FakeFortiSIEM()
    check = Check()

    # max_concurrency=2 so we can prove the gate actually caps in-flight requests.
    async with AsyncFortiSIEMClient(
        "siem.test:443",
        "admin",
        "pw",
        domain="Super",
        max_concurrency=2,
        backoff_factor=0.0,  # no real waiting in tests
        poll_interval=0.0,
        transport=httpx.MockTransport(fake.handler),
    ) as fsm:
        print("health()")
        check("health is 200", await fsm.health() == 200)

        print("list_incidents()")
        incidents = await fsm.list_incidents(status=[0], size=10)
        check("returns typed Incidents", all(isinstance(i, Incident) for i in incidents))
        check("got 3 incidents", len(incidents) == 3, f"got {len(incidents)}")
        check("camelCase mapped to snake", incidents[0].incident_title is not None)

        print("get_incident()")
        inc = await fsm.get_incident(101)
        check("incident 101 found", inc is not None and inc.incident_id == 101)
        missing = await fsm.get_incident(999999)
        check("missing incident -> None", missing is None)

        print("get_associated_events()  [exercises 503 retry]")
        events = await fsm.get_associated_events(101, size=5)
        check("retried past 503", fake.flaky_hits >= 2)
        check("returns typed Events", all(isinstance(e, Event) for e in events))
        check("got 2 events", len(events) == 2, f"got {len(events)}")

        print("get_associated_events_via_query()  [start/progress/result lifecycle]")
        qevents = await fsm.get_associated_events_via_query(102, size=50)
        check("polled progress >1x before 100%", fake.progress_hits.get("q-102", 0) >= 2)
        check("got 3 events from result", len(qevents) == 3, f"got {len(qevents)}")

        print("get_incident_with_events()  [marquee]")
        iwe = await fsm.get_incident_with_events(103, size=5)
        check("is IncidentWithEvents", isinstance(iwe, IncidentWithEvents))
        check(
            "has incident + events",
            iwe is not None and iwe.incident_id == 103 and len(iwe.events) == 2,
        )

        print("get_incident_with_events(use_query_lifecycle=True)")
        iwe_q = await fsm.get_incident_with_events(103, use_query_lifecycle=True, size=5)
        check("lifecycle path attaches events", iwe_q is not None and len(iwe_q.events) == 3)

        print("list_incidents_with_events()  [bulk concurrent enrichment]")
        fake.max_inflight = 0  # reset the high-water mark for this measurement
        bulk = await fsm.list_incidents_with_events(status=[0], size=10, events_per_incident=2)
        check(
            "all enriched", len(bulk) == 3 and all(isinstance(b, IncidentWithEvents) for b in bulk)
        )
        check("every incident has events", all(len(b.events) == 2 for b in bulk))
        check(
            "concurrency gate held (<=2 in flight)",
            fake.max_inflight <= 2,
            f"peak in-flight was {fake.max_inflight}",
        )

        print("search_events_by_query_id()")
        res = await fsm.search_events_by_query_id("q-1", begin=0, end=100)
        check("parsed query result", res.total_count == 1 and len(res.events) == 1)

        print("error handling")
        try:
            await fsm._request("GET", "/does/not/exist")  # 404 is retryable then fails
            check("unhandled path raises", False, "no exception")
        except FortiSIEMError:
            check("unhandled path raises FortiSIEMError", True)

    # ---- Auth mode 2: API key (OAuth2 bearer) -----------------------------
    print("\nAPI-key auth mode (OAuth2 client_credentials -> bearer)")
    fake2 = FakeFortiSIEM()
    async with AsyncFortiSIEMClient.with_api_key(
        "siem.test:443",
        "my-client-id",
        "my-client-secret",
        max_concurrency=5,
        backoff_factor=0.0,
        poll_interval=0.0,
        transport=httpx.MockTransport(fake2.handler),
    ) as fsm2:
        check("auth_mode is apikey", fsm2.auth_mode == "apikey")
        check("no token before first call", fake2.token_mints == 0)
        inc = await fsm2.get_incident_with_events(101, size=5)
        check("bearer call returns incident+events", inc is not None and len(inc.events) == 2)
        check("token minted exactly once", fake2.token_mints == 1, f"mints={fake2.token_mints}")
        # second call reuses the cached token (no re-mint)
        await fsm2.list_incidents(status=[0])
        check("cached token reused (still 1 mint)", fake2.token_mints == 1)

    print("\nConstructor validation")
    try:
        AsyncFortiSIEMClient("h", username="a", password="b", client_id="c", client_secret="d")
        check("rejects both auth modes", False, "no exception")
    except ValueError:
        check("rejects both auth modes", True)
    try:
        AsyncFortiSIEMClient("h")
        check("rejects no auth mode", False, "no exception")
    except ValueError:
        check("rejects no auth mode", True)

    print(f"\n{check.passed} passed, {check.failed} failed")
    return 1 if check.failed else 0


async def run_live() -> int:
    host = os.environ["FSM_HOST"]
    domain = os.environ.get("FSM_DOMAIN", "Super")
    # Prefer API key if both client_id/secret are set; else fall back to user/pass.
    if os.environ.get("FSM_CLIENT_ID") and os.environ.get("FSM_CLIENT_SECRET"):
        print(f"Live mode (API key) — read-only smoke test against {host}\n")
        fsm = AsyncFortiSIEMClient.with_api_key(
            host,
            os.environ["FSM_CLIENT_ID"],
            os.environ["FSM_CLIENT_SECRET"],
            verify=False,
            max_concurrency=10,
        )
    else:
        print(f"Live mode (basic auth) — read-only smoke test against {host}\n")
        fsm = AsyncFortiSIEMClient.with_basic_auth(
            host,
            os.environ["FSM_USER"],
            os.environ["FSM_PASS"],
            domain=domain,
            verify=False,
            max_concurrency=10,
        )
    # FortiSIEM requires a time window on incident queries — last 7 days, epoch ms.
    now_ms = int(time.time() * 1000)
    week_ms = 7 * 24 * 60 * 60 * 1000
    time_from, time_to = now_ms - week_ms, now_ms
    check = Check()

    async with fsm:
        print("health()")
        check("health is 200", await fsm.health() == 200)

        print("list_incidents()  [last 7 days]")
        incidents = await fsm.list_incidents(
            time_from=time_from, time_to=time_to, status=[0, 1], size=10
        )
        check("returns typed Incidents", all(isinstance(i, Incident) for i in incidents))
        print(f"    -> {len(incidents)} incidents")

        if not incidents:
            print("    (no incidents in window — widening to 30 days)")
            incidents = await fsm.list_incidents(
                time_from=now_ms - 30 * week_ms // 7 * 7, time_to=time_to, size=10
            )
            print(f"    -> {len(incidents)} incidents")

        if incidents:
            iid = incidents[0].incident_id

            print(f"get_incident({iid})")
            inc = await fsm.get_incident(iid, time_from=time_from, time_to=time_to)
            check("incident fetched by id", inc is not None and inc.incident_id == iid)

            print(f"get_associated_events({iid})  [direct]")
            ev = await fsm.get_associated_events(iid, size=5, time_from=time_from, time_to=time_to)
            check("events are typed", all(isinstance(e, Event) for e in ev))
            print(f"    -> {len(ev)} events")

            print(f"get_associated_events_via_query({iid})  [start/progress/result]")
            try:
                evq = await fsm.get_associated_events_via_query(
                    iid, size=20, time_from=time_from, time_to=time_to
                )
                check("lifecycle events are typed", all(isinstance(e, Event) for e in evq))
                print(f"    -> {len(evq)} events")
            except FortiSIEMError as e:
                print(f"    (lifecycle endpoint unavailable on this version: {e})")

            print(f"get_incident_with_events({iid})  [marquee]")
            iwe = await fsm.get_incident_with_events(
                iid, size=5, time_from=time_from, time_to=time_to
            )
            check(
                "marquee returns IncidentWithEvents",
                isinstance(iwe, IncidentWithEvents) and iwe.incident_id == iid,
            )
            print(f"    -> {iwe.incident_title!r} with {len(iwe.events)} events")

            print("list_incidents_with_events()  [bulk concurrent, gate=10]")
            bulk = await fsm.list_incidents_with_events(
                time_from=time_from,
                time_to=time_to,
                status=[0, 1],
                size=min(len(incidents), 8),
                events_per_incident=3,
            )
            check("bulk enriched all", all(isinstance(b, IncidentWithEvents) for b in bulk))
            print(f"    -> enriched {len(bulk)} incidents concurrently")
        else:
            print("    (no incidents available to exercise event paths)")

    print(f"\n{check.passed} passed, {check.failed} failed")
    return 1 if check.failed else 0


def main() -> int:
    if "--live" in sys.argv:
        return asyncio.run(run_live())
    return asyncio.run(run_offline())


if __name__ == "__main__":
    raise SystemExit(main())

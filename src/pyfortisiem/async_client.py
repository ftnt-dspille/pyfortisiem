"""Fully-async, fully-typed FortiSIEM REST client focused on incidents + events.

Why this exists
---------------
FortiSIEM event retrieval is *server-side asynchronous*: you submit a query, the
supervisor hands you a ``queryId``, you poll a progress endpoint until it reaches
100%, then you page the result. The triggering-events surface for an incident
behaves the same way (``triggeringEvents/start`` -> ``progress`` -> ``result``).
That maps cleanly onto ``asyncio``: every poll loop is an ``await`` instead of a
blocking ``time.sleep``, and many incidents can be enriched concurrently.

This mirrors the production FortiSOAR connector's async path
(``ConnectorsV2/fortisiem/.../connections.py``: ``MAX_CONCURRENT_REQUESTS = 10``,
``async_make_rest_call`` with a ``Semaphore``) but improves on it:

* one pooled ``httpx.AsyncClient`` instead of a fresh ``aiohttp.ClientSession``
  per request,
* a single shared, **configurable** concurrency gate (default 10),
* genuine end-to-end ``async`` (no ``loop.run_until_complete`` bridge),
* typed return values (``Incident`` / ``Event`` / ``IncidentWithEvents``).

Auth surface here is **basic auth** against the public ``/phoenix/rest/...`` API
(the simplest surface, good for incident/event reads). For OAuth-token and MCP
work, use the synchronous :class:`fortisiem_client.FortiSIEMClient`.

Quick start
-----------
    async with AsyncFortiSIEMClient("fortisiem.example.com:443", "admin", "pw",
                                    domain="Super", max_concurrency=10) as fsm:
        # one incident + its evidence
        inc = await fsm.get_incident_with_events(123456)
        print(inc.incident_title, len(inc.events))

        # many incidents, enriched concurrently under the concurrency gate
        incs = await fsm.list_incidents_with_events(status=[0], size=50)
"""

from __future__ import annotations

import asyncio
import base64
from types import TracebackType

import httpx

from .exceptions import FortiSIEMError
from .models import (
    Event,
    EventQueryResult,
    Incident,
    IncidentWithEvents,
)

__all__ = ["AsyncFortiSIEMClient"]


# Retry/poll knobs (overridable per-instance via the constructor).
_DEFAULT_MAX_CONCURRENCY = 10
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_BACKOFF = 0.5  # seconds, multiplied by attempt number
_DEFAULT_POLL_INTERVAL = 2.0  # seconds between progress polls
_DEFAULT_POLL_TIMEOUT = 120.0  # give up waiting for a query after this long
# HTTP statuses FortiSIEM uses to mean "not ready yet, back off and retry".
_RETRY_STATUSES = frozenset({429, 503, 404})


class AsyncFortiSIEMClient:
    """Async client over FortiSIEM's incident/event REST surface.

    Two auth modes, both valid against the public ``/rest/pub/...`` surface:

    * **User/pass/org (basic auth)** — pass ``username`` + ``password`` (+ optional
      ``domain``). The account is org-qualified on the wire (``super/admin``).
    * **API key (OAuth2 ``client_credentials`` -> bearer)** — pass ``client_id`` +
      ``client_secret``. The client mints a bearer token lazily on first request,
      caches it, and silently re-mints once on a ``401`` (token expiry). This is
      the same credential FortiSIEM's *API Token* feature issues and the only auth
      the MCP endpoint accepts.

    Provide **exactly one** mode. Use the classmethods for clarity::

        AsyncFortiSIEMClient.with_basic_auth(host, "admin", "pw", domain="Super")
        AsyncFortiSIEMClient.with_api_key(host, client_id, client_secret)

    Args:
        host: ``host:port`` of the supervisor, e.g. ``fortisiem.example.com:443``.
        username / password: basic-auth account + password.
        domain: organization/domain for basic auth; ``Super`` for super-global.
        client_id / client_secret: API-key (OAuth2 client_credentials) material.
        verify: TLS verification (``False`` for self-signed lab certs).
        max_concurrency: ceiling on in-flight requests — the "max thread limit"
            of concurrent sessions. Defaults to 10; raise/lower as needed.
        timeout: per-request timeout in seconds.
        max_retries: attempts on transient (429/503/404) responses.
        backoff_factor: base seconds for linear backoff between retries.
        poll_interval / poll_timeout: cadence and ceiling for query progress
            polling.
    """

    def __init__(
        self,
        host: str,
        username: str | None = None,
        password: str | None = None,
        *,
        domain: str = "Super",
        client_id: str | None = None,
        client_secret: str | None = None,
        verify: bool = False,
        max_concurrency: int = _DEFAULT_MAX_CONCURRENCY,
        timeout: float = 30.0,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        backoff_factor: float = _DEFAULT_BACKOFF,
        poll_interval: float = _DEFAULT_POLL_INTERVAL,
        poll_timeout: float = _DEFAULT_POLL_TIMEOUT,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")

        basic = username is not None and password is not None
        apikey = client_id is not None and client_secret is not None
        if basic == apikey:  # both or neither
            raise ValueError(
                "Provide exactly one auth mode: username+password (basic) OR "
                "client_id+client_secret (api key)."
            )

        self.base = f"https://{host}".rstrip("/")
        self.phoenix = f"{self.base}/phoenix"
        self.username = username
        self.password = password
        self.domain = domain
        self.client_id = client_id
        self._client_secret = client_secret
        self.auth_mode = "basic" if basic else "apikey"
        # Org-qualified basic-auth user, precomputed (basic mode only).
        self._basic_user = f"{domain.lower()}/{username}" if basic else None
        self._bearer: str | None = None  # cached OAuth token (apikey mode)
        self._token_lock = asyncio.Lock()

        self._max_retries = max_retries
        self._backoff = backoff_factor
        self._poll_interval = poll_interval
        self._poll_timeout = poll_timeout

        self._max_concurrency = max_concurrency
        self._sem = asyncio.Semaphore(max_concurrency)
        # One pooled client, capped so the pool can't exceed the concurrency gate.
        # Auth is applied per-request (not via httpx's auth=) so basic and bearer
        # share one code path and bearer re-minting stays in our control.
        limits = httpx.Limits(
            max_connections=max_concurrency,
            max_keepalive_connections=max_concurrency,
        )
        self._client = httpx.AsyncClient(
            verify=verify,
            timeout=timeout,
            limits=limits,
            transport=transport,  # injectable for offline testing
        )

    # ----------------------------------------------------------- constructors
    @classmethod
    def with_basic_auth(
        cls, host: str, username: str, password: str, *, domain: str = "Super", **kw
    ) -> AsyncFortiSIEMClient:
        """Build a client that authenticates with user/password/org (basic auth)."""
        return cls(host, username, password, domain=domain, **kw)

    @classmethod
    def with_api_key(
        cls, host: str, client_id: str, client_secret: str, **kw
    ) -> AsyncFortiSIEMClient:
        """Build a client that authenticates with an API key (OAuth2 bearer)."""
        return cls(host, client_id=client_id, client_secret=client_secret, **kw)

    # ----------------------------------------------------------------- lifecycle
    async def __aenter__(self) -> AsyncFortiSIEMClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    @property
    def max_concurrency(self) -> int:
        """The configured concurrency ceiling (max simultaneous in-flight requests)."""
        return self._max_concurrency

    # ------------------------------------------------------------------ auth
    async def _auth_header(self, *, force_refresh: bool = False) -> dict[str, str]:
        """The ``Authorization`` header for the active auth mode.

        Basic mode: a precomputed ``Basic`` header. API-key mode: a cached
        ``Bearer`` token, minted on first use (and re-minted when
        ``force_refresh`` is set, e.g. after a ``401``)."""
        if self.auth_mode == "basic":
            token = base64.b64encode(f"{self._basic_user}:{self.password}".encode()).decode()
            return {"Authorization": f"Basic {token}"}
        # API-key (bearer). Mint under a lock so concurrent callers share one token.
        if self._bearer is None or force_refresh:
            async with self._token_lock:
                if self._bearer is None or force_refresh:
                    self._bearer = await self._mint_token()
        return {"Authorization": f"Bearer {self._bearer}"}

    async def _mint_token(self) -> str:
        """Exchange client_id/secret for an OAuth2 bearer access token."""
        url = f"{self.phoenix}/rest/pub/security/oauth/token"
        async with self._sem:
            resp = await self._client.post(
                url,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self._client_secret,
                },
            )
        if not resp.is_success:
            raise FortiSIEMError(
                f"OAuth token mint failed ({resp.status_code}): {resp.text[:200]!r}"
            )
        try:
            return resp.json()["access_token"]
        except (ValueError, KeyError) as e:
            raise FortiSIEMError(f"OAuth token response missing access_token: {e}") from e

    # ------------------------------------------------------------------ transport
    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json: dict | None = None,
        data: str | None = None,
        headers: dict | None = None,
        expect_json: bool = True,
    ) -> object:
        """Issue one request under the concurrency gate, applying auth and
        retrying transient statuses with linear backoff. In API-key mode a single
        ``401`` triggers a token re-mint and one extra attempt."""
        url = f"{self.phoenix}/rest/{path.lstrip('/')}"
        last_exc: Exception | None = None
        reminted = False
        for attempt in range(1, self._max_retries + 1):
            req_headers = {**(headers or {}), **await self._auth_header()}
            async with self._sem:  # the "max sessions" gate
                try:
                    resp = await self._client.request(
                        method, url, params=params, json=json, data=data, headers=req_headers
                    )
                except httpx.HTTPError as e:  # connect/timeout/transport
                    last_exc = e
                    await self._sleep_backoff(attempt)
                    continue

            # API-key token expiry: re-mint once and retry immediately.
            if resp.status_code == 401 and self.auth_mode == "apikey" and not reminted:
                reminted = True
                await self._auth_header(force_refresh=True)
                continue
            if resp.status_code in _RETRY_STATUSES:
                last_exc = FortiSIEMError(
                    f"{resp.status_code} on {method} {path}: {resp.text[:200]!r}"
                )
                await self._sleep_backoff(attempt)
                continue
            if resp.is_success:
                if not expect_json:
                    return resp.text
                try:
                    return resp.json()
                except ValueError:
                    return resp.text
            # Non-retryable error status.
            raise FortiSIEMError(f"{resp.status_code} on {method} {path}: {resp.text[:300]!r}")
        raise FortiSIEMError(
            f"{method} {path} failed after {self._max_retries} attempts: {last_exc}"
        )

    async def _sleep_backoff(self, attempt: int) -> None:
        await asyncio.sleep(self._backoff * attempt)

    # ------------------------------------------------------------------- health
    async def health(self) -> int:
        """System-health summary HTTP status (200 == reachable + authorized)."""
        url = f"{self.phoenix}/rest/system/health/summary"
        async with self._sem:
            resp = await self._client.get(url, headers=await self._auth_header())
        return resp.status_code

    # ---------------------------------------------------------------- incidents
    async def list_incidents(
        self,
        *,
        time_from: int | None = None,
        time_to: int | None = None,
        status: list[int] | None = None,
        size: int = 100,
        start: int = 0,
        order_by: str = "incidentLastSeen",
        descending: bool = True,
        extra_filters: dict | None = None,
    ) -> list[Incident]:
        """List incidents from ``/rest/pub/incident``.

        ``time_from`` / ``time_to`` are epoch **milliseconds**. ``status`` filters
        on incident status codes (``0`` == active). Returns typed ``Incident``s."""
        filters: dict = {}
        if status is not None:
            filters["status"] = status
        if extra_filters:
            filters.update(extra_filters)
        payload: dict = {
            "size": size,
            "start": start,
            "orderBy": order_by,
            "descending": descending,
        }
        if time_from is not None:
            payload["timeFrom"] = time_from
        if time_to is not None:
            payload["timeTo"] = time_to
        if filters:
            payload["filters"] = filters

        body = await self._request("POST", "/pub/incident", json=payload)
        rows = body.get("data", []) if isinstance(body, dict) else []
        return [Incident.model_validate(r) for r in rows]

    async def get_incident(
        self,
        incident_id: int,
        *,
        time_from: int | None = None,
        time_to: int | None = None,
    ) -> Incident | None:
        """Fetch a single incident by id. ``None`` if not found.

        FortiSIEM requires a time range on incident queries; pass ``time_from`` /
        ``time_to`` (epoch ms) covering when the incident was seen."""
        payload: dict = {"filters": {"incidentId": [incident_id]}, "size": 1}
        if time_from is not None:
            payload["timeFrom"] = time_from
        if time_to is not None:
            payload["timeTo"] = time_to
        body = await self._request("POST", "/pub/incident", json=payload)
        rows = body.get("data", []) if isinstance(body, dict) else []
        return Incident.model_validate(rows[0]) if rows else None

    # ----------------------------------------------------- associated events (simple)
    async def get_associated_events(
        self,
        incident_id: int,
        *,
        size: int = 10,
        time_from: int | None = None,
        time_to: int | None = None,
    ) -> list[Event]:
        """Events that triggered an incident, via the *direct*
        ``/rest/pub/incident/triggeringEvents`` endpoint (no polling)."""
        params: dict = {"incidentId": incident_id, "size": size}
        if time_from is not None:
            params["timeFrom"] = time_from
        if time_to is not None:
            params["timeTo"] = time_to
        body = await self._request("GET", "/pub/incident/triggeringEvents", params=params)
        rows = body.get("data", []) if isinstance(body, dict) else (body or [])
        return [Event.model_validate(r) for r in rows]

    # ------------------------------------------- associated events (async query lifecycle)
    async def get_associated_events_via_query(
        self,
        incident_id: int,
        *,
        size: int = 50,
        time_from: int | None = None,
        time_to: int | None = None,
    ) -> list[Event]:
        """Events for an incident via the *asynchronous* start/progress/result
        lifecycle — the right path when the direct endpoint truncates or for
        large evidence sets.

        Steps: ``triggeringEvents/start`` (-> queryId) -> poll
        ``triggeringEvents/progress/{queryId}`` to 100% -> page
        ``triggeringEvents/result/{queryId}``."""
        params: dict = {"incidentId": incident_id, "size": size}
        if time_from is not None:
            params["timeFrom"] = time_from
        if time_to is not None:
            params["timeTo"] = time_to
        started = await self._request("GET", "/pub/incident/triggeringEvents/start", params=params)
        query_id = started.get("queryId") if isinstance(started, dict) else started
        if not query_id:
            raise FortiSIEMError(f"No queryId returned for incident {incident_id}: {started!r}")

        await self._await_query(f"/pub/incident/triggeringEvents/progress/{query_id}")

        result_path = f"/pub/incident/triggeringEvents/result/{query_id}"
        body = await self._request("GET", result_path, params={"size": size})
        rows = body.get("data", []) if isinstance(body, dict) else (body or [])
        return [Event.model_validate(r) for r in rows]

    async def _await_query(self, progress_path: str) -> None:
        """Poll a progress endpoint until ``progressPct == 100`` or timeout."""
        waited = 0.0
        while waited <= self._poll_timeout:
            body = await self._request("GET", progress_path)
            pct = body.get("progressPct") if isinstance(body, dict) else body
            if str(pct) == "100":
                return
            await asyncio.sleep(self._poll_interval)
            waited += self._poll_interval
        raise FortiSIEMError(
            f"Query {progress_path} did not reach 100% within {self._poll_timeout}s"
        )

    # --------------------------------------------------------- marquee: incident+events
    async def get_incident_with_events(
        self,
        incident_id: int,
        *,
        size: int = 10,
        use_query_lifecycle: bool = False,
        time_from: int | None = None,
        time_to: int | None = None,
    ) -> IncidentWithEvents | None:
        """One call: the incident **and** its associated events, fetched
        concurrently. ``use_query_lifecycle`` switches to the start/progress/
        result path for large evidence sets."""
        fetch_events = (
            self.get_associated_events_via_query
            if use_query_lifecycle
            else self.get_associated_events
        )
        incident, events = await asyncio.gather(
            self.get_incident(incident_id, time_from=time_from, time_to=time_to),
            fetch_events(incident_id, size=size, time_from=time_from, time_to=time_to),
        )
        if incident is None:
            return None
        return IncidentWithEvents.from_incident(incident, events)

    async def list_incidents_with_events(
        self,
        *,
        time_from: int | None = None,
        time_to: int | None = None,
        status: list[int] | None = None,
        size: int = 50,
        events_per_incident: int = 10,
        use_query_lifecycle: bool = False,
    ) -> list[IncidentWithEvents]:
        """List incidents and enrich each with its events **concurrently**,
        bounded by ``max_concurrency``. This is the bulk version of the marquee
        method — the connector's ``asyncio.gather`` pattern, but the shared
        semaphore keeps total in-flight requests under the configured ceiling."""
        incidents = await self.list_incidents(
            time_from=time_from, time_to=time_to, status=status, size=size
        )
        fetch_events = (
            self.get_associated_events_via_query
            if use_query_lifecycle
            else self.get_associated_events
        )

        async def _enrich(inc: Incident) -> IncidentWithEvents:
            events = await fetch_events(
                inc.incident_id, size=events_per_incident, time_from=time_from, time_to=time_to
            )
            return IncidentWithEvents.from_incident(inc, events)

        return list(await asyncio.gather(*(_enrich(i) for i in incidents)))

    # --------------------------------------------------------- general event search
    async def search_events_by_query_id(
        self, query_id: str, *, begin: int = 0, end: int = 1000
    ) -> EventQueryResult:
        """Page already-completed event-query results by ``queryId`` using the
        ``/rest/query/events/{id}/{begin}/{end}`` surface. Returns parsed events
        when the response is JSON; raw text is preserved on the envelope's
        ``extra`` for XML-only FortiSIEM versions."""
        path = f"/query/events/{query_id}/{begin}/{end}"
        body = await self._request("GET", path, expect_json=True)
        if isinstance(body, dict):
            rows = body.get("data") or body.get("events") or []
            events = [Event.model_validate(r) for r in rows] if isinstance(rows, list) else []
            return EventQueryResult.model_validate({**body, "events": events})
        # XML/text fallback — preserve the raw payload, no parsing here.
        return EventQueryResult.model_validate({"@queryId": query_id, "raw_text": body})

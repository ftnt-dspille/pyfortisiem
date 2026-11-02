"""A small FortiSIEM API client covering its three distinct auth flows.

FortiSIEM exposes three authentication surfaces, and you need different ones for
different jobs:

1. **Basic auth** (``super/admin`` + password) -> the public REST API under
   ``/phoenix/rest/...``. Simplest; good for CMDB/config reads and queries.

2. **Session (h5) auth** -> the GUI's internal REST under ``/phoenix/rest/h5/...``.
   This is the *only* surface that can manage OAuth API-token credentials
   (ADMIN -> Setup -> System -> API Token). It is CSRF-protected: every
   state-changing call must echo the ``s`` session cookie back as an ``s:`` header
   **hex-encoded** (the GUI does ``hexEncode(getCookie("s"))``). That one detail is
   why scripting credential creation looks impossible until you know it.

3. **OAuth2 client_credentials** -> a bearer token minted at
   ``/phoenix/rest/pub/security/oauth/token`` from a client_id/secret created via
   flow #2. This bearer is what the **MCP server** at ``/phoenix/mcp`` requires
   (it answers ``www-authenticate: Bearer``), and it also works on the pub REST API.
   The token inherits the permissions of the user that created the credential.

Typical end-to-end (what this module automates):

    c = FortiSIEMClient("fortisiem.example.com:443", "admin", "pw", domain="Super")
    cred = c.create_oauth_credential("fortisoar_mcp_automation")   # flow #2
    tok  = c.mint_token(cred["client_id"], cred["client_secret"])  # flow #3
    print(c.mcp_list_tools(tok))                                   # flow #3 -> MCP

All requests are verify=False by default (lab appliances use self-signed certs);
pass ``verify=True`` for a properly-issued cert.
"""

from __future__ import annotations

import ast
import json
import re
import time

import httpx
from pydantic import BaseModel

from .exceptions import FortiSIEMError, FortiSIEMMCPError
from .models import (
    AIAnalysis,
    AIKeyDetails,
    EntityContext,
    EntityContextQuery,
    EntityIncidentQuery,
    EntityReputationQuery,
    EventTable,
    HealthOrg,
    Incident,
    IncidentDetailResult,
    IncidentId,
    IncidentIds,
    IncidentSummary,
    IncidentUpdate,
    IocEntry,
    LicenseInfo,
    McpTool,
    MutationAck,
    OAuthCredential,
    Reputation,
    RiskEntry,
    TriageRun,
    TriageStep,
    parse_risk_ranking,
)

# Non-literal constructs FortiSIEM sometimes leaks into Python-repr payloads
# (e.g. ``get_iocs_by_incident_ids`` embeds ``datetime.datetime(...)`` /
# ``zoneinfo.ZoneInfo(...)``). literal_eval rightly refuses these; we quote them
# so the surrounding list/dict still parses (the field keeps the repr text).
_NONLITERAL_CALL = re.compile(r"(?:datetime\.datetime|zoneinfo\.ZoneInfo)\((?:[^()]|\([^()]*\))*\)")


def _decode_text(text: str) -> object:
    """Parse an MCP ``text`` payload: JSON, then Python-repr, then repr with
    non-literal calls quoted. Returns the original string if all fail."""
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        pass
    try:
        return ast.literal_eval(text)
    except (ValueError, SyntaxError):
        pass
    try:
        return ast.literal_eval(_NONLITERAL_CALL.sub(lambda m: repr(m.group(0)), text))
    except (ValueError, SyntaxError):
        return text


def unwrap_mcp_content(result: object) -> object:
    """Peel the FortiSIEM MCP response down to its real payload.

    The server double-wraps payloads in nested MCP ``content[].text`` envelopes,
    and the innermost text is sometimes JSON and sometimes a Python ``repr``
    (single-quoted). This walks up to a few envelope layers, parsing each
    ``text`` with ``json`` then ``ast.literal_eval``, and raises
    :class:`FortiSIEMMCPError` if the decoded payload is an ``{"error": ...}``
    object. Returns the decoded payload (dict / list / str)."""
    obj = result
    for _ in range(3):  # at most: outer envelope -> inner envelope -> payload
        if isinstance(obj, dict) and isinstance(obj.get("content"), list) and obj["content"]:
            if obj.get("isError"):
                raise FortiSIEMMCPError(str(obj["content"]))
            obj = _decode_text(obj["content"][0].get("text", ""))
        else:
            break
    if isinstance(obj, dict) and "error" in obj and len(obj) == 1:
        raise FortiSIEMMCPError(str(obj["error"]))
    return obj


class FortiSIEMClient:
    """Thin client over FortiSIEM's REST + MCP surfaces, one method per real call.

    Args:
        host: ``host:port`` of the FortiSIEM supervisor (e.g. ``fortisiem.example.com:443``).
        username: GUI/REST account (e.g. ``admin``).
        password: that account's password.
        domain: the account's organization/domain (``Super`` for the super-global
            admin). Used for both the session login and basic-auth user prefixing.
        verify: TLS verification (False for self-signed lab certs).
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        domain: str = "Super",
        verify: bool = False,
    ) -> None:
        self.base = f"https://{host}".rstrip("/")
        self.phoenix = f"{self.base}/phoenix"
        self.h5 = f"{self.phoenix}/rest/h5"
        self.username = username
        self.password = password
        self.domain = domain
        # Basic-auth REST wants the org-qualified user, e.g. "super/admin".
        self._basic_user = f"{domain.lower()}/{username}"
        self._verify = verify
        self._client = httpx.Client(verify=verify, timeout=30)
        self._session: httpx.Client | None = None

    # ---- flow #1: basic auth (public REST) ---------------------------------

    def rest_get(self, path: str, **params) -> httpx.Response:
        """GET a ``/phoenix/rest/...`` path with basic auth. ``path`` is relative
        to ``/phoenix/rest`` (leading slash optional)."""
        url = f"{self.phoenix}/rest/{path.lstrip('/')}"
        return self._client.get(url, auth=(self._basic_user, self.password), params=params or None)

    def health(self, token: str | None = None) -> int:
        """System health summary status code. Works with basic auth or a bearer
        token (pass ``token`` to exercise the OAuth path)."""
        url = f"{self.phoenix}/rest/system/health/summary"
        if token:
            r = self._client.get(url, headers={"Authorization": f"Bearer {token}"})
        else:
            r = self._client.get(url, auth=(self._basic_user, self.password))
        return r.status_code

    def health_summary(self) -> list[HealthOrg]:
        """Per-organization health with each node's (supervisor, workers,
        collectors) status - the body behind :meth:`health`."""
        r = self.rest_get("system/health/summary")
        r.raise_for_status()
        return [HealthOrg.model_validate(o) for o in r.json()]

    # ---- flow #2: session auth (h5) + credential management ----------------

    def login(self) -> FortiSIEMClient:
        """Establish a GUI (h5) session — required for credential management.

        Sets JSESSIONID + the ``s`` CSRF cookie on an internal session client.
        Idempotent-ish: re-login refreshes the cookies.
        """
        sess = httpx.Client(verify=self._verify, timeout=30)
        r = sess.post(
            f"{self.h5}/sec/login",
            json={"username": self.username, "password": self.password, "domain": self.domain},
        )
        r.raise_for_status()
        if '"success"' not in r.text and "success" not in r.text:
            raise RuntimeError(f"FortiSIEM login did not return success: {r.text[:200]!r}")
        if "s" not in sess.cookies:
            raise RuntimeError("FortiSIEM login succeeded but no 's' CSRF cookie was set.")
        self._session = sess
        return self

    def _csrf_headers(self) -> dict[str, str]:
        """The GUI echoes the ``s`` cookie hex-encoded in an ``s:`` header on every
        state-changing h5 call. Without it the backend returns a bare 403."""
        if self._session is None:
            raise RuntimeError("Call login() before using session (h5) operations.")
        s = self._session.cookies.get("s")
        if not s:
            raise RuntimeError("No 's' cookie on the session — login() again.")
        return {"s": s.encode().hex().upper()}

    def _h5(self, method: str, path: str, *, json=None, params=None) -> httpx.Response:
        assert self._session is not None
        headers = {
            **self._csrf_headers(),
            "Content-Type": "application/json",
            "Referer": f"{self.phoenix}/html/admin",
            "Origin": self.base,
        }
        url = f"{self.h5}/{path.lstrip('/')}"
        # cache-buster query param mirrors the GUI's ?t=<ms>. Pass query params via
        # ``params``: httpx replaces a query string written into ``path``.
        return self._session.request(
            method,
            url,
            headers=headers,
            json=json,
            params={**(params or {}), "t": int(time.time() * 1000)},
        )

    def license_info(self) -> LicenseInfo:
        """The supervisor license, as ADMIN -> License shows it (h5 ``sec/license``).

        The public REST ``system/license`` answers 403 even to the super-global
        admin, so this goes through the GUI session; it logs in on first use.
        """
        if self._session is None:
            self.login()
        r = self._h5("GET", "sec/license")
        r.raise_for_status()
        return LicenseInfo.model_validate(r.json())

    # ---- FortiAI (GenAI) ---------------------------------------------------
    #
    # The incident FortiAI tab talks to a GenAI service under /phoenix/genai:
    #   1. h5 POST sec/oauth/internal/token (grant_type=internal_user) -> bearer
    #      (expires_in is in MINUTES, 15 on 7.6)
    #   2. GET /phoenix/genai/api/create_websocket with that bearer -> {"ws_uri": "/ws/<id>"}
    #   3. open wss://<host>/phoenix/genai/ws/<id>?src=incident_triage&org_id=1&user=<u>
    #      (the id is the credential; the socket itself takes no auth header)
    #   4. send {"question": "Triage incidents with ids: [N]", "optimize_triage": bool,
    #      "triage_prompt"?: str}; read JSON frames until {"finished": true}
    # Steps 1-3 reach the service without touching the LLM, so they make a free
    # health probe; step 4 spends tokens on the configured key.

    def ai_key_details(self) -> AIKeyDetails:
        """Which LLM key FortiAI is configured with (the key itself comes back masked)."""
        if self._session is None:
            self.login()
        r = self._h5("GET", "ai/getKeyDetails")
        r.raise_for_status()
        body = r.json()
        # 7.6 returns the object JSON-encoded inside a JSON string.
        return AIKeyDetails.model_validate(json.loads(body) if isinstance(body, str) else body)

    def incident_ai_result(
        self, incident_id: int, analysis_type: str = "AGENTIC"
    ) -> AIAnalysis | None:
        """The saved FortiAI analysis on an incident (``BASIC`` or ``AGENTIC``), or
        None when nothing was saved (the endpoint answers 204)."""
        if self._session is None:
            self.login()
        r = self._h5(
            "GET", f"incident/airesult/{incident_id}", params={"analysisType": analysis_type}
        )
        r.raise_for_status()
        if r.status_code == 204 or not r.content.strip():
            return None
        return AIAnalysis.model_validate({"analysisType": analysis_type, **r.json()})

    def incident_planner_prompt(self, incident_id: int) -> str:
        """The planner prompt the incident's FortiAI tab shows for Agentic mode
        (set per rule). The story endpoint only answers for the incident's exact
        first-seen time, so that is read from the incident list first."""
        if self._session is None:
            self.login()
        r = self._h5(
            "POST",
            "incident/list",
            json={"filters": {"incident": {"incidentId": [incident_id]}}, "start": 0, "size": 1},
        )
        r.raise_for_status()
        listing = r.json()
        rows = listing.get("lightValueObjects") or []
        if not rows:
            raise FortiSIEMError(f"incident {incident_id} not found")
        values = dict(zip(listing["fields"], rows[0]["data"], strict=False))
        r = self._h5(
            "GET",
            f"incidentStory/{incident_id}",
            params={
                "custId": rows[0].get("custId") or 1,
                "firstSeenTime": values.get("origFirstSeenTime") or values["incidentFirstSeen"],
                "withoutTicketId": "false",
                "start": 0,
                "size": 500,
            },
        )
        r.raise_for_status()
        story = r.json().get("data") or []
        return next(
            (i.get("plannerPrompt") or "" for i in story if i.get("incidentId") == incident_id), ""
        )

    def genai_token(self) -> str:
        """A short-lived bearer for the GenAI service (h5 ``sec/oauth/internal/token``)."""
        if self._session is None:
            self.login()
        assert self._session is not None
        r = self._session.post(
            f"{self.h5}/sec/oauth/internal/token",
            content="grant_type=internal_user",
            headers={
                **self._csrf_headers(),
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": self.base,
            },
        )
        r.raise_for_status()
        return r.json()["access_token"]

    def genai_websocket_url(self, src: str = "incident_triage", org_id: int = 1) -> str:
        """A fresh GenAI websocket URL. Reaching it proves the service is up
        without calling the LLM."""
        token = self.genai_token()  # logs in on first use
        assert self._session is not None
        r = self._session.get(
            f"{self.phoenix}/genai/api/create_websocket",
            headers={"Authorization": f"Bearer {token}"},
        )
        r.raise_for_status()
        ws = self.base.replace("https://", "wss://", 1)
        query = f"src={src}&org_id={org_id}&user={self.username}"
        return f"{ws}/phoenix/genai{r.json()['ws_uri']}?{query}"

    def genai_probe(self, timeout: float = 15) -> None:
        """Open and close a GenAI websocket: raises if FortiAI's service is
        unreachable. Spends no LLM tokens. Needs the ``genai`` extra."""
        from websockets.sync.client import connect

        with connect(self.genai_websocket_url(), ssl=self._ws_ssl(), open_timeout=timeout):
            pass

    def triage_incident(
        self,
        incident_id: int,
        *,
        prompt: str | None = None,
        optimize: bool = True,
        timeout: float = 900,
        on_message=None,
    ) -> TriageRun:
        """Run the incident FortiAI tab's **Agentic** triage and wait for it to end.

        ``prompt`` is the planner prompt; None uses the incident rule's own (what
        the tab shows, via :meth:`incident_planner_prompt`). The service needs a
        prompt: sent without one, its planner answers "your plan includes a step I
        can't execute" and finishes. ``on_message(frame: dict)`` sees every streamed frame.
        Spends LLM tokens. The result is not saved to the incident; the GUI's
        Save button does that. Needs the ``genai`` extra.
        """
        from websockets.sync.client import connect

        run = TriageRun()
        payload: dict = {
            "question": f"Triage incidents with ids: [{incident_id}]",
            "optimize_triage": optimize,
        }
        prompt = prompt or self.incident_planner_prompt(incident_id)
        if prompt:
            payload["triage_prompt"] = prompt
        deadline = time.monotonic() + timeout
        with connect(self.genai_websocket_url(), ssl=self._ws_ssl(), open_timeout=30) as ws:
            ws.send(json.dumps(payload))
            while not run.finished:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError(
                        f"FortiAI triage of incident {incident_id} still running after {timeout}s"
                    )
                frame = json.loads(ws.recv(timeout=left))
                if on_message:
                    on_message(frame)
                run.ws_id = frame.get("ws_id") or run.ws_id
                msg = frame.get("message") or ""
                if frame.get("steps"):
                    run.steps = [TriageStep.model_validate(s) for s in frame["steps"]]
                elif msg:
                    run.messages.append(msg)
                    if "Incident Triage Summary" in msg:
                        run.summary = msg.strip()
                    m = re.search(r"fileName=([^)\s]+\.pdf)", msg)
                    if m:
                        run.report = m.group(1)
                run.finished = bool(frame.get("finished"))
        return run

    def _ws_ssl(self):
        import ssl

        ctx = ssl.create_default_context()
        if not self._verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def list_oauth_credentials(self) -> list[dict]:
        """List existing API-token credentials (no secrets returned)."""
        r = self._h5("GET", "sec/oauth/tokens")
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, list) else data.get("data", data)

    def create_oauth_credential(
        self,
        name: str,
        *,
        expires_in: int = 1440,
        client_expires_in: int = 525600,
    ) -> OAuthCredential:
        """Create a ``client_credentials`` API-token credential and return it.

        Args:
            name: a human label (shown in the GUI list).
            expires_in: access-token lifetime in minutes (default 24h).
            client_expires_in: client-secret lifetime in minutes (default ~1yr).

        The ``client_secret`` is present on the returned object **only here** —
        save it now.
        """
        if self._session is None:
            self.login()
        payload = {
            "name": name,
            "grantType": "client_credentials",
            "expiresIn": expires_in,
            "clientExpiresIn": client_expires_in,
        }
        r = self._h5("POST", "sec/oauth/token", json=payload)
        r.raise_for_status()
        d = r.json()
        if isinstance(d, dict) and d.get("code") not in (None, 0):
            raise RuntimeError(f"create_oauth_credential failed: {d.get('msg') or d}")
        return OAuthCredential.from_create_response(d)

    def revoke_oauth_credential(self, cred_id: int) -> None:
        """Revoke an API-token credential by its numeric id (the GUI's delete)."""
        r = self._h5("POST", f"sec/oauth/token/{cred_id}/revoke")
        r.raise_for_status()

    def reset_oauth_secret(self, cred_id: int) -> str:
        """Rotate a credential's client_secret and return the new value."""
        r = self._h5("POST", f"sec/oauth/token/{cred_id}/resetSecret")
        r.raise_for_status()
        d = r.json()
        return d.get("issuedTokenInfo", {}).get("clientSecret") or d.get("clientSecret", "")

    # ---- flow #3: OAuth2 client_credentials -> bearer ----------------------

    def mint_token(self, client_id: str, client_secret: str) -> str:
        """Exchange a client_id/secret for a bearer access token."""
        r = self._client.post(
            f"{self.phoenix}/rest/pub/security/oauth/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )
        r.raise_for_status()
        return r.json()["access_token"]

    # ---- MCP (bearer-auth, streamable HTTP JSON-RPC) -----------------------
    #
    # The FortiSIEM MCP server speaks streamable-HTTP JSON-RPC: ``initialize``
    # returns an ``mcp-session-id`` header that subsequent calls must echo, and
    # responses arrive as Server-Sent Events (``text/event-stream``). Open one
    # session with ``mcp_session(token)`` and reuse it across calls.

    def mcp_session(self, token: str) -> MCPSession:
        """Initialize an MCP session and return a handle for tool calls."""
        return MCPSession(self._client, f"{self.phoenix}/mcp", token)

    def mcp_list_tools(self, token: str) -> list[McpTool]:
        """Return the advertised tools as typed :class:`McpTool` objects."""
        with self.mcp_session(token) as s:
            return s.list_tools()

    def close(self) -> None:
        self._client.close()
        if self._session is not None:
            self._session.close()

    def __enter__(self) -> FortiSIEMClient:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class MCPSession:
    """An initialized streamable-HTTP MCP session over the FortiSIEM ``/phoenix/mcp``
    endpoint. One ``initialize`` handshake; reuse for many ``call_tool`` invocations.

    The typed convenience methods (``get_incidents_by_entity`` etc.) wrap the
    server's 17 tools — each takes its pydantic param model from ``models.py`` and
    forwards it as the tool's single ``params`` argument. See ``FORTISIEM_API.md``
    for the full tool reference.
    """

    def __init__(self, client: httpx.Client, url: str, token: str) -> None:
        self._c = client
        self._url = url
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        self._id = 0
        init = self._post(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "fortisiem-client", "version": "1.0"},
            },
        )
        sid = init.headers.get("mcp-session-id")
        if sid:
            self._headers["mcp-session-id"] = sid
        self._notify("notifications/initialized")

    def _post(self, method: str, params: dict | None = None) -> httpx.Response:
        self._id += 1
        body = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            body["params"] = params
        r = self._c.post(self._url, headers=self._headers, json=body)
        r.raise_for_status()
        return r

    def _notify(self, method: str) -> None:
        self._c.post(self._url, headers=self._headers, json={"jsonrpc": "2.0", "method": method})

    def _rpc(self, method: str, params: dict | None = None) -> dict:
        return _parse_sse(self._post(method, params).text)

    def list_tools(self) -> list[McpTool]:
        result = self._rpc("tools/list", {}).get("result", {})
        return [McpTool.model_validate(t) for t in result.get("tools", [])]

    def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        """Raw ``tools/call``. Returns the JSON-RPC ``result`` (with ``content``),
        unparsed. Use this for tools without a typed wrapper, or to inspect the
        envelope; the typed methods below call :func:`unwrap_mcp_content` on it."""
        return self._rpc("tools/call", {"name": name, "arguments": arguments or {}}).get(
            "result", {}
        )

    # -- typed convenience wrappers (one per FortiSIEM MCP tool) --------------
    #
    # Each forwards a validated pydantic *input* model and decodes the *output*
    # into a typed response (see models.py). ``.payload(...)`` runs the raw call
    # through unwrap_mcp_content; ``raw_*`` access stays available via call_tool.

    def _payload(
        self, name: str, model: BaseModel | None = None, arguments: dict | None = None
    ) -> object:
        args = {"params": model.model_dump(exclude_none=True)} if model else (arguments or {})
        return unwrap_mcp_content(self.call_tool(name, args))

    def get_incidents_by_entity(self, q: EntityIncidentQuery) -> list[IncidentSummary]:
        """Active incidents touching one entity. -> ``list[IncidentSummary]``."""
        rows = self._payload("get_incidents_by_entity", q)
        return [IncidentSummary.model_validate(r) for r in (rows or [])]

    def get_incident_by_id(self, incident_id: int) -> IncidentDetailResult:
        """Full paged detail for one incident. -> ``IncidentDetailResult``."""
        return IncidentDetailResult.model_validate(
            self._payload("get_incident_by_id", IncidentId(incident_id=incident_id))
        )

    def get_related_incidents_by_id(self, incident_id: int) -> list[Incident]:
        """Incidents sharing entities with the given one. -> ``list[Incident]``
        (raw camelCase shape, same model as ``get_incident_by_id``'s ``.data`` —
        NOT the snake_case ``IncidentSummary`` the entity tools return)."""
        rows = self._payload("get_related_incidents_by_id", IncidentId(incident_id=incident_id))
        return [Incident.model_validate(r) for r in (rows or [])]

    def get_trigger_events_by_incident_id(self, incident_id: int) -> EventTable:
        """Raw events that triggered the incident, columnar. -> ``EventTable``
        (use ``.records()`` / ``.to_events()``)."""
        return EventTable.model_validate(
            self._payload("get_trigger_events_by_incident_id", IncidentId(incident_id=incident_id))
        )

    def get_context_by_entity(self, q: EntityContextQuery) -> EntityContext:
        """Host/device/risk context for one entity. -> ``EntityContext``."""
        return EntityContext.model_validate(self._payload("get_context_by_entity", q))

    def get_reputation_by_entity(self, q: EntityReputationQuery) -> list[Reputation]:
        """Threat-feed reputation for one entity type. -> ``list[Reputation]``."""
        rows = self._payload("get_reputation_by_entity", q)
        return [Reputation.model_validate(r) for r in (rows or [])]

    def get_iocs_by_incident_ids(self, incident_ids: list[int]) -> list[IocEntry]:
        """IOCs across the given incidents. -> ``list[IocEntry]``."""
        rows = self._payload("get_iocs_by_incident_ids", IncidentIds(incident_ids=incident_ids))
        return [IocEntry.model_validate(r) for r in (rows or [])]

    def update_incident_severity_by_id(self, u: IncidentUpdate) -> MutationAck:
        return MutationAck.model_validate(self._payload("update_incident_severity_by_id", u))

    def update_incident_resolution_by_id(self, u: IncidentUpdate) -> MutationAck:
        return MutationAck.model_validate(self._payload("update_incident_resolution_by_id", u))

    def append_incident_comment_by_id(self, u: IncidentUpdate) -> MutationAck:
        return MutationAck.model_validate(self._payload("append_incident_comment_by_id", u))

    def clear_incident_by_id(self, incident_id: int) -> MutationAck:
        return MutationAck.model_validate(
            self._payload("clear_incident_by_id", IncidentId(incident_id=incident_id))
        )

    def top_10_risky_users(self) -> list[RiskEntry]:
        """Top-10 users by risk score, sorted desc. -> ``list[RiskEntry]``."""
        return parse_risk_ranking(self._payload("get_top_10_risky_users_incidents"))

    def top_10_risky_devices(self) -> list[RiskEntry]:
        """Top-10 devices by risk score, sorted desc. -> ``list[RiskEntry]``."""
        return parse_risk_ranking(self._payload("get_top_10_risky_devices_incidents"))

    def query_postgres(self, sql: str) -> list[dict]:
        """Read-only Postgres query. -> ``list[dict]`` (shape depends on SELECT)."""
        payload = self._payload("query_fsm_postgres", arguments={"sql": sql})
        return payload if isinstance(payload, list) else [payload]

    def query_clickhouse(self, sql: str) -> EventTable:
        """Read-only ClickHouse events query. -> ``EventTable`` (columns/rows)."""
        return EventTable.model_validate(
            self._payload("query_fsm_clickhouse", arguments={"sql": sql})
        )

    def query_postgres_prompts(self) -> str:
        """LLM prompt text to help author Postgres SQL. -> ``str``."""
        return str(unwrap_mcp_content(self.call_tool("query_fsm_postgres_prompts", {})))

    def query_clickhouse_prompts(self) -> str:
        """LLM prompt text to help author ClickHouse SQL. -> ``str``."""
        return str(unwrap_mcp_content(self.call_tool("query_fsm_clickhouse_prompts", {})))

    def __enter__(self) -> MCPSession:
        return self

    def __exit__(self, *exc) -> None:
        pass


def _parse_sse(body: str) -> dict:
    """Decode a JSON-RPC response that may arrive as an SSE ``data:`` frame."""
    payload = body
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            payload = line[5:].strip()
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return {}


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="FortiSIEM auth-flow client demo")
    ap.add_argument("host", help="host:port, e.g. fortisiem.example.com:443")
    ap.add_argument("username")
    ap.add_argument("password")
    ap.add_argument("--domain", default="Super")
    ap.add_argument("--create", metavar="NAME", help="create an OAuth credential with this name")
    ap.add_argument("--list", action="store_true", help="list OAuth credentials")
    ap.add_argument("--mint", nargs=2, metavar=("CLIENT_ID", "CLIENT_SECRET"))
    args = ap.parse_args()

    c = FortiSIEMClient(args.host, args.username, args.password, domain=args.domain)
    print("health (basic auth):", c.health())
    if args.list:
        c.login()
        print(json.dumps(c.list_oauth_credentials(), indent=2))
    if args.create:
        cred = c.create_oauth_credential(args.create)
        print("created:", cred.model_dump_json(indent=2))
        tok = c.mint_token(cred.client_id, cred.client_secret)
        print("minted bearer, len:", len(tok))
        for t in c.mcp_list_tools(tok):
            print(f"  - {t.name}: {(t.description or '').splitlines()[0][:70]}")
    if args.mint:
        tok = c.mint_token(*args.mint)
        for t in c.mcp_list_tools(tok):
            print(f"  - {t.name} (required={t.required_params})")
    c.close()

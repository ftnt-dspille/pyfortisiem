"""Pydantic models for the FortiSIEM client — auth artifacts, MCP tool I/O, and
the REST shapes worth typing.

The MCP param models below are transcribed from the FortiSIEM MCP server's live
``tools/list`` ``inputSchema`` ``$defs`` (see ``reference/mcp_tools_live.json``).
Each ``*Query``/``*Update`` model is the object a tool expects inside its single
``params`` argument — e.g. ``get_incidents_by_entity(params=EntityIncidentQuery(...))``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

# --------------------------------------------------------------------------- #
# Auth (OAuth2 client_credentials API-token credentials)
# --------------------------------------------------------------------------- #


class IssuedToken(BaseModel):
    """The one-time token material returned when a credential is created."""

    model_config = ConfigDict(populate_by_name=True)

    access_token: str = Field(alias="accessToken")
    client_id: str = Field(alias="clientId")
    client_secret: str | None = Field(default=None, alias="clientSecret")
    expires_in: int = Field(alias="expiresIn")  # minutes


class OAuthCredential(BaseModel):
    """A FortiSIEM API-token credential (ADMIN -> Setup -> System -> API Token).

    ``client_secret`` is populated only on creation/reset — persist it then; the
    list/get endpoints never return it again.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: int
    name: str
    client_id: str = Field(alias="clientId")
    client_secret: str | None = None  # filled from issuedTokenInfo at create time
    expires_in: int = Field(alias="expiresIn")  # access-token lifetime, minutes
    client_expires_in: int = Field(alias="clientExpiresIn")  # secret lifetime, minutes
    revoked: bool = False
    owner_name: str | None = Field(default=None, alias="ownerName")

    @classmethod
    def from_create_response(cls, d: dict) -> OAuthCredential:
        issued = d.get("issuedTokenInfo") or {}
        cred = cls.model_validate(d)
        cred.client_secret = issued.get("clientSecret")
        return cred

    def as_env(self) -> dict[str, str]:
        """Env shape for the FortiSOAR MCP setup example."""
        return {
            "FORTISIEM_CLIENT_ID": self.client_id,
            "FORTISIEM_CLIENT_SECRET": self.client_secret or "",
        }


# --------------------------------------------------------------------------- #
# MCP tool catalogue
# --------------------------------------------------------------------------- #


class McpTool(BaseModel):
    """One entry from the MCP server's ``tools/list``."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    description: str | None = None
    input_schema: dict = Field(default_factory=dict, alias="inputSchema")

    @property
    def required_params(self) -> list[str]:
        return self.input_schema.get("required", [])


# --------------------------------------------------------------------------- #
# MCP tool param envelopes ($defs from the live inputSchema)
# --------------------------------------------------------------------------- #


class TimeUnit(str, Enum):
    hours = "hours"
    days = "days"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Resolution(str, Enum):
    TruePositive = "TruePositive"
    FalsePositive = "FalsePositive"


class IncidentStatus(int, Enum):
    ACTIVE = 0
    AUTO_CLEARED = 1
    MANUALLY_CLEARED = 2
    SYSTEM_CLEARED = 3


class _OneEntity(BaseModel):
    """Mixin: enforce that exactly one of ip/hostname/username is set when the
    tool requires a single entity."""

    def _exactly_one(self, fields: tuple[str, ...]) -> None:
        present = [f for f in fields if getattr(self, f, None)]
        if len(present) > 1:
            raise ValueError(f"Provide at most one of {fields}; got {present}")


class EntityIncidentQuery(_OneEntity):
    """``get_incidents_by_entity`` — active incidents in a look-back window,
    optionally filtered to one entity."""

    time_value: int = Field(default=24, description="Number of time units to look back")
    time_unit: TimeUnit = TimeUnit.hours
    ip: str | None = None
    hostname: str | None = None
    username: str | None = None

    @model_validator(mode="after")
    def _check(self) -> EntityIncidentQuery:
        self._exactly_one(("ip", "hostname", "username"))
        return self


class EntityContextQuery(_OneEntity):
    """``get_context_by_entity`` — enriched context; exactly one entity required."""

    ip: str | None = None
    hostname: str | None = None
    username: str | None = None

    @model_validator(mode="after")
    def _check(self) -> EntityContextQuery:
        present = [f for f in ("ip", "hostname", "username") if getattr(self, f)]
        if len(present) != 1:
            raise ValueError("Exactly one of ip/hostname/username is required")
        return self


class EntityReputationQuery(BaseModel):
    """``get_reputation_by_entity`` — threat-feed reputation; provide exactly one
    entity *type* (each is a list)."""

    ip: list[str] | None = None
    url: list[str] | None = None
    domain: list[str] | None = None
    hash: list[str] | None = None

    @model_validator(mode="after")
    def _check(self) -> EntityReputationQuery:
        present = [f for f in ("ip", "url", "domain", "hash") if getattr(self, f)]
        if len(present) != 1:
            raise ValueError("Provide exactly one entity type: ip | url | domain | hash")
        return self


class IncidentId(BaseModel):
    """``get_incident_by_id`` / ``get_trigger_events_by_incident_id`` /
    ``get_related_incidents_by_id`` / ``clear_incident_by_id``."""

    incident_id: int


class IncidentIds(BaseModel):
    """``get_iocs_by_incident_ids``."""

    incident_ids: list[int]


class IncidentUpdate(BaseModel):
    """``update_incident_severity_by_id`` / ``update_incident_resolution_by_id`` /
    ``append_incident_comment_by_id``. Set only the field the tool acts on."""

    model_config = ConfigDict(use_enum_values=True)

    incidentId: int
    incidentResolution: Resolution | None = None
    incidentSeverity: Severity | None = None
    incidentStatus: IncidentStatus | None = None
    comments: str | None = None


# --------------------------------------------------------------------------- #
# REST shapes — incidents + events (basic-auth /rest/pub surface)
#
# These are what the async client returns. FortiSIEM's incident/event JSON is
# wide and version-variant, so each model keeps ``extra="allow"`` and surfaces
# only the fields worth typing; everything else stays reachable via ``.raw`` or
# attribute access. Field names mirror the wire (camelCase) so a model round-
# trips back to a request payload without remapping.
# --------------------------------------------------------------------------- #


class Event(BaseModel):
    """One event row (a triggering event, search hit, or raw event).

    The ``/rest/pub/incident/triggeringEvents`` surface returns flat JSON; the
    XML query surface (``/rest/query/...``) returns ``attributes`` dicts that the
    connector flattens. Either way we keep the whole record and expose the common
    identifiers."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    event_id: str | None = Field(default=None, alias="eventId")
    event_type: str | None = Field(default=None, alias="eventType")
    event_name: str | None = Field(default=None, alias="eventName")
    severity: int | None = Field(default=None, alias="eventSeverity")
    severity_category: str | None = Field(default=None, alias="eventSeverityCat")
    event_time: int | None = Field(default=None, alias="eventReceiveTime")
    src_ip: str | None = Field(default=None, alias="srcIpAddr")
    dest_ip: str | None = Field(default=None, alias="destIpAddr")
    host_name: str | None = Field(default=None, alias="hostName")
    user: str | None = None

    @property
    def raw(self) -> dict:
        """The full wire record, including fields not promoted above."""
        return self.model_dump(by_alias=True, exclude_none=False)


class Incident(BaseModel):
    """One incident from ``/rest/pub/incident`` (list or by-id)."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    incident_id: int = Field(alias="incidentId")
    incident_title: str | None = Field(default=None, alias="incidentTitle")
    incident_status: int | None = Field(default=None, alias="incidentStatus")
    incident_status_str: str | None = Field(default=None, alias="incidentStatusStr")
    severity: int | None = Field(default=None, alias="eventSeverity")
    severity_category: str | None = Field(default=None, alias="eventSeverityCat")
    incident_category: int | str | None = Field(default=None, alias="phIncidentCategory")
    first_seen: int | None = Field(default=None, alias="incidentFirstSeen")
    last_seen: int | None = Field(default=None, alias="incidentLastSeen")
    incident_src: str | None = Field(default=None, alias="incidentSrc")
    incident_target: str | None = Field(default=None, alias="incidentTarget")

    @property
    def raw(self) -> dict:
        return self.model_dump(by_alias=True, exclude_none=False)


class IncidentWithEvents(Incident):
    """An incident with its associated/triggering events attached.

    This is the marquee shape: ``AsyncFortiSIEMClient.get_incident_with_events``
    and ``list_incidents_with_events`` return these so a caller has the incident
    and the evidence in one object."""

    events: list[Event] = Field(default_factory=list)

    @classmethod
    def from_incident(cls, incident: Incident, events: list[Event]) -> IncidentWithEvents:
        return cls.model_validate({**incident.model_dump(by_alias=True), "events": events})


class EventQueryResult(BaseModel):
    """Result envelope of the async XML query lifecycle (eventQuery / progress /
    events), mirroring the connector's ``make_output`` shape."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    query_id: str | None = Field(default=None, alias="@queryId")
    total_count: int | None = Field(default=None, alias="@totalCount")
    start: int | None = Field(default=None, alias="@start")
    error_code: str | None = Field(default=None, alias="@errorCode")
    events: list[Event] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# MCP tool RESPONSE models
#
# Transcribed from live raw responses captured off the box (see
# ``reference/mcp_responses_live.json``). The FortiSIEM MCP server double-wraps
# every payload in nested ``content[].text`` envelopes and sometimes returns
# Python-repr instead of JSON; ``fortisiem_client.unwrap_mcp_content`` peels that
# off, and these models type what's underneath. Each tool returns a *different*
# shape — they fall into the families below. All keep ``extra="allow"`` (FortiSIEM
# adds fields across versions) and expose ``.raw`` for the untyped remainder.
# --------------------------------------------------------------------------- #


class _RawModel(BaseModel):
    """Base that keeps unknown fields and exposes the whole wire record."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    @property
    def raw(self) -> dict:
        return self.model_dump(by_alias=True, exclude_none=False)


class IncidentSummary(_RawModel):
    """Curated incident row (snake_case) returned by the *entity-based* incident
    tools: ``get_incidents_by_entity`` and ``get_related_incidents_by_id``.

    Distinct from :class:`Incident` (the raw camelCase REST shape) — the MCP layer
    flattens incidents to this summary form."""

    incident_id: int
    incident_title: str | None = None
    incident_status: int | None = None
    last_seen_time: int | None = None  # epoch ms
    src_ip_addr: str | None = None
    src_name: str | None = None
    host_ip_addr: str | None = None
    host_name: str | None = None
    dest_ip_addr: str | None = None
    dest_name: str | None = None
    user_attr: str | None = None
    src_user_attr: str | None = None
    target_user_attr: str | None = None


class IncidentDetailResult(_RawModel):
    """Paged detail envelope from ``get_incident_by_id`` — raw camelCase incidents
    under ``data`` (reusing :class:`Incident`)."""

    total: int | None = None
    pages: int | None = None
    start: int | None = None
    size_per_page: int | None = Field(default=None, alias="sizePerPage")
    query_id: str | None = Field(default=None, alias="queryId")
    data: list[Incident] = Field(default_factory=list)


class EventTable(_RawModel):
    """Columnar result from the tabular tools: ``get_trigger_events_by_incident_id``
    and ``query_fsm_clickhouse`` (and any ``query_fsm_postgres`` that returns a
    table). ``columns`` names each position in every ``rows`` tuple."""

    columns: list[str] = Field(default_factory=list)
    rows: list[list] = Field(default_factory=list)

    def records(self) -> list[dict]:
        """Zip columns+rows into a list of dicts."""
        return [dict(zip(self.columns, r, strict=False)) for r in self.rows]

    def to_events(self) -> list[Event]:
        """Best-effort typed events (works when columns map onto Event fields)."""
        return [Event.model_validate(rec) for rec in self.records()]


class IocEntry(_RawModel):
    """One IOC/host row from ``get_iocs_by_incident_ids`` (Python-repr on the wire)."""

    incident_title: str | None = None
    src_ip_addr: str | None = None
    src_name: str | None = None
    src_geo_country: str | None = None
    dest_ip_addr: str | None = None
    dest_name: str | None = None
    dest_geo_country: str | None = None
    host_name: str | None = None
    host_ip_addr: str | None = None


class WatchlistHit(_RawModel):
    name: str | None = None
    last_modified_time: str | None = Field(default=None, alias="lastModifiedTime")
    rule_name: str | None = Field(default=None, alias="ruleName")


class ContextIncidentRef(_RawModel):
    incident_id: int | None = Field(default=None, alias="incidentId")
    rule_name: str | None = Field(default=None, alias="ruleName")
    incident_title: str | None = Field(default=None, alias="incidentTitle")
    first_seen_time: str | None = Field(default=None, alias="firstSeenTime")
    last_seen_time: str | None = Field(default=None, alias="lastSeenTime")
    severity_category: str | None = Field(default=None, alias="severityCat")


class EntityContextItem(_RawModel):
    """One resolved entity's context block within ``get_context_by_entity``."""

    parameter: str | None = None  # "ip" | "hostname" | "username"
    value: str | None = None
    watchlists: list[WatchlistHit] = Field(default_factory=list)
    incidents: list[ContextIncidentRef] = Field(default_factory=list)
    top_event_types: list[dict] = Field(default_factory=list, alias="topEventTypes")


class EntityContext(_RawModel):
    """``get_context_by_entity`` — wraps one or more :class:`EntityContextItem`."""

    contexts: list[EntityContextItem] = Field(default_factory=list)


class Reputation(_RawModel):
    """One entity's threat-feed reputation from ``get_reputation_by_entity``."""

    ip: str | None = None
    whois_info: dict | None = Field(default=None, alias="whoisInfo")
    location: dict | None = None
    malware_groups: list = Field(default_factory=list, alias="malwareGroups")
    watchlists: list = Field(default_factory=list)
    incidents: list = Field(default_factory=list)
    virus_total_fail: object = Field(default=None, alias="virusTotalFail")
    risk_iq_fail: object = Field(default=None, alias="riskIQFail")
    cts_service_fail: object = Field(default=None, alias="ctsServiceFail")


class RiskIncidentGroup(_RawModel):
    """Incidents of one rule contributing to an entity's risk score."""

    incident_ids: list[str] = Field(default_factory=list, alias="incidentIds")
    severity: str | None = None


class RiskEntry(_RawModel):
    """One ranked entity from ``get_top_10_risky_users_incidents`` /
    ``..._devices_incidents``. The wire shape is a dict keyed by entity name;
    :func:`parse_risk_ranking` injects ``name`` and returns a sorted list."""

    name: str
    score: float | None = None
    incidents: dict[str, RiskIncidentGroup] = Field(default_factory=dict)


class MutationAck(_RawModel):
    """Acknowledgement from the mutating tools (``update_*``, ``clear_*``,
    ``append_incident_comment_by_id``) — ``{"result": "success"}``."""

    result: str | None = None

    @property
    def ok(self) -> bool:
        return (self.result or "").lower() == "success"


def parse_risk_ranking(payload: dict) -> list[RiskEntry]:
    """Turn the name-keyed risk dict into a score-sorted list of RiskEntry."""
    out: list[RiskEntry] = []
    for name, body in (payload or {}).items():
        body = dict(body or {})
        score_raw = body.pop("score", None)
        try:
            score = float(score_raw) if score_raw is not None else None
        except (TypeError, ValueError):
            score = None
        out.append(RiskEntry.model_validate({"name": name, "score": score, **body}))
    return sorted(out, key=lambda e: (e.score is None, -(e.score or 0)))


# --------------------------------------------------------------------------- #
# System: license + health
# --------------------------------------------------------------------------- #


def _ms_to_dt(ms: int | None) -> datetime | None:
    """FortiSIEM epoch-millisecond timestamp -> aware UTC datetime; 0/None -> None."""
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc) if ms else None


class LicenseFeature(_RawModel):
    """One row of ADMIN -> License -> General (``licenseInfo[]``).

    ``usage`` is what the GUI prints in its expiry column: a date string
    (``"Jan 23,2027"``), ``"Perpetual"`` or ``"N/A"``.
    """

    resource_name: str = Field(alias="resourceName")
    licensed: str | None = None
    usage: str | None = None
    warn: bool = False


class LicenseInfo(_RawModel):
    """The supervisor's license, as ADMIN -> License shows it (h5 ``sec/license``).

    Only the fields worth typing are declared; the rest (worker list, per-feature
    end times) stay reachable through ``.raw``.
    """

    serial: str | None = Field(default=None, alias="sn")
    uuid: str | None = None
    type: str | None = None  # "Enterprise", "Service Provider", ...
    eps_licensed: int | None = Field(default=None, alias="epsLicensed")
    devices_licensed: int | None = Field(default=None, alias="configItemsLicensed")
    collectors_licensed: int | None = Field(default=None, alias="noOfCollectors")
    license_end_ms: int | None = Field(default=None, alias="licenseEndTime")
    support_end_ms: int | None = Field(default=None, alias="supportEndTime")
    features: list[LicenseFeature] = Field(default_factory=list, alias="licenseInfo")

    @property
    def license_end(self) -> datetime | None:
        """None when the license has no end time (perpetual or not reported)."""
        return _ms_to_dt(self.license_end_ms)

    @property
    def support_end(self) -> datetime | None:
        return _ms_to_dt(self.support_end_ms)

    def days_left(self, now: datetime | None = None) -> int | None:
        end = self.license_end
        if end is None:
            return None
        return (end - (now or datetime.now(timezone.utc))).days

    def is_valid(self, now: datetime | None = None) -> bool:
        """A serial is present and the license has not ended. Fails closed: no
        serial is unlicensed, whatever the other fields say."""
        if not self.serial:
            return False
        end = self.license_end
        return end is None or end > (now or datetime.now(timezone.utc))

    @property
    def warnings(self) -> list[str]:
        """Feature rows the GUI flags with a warning (about to expire / expired)."""
        return [f.resource_name for f in self.features if f.warn]


class HealthNode(_RawModel):
    name: str
    node_type: str | None = Field(default=None, alias="nodeType")
    status: str | None = None
    reason: list = Field(default_factory=list)


class HealthOrg(_RawModel):
    """One organization from ``/phoenix/rest/system/health/summary``."""

    name: str
    health_status: str | None = Field(default=None, alias="healthStatus")
    nodes: list[HealthNode] = Field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.health_status == "Normal" and all(n.status == "Normal" for n in self.nodes)

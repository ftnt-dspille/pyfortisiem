"""Offline typed-response tests for all 17 FortiSIEM MCP tools.

Ported from the original example_mcp.py offline harness: replays the captured
(anonymized) raw MCP responses through the decode + model layer and asserts each
tool's response type. No appliance, no network.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pyfortisiem import FortiSIEMMCPError, unwrap_mcp_content
from pyfortisiem.models import (
    EntityContext,
    EventTable,
    Incident,
    IncidentDetailResult,
    IncidentSummary,
    IocEntry,
    MutationAck,
    Reputation,
    RiskEntry,
    parse_risk_ranking,
)

FIXTURE = Path(__file__).parent / "fixtures" / "mcp_responses.json"


@pytest.fixture(scope="module")
def cap() -> dict:
    return json.loads(FIXTURE.read_text())


def payload(cap: dict, name: str) -> object:
    v = cap[name]
    return v["__decoded__"] if isinstance(v, dict) and "__decoded__" in v else unwrap_mcp_content(v)


def test_get_incidents_by_entity(cap):
    inc = [IncidentSummary.model_validate(r) for r in payload(cap, "get_incidents_by_entity")]
    assert inc and all(isinstance(x, IncidentSummary) for x in inc)
    assert inc[0].incident_id is not None


def test_get_incident_by_id(cap):
    det = IncidentDetailResult.model_validate(payload(cap, "get_incident_by_id"))
    assert det.total is not None and det.data
    assert isinstance(det.data[0], Incident)


def test_get_related_incidents_by_id(cap):
    rel = [Incident.model_validate(r) for r in payload(cap, "get_related_incidents_by_id")]
    assert isinstance(rel, list)


def test_get_trigger_events_by_incident_id(cap):
    tbl = EventTable.model_validate(payload(cap, "get_trigger_events_by_incident_id"))
    assert tbl.columns and tbl.records()
    assert len(tbl.records()[0]) == len(tbl.columns)


def test_get_context_by_entity(cap):
    ctx = EntityContext.model_validate(payload(cap, "get_context_by_entity"))
    assert ctx.contexts
    assert ctx.contexts[0].parameter in (None, "ip", "hostname", "username")


def test_get_reputation_by_entity(cap):
    rep = [Reputation.model_validate(r) for r in payload(cap, "get_reputation_by_entity")]
    assert rep and rep[0].ip is not None


def test_get_iocs_by_incident_ids_decodes_datetime_repr(cap):
    iocs = [IocEntry.model_validate(r) for r in payload(cap, "get_iocs_by_incident_ids")]
    assert iocs and iocs[0].incident_title is not None


def test_top_10_risky_users_sorted(cap):
    users = parse_risk_ranking(payload(cap, "get_top_10_risky_users_incidents"))
    assert users and all(isinstance(u, RiskEntry) for u in users)
    assert users == sorted(users, key=lambda e: (e.score is None, -(e.score or 0)))


def test_top_10_risky_devices(cap):
    devs = parse_risk_ranking(payload(cap, "get_top_10_risky_devices_incidents"))
    assert devs and isinstance(devs[0], RiskEntry)


def test_query_fsm_clickhouse(cap):
    ch = EventTable.model_validate(payload(cap, "query_fsm_clickhouse"))
    assert ch.columns and ch.rows


def test_append_incident_comment_ack(cap):
    ack = MutationAck.model_validate(payload(cap, "append_incident_comment_by_id"))
    assert ack.ok


def test_query_fsm_postgres_list_of_dicts(cap):
    pg = payload(cap, "query_fsm_postgres")
    assert isinstance(pg, list) and isinstance(pg[0], dict)


def test_prompt_tools_return_str(cap):
    pgp = unwrap_mcp_content(cap["query_fsm_postgres_prompts"])
    chp = unwrap_mcp_content(cap["query_fsm_clickhouse_prompts"])
    assert isinstance(pgp, str) and len(pgp) > 50
    assert isinstance(chp, str) and len(chp) > 50


def test_error_envelope_raises():
    with pytest.raises(FortiSIEMMCPError):
        unwrap_mcp_content({"content": [{"type": "text", "text": '{"error": "bad entity"}'}]})

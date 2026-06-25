#!/usr/bin/env python3
"""Worked example + typed-response test for ALL 17 FortiSIEM MCP tools.

Two modes:

* **Offline (default)** — replays real responses captured off the box
  (``reference/mcp_responses_live.json``) through the typed wrappers' decode +
  model layer, asserting each tool's response type. No network::

      python example_mcp.py

* **Live** — opens a real MCP session and calls every *read-only* tool, printing
  the typed result. Mutating tools (update/clear/comment) are demonstrated in
  code but not executed against the shared appliance unless ``--mutate`` is
  passed (only the benign comment append runs, on the newest incident)::

      FSM_HOST=fortisiem.example.com:443 FSM_USER=admin FSM_PASS=... \
      python example_mcp.py --live

Either way it prints, for each tool, its **input model** and **output type** —
the inputs/outputs map the user asked to see.
"""

from __future__ import annotations

import json
import os
import sys

from pyfortisiem import FortiSIEMClient, FortiSIEMMCPError, unwrap_mcp_content
from pyfortisiem.models import (
    EntityContext,
    EntityContextQuery,
    EntityIncidentQuery,
    EntityReputationQuery,
    EventTable,
    Incident,
    IncidentDetailResult,
    IncidentSummary,
    IncidentUpdate,
    IocEntry,
    MutationAck,
    Reputation,
    RiskEntry,
    parse_risk_ranking,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "tests", "fixtures", "mcp_responses.json")


# Input model + output type for every tool — the typed I/O contract, one row each.
TOOL_IO = [
    ("get_incidents_by_entity", "EntityIncidentQuery", "list[IncidentSummary]"),
    ("get_incident_by_id", "IncidentId(incident_id)", "IncidentDetailResult"),
    ("get_related_incidents_by_id", "IncidentId(incident_id)", "list[Incident]"),
    ("get_trigger_events_by_incident_id", "IncidentId(incident_id)", "EventTable"),
    ("get_context_by_entity", "EntityContextQuery", "EntityContext"),
    ("get_reputation_by_entity", "EntityReputationQuery", "list[Reputation]"),
    ("get_iocs_by_incident_ids", "IncidentIds(incident_ids)", "list[IocEntry]"),
    ("update_incident_severity_by_id", "IncidentUpdate", "MutationAck"),
    ("update_incident_resolution_by_id", "IncidentUpdate", "MutationAck"),
    ("append_incident_comment_by_id", "IncidentUpdate", "MutationAck"),
    ("clear_incident_by_id", "IncidentId(incident_id)", "MutationAck"),
    ("get_top_10_risky_users_incidents", "(no args)", "list[RiskEntry]"),
    ("get_top_10_risky_devices_incidents", "(no args)", "list[RiskEntry]"),
    ("query_fsm_postgres", "sql: str", "list[dict]"),
    ("query_fsm_clickhouse", "sql: str", "EventTable"),
    ("query_fsm_postgres_prompts", "(no args)", "str"),
    ("query_fsm_clickhouse_prompts", "(no args)", "str"),
]


def print_io_table() -> None:
    print("\nFortiSIEM MCP tools — typed inputs / outputs")
    print(f"  {'tool':<37} {'input model':<27} {'output type'}")
    print(f"  {'-' * 37} {'-' * 27} {'-' * 22}")
    for name, inp, out in TOOL_IO:
        print(f"  {name:<37} {inp:<27} {out}")


class Check:
    def __init__(self) -> None:
        self.passed = self.failed = 0

    def __call__(self, label: str, cond: bool, detail: str = "") -> None:
        self.passed += cond
        self.failed += not cond
        print(
            f"  [{'PASS' if cond else 'FAIL'}] {label}"
            + (f" — {detail}" if detail and not cond else "")
        )


# --------------------------------------------------------------------------- #
# Offline — replay captured raw responses through the typed decode/model layer.
# --------------------------------------------------------------------------- #
def run_offline() -> int:
    print("Offline mode — replaying captured raw MCP responses through the typed layer\n")
    cap = json.load(open(FIXTURES))
    check = Check()

    def payload(name: str) -> object:
        v = cap[name]
        return (
            v["__decoded__"]
            if isinstance(v, dict) and "__decoded__" in v
            else unwrap_mcp_content(v)
        )

    inc = [IncidentSummary.model_validate(r) for r in payload("get_incidents_by_entity")]
    check(
        "get_incidents_by_entity -> list[IncidentSummary]",
        inc and all(isinstance(x, IncidentSummary) for x in inc),
    )
    print(f"      e.g. #{inc[0].incident_id} {inc[0].incident_title!r}")

    det = IncidentDetailResult.model_validate(payload("get_incident_by_id"))
    check("get_incident_by_id -> IncidentDetailResult", det.total is not None and bool(det.data))
    print(
        f"      total={det.total} pages={det.pages} data[0].incident_title="
        f"{det.data[0].incident_title!r}"
    )

    rel = [Incident.model_validate(r) for r in payload("get_related_incidents_by_id")]
    check("get_related_incidents_by_id -> list[Incident]", isinstance(rel, list))

    tbl = EventTable.model_validate(payload("get_trigger_events_by_incident_id"))
    check(
        "get_trigger_events_by_incident_id -> EventTable", bool(tbl.columns) and bool(tbl.records())
    )
    print(
        f"      {len(tbl.columns)} columns, {len(tbl.rows)} rows; records()[0] keys "
        f"= {list(tbl.records()[0])[:4]}…"
    )

    ctx = EntityContext.model_validate(payload("get_context_by_entity"))
    check("get_context_by_entity -> EntityContext", bool(ctx.contexts))
    print(
        f"      parameter={ctx.contexts[0].parameter} value={ctx.contexts[0].value} "
        f"watchlists={len(ctx.contexts[0].watchlists)} incidents={len(ctx.contexts[0].incidents)}"
    )

    rep = [Reputation.model_validate(r) for r in payload("get_reputation_by_entity")]
    check("get_reputation_by_entity -> list[Reputation]", rep and rep[0].ip is not None)
    print(f"      ip={rep[0].ip} org={(rep[0].whois_info or {}).get('organization')!r}")

    iocs = [IocEntry.model_validate(r) for r in payload("get_iocs_by_incident_ids")]
    check(
        "get_iocs_by_incident_ids -> list[IocEntry] (datetime-repr decoded)",
        iocs and iocs[0].incident_title is not None,
    )

    users = parse_risk_ranking(payload("get_top_10_risky_users_incidents"))
    check(
        "get_top_10_risky_users_incidents -> list[RiskEntry] (sorted)",
        users
        and all(isinstance(u, RiskEntry) for u in users)
        and users == sorted(users, key=lambda e: (e.score is None, -(e.score or 0))),
    )
    print(
        f"      top user: {users[0].name} score={users[0].score} "
        f"rules={list(users[0].incidents)[:2]}"
    )

    devs = parse_risk_ranking(payload("get_top_10_risky_devices_incidents"))
    check(
        "get_top_10_risky_devices_incidents -> list[RiskEntry]",
        devs and isinstance(devs[0], RiskEntry),
    )

    ch = EventTable.model_validate(payload("query_fsm_clickhouse"))
    check("query_fsm_clickhouse -> EventTable", bool(ch.columns) and bool(ch.rows))
    print(f"      columns={ch.columns} first row={ch.rows[0]}")

    ack = MutationAck.model_validate(payload("append_incident_comment_by_id"))
    check("append_incident_comment_by_id -> MutationAck(.ok)", ack.ok)

    # query_fsm_postgres -> list[dict]
    pg = payload("query_fsm_postgres")
    check("query_fsm_postgres -> list[dict]", isinstance(pg, list) and isinstance(pg[0], dict))

    # prompts -> str
    pgp = unwrap_mcp_content(cap["query_fsm_postgres_prompts"])
    chp = unwrap_mcp_content(cap["query_fsm_clickhouse_prompts"])
    check("query_fsm_postgres_prompts -> str", isinstance(pgp, str) and len(pgp) > 50)
    check("query_fsm_clickhouse_prompts -> str", isinstance(chp, str) and len(chp) > 50)

    # error envelope raises
    try:
        unwrap_mcp_content({"content": [{"type": "text", "text": '{"error": "bad entity"}'}]})
        check("{error} payload raises FortiSIEMMCPError", False, "no raise")
    except FortiSIEMMCPError:
        check("{error} payload raises FortiSIEMMCPError", True)

    print(f"\n{check.passed} passed, {check.failed} failed (covering all 17 tools)")
    return 1 if check.failed else 0


# --------------------------------------------------------------------------- #
# Live — call every read-only tool against the box, print typed results.
# --------------------------------------------------------------------------- #
def run_live(mutate: bool) -> int:
    host, user, pw = os.environ["FSM_HOST"], os.environ["FSM_USER"], os.environ["FSM_PASS"]
    dom = os.environ.get("FSM_DOMAIN", "Super")
    c = FortiSIEMClient(host, user, pw, domain=dom, verify=False).login()
    cred = c.create_oauth_credential(f"example_mcp_{os.getpid()}")
    tok = c.mint_token(cred.client_id, cred.client_secret)
    check = Check()
    try:
        # Seed a real incident id + entity ip via raw REST.
        import time

        now = int(time.time() * 1000)
        rr = c._client.post(
            f"{c.phoenix}/rest/pub/incident",
            auth=(c._basic_user, c.password),
            json={
                "timeFrom": now - 7 * 86400_000,
                "timeTo": now,
                "size": 5,
                "filters": {"status": [0, 1]},
                "orderBy": "incidentLastSeen",
                "descending": True,
            },
        )
        incs = rr.json().get("data", []) if rr.is_success else []
        iid = incs[0]["incidentId"] if incs else None
        src = (incs[0].get("incidentRptIp") or "8.8.8.8") if incs else "8.8.8.8"
        print(f"seed incident id={iid} entity ip={src}\n")

        with c.mcp_session(tok) as s:
            print(f"tools/list: {len(s.list_tools())} tools advertised")

            r = s.get_incidents_by_entity(
                EntityIncidentQuery(time_value=24, time_unit="hours", ip=src)
            )
            check(
                "get_incidents_by_entity -> list[IncidentSummary]",
                all(isinstance(x, IncidentSummary) for x in r),
            )
            print(f"      {len(r)} incidents")

            if iid:
                d = s.get_incident_by_id(iid)
                check(
                    "get_incident_by_id -> IncidentDetailResult",
                    isinstance(d, IncidentDetailResult),
                )
                print(f"      total={d.total}")

                rel = s.get_related_incidents_by_id(iid)
                check(
                    "get_related_incidents_by_id -> list[Incident]",
                    isinstance(rel, list) and all(isinstance(x, Incident) for x in rel),
                )

                tbl = s.get_trigger_events_by_incident_id(iid)
                check(
                    "get_trigger_events_by_incident_id -> EventTable", isinstance(tbl, EventTable)
                )
                print(f"      {len(tbl.columns)} columns / {len(tbl.rows)} rows")

                iocs = s.get_iocs_by_incident_ids([iid])
                check(
                    "get_iocs_by_incident_ids -> list[IocEntry]",
                    all(isinstance(x, IocEntry) for x in iocs),
                )

            try:
                ctx = s.get_context_by_entity(EntityContextQuery(ip=src))
                check("get_context_by_entity -> EntityContext", isinstance(ctx, EntityContext))
            except FortiSIEMMCPError as e:
                print(f"  [skip] get_context_by_entity (no context for {src}): {e}")

            rep = s.get_reputation_by_entity(EntityReputationQuery(ip=["8.8.8.8"]))
            check(
                "get_reputation_by_entity -> list[Reputation]",
                all(isinstance(x, Reputation) for x in rep),
            )

            users = s.top_10_risky_users()
            check(
                "get_top_10_risky_users_incidents -> list[RiskEntry]",
                all(isinstance(x, RiskEntry) for x in users),
            )
            print(
                f"      top user: {users[0].name} score={users[0].score}"
                if users
                else "      (none)"
            )
            devs = s.top_10_risky_devices()
            check(
                "get_top_10_risky_devices_incidents -> list[RiskEntry]",
                all(isinstance(x, RiskEntry) for x in devs),
            )

            pg = s.query_postgres("SELECT 1 AS one")
            check("query_fsm_postgres -> list[dict]", pg == [{"one": 1}])
            ch = s.query_clickhouse(
                "SELECT eventType, count(*) c FROM events GROUP BY eventType LIMIT 3"
            )
            check(
                "query_fsm_clickhouse -> EventTable",
                isinstance(ch, EventTable) and bool(ch.columns),
            )

            check("query_fsm_postgres_prompts -> str", isinstance(s.query_postgres_prompts(), str))
            check(
                "query_fsm_clickhouse_prompts -> str", isinstance(s.query_clickhouse_prompts(), str)
            )

            # Mutating tools — only the benign comment append, only with --mutate.
            if mutate and iid:
                ack = s.append_incident_comment_by_id(
                    IncidentUpdate(incidentId=iid, comments="example_mcp.py live demo (benign)")
                )
                check(
                    "append_incident_comment_by_id -> MutationAck(.ok)",
                    isinstance(ack, MutationAck) and ack.ok,
                )
            else:
                print(
                    "  [skip] mutating tools (update/clear/comment)"
                    " — pass --mutate to run the benign comment"
                )
    finally:
        try:
            c.revoke_oauth_credential(cred.id)
        finally:
            c.close()
    print(f"\n{check.passed} passed, {check.failed} failed")
    return 1 if check.failed else 0


def main() -> int:
    print_io_table()
    if "--live" in sys.argv:
        return run_live(mutate="--mutate" in sys.argv)
    return run_offline()


if __name__ == "__main__":
    raise SystemExit(main())

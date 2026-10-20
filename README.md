# pyfortisiem

[![PyPI](https://img.shields.io/pypi/v/pyfortisiem.svg)](https://pypi.org/project/pyfortisiem/)
[![CI](https://github.com/ftnt-dspille/pyfortisiem/actions/workflows/ci.yml/badge.svg)](https://github.com/ftnt-dspille/pyfortisiem/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/pyfortisiem.svg)](https://pypi.org/project/pyfortisiem/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**The first Python client for the FortiSIEM REST API — async-first, fully typed, and the only library that speaks the FortiSIEM 8.0 MCP server.**

The `pyforti*` family covers FortiGate, FortiManager, and FortiZTP — but nothing for FortiSIEM. `pyfortisiem` fills that gap with a pooled async incident/event client, a sync client that automates all three FortiSIEM auth flows (including the CSRF-gated credential-management surface), and a typed session over the new MCP tool catalogue.

> Not affiliated with, authorized, maintained, sponsored, or endorsed by Fortinet. See [NOTICE](NOTICE).

## Install

```bash
pip install pyfortisiem
```

## Quickstart — async incidents + events

FortiSIEM event retrieval is server-side asynchronous (submit query → poll progress → page result). `pyfortisiem` maps that onto `asyncio` so many incidents enrich concurrently under one shared concurrency gate.

```python
import asyncio
from pyfortisiem import AsyncFortiSIEMClient

async def main():
    async with AsyncFortiSIEMClient.with_basic_auth(
        "fortisiem.example.com:443", "admin", "pw", domain="Super",
        max_concurrency=10,
    ) as fsm:
        # marquee: one incident + its triggering events, fetched concurrently
        inc = await fsm.get_incident_with_events(123456)
        print(inc.incident_title, len(inc.events))

        # bulk: list incidents and enrich each with events, bounded by the gate
        incs = await fsm.list_incidents_with_events(status=[0], size=50)

asyncio.run(main())
```

## License + health

```python
from pyfortisiem import FortiSIEMClient

with FortiSIEMClient("fortisiem.example.com:443", "admin", "pw") as c:
    lic = c.license_info()              # h5 session, logs in on first use
    print(lic.serial, lic.type, lic.license_end, lic.days_left(), lic.is_valid())
    print([(o.name, o.ok) for o in c.health_summary()])   # supervisor + collectors
```

## Auth modes

| Mode | How | Use for |
|------|-----|---------|
| **Basic auth** | `with_basic_auth(host, user, pw, domain=...)` | public `/phoenix/rest/...` reads (incidents, events, queries) |
| **OAuth2 API key** | `with_api_key(host, client_id, client_secret)` | bearer token (lazy mint + 401 re-mint); **the only auth the MCP endpoint accepts** |
| **Session (h5)** | sync `FortiSIEMClient(...).login()` | the CSRF-gated GUI surface — the only one that can create/revoke API-token credentials |

The h5 surface is CSRF-protected: every state-changing call must echo the `s` session cookie back **hex-encoded** as an `s:` header (the GUI's `hexEncode(getCookie("s"))`). The sync client handles this for you:

```python
from pyfortisiem import FortiSIEMClient

c = FortiSIEMClient("fortisiem.example.com:443", "admin", "pw", domain="Super")
cred = c.create_oauth_credential("automation")        # h5 / CSRF flow
token = c.mint_token(cred.client_id, cred.client_secret)
print([t.name for t in c.mcp_list_tools(token)])      # OAuth bearer → MCP
```

## MCP — FortiSIEM 8.0

`MCPSession` wraps all 17 tools the FortiSIEM MCP server advertises, each with a typed pydantic input model and decoded response. The server double-wraps payloads in nested `content[].text` envelopes (sometimes JSON, sometimes Python `repr`); `unwrap_mcp_content` peels that off and the response models type what's underneath.

| Tool | Input | Output |
|------|-------|--------|
| `get_incidents_by_entity` | `EntityIncidentQuery` | `list[IncidentSummary]` |
| `get_incident_by_id` | `IncidentId` | `IncidentDetailResult` |
| `get_related_incidents_by_id` | `IncidentId` | `list[Incident]` |
| `get_trigger_events_by_incident_id` | `IncidentId` | `EventTable` |
| `get_context_by_entity` | `EntityContextQuery` | `EntityContext` |
| `get_reputation_by_entity` | `EntityReputationQuery` | `list[Reputation]` |
| `get_iocs_by_incident_ids` | `IncidentIds` | `list[IocEntry]` |
| `update_incident_severity_by_id` | `IncidentUpdate` | `MutationAck` |
| `update_incident_resolution_by_id` | `IncidentUpdate` | `MutationAck` |
| `append_incident_comment_by_id` | `IncidentUpdate` | `MutationAck` |
| `clear_incident_by_id` | `IncidentId` | `MutationAck` |
| `get_top_10_risky_users_incidents` | — | `list[RiskEntry]` |
| `get_top_10_risky_devices_incidents` | — | `list[RiskEntry]` |
| `query_fsm_postgres` | `sql: str` | `list[dict]` |
| `query_fsm_clickhouse` | `sql: str` | `EventTable` |
| `query_fsm_postgres_prompts` | — | `str` |
| `query_fsm_clickhouse_prompts` | — | `str` |

```python
from pyfortisiem import FortiSIEMClient
from pyfortisiem.models import EntityIncidentQuery

c = FortiSIEMClient("fortisiem.example.com:443", "admin", "pw")
token = c.mint_token(client_id, client_secret)
with c.mcp_session(token) as s:
    for inc in s.get_incidents_by_entity(EntityIncidentQuery(ip="203.0.113.7")):
        print(inc.incident_id, inc.incident_title)
```

### Two incident shapes

The MCP entity tools (`get_incidents_by_entity`, `get_related_incidents_by_id`*) return curated snake_case `IncidentSummary` rows, while `get_incident_by_id`'s `.data` and the REST surface return the raw camelCase `Incident`. The shared models — `Incident`, `Event`, `EventTable`, `MutationAck` — are reused across both surfaces so you learn them once.

## Concurrency & query lifecycle

`max_concurrency` (default 10) caps in-flight requests via one shared semaphore, and the httpx connection pool is sized to match. For large evidence sets, pass `use_query_lifecycle=True` to drive the `triggeringEvents/start → progress → result` async path instead of the direct endpoint.

## Development

```bash
pip install -e ".[test]"
pytest                 # offline suites — no appliance needed
pytest -m live         # opt-in live tests; needs FSM_* env (see examples/)
```

## License

MIT — see [LICENSE](LICENSE).

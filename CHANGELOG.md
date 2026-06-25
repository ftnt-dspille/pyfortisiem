# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Initial public release.
- `AsyncFortiSIEMClient` — fully-async, typed REST client over the FortiSIEM
  incident/event surface; basic-auth and OAuth2-bearer modes; configurable
  `max_concurrency`; direct and start/progress/result event lifecycles; marquee
  `get_incident_with_events` / bulk `list_incidents_with_events`.
- `FortiSIEMClient` — sync client covering all three auth flows (basic, h5/CSRF
  session, OAuth2) plus OAuth API-token credential management.
- `MCPSession` — typed session over the FortiSIEM 8.0 MCP server (17 tools) with
  `unwrap_mcp_content` envelope decoding.
- Pydantic models for incidents, events, MCP tool I/O, and auth artifacts.
- Offline pytest suites (httpx MockTransport + captured MCP response fixtures).

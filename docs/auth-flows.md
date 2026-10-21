# FortiSIEM auth flows

FortiSIEM exposes three authentication surfaces; `pyfortisiem` covers all three.

## 1. Basic auth → public REST (`/phoenix/rest/...`)

The simplest surface, good for incident/event reads and queries. The account is
sent org-qualified on the wire (`super/admin`). Both clients support it:

```python
AsyncFortiSIEMClient.with_basic_auth(host, "admin", "pw", domain="Super")
FortiSIEMClient(host, "admin", "pw", domain="Super")
```

## 2. Session (h5) auth → GUI internal REST (`/phoenix/rest/h5/...`)

The **only** surface that can manage OAuth API-token credentials
(ADMIN → Setup → System → API Token). It is CSRF-protected: every
state-changing call must echo the `s` session cookie back **hex-encoded** in an
`s:` header — the GUI's `hexEncode(getCookie("s"))`. Without it the backend
returns a bare `403`. `FortiSIEMClient.login()` + the credential-management
methods handle this transparently:

```python
c = FortiSIEMClient(host, "admin", "pw").login()
cred = c.create_oauth_credential("automation")  # client_secret returned once
c.revoke_oauth_credential(cred.id)
```

## 3. OAuth2 `client_credentials` → bearer token

A bearer minted at `/phoenix/rest/pub/security/oauth/token` from a
client_id/secret created via flow #2. This bearer is what the **MCP server** at
`/phoenix/mcp` requires, and it also works on the public REST API. The token
inherits the permissions of the user that created the credential.

```python
token = c.mint_token(cred.client_id, cred.client_secret)
# AsyncFortiSIEMClient mints + caches the bearer for you, re-minting once on 401:
AsyncFortiSIEMClient.with_api_key(host, client_id, client_secret)
```

## MCP transport

The FortiSIEM MCP server speaks streamable-HTTP JSON-RPC: `initialize` returns
an `mcp-session-id` header that subsequent calls echo, and responses arrive as
Server-Sent Events. Payloads are double-wrapped in nested `content[].text`
envelopes whose innermost text is sometimes JSON and sometimes a Python `repr`;
`unwrap_mcp_content` peels both layers and raises `FortiSIEMMCPError` on an
`{"error": ...}` payload.

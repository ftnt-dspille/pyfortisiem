"""pyfortisiem — async + sync + MCP client for FortiSIEM.

Public surface:

* :class:`AsyncFortiSIEMClient` — fully-async, typed REST client over the
  incident/event surface (basic auth or OAuth2 bearer).
* :class:`FortiSIEMClient` — sync client covering all three auth flows
  (basic, h5/CSRF session, OAuth2) plus credential management.
* :class:`MCPSession` — typed session over the FortiSIEM 8.0 MCP server.
* :func:`unwrap_mcp_content` — peel the MCP double-wrapped response envelope.
* the pydantic models in :mod:`pyfortisiem.models`.
* :class:`FortiSIEMError`, :class:`FortiSIEMMCPError`.

Not affiliated with or endorsed by Fortinet. See NOTICE.
"""

from __future__ import annotations

from . import models
from .async_client import AsyncFortiSIEMClient
from .client import FortiSIEMClient, MCPSession, unwrap_mcp_content
from .exceptions import FortiSIEMError, FortiSIEMMCPError

try:  # version is injected at build time by hatch-vcs
    from ._version import __version__
except ImportError:  # editable/source checkout without a build
    __version__ = "0.0.0+unknown"

__all__ = [
    "AsyncFortiSIEMClient",
    "FortiSIEMClient",
    "MCPSession",
    "unwrap_mcp_content",
    "FortiSIEMError",
    "FortiSIEMMCPError",
    "models",
    "__version__",
]

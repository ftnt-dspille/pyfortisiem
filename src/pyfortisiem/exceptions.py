"""Exception types shared across the FortiSIEM client surfaces."""

from __future__ import annotations

__all__ = ["FortiSIEMError", "FortiSIEMMCPError"]


class FortiSIEMError(RuntimeError):
    """Any non-retryable FortiSIEM API failure."""


class FortiSIEMMCPError(RuntimeError):
    """An MCP tool returned an ``{"error": ...}`` payload or signalled ``isError``."""

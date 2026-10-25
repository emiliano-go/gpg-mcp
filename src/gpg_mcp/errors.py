"""Typed errors that are safe to surface to an MCP client."""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from mcp.server.mcpserver.exceptions import ToolError

_SECRET_MARKERS = (
    "PRIVATE KEY BLOCK",
    "SECRET KEY BLOCK",
    "PRIVATE KEY-----",
)

_PASSPHRASE_RE = re.compile(r"(?i)\bpassphrase\b\s*[:=]\s*\S+")
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text(text: str, *, limit: int = 200_000) -> str:
    """Strip terminal escapes/control bytes from untrusted gpg/UID text."""
    if not text:
        return text
    return _CONTROL_RE.sub("", _ANSI_RE.sub("", text))[:limit]


def single_line(text: str, *, limit: int = 512) -> str:
    """Render untrusted text safely inside a one-line approval dialog.

    Newlines, carriage returns, tabs, backslashes, ANSI escapes and Unicode
    format/line-separator characters are escaped so a crafted UID cannot forge
    a second line or visually reorder the dialog.
    """
    if not text:
        return text
    cleaned = sanitize_text(text, limit=limit * 4)
    escaped: list[str] = []
    for ch in cleaned:
        category = unicodedata.category(ch)
        if ch == "\\":
            escaped.append("\\\\")
        elif ch == "\n":
            escaped.append("\\n")
        elif ch == "\r":
            escaped.append("\\r")
        elif ch == "\t":
            escaped.append("\\t")
        elif category in {"Cf", "Cc", "Zl", "Zp"}:
            escaped.append(f"\\u{ord(ch):04x}")
        else:
            escaped.append(ch)
    return "".join(escaped)[:limit]


def contains_secret_material(text: str) -> bool:
    """Return True when text looks like it contains private key material."""
    if not text:
        return False
    upper = text.upper()
    return any(marker in upper for marker in _SECRET_MARKERS)


def redact(text: str) -> str:
    """Best-effort redaction for anything that must never reach the agent."""
    if not text:
        return text
    if contains_secret_material(text):
        return "[redacted: private key material was produced by gpg and blocked]"
    return _PASSPHRASE_RE.sub("passphrase: [redacted]", text)


class GpgMcpError(ToolError):
    """Base error for gpg-mcp. Subclasses ToolError so the MCP client sees the reason."""

    code = "gpg_error"

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        detail: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code or self.code
        self.detail = redact(detail) if detail else None
        self.data = data or {}

    def __str__(self) -> str:
        message = f"[{self.code}] {self.message}"
        if self.detail:
            message += f": {self.detail[-1000:]}"
        return redact(message)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": False,
            "error": self.code,
            "message": redact(self.message),
        }
        if self.detail:
            payload["detail"] = self.detail[-4000:]
        if self.data:
            payload["data"] = self.data
        return payload


class PolicyError(GpgMcpError):
    code = "policy_denied"


class ApprovalError(GpgMcpError):
    code = "approval_required"


class InputError(GpgMcpError):
    code = "invalid_input"


class GpgExecutionError(GpgMcpError):
    code = "gpg_failed"

    def __init__(
        self,
        message: str,
        *,
        returncode: int | None = None,
        stderr: str | None = None,
        status: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(message, detail=stderr, data={"returncode": returncode} if returncode is not None else None)
        self.returncode = returncode
        self.stderr = redact(stderr or "")
        self.status = status or []


class TimeoutError_(GpgMcpError):
    code = "timeout"


class OutputLimitError(GpgMcpError):
    code = "output_too_large"


class AuditError(GpgMcpError):
    code = "audit_unavailable"

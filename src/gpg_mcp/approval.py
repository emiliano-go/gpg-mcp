"""Human approval gates for high-risk operations.

The default mode is ``client``: the MCP client is asked through an
elicitation resolver, which works on both legacy and current protocol
versions. ``local`` uses an operating-system dialog (zenity) and is
independent of the MCP client. ``none`` exists for disposable test
keyrings and is recorded in the audit log.
"""

from __future__ import annotations

import asyncio
import os
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from mcp.server.mcpserver import (
    AcceptedElicitation,
    CancelledElicitation,
    DeclinedElicitation,
    Elicit,
    ElicitationResult,
)
from pydantic import BaseModel, Field

from .binaries import secure_binary
from .errors import GpgMcpError, single_line
from .policy import (
    Operation,
    assert_registered_operation,
    audit,
    get_policy,
    requires_approval,
)

_APPROVAL_CTX: ContextVar[Any | None] = ContextVar("gpg_mcp_approval_ctx", default=None)


def set_approval_context(ctx: Any | None) -> None:
    """Called by each resolver so approval can inspect client capabilities."""
    _APPROVAL_CTX.set(ctx)


def _client_can_elicit() -> bool:
    ctx = _APPROVAL_CTX.get()
    if ctx is None:
        return False
    params = getattr(getattr(ctx, "session", None), "client_params", None)
    capabilities = getattr(params, "capabilities", None)
    return bool(capabilities is not None and getattr(capabilities, "elicitation", None) is not None)


class Confirm(BaseModel):
    approve: bool = Field(description="Approve this gpg-mcp operation?")


class DestructiveConfirm(BaseModel):
    approve: bool = Field(description="Approve this destructive operation?")
    confirmation: str = Field(
        description="Type the last 8 characters of the key fingerprint to confirm"
    )


@dataclass(frozen=True)
class Decision:
    approved: bool
    reason: str


def _summary_hash(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def payload_summary(action: str, data: bytes, *, key: str = "", extra: str = "") -> str:
    preview = ""
    try:
        text = data[:200].decode("utf-8")
        if text.isprintable() and "\x00" not in text:
            preview = "\nPreview: " + single_line(text, limit=120)
    except UnicodeDecodeError:
        pass
    parts = [
        f"gpg-mcp wants to {action}.",
        f"Key: {key}" if key else "",
        f"Size: {len(data)} bytes",
        f"SHA-256: {_summary_hash(data)}",
        extra,
        preview,
    ]
    return "\n".join(part for part in parts if part)


def _zenity() -> str | None:
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return None
    try:
        return secure_binary("zenity", required=False)
    except GpgMcpError:
        # An unsafe zenity must fail closed, never imitate approval.
        return None


async def _zenity_question(summary: str) -> bool:
    binary = _zenity()
    if not binary:
        return False
    try:
        proc = await asyncio.create_subprocess_exec(
            binary,
            "--question",
            "--title",
            "gpg-mcp approval",
            "--width",
            "640",
            "--text",
            summary,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            code = await asyncio.wait_for(proc.wait(), timeout=180)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return False
        return code == 0
    except OSError:
        return False


async def _zenity_entry(summary: str, prompt: str) -> str | None:
    binary = _zenity()
    if not binary:
        return None
    try:
        proc = await asyncio.create_subprocess_exec(
            binary,
            "--entry",
            "--title",
            "gpg-mcp destructive confirmation",
            "--width",
            "640",
            "--text",
            f"{summary}\n\n{prompt}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return None
        if proc.returncode != 0:
            return None
        return out.decode("utf-8", errors="replace").strip()
    except OSError:
        return None


def _require_local_approval_available() -> None:
    if _zenity() is None:
        raise GpgMcpError(
            "the MCP client does not support elicitation and local approval is "
            "unavailable; install zenity/run with a display, or set approval='local'",
            code="approval_unavailable",
        )


def _required_operations(ops: list[str]) -> tuple[Any, list[str]]:
    """Resolve the operations that actually require approval.

    Unknown operation names raise instead of being treated as pre-approved.
    Composite operations inherit every constituent's requirement.
    """
    policy = get_policy()
    for op in ops:
        assert_registered_operation(op)
    required = [op for op in ops if requires_approval(policy, op)]
    return policy, required


def _audit_approval(policy: Any, ops: list[str], decision: str, *, destructive: bool = False) -> None:
    # Deliberately no summary: summaries contain payload previews.
    audit(
        policy,
        {
            "event": "approval",
            "operations": ops,
            "decision": decision,
            "destructive": destructive,
        },
        phase="approval",
    )


async def request_all(ops: list[str], summary: str) -> Confirm | Elicit[Confirm]:
    """Ask once when any constituent operation requires approval."""
    policy, required = _required_operations(ops)
    if not required:
        return Confirm(approve=True)
    if policy.approval == "none":
        _audit_approval(policy, required, "skipped")
        return Confirm(approve=True)
    if policy.approval == "local":
        approved = await _zenity_question(summary)
        _audit_approval(policy, required, "local_accept" if approved else "local_decline")
        return Confirm(approve=approved)
    if not _client_can_elicit():
        # The client did not declare elicitation. Fall back to an OS dialog,
        # which is independent of the MCP client and still a human gate.
        _require_local_approval_available()
        approved = await _zenity_question(summary)
        _audit_approval(
            policy,
            required,
            "local_fallback_accept" if approved else "local_fallback_decline",
        )
        return Confirm(approve=approved)
    return Elicit(summary, Confirm)


async def request(op: str, summary: str) -> Confirm | Elicit[Confirm]:
    """Return a decision, or ask the MCP client to decide."""
    return await request_all([op], summary)


async def request_destructive(
    op: str, summary: str, fingerprint: str
) -> DestructiveConfirm | Elicit[DestructiveConfirm]:
    spec: Operation = assert_registered_operation(op)
    if not spec.destructive:
        raise GpgMcpError(
            f"{op} is not registered as destructive; refusing destructive approval path",
            code="policy_error",
        )
    policy, required = _required_operations([op])
    suffix = fingerprint[-8:].upper()
    if not required and not policy.destructive_confirmation:
        # Explicit opt-out from both approval and typed confirmation.
        _audit_approval(policy, [op], "configured_skip", destructive=True)
        return DestructiveConfirm(approve=True, confirmation=suffix)
    if policy.approval == "none":
        _audit_approval(policy, required or [op], "skipped", destructive=True)
        return DestructiveConfirm(approve=True, confirmation=suffix)
    fallback = policy.approval != "local" and not _client_can_elicit()
    if policy.approval == "local" or fallback:
        if fallback:
            _require_local_approval_available()
        approved = await _zenity_question(summary)
        typed = (
            await _zenity_entry(summary, f"Type the last 8 characters: {suffix}")
            if approved
            else None
        )
        ok = bool(approved and typed and typed.strip().upper() == suffix)
        decision = ("local_fallback_" if fallback else "local_") + (
            "accept" if ok else "decline"
        )
        _audit_approval(policy, required or [op], decision, destructive=True)
        return DestructiveConfirm(approve=ok, confirmation=typed or "")
    return Elicit(
        f"{summary}\n\nThis is destructive. Type the last 8 characters of the "
        f"fingerprint ({suffix}) to confirm.",
        DestructiveConfirm,
    )


def evaluate(result: ElicitationResult[Any] | Confirm | DestructiveConfirm) -> Decision:
    if isinstance(result, Confirm):
        return Decision(result.approve, "accepted" if result.approve else "declined")
    if isinstance(result, DestructiveConfirm):
        return Decision(result.approve, "accepted" if result.approve else "declined")
    match result:
        case AcceptedElicitation(data=Confirm(approve=approved)):
            return Decision(approved, "accepted" if approved else "declined")
        case AcceptedElicitation(data=DestructiveConfirm()):
            return Decision(False, "destructive confirmation required")
        case DeclinedElicitation():
            return Decision(False, "declined")
        case CancelledElicitation():
            return Decision(False, "cancelled")
        case _:
            return Decision(False, "no approval")


def evaluate_destructive(
    result: ElicitationResult[Any] | DestructiveConfirm, fingerprint: str
) -> Decision:
    suffix = fingerprint[-8:].upper()
    if isinstance(result, DestructiveConfirm):
        if result.approve and result.confirmation.strip().upper() == suffix:
            return Decision(True, "accepted")
        if not result.approve:
            return Decision(False, "declined")
        return Decision(False, "confirmation text did not match")
    match result:
        case AcceptedElicitation(data=DestructiveConfirm(approve=True, confirmation=typed)):
            if typed.strip().upper() == suffix:
                return Decision(True, "accepted")
            return Decision(False, "confirmation text did not match")
        case AcceptedElicitation(data=DestructiveConfirm(approve=False)):
            return Decision(False, "declined")
        case DeclinedElicitation():
            return Decision(False, "declined")
        case CancelledElicitation():
            return Decision(False, "cancelled")
        case _:
            return Decision(False, "no approval")


def record_decision(
    op: str,
    decision: Decision,
    *,
    fingerprint: str | None = None,
    operations: list[str] | None = None,
    **extra: Any,
) -> None:
    audit(
        get_policy(),
        {
            "event": "approval_result",
            "operation": op,
            "operations": operations or [op],
            "decision": decision.reason,
            "approved": decision.approved,
            "fingerprint": fingerprint,
            **extra,
        },
        phase="intent",
    )


def require_approved(decision: Decision, op: str) -> None:
    if not decision.approved:
        raise GpgMcpError(
            f"{op} was not approved ({decision.reason})",
            code="approval_denied",
        )

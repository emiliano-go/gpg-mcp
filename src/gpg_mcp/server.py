"""MCP tool surface for gpg-mcp.

Design rules enforced here:
  * secret key material is never returned, imported or exported;
  * signing/decryption/encryption/key-management calls pass an approval gate;
  * destructive calls require typing the fingerprint suffix;
  * every high-risk operation is written to the audit ledger.
"""

from __future__ import annotations

import hashlib
from typing import Annotated, Any, Literal

from mcp.server import MCPServer
from mcp.server.mcpserver import Context, Elicit, ElicitationResult, Resolve
from mcp.types import ToolAnnotations

from .approval import (
    Confirm,
    DestructiveConfirm,
    evaluate,
    evaluate_destructive,
    payload_summary,
    record_decision,
    request,
    request_all,
    request_destructive,
    require_approved,
    set_approval_context,
)
from .gpg import Gpg
from .policy import (
    audit,
    decode_payload,
    get_policy,
    require_fingerprint,
)

INSTRUCTIONS = """\
gpg-mcp is a security-focused GnuPG wrapper.

Private keys never leave gpg-agent and are never returned by any tool. The
server never accepts a passphrase: gpg-agent asks through pinentry. Signing,
decryption, encryption and key management are gated by policy and an explicit
human approval; destructive operations require typing the fingerprint suffix.

If an operation is denied, do not attempt to work around the policy. Use
list_keys/get_key to discover full fingerprints; only full fingerprints are
accepted for key selection.
"""

READ = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)
NETWORK_READ = ToolAnnotations(readOnlyHint=True, openWorldHint=True)
NETWORK_WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True)

mcp = MCPServer("gpg-mcp", version="0.1.0", instructions=INSTRUCTIONS)

_GPGS: Gpg | None = None


def gpg() -> Gpg:
    global _GPGS
    if _GPGS is None:
        _GPGS = Gpg(get_policy())
    return _GPGS


def reset_gpg() -> None:
    """Used by tests after switching GNUPGHOME."""
    global _GPGS
    _GPGS = None


def _decode(data: str | None, data_base64: str | None) -> bytes:
    return decode_payload(data, data_base64, limit=get_policy().max_input_bytes)


def _audit(tool: str, **fields: Any) -> None:
    audit(get_policy(), {"event": "operation", "tool": tool, **fields})


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


async def _key_label(fingerprint: str | None) -> str:
    """Human-readable signer/recipient label for approval forms."""
    fpr = (fingerprint or "").strip().upper()
    if not fpr:
        return "unspecified"
    try:
        key = await gpg().get_key(fpr)
    except Exception:  # noqa: BLE001 - labels are best effort
        return fpr
    uids = ", ".join(item["uid"] for item in key["uids"][:2])
    return f"{fpr} ({uids})" if uids else fpr


# ---------------------------------------------------------------------------
# approval resolvers
# ---------------------------------------------------------------------------

async def _ask_sign(
    data: str | None = None,
    data_base64: str | None = None,
    signer: str = "",
    mode: str = "detached",
    armor: bool = True,
    hash_algo: str = "SHA256",
    ctx: Context | None = None,
) -> Confirm | Elicit[Confirm]:
    set_approval_context(ctx)
    payload = _decode(data, data_base64)
    return await request(
        "sign",
        payload_summary(
            "sign data",
            payload,
            key=await _key_label(signer),
            extra=f"Mode: {mode}\nArmor: {armor}\nHash: {hash_algo}",
        ),
    )


async def _ask_encrypt(
    data: str | None = None,
    data_base64: str | None = None,
    recipients: list[str] | None = None,
    sign_with: str | None = None,
    armor: bool = True,
    ctx: Context | None = None,
) -> Confirm | Elicit[Confirm]:
    set_approval_context(ctx)
    payload = _decode(data, data_base64)
    recipient_labels = [await _key_label(recipient) for recipient in (recipients or [])]
    recipient_text = "\n".join(f"- {label}" for label in recipient_labels) or "- none"
    signer_label = await _key_label(sign_with) if sign_with else "no"
    operations = ["encrypt"] + (["sign"] if sign_with else [])
    return await request_all(
        operations,
        payload_summary(
            "encrypt data",
            payload,
            extra=(
                f"Recipients:\n{recipient_text}\n"
                f"Sign with: {signer_label}\nArmor: {armor}"
            ),
        ),
    )


async def _ask_sign_and_encrypt(
    data: str | None = None,
    data_base64: str | None = None,
    recipients: list[str] | None = None,
    signer: str = "",
    armor: bool = True,
    ctx: Context | None = None,
) -> Confirm | Elicit[Confirm]:
    set_approval_context(ctx)
    payload = _decode(data, data_base64)
    recipient_labels = [await _key_label(recipient) for recipient in (recipients or [])]
    recipient_text = "\n".join(f"- {label}" for label in recipient_labels) or "- none"
    return await request_all(
        ["sign", "encrypt"],
        payload_summary(
            "sign and encrypt data",
            payload,
            key=await _key_label(signer),
            extra=f"Recipients:\n{recipient_text}\nArmor: {armor}",
        ),
    )


async def _ask_decrypt(
    ciphertext: str | None = None,
    ciphertext_base64: str | None = None,
    verify: bool = True,
    expected_key: str | None = None,
    ctx: Context | None = None,
) -> Confirm | Elicit[Confirm]:
    set_approval_context(ctx)
    payload = _decode(ciphertext, ciphertext_base64)
    label = await _key_label(expected_key) if expected_key else "auto"
    return await request(
        "decrypt",
        payload_summary(
            "decrypt ciphertext",
            payload,
            key=label,
            extra=f"Verify embedded signature: {verify}\nPlaintext will be returned.",
        ),
    )


async def _ask_symmetric_encrypt(
    data: str | None = None, data_base64: str | None = None, armor: bool = True,
    ctx: Context | None = None,
) -> Confirm | Elicit[Confirm]:
    set_approval_context(ctx)
    payload = _decode(data, data_base64)
    return await request(
        "symmetric_encrypt",
        payload_summary("symmetrically encrypt data", payload, extra=f"Armor: {armor}"),
    )


async def _ask_symmetric_decrypt(
    ciphertext: str | None = None, ciphertext_base64: str | None = None,
    ctx: Context | None = None,
) -> Confirm | Elicit[Confirm]:
    set_approval_context(ctx)
    payload = _decode(ciphertext, ciphertext_base64)
    return await request(
        "symmetric_decrypt",
        payload_summary("symmetrically decrypt data", payload),
    )


async def _ask_create_key(
    uid: str = "",
    algo: str = "ed25519",
    expire: str = "2y",
    protect: bool = True,
    subkey_algo: str = "cv25519",
    ctx: Context | None = None,
) -> Confirm | Elicit[Confirm]:
    set_approval_context(ctx)
    warning = "" if protect else "\nWARNING: the new key will have NO passphrase."
    return await request(
        "create_key",
        f"gpg-mcp wants to create a key.\nUID: {uid}\nAlgorithm: {algo}\n"
        f"Subkey: {subkey_algo}\nExpire: {expire}\nProtected: {protect}{warning}",
    )


async def _ask_add_subkey(
    fingerprint: str = "", algo: str = "cv25519", expire: str = "2y", usage: str = "default",
    ctx: Context | None = None,
) -> Confirm | Elicit[Confirm]:
    set_approval_context(ctx)
    return await request(
        "add_subkey",
        f"gpg-mcp wants to add a subkey.\nFingerprint: {fingerprint}\n"
        f"Algorithm: {algo}\nUsage: {usage}\nExpire: {expire}",
    )


async def _ask_add_uid(fingerprint: str = "", uid: str = "", ctx: Context | None = None) -> Confirm | Elicit[Confirm]:
    set_approval_context(ctx)
    return await request(
        "add_uid", f"gpg-mcp wants to add a UID.\nFingerprint: {fingerprint}\nUID: {uid}"
    )


async def _ask_set_expiry(
    fingerprint: str = "", expire: str = "", subkeys: bool = False,
    ctx: Context | None = None,
) -> Confirm | Elicit[Confirm]:
    set_approval_context(ctx)
    return await request(
        "set_expiry",
        f"gpg-mcp wants to change key expiry.\nFingerprint: {fingerprint}\n"
        f"Expire: {expire}\nSubkeys: {subkeys}",
    )


async def _ask_change_passphrase(fingerprint: str = "", ctx: Context | None = None) -> Confirm | Elicit[Confirm]:
    set_approval_context(ctx)
    return await request(
        "change_passphrase",
        f"gpg-mcp wants to change the passphrase for {fingerprint}.\n"
        "The old and new passphrases are entered only into pinentry.",
    )


async def _ask_import_public_key(
    key: str | None = None, key_base64: str | None = None, allow_secret: bool = False,
    ctx: Context | None = None,
) -> Confirm | Elicit[Confirm]:
    set_approval_context(ctx)
    payload = _decode(key, key_base64)
    return await request(
        "import_public_key",
        payload_summary(
            "import an OpenPGP key",
            payload,
            extra=f"Secret import requested: {allow_secret}",
        ),
    )


async def _ask_set_ownertrust(
    fingerprint: str = "", level: str = "", ctx: Context | None = None
) -> Confirm | Elicit[Confirm]:
    set_approval_context(ctx)
    return await request(
        "set_ownertrust",
        f"gpg-mcp wants to set ownertrust.\nFingerprint: {fingerprint}\nLevel: {level}",
    )


async def _ask_generate_revocation(fingerprint: str = "", ctx: Context | None = None) -> Confirm | Elicit[Confirm]:
    set_approval_context(ctx)
    fpr = require_fingerprint(fingerprint)
    return await request(
        "generate_revocation",
        f"gpg-mcp wants to export the revocation certificate for {await _key_label(fpr)}.\n"
        "This certificate can permanently revoke the key; store it offline.",
    )


async def _ask_send_key(fingerprint: str = "", ctx: Context | None = None) -> Confirm | Elicit[Confirm]:
    set_approval_context(ctx)
    policy = get_policy()
    return await request(
        "send_key",
        f"gpg-mcp wants to publish a public key.\nFingerprint: {fingerprint}\n"
        f"Keyserver: {policy.keyserver}",
    )


async def _ask_delete_key(
    fingerprint: str = "", secret: bool = False,
    ctx: Context | None = None,
) -> DestructiveConfirm | Elicit[DestructiveConfirm]:
    set_approval_context(ctx)
    fpr = fingerprint.strip().upper()
    what = "the SECRET and public key" if secret else "the public key"
    return await request_destructive(
        "delete_key",
        f"gpg-mcp wants to DELETE {what}.\nFingerprint: {fpr}\n"
        "This cannot be undone unless you have a backup.",
        fpr,
    )


async def _ask_revoke_key(
    fingerprint: str = "", ctx: Context | None = None
) -> DestructiveConfirm | Elicit[DestructiveConfirm]:
    set_approval_context(ctx)
    fpr = require_fingerprint(fingerprint)
    return await request_destructive(
        "revoke_key",
        f"gpg-mcp wants to REVOKE this key permanently.\nTarget: {await _key_label(fpr)}",
        fpr,
    )


async def _ask_import_revocation(
    certificate: str | None = None,
    certificate_base64: str | None = None,
    fingerprint: str = "",
    apply: bool = True,
    ctx: Context | None = None,
) -> DestructiveConfirm | Elicit[DestructiveConfirm]:
    set_approval_context(ctx)
    payload = _decode(certificate, certificate_base64)
    requested = require_fingerprint(fingerprint)
    validated = await gpg().inspect_revocation(
        payload, expected_fingerprint=requested
    )
    actual = validated["fingerprint"]
    label = actual
    if validated.get("uid"):
        label += f" ({validated['uid']})"
    action = "apply" if apply else "validate without applying"
    return await request_destructive(
        "import_revocation",
        f"gpg-mcp wants to {action} a revocation certificate.\n"
        f"Target: {label}\nThis permanently revokes the key.",
        actual,
    )


# ---------------------------------------------------------------------------
# read-only tools
# ---------------------------------------------------------------------------

@mcp.tool(annotations=READ)
async def list_keys(
    query: str | None = None,
    secret: bool = False,
    with_sigs: bool = False,
) -> dict[str, Any]:
    """List public keys, or secret key metadata (never secret key material)."""
    return {"keys": await gpg().list_keys(secret=secret, with_sigs=with_sigs, query=query)}


@mcp.tool(annotations=READ)
async def get_key(fingerprint: str, with_sigs: bool = False) -> dict[str, Any]:
    """Return public metadata for one key identified by full fingerprint."""
    return {"key": await gpg().get_key(fingerprint, with_sigs=with_sigs)}


@mcp.tool(annotations=READ)
async def export_public_key(fingerprint: str, armor: bool = True) -> dict[str, Any]:
    """Export a public key. Secret keys are never exported."""
    return await gpg().export_public_key(fingerprint, armor=armor)


@mcp.tool(annotations=READ)
async def export_ssh_key(fingerprint: str) -> dict[str, Any]:
    """Export an authentication subkey in OpenSSH public key format."""
    return await gpg().export_ssh_key(fingerprint)


@mcp.tool(annotations=READ)
async def inspect(
    data: str | None = None,
    data_base64: str | None = None,
    packets: bool = False,
) -> dict[str, Any]:
    """Inspect OpenPGP data without importing or decrypting it. Secret keys are rejected."""
    return await gpg().inspect(_decode(data, data_base64), packets=packets)


@mcp.tool(annotations=READ)
async def inspect_recipients(
    ciphertext: str | None = None, ciphertext_base64: str | None = None
) -> dict[str, Any]:
    """List the recipients of an encrypted message without decrypting it."""
    return await gpg().inspect_recipients(_decode(ciphertext, ciphertext_base64))


@mcp.tool(annotations=READ)
async def verify(
    data: str | None = None,
    data_base64: str | None = None,
    signature: str | None = None,
    signature_base64: str | None = None,
    mode: Literal["detached", "cleartext", "inline"] = "detached",
) -> dict[str, Any]:
    """Verify a detached, cleartext or inline OpenPGP signature."""
    payload = _decode(data, data_base64)
    sig = None
    if signature is not None or signature_base64 is not None:
        sig = _decode(signature, signature_base64)
    return await gpg().verify(payload, signature=sig, mode=mode)


@mcp.tool(annotations=READ)
async def card_status() -> dict[str, Any]:
    """Show OpenPGP smartcard status. No private key material is returned."""
    return await gpg().card_status()


@mcp.tool(annotations=READ)
async def agent_info() -> dict[str, Any]:
    """Show gpg and gpg-agent configuration relevant to this server."""
    return await gpg().agent_info()


@mcp.tool(annotations=READ)
async def doctor() -> dict[str, Any]:
    """Run read-only health checks for the binary, keyring and policy."""
    return await gpg().doctor()


# ---------------------------------------------------------------------------
# crypto tools
# ---------------------------------------------------------------------------

@mcp.tool(annotations=WRITE)
async def sign(
    data: str | None = None,
    data_base64: str | None = None,
    signer: str = "",
    mode: Literal["detached", "cleartext", "inline"] = "detached",
    armor: bool = True,
    hash_algo: str = "SHA256",
    approval: Annotated[ElicitationResult[Confirm], Resolve(_ask_sign)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Sign data with an allow-listed key. The private key stays in gpg-agent."""
    payload = _decode(data, data_base64)
    fpr = require_fingerprint(signer, what="signer")
    decision = evaluate(approval)
    record_decision("sign", decision, fingerprint=fpr)
    require_approved(decision, "sign")
    result = await gpg().sign(payload, signer=fpr, mode=mode, armor=armor, hash_algo=hash_algo)
    _audit(
        "sign",
        fingerprint=fpr,
        mode=mode,
        payload_sha256=_hash(payload),
        size=len(payload),
        result="ok",
    )
    return result


@mcp.tool(annotations=WRITE)
async def encrypt(
    data: str | None = None,
    data_base64: str | None = None,
    recipients: list[str] | None = None,
    sign_with: str | None = None,
    armor: bool = True,
    approval: Annotated[ElicitationResult[Confirm], Resolve(_ask_encrypt)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Encrypt data to one or more full recipient fingerprints."""
    payload = _decode(data, data_base64)
    decision = evaluate(approval)
    operations = ["encrypt"] + (["sign"] if sign_with else [])
    record_decision("encrypt", decision, operations=operations)
    require_approved(decision, "encrypt")
    result = await gpg().encrypt(
        payload, recipients=recipients or [], sign_with=sign_with, armor=armor
    )
    _audit(
        "encrypt",
        recipients=result["recipients"],
        signed_by=result["signed_by"],
        payload_sha256=_hash(payload),
        size=len(payload),
        result="ok",
    )
    return result


@mcp.tool(annotations=WRITE)
async def sign_and_encrypt(
    data: str | None = None,
    data_base64: str | None = None,
    recipients: list[str] | None = None,
    signer: str = "",
    armor: bool = True,
    approval: Annotated[ElicitationResult[Confirm], Resolve(_ask_sign_and_encrypt)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Sign with an allow-listed key and encrypt to the recipients."""
    payload = _decode(data, data_base64)
    fpr = require_fingerprint(signer, what="signer")
    decision = evaluate(approval)
    record_decision(
        "sign_and_encrypt",
        decision,
        fingerprint=fpr,
        operations=["sign", "encrypt"],
    )
    require_approved(decision, "sign_and_encrypt")
    result = await gpg().sign_and_encrypt(
        payload, recipients=recipients or [], signer=fpr, armor=armor
    )
    _audit(
        "sign_and_encrypt",
        fingerprint=fpr,
        recipients=result["recipients"],
        payload_sha256=_hash(payload),
        size=len(payload),
        result="ok",
    )
    return result


@mcp.tool(annotations=WRITE)
async def decrypt(
    ciphertext: str | None = None,
    ciphertext_base64: str | None = None,
    verify: bool = True,
    expected_key: str | None = None,
    approval: Annotated[ElicitationResult[Confirm], Resolve(_ask_decrypt)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Decrypt data addressed to an allow-listed key. Invalid embedded signatures abort."""
    payload = _decode(ciphertext, ciphertext_base64)
    decision = evaluate(approval)
    record_decision("decrypt", decision, fingerprint=expected_key)
    require_approved(decision, "decrypt")
    result = await gpg().decrypt(payload, verify=verify, expected_key=expected_key)
    _audit(
        "decrypt",
        expected_key=expected_key,
        ciphertext_sha256=_hash(payload),
        size=len(payload),
        signed=result["signed"],
        result="ok",
    )
    return result


@mcp.tool(annotations=WRITE)
async def symmetric_encrypt(
    data: str | None = None,
    data_base64: str | None = None,
    armor: bool = True,
    approval: Annotated[ElicitationResult[Confirm], Resolve(_ask_symmetric_encrypt)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Encrypt with a passphrase entered only into pinentry. Disabled by default."""
    payload = _decode(data, data_base64)
    decision = evaluate(approval)
    record_decision("symmetric_encrypt", decision)
    require_approved(decision, "symmetric_encrypt")
    result = await gpg().symmetric_encrypt(payload, armor=armor)
    _audit("symmetric_encrypt", payload_sha256=_hash(payload), size=len(payload), result="ok")
    return result


@mcp.tool(annotations=WRITE)
async def symmetric_decrypt(
    ciphertext: str | None = None,
    ciphertext_base64: str | None = None,
    approval: Annotated[ElicitationResult[Confirm], Resolve(_ask_symmetric_decrypt)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Decrypt a symmetric message with a passphrase entered only into pinentry."""
    payload = _decode(ciphertext, ciphertext_base64)
    decision = evaluate(approval)
    record_decision("symmetric_decrypt", decision)
    require_approved(decision, "symmetric_decrypt")
    result = await gpg().symmetric_decrypt(payload)
    _audit(
        "symmetric_decrypt", ciphertext_sha256=_hash(payload), size=len(payload), result="ok"
    )
    return result


# ---------------------------------------------------------------------------
# key management
# ---------------------------------------------------------------------------

@mcp.tool(annotations=WRITE)
async def create_key(
    uid: str,
    algo: Literal["ed25519", "rsa3072", "rsa4096", "future-default", "default"] = "ed25519",
    expire: str = "2y",
    protect: bool = True,
    subkey_algo: Literal["cv25519", "rsa3072", "rsa4096", "future-default", "default"] = "cv25519",
    approval: Annotated[ElicitationResult[Confirm], Resolve(_ask_create_key)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Create a key. The passphrase is entered only into pinentry."""
    decision = evaluate(approval)
    record_decision("create_key", decision)
    require_approved(decision, "create_key")
    result = await gpg().create_key(
        uid=uid, algo=algo, expire=expire, protect=protect, subkey_algo=subkey_algo
    )
    _audit("create_key", fingerprint=result["fingerprint"], uid=uid, protected=protect, result="ok")
    return result


@mcp.tool(annotations=WRITE)
async def add_subkey(
    fingerprint: str,
    algo: Literal["cv25519", "ed25519", "rsa3072", "rsa4096", "future-default", "default"] = "cv25519",
    expire: str = "2y",
    usage: Literal["default", "sign", "encr", "auth"] = "default",
    approval: Annotated[ElicitationResult[Confirm], Resolve(_ask_add_subkey)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Add a subkey to an existing key."""
    fpr = require_fingerprint(fingerprint)
    decision = evaluate(approval)
    record_decision("add_subkey", decision, fingerprint=fpr)
    require_approved(decision, "add_subkey")
    result = await gpg().add_subkey(fpr, algo=algo, expire=expire, usage=usage)
    _audit("add_subkey", fingerprint=fpr, algo=algo, result="ok")
    return result


@mcp.tool(annotations=WRITE)
async def add_uid(
    fingerprint: str,
    uid: str,
    approval: Annotated[ElicitationResult[Confirm], Resolve(_ask_add_uid)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Add a user ID to an existing key."""
    fpr = require_fingerprint(fingerprint)
    decision = evaluate(approval)
    record_decision("add_uid", decision, fingerprint=fpr)
    require_approved(decision, "add_uid")
    result = await gpg().add_uid(fpr, uid)
    _audit("add_uid", fingerprint=fpr, result="ok")
    return result


@mcp.tool(annotations=WRITE)
async def set_expiry(
    fingerprint: str,
    expire: str,
    subkeys: bool = False,
    approval: Annotated[ElicitationResult[Confirm], Resolve(_ask_set_expiry)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Set the expiry of a key and optionally its subkeys."""
    fpr = require_fingerprint(fingerprint)
    decision = evaluate(approval)
    record_decision("set_expiry", decision, fingerprint=fpr)
    require_approved(decision, "set_expiry")
    result = await gpg().set_expiry(fpr, expire=expire, subkeys=subkeys)
    _audit("set_expiry", fingerprint=fpr, expire=expire, result="ok")
    return result


@mcp.tool(annotations=WRITE)
async def change_passphrase(
    fingerprint: str,
    approval: Annotated[ElicitationResult[Confirm], Resolve(_ask_change_passphrase)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Change a key passphrase. Old and new passphrases go only to pinentry."""
    fpr = require_fingerprint(fingerprint)
    decision = evaluate(approval)
    record_decision("change_passphrase", decision, fingerprint=fpr)
    require_approved(decision, "change_passphrase")
    result = await gpg().change_passphrase(fpr)
    _audit("change_passphrase", fingerprint=fpr, result="ok")
    return result


@mcp.tool(annotations=WRITE)
async def import_public_key(
    key: str | None = None,
    key_base64: str | None = None,
    allow_secret: bool = False,
    approval: Annotated[ElicitationResult[Confirm], Resolve(_ask_import_public_key)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Import public key material. Secret key material is rejected."""
    payload = _decode(key, key_base64)
    decision = evaluate(approval)
    record_decision("import_public_key", decision)
    require_approved(decision, "import_public_key")
    result = await gpg().import_public_key(payload, allow_secret=allow_secret)
    _audit(
        "import_public_key",
        imported=result["imported_fingerprints"],
        payload_sha256=_hash(payload),
        result="ok",
    )
    return result


@mcp.tool(annotations=DESTRUCTIVE)
async def delete_key(
    fingerprint: str,
    secret: bool = False,
    approval: Annotated[ElicitationResult[DestructiveConfirm], Resolve(_ask_delete_key)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Permanently delete a public key, or a secret and public key. Requires typed confirmation."""
    fpr = require_fingerprint(fingerprint)
    decision = evaluate_destructive(approval, fpr)
    record_decision("delete_key", decision, fingerprint=fpr, secret=secret)
    require_approved(decision, "delete_key")
    result = await gpg().delete_key(fpr, secret=secret)
    _audit("delete_key", fingerprint=fpr, secret=secret, result="ok")
    return result


@mcp.tool(annotations=WRITE)
async def set_ownertrust(
    fingerprint: str,
    level: Literal["never", "marginal", "full"],
    approval: Annotated[ElicitationResult[Confirm], Resolve(_ask_set_ownertrust)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Set ownertrust for a key. Ultimate trust is deliberately unavailable over MCP."""
    fpr = require_fingerprint(fingerprint)
    decision = evaluate(approval)
    record_decision("set_ownertrust", decision, fingerprint=fpr)
    require_approved(decision, "set_ownertrust")
    result = await gpg().set_ownertrust(fpr, level)
    _audit("set_ownertrust", fingerprint=fpr, level=level, result="ok")
    return result


@mcp.tool(annotations=WRITE)
async def generate_revocation(
    fingerprint: str,
    approval: Annotated[ElicitationResult[Confirm], Resolve(_ask_generate_revocation)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Return the pre-generated revocation certificate for a key. Treat it as sensitive."""
    fpr = require_fingerprint(fingerprint)
    decision = evaluate(approval)
    record_decision("generate_revocation", decision, fingerprint=fpr)
    require_approved(decision, "generate_revocation")
    result = await gpg().generate_revocation(fpr)
    _audit("generate_revocation", fingerprint=fpr, result="ok")
    return result


@mcp.tool(annotations=DESTRUCTIVE)
async def import_revocation(
    fingerprint: str,
    certificate: str | None = None,
    certificate_base64: str | None = None,
    apply: bool = True,
    approval: Annotated[ElicitationResult[DestructiveConfirm], Resolve(_ask_import_revocation)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Apply a revocation certificate. Requires typed confirmation of the fingerprint."""
    fpr = require_fingerprint(fingerprint)
    payload = _decode(certificate, certificate_base64)
    validated = await gpg().inspect_revocation(payload, expected_fingerprint=fpr)
    actual = validated["fingerprint"]
    decision = evaluate_destructive(approval, actual)
    record_decision("import_revocation", decision, fingerprint=actual)
    require_approved(decision, "import_revocation")
    result = await gpg().import_revocation(
        payload, expected_fingerprint=fpr, apply=apply
    )
    _audit(
        "import_revocation",
        fingerprint=actual,
        certificate_sha256=_hash(payload),
        applied=apply,
        result="ok",
    )
    return result


@mcp.tool(annotations=DESTRUCTIVE)
async def revoke_key(
    fingerprint: str,
    approval: Annotated[ElicitationResult[DestructiveConfirm], Resolve(_ask_revoke_key)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Permanently revoke a key using its stored revocation certificate."""
    fpr = require_fingerprint(fingerprint)
    decision = evaluate_destructive(approval, fpr)
    record_decision("revoke_key", decision, fingerprint=fpr)
    require_approved(decision, "revoke_key")
    result = await gpg().revoke_key(fpr)
    _audit("revoke_key", fingerprint=fpr, result="ok")
    return result


# ---------------------------------------------------------------------------
# network tools
# ---------------------------------------------------------------------------

@mcp.tool(annotations=NETWORK_READ)
async def search_keyserver(query: str) -> dict[str, Any]:
    """Search the configured keyserver. Network operations are disabled by default."""
    return await gpg().search_keyserver(query)


@mcp.tool(annotations=NETWORK_READ)
async def fetch_key(fingerprint: str) -> dict[str, Any]:
    """Fetch a public key by full fingerprint from the configured keyserver."""
    return await gpg().fetch_key(fingerprint)


@mcp.tool(annotations=NETWORK_WRITE)
async def send_key(
    fingerprint: str,
    approval: Annotated[ElicitationResult[Confirm], Resolve(_ask_send_key)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Publish a public key to the configured keyserver."""
    fpr = require_fingerprint(fingerprint)
    decision = evaluate(approval)
    record_decision("send_key", decision, fingerprint=fpr)
    require_approved(decision, "send_key")
    result = await gpg().send_key(fpr)
    _audit("send_key", fingerprint=fpr, keyserver=get_policy().keyserver, result="ok")
    return result

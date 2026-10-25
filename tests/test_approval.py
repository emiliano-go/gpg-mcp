from __future__ import annotations

import re

import pytest

from gpg_mcp.policy import reset_policy_cache
from gpg_mcp.server import mcp, reset_gpg


async def call(client, name: str, **kwargs):
    return await client.call_tool(name, kwargs)


def _approval_config(keyring, mode: str = "client"):
    path = keyring.config.parent / "approval.toml"
    path.write_text(
        f'gnupg_home = "{keyring.home}"\n'
        f'audit_log = "{keyring.home.parent / "audit-approval.jsonl"}"\n'
        f'approval = "{mode}"\n'
        "enable_network = false\n"
        "enable_symmetric = false\n"
        "allow_unprotected_keys = true\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def approval_env(monkeypatch, keyring):
    path = _approval_config(keyring)
    monkeypatch.setenv("GPG_MCP_CONFIG", str(path))
    reset_policy_cache()
    reset_gpg()
    yield path
    monkeypatch.undo()
    reset_policy_cache()
    reset_gpg()


@pytest.mark.asyncio
async def test_client_approval_accept_and_decline(approval_env, keyring) -> None:
    import mcp.types as types
    from mcp import Client

    state = {"mode": "accept"}

    async def cb(context, params):
        if state["mode"] == "decline":
            return types.ElicitResult(action="decline")
        content = {"approve": True}
        if "confirmation" in (params.requested_schema.get("properties") or {}):
            match = re.search(r"\(([0-9A-F]{8})\)", params.message)
            content["confirmation"] = match.group(1) if match else "WRONG"
        return types.ElicitResult(action="accept", content=content)

    async with Client(mcp, elicitation_callback=cb) as client:
        signed = await call(client, "sign", data="approved", signer=keyring.fpr)
        assert not signed.is_error

        state["mode"] = "decline"
        denied = await call(client, "sign", data="denied", signer=keyring.fpr)
        assert denied.is_error
        assert "not approved" in denied.content[0].text


@pytest.mark.asyncio
async def test_destructive_requires_typed_suffix(approval_env, keyring) -> None:
    import mcp.types as types
    from mcp import Client

    state = {"wrong": True}

    async def cb(context, params):
        props = params.requested_schema.get("properties") or {}
        content = {"approve": True}
        if "confirmation" in props:
            if state["wrong"]:
                content["confirmation"] = "WRONG"
            else:
                match = re.search(r"\(([0-9A-F]{8})\)", params.message)
                content["confirmation"] = match.group(1) if match else "WRONG"
        return types.ElicitResult(action="accept", content=content)

    async with Client(mcp, elicitation_callback=cb) as client:
        created = await call(
            client,
            "create_key",
            uid="Disposable Approval <approval@example.com>",
            protect=False,
        )
        assert not created.is_error, created.content[0].text
        fpr = created.structured_content["fingerprint"]

        wrong = await call(client, "delete_key", fingerprint=fpr, secret=True)
        assert wrong.is_error
        assert "confirmation" in wrong.content[0].text

        state["wrong"] = False
        deleted = await call(client, "delete_key", fingerprint=fpr, secret=True)
        assert not deleted.is_error, deleted.content[0].text
        assert deleted.structured_content["deleted"] is True


@pytest.mark.asyncio
async def test_import_revocation_requires_typed_confirmation(approval_env, keyring) -> None:
    import mcp.types as types
    from mcp import Client

    seen: list[tuple[str, dict]] = []
    state = {"mode": "accept"}

    async def cb(context, params):
        props = params.requested_schema.get("properties") or {}
        seen.append((params.message, props))
        if state["mode"] == "decline":
            return types.ElicitResult(action="decline")
        content = {"approve": True}
        if "confirmation" in props:
            match = re.search(r"\(([0-9A-F]{8})\)", params.message)
            content["confirmation"] = match.group(1) if match else "WRONG"
        return types.ElicitResult(action="accept", content=content)

    async with Client(mcp, elicitation_callback=cb) as client:
        created = await call(
            client,
            "create_key",
            uid="Approval Revocation <approval-revocation@example.com>",
            protect=False,
        )
        assert not created.is_error, created.content[0].text
        fpr = created.structured_content["fingerprint"]
        cert = (
            await call(client, "generate_revocation", fingerprint=fpr)
        ).structured_content["revocation_certificate"]

        dry = await call(
            client,
            "import_revocation",
            fingerprint=fpr,
            certificate=cert,
            apply=False,
        )
        assert not dry.is_error, dry.content[0].text
        assert dry.structured_content["applied"] is False
        assert any(
            "revocation certificate" in message and "confirmation" in props
            for message, props in seen
        )

        state["mode"] = "decline"
        denied = await call(
            client,
            "import_revocation",
            fingerprint=fpr,
            certificate=cert,
            apply=False,
        )
        assert denied.is_error
        assert "not approved" in denied.content[0].text

        state["mode"] = "accept"
        ok_delete = await call(client, "delete_key", fingerprint=fpr, secret=True)
        assert not ok_delete.is_error, ok_delete.content[0].text


@pytest.fixture
def composite_env(monkeypatch, keyring):
    def _make(required: list[str]) -> None:
        path = keyring.config.parent / f"composite-{'-'.join(required)}.toml"
        path.write_text(
            f'gnupg_home = "{keyring.home}"\n'
            f'audit_log = "{keyring.home.parent / "audit-composite.jsonl"}"\n'
            'approval = "client"\n'
            "enable_network = false\n"
            "enable_symmetric = false\n"
            "allow_unprotected_keys = true\n"
            f"require_approval = {required!r}\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("GPG_MCP_CONFIG", str(path))
        reset_policy_cache()
        reset_gpg()

    yield _make
    monkeypatch.undo()
    reset_policy_cache()
    reset_gpg()


@pytest.mark.asyncio
async def test_encrypt_with_sign_requires_sign_approval(composite_env, keyring) -> None:
    import mcp.types as types
    from mcp import Client

    composite_env(["sign"])
    calls = {"count": 0}

    async def cb(context, params):
        calls["count"] += 1
        return types.ElicitResult(action="accept", content={"approve": True})

    async with Client(mcp, elicitation_callback=cb) as client:
        result = await call(
            client,
            "encrypt",
            data="composite",
            recipients=[keyring.fpr],
            sign_with=keyring.fpr,
        )
        assert not result.is_error, result.content[0].text
    assert calls["count"] == 1


@pytest.mark.asyncio
async def test_sign_and_encrypt_requires_encrypt_approval(composite_env, keyring) -> None:
    import mcp.types as types
    from mcp import Client

    composite_env(["encrypt"])
    calls = {"count": 0}

    async def cb(context, params):
        calls["count"] += 1
        return types.ElicitResult(action="accept", content={"approve": True})

    async with Client(mcp, elicitation_callback=cb) as client:
        result = await call(
            client,
            "sign_and_encrypt",
            data="composite",
            recipients=[keyring.fpr],
            signer=keyring.fpr,
        )
        assert not result.is_error, result.content[0].text
    assert calls["count"] == 1


@pytest.mark.asyncio
async def test_client_without_elicitation_falls_back_to_local(
    approval_env, monkeypatch
) -> None:
    from types import SimpleNamespace

    from mcp.server.mcpserver import Elicit

    from gpg_mcp.approval import (
        Confirm,
        request_all,
        request_destructive,
        set_approval_context,
    )
    from gpg_mcp.errors import GpgMcpError

    fake_ctx = SimpleNamespace(
        session=SimpleNamespace(
            client_params=SimpleNamespace(
                capabilities=SimpleNamespace(elicitation=None)
            )
        )
    )

    async def yes(_summary: str) -> bool:
        return True

    async def entry(_summary: str, _prompt: str) -> str:
        return "ABCDEF12"

    monkeypatch.setattr("gpg_mcp.approval._zenity", lambda: "/bin/true")
    monkeypatch.setattr("gpg_mcp.approval._zenity_question", yes)
    monkeypatch.setattr("gpg_mcp.approval._zenity_entry", entry)
    set_approval_context(fake_ctx)
    try:
        decision = await request_all(["sign"], "fallback approval")
        assert isinstance(decision, Confirm)
        assert decision.approve is True

        destructive = await request_destructive(
            "delete_key", "delete", "A" * 32 + "ABCDEF12"
        )
        assert destructive.approve is True
        assert destructive.confirmation == "ABCDEF12"

        monkeypatch.setattr("gpg_mcp.approval._zenity", lambda: None)
        with pytest.raises(GpgMcpError):
            await request_all(["sign"], "no dialog")

        capable = SimpleNamespace(
            session=SimpleNamespace(
                client_params=SimpleNamespace(
                    capabilities=SimpleNamespace(elicitation=object())
                )
            )
        )
        set_approval_context(capable)
        elicited = await request_all(["sign"], "elicit")
        assert isinstance(elicited, Elicit)
    finally:
        set_approval_context(None)


@pytest.mark.asyncio
async def test_resolver_falls_back_without_client_capability(
    approval_env, keyring, monkeypatch
) -> None:
    from mcp import Client

    import gpg_mcp.approval as approval

    async def yes(_summary: str) -> bool:
        return True

    monkeypatch.setattr(approval, "_zenity", lambda: "/bin/true")
    monkeypatch.setattr(approval, "_zenity_question", yes)

    async with Client(mcp) as client:
        result = await call(
            client, "sign", data="fallback via resolver", signer=keyring.fpr
        )
        assert not result.is_error, result.content[0].text if result.content else result

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

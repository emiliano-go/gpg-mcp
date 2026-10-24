"""Tests that intentionally require a human at pinentry.

Skipped by default. Run with:

    GPG_MCP_INTERACTIVE=1 uv run pytest tests/test_interactive.py -s
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("GPG_MCP_INTERACTIVE"),
    reason="sets GPG_MCP_INTERACTIVE=1 to run tests that use pinentry",
)


async def call(client, name: str, **kwargs):
    return await client.call_tool(name, kwargs)


def ok(result):
    assert not result.is_error, result.content[0].text if result.content else result
    return result.structured_content


@pytest.mark.asyncio
async def test_add_subkey_and_export_ssh(connect) -> None:
    async with connect() as client:
        created = ok(
            await call(
                client,
                "create_key",
                uid="Interactive Test <interactive@example.com>",
                protect=True,
            )
        )
        fpr = created["fingerprint"]

        sign = ok(
            await call(
                client,
                "add_subkey",
                fingerprint=fpr,
                algo="ed25519",
                usage="sign",
                expire="1y",
            )
        )
        assert sign["subkey_fingerprint"]

        auth = ok(
            await call(
                client,
                "add_subkey",
                fingerprint=fpr,
                algo="ed25519",
                usage="auth",
                expire="1y",
            )
        )
        assert auth["subkey_fingerprint"]

        ssh = ok(await call(client, "export_ssh_key", fingerprint=fpr))
        assert ssh["ssh_key"].startswith("ssh-")

        ok(await call(client, "delete_key", fingerprint=fpr, secret=True))

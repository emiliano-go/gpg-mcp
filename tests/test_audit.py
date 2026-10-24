from __future__ import annotations

import os
import stat

import pytest

from gpg_mcp.policy import audit, load_policy, reset_policy_cache
from gpg_mcp.server import reset_gpg


def _policy(tmp_path, audit_log: str):
    config = tmp_path / "config.toml"
    config.write_text(
        f'gnupg_home = "{tmp_path / "home"}"\n'
        f'audit_log = "{audit_log}"\n'
        'approval = "none"\n',
        encoding="utf-8",
    )
    reset_policy_cache()
    return load_policy(config, env={})


def test_audit_does_not_chmod_existing_parent(tmp_path) -> None:
    parent = tmp_path / "existing"
    parent.mkdir()
    os.chmod(parent, 0o755)
    policy = _policy(tmp_path, str(parent / "audit.jsonl"))
    audit(policy, {"event": "test"})
    assert stat.S_IMODE(parent.stat().st_mode) == 0o755
    assert stat.S_IMODE((parent / "audit.jsonl").stat().st_mode) == 0o600
    reset_policy_cache()


def test_audit_creates_new_parent_0700(tmp_path) -> None:
    parent = tmp_path / "new-audit-dir"
    policy = _policy(tmp_path, str(parent / "audit.jsonl"))
    audit(policy, {"event": "test"})
    assert stat.S_IMODE(parent.stat().st_mode) == 0o700
    assert stat.S_IMODE((parent / "audit.jsonl").stat().st_mode) == 0o600
    reset_policy_cache()


@pytest.mark.asyncio
async def test_audit_contains_no_payload_preview(monkeypatch, tmp_path, keyring, connect) -> None:
    audit_log = tmp_path / "audit.jsonl"
    config = tmp_path / "config.toml"
    config.write_text(
        f'gnupg_home = "{keyring.home}"\n'
        f'audit_log = "{audit_log}"\n'
        'approval = "none"\n'
        "enable_network = false\n"
        "enable_symmetric = false\n"
        "allow_unprotected_keys = true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("GPG_MCP_CONFIG", str(config))
    reset_policy_cache()
    reset_gpg()
    try:
        async with connect() as client:
            result = await client.call_tool(
                "sign", {"data": "SUPER SECRET PREVIEW", "signer": keyring.fpr}
            )
            assert not result.is_error, result.content[0].text if result.content else result
        text = audit_log.read_text(encoding="utf-8")
        assert "SUPER SECRET PREVIEW" not in text
        assert "SUPER SECRET" not in text
        assert "payload_sha256" in text
        assert stat.S_IMODE(audit_log.stat().st_mode) == 0o600
    finally:
        reset_policy_cache()
        reset_gpg()

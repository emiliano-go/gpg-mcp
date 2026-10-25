from __future__ import annotations

import os
import stat

import pytest

from gpg_mcp.errors import AuditError
from gpg_mcp.policy import audit, load_policy, reset_policy_cache
from gpg_mcp.server import reset_gpg


def _policy(tmp_path, audit_log: str, *, audit_required: bool = True):
    config = tmp_path / "config.toml"
    config.write_text(
        f'gnupg_home = "{tmp_path / "home"}"\n'
        f'audit_log = "{audit_log}"\n'
        'approval = "none"\n'
        f'audit_required = {str(audit_required).lower()}\n',
        encoding="utf-8",
    )
    os.chmod(config, 0o600)
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
    os.chmod(config, 0o600)
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


def test_audit_tightens_existing_file(tmp_path) -> None:
    parent = tmp_path / "permissions"
    parent.mkdir()
    os.chmod(parent, 0o755)
    log = parent / "audit.jsonl"
    log.write_text("existing\n", encoding="utf-8")
    os.chmod(log, 0o644)
    policy = _policy(tmp_path, str(log))
    audit(policy, {"event": "test"})
    assert stat.S_IMODE(parent.stat().st_mode) == 0o755
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    assert "existing" in log.read_text(encoding="utf-8")
    reset_policy_cache()


def test_audit_refuses_symlink(tmp_path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("keep", encoding="utf-8")
    link = tmp_path / "audit.jsonl"
    link.symlink_to(target)
    policy = _policy(tmp_path, str(link), audit_required=False)
    audit(policy, {"event": "test"})
    assert target.read_text(encoding="utf-8") == "keep"
    reset_policy_cache()


def test_audit_refuses_fifo_without_blocking(tmp_path) -> None:
    parent = tmp_path / "fifo"
    parent.mkdir()
    fifo = parent / "audit.jsonl"
    os.mkfifo(fifo)
    policy = _policy(tmp_path, str(fifo), audit_required=False)
    audit(policy, {"event": "test"})
    assert fifo.exists()
    reset_policy_cache()


def test_audit_required_raises_on_unsafe_file(tmp_path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("keep", encoding="utf-8")
    link = tmp_path / "audit.jsonl"
    link.symlink_to(target)
    policy = _policy(tmp_path, str(link), audit_required=True)
    with pytest.raises(AuditError):
        audit(policy, {"event": "test"})
    reset_policy_cache()


def test_audit_handles_short_writes(tmp_path, monkeypatch) -> None:
    parent = tmp_path / "short-writes"
    parent.mkdir()
    log = parent / "audit.jsonl"
    policy = _policy(tmp_path, str(log))
    real_write = os.write
    monkeypatch.setattr(
        os, "write", lambda fd, data: real_write(fd, bytes(data[:1]))
    )
    audit(policy, {"event": "test"})
    text = log.read_text(encoding="utf-8")
    assert '"event": "test"' in text
    reset_policy_cache()


def test_audit_outcome_failure_is_explicit(tmp_path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("keep", encoding="utf-8")
    link = tmp_path / "audit.jsonl"
    link.symlink_to(target)
    policy = _policy(tmp_path, str(link), audit_required=True)
    with pytest.raises(AuditError) as exc:
        audit(policy, {"event": "operation"}, phase="outcome")
    assert "outcome" in str(exc.value)
    assert exc.value.data.get("operation_may_have_completed") is True
    reset_policy_cache()


def test_audit_rejects_non_sticky_writable_ancestor(tmp_path) -> None:
    unsafe = tmp_path / "unsafe-audit"
    unsafe.mkdir()
    os.chmod(unsafe, 0o777)
    child = unsafe / "child"
    child.mkdir(mode=0o700)
    log = child / "audit.jsonl"
    policy = _policy(tmp_path, str(log), audit_required=True)
    with pytest.raises(AuditError):
        audit(policy, {"event": "test"})
    assert not log.exists()
    reset_policy_cache()


def test_audit_does_not_create_through_symlinked_ancestor(tmp_path) -> None:
    real = tmp_path / "real-audit"
    real.mkdir()
    link = tmp_path / "link-audit"
    link.symlink_to(real, target_is_directory=True)
    log = link / "missing" / "audit.jsonl"
    policy = _policy(tmp_path, str(log), audit_required=True)
    with pytest.raises(AuditError):
        audit(policy, {"event": "test"})
    assert not (real / "missing").exists()
    reset_policy_cache()

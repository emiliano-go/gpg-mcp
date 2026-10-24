from __future__ import annotations

import os

import pytest

from gpg_mcp.binaries import secure_binary
from gpg_mcp.errors import GpgMcpError


def test_secure_binary_accepts_user_owned_0755(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "safe-tool"
    binary.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    os.chmod(binary, 0o755)
    monkeypatch.setattr("shutil.which", lambda name: str(binary))
    assert secure_binary("safe-tool") == str(binary.resolve())


def test_secure_binary_rejects_group_or_world_writable(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "unsafe-tool"
    binary.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    os.chmod(binary, 0o777)
    monkeypatch.setattr("shutil.which", lambda name: str(binary))
    with pytest.raises(GpgMcpError):
        secure_binary("unsafe-tool")


def test_secure_binary_rejects_missing_required(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(GpgMcpError):
        secure_binary("absent")
    assert secure_binary("absent", required=False) is None

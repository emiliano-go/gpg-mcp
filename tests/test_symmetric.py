from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest

from gpg_mcp.errors import GpgMcpError
from gpg_mcp.gpg import Gpg, GpgResult, StatusEvent
from gpg_mcp.policy import get_policy


def _runner() -> Gpg:
    runner = Gpg.__new__(Gpg)
    runner.policy = replace(get_policy(), enable_symmetric=True)
    runner.gpg = "/usr/bin/gpg"
    runner.gpgconf = None
    runner.home = runner.policy.gnupg_home
    runner.env = {}
    runner._lock = asyncio.Lock()
    runner._proc_all = None
    return runner


def _result(status: list[StatusEvent]) -> GpgResult:
    return GpgResult(
        argv=[], returncode=0, stdout=b"sym plaintext", stderr="", status=status
    )


@pytest.mark.asyncio
async def test_symmetric_decrypt_rejects_bad_signature(monkeypatch) -> None:
    runner = _runner()

    async def fake_inspect(_ciphertext):
        return {"symmetric": True, "public_key_ids": [], "encrypted": True}

    async def fake_run(*_args, **_kwargs):
        return _result(
            [
                StatusEvent("DECRYPTION_OKAY", [], ""),
                StatusEvent("NEWSIG", [], ""),
                StatusEvent("BADSIG", ["KEYID", "Evil"], ""),
            ]
        )

    monkeypatch.setattr(runner, "inspect_recipients", fake_inspect)
    monkeypatch.setattr(runner, "run", fake_run)
    with pytest.raises(GpgMcpError) as exc:
        await runner.symmetric_decrypt(b"ciphertext")
    assert exc.value.code == "bad_signature"


@pytest.mark.asyncio
async def test_symmetric_decrypt_reports_good_signature(monkeypatch) -> None:
    runner = _runner()

    async def fake_inspect(_ciphertext):
        return {"symmetric": True, "public_key_ids": [], "encrypted": True}

    async def fake_run(*_args, **_kwargs):
        return _result(
            [
                StatusEvent("DECRYPTION_OKAY", [], ""),
                StatusEvent("NEWSIG", [], ""),
                StatusEvent("GOODSIG", ["KEYID", "Good"], ""),
                StatusEvent(
                    "VALIDSIG",
                    [
                        "A" * 40,
                        "2026-10-24",
                        "1792883400",
                        "0",
                        "5",
                        "0",
                        "22",
                        "8",
                        "00",
                        "A" * 40,
                    ],
                    "",
                ),
                StatusEvent("TRUST_ULTIMATE", ["0", "pgp"], ""),
            ]
        )

    monkeypatch.setattr(runner, "inspect_recipients", fake_inspect)
    monkeypatch.setattr(runner, "run", fake_run)
    result = await runner.symmetric_decrypt(b"ciphertext")
    assert result["plaintext"] == {"text": "sym plaintext"}
    assert result["signed"] is True
    assert result["signature"]["valid"] is True

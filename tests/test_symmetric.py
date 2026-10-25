from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from gpg_mcp.errors import GpgMcpError
from gpg_mcp.gpg import Gpg, GpgResult, StatusEvent
from gpg_mcp.policy import get_policy, reset_policy_cache
from gpg_mcp.server import reset_gpg


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


@pytest.fixture
def symmetric_env(monkeypatch, keyring):
    path = keyring.config.parent / "symmetric.toml"
    path.write_text(
        f'gnupg_home = "{keyring.home}"\n'
        f'audit_log = "{keyring.home.parent / "audit-symmetric.jsonl"}"\n'
        'approval = "none"\n'
        "enable_symmetric = true\n"
        "enable_network = false\n",
        encoding="utf-8",
    )
    os.chmod(path, 0o600)
    monkeypatch.setenv("GPG_MCP_CONFIG", str(path))
    reset_policy_cache()
    reset_gpg()
    yield
    monkeypatch.undo()
    reset_policy_cache()
    reset_gpg()


def _hybrid_ciphertext(keyring) -> str:
    env = {
        "GNUPGHOME": str(keyring.home),
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "HOME": os.environ.get("HOME", str(Path.home())),
    }
    proc = subprocess.run(
        [
            shutil.which("gpg"),
            "--batch",
            "--no-tty",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "testpass",
            "--armor",
            "--symmetric",
            "--encrypt",
            "--recipient",
            keyring.fpr,
        ],
        input=b"hybrid plaintext",
        env=env,
        capture_output=True,
        check=True,
    )
    return proc.stdout.decode("utf-8")


@pytest.mark.asyncio
async def test_symmetric_decrypt_rejects_hybrid_ciphertext(symmetric_env, keyring, connect) -> None:
    ciphertext = _hybrid_ciphertext(keyring)
    async with connect() as client:
        result = await client.call_tool(
            "symmetric_decrypt", {"ciphertext": ciphertext}
        )
        assert result.is_error
        assert "symmetric-only" in result.content[0].text


@pytest.mark.asyncio
async def test_symmetric_approval_shows_verify(monkeypatch) -> None:
    from gpg_mcp import server

    captured: list[tuple[str, str]] = []

    async def fake_request(op: str, summary: str):
        captured.append((op, summary))
        return server.Confirm(approve=True)

    monkeypatch.setattr(server, "request", fake_request)
    result = await server._ask_symmetric_decrypt(ciphertext="abc", verify=False)
    assert result.approve is True
    assert captured[0][0] == "symmetric_decrypt"
    assert "Verify embedded signature: False" in captured[0][1]


def _symmetric_only(keyring) -> str:
    env = {
        "GNUPGHOME": str(keyring.home),
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "HOME": os.environ.get("HOME", str(Path.home())),
    }
    proc = subprocess.run(
        [
            shutil.which("gpg"),
            "--batch",
            "--no-tty",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "testpass",
            "--armor",
            "--symmetric",
        ],
        input=b"symmetric only",
        env=env,
        capture_output=True,
        check=True,
    )
    return proc.stdout.decode("utf-8")


@pytest.mark.asyncio
async def test_decrypt_rejects_symmetric_only_ciphertext(keyring, connect) -> None:
    ciphertext = _symmetric_only(keyring)
    async with connect() as client:
        result = await client.call_tool("decrypt", {"ciphertext": ciphertext})
        assert result.is_error
        assert "must use symmetric_decrypt" in result.content[0].text


@pytest.mark.asyncio
async def test_decrypt_accepts_hybrid_via_public_key(keyring, connect) -> None:
    ciphertext = _hybrid_ciphertext(keyring)
    async with connect() as client:
        result = await client.call_tool("decrypt", {"ciphertext": ciphertext})
        assert not result.is_error, result.content[0].text
        data = result.structured_content
        assert data["plaintext"] == {"text": "hybrid plaintext"}
        assert data["actual_keys"]
        assert data["actual_keys"][0]["primary_fingerprint"] == keyring.fpr


@pytest.mark.asyncio
async def test_custom_policy_cannot_bypass_symmetric_approval(
    monkeypatch, keyring
) -> None:
    import mcp.types as types
    from mcp import Client

    from gpg_mcp.policy import reset_policy_cache
    from gpg_mcp.server import mcp, reset_gpg

    config = keyring.config.parent / "symmetric-approval.toml"
    config.write_text(
        f'gnupg_home = "{keyring.home}"\n'
        f'audit_log = "{keyring.home.parent / "audit-symmetric-approval.jsonl"}"\n'
        'approval = "client"\n'
        'require_approval = ["symmetric_decrypt"]\n'
        "enable_symmetric = true\n"
        "enable_network = false\n",
        encoding="utf-8",
    )
    os.chmod(config, 0o600)
    monkeypatch.setenv("GPG_MCP_CONFIG", str(config))
    reset_policy_cache()
    reset_gpg()

    calls: list[str] = []

    async def cb(context, params):
        calls.append(params.message)
        return types.ElicitResult(action="accept", content={"approve": True})

    ciphertext = _symmetric_only(keyring)
    try:
        async with Client(mcp, elicitation_callback=cb) as client:
            via_decrypt = await client.call_tool(
                "decrypt", {"ciphertext": ciphertext}
            )
            assert via_decrypt.is_error
            assert "must use symmetric_decrypt" in via_decrypt.content[0].text
            assert calls == []

            await client.call_tool("symmetric_decrypt", {"ciphertext": ciphertext})
            assert len(calls) == 1
            assert "symmetrically decrypt data" in calls[0]
    finally:
        reset_policy_cache()
        reset_gpg()


def test_symmetric_decryption_status_policy() -> None:
    from gpg_mcp.gpg import StatusEvent, symmetric_decryption_status_ok

    def events(*items):
        return [StatusEvent(keyword, args, "") for keyword, args in items]

    assert symmetric_decryption_status_ok(
        events(("DECRYPTION_OKAY", [])), 0, verify=True
    ) is True
    assert symmetric_decryption_status_ok(
        events(("DECRYPTION_OKAY", []), ("DECRYPTION_FAILED", [])), 0, verify=True
    ) is False
    assert symmetric_decryption_status_ok(
        events(("DECRYPTION_OKAY", []), ("BADMDC", [])), 0, verify=True
    ) is False
    assert symmetric_decryption_status_ok(
        events(("DECRYPTION_OKAY", []), ("ERROR", ["get_passphrase"])), 0, verify=True
    ) is False
    assert symmetric_decryption_status_ok(
        events(("DECRYPTION_OKAY", [])), 2, verify=True
    ) is False
    assert symmetric_decryption_status_ok(
        events(
            ("DECRYPTION_OKAY", []),
            ("BADSIG", ["KEYID", "uid"]),
            ("FAILURE", ["gpg-exit"]),
        ),
        2,
        verify=False,
    ) is True
    assert symmetric_decryption_status_ok(
        events(
            ("DECRYPTION_OKAY", []),
            ("BADSIG", ["KEYID", "uid"]),
            ("FAILURE", ["gpg-exit"]),
        ),
        2,
        verify=True,
    ) is False
    assert symmetric_decryption_status_ok(
        events(("DECRYPTION_OKAY", []), ("FAILURE", ["gpg-exit"])),
        2,
        verify=False,
    ) is False


@pytest.mark.asyncio
async def test_symmetric_decrypt_rejects_unexplained_nonzero(monkeypatch) -> None:
    runner = _runner()

    async def fake_inspect(_ciphertext):
        return {"symmetric": True, "public_key_ids": [], "encrypted": True}

    async def fake_run(*_args, **_kwargs):
        return GpgResult(
            argv=[],
            returncode=2,
            stdout=b"plaintext",
            stderr="",
            status=[StatusEvent("DECRYPTION_OKAY", [], "")],
        )

    monkeypatch.setattr(runner, "inspect_recipients", fake_inspect)
    monkeypatch.setattr(runner, "run", fake_run)
    with pytest.raises(GpgMcpError) as exc:
        await runner.symmetric_decrypt(b"ciphertext")
    assert "exited with status 2" in str(exc.value)


@pytest.mark.asyncio
async def test_symmetric_decrypt_verify_false_allows_recognized_signature_failure(
    monkeypatch,
) -> None:
    runner = _runner()

    async def fake_inspect(_ciphertext):
        return {"symmetric": True, "public_key_ids": [], "encrypted": True}

    async def fake_run(*_args, **_kwargs):
        return GpgResult(
            argv=[],
            returncode=2,
            stdout=b"plaintext",
            stderr="",
            status=[
                StatusEvent("DECRYPTION_OKAY", [], ""),
                StatusEvent("NEWSIG", [], ""),
                StatusEvent("BADSIG", ["KEYID", "uid"], ""),
                StatusEvent("FAILURE", ["gpg-exit"], ""),
            ],
        )

    monkeypatch.setattr(runner, "inspect_recipients", fake_inspect)
    monkeypatch.setattr(runner, "run", fake_run)
    result = await runner.symmetric_decrypt(b"ciphertext", verify=False)
    assert result["plaintext"] == {"text": "plaintext"}
    assert result["signed"] is True
    assert result["signature"]["valid"] is False

    with pytest.raises(GpgMcpError) as exc:
        await runner.symmetric_decrypt(b"ciphertext", verify=True)
    assert exc.value.code == "gpg_failed"

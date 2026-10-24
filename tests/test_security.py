from __future__ import annotations

import base64
import os
import shutil
import subprocess
from pathlib import Path

import pytest


async def call(client, name: str, **kwargs):
    return await client.call_tool(name, kwargs)


def ok(result):
    assert not result.is_error, result.content[0].text if result.content else result
    return result.structured_content


def _gpg(keyring, *args: str, input_data: bytes | None = None) -> bytes:
    env = {
        "GNUPGHOME": str(keyring.home),
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "HOME": os.environ.get("HOME", str(Path.home())),
    }
    proc = subprocess.run(
        [shutil.which("gpg"), "--batch", "--no-tty", *args],
        input=input_data,
        env=env,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    return proc.stdout


@pytest.mark.asyncio
async def test_no_private_key_material_in_any_output(connect, keyring) -> None:
    async with connect() as client:
        outputs: list[str] = []
        outputs.append(str(ok(await call(client, "list_keys"))))
        outputs.append(str(ok(await call(client, "list_keys", secret=True))))
        outputs.append(str(ok(await call(client, "get_key", fingerprint=keyring.fpr))))
        outputs.append(
            str(ok(await call(client, "export_public_key", fingerprint=keyring.fpr)))
        )
        signed = ok(await call(client, "sign", data="guard", signer=keyring.fpr))
        outputs.append(str(signed))
        encrypted = ok(
            await call(client, "encrypt", data="guard", recipients=[keyring.fpr])
        )
        outputs.append(str(encrypted))
        outputs.append(
            str(ok(await call(client, "decrypt", ciphertext=encrypted["ciphertext"]["text"])))
        )
        for output in outputs:
            assert "PRIVATE KEY BLOCK" not in output
            assert "SECRET KEY BLOCK" not in output


@pytest.mark.asyncio
async def test_secret_key_is_rejected_by_inspect_and_import(connect, keyring) -> None:
    secret = _gpg(keyring, "--armor", "--export-secret-keys", keyring.fpr)
    text = secret.decode("utf-8")
    assert "PRIVATE KEY BLOCK" in text

    async with connect() as client:
        inspected = await call(client, "inspect", data=text)
        assert inspected.is_error
        assert "secret" in inspected.content[0].text.lower()
        assert "PRIVATE KEY BLOCK" not in inspected.content[0].text

        imported = await call(client, "import_public_key", key=text)
        assert imported.is_error
        assert "secret" in imported.content[0].text.lower()
        assert "PRIVATE KEY BLOCK" not in imported.content[0].text


@pytest.mark.asyncio
async def test_secret_key_is_rejected_as_binary(connect, keyring) -> None:
    secret = _gpg(keyring, "--export-secret-keys", keyring.fpr)
    encoded = base64.b64encode(secret).decode("ascii")
    async with connect() as client:
        result = await call(client, "import_public_key", key_base64=encoded)
        assert result.is_error
        assert "secret" in result.content[0].text.lower()


@pytest.mark.asyncio
async def test_option_injection_via_uid_rejected(connect, keyring) -> None:
    async with connect() as client:
        result = await call(client, "add_uid", fingerprint=keyring.fpr, uid="--help")
        assert result.is_error
        assert "option injection" in result.content[0].text


@pytest.mark.asyncio
async def test_short_fingerprint_rejected(connect) -> None:
    async with connect() as client:
        result = await call(client, "sign", data="x", signer="DEADBEEF")
        assert result.is_error
        assert "full OpenPGP fingerprint" in result.content[0].text


@pytest.mark.asyncio
async def test_hidden_recipients_rejected_by_default(connect, keyring) -> None:
    hidden = _gpg(
        keyring,
        "--armor",
        "--trust-model",
        "always",
        "--throw-keyids",
        "--recipient",
        keyring.fpr,
        "--encrypt",
        input_data=b"hidden message",
    ).decode("utf-8")
    async with connect() as client:
        result = await call(client, "decrypt", ciphertext=hidden)
        assert result.is_error
        assert "hidden recipients" in result.content[0].text


@pytest.mark.asyncio
async def test_mixed_hidden_and_visible_recipients_rejected(connect, keyring) -> None:
    mixed = _gpg(
        keyring,
        "--armor",
        "--trust-model",
        "always",
        "--recipient",
        keyring.fpr,
        "--hidden-recipient",
        keyring.fpr2,
        "--encrypt",
        input_data=b"mixed message",
    ).decode("utf-8")
    async with connect() as client:
        result = await call(client, "decrypt", ciphertext=mixed)
        assert result.is_error
        assert "hidden recipients" in result.content[0].text


@pytest.mark.asyncio
async def test_network_is_disabled_by_default(connect) -> None:
    async with connect() as client:
        result = await call(client, "search_keyserver", query="alice@example.com")
        assert result.is_error
        assert "disabled" in result.content[0].text


def test_no_forbidden_options_in_source() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "gpg_mcp"
    text = "\n".join(path.read_text(encoding="utf-8") for path in root.glob("*.py"))
    for forbidden in (
        "--export-secret-keys",
        "--export-secret-subkeys",
        "--export-secret-ssh-key",
        "--passphrase",
        "--homedir",
        "--command-fd",
        "--options",
        "--pinentry-mode loopback",
    ):
        assert forbidden not in text, f"forbidden option in source: {forbidden}"


def test_no_secret_export_tool() -> None:
    from gpg_mcp.server import mcp

    names = {tool.name for tool in mcp._tool_manager.list_tools()}
    assert "run_gpg" not in names
    assert "gpg" not in names
    assert not any("secret" in n and ("export" in n or "backup" in n) for n in names)
    assert "export_public_key" in names

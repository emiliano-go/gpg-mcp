from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from gpg_mcp import server
from gpg_mcp.errors import InputError, single_line
from gpg_mcp.policy import reset_policy_cache
from gpg_mcp.server import reset_gpg


def test_single_line_escapes_dialog_controls() -> None:
    hostile = "line1\nline2\r\t\x1b[31mred\x1b[0m\u202Eevil\\"
    rendered = single_line(hostile)
    assert "\n" not in rendered
    assert "\r" not in rendered
    assert "\t" not in rendered
    assert "\x1b" not in rendered
    assert "\u202e" not in rendered
    assert "\\n" in rendered
    assert "\\u202e" in rendered
    assert "\\\\" in rendered


@pytest.mark.asyncio
async def test_key_label_escapes_uid(monkeypatch) -> None:
    class FakeGpg:
        async def get_key(self, _fingerprint: str):
            return {"uids": [{"uid": "line1\nline2\u202Eevil"}]}

    monkeypatch.setattr(server, "gpg", lambda: FakeGpg())
    label = await server._key_label("A" * 40)
    assert "\n" not in label
    assert "\u202e" not in label
    assert "\\n" in label
    assert "\\u202e" in label


@pytest.mark.asyncio
async def test_resolvers_validate_before_approval() -> None:
    with pytest.raises(InputError):
        await server._ask_create_key(uid="line1\nline2")
    with pytest.raises(InputError):
        await server._ask_add_uid(fingerprint="A" * 40, uid="--help")
    with pytest.raises(InputError):
        await server._ask_sign(signer="DEADBEEF", data="x")
    with pytest.raises(InputError):
        await server._ask_encrypt(recipients=["DEADBEEF"], data="x")


@pytest.fixture
def approval_env(monkeypatch, keyring):
    path = keyring.config.parent / "approval-text.toml"
    path.write_text(
        f'gnupg_home = "{keyring.home}"\n'
        f'audit_log = "{keyring.home.parent / "audit-text.jsonl"}"\n'
        'approval = "client"\n'
        "enable_network = false\n"
        "enable_symmetric = false\n"
        "allow_unprotected_keys = true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("GPG_MCP_CONFIG", str(path))
    reset_policy_cache()
    reset_gpg()
    yield path
    monkeypatch.undo()
    reset_policy_cache()
    reset_gpg()


def _malicious_key(tmp_path: Path) -> tuple[str, str]:
    home = tmp_path / "malicious-gnupg"
    home.mkdir(mode=0o700)
    env = {
        "GNUPGHOME": str(home),
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "HOME": os.environ.get("HOME", str(Path.home())),
    }
    uid = "Evil\nUID\u202e <evil@example.com>"
    subprocess.run(
        [
            shutil.which("gpg"),
            "--batch",
            "--no-tty",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            uid,
            "future-default",
            "default",
            "1d",
        ],
        env=env,
        check=True,
        capture_output=True,
    )
    listed = subprocess.run(
        [shutil.which("gpg"), "--with-colons", "--list-keys"],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    fpr = next(line.split(":")[9] for line in listed.splitlines() if line.startswith("fpr:"))
    public = subprocess.run(
        [shutil.which("gpg"), "--armor", "--export", fpr],
        env=env,
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8")
    return fpr, public


@pytest.mark.asyncio
async def test_malicious_uid_is_escaped_in_approval(
    approval_env, connect, tmp_path
) -> None:
    import mcp.types as types
    from mcp import Client

    fpr, public = _malicious_key(tmp_path)
    messages: list[str] = []

    async def cb(context, params):
        messages.append(params.message)
        return types.ElicitResult(action="accept", content={"approve": True})

    async with Client(server.mcp, elicitation_callback=cb) as client:
        imported = await client.call_tool("import_public_key", {"key": public})
        assert not imported.is_error, imported.content[0].text
        encrypted = await client.call_tool(
            "encrypt", {"data": "x", "recipients": [fpr]}
        )
        assert not encrypted.is_error, encrypted.content[0].text

    recipient_messages = [message for message in messages if fpr in message]
    assert recipient_messages
    combined = "\n".join(recipient_messages)
    assert "\u202e" not in combined
    assert "\\u202e" in combined

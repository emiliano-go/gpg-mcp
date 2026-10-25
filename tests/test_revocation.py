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


async def _create(client, name: str) -> str:
    created = ok(
        await call(
            client,
            "create_key",
            uid=f"{name} <{name.lower()}@example.com>",
            protect=False,
        )
    )
    return created["fingerprint"]


@pytest.mark.asyncio
async def test_dry_run_is_non_mutating(connect) -> None:
    async with connect() as client:
        fpr = await _create(client, "Dry Run")
        cert = ok(await call(client, "generate_revocation", fingerprint=fpr))[
            "revocation_certificate"
        ]
        dry = ok(
            await call(
                client,
                "import_revocation",
                fingerprint=fpr,
                certificate=cert,
                apply=False,
            )
        )
        assert dry["applied"] is False
        assert dry["would_revoke"] is True
        assert dry["fingerprint"] == fpr

        key = ok(await call(client, "get_key", fingerprint=fpr))["key"]
        assert key["validity"] != "revoked"
        ok(await call(client, "delete_key", fingerprint=fpr, secret=True))


@pytest.mark.asyncio
async def test_apply_revokes_only_the_target(connect) -> None:
    async with connect() as client:
        fpr = await _create(client, "Apply Revocation")
        cert = ok(await call(client, "generate_revocation", fingerprint=fpr))[
            "revocation_certificate"
        ]
        applied = ok(
            await call(
                client,
                "import_revocation",
                fingerprint=fpr,
                certificate=cert,
                apply=True,
            )
        )
        assert applied["applied"] is True
        assert applied["revoked"] is True
        assert applied["imported"] is True
        assert applied["revocation_imported"] is True
        key = ok(await call(client, "get_key", fingerprint=fpr))["key"]
        assert key["validity"] == "revoked"
        ok(await call(client, "delete_key", fingerprint=fpr, secret=True))


@pytest.mark.asyncio
async def test_rejects_a_plain_public_key(connect) -> None:
    async with connect() as client:
        fpr = await _create(client, "Public Reject")
        public = ok(await call(client, "export_public_key", fingerprint=fpr))["text"]
        result = await call(
            client, "import_revocation", fingerprint=fpr, certificate=public
        )
        assert result.is_error
        assert "revocation signature" in result.content[0].text
        key = ok(await call(client, "get_key", fingerprint=fpr))["key"]
        assert key["validity"] != "revoked"
        ok(await call(client, "delete_key", fingerprint=fpr, secret=True))


@pytest.mark.asyncio
async def test_rejects_binary_secret_key(connect, keyring) -> None:
    async with connect() as client:
        fpr = await _create(client, "Secret Reject")
        secret = _gpg(keyring, "--export-secret-keys", fpr)
        encoded = base64.b64encode(secret).decode("ascii")
        result = await call(
            client,
            "import_revocation",
            fingerprint=fpr,
            certificate_base64=encoded,
        )
        assert result.is_error
        assert "secret" in result.content[0].text.lower()
        ok(await call(client, "delete_key", fingerprint=fpr, secret=True))


@pytest.mark.asyncio
async def test_rejects_certificate_for_another_key(connect) -> None:
    async with connect() as client:
        target = await _create(client, "Target Key")
        other = await _create(client, "Other Key")
        other_cert = ok(await call(client, "generate_revocation", fingerprint=other))[
            "revocation_certificate"
        ]
        result = await call(
            client,
            "import_revocation",
            fingerprint=target,
            certificate=other_cert,
            apply=False,
        )
        assert result.is_error
        assert "targets" in result.content[0].text
        key = ok(await call(client, "get_key", fingerprint=target))["key"]
        assert key["validity"] != "revoked"
        ok(await call(client, "delete_key", fingerprint=target, secret=True))
        ok(await call(client, "delete_key", fingerprint=other, secret=True))


@pytest.mark.asyncio
async def test_rejects_malformed_certificate(connect) -> None:
    async with connect() as client:
        fpr = await _create(client, "Malformed")
        result = await call(
            client,
            "import_revocation",
            fingerprint=fpr,
            certificate="this is not an OpenPGP certificate",
            apply=False,
        )
        assert result.is_error
        ok(await call(client, "delete_key", fingerprint=fpr, secret=True))


@pytest.mark.asyncio
async def test_generic_import_cannot_apply_revocation(connect) -> None:
    async with connect() as client:
        fpr = await _create(client, "Import Bypass")
        cert = ok(await call(client, "generate_revocation", fingerprint=fpr))[
            "revocation_certificate"
        ]
        result = await call(client, "import_public_key", key=cert)
        assert result.is_error
        assert "import_revocation" in result.content[0].text
        key = ok(await call(client, "get_key", fingerprint=fpr))["key"]
        assert key["validity"] != "revoked"
        ok(await call(client, "delete_key", fingerprint=fpr, secret=True))

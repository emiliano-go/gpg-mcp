from __future__ import annotations

import asyncio
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
async def test_expired_signature_is_rejected(connect, keyring) -> None:
    signature = _gpg(
        keyring,
        "--armor",
        "--default-sig-expire",
        "seconds=1",
        "--detach-sign",
        "--local-user",
        keyring.fpr,
        input_data=b"expires quickly",
    ).decode("utf-8")
    await asyncio.sleep(2)
    async with connect() as client:
        result = ok(
            await call(
                client,
                "verify",
                data="expires quickly",
                signature=signature,
                mode="detached",
            )
        )
    assert result["cryptographically_valid"] is True
    assert result["policy_acceptable"] is False
    assert result["valid"] is False
    assert result["sig_expired"] is True


@pytest.mark.asyncio
async def test_expired_key_signature_is_rejected(connect) -> None:
    async with connect() as client:
        created = ok(
            await call(
                client,
                "create_key",
                uid="Short Lived <short@example.com>",
                expire="seconds=2",
                protect=False,
            )
        )
        fpr = created["fingerprint"]
        signed = ok(await call(client, "sign", data="short lived", signer=fpr))
        signature = signed["signature"]["text"]
        await asyncio.sleep(3)
        result = ok(
            await call(
                client,
                "verify",
                data="short lived",
                signature=signature,
                mode="detached",
            )
        )
        assert result["cryptographically_valid"] is True
        assert result["policy_acceptable"] is False
        assert result["valid"] is False
        assert result["key_expired"] is True
        ok(await call(client, "delete_key", fingerprint=fpr, secret=True))


@pytest.mark.asyncio
async def test_revoked_key_signature_is_rejected(connect) -> None:
    async with connect() as client:
        created = ok(
            await call(
                client,
                "create_key",
                uid="Revoked Signer <revoked@example.com>",
                protect=False,
            )
        )
        fpr = created["fingerprint"]
        signed = ok(await call(client, "sign", data="before revocation", signer=fpr))
        signature = signed["signature"]["text"]
        ok(await call(client, "revoke_key", fingerprint=fpr))
        result = ok(
            await call(
                client,
                "verify",
                data="before revocation",
                signature=signature,
                mode="detached",
            )
        )
        assert result["cryptographically_valid"] is True
        assert result["policy_acceptable"] is False
        assert result["valid"] is False
        assert result["key_revoked"] is True
        ok(await call(client, "delete_key", fingerprint=fpr, secret=True))


@pytest.mark.asyncio
async def test_missing_public_key_is_rejected(connect) -> None:
    async with connect() as client:
        created = ok(
            await call(
                client,
                "create_key",
                uid="Missing Signer <missing@example.com>",
                protect=False,
            )
        )
        fpr = created["fingerprint"]
        signed = ok(await call(client, "sign", data="missing key", signer=fpr))
        signature = signed["signature"]["text"]
        ok(await call(client, "delete_key", fingerprint=fpr, secret=True))
        result = ok(
            await call(
                client,
                "verify",
                data="missing key",
                signature=signature,
                mode="detached",
            )
        )
        assert result["cryptographically_valid"] is False
        assert result["policy_acceptable"] is False
        assert result["valid"] is False
        assert result["missing_key"] is True


@pytest.mark.asyncio
async def test_decrypt_refuses_revoked_embedded_signature(connect) -> None:
    plaintext = "do not release this plaintext"
    async with connect() as client:
        created = ok(
            await call(
                client,
                "create_key",
                uid="Embedded Signer <embedded@example.com>",
                protect=False,
            )
        )
        fpr = created["fingerprint"]
        encrypted = ok(
            await call(
                client,
                "sign_and_encrypt",
                data=plaintext,
                recipients=[fpr],
                signer=fpr,
            )
        )
        ok(await call(client, "revoke_key", fingerprint=fpr))
        failure = await call(
            client, "decrypt", ciphertext=encrypted["ciphertext"]["text"]
        )
        assert failure.is_error
        assert plaintext not in (failure.content[0].text if failure.content else "")
        ok(await call(client, "delete_key", fingerprint=fpr, secret=True))


@pytest.mark.asyncio
async def test_multiple_embedded_signatures_fail_closed(connect, keyring) -> None:
    async with connect() as client:

        async def raw_sign(data: str, signer: str) -> bytes:
            result = await call(
                client, "sign", data=data, signer=signer, armor=False
            )
            payload = result.structured_content["signature"]
            return base64.b64decode(payload["data_base64"])

        good = await raw_sign("multi", keyring.fpr)
        good2 = await raw_sign("multi", keyring.fpr2)
        bad = await raw_sign("different", keyring.fpr2)

        two_good = base64.b64encode(good + good2).decode("ascii")
        result = ok(
            await call(
                client,
                "verify",
                data="multi",
                signature_base64=two_good,
                mode="detached",
            )
        )
        assert result["signature_count"] == 2
        assert result["valid"] is True

        bad_first = base64.b64encode(bad + good).decode("ascii")
        result = ok(
            await call(
                client,
                "verify",
                data="multi",
                signature_base64=bad_first,
                mode="detached",
            )
        )
        assert result["signature_count"] == 2
        assert result["valid"] is False
        assert result["status"] == "BADSIG"

        good_first = base64.b64encode(good + bad).decode("ascii")
        result = ok(
            await call(
                client,
                "verify",
                data="multi",
                signature_base64=good_first,
                mode="detached",
            )
        )
        assert result["signature_count"] == 2
        assert result["valid"] is False
        assert result["status"] == "BADSIG"

from __future__ import annotations

import pytest


async def call(client, name: str, **kwargs):
    return await client.call_tool(name, kwargs)


def ok(result):
    assert not result.is_error, result.content[0].text if result.content else result
    return result.structured_content


@pytest.mark.asyncio
async def test_list_and_get(connect, keyring) -> None:
    async with connect() as client:
        data = ok(await call(client, "list_keys", query=keyring.fpr))["keys"]
        assert any(k["fingerprint"] == keyring.fpr for k in data)

        key = ok(await call(client, "get_key", fingerprint=keyring.fpr))["key"]
        assert key["fingerprint"] == keyring.fpr
        assert key["secret_available"] is True
        assert key["uids"][0]["uid"]

        secret = ok(await call(client, "list_keys", secret=True))["keys"]
        assert all("secret" in k for k in secret)
        assert any(k["fingerprint"] == keyring.fpr for k in secret)


@pytest.mark.asyncio
async def test_export_public_and_inspect(connect, keyring) -> None:
    async with connect() as client:
        exported = ok(await call(client, "export_public_key", fingerprint=keyring.fpr))
        armored = exported["text"]
        assert armored.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")

        inspected = ok(await call(client, "inspect", data=armored))
        assert inspected["keys"][0]["fingerprint"] == keyring.fpr

        packets = ok(await call(client, "inspect", data=armored, packets=True))
        assert "public key packet" in packets["packets"]


@pytest.mark.asyncio
async def test_sign_verify_modes(connect, keyring) -> None:
    async with connect() as client:
        for mode in ("detached", "cleartext", "inline"):
            signed = ok(
                await call(
                    client,
                    "sign",
                    data="hello modes",
                    signer=keyring.fpr,
                    mode=mode,
                    armor=True,
                    hash_algo="SHA512",
                )
            )
            assert signed["signer_fingerprint"] == keyring.fpr
            assert signed["hash_algo"] == "SHA512"
            if mode == "detached":
                verification = ok(
                    await call(
                        client,
                        "verify",
                        data="hello modes",
                        signature=signed["signature"]["text"],
                        mode=mode,
                    )
                )
            else:
                verification = ok(
                    await call(client, "verify", data=signed["signature"]["text"], mode=mode)
                )
            assert verification["valid"] is True
            assert verification["signer_fingerprint"] == keyring.fpr

        original = ok(await call(client, "sign", data="original", signer=keyring.fpr))
        tampered = ok(
            await call(
                client,
                "verify",
                data="tampered",
                signature=original["signature"]["text"],
                mode="detached",
            )
        )
        assert tampered["valid"] is False
        assert tampered["status"] == "BADSIG"


@pytest.mark.asyncio
async def test_encrypt_decrypt(connect, keyring) -> None:
    async with connect() as client:
        encrypted = ok(await call(client, "encrypt", data="top secret", recipients=[keyring.fpr]))
        ciphertext = encrypted["ciphertext"]["text"]
        assert ciphertext.startswith("-----BEGIN PGP MESSAGE-----")

        recipients = ok(await call(client, "inspect_recipients", ciphertext=ciphertext))
        assert recipients["encrypted"] is True
        assert recipients["symmetric"] is False
        assert recipients["public_key_ids"]

        decrypted = ok(await call(client, "decrypt", ciphertext=ciphertext))
        assert decrypted["plaintext"] == {"text": "top secret"}
        assert decrypted["signed"] is False
        assert decrypted["actual_keys"]
        assert decrypted["actual_keys"][0]["primary_fingerprint"] == keyring.fpr
        assert decrypted["decryption_keys"] == [keyring.fpr]


@pytest.mark.asyncio
async def test_sign_and_encrypt(connect, keyring) -> None:
    async with connect() as client:
        encrypted = ok(
            await call(
                client,
                "sign_and_encrypt",
                data="signed secret",
                recipients=[keyring.fpr],
                signer=keyring.fpr,
            )
        )
        decrypted = ok(
            await call(client, "decrypt", ciphertext=encrypted["ciphertext"]["text"])
        )
        assert decrypted["plaintext"] == {"text": "signed secret"}
        assert decrypted["signed"] is True
        assert decrypted["signature"]["valid"] is True


@pytest.mark.asyncio
async def test_decrypt_only_for_allowed_key(connect, keyring) -> None:
    async with connect() as client:
        encrypted = ok(
            await call(client, "encrypt", data="for key two", recipients=[keyring.fpr2])
        )
        ciphertext = encrypted["ciphertext"]["text"]

        failed = await call(client, "decrypt", ciphertext=ciphertext, expected_key=keyring.fpr)
        assert failed.is_error
        assert "not addressed" in failed.content[0].text

        success = ok(
            await call(client, "decrypt", ciphertext=ciphertext, expected_key=keyring.fpr2)
        )
        assert success["plaintext"] == {"text": "for key two"}


@pytest.mark.asyncio
async def test_symmetric_is_disabled_by_default(connect) -> None:
    async with connect() as client:
        result = await call(client, "symmetric_encrypt", data="symmetric secret")
        assert result.is_error
        assert "disabled" in result.content[0].text


@pytest.mark.asyncio
async def test_create_and_delete_key(connect) -> None:
    async with connect() as client:
        created = ok(
            await call(
                client,
                "create_key",
                uid="Disposable <disposable@example.com>",
                protect=False,
            )
        )
        fpr = created["fingerprint"]
        assert len(fpr) in (40, 64)

        deleted = ok(await call(client, "delete_key", fingerprint=fpr, secret=True))
        assert deleted["deleted"] is True

        missing = await call(client, "get_key", fingerprint=fpr)
        assert missing.is_error


@pytest.mark.asyncio
async def test_import_public_key_roundtrip(connect) -> None:
    async with connect() as client:
        created = ok(
            await call(client, "create_key", uid="Import Me <import@example.com>", protect=False)
        )
        fpr = created["fingerprint"]
        armored = ok(await call(client, "export_public_key", fingerprint=fpr))["text"]
        ok(await call(client, "delete_key", fingerprint=fpr, secret=True))

        imported = ok(await call(client, "import_public_key", key=armored))
        assert imported["imported"] is True
        assert fpr in imported["imported_fingerprints"]

        key = ok(await call(client, "get_key", fingerprint=fpr))["key"]
        assert key["fingerprint"] == fpr
        assert key["secret_available"] is False


@pytest.mark.asyncio
async def test_doctor_agent_and_card(connect) -> None:
    async with connect() as client:
        doctor = ok(await call(client, "doctor"))
        assert doctor["version"]["ok"] is True
        assert doctor["keyring"]["ok"] is True

        agent = ok(await call(client, "agent_info"))
        assert agent["version"]["version"]

        card = ok(await call(client, "card_status"))
        assert "present" in card


@pytest.mark.asyncio
async def test_key_management_and_revocation(connect) -> None:
    async with connect() as client:
        created = ok(
            await call(
                client,
                "create_key",
                uid="Manage Me <manage@example.com>",
                protect=False,
            )
        )
        fpr = created["fingerprint"]

        added_uid = ok(
            await call(client, "add_uid", fingerprint=fpr, uid="Manage Alias <alias@example.com>")
        )
        assert added_uid["updated"] is True

        # add_subkey and change_passphrase intentionally require pinentry and
        # are covered by the interactive test below instead of the default run.
        expiry = ok(
            await call(client, "set_expiry", fingerprint=fpr, expire="1y", subkeys=True)
        )
        assert expiry["updated"] is True

        trust = ok(
            await call(client, "set_ownertrust", fingerprint=fpr, level="marginal")
        )
        assert trust["ownertrust"] == "marginal"

        key = ok(await call(client, "get_key", fingerprint=fpr))["key"]
        assert len(key["uids"]) >= 2
        assert len(key["subkeys"]) >= 1

        revocation = ok(await call(client, "generate_revocation", fingerprint=fpr))
        cert = revocation["revocation_certificate"]
        assert cert.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        assert not cert.startswith(":")

        revoked = ok(await call(client, "revoke_key", fingerprint=fpr))
        assert revoked["revoked"] is True

        after = ok(await call(client, "get_key", fingerprint=fpr))["key"]
        assert after["validity"] == "revoked"

        ok(await call(client, "delete_key", fingerprint=fpr, secret=True))


@pytest.mark.asyncio
async def test_key_algorithm_combinations(connect) -> None:
    async with connect() as client:
        bad = await call(
            client,
            "create_key",
            uid="Bad Combo <bad@example.com>",
            algo="ed25519",
            subkey_algo="rsa3072",
            protect=False,
        )
        assert bad.is_error
        assert "cv25519" in bad.content[0].text

        good = ok(
            await call(
                client,
                "create_key",
                uid="RSA ECDH <rsa@example.com>",
                algo="rsa3072",
                subkey_algo="cv25519",
                protect=False,
            )
        )
        fpr = good["fingerprint"]
        assert good["generated"]["primary"].startswith("RSA")
        assert good["generated"]["subkeys"] == ["ECDH"]
        key = ok(await call(client, "get_key", fingerprint=fpr))["key"]
        assert key["subkeys"][0]["algorithm"] == "ECDH"
        ok(await call(client, "delete_key", fingerprint=fpr, secret=True))

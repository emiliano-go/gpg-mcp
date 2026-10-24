from __future__ import annotations

import os

import pytest

from gpg_mcp.errors import InputError, PolicyError, contains_secret_material, redact
from gpg_mcp.policy import (
    assert_keyring_permissions,
    assert_sign_key_allowed,
    decode_payload,
    load_policy,
    reset_policy_cache,
    validate_hash_algo,
    validate_query,
    validate_uid,
)


def _config(tmp_path, text: str):
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    reset_policy_cache()
    policy = load_policy(path, env={})
    reset_policy_cache()
    return policy


def test_load_defaults(tmp_path) -> None:
    policy = _config(tmp_path, f'gnupg_home = "{tmp_path / "home"}"\n')
    assert policy.approval == "client"
    assert policy.enable_network is False
    assert policy.enable_symmetric is False
    assert policy.dedicated_home is True


def test_reject_bad_approval(tmp_path) -> None:
    with pytest.raises(InputError):
        _config(tmp_path, f'gnupg_home = "{tmp_path}"\napproval = "yolo"\n')


def test_reject_bad_fingerprint(tmp_path) -> None:
    with pytest.raises(InputError):
        _config(
            tmp_path,
            f'gnupg_home = "{tmp_path}"\nallowed_sign_keys = ["DEADBEEF"]\n',
        )


def test_reject_bad_keyserver(tmp_path) -> None:
    with pytest.raises(InputError):
        _config(tmp_path, f'gnupg_home = "{tmp_path}"\nkeyserver = "http://evil"\n')


def test_uid_option_injection() -> None:
    with pytest.raises(InputError):
        validate_uid("--help")
    with pytest.raises(InputError):
        validate_uid("line\nbreak")
    assert validate_uid("Alice <alice@example.com>") == "Alice <alice@example.com>"


def test_query_injection() -> None:
    with pytest.raises(InputError):
        validate_query("--keyserver evil")
    assert validate_query("alice@example.com") == "alice@example.com"


def test_weak_hash_rejected() -> None:
    with pytest.raises(InputError):
        validate_hash_algo("SHA1")
    assert validate_hash_algo("sha512") == "SHA512"


def test_decode_payload_requires_one_input() -> None:
    with pytest.raises(InputError):
        decode_payload(None, None, limit=10)
    with pytest.raises(InputError):
        decode_payload("a", "YQ==", limit=10)
    assert decode_payload("hello", None, limit=10) == b"hello"


def test_keyring_permissions(tmp_path) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o755)
    os.chmod(home, 0o755)
    with pytest.raises(PolicyError):
        assert_keyring_permissions(home)
    os.chmod(home, 0o700)
    assert_keyring_permissions(home)


def test_shared_keyring_denies_with_empty_allowlist(tmp_path) -> None:
    policy = _config(
        tmp_path,
        f'gnupg_home = "{os.path.expanduser("~/.gnupg")}"\n',
    )
    if policy.dedicated_home:
        pytest.skip("test user has no ~/.gnupg")
    with pytest.raises(PolicyError):
        assert_sign_key_allowed(policy, "A" * 40)


def test_secret_material_detection_and_redaction() -> None:
    secret = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nabc"
    assert contains_secret_material(secret)
    assert "redacted" in redact(secret)
    assert not contains_secret_material("-----BEGIN PGP PUBLIC KEY BLOCK-----")

from __future__ import annotations

import pytest

from gpg_mcp.gpg import _verification, parse_colon_keys, parse_status

COLONS = """\
tru:o:1:1792883394:1:3:1:5
pub:u:255:22:7DE1AEEAAC04693B:1792883394:1855955394::u:::scESC:::::ed25519:::0:
fpr:::::::::A6314C63B4A19DF3CDC098D97DE1AEEAAC04693B:
uid:u::::1792883394::F2E723F89EE13F7007A48DDACDB395768100ABC3::Test User <test@example.com>::::::::::0:
sub:u:255:18:494FC533F5726AC6:1792883394:1855955394:::::e:::::cv25519::
fpr:::::::::4CBB6329238555B2EC6D752D494FC533F5726AC6:
"""

STATUS = (
    "[GNUPG:] NEWSIG\n"
    "[GNUPG:] GOODSIG A6314C63B4A19DF3 Test User <test@example.com>\n"
    "[GNUPG:] VALIDSIG A6314C63B4A19DF3CDC098D97DE1AEEAAC04693B 2026-10-24 "
    "1792883400 0 5 0 22 8 00 A6314C63B4A19DF3CDC098D97DE1AEEAAC04693B\n"
    "[GNUPG:] TRUST_ULTIMATE 0 pgp\n"
)


def test_parse_colon_keys() -> None:
    keys = parse_colon_keys(COLONS)
    assert len(keys) == 1
    key = keys[0]
    assert key["fingerprint"] == "A6314C63B4A19DF3CDC098D97DE1AEEAAC04693B"
    assert key["key_id"] == "7DE1AEEAAC04693B"
    assert key["algorithm"] == "EdDSA"
    assert key["capabilities"]["sign"] is True
    assert key["capabilities"]["usable_encrypt"] is True
    assert key["uids"][0]["uid"] == "Test User <test@example.com>"
    assert key["subkeys"][0]["fingerprint"] == "4CBB6329238555B2EC6D752D494FC533F5726AC6"
    assert key["subkeys"][0]["capabilities"]["encrypt"] is True


def test_parse_colon_keys_sanitizes_control_characters() -> None:
    text = COLONS.replace("Test User", "Test\x1b[31m User")
    keys = parse_colon_keys(text)
    assert "\x1b" not in keys[0]["uids"][0]["uid"]


def test_parse_status() -> None:
    events = parse_status(STATUS)
    assert [e.keyword for e in events] == ["NEWSIG", "GOODSIG", "VALIDSIG", "TRUST_ULTIMATE"]
    info = _verification(events)
    assert info["valid"] is True
    assert info["status"] == "GOODSIG"
    assert info["signer_fingerprint"] == "A6314C63B4A19DF3CDC098D97DE1AEEAAC04693B"
    assert info["hash_algo"] == "SHA256"
    assert info["trust"] == "ultimate"


def test_verification_rejects_bad_signature() -> None:
    events = parse_status("[GNUPG:] BADSIG A6314C63B4A19DF3 Test\n")
    info = _verification(events)
    assert info["valid"] is False
    assert info["status"] == "BADSIG"


def test_verification_marks_revoked_key() -> None:
    events = parse_status(
        "[GNUPG:] VALIDSIG A6314C63B4A19DF3CDC098D97DE1AEEAAC04693B "
        "2026-10-24 1792883400 0 5 0 22 8 00 "
        "A6314C63B4A19DF3CDC098D97DE1AEEAAC04693B\n"
        "[GNUPG:] REVKEYSIG A6314C63B4A19DF3 Test\n"
    )
    info = _verification(events)
    assert info["cryptographically_valid"] is True
    assert info["valid"] is False
    assert info["policy_acceptable"] is False
    assert info["key_revoked"] is True


def test_expired_signature_is_not_policy_acceptable() -> None:
    events = parse_status(
        "[GNUPG:] VALIDSIG A6314C63B4A19DF3CDC098D97DE1AEEAAC04693B "
        "2026-10-24 1792883400 0 5 0 22 8 00 "
        "A6314C63B4A19DF3CDC098D97DE1AEEAAC04693B\n"
        "[GNUPG:] EXPSIG A6314C63B4A19DF3 Test\n"
        "[GNUPG:] SIGEXPIRED\n"
    )
    info = _verification(events)
    assert info["cryptographically_valid"] is True
    assert info["policy_acceptable"] is False
    assert info["valid"] is False
    assert info["sig_expired"] is True


def test_expired_key_is_not_policy_acceptable() -> None:
    events = parse_status(
        "[GNUPG:] VALIDSIG A6314C63B4A19DF3CDC098D97DE1AEEAAC04693B "
        "2026-10-24 1792883400 0 5 0 22 8 00 "
        "A6314C63B4A19DF3CDC098D97DE1AEEAAC04693B\n"
        "[GNUPG:] EXPKEYSIG A6314C63B4A19DF3 Test\n"
        "[GNUPG:] KEYEXPIRED 1792883400\n"
    )
    info = _verification(events)
    assert info["cryptographically_valid"] is True
    assert info["policy_acceptable"] is False
    assert info["valid"] is False
    assert info["key_expired"] is True


def test_missing_key_is_not_policy_acceptable() -> None:
    events = parse_status(
        "[GNUPG:] ERRSIG A6314C63B4A19DF3 22 8 00 1792883400 9 -\n"
        "[GNUPG:] NO_PUBKEY A6314C63B4A19DF3\n"
    )
    info = _verification(events)
    assert info["cryptographically_valid"] is False
    assert info["policy_acceptable"] is False
    assert info["valid"] is False
    assert info["missing_key"] is True


MULTI_BAD_FIRST = (
    "[GNUPG:] NEWSIG\n"
    "[GNUPG:] BADSIG A6314C63B4A19DF3 Bad Signer\n"
    "[GNUPG:] NEWSIG\n"
    "[GNUPG:] GOODSIG A6314C63B4A19DF3 Good Signer\n"
    "[GNUPG:] VALIDSIG A6314C63B4A19DF3CDC098D97DE1AEEAAC04693B "
    "2026-10-24 1792883400 0 5 0 22 8 00 "
    "A6314C63B4A19DF3CDC098D97DE1AEEAAC04693B\n"
)

MULTI_GOOD_FIRST = (
    "[GNUPG:] NEWSIG\n"
    "[GNUPG:] GOODSIG A6314C63B4A19DF3 Good Signer\n"
    "[GNUPG:] VALIDSIG A6314C63B4A19DF3CDC098D97DE1AEEAAC04693B "
    "2026-10-24 1792883400 0 5 0 22 8 00 "
    "A6314C63B4A19DF3CDC098D97DE1AEEAAC04693B\n"
    "[GNUPG:] NEWSIG\n"
    "[GNUPG:] BADSIG A6314C63B4A19DF3 Bad Signer\n"
)


def test_multiple_signatures_bad_first() -> None:
    info = _verification(parse_status(MULTI_BAD_FIRST))
    assert info["signature_count"] == 2
    assert info["valid"] is False
    assert info["policy_acceptable"] is False
    assert info["status"] == "BADSIG"
    assert [item["status"] for item in info["signatures"]] == ["BADSIG", "GOODSIG"]


def test_multiple_signatures_good_first() -> None:
    info = _verification(parse_status(MULTI_GOOD_FIRST))
    assert info["signature_count"] == 2
    assert info["valid"] is False
    assert info["status"] == "BADSIG"
    assert [item["status"] for item in info["signatures"]] == ["GOODSIG", "BADSIG"]


def test_multiple_good_signatures_are_acceptable() -> None:
    two_good = (
        "[GNUPG:] NEWSIG\n"
        "[GNUPG:] GOODSIG A6314C63B4A19DF3 One\n"
        "[GNUPG:] VALIDSIG A6314C63B4A19DF3CDC098D97DE1AEEAAC04693B "
        "2026-10-24 1792883400 0 5 0 22 8 00 "
        "A6314C63B4A19DF3CDC098D97DE1AEEAAC04693B\n"
        "[GNUPG:] NEWSIG\n"
        "[GNUPG:] GOODSIG B6314C63B4A19DF3 Two\n"
        "[GNUPG:] VALIDSIG B6314C63B4A19DF3CDC098D97DE1AEEAAC04693B "
        "2026-10-24 1792883400 0 5 0 22 8 00 "
        "B6314C63B4A19DF3CDC098D97DE1AEEAAC04693B\n"
    )
    info = _verification(parse_status(two_good))
    assert info["signature_count"] == 2
    assert info["valid"] is True
    assert info["status"] == "GOODSIG"


def test_actual_decryption_key_must_be_allowed() -> None:
    from gpg_mcp.errors import GpgMcpError, PolicyError
    from gpg_mcp.gpg import Gpg, StatusEvent

    status = [
        StatusEvent("DECRYPTION_KEY", ["B" * 40, "B" * 40, "u"], ""),
    ]
    try:
        Gpg._check_decryption_key(None, status, ["A" * 40])
    except PolicyError as exc:
        assert "outside the allow-list" in str(exc)
    else:
        raise AssertionError("unauthorised decryption key was accepted")

    allowed = Gpg._check_decryption_key(
        None,
        [StatusEvent("DECRYPTION_KEY", ["A" * 40, "A" * 40, "u"], "")],
        ["A" * 40],
    )
    assert allowed[0]["primary_fingerprint"] == "A" * 40

    try:
        Gpg._check_decryption_key(None, [], ["A" * 40])
    except GpgMcpError as exc:
        assert "did not report" in str(exc)
    else:
        raise AssertionError("missing decryption-key status was accepted")


def test_status_file_limit_fails_closed(tmp_path) -> None:
    from gpg_mcp.errors import OutputLimitError
    from gpg_mcp.gpg import read_status_file

    path = tmp_path / "status"
    path.write_text("[GNUPG:] GOODSIG " + "A" * 100, encoding="utf-8")
    with pytest.raises(OutputLimitError):
        read_status_file(path, 10)
    assert read_status_file(path, 10_000).startswith("[GNUPG:]")


def test_recipient_packets_ignore_signature_issuers() -> None:
    from gpg_mcp.gpg import parse_recipient_packets

    signed_only = (
        ":signature packet: algo 22, keyid A6314C63B4A19DF3\n"
        "\tversion 4, created 1792883651, sigclass 0x00\n"
    )
    parsed = parse_recipient_packets(signed_only)
    assert parsed["encrypted"] is False
    assert parsed["public_key_ids"] == []

    encrypted = (
        ":pubkey enc packet: version 3, algo 18, keyid CEE0253087DC02F4\n"
        ":encrypted data packet:\n"
    )
    parsed = parse_recipient_packets(encrypted)
    assert parsed["encrypted"] is True
    assert parsed["public_key_ids"] == ["CEE0253087DC02F4"]

    symmetric = ":symkey enc packet: version 4\n"
    parsed = parse_recipient_packets(symmetric)
    assert parsed["encrypted"] is True
    assert parsed["symmetric"] is True


def test_capability_case_is_preserved() -> None:
    text = (
        "pub:u:255:22:AAAA:1:2::u:::sc:::::ed25519::\n"
        "fpr:::::::::A" * 40 + ":\n"
        "sub:u:255:18:BBBB:1:2:::::e:::::cv25519::\n"
        "fpr:::::::::B" * 40 + ":\n"
    )
    key = parse_colon_keys(text)[0]
    assert key["capabilities"]["encrypt"] is False
    assert key["capabilities"]["usable_encrypt"] is False
    assert key["subkeys"][0]["capabilities"]["encrypt"] is True
    assert key["subkeys"][0]["capabilities"]["usable_encrypt"] is False


def test_trust_fully_is_identity_trusted() -> None:
    status = parse_status(
        "[GNUPG:] NEWSIG\n"
        "[GNUPG:] GOODSIG A6314C63B4A19DF3 Test\n"
        "[GNUPG:] VALIDSIG A6314C63B4A19DF3CDC098D97DE1AEEAAC04693B "
        "2026-10-24 1792883400 0 5 0 22 8 00 "
        "A6314C63B4A19DF3CDC098D97DE1AEEAAC04693B\n"
        "[GNUPG:] TRUST_FULLY 0 pgp\n"
    )
    info = _verification(status)
    assert info["trust"] == "full"
    assert info["identity_trusted"] is True


def test_import_result_states() -> None:
    from gpg_mcp.gpg import GpgResult, StatusEvent, _import_summary, import_result

    complete = GpgResult(
        argv=[],
        returncode=0,
        stdout=b"",
        stderr="",
        status=[StatusEvent("IMPORT_OK", ["0", "A" * 40], "")],
    )
    assert import_result(complete, _import_summary(complete.status))["status"] == "complete"

    partial = GpgResult(
        argv=[],
        returncode=2,
        stdout=b"",
        stderr="",
        status=[
            StatusEvent("IMPORT_OK", ["0", "A" * 40], ""),
            StatusEvent("IMPORT_PROBLEM", ["1"], ""),
        ],
    )
    assert import_result(partial, _import_summary(partial.status))["status"] == "partial"

    failed = GpgResult(argv=[], returncode=2, stdout=b"", stderr="", status=[])
    assert import_result(failed, _import_summary(failed.status))["status"] == "failed"

from __future__ import annotations

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

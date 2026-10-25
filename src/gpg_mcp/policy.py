"""Configuration, allow-lists, keyring hygiene and the audit ledger."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import tomllib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .errors import InputError, PolicyError

USER_GNUPG_HOME = (Path.home() / ".gnupg").resolve()
DEFAULT_GNUPG_HOME = (Path.home() / ".local" / "share" / "gpg-mcp" / "gnupg").resolve()
DEFAULT_CONFIG = Path.home() / ".config" / "gpg-mcp" / "config.toml"
DEFAULT_AUDIT = Path.home() / ".local" / "share" / "gpg-mcp" / "audit.jsonl"

_FPR_RE = re.compile(r"^(?:[0-9A-F]{40}|[0-9A-F]{64})$")
_EXPIRE_RE = re.compile(
    r"^(?:never|none|\d{4}-\d{2}-\d{2}|\d{8}T\d{6}|\d+[dwmy]?|seconds=\d+)$"
)
_HASHES = {"SHA256", "SHA384", "SHA512"}
_SIGN_ALGOS = {"ed25519", "rsa3072", "rsa4096", "future-default", "default"}
_SUBKEY_ALGOS = {"cv25519", "ed25519", "rsa3072", "rsa4096", "future-default", "default"}
_APPROVAL_MODES = {"client", "local", "none"}
_OWNERTRUST = {"never", "marginal", "full"}


@dataclass(frozen=True)
class Operation:
    """Authorization metadata for one MCP-facing operation.

    ``constituents`` models composite actions. Approval is required when the
    operation itself is in ``require_approval`` *or* any constituent is, so a
    custom policy cannot approve signing but silently allow sign-and-encrypt.
    """

    name: str
    destructive: bool = False
    constituents: tuple[str, ...] = ()
    description: str = ""


OPERATIONS: dict[str, Operation] = {
    "sign": Operation("sign", description="Sign data"),
    "encrypt": Operation("encrypt", description="Encrypt data"),
    "sign_and_encrypt": Operation(
        "sign_and_encrypt",
        constituents=("sign", "encrypt"),
        description="Sign and encrypt data",
    ),
    "decrypt": Operation("decrypt", description="Decrypt ciphertext"),
    "symmetric_encrypt": Operation("symmetric_encrypt", description="Symmetric encryption"),
    "symmetric_decrypt": Operation("symmetric_decrypt", description="Symmetric decryption"),
    "create_key": Operation("create_key", description="Create a key"),
    "add_subkey": Operation("add_subkey", description="Add a subkey"),
    "add_uid": Operation("add_uid", description="Add a user ID"),
    "set_expiry": Operation("set_expiry", description="Change key expiry"),
    "change_passphrase": Operation("change_passphrase", description="Change a passphrase"),
    "import_public_key": Operation("import_public_key", description="Import a public key"),
    "import_revocation": Operation(
        "import_revocation",
        destructive=True,
        description="Apply a revocation certificate",
    ),
    "generate_revocation": Operation(
        "generate_revocation", description="Export a revocation certificate"
    ),
    "revoke_key": Operation("revoke_key", destructive=True, description="Revoke a key"),
    "delete_key": Operation("delete_key", destructive=True, description="Delete a key"),
    "set_ownertrust": Operation("set_ownertrust", description="Set ownertrust"),
    "send_key": Operation("send_key", description="Publish a public key"),
    "fetch_key": Operation("fetch_key", description="Fetch and import a public key"),
}

ALL_OPERATIONS = frozenset(OPERATIONS)
READ_ONLY_TOOLS = frozenset(
    {
        "list_keys",
        "get_key",
        "export_public_key",
        "export_ssh_key",
        "inspect",
        "inspect_recipients",
        "verify",
        "card_status",
        "agent_info",
        "doctor",
        "search_keyserver",
    }
)


def operation_spec(name: str) -> Operation | None:
    return OPERATIONS.get(name)


def assert_registered_operation(name: str) -> Operation:
    spec = OPERATIONS.get(name)
    if spec is None:
        raise PolicyError(
            f"operation {name!r} is not registered in the authorization policy"
        )
    return spec


def requires_approval(policy: Policy, name: str) -> bool:
    """Fail closed: unknown operations always require approval.

    Composite operations inherit the requirement of every constituent.
    """
    spec = OPERATIONS.get(name)
    if spec is None:
        return True
    if name in policy.require_approval:
        return True
    return any(requires_approval(policy, constituent) for constituent in spec.constituents)


@dataclass(frozen=True)
class Policy:
    gnupg_home: Path
    default_sign_key: str | None
    allowed_sign_keys: tuple[str, ...]
    allowed_decrypt_keys: tuple[str, ...]
    allowed_recipients: tuple[str, ...]
    require_approval: frozenset[str]
    approval: str
    destructive_confirmation: bool
    max_input_bytes: int
    max_output_bytes: int
    timeout_s: int
    keygen_timeout_s: int
    enable_network: bool
    enable_symmetric: bool
    allow_unprotected_keys: bool
    allow_hidden_recipients: bool
    allow_secret_import: bool
    keyserver: str
    audit_log: Path
    config_path: Path
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def dedicated_home(self) -> bool:
        return self.gnupg_home.resolve() != USER_GNUPG_HOME

    @property
    def max_status_bytes(self) -> int:
        return max(1_000_000, self.max_output_bytes)


_CACHED: Policy | None = None


def _as_bool(value: Any, key: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"1", "true", "yes", "on"}:
        return True
    if isinstance(value, str) and value.lower() in {"0", "false", "no", "off"}:
        return False
    raise InputError(f"config {key!r} must be a boolean")


def _as_int(value: Any, key: str, *, minimum: int, maximum: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise InputError(f"config {key!r} must be an integer") from exc
    if not minimum <= n <= maximum:
        raise InputError(f"config {key!r} must be between {minimum} and {maximum}")
    return n


def _as_str_tuple(value: Any, key: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise InputError(f"config {key!r} must be a list of strings")
    return tuple(v.strip().upper() for v in value if v.strip())


def _expand(value: Any, key: str, default: Path) -> Path:
    if value is None:
        return default
    if not isinstance(value, str):
        raise InputError(f"config {key!r} must be a path string")
    return Path(os.path.expandvars(os.path.expanduser(value)))


def _validate_keyserver(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"hkps", "https"}:
        raise InputError("keyserver must use hkps:// or https://")
    if not parsed.netloc or parsed.username or parsed.password:
        raise InputError("keyserver must be a host without credentials")
    if parsed.query or parsed.fragment:
        raise InputError("keyserver must not contain a query or fragment")
    return value


def load_policy(path: Path | None = None, *, env: dict[str, str] | None = None) -> Policy:
    """Load config from TOML and environment. Environment wins over the file."""
    global _CACHED
    env = os.environ if env is None else env
    config_path = Path(
        os.path.expanduser(env.get("GPG_MCP_CONFIG", str(path or DEFAULT_CONFIG)))
    )
    raw: dict[str, Any] = {}
    if config_path.exists():
        with config_path.open("rb") as fh:
            raw = tomllib.load(fh)
        if not isinstance(raw, dict):
            raise InputError("config root must be a table")

    home = _expand(
        env.get("GPG_MCP_HOME", raw.get("gnupg_home")), "gnupg_home", DEFAULT_GNUPG_HOME
    )
    audit_log = _expand(
        env.get("GPG_MCP_AUDIT", raw.get("audit_log")), "audit_log", DEFAULT_AUDIT
    )

    approval = str(env.get("GPG_MCP_APPROVAL", raw.get("approval", "client"))).lower()
    if approval not in _APPROVAL_MODES:
        raise InputError(f"approval must be one of {sorted(_APPROVAL_MODES)}")

    require = raw.get("require_approval", sorted(ALL_OPERATIONS))
    if not isinstance(require, list) or not all(isinstance(v, str) for v in require):
        raise InputError("require_approval must be a list of operation names")
    unknown = set(require) - ALL_OPERATIONS
    if unknown:
        raise InputError(f"unknown operations in require_approval: {sorted(unknown)}")

    policy = Policy(
        gnupg_home=home.resolve(),
        default_sign_key=(
            str(raw["default_sign_key"]).strip().upper() if raw.get("default_sign_key") else None
        ),
        allowed_sign_keys=_as_str_tuple(raw.get("allowed_sign_keys"), "allowed_sign_keys"),
        allowed_decrypt_keys=_as_str_tuple(
            raw.get("allowed_decrypt_keys"), "allowed_decrypt_keys"
        ),
        allowed_recipients=_as_str_tuple(raw.get("allowed_recipients"), "allowed_recipients"),
        require_approval=frozenset(require),
        approval=approval,
        destructive_confirmation=_as_bool(
            raw.get("destructive_confirmation", True), "destructive_confirmation"
        ),
        max_input_bytes=_as_int(
            raw.get("max_input_bytes", 10 * 1024 * 1024),
            "max_input_bytes",
            minimum=1,
            maximum=64 * 1024 * 1024,
        ),
        max_output_bytes=_as_int(
            raw.get("max_output_bytes", 20 * 1024 * 1024),
            "max_output_bytes",
            minimum=1,
            maximum=128 * 1024 * 1024,
        ),
        timeout_s=_as_int(raw.get("timeout_s", 120), "timeout_s", minimum=1, maximum=3600),
        keygen_timeout_s=_as_int(
            raw.get("keygen_timeout_s", 300), "keygen_timeout_s", minimum=1, maximum=3600
        ),
        enable_network=_as_bool(
            env.get("GPG_MCP_ENABLE_NETWORK", raw.get("enable_network", False)),
            "enable_network",
        ),
        enable_symmetric=_as_bool(
            env.get("GPG_MCP_ENABLE_SYMMETRIC", raw.get("enable_symmetric", False)),
            "enable_symmetric",
        ),
        allow_unprotected_keys=_as_bool(
            raw.get("allow_unprotected_keys", False), "allow_unprotected_keys"
        ),
        allow_hidden_recipients=_as_bool(
            raw.get("allow_hidden_recipients", False), "allow_hidden_recipients"
        ),
        allow_secret_import=_as_bool(
            raw.get("allow_secret_import", False), "allow_secret_import"
        ),
        keyserver=_validate_keyserver(
            str(raw.get("keyserver", "hkps://keys.openpgp.org"))
        ),
        audit_log=audit_log.absolute(),
        config_path=config_path.resolve(),
        raw=raw,
    )

    for name, values in (
        ("allowed_sign_keys", policy.allowed_sign_keys),
        ("allowed_decrypt_keys", policy.allowed_decrypt_keys),
        ("allowed_recipients", policy.allowed_recipients),
    ):
        for value in values:
            if not _FPR_RE.match(value):
                raise InputError(f"{name} contains an invalid fingerprint: {value!r}")
    if policy.default_sign_key and not _FPR_RE.match(policy.default_sign_key):
        raise InputError("default_sign_key must be a full fingerprint")

    _CACHED = policy
    return policy


def get_policy() -> Policy:
    if _CACHED is None:
        return load_policy()
    return _CACHED


def reset_policy_cache() -> None:
    global _CACHED
    _CACHED = None


def is_fingerprint(value: str) -> bool:
    return bool(_FPR_RE.match(value.strip().upper()))


def require_fingerprint(value: str, *, what: str = "fingerprint") -> str:
    fpr = (value or "").strip().upper().replace(" ", "")
    if not _FPR_RE.match(fpr):
        raise InputError(
            f"{what} must be a full OpenPGP fingerprint (40 or 64 hex characters)"
        )
    return fpr


def validate_hash_algo(value: str) -> str:
    algo = (value or "SHA256").strip().upper()
    if algo not in _HASHES:
        raise InputError("hash_algo must be SHA256, SHA384 or SHA512")
    return algo


def validate_uid(value: str) -> str:
    uid = (value or "").strip()
    if not uid or len(uid) > 512:
        raise InputError("uid must be 1..512 characters")
    if uid.startswith("-"):
        raise InputError("uid must not start with '-' (option injection)")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in uid):
        raise InputError("uid must not contain control characters or newlines")
    return uid


def validate_expire(value: str) -> str:
    expire = (value or "").strip()
    if not _EXPIRE_RE.match(expire):
        raise InputError(
            "expire must be never, none, YYYY-MM-DD, YYYYMMDDThhmmss, "
            "N[d|w|m|y], or seconds=N"
        )
    return expire


def validate_sign_algo(value: str) -> str:
    algo = (value or "ed25519").strip().lower()
    if algo not in _SIGN_ALGOS:
        raise InputError(f"algo must be one of {sorted(_SIGN_ALGOS)}")
    return algo


def validate_subkey_algo(value: str) -> str:
    algo = (value or "cv25519").strip().lower()
    if algo not in _SUBKEY_ALGOS:
        raise InputError(f"subkey algo must be one of {sorted(_SUBKEY_ALGOS)}")
    return algo


def validate_ownertrust(value: str) -> str:
    level = (value or "").strip().lower()
    if level not in _OWNERTRUST:
        raise InputError("ownertrust must be never, marginal or full (ultimate is CLI-only)")
    return level


def validate_query(value: str, *, field: str = "query") -> str:
    q = (value or "").strip()
    if not q or len(q) > 256:
        raise InputError(f"{field} must be 1..256 characters")
    if q.startswith("-") or any(ch in q for ch in "\x00\n\r"):
        raise InputError(f"{field} must not start with '-' or contain control characters")
    return q


def decode_payload(data: str | None, data_base64: str | None, *, limit: int) -> bytes:
    import base64
    import binascii

    if (data is None) == (data_base64 is None):
        raise InputError("provide exactly one of data or data_base64")
    if data is not None:
        payload = data.encode("utf-8")
    else:
        try:
            payload = base64.b64decode(data_base64 or "", validate=True)
        except (binascii.Error, ValueError) as exc:
            raise InputError("data_base64 is not valid base64") from exc
    if len(payload) > limit:
        raise InputError(f"payload exceeds the {limit} byte limit")
    return payload


def encode_payload(payload: bytes) -> dict[str, Any]:
    try:
        return {"text": payload.decode("utf-8")}
    except UnicodeDecodeError:
        import base64

        return {"data_base64": base64.b64encode(payload).decode("ascii")}


def assert_keyring_permissions(home: Path) -> None:
    try:
        st = home.stat()
    except FileNotFoundError as exc:
        raise PolicyError(
            f"GNUPGHOME does not exist: {home}. Run 'gpg-mcp init' first."
        ) from exc
    if not stat.S_ISDIR(st.st_mode):
        raise PolicyError(f"GNUPGHOME is not a directory: {home}")
    if st.st_uid != os.getuid():
        raise PolicyError("GNUPGHOME is not owned by the current user")
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise PolicyError(
            f"GNUPGHOME must be 0700, found {oct(stat.S_IMODE(st.st_mode))}"
        )


def assert_sign_key_allowed(policy: Policy, fingerprint: str) -> str:
    fpr = require_fingerprint(fingerprint)
    if policy.allowed_sign_keys:
        if fpr not in policy.allowed_sign_keys:
            raise PolicyError("signing key is not in allowed_sign_keys")
        return fpr
    if not policy.dedicated_home:
        raise PolicyError(
            "allowed_sign_keys is empty and the shared ~/.gnupg keyring is in use; "
            "add an explicit signing fingerprint or use a dedicated GNUPGHOME"
        )
    return fpr


def assert_decrypt_key_allowed(policy: Policy, fingerprint: str) -> str:
    fpr = require_fingerprint(fingerprint)
    if policy.allowed_decrypt_keys:
        if fpr not in policy.allowed_decrypt_keys:
            raise PolicyError("decryption key is not in allowed_decrypt_keys")
        return fpr
    if not policy.dedicated_home:
        raise PolicyError(
            "allowed_decrypt_keys is empty and the shared ~/.gnupg keyring is in use; "
            "add an explicit decryption fingerprint or use a dedicated GNUPGHOME"
        )
    return fpr


def assert_recipient_allowed(policy: Policy, fingerprint: str) -> str:
    fpr = require_fingerprint(fingerprint)
    if policy.allowed_recipients and fpr not in policy.allowed_recipients:
        raise PolicyError("recipient is not in allowed_recipients")
    return fpr


def audit(policy: Policy, record: dict[str, Any]) -> None:
    """Append one JSON line to the audit ledger. Best effort, never contains secrets."""
    entry = {
        "ts": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "home": str(policy.gnupg_home),
        **record,
    }
    line = json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n"
    try:
        parent = policy.audit_log.parent
        if not parent.exists():
            # Only tighten permissions on a directory this process creates.
            # Never chmod an existing arbitrary parent (for example /tmp).
            parent.mkdir(parents=True, mode=0o700)
            os.chmod(parent, 0o700)
        flags = (
            os.O_APPEND
            | os.O_CREAT
            | os.O_WRONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        fd = os.open(policy.audit_log, flags, 0o600)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                print(
                    "gpg-mcp: audit log is not a regular file; refusing to write",
                    file=sys.stderr,
                )
                return
            if st.st_uid != os.getuid():
                print(
                    "gpg-mcp: audit log is not owned by the current user; "
                    "refusing to write",
                    file=sys.stderr,
                )
                return
            if stat.S_IMODE(st.st_mode) & 0o077:
                try:
                    os.fchmod(fd, 0o600)
                except OSError as exc:
                    print(
                        f"gpg-mcp: cannot tighten audit log permissions: {exc}",
                        file=sys.stderr,
                    )
                    return
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
    except OSError as exc:  # pragma: no cover - depends on host
        print(f"gpg-mcp: audit log unavailable: {exc}", file=sys.stderr)


def assert_manage_key_allowed(policy: Policy, fingerprint: str) -> str:
    """Key management is unrestricted only inside a dedicated keyring."""
    fpr = require_fingerprint(fingerprint)
    if policy.dedicated_home:
        return fpr
    allowed = set(policy.allowed_sign_keys) | set(policy.allowed_decrypt_keys)
    if fpr in allowed:
        return fpr
    raise PolicyError(
        "key management is not allowed for this fingerprint while the shared "
        "~/.gnupg keyring is in use"
    )

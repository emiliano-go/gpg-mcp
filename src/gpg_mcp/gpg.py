"""Shell-free GnuPG runner, parsers and the high-level operation set.

Every call goes through :meth:`Gpg.run`, which:
  * uses an absolute, sanitised gpg binary path;
  * passes a minimal environment (no LD_*, no GPG_AGENT_INFO, no GPG_TTY);
  * creates a 0700 temporary directory and 0600 files;
  * caps stdout/stderr and kills the process group on timeout;
  * never places a passphrase on a command line, in env or on stdin.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import shutil
import signal
import tempfile
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .binaries import secure_binary
from .errors import (
    GpgExecutionError,
    GpgMcpError,
    InputError,
    OutputLimitError,
    PolicyError,
    TimeoutError_,
    contains_secret_material,
    redact,
    sanitize_text,
)
from .policy import (
    Policy,
    assert_config_file,
    assert_config_parent,
    assert_decrypt_key_allowed,
    assert_keyring_permissions,
    assert_manage_key_allowed,
    assert_recipient_allowed,
    assert_sign_key_allowed,
    encode_payload,
    require_fingerprint,
    validate_expire,
    validate_hash_algo,
    validate_key_algorithms,
    validate_ownertrust,
    validate_query,
    validate_subkey_algo,
    validate_uid,
)

MIN_GPG = (2, 2)
_TMP = "{tmp}"
_TOOL_OUTPUT_LIMIT = 1 * 1024 * 1024


# ---------------------------------------------------------------------------
# binary and environment hygiene
# ---------------------------------------------------------------------------

def _base_env(home: Path) -> dict[str, str]:
    env = {
        "GNUPGHOME": str(home),
        "HOME": os.environ.get("HOME", str(Path.home())),
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
    }
    for key in (
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_RUNTIME_DIR",
        "XAUTHORITY",
    ):
        value = os.environ.get(key)
        if value:
            env[key] = value
    return env


def _write_private(path: Path, data: bytes) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def read_status_file(path: Path, limit: int) -> str:
    """Read a status file, failing closed if it exceeds the configured limit."""
    size = path.stat().st_size
    if size > limit:
        raise OutputLimitError(
            f"gpg status output exceeded the {limit} byte limit"
        )
    return path.read_bytes().decode("utf-8", errors="replace")


def _kill_group(proc: asyncio.subprocess.Process) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        with contextlib.suppress(ProcessLookupError):
            proc.kill()


# ---------------------------------------------------------------------------
# results and parsing
# ---------------------------------------------------------------------------

@dataclass
class StatusEvent:
    keyword: str
    args: list[str]
    raw: str

    def as_dict(self) -> dict[str, Any]:
        return {"keyword": self.keyword, "args": self.args}


@dataclass
class GpgResult:
    argv: list[str]
    returncode: int
    stdout: bytes
    stderr: str
    status: list[StatusEvent] = field(default_factory=list)
    duration_ms: int = 0

    @property
    def text(self) -> str:
        return self.stdout.decode("utf-8", errors="replace")

    def first(self, keyword: str) -> StatusEvent | None:
        return next((e for e in self.status if e.keyword == keyword), None)

    def all(self, keyword: str) -> list[StatusEvent]:
        return [e for e in self.status if e.keyword == keyword]

    def status_dict(self) -> list[dict[str, Any]]:
        return [e.as_dict() for e in self.status]


_ALGO = {
    1: "RSA",
    2: "RSA",
    3: "RSA",
    16: "ElGamal",
    17: "DSA",
    18: "ECDH",
    19: "ECDSA",
    20: "ElGamal",
    22: "EdDSA",
    23: "EdDSA",
    25: "X25519",
    26: "X448",
    27: "Ed25519",
    28: "Ed448",
}
_HASH_ALGO = {1: "MD5", 2: "SHA1", 8: "SHA256", 9: "SHA384", 10: "SHA512", 11: "SHA224"}
_VALIDITY = {
    "e": "expired",
    "r": "revoked",
    "d": "disabled",
    "i": "invalid",
    "n": "unknown",
    "m": "marginal",
    "f": "full",
    "u": "ultimate",
    "w": "well",
    "-": "unknown",
    "?": "undefined",
}
_BAD_VALIDITY = {"revoked", "expired", "invalid", "disabled"}


def _usable(item: dict[str, Any]) -> bool:
    return item.get("validity") not in _BAD_VALIDITY


def parse_status(text: str) -> list[StatusEvent]:
    events: list[StatusEvent] = []
    prefix = "[GNUPG:] "
    for line in text.splitlines():
        if not line.startswith(prefix):
            continue
        payload = line[len(prefix) :]
        keyword, _, rest = payload.partition(" ")
        events.append(StatusEvent(keyword, rest.split() if rest else [], line))
    return events


def _iso(ts: str | None) -> str | None:
    if not ts or ts in {"0", "-"}:
        return None
    if "T" in ts:
        return ts
    try:
        return datetime.fromtimestamp(int(ts), UTC).isoformat().replace("+00:00", "Z")
    except (ValueError, OSError):
        return None


def _algo(value: str | None) -> str:
    try:
        return _ALGO.get(int(value or "0"), f"algo:{value}")
    except ValueError:
        return f"algo:{value}"


def _hash_name(value: str | None) -> str:
    try:
        return _HASH_ALGO.get(int(value or "0"), f"hash:{value}")
    except ValueError:
        return f"hash:{value}"


def _caps(value: str) -> dict[str, bool]:
    raw = value or ""
    own = raw.lower()
    return {
        "certify": "c" in own,
        "sign": "s" in own,
        "encrypt": "e" in own,
        "auth": "a" in own,
        "usable_certify": "C" in raw,
        "usable_sign": "S" in raw,
        "usable_encrypt": "E" in raw,
        "usable_auth": "A" in raw,
    }


def parse_colon_keys(text: str) -> list[dict[str, Any]]:
    """Parse ``--with-colons`` output into primary keys with UIDs/subkeys."""
    keys: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    target: dict[str, Any] | None = None

    def new_key(record: list[str], secret: bool) -> dict[str, Any]:
        return {
            "type": record[0],
            "validity": _VALIDITY.get(record[1], record[1]),
            "bits": int(record[2]) if record[2].isdigit() else None,
            "algorithm": _algo(record[3]),
            "key_id": (record[4] or "").upper(),
            "created_at": _iso(record[5]),
            "expires_at": _iso(record[6]),
            "owner_trust": _VALIDITY.get(record[8], record[8]) if len(record) > 8 else None,
            "capabilities": _caps(record[11] if len(record) > 11 else ""),
            "capability_letters": (record[11] if len(record) > 11 else ""),
            "secret": secret,
            "fingerprint": None,
            "keygrip": None,
            "uids": [],
            "subkeys": [],
            "signatures": [],
        }

    for line in text.splitlines():
        if not line:
            continue
        f = line.split(":")
        rectype = f[0]
        if rectype in {"pub", "sec"}:
            current = new_key(f, rectype == "sec")
            keys.append(current)
            target = current
        elif rectype in {"sub", "ssb"} and current is not None:
            sub = new_key(f, rectype == "ssb")
            current["subkeys"].append(sub)
            target = sub
        elif rectype == "fpr" and target is not None:
            if not target.get("fingerprint") and len(f) > 9:
                target["fingerprint"] = f[9].upper()
        elif rectype == "grp" and target is not None:
            if len(f) > 9:
                target["keygrip"] = f[9]
        elif rectype == "uid" and current is not None:
            if len(f) > 9:
                current["uids"].append(
                    {"uid": sanitize_text(unquote(f[9])), "validity": _VALIDITY.get(f[1], f[1])}
                )
        elif rectype in {"sig", "rev"} and current is not None:
            if len(f) > 10:
                current["signatures"].append(
                    {
                        "type": rectype,
                        "validity": _VALIDITY.get(f[1], f[1]),
                        "key_id": (f[4] or "").upper(),
                        "created_at": _iso(f[5]),
                        "uid": sanitize_text(unquote(f[9])) if f[9] else None,
                        "sig_class": f[10] or None,
                    }
                )
    return keys


def _verify_one(status: list[StatusEvent]) -> dict[str, Any]:
    """Classify one signature sequence.

    ``cryptographically_valid`` means the math checked out (VALIDSIG).
    ``policy_acceptable`` additionally requires a GOODSIG with no expired
    signature, expired key or revoked key. ``valid`` is kept as the policy
    result so decryption only releases plaintext under the strict rule.
    Identity trust is reported separately and is not part of acceptance.
    """
    out: dict[str, Any] = {
        "valid": False,
        "cryptographically_valid": False,
        "policy_acceptable": False,
        "status": "UNKNOWN",
        "signer_fingerprint": None,
        "primary_fingerprint": None,
        "key_id": None,
        "uid": None,
        "trust": None,
        "identity_trusted": False,
        "hash_algo": None,
        "pubkey_algo": None,
        "sig_class": None,
        "created_at": None,
        "expires_at": None,
        "key_expired": False,
        "sig_expired": False,
        "key_revoked": False,
        "missing_key": False,
    }
    for ev in status:
        kw = ev.keyword
        if kw == "VALIDSIG" and len(ev.args) >= 9:
            out.update(
                cryptographically_valid=True,
                signer_fingerprint=ev.args[0].upper(),
                created_at=_iso(ev.args[2]),
                expires_at=_iso(ev.args[3]),
                pubkey_algo=_algo(ev.args[6]),
                hash_algo=_hash_name(ev.args[7]),
                sig_class=ev.args[8],
                primary_fingerprint=(ev.args[9].upper() if len(ev.args) > 9 else ev.args[0].upper()),
            )
        elif kw in {"GOODSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "BADSIG"}:
            out["status"] = kw
            if ev.args:
                out["key_id"] = ev.args[0].upper()
            if len(ev.args) > 1:
                out["uid"] = sanitize_text(unquote(" ".join(ev.args[1:])))
            if kw == "EXPKEYSIG":
                out["key_expired"] = True
            elif kw == "EXPSIG":
                out["sig_expired"] = True
            elif kw == "REVKEYSIG":
                out["key_revoked"] = True
        elif kw == "ERRSIG":
            out["status"] = "ERRSIG"
            if ev.args:
                out["key_id"] = ev.args[0].upper()
        elif kw == "NO_PUBKEY":
            out["missing_key"] = True
        elif kw.startswith("TRUST_"):
            level = kw.removeprefix("TRUST_").lower()
            out["trust"] = "full" if level == "fully" else level
        elif kw == "KEYEXPIRED":
            out["key_expired"] = True
        elif kw == "SIGEXPIRED":
            out["sig_expired"] = True
        elif kw == "KEYREVOKED":
            out["key_revoked"] = True

    conditions_clear = not (
        out["key_expired"]
        or out["sig_expired"]
        or out["key_revoked"]
        or out["missing_key"]
    )
    out["policy_acceptable"] = bool(
        out["cryptographically_valid"] and conditions_clear and out["status"] == "GOODSIG"
    )
    out["valid"] = out["policy_acceptable"]
    out["identity_trusted"] = out["trust"] in {"full", "ultimate"}
    return out


_SIGNATURE_EVENTS = {
    "NEWSIG",
    "VALIDSIG",
    "GOODSIG",
    "BADSIG",
    "EXPSIG",
    "EXPKEYSIG",
    "REVKEYSIG",
    "ERRSIG",
    "NO_PUBKEY",
    "KEYEXPIRED",
    "SIGEXPIRED",
    "KEYREVOKED",
}


def _signature_sequences(status: list[StatusEvent]) -> list[list[StatusEvent]]:
    sequences: list[list[StatusEvent]] = []
    current: list[StatusEvent] | None = None
    for event in status:
        if event.keyword == "NEWSIG":
            if current:
                sequences.append(current)
            current = [event]
        elif event.keyword in _SIGNATURE_EVENTS or event.keyword.startswith("TRUST_"):
            if current is None:
                current = []
            current.append(event)
    if current:
        sequences.append(current)
    return sequences


def _worst_signature_status(results: list[dict[str, Any]]) -> str:
    for candidate in ("BADSIG", "ERRSIG", "REVKEYSIG", "EXPSIG", "EXPKEYSIG", "UNKNOWN"):
        if any(result["status"] == candidate for result in results):
            return candidate
    if all(result["status"] == "GOODSIG" for result in results):
        return "GOODSIG"
    return "UNKNOWN"


def _aggregate_verification_results(
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    if not results:
        return _verify_one([])
    aggregate = dict(results[0])
    aggregate["signatures"] = results
    aggregate["signature_count"] = len(results)
    if len(results) == 1:
        return aggregate
    aggregate["cryptographically_valid"] = all(
        result["cryptographically_valid"] for result in results
    )
    aggregate["policy_acceptable"] = all(
        result["policy_acceptable"] for result in results
    )
    aggregate["valid"] = aggregate["policy_acceptable"]
    aggregate["identity_trusted"] = all(
        result["identity_trusted"] for result in results
    )
    for flag in ("key_expired", "sig_expired", "key_revoked", "missing_key"):
        aggregate[flag] = any(result[flag] for result in results)
    aggregate["status"] = _worst_signature_status(results)
    return aggregate


def _verification(status: list[StatusEvent]) -> dict[str, Any]:
    """Aggregate one result per NEWSIG sequence, failing closed across all.

    A message can carry multiple signatures. An invalid signature must not be
    hidden by a later valid one, so the aggregate is acceptable only when every
    signature is policy-acceptable.
    """
    results = [_verify_one(sequence) for sequence in _signature_sequences(status)]
    return _aggregate_verification_results(results)


def import_result(result: GpgResult, summary: dict[str, Any]) -> dict[str, Any]:
    """Classify an import as complete, partial or failed."""
    if result.returncode == 0 and not summary["problems"]:
        status = "complete"
    elif summary["imported"]:
        status = "partial"
    else:
        status = "failed"
    return {**summary, "gpg_exit_code": result.returncode, "status": status}


def _created_key(status: list[StatusEvent]) -> str | None:
    for ev in status:
        if ev.keyword == "KEY_CREATED" and len(ev.args) >= 2:
            return ev.args[1].upper()
    return None


def clean_revocation_certificate(text: str) -> str:
    """Extract the armored revocation block and remove GnuPG's safety colon."""
    lines = text.splitlines()
    start: int | None = None
    for index, line in enumerate(lines):
        candidate = line[1:] if line.startswith(":") else line
        if candidate.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----"):
            lines[index] = candidate
            start = index
            break
    if start is None:
        return text
    for end in range(start + 1, len(lines)):
        if lines[end].startswith("-----END PGP PUBLIC KEY BLOCK-----"):
            return "\n".join(lines[start : end + 1]) + "\n"
    return text


_ISSUER_FPR_RE = re.compile(r"issuer fpr v[0-9]+ ([0-9A-Fa-f]{40,64})")
_REVOCATION_SIG_RE = re.compile(r"sigclass 0x20", re.IGNORECASE)
_ANY_REVOCATION_SIG_RE = re.compile(r"sigclass 0x(?:20|28|30)", re.IGNORECASE)
_KEYID_RE = re.compile(r"keyid ([0-9A-Fa-f]{16,32})")
_PUBKEY_ENC_RE = re.compile(
    r"^:pubkey enc packet:.*?keyid ([0-9A-Fa-f]{16,32})", re.MULTILINE
)
_SYMKEY_ENC_RE = re.compile(r"^:symkey enc packet:", re.MULTILINE)
_ENCRYPTED_DATA_RE = re.compile(r"^:encrypted data packet:", re.MULTILINE)


def parse_recipient_packets(packet_text: str) -> dict[str, Any]:
    keyids = sorted({match.upper() for match in _PUBKEY_ENC_RE.findall(packet_text)})
    symmetric = bool(_SYMKEY_ENC_RE.search(packet_text))
    encrypted_data = bool(_ENCRYPTED_DATA_RE.search(packet_text))
    return {
        "public_key_ids": keyids,
        "symmetric": symmetric,
        "encrypted": encrypted_data or symmetric or bool(keyids),
    }


def revocation_packet_info(packet_text: str) -> dict[str, Any]:
    keyids = {match.upper() for match in _KEYID_RE.findall(packet_text)}
    return {
        "issuer_fingerprints": {
            match.upper() for match in _ISSUER_FPR_RE.findall(packet_text)
        },
        "keyids": keyids,
        "has_revocation_signature": bool(_REVOCATION_SIG_RE.search(packet_text)),
        "has_any_revocation_signature": bool(
            _ANY_REVOCATION_SIG_RE.search(packet_text)
        ),
        "has_public_key": bool(
            re.search(r":public (?:sub )?key packet:", packet_text)
        ),
        "hidden_keyids": any(set(keyid) == {"0"} for keyid in keyids),
    }


def _import_summary(status: list[StatusEvent]) -> dict[str, Any]:
    imported = [
        ev.args[1].upper()
        for ev in status
        if ev.keyword == "IMPORT_OK" and len(ev.args) > 1 and ev.args[1] != "-"
    ]
    res = next((ev.args for ev in status if ev.keyword == "IMPORT_RES"), [])
    problems = [ev.raw for ev in status if ev.keyword in {"IMPORT_PROBLEM", "NODATA"}]
    return {
        "imported_fingerprints": imported,
        "imported": bool(imported),
        "counts": res,
        "problems": problems,
    }


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------

class Gpg:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.home = policy.gnupg_home
        self.gpg = secure_binary("gpg")
        self.gpgconf = secure_binary("gpgconf", required=False)
        self.env = _base_env(self.home)
        self._lock = asyncio.Lock()
        self._proc_all: bool | None = None

    # -- process plumbing ---------------------------------------------------

    def _base_args(self) -> list[str]:
        return [
            self.gpg or "gpg",
            "--batch",
            "--no-tty",
            "--no-options",
            "--pinentry-mode",
            "ask",
            "--no-auto-check-trustdb",
            "--no-auto-key-retrieve",
            "--no-auto-key-import",
            "--no-auto-key-locate",
            "--no-encrypt-to",
            "--no-comments",
            "--no-emit-version",
        ]

    async def _read_capped(
        self, stream: asyncio.StreamReader | None, limit: int
    ) -> bytes:
        if stream is None:
            return b""
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise OutputLimitError(f"gpg output exceeded the {limit} byte limit")
            chunks.append(chunk)
        return b"".join(chunks)

    async def run(
        self,
        args: Iterable[str],
        *,
        input_data: bytes | None = None,
        files: dict[str, bytes] | None = None,
        timeout: int | None = None,
        check: bool = True,
        use_status: bool = True,
        home: Path | None = None,
    ) -> GpgResult:
        target_home = home or self.home
        target_env = self.env if home is None else _base_env(target_home)
        assert_keyring_permissions(target_home)
        async with self._lock:
            tmp = Path(tempfile.mkdtemp(prefix="gpg-mcp-"))
            os.chmod(tmp, 0o700)
            try:
                if files:
                    for name, data in files.items():
                        if Path(name).name != name:
                            raise InputError("internal temp file name is invalid")
                        _write_private(tmp / name, data)
                status_path = tmp / "status"
                argv = self._base_args()
                if use_status:
                    argv += ["--status-file", str(status_path)]
                argv += [a.replace(_TMP, str(tmp)) for a in args]

                started = time.monotonic()
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    stdin=asyncio.subprocess.PIPE
                    if input_data is not None
                    else asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=target_env,
                    start_new_session=True,
                )
                stdout_task = asyncio.create_task(
                    self._read_capped(proc.stdout, self.policy.max_output_bytes)
                )
                stderr_task = asyncio.create_task(
                    self._read_capped(proc.stderr, 256 * 1024)
                )
                tasks = [stdout_task, stderr_task]
                if input_data is not None:

                    async def feed() -> None:
                        assert proc.stdin is not None
                        try:
                            proc.stdin.write(input_data)
                            await proc.stdin.drain()
                        finally:
                            proc.stdin.close()

                    tasks.append(asyncio.create_task(feed()))

                limit = timeout if timeout is not None else self.policy.timeout_s
                try:
                    await asyncio.wait_for(asyncio.gather(*tasks), timeout=limit)
                except TimeoutError:
                    _kill_group(proc)
                    await proc.wait()
                    raise TimeoutError_(f"gpg timed out after {limit}s") from None
                except BaseException:
                    _kill_group(proc)
                    await proc.wait()
                    raise
                finally:
                    for task in tasks:
                        task.cancel()

                returncode = await proc.wait()
                stdout = stdout_task.result() if stdout_task.done() else b""
                stderr = (
                    stderr_task.result().decode("utf-8", errors="replace")
                    if stderr_task.done()
                    else ""
                )
                status_text = ""
                if use_status and status_path.exists():
                    status_text = read_status_file(
                        status_path, self.policy.max_status_bytes
                    )
                result = GpgResult(
                    argv=[redact(a) for a in argv],
                    returncode=returncode,
                    stdout=stdout,
                    stderr=redact(stderr),
                    status=parse_status(status_text),
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
                if check and returncode != 0:
                    raise self._execution_error(result)
                if contains_secret_material(result.text) or contains_secret_material(stderr):
                    raise GpgMcpError(
                        "gpg produced secret key material; output was blocked",
                        code="secret_material_blocked",
                    )
                return result
            finally:
                shutil.rmtree(tmp, ignore_errors=True)

    def _execution_error(self, result: GpgResult) -> GpgExecutionError:
        messages = [
            ev.raw
            for ev in result.status
            if ev.keyword in {"ERROR", "FAILURE", "BAD_PASSPHRASE", "MISSING_PASSPHRASE", "NODATA"}
        ]
        detail = "; ".join(messages) or result.stderr.strip().splitlines()[-1:] or ""
        if isinstance(detail, list):
            detail = "; ".join(detail)
        return GpgExecutionError(
            f"gpg exited with status {result.returncode}",
            returncode=result.returncode,
            stderr=detail,
            status=result.status_dict(),
        )

    async def run_tool(
        self,
        binary: str,
        args: Iterable[str],
        *,
        timeout: int = 15,
        home: Path | None = None,
    ) -> tuple[int, bytes, str]:
        env = self.env if home is None else _base_env(home)
        proc = await asyncio.create_subprocess_exec(
            binary,
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            start_new_session=True,
        )
        stdout_task = asyncio.create_task(
            self._read_capped(proc.stdout, _TOOL_OUTPUT_LIMIT)
        )
        stderr_task = asyncio.create_task(
            self._read_capped(proc.stderr, _TOOL_OUTPUT_LIMIT)
        )
        tasks = [stdout_task, stderr_task]
        try:
            await asyncio.wait_for(asyncio.gather(*tasks), timeout=timeout)
        except TimeoutError:
            _kill_group(proc)
            await proc.wait()
            raise TimeoutError_(f"{Path(binary).name} timed out") from None
        except BaseException:
            _kill_group(proc)
            await proc.wait()
            raise
        finally:
            for task in tasks:
                task.cancel()
        returncode = await proc.wait()
        out = stdout_task.result() if stdout_task.done() else b""
        err = stderr_task.result() if stderr_task.done() else b""
        return returncode, out, redact(err.decode("utf-8", errors="replace"))

    async def _supports_proc_all_sigs(self) -> bool:
        if self._proc_all is None:
            try:
                rc, out, _ = await self.run_tool(
                    self.gpg or "gpg", ["--dump-options"]
                )
                self._proc_all = rc == 0 and b"--proc-all-sigs" in out
            except Exception:  # noqa: BLE001 - fall back to single-signature behavior
                self._proc_all = False
        return self._proc_all

    # -- version / doctor ---------------------------------------------------

    async def version(self) -> dict[str, Any]:
        rc, out, err = await self.run_tool(self.gpg or "gpg", ["--version"])
        if rc != 0:
            raise GpgMcpError(f"gpg --version failed: {err}")
        text = out.decode("utf-8", errors="replace")
        first = text.splitlines()[0] if text else "unknown"
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", first)
        if not match:
            raise GpgMcpError("could not determine the gpg version")
        ver = tuple(int(x) for x in match.groups())
        if ver[:2] < MIN_GPG:
            raise GpgMcpError(
                f"gpg {'.'.join(map(str, ver))} is too old; need >= {'.'.join(map(str, MIN_GPG))}"
            )
        return {"version": ".".join(map(str, ver)), "banner": first, "raw": text}

    async def doctor(self) -> dict[str, Any]:
        checks: dict[str, Any] = {}
        try:
            checks["version"] = await self.version()
            checks["version"]["ok"] = True
        except Exception as exc:  # noqa: BLE001 - doctor reports failures
            checks["version"] = {"ok": False, "error": str(exc)}
        try:
            assert_keyring_permissions(self.home)
            checks["keyring"] = {"ok": True, "path": str(self.home)}
        except Exception as exc:  # noqa: BLE001
            checks["keyring"] = {"ok": False, "path": str(self.home), "error": str(exc)}
        checks["gpg"] = {"path": self.gpg, "ok": bool(self.gpg)}
        checks["gpgconf"] = {"path": self.gpgconf, "ok": bool(self.gpgconf)}
        try:
            assert_config_parent(self.policy.config_path)
            assert_config_file(self.policy.config_path)
            checks["config"] = {"path": str(self.policy.config_path), "ok": True}
        except Exception as exc:  # noqa: BLE001
            checks["config"] = {
                "path": str(self.policy.config_path),
                "ok": False,
                "error": str(exc),
            }
        checks["approval"] = self.policy.approval
        checks["destructive_confirmation"] = self.policy.destructive_confirmation
        checks["allow_test_mode"] = self.policy.allow_test_mode
        checks["audit_required"] = self.policy.audit_required
        checks["network"] = self.policy.enable_network
        checks["symmetric"] = self.policy.enable_symmetric
        checks["dedicated_home"] = self.policy.dedicated_home
        return checks

    # -- key listing --------------------------------------------------------

    async def list_keys(
        self,
        *,
        secret: bool = False,
        with_sigs: bool = False,
        query: str | None = None,
    ) -> list[dict[str, Any]]:
        if secret and with_sigs:
            raise InputError("with_sigs is not available for secret key listings")
        command = "--list-secret-keys" if secret else ("--check-signatures" if with_sigs else "--list-keys")
        result = await self.run(
            [command, "--with-colons", "--with-fingerprint", "--with-fingerprint"],
            check=False,
            use_status=False,
        )
        if result.returncode not in (0, 2):
            raise self._execution_error(result)
        keys = parse_colon_keys(result.text)
        if secret:
            for key in keys:
                key["secret"] = True
        if query:
            needle = query.casefold()
            keys = [
                key
                for key in keys
                if needle in (key.get("fingerprint") or "").casefold()
                or needle in (key.get("key_id") or "").casefold()
                or any(needle in item["uid"].casefold() for item in key["uids"])
            ]
        return keys

    async def get_key(self, fingerprint: str, *, with_sigs: bool = False) -> dict[str, Any]:
        fpr = require_fingerprint(fingerprint)
        keys = await self.list_keys(with_sigs=with_sigs)
        for key in keys:
            if key.get("fingerprint") == fpr:
                secret = await self.list_keys(secret=True)
                key["secret_available"] = any(
                    item.get("fingerprint") == fpr for item in secret
                )
                return key
        raise GpgMcpError(f"key not found: {fpr}", code="key_not_found")

    async def export_public_key(self, fingerprint: str, *, armor: bool = True) -> dict[str, Any]:
        fpr = require_fingerprint(fingerprint)
        args = ["--export", fpr]
        if armor:
            args.insert(0, "--armor")
        result = await self.run(args, use_status=False)
        if not result.stdout:
            raise GpgMcpError(f"key not found: {fpr}", code="key_not_found")
        return {"fingerprint": fpr, "armor": armor, **encode_payload(result.stdout)}

    async def export_ssh_key(self, fingerprint: str) -> dict[str, Any]:
        fpr = require_fingerprint(fingerprint)
        result = await self.run(["--export-ssh-key", fpr], use_status=False)
        return {"fingerprint": fpr, "ssh_key": result.text.strip()}

    # -- inspection ---------------------------------------------------------

    async def _list_packets(self, data: bytes) -> tuple[int, str]:
        result = await self.run(
            ["--list-packets"], input_data=data, check=False, use_status=False
        )
        return result.returncode, result.text

    async def inspect(self, data: bytes, *, packets: bool = False) -> dict[str, Any]:
        if contains_secret_material(data.decode("utf-8", errors="ignore")):
            raise PolicyError("secret key material is not accepted by this tool")
        rc, packet_text = await self._list_packets(data)
        packet_text = sanitize_text(packet_text, limit=50_000)
        if re.search(r":secret (?:sub )?key packet:", packet_text):
            raise PolicyError("secret key material is not accepted by this tool")
        if packets:
            return {"packets": packet_text, "format": "packets"}
        show = await self.run(
            ["--show-keys", "--with-colons"], input_data=data, check=False, use_status=False
        )
        keys = parse_colon_keys(show.text)
        if not keys:
            if rc != 0:
                raise GpgMcpError("input is not valid OpenPGP data", code="invalid_data")
            return {"keys": [], "packets": packet_text}
        return {"keys": keys, "packets": packet_text if rc == 0 else None}

    async def inspect_recipients(self, ciphertext: bytes) -> dict[str, Any]:
        rc, text = await self._list_packets(ciphertext)
        parsed = parse_recipient_packets(text)
        return {
            **parsed,
            "exit_code": rc,
        }

    # -- verify -------------------------------------------------------------

    async def _signature_packets(self, signature: bytes) -> list[bytes]:
        """Split a detached signature into individual signature packets."""
        data = signature
        if data.lstrip().startswith(b"-----BEGIN PGP SIGNATURE-----"):
            dearmored = await self.run(
                ["--dearmor"], input_data=data, check=False, use_status=False
            )
            if dearmored.returncode != 0 or not dearmored.stdout:
                return [signature]
            data = dearmored.stdout
        listing = await self.run(
            ["--list-packets"], input_data=data, check=False, use_status=False
        )
        offsets = sorted(
            {
                int(match.group(1))
                for line in listing.text.splitlines()
                if (match := re.match(r"# off=(\d+) ctb=\S+ tag=2\b", line))
            }
        )
        if len(offsets) <= 1:
            return [data]
        return [
            data[start : offsets[index + 1] if index + 1 < len(offsets) else len(data)]
            for index, start in enumerate(offsets)
        ]

    async def _verify_detached_individually(
        self, data: bytes, signature: bytes
    ) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        codes: list[int] = []
        for packet in await self._signature_packets(signature):
            result = await self.run(
                ["--verify", f"{_TMP}/sig", "-"],
                input_data=data,
                files={"sig": packet},
                check=False,
            )
            results.append(_verify_one(result.status))
            codes.append(result.returncode)
        aggregate = _aggregate_verification_results(results)
        aggregate["gpg_exit_code"] = next((code for code in codes if code != 0), 0)
        if aggregate["gpg_exit_code"] != 0:
            aggregate["policy_acceptable"] = False
            aggregate["valid"] = False
        return aggregate

    async def verify(
        self,
        data: bytes,
        *,
        signature: bytes | None = None,
        mode: str = "detached",
    ) -> dict[str, Any]:
        if mode not in {"detached", "cleartext", "inline"}:
            raise InputError("mode must be detached, cleartext or inline")
        args: list[str] = []
        supports_all = await self._supports_proc_all_sigs()
        if supports_all:
            args.append("--proc-all-sigs")
        if mode == "detached":
            if signature is None:
                raise InputError("signature is required for detached verification")
            if not supports_all:
                info = await self._verify_detached_individually(data, signature)
                info["mode"] = mode
                return info
            result = await self.run(
                [*args, "--verify", f"{_TMP}/sig", "-"],
                input_data=data,
                files={"sig": signature},
                check=False,
            )
        else:
            result = await self.run([*args, "--verify", "-"], input_data=data, check=False)
        info = _verification(result.status)
        info["gpg_exit_code"] = result.returncode
        if result.returncode != 0:
            info["policy_acceptable"] = False
            info["valid"] = False
        info["mode"] = mode
        return info

    # -- sign ---------------------------------------------------------------

    async def sign(
        self,
        data: bytes,
        *,
        signer: str,
        mode: str = "detached",
        armor: bool = True,
        hash_algo: str = "SHA256",
    ) -> dict[str, Any]:
        if mode not in {"detached", "cleartext", "inline"}:
            raise InputError("mode must be detached, cleartext or inline")
        fpr = assert_sign_key_allowed(self.policy, signer)
        key = await self.get_key(fpr)
        usable_signer = (
            (key["capabilities"]["sign"] and _usable(key))
            or any(sub["capabilities"]["sign"] and _usable(sub) for sub in key["subkeys"])
        )
        if not usable_signer:
            raise PolicyError("signing key has no usable signing capability")
        algo = validate_hash_algo(hash_algo)
        args: list[str] = []
        if mode == "detached":
            args = ["--detach-sign"]
            if armor:
                args.insert(0, "--armor")
        elif mode == "cleartext":
            args = ["--clearsign"]
        else:
            args = ["--sign"]
            if armor:
                args.insert(0, "--armor")
        args += ["--local-user", fpr, "--digest-algo", algo]
        result = await self.run(args, input_data=data)
        created = result.first("SIG_CREATED")
        meta: dict[str, Any] = {
            "signer_fingerprint": fpr,
            "mode": mode,
            "armor": armor or mode == "cleartext",
            "hash_algo": algo,
            "signature": encode_payload(result.stdout),
        }
        if created and len(created.args) >= 6:
            meta["signature_type"] = created.args[0]
            meta["signature_class"] = created.args[3]
            meta["created_at"] = _iso(created.args[4])
            meta["hash_algo"] = _hash_name(created.args[2])
        return meta

    # -- encryption ---------------------------------------------------------

    async def _public_key_for(self, fingerprint: str) -> dict[str, Any]:
        fpr = require_fingerprint(fingerprint)
        keys = await self.list_keys()
        for key in keys:
            if key.get("fingerprint") == fpr:
                return key
        raise GpgMcpError(f"recipient key not found: {fpr}", code="key_not_found")

    @staticmethod
    def _can_encrypt(key: dict[str, Any]) -> bool:
        if not _usable(key):
            return False
        if key["capabilities"]["encrypt"]:
            return True
        return any(
            sub["capabilities"]["encrypt"] and _usable(sub) for sub in key["subkeys"]
        )

    async def encrypt(
        self,
        data: bytes,
        *,
        recipients: list[str],
        sign_with: str | None = None,
        armor: bool = True,
    ) -> dict[str, Any]:
        if not recipients:
            raise InputError("at least one recipient fingerprint is required")
        if len(recipients) > 20:
            raise InputError("at most 20 recipients are allowed")
        resolved: list[str] = []
        for recipient in recipients:
            fpr = assert_recipient_allowed(self.policy, recipient)
            key = await self._public_key_for(fpr)
            if not _usable(key):
                raise PolicyError(f"recipient key is {key['validity']}: {fpr}")
            if not self._can_encrypt(key):
                raise PolicyError(f"recipient has no usable encryption key: {fpr}")
            if fpr not in resolved:
                resolved.append(fpr)
        args: list[str] = []
        if sign_with:
            signer = assert_sign_key_allowed(self.policy, sign_with)
            signer_key = await self.get_key(signer)
            usable_signer = (
                (signer_key["capabilities"]["sign"] and _usable(signer_key))
                or any(
                    sub["capabilities"]["sign"] and _usable(sub)
                    for sub in signer_key["subkeys"]
                )
            )
            if not usable_signer:
                raise PolicyError("signing key has no usable signing capability")
            args += ["--sign", "--local-user", signer]
        args += ["--encrypt", "--trust-model", "always"]
        for fpr in resolved:
            args += ["--recipient", fpr]
        if armor:
            args.insert(0, "--armor")
        result = await self.run(args, input_data=data)
        return {
            "recipients": resolved,
            "signed_by": sign_with.upper() if sign_with else None,
            "armor": armor,
            "ciphertext": encode_payload(result.stdout),
        }

    async def sign_and_encrypt(
        self,
        data: bytes,
        *,
        recipients: list[str],
        signer: str,
        armor: bool = True,
    ) -> dict[str, Any]:
        return await self.encrypt(
            data, recipients=recipients, sign_with=signer, armor=armor
        )

    # -- decryption ---------------------------------------------------------

    async def _allowed_decrypt_keyids(
        self, expected_key: str | None
    ) -> tuple[set[str], list[str]]:
        if expected_key:
            fpr = assert_decrypt_key_allowed(self.policy, expected_key)
            wanted = [fpr]
        elif self.policy.allowed_decrypt_keys:
            wanted = list(self.policy.allowed_decrypt_keys)
        elif self.policy.dedicated_home:
            wanted = [
                key["fingerprint"]
                for key in await self.list_keys(secret=True)
                if key.get("fingerprint")
            ]
            if not wanted:
                raise PolicyError("no secret keys are available in the dedicated keyring")
        else:
            raise PolicyError(
                "allowed_decrypt_keys is empty and the shared ~/.gnupg keyring is in use"
            )
        secret = await self.list_keys(secret=True)
        keyids: set[str] = set()
        for key in secret:
            if key.get("fingerprint") in wanted:
                for item in [key, *key["subkeys"]]:
                    if (
                        item.get("key_id")
                        and item["capabilities"]["encrypt"]
                        and _usable(item)
                    ):
                        keyids.add(item["key_id"].upper())
        if not keyids:
            raise PolicyError("no matching usable secret key is available for decryption")
        return keyids, wanted

    def _check_decryption_key(
        self,
        status: list[StatusEvent],
        wanted: list[str],
    ) -> list[dict[str, Any]]:
        allowed = {fpr.upper() for fpr in wanted}
        used = [
            event
            for event in status
            if event.keyword == "DECRYPTION_KEY" and len(event.args) >= 2
        ]
        if not used:
            raise GpgMcpError(
                "gpg did not report which public key performed decryption; "
                "decrypt() refuses a symmetric fallback",
                code="decryption_key_unknown",
            )
        actual: list[dict[str, Any]] = []
        for event in used:
            fingerprint = event.args[0].upper()
            primary = event.args[1].upper()
            if fingerprint not in allowed and primary not in allowed:
                raise PolicyError(
                    "decryption used a key outside the allow-list: "
                    f"{primary} ({fingerprint})"
                )
            actual.append(
                {
                    "fingerprint": fingerprint,
                    "primary_fingerprint": primary,
                    "ownertrust": event.args[2] if len(event.args) > 2 else None,
                }
            )
        return actual

    async def decrypt(
        self,
        ciphertext: bytes,
        *,
        verify: bool = True,
        expected_key: str | None = None,
    ) -> dict[str, Any]:
        preflight = await self.inspect_recipients(ciphertext)
        if not preflight["encrypted"]:
            raise GpgMcpError("input is not an encrypted message", code="not_encrypted")
        if preflight["symmetric"] and not preflight["public_key_ids"]:
            raise PolicyError(
                "symmetric-only ciphertext must use symmetric_decrypt"
            )
        allowed_keyids, wanted = await self._allowed_decrypt_keyids(expected_key)
        all_keyids = preflight["public_key_ids"]
        hidden = [kid for kid in all_keyids if set(kid) == {"0"}]
        visible = [kid for kid in all_keyids if set(kid) != {"0"}]
        if hidden and not self.policy.allow_hidden_recipients:
            raise PolicyError(
                "ciphertext contains hidden recipients; set allow_hidden_recipients "
                "to permit this"
            )
        extra: list[str] = []
        if visible:
            extra = [
                kid
                for kid in visible
                if kid.upper() not in allowed_keyids
                and kid.upper()[-16:] not in allowed_keyids
            ]
            matched = any(
                kid.upper() in allowed_keyids or kid.upper()[-16:] in allowed_keyids
                for kid in visible
            )
            if not matched:
                raise PolicyError(
                    "ciphertext is not addressed to an allowed decryption key"
                )
        result = await self.run(
            ["--decrypt", "--no-symkey-cache"], input_data=ciphertext, check=False
        )
        status = result.status
        decryption_ok = any(ev.keyword == "DECRYPTION_OKAY" for ev in status)
        bad_mdc = any(ev.keyword == "BADMDC" for ev in status)
        if bad_mdc or not decryption_ok:
            raise self._execution_error(result)
        actual_keys = self._check_decryption_key(status, wanted)
        sig = _verification(status)
        has_signature = sig["status"] not in {"UNKNOWN", None}
        if verify and has_signature and not sig["valid"]:
            raise GpgMcpError(
                "refusing to return plaintext with an invalid embedded signature",
                code="bad_signature",
                data={"signature": sig},
            )
        payload: dict[str, Any] = {
            "plaintext": encode_payload(result.stdout),
            "decryption_keys": [
                item["primary_fingerprint"] for item in actual_keys
            ],
            "allowed_keys": wanted,
            "actual_keys": actual_keys,
            "recipients": visible,
            "extra_recipients": extra,
            "signed": has_signature,
            "signature": sig if has_signature else None,
        }
        if extra:
            payload["warning"] = (
                "ciphertext is also addressed to recipients outside the allowed set"
            )
        return payload

    # -- symmetric ----------------------------------------------------------

    def _require_symmetric(self) -> None:
        if not self.policy.enable_symmetric:
            raise PolicyError("symmetric encryption is disabled by configuration")

    async def symmetric_encrypt(self, data: bytes, *, armor: bool = True) -> dict[str, Any]:
        self._require_symmetric()
        args = ["--symmetric", "--no-symkey-cache", "--cipher-algo", "AES256"]
        if armor:
            args.insert(0, "--armor")
        result = await self.run(args, input_data=data)
        return {"armor": armor, "ciphertext": encode_payload(result.stdout)}

    async def symmetric_decrypt(
        self, ciphertext: bytes, *, verify: bool = True
    ) -> dict[str, Any]:
        self._require_symmetric()
        preflight = await self.inspect_recipients(ciphertext)
        if not preflight["symmetric"]:
            raise GpgMcpError("input is not a symmetrically encrypted message", code="not_symmetric")
        if preflight["public_key_ids"]:
            raise PolicyError(
                "symmetric_decrypt requires symmetric-only ciphertext; "
                "use decrypt for hybrid public-key/symmetric messages"
            )
        result = await self.run(
            ["--decrypt", "--no-symkey-cache"], input_data=ciphertext, check=False
        )
        if any(ev.keyword in {"DECRYPTION_FAILED", "BADMDC", "ERROR", "FAILURE"} for ev in result.status):
            raise self._execution_error(result)
        if result.returncode != 0 and not any(
            ev.keyword == "DECRYPTION_OKAY" for ev in result.status
        ):
            raise self._execution_error(result)
        sig = _verification(result.status)
        has_signature = sig["status"] not in {"UNKNOWN", None}
        if verify and has_signature and not sig["valid"]:
            raise GpgMcpError(
                "refusing to return plaintext with an invalid embedded signature",
                code="bad_signature",
                data={"signature": sig},
            )
        return {
            "plaintext": encode_payload(result.stdout),
            "signed": has_signature,
            "signature": sig if has_signature else None,
        }

    # -- import -------------------------------------------------------------

    async def inspect_import_keys(self, key_data: bytes) -> dict[str, Any]:
        """Validate public-key material and return the identities it carries.

        Secret-key packets and any revocation signature are rejected. Full key
        revocations must use the dedicated import_revocation path.
        """
        if contains_secret_material(key_data.decode("utf-8", errors="ignore")):
            raise PolicyError("secret key material is never imported through gpg-mcp")
        _, packet_text = await self._list_packets(key_data)
        if re.search(r":secret (?:sub )?key packet:", packet_text):
            raise PolicyError("secret key material is never imported through gpg-mcp")
        info = revocation_packet_info(packet_text)
        if info["has_any_revocation_signature"]:
            raise PolicyError(
                "revocation signatures must be imported with import_revocation"
            )
        show = await self.run(
            ["--show-keys", "--with-colons"],
            input_data=key_data,
            check=False,
            use_status=False,
        )
        keys = parse_colon_keys(show.text)
        if not keys:
            raise GpgMcpError(
                "input does not contain a usable public key", code="invalid_key"
            )
        return {
            "keys": keys,
            "fingerprints": [
                key["fingerprint"] for key in keys if key.get("fingerprint")
            ],
        }

    async def import_public_key(self, key_data: bytes) -> dict[str, Any]:
        await self.inspect_import_keys(key_data)
        result = await self.run(["--import"], input_data=key_data, check=False)
        summary = _import_summary(result.status)
        outcome = import_result(result, summary)
        if outcome["status"] == "failed":
            raise self._execution_error(result)
        return outcome

    # -- key management -----------------------------------------------------

    def _key_params(
        self,
        uid: str,
        algo: str,
        expire: str,
        protect: bool,
        subkey_algo: str,
    ) -> str:
        lines: list[str] = []
        if algo in {"future-default", "default"}:
            lines += ["Key-Type: default", "Subkey-Type: default"]
        elif algo == "ed25519":
            lines += [
                "Key-Type: eddsa",
                "Key-Curve: ed25519",
                "Key-Usage: cert,sign",
                "Subkey-Type: ecdh",
                "Subkey-Curve: cv25519",
                "Subkey-Usage: encrypt",
            ]
        else:
            bits = algo.removeprefix("rsa")
            lines += [
                "Key-Type: RSA",
                f"Key-Length: {bits}",
                "Key-Usage: cert,sign",
            ]
            if subkey_algo == "cv25519":
                lines += [
                    "Subkey-Type: ecdh",
                    "Subkey-Curve: cv25519",
                    "Subkey-Usage: encrypt",
                ]
            else:
                sub_bits = (
                    bits if subkey_algo == "default" else subkey_algo.removeprefix("rsa")
                )
                lines += [
                    "Subkey-Type: RSA",
                    f"Subkey-Length: {sub_bits}",
                    "Subkey-Usage: encrypt",
                ]
        match = re.match(r"^\s*(.*?)\s*<([^<>\s]+@[^<>\s]+)>\s*$", uid)
        if match:
            name = match.group(1).strip() or match.group(2)
            lines += [f"Name-Real: {name}", f"Name-Email: {match.group(2).strip()}"]
        else:
            lines.append(f"Name-Real: {uid}")
        lines.append(f"Expire-Date: {expire}")
        if not protect:
            lines.append("%no-protection")
        lines.append("%commit")
        return "\n".join(lines) + "\n"

    async def create_key(
        self,
        *,
        uid: str,
        algo: str = "ed25519",
        expire: str = "2y",
        protect: bool = True,
        subkey_algo: str = "cv25519",
    ) -> dict[str, Any]:
        uid = validate_uid(uid)
        algo, subkey_algo = validate_key_algorithms(algo, subkey_algo)
        expire = validate_expire(expire)
        if not protect and not self.policy.allow_unprotected_keys:
            raise PolicyError(
                "unprotected keys are disabled; set allow_unprotected_keys=true only "
                "for disposable test keyrings"
            )
        before = {
            key["fingerprint"]
            for key in await self.list_keys(secret=True)
            if key.get("fingerprint")
        }
        params = self._key_params(uid, algo, expire, protect, subkey_algo)
        result = await self.run(
            ["--generate-key", f"{_TMP}/keyparams"],
            files={"keyparams": params.encode("utf-8")},
            timeout=self.policy.keygen_timeout_s,
        )
        fpr = _created_key(result.status)
        if not fpr:
            after = await self.list_keys(secret=True)
            new = [
                key["fingerprint"]
                for key in after
                if key.get("fingerprint") and key["fingerprint"] not in before
            ]
            if len(new) != 1:
                raise GpgMcpError(
                    "key was generated but its fingerprint could not be determined"
                )
            fpr = new[0]
        key = await self.get_key(fpr)
        return {
            "fingerprint": fpr,
            "uid": uid,
            "algorithm": algo,
            "expire": expire,
            "protected": protect,
            "requested_subkey_algo": subkey_algo,
            "generated": {
                "primary": key["algorithm"],
                "subkeys": [subkey["algorithm"] for subkey in key["subkeys"]],
            },
            "key": key,
        }

    async def add_subkey(
        self, fingerprint: str, *, algo: str = "cv25519", expire: str = "2y", usage: str = "default"
    ) -> dict[str, Any]:
        fpr = assert_manage_key_allowed(self.policy, fingerprint)
        algo = validate_subkey_algo(algo)
        expire = validate_expire(expire)
        if usage not in {"default", "sign", "encr", "auth"}:
            raise InputError("usage must be default, sign, encr or auth")
        derived = usage
        if derived == "default":
            derived = "sign" if algo == "ed25519" else "encr"
        result = await self.run(
            ["--quick-add-key", fpr, algo, derived, expire],
            timeout=self.policy.keygen_timeout_s,
        )
        return {
            "fingerprint": fpr,
            "subkey_fingerprint": _created_key(result.status),
            "algo": algo,
            "usage": derived,
            "expire": expire,
        }

    async def add_uid(self, fingerprint: str, uid: str) -> dict[str, Any]:
        fpr = assert_manage_key_allowed(self.policy, fingerprint)
        uid = validate_uid(uid)
        await self.run(["--quick-add-uid", fpr, uid])
        return {"fingerprint": fpr, "uid": uid, "updated": True}

    async def set_expiry(
        self, fingerprint: str, *, expire: str, subkeys: bool = False
    ) -> dict[str, Any]:
        fpr = assert_manage_key_allowed(self.policy, fingerprint)
        expire = validate_expire(expire)
        args = ["--quick-set-expire", fpr, expire]
        if subkeys:
            args.append("*")
        await self.run(args)
        return {"fingerprint": fpr, "expire": expire, "subkeys": subkeys, "updated": True}

    async def change_passphrase(self, fingerprint: str) -> dict[str, Any]:
        fpr = assert_manage_key_allowed(self.policy, fingerprint)
        await self.run(
            ["--change-passphrase", fpr], timeout=self.policy.keygen_timeout_s
        )
        return {"fingerprint": fpr, "updated": True, "passphrase_source": "pinentry"}

    async def delete_key(self, fingerprint: str, *, secret: bool = False) -> dict[str, Any]:
        fpr = assert_manage_key_allowed(self.policy, fingerprint)
        if secret:
            await self.run(["--yes", "--delete-secret-keys", fpr])
            await self.run(["--yes", "--delete-keys", fpr])
        else:
            await self.run(["--yes", "--delete-keys", fpr])
        return {"fingerprint": fpr, "secret_deleted": secret, "deleted": True}

    async def set_ownertrust(self, fingerprint: str, level: str) -> dict[str, Any]:
        fpr = assert_manage_key_allowed(self.policy, fingerprint)
        level = validate_ownertrust(level)
        code = {"never": 2, "marginal": 3, "full": 4}[level]
        await self.run(
            ["--import-ownertrust"], input_data=f"{fpr}:{code}:\n".encode("ascii")
        )
        return {"fingerprint": fpr, "ownertrust": level, "updated": True}

    def _revocation_path(self, fingerprint: str) -> Path:
        directory = self.home / "openpgp-revocs.d"
        for name in (f"{fingerprint}.rev", f"{fingerprint.lower()}.rev"):
            candidate = directory / name
            if candidate.exists():
                return candidate
        raise GpgMcpError(
            "no revocation certificate was found in openpgp-revocs.d; "
            "generate one out-of-band with 'gpg --gen-revoke'",
            code="revocation_not_found",
        )

    async def _resolve_revocation_issuer(self, packet_info: dict[str, Any]) -> str:
        issuers = packet_info["issuer_fingerprints"]
        if len(issuers) == 1:
            return next(iter(issuers))
        if len(issuers) > 1:
            raise PolicyError("revocation certificate names multiple issuers")
        keyids = {keyid for keyid in packet_info["keyids"] if set(keyid) != {"0"}}
        if not keyids:
            raise PolicyError("revocation certificate does not identify an issuer")
        matches: set[str] = set()
        for key in await self.list_keys():
            for item in [key, *key["subkeys"]]:
                if item.get("key_id") in keyids and key.get("fingerprint"):
                    matches.add(key["fingerprint"])
        if len(matches) != 1:
            raise PolicyError("could not resolve a unique issuer for the revocation certificate")
        return next(iter(matches))

    async def inspect_revocation(
        self, certificate: bytes, *, expected_fingerprint: str | None = None
    ) -> dict[str, Any]:
        """Validate a revocation certificate without touching the real keyring.

        The certificate is verified against the target public key in an
        ephemeral keyring. This rejects secret keys, unrelated public keys,
        certificates for another key, and certificates that do not revoke the
        target. The returned ``certificate`` is normalized and safe to import.
        """
        if contains_secret_material(certificate.decode("utf-8", errors="ignore")):
            raise PolicyError("secret key material is not accepted")
        text = certificate.decode("utf-8", errors="ignore")
        if "-----BEGIN PGP PUBLIC KEY BLOCK-----" in text:
            normalized = clean_revocation_certificate(text)
            if not normalized.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----"):
                raise PolicyError("could not extract an armored revocation certificate")
            certificate = normalized.encode("utf-8")
        _, packet_text = await self._list_packets(certificate)
        if re.search(r":secret (?:sub )?key packet:", packet_text):
            raise PolicyError("secret key material is not accepted")
        info = revocation_packet_info(packet_text)
        if not info["has_revocation_signature"]:
            raise PolicyError("input does not contain a revocation signature")
        if info["hidden_keyids"]:
            raise PolicyError("revocation certificate hides its issuer")
        issuer = await self._resolve_revocation_issuer(info)
        if expected_fingerprint:
            expected = require_fingerprint(expected_fingerprint)
            if issuer != expected:
                raise PolicyError(
                    f"certificate targets {issuer}, not the requested {expected}"
                )
        key = await self.get_key(issuer)
        uids = key["uids"]

        temp_home = Path(tempfile.mkdtemp(prefix="gpg-mcp-revocation-"))
        os.chmod(temp_home, 0o700)
        try:
            exported = await self.run(["--armor", "--export", issuer], use_status=False)
            if not exported.stdout:
                raise PolicyError("target key is not present in the keyring")
            await self.run(["--import"], input_data=exported.stdout, home=temp_home)
            imported = await self.run(
                ["--import"], input_data=certificate, home=temp_home, check=False
            )
            summary = _import_summary(imported.status)
            if imported.returncode != 0 and not summary["imported"]:
                raise GpgMcpError(
                    "revocation certificate could not be applied to the target key",
                    detail=imported.stderr,
                )
            listing = await self.run(
                ["--with-colons", "--list-keys"],
                home=temp_home,
                check=False,
                use_status=False,
            )
            temp_keys = parse_colon_keys(listing.text)
            if len(temp_keys) != 1:
                raise PolicyError(
                    "certificate does not target exactly the requested key"
                )
            temp_key = temp_keys[0]
            if temp_key.get("fingerprint") != issuer:
                raise PolicyError("certificate targets a different key")
            if temp_key.get("validity") != "revoked":
                raise PolicyError("certificate does not revoke the target key")
            return {
                "fingerprint": issuer,
                "uid": uids[0]["uid"] if uids else None,
                "uids": uids,
                "revoked": True,
                "certificate": certificate,
                "import_summary": summary,
            }
        finally:
            if self.gpgconf:
                with contextlib.suppress(Exception):
                    await self.run_tool(
                        self.gpgconf, ["--kill", "gpg-agent"], home=temp_home
                    )
            shutil.rmtree(temp_home, ignore_errors=True)

    async def generate_revocation(self, fingerprint: str) -> dict[str, Any]:
        fpr = assert_manage_key_allowed(self.policy, fingerprint)
        path = self._revocation_path(fpr)
        cert_text = clean_revocation_certificate(path.read_text(encoding="utf-8"))
        if contains_secret_material(cert_text):
            raise GpgMcpError("revocation certificate unexpectedly contained key material")
        if not cert_text.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----"):
            raise GpgMcpError("could not extract an armored revocation certificate")
        validated = await self.inspect_revocation(
            cert_text.encode("utf-8"), expected_fingerprint=fpr
        )
        return {
            "fingerprint": fpr,
            "uid": validated["uid"],
            "revocation_certificate": cert_text,
            "warning": "This certificate can permanently revoke the key. Store it offline.",
        }

    async def import_revocation(
        self,
        certificate: bytes,
        *,
        expected_fingerprint: str | None = None,
        apply: bool = False,
    ) -> dict[str, Any]:
        validated = await self.inspect_revocation(
            certificate, expected_fingerprint=expected_fingerprint
        )
        fpr = validated["fingerprint"]
        if not apply:
            # True dry run: validation happened in an ephemeral keyring only.
            return {
                "applied": False,
                "would_revoke": True,
                "status": "validated",
                "fingerprint": fpr,
                "uid": validated["uid"],
                "uids": validated["uids"],
            }
        result = await self.run(
            ["--import"], input_data=validated["certificate"], check=False
        )
        summary = _import_summary(result.status)
        if result.returncode != 0 and not summary["imported"]:
            raise self._execution_error(result)
        after = await self.get_key(fpr)
        if after.get("validity") != "revoked":
            raise GpgMcpError(
                "revocation import returned success but the key is not revoked",
                code="revocation_not_applied",
            )
        return {
            "applied": True,
            "revoked": True,
            "fingerprint": fpr,
            "uid": validated["uid"],
            "uids": validated["uids"],
            **summary,
            "status": "complete",
            "gpg_exit_code": result.returncode,
            "imported": True,
            "revocation_imported": True,
        }

    async def revoke_key(self, fingerprint: str) -> dict[str, Any]:
        fpr = assert_manage_key_allowed(self.policy, fingerprint)
        path = self._revocation_path(fpr)
        cert = clean_revocation_certificate(path.read_text(encoding="utf-8")).encode("utf-8")
        result = await self.import_revocation(
            cert, expected_fingerprint=fpr, apply=True
        )
        return {
            "source": "openpgp-revocs.d",
            **result,
        }

    # -- network ------------------------------------------------------------

    def _require_network(self) -> None:
        if not self.policy.enable_network:
            raise PolicyError("network operations are disabled by configuration")

    async def search_keyserver(self, query: str) -> dict[str, Any]:
        self._require_network()
        query = validate_query(query)
        result = await self.run(
            ["--keyserver", self.policy.keyserver, "--search-keys", query],
            check=False,
            use_status=False,
            timeout=self.policy.timeout_s,
        )
        if result.returncode not in (0, 2) and not result.text.strip():
            raise self._execution_error(result)
        return {
            "keyserver": self.policy.keyserver,
            "query": query,
            "results": sanitize_text(result.text, limit=100_000),
            "exit_code": result.returncode,
        }

    async def fetch_key(self, fingerprint: str) -> dict[str, Any]:
        self._require_network()
        fpr = require_fingerprint(fingerprint)
        result = await self.run(
            ["--keyserver", self.policy.keyserver, "--recv-keys", fpr],
            check=False,
            timeout=self.policy.timeout_s,
        )
        summary = _import_summary(result.status)
        outcome = import_result(result, summary)
        if outcome["status"] == "failed":
            raise self._execution_error(result)
        return {"keyserver": self.policy.keyserver, **outcome}

    async def send_key(self, fingerprint: str) -> dict[str, Any]:
        self._require_network()
        fpr = require_fingerprint(fingerprint)
        result = await self.run(
            ["--keyserver", self.policy.keyserver, "--send-keys", fpr],
            check=False,
            timeout=self.policy.timeout_s,
        )
        if result.returncode != 0:
            raise self._execution_error(result)
        return {"keyserver": self.policy.keyserver, "fingerprint": fpr, "sent": True}

    # -- smartcard / agent --------------------------------------------------

    async def card_status(self) -> dict[str, Any]:
        result = await self.run(["--card-status"], check=False, use_status=False)
        text = sanitize_text(result.text, limit=20_000)
        fields: dict[str, str] = {}
        for line in text.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                fields[sanitize_text(key.strip())] = sanitize_text(value.strip())
        return {
            "present": result.returncode == 0,
            "text": text,
            "fields": fields,
            "exit_code": result.returncode,
        }

    async def agent_info(self) -> dict[str, Any]:
        version = await self.version()
        info: dict[str, Any] = {"version": version, "home": str(self.home)}
        if self.gpgconf:
            rc, out, err = await self.run_tool(self.gpgconf, ["--list-dirs"])
            if rc == 0:
                info["dirs"] = out.decode("utf-8", errors="replace").splitlines()
            else:
                info["dirs_error"] = err
            rc, out, err = await self.run_tool(
                self.gpgconf, ["--list-options", "gpg-agent"]
            )
            if rc == 0:
                wanted = {
                    "default-cache-ttl",
                    "max-cache-ttl",
                    "ignore-cache-for-signing",
                    "allow-preset-passphrase",
                    "no-allow-external-cache",
                }
                options = []
                for line in out.decode("utf-8", errors="replace").splitlines():
                    name = line.split(":", 1)[0]
                    if name in wanted:
                        options.append(line)
                info["agent_options"] = options
        return info

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from gpg_mcp.policy import reset_policy_cache
from gpg_mcp.server import reset_gpg


@dataclass
class Keyring:
    home: Path
    config: Path
    fpr: str
    fpr2: str


CONFIG = """\
gnupg_home = "{home}"
audit_log = "{base}/audit.jsonl"
approval = "none"
enable_network = false
enable_symmetric = false
allow_unprotected_keys = true
allow_hidden_recipients = false
max_input_bytes = 1048576
max_output_bytes = 2097152
timeout_s = 60
keygen_timeout_s = 120
"""

PARAMS = """\
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: cert,sign
Subkey-Type: ecdh
Subkey-Curve: cv25519
Subkey-Usage: encrypt
Name-Real: {name}
Name-Email: {email}
Expire-Date: 2y
%commit
"""


def _generate(home: Path, name: str, email: str) -> str:
    params = home.parent / f"params-{email.replace('@', '-')}"
    params.write_text(PARAMS.format(name=name, email=email), encoding="utf-8")
    env = {
        "GNUPGHOME": str(home),
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "HOME": os.environ.get("HOME", str(Path.home())),
    }
    subprocess.run(
        [shutil.which("gpg"), "--batch", "--no-tty", "--generate-key", str(params)],
        env=env,
        check=True,
        capture_output=True,
    )
    out = subprocess.run(
        [shutil.which("gpg"), "--with-colons", "--list-secret-keys"],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    blocks: list[dict] = []
    current: dict | None = None
    for line in out.splitlines():
        fields = line.split(":")
        if fields[0] == "sec":
            current = {"fpr": None, "uids": []}
            blocks.append(current)
        elif fields[0] == "fpr" and current is not None and current["fpr"] is None:
            current["fpr"] = fields[9]
        elif fields[0] == "uid" and current is not None:
            current["uids"].append(fields[9])
    for block in blocks:
        if block["fpr"] and any(email in uid for uid in block["uids"]):
            return block["fpr"]
    raise RuntimeError("test key generation produced no matching fingerprint")


@pytest.fixture(scope="session", autouse=True)
def keyring(tmp_path_factory: pytest.TempPathFactory) -> Keyring:
    base = tmp_path_factory.mktemp("gpg-mcp")
    home = base / "gnupg"
    home.mkdir(mode=0o700)
    agent_conf = home / "gpg-agent.conf"
    # A test must never pop a pinentry dialog. If a test path unexpectedly
    # needs a passphrase it fails loudly instead of blocking or prompting.
    # GPG_MCP_INTERACTIVE=1 opts into the few tests that intentionally prompt.
    pinentry = "" if os.environ.get("GPG_MCP_INTERACTIVE") else "pinentry-program /bin/false\n"
    agent_conf.write_text(
        "default-cache-ttl 1\nmax-cache-ttl 1\nignore-cache-for-signing\n"
        f"no-allow-external-cache\n{pinentry}pinentry-timeout 5\n",
        encoding="utf-8",
    )
    fpr = _generate(home, "Test One", "one@example.com")
    fpr2 = _generate(home, "Test Two", "two@example.com")
    config = base / "config.toml"
    config.write_text(CONFIG.format(home=home, base=base), encoding="utf-8")
    os.chmod(config, 0o600)
    os.environ["GPG_MCP_CONFIG"] = str(config)
    os.environ["GPG_MCP_HOME"] = str(home)
    reset_policy_cache()
    reset_gpg()
    yield Keyring(home=home, config=config, fpr=fpr, fpr2=fpr2)
    subprocess.run(
        [shutil.which("gpgconf"), "--homedir", str(home), "--kill", "gpg-agent"],
        check=False,
        capture_output=True,
    )


@pytest.fixture
def connect():
    """Return an async context manager factory.

    Creating the MCP client inside the test task avoids anyio cancel-scope
    teardown problems that occur when an async fixture is finalized in a
    different task.
    """
    from contextlib import asynccontextmanager

    from mcp import Client

    from gpg_mcp.server import mcp

    @asynccontextmanager
    async def _connect():
        async with Client(mcp) as client:
            yield client

    return _connect


async def call(client, name: str, **kwargs):
    return await client.call_tool(name, kwargs)

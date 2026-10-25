"""CLI entry point: serve, init, doctor and version."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import stat
import sys
from pathlib import Path

from .gpg import Gpg
from .policy import (
    DEFAULT_CONFIG,
    DEFAULT_GNUPG_HOME,
    assert_config_file,
    assert_keyring_permissions,
    assert_production_policy,
    get_policy,
    load_policy,
)
from .server import mcp, reset_gpg

AGENT_CONF = """\
# Managed by gpg-mcp. Keep this keyring isolated from your everyday ~/.gnupg.
default-cache-ttl 60
max-cache-ttl 300
ignore-cache-for-signing
no-allow-external-cache
no-allow-mark-trusted
pinentry-timeout 120
"""

DEFAULT_CONFIG_TEXT = """\
# gpg-mcp configuration. Restrictive defaults; edit deliberately.
gnupg_home = "{home}"
approval = "client"                 # client | local | none
destructive_confirmation = true     # typed fingerprint suffix, independent of require_approval
allow_test_mode = false             # required for approval = "none"
audit_required = true               # refuse high-risk operations if the ledger cannot be written
enable_network = false
enable_symmetric = false
allow_unprotected_keys = false
allow_hidden_recipients = false
max_input_bytes = 10485760
max_output_bytes = 20971520
timeout_s = 120
keygen_timeout_s = 300
keyserver = "hkps://keys.openpgp.org"

# Pin the keys you intend to use. With a dedicated keyring, empty means
# "any key in this keyring"; with ~/.gnupg, empty denies signing/decryption.
# allowed_sign_keys = ["FULL40HEXFINGERPRINT"]
# allowed_decrypt_keys = ["FULL40HEXFINGERPRINT"]
# allowed_recipients = ["FULL40HEXFINGERPRINT"]
"""


def _set_env(config: str | None, home: str | None) -> None:
    if config:
        os.environ["GPG_MCP_CONFIG"] = config
    if home:
        os.environ["GPG_MCP_HOME"] = home


def cmd_init(args: argparse.Namespace) -> int:
    home = Path(os.path.expanduser(args.home or str(DEFAULT_GNUPG_HOME))).resolve()
    config = Path(os.path.expanduser(args.config or str(DEFAULT_CONFIG))).absolute()
    home.mkdir(parents=True, exist_ok=True)
    os.chmod(home, 0o700)
    agent_conf = home / "gpg-agent.conf"
    if not agent_conf.exists():
        agent_conf.write_text(AGENT_CONF, encoding="utf-8")
    os.chmod(agent_conf, 0o600)
    if not config.parent.exists():
        config.parent.mkdir(parents=True, mode=0o700)
        os.chmod(config.parent, 0o700)
    if not config.exists():
        config.write_text(DEFAULT_CONFIG_TEXT.format(home=home), encoding="utf-8")
    st = config.lstat()
    if stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid():
        os.chmod(config, 0o600)
    else:
        print(
            "gpg-mcp: config is not a regular file owned by the current user; "
            "not changing its permissions",
            file=sys.stderr,
        )
    assert_config_file(config)
    print(f"keyring: {home}")
    print(f"config:  {config}")
    print()
    print("Next steps:")
    print("  1. Add this server to your MCP client, for example:")
    print(f'     "command": "gpg-mcp", "args": ["serve", "--config", "{config}"]')
    print("  2. Create a key with the create_key tool (the passphrase is entered")
    print("     only into pinentry), or import an existing public key.")
    print("  3. Review the config and pin allowed fingerprints for production use.")
    print()
    print("This keyring is separate from ~/.gnupg. To move an existing secret key")
    print("into it, do that yourself out-of-band; gpg-mcp never exports secret keys.")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    _set_env(args.config, args.home)
    policy = load_policy()
    async def run() -> dict:
        g = Gpg(policy)
        return await g.doctor()
    report = asyncio.run(run())
    print(json.dumps(report, indent=2))
    return 0 if all(v.get("ok", True) for v in report.values() if isinstance(v, dict)) else 1


def cmd_serve(args: argparse.Namespace) -> int:
    _set_env(args.config, args.home)
    policy = load_policy()
    assert_production_policy(policy)
    if policy.approval == "none":
        print(
            "gpg-mcp: WARNING approval is disabled (test mode) for "
            f"{policy.gnupg_home}",
            file=sys.stderr,
        )
    assert_keyring_permissions(policy.gnupg_home)
    reset_gpg()

    async def preflight() -> None:
        await Gpg(policy).version()

    asyncio.run(preflight())
    mcp.run(transport="stdio")
    return 0


def cmd_version(_: argparse.Namespace) -> int:
    from . import __version__

    print(f"gpg-mcp {__version__}")
    try:
        policy = get_policy()
        async def run() -> dict:
            return await Gpg(policy).version()
        info = asyncio.run(run())
        print(info["banner"])
    except Exception as exc:  # noqa: BLE001
        print(f"gpg: unavailable ({exc})")
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gpg-mcp", description="Security-focused MCP server for GnuPG")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="create an isolated keyring and config")
    p_init.add_argument("--home", help="GNUPGHOME to create")
    p_init.add_argument("--config", help="config file path")
    p_init.set_defaults(func=cmd_init)

    p_serve = sub.add_parser("serve", help="serve MCP over stdio")
    p_serve.add_argument("--config", help="config file path")
    p_serve.add_argument("--home", help="GNUPGHOME override")
    p_serve.set_defaults(func=cmd_serve)

    p_doctor = sub.add_parser("doctor", help="run health checks")
    p_doctor.add_argument("--config", help="config file path")
    p_doctor.add_argument("--home", help="GNUPGHOME override")
    p_doctor.set_defaults(func=cmd_doctor)

    p_version = sub.add_parser("version", help="print versions")
    p_version.set_defaults(func=cmd_version)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"gpg-mcp: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

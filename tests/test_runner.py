from __future__ import annotations

import asyncio
import os

from gpg_mcp.gpg import Gpg
from gpg_mcp.policy import load_policy, reset_policy_cache


def test_base_args_force_pinentry_and_ignore_option_files() -> None:
    gpg = Gpg.__new__(Gpg)
    gpg.gpg = "/usr/bin/gpg"
    args = gpg._base_args()
    assert "--no-options" in args
    assert "--pinentry-mode" in args
    assert args[args.index("--pinentry-mode") + 1] == "ask"


def test_hostile_gpg_conf_is_ignored(tmp_path) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    (home / "gpg.conf").write_text("this-option-does-not-exist\n", encoding="utf-8")
    config = tmp_path / "config.toml"
    config.write_text(
        f'gnupg_home = "{home}"\n'
        f'audit_log = "{tmp_path / "audit.jsonl"}"\n'
        'approval = "none"\n',
        encoding="utf-8",
    )
    os.chmod(config, 0o600)
    reset_policy_cache()
    policy = load_policy(config, env={})
    reset_policy_cache()
    runner = Gpg(policy)
    result = asyncio.run(runner.run(["--list-keys"], use_status=False))
    assert result.returncode == 0

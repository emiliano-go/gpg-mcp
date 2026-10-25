"""Validate release metadata before a tag is published."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = ("\u2014", "\u2013", " -- ")


def fail(errors: list[str]) -> None:
    for error in errors:
        print(f"release-check: {error}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate release metadata.")
    parser.add_argument("--tag", required=True, help="Release tag, for example v0.1.0.")
    args = parser.parse_args()

    tag = args.tag
    match = re.fullmatch(r"v(\d+\.\d+\.\d+)", tag)
    if not match:
        fail([f"tag {tag!r} must match vX.Y.Z"])
    version = match.group(1)

    errors: list[str] = []

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    project_version = pyproject["project"]["version"]
    if project_version != version:
        errors.append(f"pyproject version is {project_version}, tag is {version}")

    server_path = ROOT / "server.json"
    if not server_path.is_file():
        fail(["server.json is missing"])
    server = json.loads(server_path.read_text())
    if server.get("version") != version:
        errors.append(f"server.json version is {server.get('version')!r}, tag is {version}")

    packages = server.get("packages") or []
    if len(packages) != 1 or not isinstance(packages[0], dict):
        errors.append("server.json must contain exactly one package")
    else:
        package = packages[0]
        if package.get("identifier") != "gpg-mcp":
            errors.append("server.json package identifier must be gpg-mcp")
        if package.get("version") != version:
            errors.append(f"server.json package version is {package.get('version')!r}, tag is {version}")

    name = server.get("name")
    if not name:
        errors.append("server.json name is missing")
    else:
        marker = f"<!-- mcp-name: {name} -->"
        readme = ROOT / "README.md"
        if marker not in readme.read_text():
            errors.append(f"README.md is missing the marker {marker!r}")

    notes = ROOT / "release" / "notes" / f"{tag}.md"
    if not notes.is_file():
        errors.append(f"release notes are missing at {notes.relative_to(ROOT)}")
    else:
        text = notes.read_text()
        for needle in FORBIDDEN:
            if needle in text:
                errors.append(f"release notes contain forbidden punctuation {needle!r}")
        if not text.strip():
            errors.append("release notes are empty")

    if errors:
        fail(errors)

    print(f"release-check: {tag} is ready to publish")


if __name__ == "__main__":
    main()

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _version() -> str:
    return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]


def test_release_metadata_matches_version():
    version = _version()
    server = json.loads((ROOT / "server.json").read_text())
    assert server["version"] == version
    package = server["packages"][0]
    assert package["identifier"] == "gpg-mcp"
    assert package["version"] == version
    assert package["runtimeHint"] == "uvx"
    assert package["packageArguments"] == [
        {"type": "positional", "valueHint": "command", "value": "serve"}
    ]


def test_readme_has_registry_marker():
    server = json.loads((ROOT / "server.json").read_text())
    assert f"<!-- mcp-name: {server['name']} -->" in (ROOT / "README.md").read_text()


def test_release_notes_exist_and_are_clean():
    notes = ROOT / "release" / "notes" / f"v{_version()}.md"
    assert notes.is_file()
    text = notes.read_text()
    assert text.strip()
    assert "\u2014" not in text
    assert "\u2013" not in text
    assert " -- " not in text

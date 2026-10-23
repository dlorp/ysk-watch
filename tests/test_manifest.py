"""The plugin manifest agrees with the code, the changelog and the license.

Hermes reads ``plugin.yaml`` before it imports anything, so a hook missing from
``provides_hooks``, or a version that disagrees with the changelog, fails quietly at install
time rather than in a test run.
"""

from __future__ import annotations

import importlib
import importlib.util
import re
import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _manifest():
    text = (PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8")
    try:
        import yaml

        return yaml.safe_load(text)
    except ImportError:
        pass
    try:
        from ruamel.yaml import YAML
    except ImportError:
        pytest.skip("neither PyYAML nor ruamel.yaml is installed")
    return YAML(typ="safe", pure=True).load(text)


def _plugin():
    name = "ysk_watch_manifest"
    spec = importlib.util.spec_from_file_location(
        name, PLUGIN_DIR / "__init__.py", submodule_search_locations=[str(PLUGIN_DIR)]
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_provides_hooks_matches_what_register_registers():
    registered = []

    class Context:
        def register_hook(self, name, handler):
            assert callable(handler)
            registered.append(name)

    _plugin().register(Context())
    assert sorted(_manifest()["provides_hooks"]) == sorted(registered)


def test_version_matches_the_newest_changelog_entry():
    changelog = (PLUGIN_DIR / "CHANGELOG.md").read_text(encoding="utf-8")
    newest = re.search(r"^## \[(\d+\.\d+\.\d+)\]", changelog, re.MULTILINE)
    assert newest, "CHANGELOG.md has no released version heading"
    assert str(_manifest()["version"]) == newest.group(1)


def test_license_field_matches_the_license_file():
    first_line = (PLUGIN_DIR / "LICENSE").read_text(encoding="utf-8").splitlines()[0]
    assert first_line.startswith(f"{_manifest()['license']} License")

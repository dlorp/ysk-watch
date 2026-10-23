"""Test harness stubs.

The plugin imports ``hermes_constants`` lazily; only ``HERMES_HOME`` matters here. Stubbing it
keeps the suite runnable outside a Hermes install (CI), while a real install still wins.
"""

from __future__ import annotations

import os
import sys
import types

try:  # pragma: no cover - depends on the host
    import hermes_constants  # noqa: F401
except ImportError:  # pragma: no cover - exercised in CI
    stub = types.ModuleType("hermes_constants")

    def get_hermes_home() -> str:
        return os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")

    def hermes_home_key() -> str:
        return os.path.realpath(get_hermes_home())

    stub.get_hermes_home = get_hermes_home
    stub.hermes_home_key = hermes_home_key
    sys.modules["hermes_constants"] = stub

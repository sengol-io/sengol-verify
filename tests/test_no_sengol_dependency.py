"""Enforces the zero-runtime-dependency contract: sengol_verify must never
import ``sengol`` or any ``sengol.*`` submodule, even transitively.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"

_PROBE = """
import sys

assert "sengol" not in sys.modules, "sengol pre-imported before the probe ran"

# Make importing the real sengol package impossible: any attempt raises.
class _Blocker:
    def find_module(self, name, path=None):
        if name == "sengol" or name.startswith("sengol."):
            raise ImportError(f"sengol_verify attempted to import {name!r}")
        return None

sys.meta_path.insert(0, _Blocker())

import sengol_verify  # noqa: F401
import sengol_verify.canonical  # noqa: F401
import sengol_verify.merkle  # noqa: F401
import sengol_verify.bundle  # noqa: F401
import sengol_verify.verify  # noqa: F401
import sengol_verify.cli  # noqa: F401

for name in sys.modules:
    assert name != "sengol" and not name.startswith("sengol."), (
        f"sengol_verify imported {name!r}"
    )

print("OK: no sengol import")
"""


def test_importing_sengol_verify_never_imports_sengol(tmp_path):
    probe = tmp_path / "probe.py"
    probe.write_text(_PROBE)
    result = subprocess.run(
        [sys.executable, str(probe)],
        cwd=tmp_path,
        env={"PYTHONPATH": str(_SRC), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "OK: no sengol import" in result.stdout


def test_sengol_verify_declares_no_sengol_dependency():
    """The package's own dependency list never names sengol."""
    pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
    assert "sengol" not in pyproject.lower() or "sengol-verify" in pyproject.lower(), (
        "pyproject.toml must not depend on the sengol package"
    )
    # Stronger check: no dependency line names the sengol package itself.
    for line in pyproject.splitlines():
        stripped = line.strip().strip('",')
        if stripped.lower() == "sengol" or stripped.lower().startswith("sengol>="):
            raise AssertionError(f"found a sengol runtime dependency: {line!r}")

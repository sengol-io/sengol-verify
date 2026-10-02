"""Shared trust material for tests: the Ed25519 public key the fixtures were
countersigned with, as a caller would supply it out of band."""

from __future__ import annotations

from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
KEY_ID = "test-ed25519-key-1"
TRUSTED_PEM_PATH = FIXTURES / "trusted_ed25519.pem"
TRUSTED_KEYS = {KEY_ID: TRUSTED_PEM_PATH.read_text()}
TRUST_ARGS = ["--trusted-key", f"{KEY_ID}={TRUSTED_PEM_PATH}"]

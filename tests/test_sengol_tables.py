"""The vendored signing tables against a snapshot of sengol's own.

``tests/fixtures/sengol_tables.json`` is written by ``scripts/generate_fixtures.py``
from a sengol checkout's classes (families, versions, record types, unsigned,
unordered and nested-unsigned fields). ``scripts/crosscheck.py`` makes the same
comparison against a live checkout. This test needs no sengol: a change to a
vendored table that sengol's snapshot does not carry fails here, and a sengol
change shows up as a stale snapshot when the fixtures are regenerated.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SNAPSHOT = json.loads((_ROOT / "tests" / "fixtures" / "sengol_tables.json").read_text())


def _load_tables_module():
    spec = importlib.util.spec_from_file_location("_tables", _ROOT / "scripts" / "_tables.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_TABLES = _load_tables_module()


def test_vendored_tables_equal_sengols_snapshot():
    assert _TABLES.diff(_SNAPSHOT, _TABLES.vendored_tables()) == []


def test_snapshot_registers_the_families_this_verifier_must_know():
    # Guards the snapshot itself: an empty or truncated one would make the
    # comparison above vacuous.
    assert {"AuditRecord", "SoDApprovalRecord", "CallStartedRecord", "AcceptedSetLease"} <= set(
        _SNAPSHOT["versions"]
    )
    assert _SNAPSHOT["record_types"]["sengol.sod.approval"] == "SoDApprovalRecord"
    assert _SNAPSHOT["unordered"]["SoDDecisionRecord"] == ["approval_record_ids"]
    assert _SNAPSHOT["unordered"]["AcceptedSetLease"] == ["accepted_cert_ids"]
    assert "anchor_record_id" in _SNAPSHOT["unsigned"]["CertificationRecord"]
    assert "call_signature_manifests" in _SNAPSHOT["unsigned"]["AuditRecord"]
    assert _SNAPSHOT["nested_unsigned"]["AuditRecord"] == {
        "eval_result.scores": ["reason", "reason_status"]
    }
    assert set(_SNAPSHOT["nested_unsigned"]["RegressionCaseRecord"]) == {"bindings"}


def test_diff_names_a_divergence():
    mutated = json.loads(json.dumps(_TABLES.vendored_tables()))
    mutated["unordered"].pop("SoDDecisionRecord")
    mutated["versions"].pop("SoDApprovalRecord")
    out = _TABLES.diff(_SNAPSHOT, mutated)
    assert any(line.startswith("unordered[SoDDecisionRecord]") for line in out)
    assert any(line.startswith("versions[SoDApprovalRecord]") for line in out)

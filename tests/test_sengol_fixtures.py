"""Fixtures built and signed by sengol's own classes, replayed offline.

``scripts/generate_fixtures.py`` writes them from a sengol checkout; nothing
here imports sengol. Together they cover every signed family at every payload
version, a hash-chained partition of every audit family with regression
evidence, and a judge evidence pack.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
from pathlib import Path

import pytest

from sengol_verify import canonical
from sengol_verify.canonical import Record, family_for
from sengol_verify.verify import verify_bundle, verify_bundle_file

_FIXTURES = Path(__file__).parent / "fixtures"
_CANONICAL = json.loads((_FIXTURES / "canonical_fixtures.json").read_text())
_TABLES = json.loads((_FIXTURES / "sengol_tables.json").read_text())
_HMAC_KEY = "not-a-real-secret-do-not-reuse"
_KEY_ID = "test-hmac-key-1"
_SKIP = {"hmac_signature", "signing_backend", "payload_version"}


def _steps(result) -> dict:
    return {s.check: s for s in result.step_results}


def _with_hmac_material(bundle: dict) -> dict:
    bundle = copy.deepcopy(bundle)
    bundle["public_keys"]["hmac_material"] = {_KEY_ID: _HMAC_KEY}
    return bundle


def test_every_registered_family_and_version_has_a_fixture():
    have = {(f["family"], f["version"]) for f in _CANONICAL}
    want = {(fam, v) for fam, vs in _TABLES["versions"].items() for v in vs}
    assert want <= have, sorted(want - have)
    assert want == {(fam, v) for fam, vs in canonical._VERSIONS.items() for v in vs}


@pytest.mark.parametrize(
    "entry", _CANONICAL, ids=lambda f: f"{f['family']}-v{f['version']}-{f.get('case', '')}"
)
def test_fixture_reproduces_sengols_bytes_and_hmac(entry):
    rec = Record(entry["raw"], entry["family"])
    assert rec.canonical_payload() == entry["canonical"]
    expected = hmac.new(
        entry["hmac_key"].encode(), rec.canonical_payload().encode(), hashlib.sha256
    ).hexdigest()
    assert entry["raw"]["hmac_signature"] == expected


@pytest.mark.parametrize(
    "entry",
    [f for f in _CANONICAL if not f.get("case")],
    ids=lambda f: f"{f['family']}-v{f['version']}",
)
def test_signed_fields_change_the_bytes_and_unsigned_fields_do_not(entry):
    """Every top-level field is signed except the family's unsigned ones, on a
    record with every field populated."""
    family = entry["family"]
    unsigned = set(_TABLES["unsigned"][family])
    raw = entry["raw"]
    for name, value in raw.items():
        if name in _SKIP or value is None:
            continue
        changed = copy.deepcopy(raw)
        changed[name] = {"changed": True}
        same = Record(changed, family).canonical_payload() == entry["canonical"]
        assert same == (name in unsigned), (family, name)


@pytest.mark.parametrize(
    "family,field", [(f, n) for f, names in _TABLES["unordered"].items() for n in names]
)
def test_unordered_lists_sign_the_same_in_any_order(family, field):
    entry = next(f for f in _CANONICAL if f["family"] == family and not f.get("case"))
    values = entry["raw"][field]
    assert len(values) >= 2
    reordered = dict(entry["raw"], **{field: list(reversed(values))})
    assert Record(reordered, family).canonical_payload() == entry["canonical"]


def test_every_audit_family_is_in_the_partition_bundle_and_maps_to_itself():
    bundle = json.loads((_FIXTURES / "partition_bundle.json").read_text())
    types = {r.get("record_type") for r in bundle["records"]}
    assert set(_TABLES["record_types"]) <= types
    assert None in types
    for raw in bundle["records"]:
        if raw.get("record_type"):
            assert family_for(raw) == _TABLES["record_types"][raw["record_type"]]


def test_partition_bundle_verifies_every_step_but_the_withheld_secrets():
    result = verify_bundle_file(_FIXTURES / "partition_bundle.json")
    steps = _steps(result)
    for check in ("payload_hash_integrity", "chain_continuity", "anchor_coverage"):
        assert steps[check].result == "PASS", (check, steps[check].detail)
    assert steps["hmac_verify"].result == "UNVERIFIABLE"
    assert steps["regression_lineage"].result == "UNVERIFIABLE"
    assert steps["field_coverage"].result == "PASS"


def test_partition_bundle_with_hmac_material_verifies_every_record_and_the_lineage():
    bundle = _with_hmac_material(json.loads((_FIXTURES / "partition_bundle.json").read_text()))
    steps = _steps(verify_bundle(bundle))
    assert steps["hmac_verify"].result == "PASS", steps["hmac_verify"].detail
    assert steps["regression_lineage"].result == "PASS", steps["regression_lineage"].detail
    assert (
        steps["canonical_payload" if "canonical_payload" in steps else "chain_continuity"].result
        == "PASS"
    )


def test_partition_bundle_rejects_an_edit_to_any_one_record():
    bundle = json.loads((_FIXTURES / "partition_bundle.json").read_text())
    for i, record in enumerate(bundle["records"]):
        edited = copy.deepcopy(bundle)
        edited["records"][i]["agent_version"] = "tampered"
        steps = _steps(verify_bundle(edited))
        assert steps["payload_hash_integrity"].result == "FAIL", record.get("record_type")
        assert steps["chain_continuity"].result == "FAIL" or i == len(bundle["records"]) - 1


def test_judge_evidence_pack_verifies_in_portable_mode_and_not_as_a_partition():
    path = _FIXTURES / "judge_evidence_pack.json"
    steps = _steps(verify_bundle_file(path))
    assert steps["payload_hash_integrity"].result == "PASS"
    assert steps["chain_continuity"].result == "PASS"
    assert "sparse pack" in steps["chain_continuity"].detail
    bundle = json.loads(path.read_text())
    assert _steps(verify_bundle(bundle, portable=False))["chain_continuity"].result == "FAIL"

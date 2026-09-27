"""Byte-identity tests for the ADR-0019 RFC 8785 canonicalization rule.

``tests/fixtures/canonical_fixtures.json`` was produced by signing real
records with sengol's own code (``sengol/core/types.py`` +
``payload_registry.py``) — see ``scripts/crosscheck_canonical.py`` for how
to regenerate it. This file needs no ``sengol`` import at test time: it
only replays those pre-computed bytes and HMACs.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from sengol_verify.canonical import Record, canonical_payload

_FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "canonical_fixtures.json").read_text())


def test_rfc8785_envelope_shape_and_none_omission():
    raw = {
        "record_id": "r-1",
        "agent_id": "a-1",
        "tenant_id": "t-1",
        "payload_version": 3,
        "artifact_digest": None,  # must be omitted, not signed as null
        "hmac_signature": "should-not-appear",
        "signing_backend": "local",
    }
    rec = Record(raw, "AuditRecord")
    body = rec.canonical_payload()
    parsed = json.loads(body)
    assert parsed["type"] == "AuditRecord"
    assert "artifact_digest" not in parsed["record"]
    assert "hmac_signature" not in parsed["record"]
    assert parsed["record"]["record_id"] == "r-1"


def test_nested_unsigned_fields_are_excluded_from_bindings():
    raw = {
        "case_id": "c-1",
        "failure_id": "f-1",
        "tenant_id": "t-1",
        "agent_id": "a-1",
        "payload_version": 1,
        "input_hash": "sha256:" + "a" * 64,
        "promoted_by": "dev-1",
        "bindings": [
            {
                "evaluator": "Faithfulness",
                "config": {"threshold": 0.9},
                "config_hash": "sha256:" + "b" * 64,
                "reference": "the answer",
                "reference_hash": None,
            }
        ],
    }
    rec = Record(raw, "RegressionCaseRecord")
    parsed = json.loads(rec.canonical_payload())
    binding = parsed["record"]["bindings"][0]
    assert "config" not in binding and "reference" not in binding
    assert binding["config_hash"] == "sha256:" + "b" * 64


def test_unordered_fields_sort_by_their_own_bytes():
    raw = {
        "record_id": "r-1",
        "agent_id": "a-1",
        "agent_version": "1",
        "tenant_id": "t-1",
        "payload_version": 6,
        "run_id": "run-1",
        "suite_name": "s",
        "total": 0,
        "passed": 0,
        "pass_rate": 0.0,
        "gate_passed": True,
        "required_pass_rate": 1.0,
        "evaluator_manifest": [
            {"evaluator": "Z", "evaluator_version": "1"},
            {"evaluator": "A", "evaluator_version": "1"},
        ],
    }
    rec_1 = Record(raw, "EvaluationRunRecord")
    raw2 = dict(raw, evaluator_manifest=list(reversed(raw["evaluator_manifest"])))
    rec_2 = Record(raw2, "EvaluationRunRecord")
    assert rec_1.canonical_payload() == rec_2.canonical_payload()


def _hmac_hex(key: str, canonical: str) -> str:
    return hmac.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def test_crosscheck_fixtures_reproduce_real_sengol_bytes_and_hmac():
    """Every fixture's canonical bytes AND recomputed HMAC match what real
    sengol produced when it signed the record."""
    assert {f["family"] for f in _FIXTURES} >= {
        "AuditRecord",
        "TombstoneRecord",
        "EvaluationRunRecord",
        "CertificationRecord",
        "ProductionFailureRecord",
        "RegressionCaseRecord",
        "RegressionCaseRetirementRecord",
        "ProductionFailureWaiverRecord",
    }
    for f in _FIXTURES:
        rec = Record(f["raw"], f["family"])
        assert rec.canonical_payload() == f["canonical"], f["family"]
        assert _hmac_hex(f["hmac_key"], rec.canonical_payload()) == f["raw"]["hmac_signature"]


def test_certification_record_excludes_evidence_pack_id_unsigned_field():
    cert = next(f for f in _FIXTURES if f["family"] == "CertificationRecord")
    assert cert["raw"]["evidence_pack_id"] == "pack-1"
    parsed = json.loads(cert["canonical"])
    assert "evidence_pack_id" not in parsed["record"]


def test_certification_record_supersedes_is_sorted_by_its_own_bytes():
    cert = next(f for f in _FIXTURES if f["family"] == "CertificationRecord")
    raw = cert["raw"]
    assert len(raw["supersedes"]) == 2
    reordered = dict(raw, supersedes=list(reversed(raw["supersedes"])))
    rec_a = Record(raw, "CertificationRecord")
    rec_b = Record(reordered, "CertificationRecord")
    assert rec_a.canonical_payload() == rec_b.canonical_payload()


def test_regression_case_binding_reference_is_unsigned_but_config_hash_is_not():
    """CaseBinding.UNSIGNED_FIELDS (config, reference) travel with the fixture
    but never enter the signed bytes; config_hash/evaluator do."""
    case = next(f for f in _FIXTURES if f["family"] == "RegressionCaseRecord")
    binding = case["raw"]["bindings"][0]
    assert binding["reference"] and binding["config"]
    parsed = json.loads(case["canonical"])
    parsed_binding = parsed["record"]["bindings"][0]
    assert "reference" not in parsed_binding and "config" not in parsed_binding
    assert parsed_binding["config_hash"] == binding["config_hash"]
    assert parsed_binding["reference_hash"] == binding["reference_hash"]


def test_tamper_on_each_regression_family_breaks_the_hmac():
    """One field per new family, mutated: proof each is actually inside the
    signature, not decorative (spec success criterion 4)."""
    tampers = {
        "ProductionFailureRecord": ("failure_mode", "TAMPERED_MODE"),
        "RegressionCaseRecord": ("promoted_by", "someone-else"),
        "RegressionCaseRetirementRecord": ("reason", "tampered reason"),
        "ProductionFailureWaiverRecord": ("waived_by", "someone-else"),
    }
    for family, (field, new_value) in tampers.items():
        f = next(x for x in _FIXTURES if x["family"] == family)
        rec = Record(f["raw"], family)
        assert _hmac_hex(f["hmac_key"], rec.canonical_payload()) == f["raw"]["hmac_signature"]

        tampered_raw = dict(f["raw"], **{field: new_value})
        tampered = Record(tampered_raw, family)
        assert tampered.canonical_payload() != f["canonical"], family
        assert (
            _hmac_hex(f["hmac_key"], tampered.canonical_payload()) != f["raw"]["hmac_signature"]
        ), family


def test_tamper_on_signed_field_breaks_the_hmac():
    """Flipping a signed field changes the canonical bytes, so the original
    HMAC no longer verifies — proof the field is actually inside the
    signature, not decorative."""
    f = next(x for x in _FIXTURES if x["family"] == "AuditRecord" and x["version"] == 3)
    rec = Record(f["raw"], f["family"])
    assert _hmac_hex(f["hmac_key"], rec.canonical_payload()) == f["raw"]["hmac_signature"]

    tampered_raw = dict(f["raw"], agent_version="9.9.9-tampered")
    tampered = Record(tampered_raw, f["family"])
    assert tampered.canonical_payload() != f["canonical"]
    assert _hmac_hex(f["hmac_key"], tampered.canonical_payload()) != f["raw"]["hmac_signature"]


def test_unknown_payload_version_rejected():
    from sengol_verify.canonical import UnknownPayloadVersion

    raw = {"agent_id": "a", "tenant_id": "t", "payload_version": 999}
    rec = Record(raw, "AuditRecord")
    try:
        rec.canonical_payload()
    except UnknownPayloadVersion:
        pass
    else:
        raise AssertionError("expected UnknownPayloadVersion")


def test_canonical_payload_matches_record_method():
    raw = {"agent_id": "a", "tenant_id": "t", "payload_version": 1}
    rec = Record(raw, "AuthorityModelRecord")
    assert canonical_payload("AuthorityModelRecord", 1, rec) == rec.canonical_payload()


def test_every_audit_subtype_maps_to_its_own_family():
    """A subtype missing from the map would canonicalize as `AuditRecord`
    and fail its own genuine HMAC; these are the ones sengol signs under
    their own family name."""
    from sengol_verify.canonical import family_for

    assert family_for({"record_type": "sengol.audit.trace_reveal"}) == "TraceRevealRecord"
    assert family_for({"record_type": "sengol.registration.agent"}) == "AgentRegistrationRecord"
    assert family_for({"record_type": "sengol.governance.change"}) == "GovernanceChangeRecord"
    assert family_for({"record_type": "sengol.sod.decision"}) == "SoDDecisionRecord"
    assert family_for({}) == "AuditRecord"


def test_hmac_check_covers_version_1_records():
    """A version-1 record carries an HMAC like any other; a tampered one
    fails the HMAC step instead of being skipped."""
    from sengol_verify.verify import _check_hmac

    f = next(x for x in _FIXTURES if x["family"] == "AuditRecord" and x["version"] == 1)
    material = {"hmac_material": {f["raw"]["key_id"]: f["hmac_key"]}}
    genuine = Record(dict(f["raw"]), "AuditRecord")
    assert _check_hmac([genuine], material).result == "PASS"
    forged = Record({**f["raw"], "hmac_signature": "0" * 64}, "AuditRecord")
    assert _check_hmac([forged], material).result == "FAIL"

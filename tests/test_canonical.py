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

import pytest

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
        "AcceptedSetLease",
        "CallStartedRecord",
        "EvaluationRunRecord",
        "CertificationRecord",
        "ProductionFailureRecord",
        "RegressionCaseRecord",
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
    """One field per signed regression family, mutated: proof each is
    actually inside the signature, not decorative (spec success criterion 4)."""
    tampers = {
        "ProductionFailureRecord": ("failure_mode", "TAMPERED_MODE"),
        "RegressionCaseRecord": ("promoted_by", "someone-else"),
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
    rec = Record(raw, "AgentTierChangeRecord")
    assert canonical_payload("AgentTierChangeRecord", 1, rec) == rec.canonical_payload()


def test_every_audit_subtype_maps_to_its_own_family():
    """A subtype missing from the map would canonicalize as `AuditRecord`
    and fail its own genuine HMAC; these are the ones sengol signs under
    their own family name."""
    from sengol_verify.canonical import family_for

    assert family_for({"record_type": "sengol.audit.trace_reveal"}) == "TraceRevealRecord"
    assert family_for({"record_type": "sengol.agent.tier_change"}) == "AgentTierChangeRecord"
    assert family_for({"record_type": "sengol.sod.decision"}) == "SoDDecisionRecord"
    assert family_for({}) == "AuditRecord"
    assert family_for({"record_type": None}) == "AuditRecord"


@pytest.mark.parametrize(
    "record_type",
    [
        "sengol.registration.agent",  # a family sengol no longer signs
        "sengol.governance.change",
        "sengol.made.up",
        "",
        7,
        ["sengol.agent.call"],  # unhashable: must not raise TypeError
    ],
)
def test_unregistered_record_type_is_refused_not_read_as_audit_record(record_type):
    from sengol_verify.canonical import UnknownRecordType, family_for

    with pytest.raises(UnknownRecordType) as exc:
        family_for({"record_type": record_type})
    assert exc.value.record_type == record_type
    assert repr(record_type) in str(exc.value)


def test_record_without_a_family_has_no_canonical_payload():
    from sengol_verify.canonical import UnknownRecordType

    rec = Record({"record_type": "sengol.made.up", "agent_id": "a"}, None)
    with pytest.raises(UnknownRecordType, match="sengol.made.up"):
        rec.canonical_payload()


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


def _fixture(family: str, case: str | None = None) -> dict:
    return next(x for x in _FIXTURES if x["family"] == family and x.get("case") == case)


def test_score_reason_and_reason_status_are_not_signed_but_reason_digest_is():
    """sengol signs a keyed `reason_digest` and leaves the text and its read
    status out of the bytes (ADR-0078), so an exported record verifies with
    the text served, with it erased, or with a status set."""
    served = _fixture("AuditRecord", "reason_erased")
    score = served["raw"]["eval_result"]["scores"][0]
    assert score["reason"] == "" and score["reason_status"] == "ERASED"
    assert score["reason_digest"].startswith("hmac-sha256:")

    rec = Record(served["raw"], "AuditRecord")
    assert rec.canonical_payload() == served["canonical"]
    assert _hmac_hex(served["hmac_key"], rec.canonical_payload()) == served["raw"]["hmac_signature"]

    signed_score = json.loads(served["canonical"])["record"]["eval_result"]["scores"][0]
    assert "reason" not in signed_score and "reason_status" not in signed_score
    assert signed_score["reason_digest"] == score["reason_digest"]

    # The text is a free field: any value leaves the bytes unchanged.
    for text in ("", "other text", "x" * 50):
        raw = json.loads(json.dumps(served["raw"]))
        raw["eval_result"]["scores"][0]["reason"] = text
        assert Record(raw, "AuditRecord").canonical_payload() == served["canonical"]

    # The digest is signed: swapping it breaks the bytes.
    raw = json.loads(json.dumps(served["raw"]))
    raw["eval_result"]["scores"][0]["reason_digest"] = "hmac-sha256:" + "0" * 64
    assert Record(raw, "AuditRecord").canonical_payload() != served["canonical"]


def test_score_exclusion_is_scoped_to_eval_result_scores():
    """`reason` stays signed everywhere else, including a `scores` list that
    is not the evaluator's (an evaluation case's per-evaluator verdicts)."""
    raw = {
        "run_id": "r-1",
        "case_index": 0,
        "case_key": "row:0",
        "tenant_id": "t-1",
        "payload_version": 1,
        "scores": [{"evaluator": "E", "evaluator_version": "1", "passed": True, "reason": "x"}],
    }
    signed = json.loads(Record(raw, "EvaluationCaseRecord").canonical_payload())
    assert signed["record"]["scores"][0]["reason"] == "x"

    tomb = _fixture("TombstoneRecord")
    assert json.loads(tomb["canonical"])["record"]["reason"] == "right to erasure"
    changed = Record(dict(tomb["raw"], reason="other"), "TombstoneRecord")
    assert changed.canonical_payload() != tomb["canonical"]


def test_tamper_on_evaluator_verdict_still_breaks_the_hmac():
    """Excluding `reason` does not loosen the rest of the score."""
    f = next(x for x in _FIXTURES if x["family"] == "AuditRecord" and x["version"] == 3)
    for field, value in (("passed", False), ("evaluator", "Other"), ("failure_mode", "X")):
        raw = json.loads(json.dumps(f["raw"]))
        raw["eval_result"]["scores"][0][field] = value
        tampered = Record(raw, "AuditRecord")
        assert tampered.canonical_payload() != f["canonical"], field


def test_call_provenance_families_map_and_verify():
    """The call-start record and the accepted-set lease are AuditRecord
    subtypes with their own family names in the envelope."""
    from sengol_verify.canonical import family_for

    assert family_for({"record_type": "sengol.call.started"}) == "CallStartedRecord"
    assert family_for({"record_type": "sengol.behaviour.lease"}) == "AcceptedSetLease"
    for family in ("CallStartedRecord", "AcceptedSetLease"):
        f = _fixture(family)
        assert family_for(f["raw"]) == family
        rec = Record(f["raw"], family)
        assert rec.canonical_payload() == f["canonical"]
        assert _hmac_hex(f["hmac_key"], rec.canonical_payload()) == f["raw"]["hmac_signature"]
        assert json.loads(f["canonical"])["type"] == family


def test_accepted_set_lease_cert_ids_are_signed_sorted():
    f = _fixture("AcceptedSetLease")
    ids = f["raw"]["accepted_cert_ids"]
    assert len(ids) == 2
    assert ids != sorted(ids), "fixture must carry the ids out of order"
    for order in (ids, list(reversed(ids))):
        reordered = dict(f["raw"], accepted_cert_ids=order)
        assert Record(reordered, "AcceptedSetLease").canonical_payload() == f["canonical"]
    dropped = dict(f["raw"], accepted_cert_ids=ids[:1])
    assert Record(dropped, "AcceptedSetLease").canonical_payload() != f["canonical"]


def test_call_signature_manifests_is_unsigned_on_every_audit_family():
    """The transport-only sidecar is outside the bytes of every AuditRecord
    subtype, `AuthorizationDecisionRecord` (which extends the base list)
    included."""
    from sengol_verify.canonical import RECORD_TYPE_TO_FAMILY

    f = _fixture("AgentCallRecord", "manifest_sidecar")
    assert f["raw"]["call_signature_manifests"]
    rec = Record(f["raw"], "AgentCallRecord")
    assert rec.canonical_payload() == f["canonical"]
    assert _hmac_hex(f["hmac_key"], rec.canonical_payload()) == f["raw"]["hmac_signature"]

    families = {"AuditRecord", *RECORD_TYPE_TO_FAMILY.values()}
    assert {"AuthorizationDecisionRecord", "CallStartedRecord"} <= families
    for family in sorted(families):
        raw = {"agent_id": "a", "tenant_id": "t", "payload_version": 1}
        with_sidecar = dict(raw, call_signature_manifests={"sha256:" + "a" * 64: "raw"})
        assert (
            Record(with_sidecar, family).canonical_payload()
            == Record(raw, family).canonical_payload()
        ), family


def test_certification_anchor_record_id_is_unsigned():
    f = _fixture("CertificationRecord", "anchor_record_id")
    assert f["raw"]["anchor_record_id"]
    rec = Record(f["raw"], "CertificationRecord")
    assert rec.canonical_payload() == f["canonical"]
    assert _hmac_hex(f["hmac_key"], rec.canonical_payload()) == f["raw"]["hmac_signature"]
    assert "anchor_record_id" not in json.loads(f["canonical"])["record"]


_RETIRED_FAMILIES = (
    "AgentIdentityBindingRecord",
    "AgentLabelChangeRecord",
    "AgentRegistrationRecord",
    "AgentSecretExpiryScheduledRecord",
    "AgentSecretIssuedRecord",
    "AgentSecretRevokedRecord",
    "AuthorityModelRecord",
    "ErasureDualControlChangeRecord",
    "GovernanceChangeRecord",
    "LegalHoldRecord",
    "ProductionFailureWaiverRecord",
    "RegressionCaseRetirementRecord",
    "RegulationUpdateEvent",
    "RetentionAutoExecuteChangeRecord",
    "RetentionPolicyChangeRecord",
    "RetentionRetirementRecord",
    "ShadowAgentDispositionRecord",
    "TenantStatusChangeRecord",
)


@pytest.mark.parametrize("family", _RETIRED_FAMILIES)
def test_families_sengol_no_longer_signs_are_not_registered(family):
    """The verifier carries no canonical rule for a family sengol stopped
    signing: it is in no table, and a record built under its name has no
    payload version to canonicalize under."""
    from sengol_verify import canonical
    from sengol_verify.canonical import UnknownPayloadVersion

    assert family not in canonical._VERSIONS
    assert family not in canonical.RECORD_TYPE_TO_FAMILY.values()
    assert family not in canonical._UNSIGNED_FIELDS
    assert family not in canonical._UNORDERED_FIELDS
    with pytest.raises(UnknownPayloadVersion):
        Record({"payload_version": 1}, family).canonical_payload()

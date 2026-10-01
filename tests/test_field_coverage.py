"""Step 6, ``field_coverage``: names the set fields that sit outside each
record's signature by design. It reports; it has no FAIL branch."""

from __future__ import annotations

import copy
import dataclasses
import json
from pathlib import Path

from sengol_verify.bundle import reconstruct_records
from sengol_verify.canonical import Record, unsigned_field_paths
from sengol_verify.cli import main
from sengol_verify.verify import _check_field_coverage, verify_bundle, verify_bundle_file

_FIXTURES = Path(__file__).parent / "fixtures"
_CANONICAL = json.loads((_FIXTURES / "canonical_fixtures.json").read_text())
_PREFIX = (
    "Every set field is inside the signature except these, which are unsigned "
    "by design and not vouched for by any step: "
)


def _fixture(family: str, case: str | None = None) -> Record:
    f = next(x for x in _CANONICAL if x["family"] == family and x.get("case") == case)
    return Record(f["raw"], family)


def _listed(records: list[Record]) -> str:
    step = _check_field_coverage(records)
    assert step.result == "PASS"
    return step.detail


def test_genuine_bundle_lists_the_unsigned_fields_its_records_carry():
    result = verify_bundle_file(_FIXTURES / "bundle_full_pass.json")
    step = next(s for s in result.step_results if s.check == "field_coverage")
    assert step.result == "PASS"
    assert step.scope == "3 records"
    assert step.detail == _PREFIX + str(
        ["eval_result.scores.reason", "hmac_signature", "signing_backend"]
    )


def test_bundle_with_no_unsigned_field_set_says_so():
    bundle = {"records": [{"agent_id": "a", "tenant_id": "t", "payload_version": 1}]}
    step = next(s for s in verify_bundle(bundle).step_results if s.check == "field_coverage")
    assert step.result == "PASS"
    assert step.scope == "1 records"
    assert step.detail == _PREFIX + "[]"


def test_empty_bundle_reports_no_unsigned_fields():
    step = _check_field_coverage([])
    assert (step.scope, step.result, step.detail) == ("0 records", "PASS", _PREFIX + "[]")


def test_family_unsigned_fields_are_listed_when_set():
    cert = _fixture("CertificationRecord")
    assert cert._raw["evidence_pack_id"] == "pack-1"
    assert "evidence_pack_id" in unsigned_field_paths(cert)
    anchored = _fixture("CertificationRecord", "anchor_record_id")
    assert "anchor_record_id" in unsigned_field_paths(anchored)
    sidecar = _fixture("AgentCallRecord", "manifest_sidecar")
    assert "call_signature_manifests" in unsigned_field_paths(sidecar)


def test_unsigned_field_that_is_none_is_not_listed():
    rec = Record(
        {"remediated_at": None, "hmac_signature": "x", "suite_name": "s"}, "SaturationEvent"
    )
    assert unsigned_field_paths(rec) == ["hmac_signature"]
    rec = Record({"remediated_at": "2026-01-01T00:00:00Z"}, "SaturationEvent")
    assert unsigned_field_paths(rec) == ["remediated_at"]


def test_score_reason_and_status_are_listed_by_path_and_only_where_set():
    served = _fixture("AuditRecord", "reason_erased")
    paths = unsigned_field_paths(served)
    assert "eval_result.scores.reason" in paths and "eval_result.scores.reason_status" in paths
    assert "eval_result.scores.reason_digest" not in paths

    raw = copy.deepcopy(served._raw)
    raw["eval_result"]["scores"][0]["reason"] = None
    raw["eval_result"]["scores"][0]["reason_status"] = None
    assert "eval_result.scores.reason" not in unsigned_field_paths(Record(raw, "AuditRecord"))


def test_nested_path_is_listed_where_the_binding_names_it():
    case = _fixture("RegressionCaseRecord")
    assert {"bindings.config", "bindings.reference"} <= set(unsigned_field_paths(case))


def test_a_field_inside_an_unsigned_parent_is_not_listed_again():
    raw = {
        "eval_result": {"scores": [{"evaluator": "x", "reason": "r"}]},
        "model": "m",
    }
    rec = Record(raw, "AuthorizationDecisionRecord")
    assert unsigned_field_paths(rec) == ["eval_result", "model"]


def test_reason_stays_signed_outside_eval_result_scores():
    raw = {"scores": [{"evaluator": "E", "passed": True, "reason": "x"}], "run_id": "r"}
    assert unsigned_field_paths(Record(raw, "EvaluationCaseRecord")) == []
    # A tombstone's own top-level `reason` is signed; only the scores' is not.
    tomb = unsigned_field_paths(_fixture("TombstoneRecord"))
    assert "reason" not in tomb and "eval_result.scores.reason" in tomb


def test_every_listed_path_is_absent_from_the_canonical_payload():
    """The listing and the canonicalizer agree: whatever this step calls
    unsigned is not in the bytes."""
    assert sum(len(unsigned_field_paths(Record(f["raw"], f["family"]))) for f in _CANONICAL) > 10
    for f in _CANONICAL:
        rec = Record(f["raw"], f["family"])
        signed = json.loads(rec.canonical_payload())["record"]
        for path in unsigned_field_paths(rec):
            nodes = [signed]
            for key in path.split("."):
                nodes = [
                    child
                    for node in nodes
                    for item in (node if isinstance(node, list) else [node])
                    if isinstance(item, dict) and key in item
                    for child in [item[key]]
                ]
            assert not nodes, (f["family"], path)


def test_unregistered_record_type_is_not_assessed_and_does_not_fail_the_step():
    records = reconstruct_records(
        {
            "records": [
                {"record_type": "sengol.made.up", "signing_backend": "local"},
                {"hmac_signature": "y"},
            ]
        }
    )
    assert unsigned_field_paths(records[0]) == []
    step = _check_field_coverage(records)
    assert step.result == "PASS"
    assert step.detail == (
        _PREFIX + "['hmac_signature']. 1 record(s) with a record_type not registered in "
        "this verifier are not assessed"
    )


def test_row_shape_is_unchanged_in_the_report_and_in_json(tmp_path, capsys):
    result = verify_bundle_file(_FIXTURES / "bundle_full_pass.json")
    row = next(s for s in result.step_results if s.check == "field_coverage")
    assert [f.name for f in dataclasses.fields(row)] == ["check", "scope", "result", "detail"]
    assert result.step_results[5] is row

    assert main([str(_FIXTURES / "bundle_full_pass.json"), "--json"]) == 0
    steps = json.loads(capsys.readouterr().out)["steps"]
    out = next(s for s in steps if s["check"] == "field_coverage")
    assert list(out) == ["check", "scope", "result", "detail"]
    assert out["result"] == "PASS" and out["scope"] == "3 records"


def test_editing_an_unsigned_field_cannot_fail_the_step(tmp_path):
    """The step reports; it is not a check on those values. The edit is
    visible only as a listed field, and the bundle still verifies."""
    bundle = json.loads((_FIXTURES / "bundle_full_pass.json").read_text())
    bundle["records"][0]["eval_result"]["scores"][0]["reason"] = "edited after signing"
    step = next(s for s in verify_bundle(bundle).step_results if s.check == "field_coverage")
    assert step.result == "PASS"
    assert "eval_result.scores.reason" in step.detail

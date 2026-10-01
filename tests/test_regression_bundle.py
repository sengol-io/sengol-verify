"""``regression_evidence`` bundle section -> ``regression_lineage`` step."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from sengol_verify.canonical import Record
from sengol_verify.verify import verify_bundle, verify_bundle_file

_CHAIN = json.loads(
    (Path(__file__).parent / "fixtures" / "regression_chain_fixture.json").read_text()
)
_ORDER = ("failure", "case", "run", "certification")


def _bundle(*, hmac=False, mutate=None) -> dict:
    entries = {n: copy.deepcopy(_CHAIN[n]) for n in _ORDER}
    if mutate:
        mutate(entries)
    bundle = {
        "records": [],
        "public_keys": {"hmac_material": {"k1": _CHAIN["failure"]["hmac_key"]}} if hmac else {},
        "regression_evidence": {
            "format": "sengol-regression-evidence/v1",
            "agent_id": entries["failure"]["raw"]["agent_id"],
            "records": [
                {"family": entries[n]["family"], "record": entries[n]["raw"]} for n in _ORDER
            ],
        },
    }
    return bundle


def _step(bundle):
    steps = {s.check: s for s in verify_bundle(bundle).step_results}
    return steps["regression_lineage"]


def test_happy_path_with_hmac_material_passes():
    step = _step(_bundle(hmac=True))
    assert step.result == "PASS", step.detail
    assert "not chained" in step.scope


def test_happy_path_without_hmac_material_is_unverifiable():
    assert _step(_bundle()).result == "UNVERIFIABLE"


def test_tampered_signed_field_fails():
    def m(e):
        e["case"]["raw"]["promoted_by"] = "mallory"

    step = _step(_bundle(hmac=True, mutate=m))
    assert step.result == "FAIL"
    assert "hmac" in step.detail.lower()


def test_case_with_missing_failure_fails():
    def m(e):
        e["case"]["raw"]["failure_id"] = "gone-failure"

    step = _step(_bundle(mutate=m))
    assert step.result == "FAIL" and "gone-failure" in step.detail


def test_run_referencing_unknown_case_fails():
    def m(e):
        e["run"]["raw"]["case_results"][0]["case_id"] = "ghost-case"

    step = _step(_bundle(mutate=m))
    assert step.result == "FAIL" and "ghost-case" in step.detail


def test_cert_run_hash_mismatch_fails():
    def m(e):
        e["certification"]["raw"]["run_payload_sha256"] = "0" * 64

    step = _step(_bundle(mutate=m))
    assert step.result == "FAIL" and _CHAIN["certification"]["raw"]["cert_id"] in step.detail


def test_cert_run_id_mismatch_fails():
    def m(e):
        e["certification"]["raw"]["run_id"] = "other-run"

    assert _step(_bundle(mutate=m)).result == "FAIL"


def test_unknown_family_fails():
    bundle = _bundle()
    bundle["regression_evidence"]["records"][0]["family"] = "BogusRecord"
    step = _step(bundle)
    assert step.result == "FAIL" and "BogusRecord" in step.detail


def test_no_section_no_step():
    bundle = _bundle()
    del bundle["regression_evidence"]
    assert "regression_lineage" not in {s.check for s in verify_bundle(bundle).step_results}


def test_file_path_and_cli_show_step(tmp_path, capsys):
    from sengol_verify.cli import main

    p = tmp_path / "b.json"
    p.write_text(json.dumps(_bundle(hmac=True)))
    assert "regression_lineage" in {s.check for s in verify_bundle_file(p).step_results}
    main([str(p)])
    assert "regression_lineage" in capsys.readouterr().out


def test_fixture_run_hash_is_what_the_step_binds():
    run = Record(_CHAIN["run"]["raw"], "EvaluationRunRecord")
    assert (
        hashlib.sha256(run.canonical_payload().encode()).hexdigest()
        == _CHAIN["certification"]["raw"]["run_payload_sha256"]
    )


def test_signed_retirement_family_is_an_unknown_family():
    """sengol no longer signs retirements (ADR-0024); an entry naming the
    old signed family is refused by name, not read as a signed record."""
    bundle = _bundle(hmac=True)
    bundle["regression_evidence"]["records"].append(
        {
            "family": "RegressionCaseRetirementRecord",
            "record": {
                "agent_id": _CHAIN["case"]["raw"]["agent_id"],
                "case_id": _CHAIN["case"]["raw"]["case_id"],
                "reason": "obsolete",
            },
        }
    )
    step = _step(bundle)
    assert step.result == "FAIL"
    assert "unknown family 'RegressionCaseRetirementRecord'" in step.detail


def test_signed_waiver_family_is_an_unknown_family():
    bundle = _bundle(hmac=True)
    bundle["regression_evidence"]["records"].append(
        {
            "family": "ProductionFailureWaiverRecord",
            "record": {"agent_id": _CHAIN["failure"]["raw"]["agent_id"]},
        }
    )
    step = _step(bundle)
    assert step.result == "FAIL"
    assert "unknown family 'ProductionFailureWaiverRecord'" in step.detail


def test_duplicate_case_id_fails():
    bundle = _bundle(hmac=True)
    bundle["regression_evidence"]["records"].append(
        {
            "family": _CHAIN["case"]["family"],
            "record": copy.deepcopy(_CHAIN["case"]["raw"]),
        }
    )
    step = _step(bundle)
    assert step.result == "FAIL"
    assert "duplicate id" in step.detail


def test_legacy_certification_without_run_hash_needs_its_run():
    """A certification that predates run_payload_sha256 is still resolved
    by run_id, so it cannot point at a run absent from the section."""

    def m(e):
        e["certification"]["raw"].pop("run_payload_sha256")

    bundle = _bundle(mutate=m)
    bundle["regression_evidence"]["records"] = [
        r for r in bundle["regression_evidence"]["records"] if r["family"] != "EvaluationRunRecord"
    ]
    step = _step(bundle)
    assert step.result == "FAIL"
    assert "references missing EvaluationRunRecord" in step.detail


def test_unsupported_format_fails():
    bundle = _bundle(hmac=True)
    bundle["regression_evidence"]["format"] = "sengol-regression-evidence/v2"
    step = _step(bundle)
    assert step.result == "FAIL"
    assert "unsupported format" in step.detail


def test_section_agent_must_match_signed_records():
    bundle = _bundle(hmac=True)
    bundle["regression_evidence"]["agent_id"] = "some-other-agent"
    step = _step(bundle)
    assert step.result == "FAIL"
    assert "is not the section's" in step.detail


def test_null_section_is_treated_as_absent():
    bundle = _bundle(hmac=True)
    bundle["regression_evidence"] = None
    checks = [s.check for s in verify_bundle(bundle).step_results]
    assert "regression_lineage" not in checks


def test_malformed_case_result_entry_fails_without_crashing():
    def m(e):
        e["run"]["raw"]["case_results"] = [None]

    step = _step(_bundle(hmac=True, mutate=m))
    assert step.result == "FAIL"
    assert "malformed case_results entry" in step.detail


def test_scalar_case_results_fails_without_crashing():
    def m(e):
        e["run"]["raw"]["case_results"] = 1

    step = _step(_bundle(hmac=True, mutate=m))
    assert step.result == "FAIL"
    assert "case_results is not a list" in step.detail


def test_unhashable_family_fails_without_crashing():
    bundle = _bundle()
    bundle["regression_evidence"]["records"][0]["family"] = []
    step = _step(bundle)
    assert step.result == "FAIL"
    assert "unknown family" in step.detail


def test_non_string_hmac_signature_fails_without_crashing():
    def m(e):
        e["case"]["raw"]["hmac_signature"] = None

    step = _step(_bundle(hmac=True, mutate=m))
    assert step.result == "FAIL"
    assert "HMAC mismatch" in step.detail


def test_certification_agent_version_must_match_its_run():
    def m(e):
        e["certification"]["raw"]["agent_version"] = "not-the-evaluated-version"

    step = _step(_bundle(mutate=m))
    assert step.result == "FAIL"
    assert "agent_version" in step.detail


def _unsigned(family: str, **fields) -> dict:
    case = _CHAIN["case"]["raw"]
    return {
        "family": family,
        "record": {"tenant_id": case["tenant_id"], "agent_id": case["agent_id"], **fields},
    }


def test_unsigned_retirement_and_waiver_are_link_checked_and_pass():
    """sengol ADR-0024 exports retirements and waivers unsigned, under the
    names RegressionCaseRetirement / ProductionFailureWaiver."""
    bundle = _bundle(hmac=True)
    bundle["regression_evidence"]["records"] += [
        _unsigned(
            "RegressionCaseRetirement",
            case_id=_CHAIN["case"]["raw"]["case_id"],
            reason="obsolete",
            retired_by="reviewer-2",
            retired_at="2026-09-28T00:00:00Z",
        ),
        _unsigned(
            "ProductionFailureWaiver",
            failure_id=_CHAIN["failure"]["raw"]["failure_id"],
            reason="untestable",
            waived_by="reviewer-2",
            waived_at="2026-09-28T00:00:00Z",
        ),
    ]
    step = _step(bundle)
    assert step.result == "PASS", step.detail


def test_unsigned_retirement_with_dangling_case_fails():
    bundle = _bundle(hmac=True)
    bundle["regression_evidence"]["records"].append(
        _unsigned("RegressionCaseRetirement", case_id="no-such-case", reason="x")
    )
    step = _step(bundle)
    assert step.result == "FAIL"
    assert "no-such-case" in step.detail


def test_unsigned_waiver_for_another_agent_fails():
    bundle = _bundle(hmac=True)
    w = _unsigned("ProductionFailureWaiver", failure_id=_CHAIN["failure"]["raw"]["failure_id"])
    w["record"]["agent_id"] = "someone-else"
    bundle["regression_evidence"]["records"].append(w)
    step = _step(bundle)
    assert step.result == "FAIL"
    assert "is not the section's" in step.detail

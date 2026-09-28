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

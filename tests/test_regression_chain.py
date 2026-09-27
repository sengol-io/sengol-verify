"""Offline walk: production failure -> case -> run -> certification,
success criterion 4 of the design spec (2026-09-24-production-failure-
regression-design.md). Fixtures are real sengol-signed records — see
``scripts/crosscheck_canonical.py`` for how ``regression_chain_fixture.json``
is regenerated.

``EvaluationRunRecord`` and ``CertificationRecord`` carry no ``record_type``
field (they live outside the audit chain, in their own tables) — neither do
the four regression records. None of the five is in ``RECORD_TYPE_TO_FAMILY``,
so each ``Record`` here is built with its family passed explicitly, exactly
as ``scripts/crosscheck_canonical.py`` already does for ``GoldScoreRecord``
and ``SaturationEvent``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from sengol_verify.canonical import Record

_CHAIN = json.loads(
    (Path(__file__).parent / "fixtures" / "regression_chain_fixture.json").read_text()
)


def _record(name: str) -> Record:
    entry = _CHAIN[name]
    return Record(entry["raw"], entry["family"])


def test_case_links_to_its_failure_by_id():
    case = _record("case")
    failure = _record("failure")
    assert case._raw["failure_id"] == failure._raw["failure_id"]


def test_run_case_results_reference_the_case():
    run = _record("run")
    case = _record("case")
    assert run._raw["case_results"][0]["case_id"] == case._raw["case_id"]


def test_certification_binds_the_runs_hash():
    run = _record("run")
    cert = _record("certification")
    run_hash = hashlib.sha256(run.canonical_payload().encode()).hexdigest()
    assert cert._raw["run_payload_sha256"] == run_hash


def test_certification_run_id_matches_the_bound_run():
    run = _record("run")
    cert = _record("certification")
    assert cert._raw["run_id"] == run._raw["run_id"]


def test_full_chain_reproduces_its_recorded_canonical_bytes_and_hmac():
    """Every record in the chain verifies against its own stored HMAC,
    proving the four families and the case-set fields sign correctly end
    to end, not just in isolation."""
    import hmac as _hmac

    for name in ("failure", "case", "run", "certification"):
        entry = _CHAIN[name]
        rec = Record(entry["raw"], entry["family"])
        assert rec.canonical_payload() == entry["canonical"], name
        expected = _hmac.new(
            entry["hmac_key"].encode(),
            rec.canonical_payload().encode(),
            hashlib.sha256,
        ).hexdigest()
        assert expected == entry["raw"]["hmac_signature"], name

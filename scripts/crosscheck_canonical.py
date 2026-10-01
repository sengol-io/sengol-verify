"""Cross-check: real sengol canonical bytes vs the vendored copy.

Run from the sengol checkout with sengol-verify's src on the path:

    cd /home/user/sengol && PYTHONPATH=/home/user/sengol:/path/to/sengol-verify/src \
        uv run python /path/to/sengol-verify/scripts/crosscheck_canonical.py

Not part of the test suite (it depends on sengol being importable). It
compares sengol's ``payload_registry._VERSIONS`` with the vendored
``_VERSIONS``: the two must name the same families with the same version
tuples, and every record built below is signed by sengol and
re-canonicalized by the vendored copy. Exits 1 on any mismatch, a record whose
family is not in both registries, a family only one side registers (a family
sengol stopped signing must be deleted from the vendored copy).
"""

import sys
from datetime import UTC, datetime
from uuid import UUID

from sengol.core.payload_registry import _VERSIONS as SENGOL_VERSIONS
from sengol.core.types import (
    AcceptedSetLease,
    AgentCallRecord,
    AuditRecord,
    AuthorizationDecisionRecord,
    CallStartedRecord,
    CaseBinding,
    CaseResult,
    CertificationRecord,
    EvalManifestEntry,
    EvalResult,
    EvalScore,
    EvaluationRunRecord,
    GoldScoreRecord,
    JudgeModelCard,
    ProductionFailureRecord,
    RegressionCaseRecord,
    SaturationEvent,
    TombstoneRecord,
)

from sengol_verify.canonical import _VERSIONS as VERIFY_VERSIONS
from sengol_verify.canonical import Record, family_for

SHARED = frozenset(SENGOL_VERSIONS) & frozenset(VERIFY_VERSIONS)
CHECKED: set[str] = set()
FAILURES: list[str] = []

TENANT = "acme-bank"
AGENT = "loan-underwriter-bot"


def _eval_result() -> EvalResult:
    return EvalResult(
        agent_id=AGENT,
        agent_version="1.0.0",
        scores=[EvalScore(evaluator="x", passed=True)],
        overall_passed=True,
        policies=["OSFI_E23"],
    )


def _check(real, family: str | None = None) -> None:
    """*family* is required for a record with no ``record_type`` field
    (EvaluationRunRecord, CertificationRecord, GoldScoreRecord,
    SaturationEvent, the regression records) — ``family_for`` only resolves
    that field."""
    raw = real.model_dump(mode="json")
    name = family or family_for(raw)
    label = f"{name} v{real.payload_version}"
    if name not in SHARED:
        FAILURES.append(label)
        print(f"NOT SHARED: {label} is not registered on both sides")
        return
    CHECKED.add(name)
    mine = Record(raw, name)
    real_bytes = real._canonical_payload()
    mine_bytes = mine.canonical_payload()
    if real_bytes == mine_bytes:
        print(f"OK: {label}")
        return
    FAILURES.append(label)
    print(f"MISMATCH: {label}")
    print("  real:", real_bytes)
    print("  mine:", mine_bytes)


def main() -> None:
    _check(
        AgentCallRecord(
            agent_id=AGENT,
            agent_version="1.0.0",
            tenant_id=TENANT,
            eval_result=_eval_result(),
            policies=[],
            caller_agent_id="orchestrator",
            callee_agent_id=AGENT,
            declared=True,
            risk_tier_escalation=False,
            authorization_record_id="auth-1",
            mcp_tool_hash="sha256:" + "a" * 64,
            mcp_tool_pinned_hash="sha256:" + "b" * 64,
            sequence_number=1,
            prev_hash="",
            key_id="k1",
        ).sign("hmac-key")
    )

    _check(
        TombstoneRecord(
            agent_id=AGENT,
            agent_version="1.0.0",
            tenant_id=TENANT,
            eval_result=_eval_result(),
            policies=["OSFI_E23"],
            operator_id="op-1",
            purged_at=datetime.now(UTC),
            purged_count=2,
            purged_trace_ids=["t2", "t1"],
            reason="right to erasure",
            subject_ref="ticket-1",
            requester_principal_id="principal:alice",
            payload_version=2,
            sequence_number=1,
            prev_hash="",
            key_id="k1",
        ).sign("hmac-key")
    )

    lease = AcceptedSetLease(
        agent_id=AGENT,
        agent_version="1.0.0",
        tenant_id=TENANT,
        eval_result=_eval_result(),
        policies=[],
        accepted_cert_ids=[
            UUID("01a0e0ae-9261-7e42-8555-802b216f7a26"),
            UUID("01a0e0ae-9261-7e42-8555-802b216f7a25"),
        ],
        artifact_digest="sha256:" + "a" * 64,
        artifact_mutable=False,
        sequence_number=1,
        prev_hash="",
        key_id="k1",
    ).sign("hmac-key")
    _check(lease)

    _check(
        CallStartedRecord(
            agent_id=AGENT,
            agent_version="1.0.0",
            tenant_id=TENANT,
            eval_result=_eval_result(),
            policies=[],
            call_id=UUID("01a0e0ae-9261-7e42-8555-802b216f7a27"),
            lease_id=lease.record_id,
            pre_call_digest="sha256:" + "b" * 64,
            received_at=lease.timestamp,
            sequence_number=2,
            prev_hash="",
            key_id="k1",
        ).sign("hmac-key")
    )

    card = JudgeModelCard(
        agent_id=AGENT,
        agent_version="1.0.0",
        tenant_id=TENANT,
        eval_result=_eval_result(),
        policies=[],
        adapter_ref="adapter-1",
        adv_tnr=0.9,
        adv_tpr=0.9,
        base_model="base-1",
        calibration_reviewer_count=3,
        failure_mode=None,
        gate_passed=True,
        independence_established=True,
        independent_count=3,
        independent_reviewer_count=3,
        adversarial_count=3,
        position_pairs_count=3,
        kappa=0.8,
        policy="policy-1",
        position_pc=0.5,
        test_count=100,
        tnr=0.9,
        tpr=0.9,
        labels_authenticated=False,
        authenticated_records=9,
        divergent_records=1,
        sequence_number=1,
        prev_hash="",
        key_id="k1",
    ).sign("hmac-key")
    _check(card)

    _check(
        AuditRecord(
            agent_id=AGENT,
            agent_version="1.0.0",
            tenant_id=TENANT,
            eval_result=_eval_result(),
            policies=["OSFI_E23"],
            controlbook_id="cb-1",
            controlbook_version="v1",
            sequence_number=1,
            prev_hash="",
            key_id="k1",
            payload_version=3,
        ).sign("hmac-key")
    )

    _check(
        GoldScoreRecord(
            agent_id=AGENT,
            agent_version="1.0.0",
            tenant_id=TENANT,
            controlbook_id="cb-1",
            controlbook_version="v1",
            period_from=datetime.now(UTC),
            period_to=datetime.now(UTC),
            score=0.9,
            breakdown={"OSFI_E23": 0.9},
            formula_type="weighted",
            compliant=True,
            key_id="k1",
            payload_version=2,
        ).sign("hmac-key"),
        family="GoldScoreRecord",
    )

    # SaturationEvent — UNSIGNED_FIELDS (remediated_at), populated so its
    # exclusion is actually exercised, not just an absent-field no-op.
    _check(
        SaturationEvent(
            suite_name="s",
            agent_id=AGENT,
            tenant_id=TENANT,
            pass_rate=1.0,
            consecutive_runs=3,
            threshold=0.95,
            remediated_at=datetime.now(UTC),
            key_id="k1",
            payload_version=2,
        ).sign("hmac-key"),
        family="SaturationEvent",
    )

    # AuthorizationDecisionRecord — UNSIGNED_FIELDS (eval_result, model,
    # token/cost telemetry), populated so the exclusion is exercised.
    _check(
        AuthorizationDecisionRecord(
            agent_id=AGENT,
            agent_version="1.0.0",
            tenant_id=TENANT,
            caller_agent_id="orchestrator",
            callee_agent_id=AGENT,
            tool_id="tool-1",
            decision="allow",
            enforcement_mode="enforce",
            policy_matched=True,
            matched_rule="rule-1",
            reason="ok",
            policies=["OSFI_E23"],
            eval_result=_eval_result(),
            model="gpt-x",
            input_tokens=10,
            output_tokens=5,
            cost_usd=0.01,
            delegation_depth=1,
            risk_tier_escalation=False,
            sequence_number=1,
            prev_hash="",
            key_id="k1",
            payload_version=2,
        ).sign("hmac-key")
    )

    # EvaluationRunRecord v6 — UNORDERED_FIELDS (evaluator_manifest) plus the
    # case-set/regression fields.
    run = EvaluationRunRecord(
        agent_id=AGENT,
        agent_version="1.0.0",
        tenant_id=TENANT,
        suite_name="regression",
        total=2,
        passed=2,
        pass_rate=1.0,
        gate_passed=True,
        required_pass_rate=1.0,
        regression_suite_digest="sha256:" + "d" * 64,
        case_results=[
            CaseResult(case_id="c-1", passed=True, evaluator_versions=["Faithfulness@1"]),
            CaseResult(case_id="c-2", passed=True, evaluator_versions=["Faithfulness@1"]),
        ],
        case_count=2,
        dataset_sha256="e" * 64,
        dataset_row_count=2,
        evaluator_manifest=[
            EvalManifestEntry(evaluator="Z", evaluator_version="1"),
            EvalManifestEntry(evaluator="A", evaluator_version="1"),
        ],
        cases_digest="f" * 64,
        digest_algorithm="sha256-index-lines-v1",
        key_id="k1",
        payload_version=6,
    ).sign("hmac-key")
    _check(run, family="EvaluationRunRecord")

    # CertificationRecord v4 — UNSIGNED_FIELDS (evidence_pack_id) and
    # UNORDERED_FIELDS (supersedes), plus run_payload_sha256 (ADR-0020).
    cert = CertificationRecord(
        agent_id=AGENT,
        agent_version="1.0.0",
        tenant_id=TENANT,
        run_id=run.run_id,
        certified_risk_tier="TIER_2",
        policies=["OSFI_E23"],
        gate_passed=True,
        certified_by="reviewer-1",
        run_payload_sha256=run.payload_sha256(),
        supersedes=[
            "01a0e0ae-9261-7e42-8555-802b216f7a26",
            "01a0e0ae-9261-7e42-8555-802b216f7a25",
        ],
        key_id="k1",
        payload_version=4,
    ).sign("hmac-key")
    cert = cert.model_copy(update={"evidence_pack_id": "pack-1"})
    _check(cert, family="CertificationRecord")

    # The four regression records (spec §"production failure -> regression
    # suite"). None carries a record_type field, so each is checked with an
    # explicit family, the same way GoldScoreRecord/SaturationEvent are above.
    failure = ProductionFailureRecord(
        agent_id=AGENT,
        tenant_id=TENANT,
        audit_record_id="rec-1",
        trace_id="trace-1",
        failure_mode="QUOTED_STALE_RATE",
        first_failure_span_id="span-1",
        open_code_note_hash="sha256:" + "1" * 64,
        reviewer_id="reviewer-1",
        key_id="k1",
    ).sign("hmac-key")
    _check(failure, family="ProductionFailureRecord")

    # RegressionCaseRecord — CaseBinding.UNSIGNED_FIELDS (config, reference),
    # populated with real values so the nested exclusion is exercised.
    case = RegressionCaseRecord(
        agent_id=AGENT,
        tenant_id=TENANT,
        failure_id=str(failure.failure_id),
        input_hash="sha256:" + "2" * 64,
        bindings=[
            CaseBinding(
                evaluator="Faithfulness",
                config={"threshold": 0.9},
                config_hash="sha256:" + "3" * 64,
                reference="the reference answer",
                reference_hash="sha256:" + "4" * 64,
            )
        ],
        promoted_by="dev-1",
        key_id="k1",
    ).sign("hmac-key")
    _check(case, family="RegressionCaseRecord")


def report() -> int:
    """Print the family coverage and return the process exit code."""
    withdrawn = sorted(set(VERIFY_VERSIONS) - set(SENGOL_VERSIONS))
    unknown = sorted(set(SENGOL_VERSIONS) - set(VERIFY_VERSIONS))
    skew = sorted(f for f in SHARED if SENGOL_VERSIONS[f] != VERIFY_VERSIONS[f])
    print(f"\nshared families: {len(SHARED)}; checked here: {len(CHECKED)}")
    print(f"not exercised by this script: {sorted(SHARED - CHECKED)}")
    print(f"vendored only, sengol does not sign them ({len(withdrawn)}): {withdrawn}")
    print(f"sengol only, missing from the verifier: {unknown}")
    print(f"version tuples that differ: {skew}")
    bad = bool(FAILURES or withdrawn or unknown or skew)
    print("RESULT:", "FAIL" if bad else "OK")
    return 1 if bad else 0


if __name__ == "__main__":
    main()
    sys.exit(report())

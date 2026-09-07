"""One-off cross-check: real sengol canonical bytes vs the vendored copy.

Run from the sengol checkout with sengol-verify's src on the path:

    cd /home/user/sengol && PYTHONPATH=/home/user/sengol-verify/src \
        uv run python /home/user/sengol-verify/scripts/crosscheck_canonical.py

Not part of the test suite (it depends on sengol being importable) — a
one-time confidence check that the vendored copy in canonical.py produces
byte-identical output to the real payload_registry.py for record families
the committed fixtures don't exercise.
"""

from datetime import UTC, datetime

from sengol.core.types import (
    AgentCallRecord,
    AuthorityModelRecord,
    EvalResult,
    EvalScore,
    JudgeModelCard,
    TenantStatusChangeRecord,
    TombstoneRecord,
)

from sengol_verify.canonical import Record, family_for

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


def _check(real) -> None:
    raw = real.model_dump(mode="json")
    mine = Record(raw, family_for(raw))
    real_bytes = real._canonical_payload()
    mine_bytes = mine.canonical_payload()
    status = "OK" if real_bytes == mine_bytes else "MISMATCH"
    print(f"{status}: {type(real).__name__} v{real.payload_version}")
    if real_bytes != mine_bytes:
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

    _check(
        AuthorityModelRecord(
            agent_id=AGENT,
            agent_version="1.0.0",
            tenant_id=TENANT,
            eval_result=_eval_result(),
            policies=["OSFI_E23"],
            authority_version_id="av-1",
            model_digest="sha256:" + "c" * 64,
            new_status="ACTIVE",
            prior_status="PENDING",
            reason="activation",
            transition_actor="op-1",
            sequence_number=1,
            prev_hash="",
            key_id="k1",
        ).sign("hmac-key")
    )

    _check(
        TenantStatusChangeRecord(
            agent_id=AGENT,
            agent_version="1.0.0",
            tenant_id=TENANT,
            eval_result=_eval_result(),
            policies=["OSFI_E23"],
            changed_by="op-1",
            from_status="active",
            to_status="suspended",
            decided_at=datetime.now(UTC),
            seal_posture="sealed",
            sequence_number=1,
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


if __name__ == "__main__":
    main()

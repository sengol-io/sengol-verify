"""Regenerates the sengol-signed entries of ``tests/fixtures/canonical_fixtures.json``.

Run from the sengol checkout, with sengol-verify's ``src`` on the path:

    cd /home/user/sengol && PYTHONPATH=/home/user/sengol \
        uv run python /path/to/sengol-verify/scripts/generate_canonical_fixtures.py \
        /path/to/sengol-verify/tests/fixtures/canonical_fixtures.json

Every entry is signed by sengol's own ``sign()`` and its ``canonical`` bytes
come from sengol's own ``_canonical_payload()``, never from this repository.
An entry without a ``case`` key replaces the existing entry of the same
family and version; an entry with one is appended or replaced by case.
The HMAC key is a throwaway label, not a secret.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from sengol.core.types import (
    AcceptedSetLease,
    AgentCallRecord,
    AuditRecord,
    CallStartedRecord,
    CertificationRecord,
    EvalResult,
    EvalScore,
    TombstoneRecord,
)

TENANT = "acme-bank"
AGENT = "loan-underwriter-bot"
HMAC_KEY = "not-a-real-secret-do-not-reuse"
REASON_TEXT = "the customer wrote: my SIN is on file"


def _eval_result() -> EvalResult:
    return EvalResult(
        agent_id=AGENT,
        agent_version="1.0.0",
        scores=[EvalScore(evaluator="PIIEvaluator", passed=True, reason=REASON_TEXT)],
        overall_passed=True,
        policies=["OSFI_E23"],
    )


def _entry(family: str, signed, raw: dict | None = None, case: str | None = None) -> dict:
    entry = {
        "family": family,
        "version": signed.payload_version,
        "raw": raw if raw is not None else signed.model_dump(mode="json"),
        "canonical": signed._canonical_payload(),
        "hmac_key": HMAC_KEY,
    }
    if case:
        entry["case"] = case
    return entry


def _audit(version: int) -> AuditRecord:
    return AuditRecord(
        agent_id=AGENT,
        agent_version="1.0.0",
        tenant_id=TENANT,
        eval_result=_eval_result(),
        policies=["OSFI_E23"],
        controlbook_id="cb-osfi-e23",
        controlbook_version="2026.1",
        sequence_number=1,
        prev_hash="",
        key_id="k1",
        payload_version=version,
    ).sign(HMAC_KEY)


def _erased(record: AuditRecord) -> dict:
    # What a read serves after an approved erasure: no text, status set.
    raw = record.model_dump(mode="json")
    score = raw["eval_result"]["scores"][0]
    score["reason"] = ""
    score["reason_status"] = "ERASED"
    return raw


def build() -> list[dict]:
    out = [_entry("AuditRecord", _audit(v)) for v in (1, 2, 3)]
    v3 = _audit(3)
    out.append(_entry("AuditRecord", v3, _erased(v3), case="reason_erased"))

    out.append(
        _entry(
            "TombstoneRecord",
            TombstoneRecord(
                agent_id=AGENT,
                agent_version="1.0.0",
                tenant_id=TENANT,
                eval_result=_eval_result(),
                policies=["OSFI_E23"],
                operator_id="op-1",
                purged_at=datetime(2026, 9, 27, 2, 28, 31, tzinfo=UTC),
                purged_count=2,
                purged_trace_ids=["t2", "t1"],
                reason="right to erasure",
                subject_ref="ticket-1",
                requester_principal_id="principal:alice",
                payload_version=2,
                sequence_number=1,
                prev_hash="",
                key_id="k1",
            ).sign(HMAC_KEY),
        )
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
    ).sign(HMAC_KEY)
    out.append(_entry("AcceptedSetLease", lease))

    started = CallStartedRecord(
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
    ).sign(HMAC_KEY)
    out.append(_entry("CallStartedRecord", started))

    call = AgentCallRecord(
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
        call_signature_manifests={"sha256:" + "c" * 64: "raw manifest sidecar"},
        sequence_number=3,
        prev_hash="",
        key_id="k1",
    ).sign(HMAC_KEY)
    out.append(_entry("AgentCallRecord", call, case="manifest_sidecar"))

    cert = CertificationRecord(
        agent_id=AGENT,
        agent_version="1.0.0",
        tenant_id=TENANT,
        run_id=UUID("01a0e0ae-9261-7e42-8555-802b216f7a30"),
        certified_risk_tier="TIER_2",
        policies=["OSFI_E23"],
        gate_passed=True,
        certified_by="reviewer-1",
        run_payload_sha256="0" * 64,
        key_id="k1",
        payload_version=4,
    ).sign(HMAC_KEY)
    # Reserved after signing, as the store does for a certification whose
    # anchor is attached later; the signed bytes do not change.
    cert = cert.model_copy(update={"anchor_record_id": lease.record_id})
    out.append(_entry("CertificationRecord", cert, case="anchor_record_id"))
    return out


def main() -> None:
    path = Path(sys.argv[1])
    existing = json.loads(path.read_text())
    for new in build():
        case = new.get("case")
        for i, old in enumerate(existing):
            if old["family"] == new["family"] and old["version"] == new["version"]:
                if old.get("case") == case:
                    existing[i] = new
                    break
        else:
            existing.append(new)
    path.write_text(json.dumps(existing, indent=2) + "\n")
    print(f"Wrote {len(existing)} fixtures to {path}")


if __name__ == "__main__":
    main()

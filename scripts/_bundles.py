"""Assembles sengol-shaped evidence bundles from sengol's own classes.

Every record is built and signed by sengol (``_families``); every countersignature
and anchor receipt is sengol's own model dumped the way ``export_partition_bundle``
dumps it; the regression section comes from sengol's
``regression_evidence_section``. Nothing here goes through a store, because the
bundle is the exported shape, not the storage.
"""

from __future__ import annotations

import base64
import hashlib

from _families import AGENT, HMAC_KEY, KEY_ID, TENANT, _Filler
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ED25519_KEY_ID = "test-ed25519-key-1"


def public_pem(key: Ed25519PrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )


def payload_hash(record) -> str:
    return hashlib.sha256(record._canonical_payload().encode()).hexdigest()


def countersign(T, records, key: Ed25519PrivateKey) -> list[dict]:
    return [
        T.EvidenceCountersignature(
            record_id=r.record_id,
            tenant_id=r.tenant_id,
            agent_id=r.agent_id,
            payload_hash=payload_hash(r),
            key_id=ED25519_KEY_ID,
            signature=base64.b64encode(key.sign(bytes.fromhex(payload_hash(r)))).decode(),
        ).model_dump(mode="json")
        for r in records
    ]


def anchor(T, merkle_root, records) -> dict:
    leaves = [payload_hash(r) for r in records]
    return T.AnchorReceipt(
        tenant_id=records[0].tenant_id,
        agent_id=records[0].agent_id,
        merkle_root=merkle_root(leaves),
        leaf_count=len(leaves),
        seq_low=records[0].sequence_number,
        seq_high=records[-1].sequence_number,
        leaf_hashes=leaves,
    ).model_dump(mode="json")


def audit_families(T, versions: dict) -> list[str]:
    return [f for f in sorted(versions) if issubclass(getattr(T, f), T.AuditRecord)]


def chained(T, families, versions: dict, *, first_seq: int = 1, prev: str = "") -> list:
    """One signed record per family in one (tenant, agent) partition, hash-chained."""
    out = []
    for i, family in enumerate(families, start=first_seq):
        cls = getattr(T, family)
        extra = {
            "tenant_id": TENANT,
            "agent_id": AGENT,
            "sequence_number": i,
            "prev_hash": prev,
            "key_id": KEY_ID,
            "payload_version": max(versions[family]),
            # Stripped before a record is stored, so an export never carries it.
            "call_signature_manifests": None,
        }
        record = _Filler().model(cls, extra).sign(HMAC_KEY)
        prev = payload_hash(record)
        out.append(record)
    return out


def regression_chain(T) -> dict:
    """The signed failure -> case -> run -> certification lineage, by short name."""
    base = {"tenant_id": TENANT, "agent_id": AGENT, "key_id": KEY_ID}
    failure = _Filler().model(T.ProductionFailureRecord, base).sign(HMAC_KEY)
    case = (
        _Filler()
        .model(T.RegressionCaseRecord, {**base, "failure_id": str(failure.failure_id)})
        .sign(HMAC_KEY)
    )
    run = (
        _Filler()
        .model(
            T.EvaluationRunRecord,
            {
                **base,
                "agent_version": "1.0.0",
                "payload_version": 6,
                "total": 1,
                "passed": 1,
                "pass_rate": 1.0,
                "gate_passed": True,
                "case_results": [T.CaseResult(case_id=str(case.case_id), passed=True)],
            },
        )
        .sign(HMAC_KEY)
    )
    cert = (
        _Filler()
        .model(
            T.CertificationRecord,
            {
                **base,
                "agent_version": "1.0.0",
                "run_id": run.run_id,
                "run_payload_sha256": run.payload_sha256(),
            },
        )
        .sign(HMAC_KEY)
    )
    return {"failure": failure, "case": case, "run": run, "certification": cert}


def regression_entries(T) -> list[dict]:
    """The lineage as a bundle's entries, plus an unsigned retirement and waiver."""
    from sengol.governance.regression_store import (
        ProductionFailureWaiver,
        RegressionCaseRetirement,
    )

    chain = regression_chain(T)
    failure, case, run, cert = (chain[n] for n in ("failure", "case", "run", "certification"))
    retirement = RegressionCaseRetirement(
        tenant_id=TENANT, agent_id=AGENT, case_id=str(case.case_id), reason="r", retired_by="u"
    )
    waiver = ProductionFailureWaiver(
        tenant_id=TENANT,
        agent_id=AGENT,
        failure_id=str(failure.failure_id),
        reason="r",
        waived_by="u",
    )
    return [
        {"family": type(r).__name__, "record": r.model_dump(mode="json")}
        for r in (failure, case, retirement, waiver, run, cert)
    ]

"""Builds real sengol-signed test fixtures for sengol-verify's round-trip test.

Run from the sengol repo checkout so its real classes are importable:

    cd /home/user/sengol && uv run python \
        /home/user/sengol-verify/scripts/generate_fixture.py \
        /home/user/sengol-verify/tests/fixtures

This uses sengol's actual ``AuditRecord.sign()``, canonical payload functions,
and ``merkle_root`` to produce a genuinely signed, hash-chained, Ed25519
countersigned, Merkle-anchored bundle — not a hand-rolled approximation. It
does not require a running Postgres/API: the chain assignment a real ingest
call would do (sequence_number, prev_hash) is reproduced here by hand, using
the same hashing rule ``offline_verify`` checks against.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sengol.core.merkle import merkle_root
from sengol.core.types import AuditRecord, EvalResult, EvalScore

TENANT = "acme-bank"
AGENT = "loan-underwriter-bot"
HMAC_KEY_ID = "test-hmac-key-1"
HMAC_KEY_MATERIAL = "not-a-real-secret-do-not-reuse"
ED25519_KEY_ID = "test-ed25519-key-1"


def _eval_result(passed: bool) -> EvalResult:
    return EvalResult(
        agent_id=AGENT,
        agent_version="1.0.0",
        scores=[EvalScore(evaluator="PIIEvaluator", passed=passed, reason="fixture score")],
        overall_passed=passed,
        policies=["OSFI_E23"],
    )


def _build_chain(count: int) -> list[AuditRecord]:
    """Sign `count` AuditRecords chained exactly as a real store would."""
    records: list[AuditRecord] = []
    prev_hash = ""
    for i in range(1, count + 1):
        unsigned = AuditRecord(
            agent_id=AGENT,
            agent_version="1.0.0",
            tenant_id=TENANT,
            eval_result=_eval_result(passed=True),
            policies=["OSFI_E23"],
            controlbook_id="cb-osfi-e23",
            controlbook_version="2026.1",
            sequence_number=i,
            prev_hash=prev_hash,
            key_id=HMAC_KEY_ID,
            payload_version=3,
        )
        signed = unsigned.sign(HMAC_KEY_MATERIAL)
        records.append(signed)
        prev_hash = hashlib.sha256(signed._canonical_payload().encode()).hexdigest()
    return records


def _countersign(records: list[AuditRecord], priv_key: Ed25519PrivateKey) -> list[dict]:
    out = []
    for r in records:
        payload_hash = hashlib.sha256(r._canonical_payload().encode()).hexdigest()
        signature = priv_key.sign(bytes.fromhex(payload_hash))
        out.append(
            {
                "countersig_id": f"cs-{r.record_id}",
                "record_id": str(r.record_id),
                "tenant_id": TENANT,
                "agent_id": AGENT,
                "payload_hash": payload_hash,
                "algorithm": "ed25519",
                "key_id": ED25519_KEY_ID,
                "signature": base64.b64encode(signature).decode(),
            }
        )
    return out


def _anchor(records: list[AuditRecord]) -> dict:
    leaf_hashes = [hashlib.sha256(r._canonical_payload().encode()).hexdigest() for r in records]
    return {
        "anchor_id": "anchor-1",
        "tenant_id": TENANT,
        "agent_id": AGENT,
        "merkle_root": merkle_root(leaf_hashes),
        "leaf_count": len(leaf_hashes),
        "seq_low": records[0].sequence_number,
        "seq_high": records[-1].sequence_number,
        "leaf_hashes": leaf_hashes,
        "tsa_receipt": None,
        "tsa_url": None,
        "rekor_log_id": None,
    }


def build_bundle() -> dict:
    priv_key = Ed25519PrivateKey.generate()
    pub_pem = (
        priv_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )

    records = _build_chain(3)
    countersigs = _countersign(records, priv_key)
    anchor = _anchor(records)

    return {
        "tenant_id": TENANT,
        "agent_id": AGENT,
        "records": [r.model_dump(mode="json") for r in records],
        "countersignatures": countersigs,
        "anchor_receipts": [anchor],
        "public_keys": {ED25519_KEY_ID: pub_pem},
        "pending_countersignatures": 0,
    }


def main() -> None:
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("tests/fixtures")
    out_dir.mkdir(parents=True, exist_ok=True)

    bundle = build_bundle()
    (out_dir / "bundle.json").write_text(json.dumps(bundle, indent=2, default=str))

    # A bundle that ALSO embeds HMAC key material — real exports never do
    # this (the symmetric secret is withheld by design), but it proves the
    # HMAC check itself is correct, not just the Ed25519 countersig path.
    with_hmac = json.loads(json.dumps(bundle, default=str))
    with_hmac["public_keys"]["hmac_material"] = {HMAC_KEY_ID: HMAC_KEY_MATERIAL}
    (out_dir / "bundle_full_pass.json").write_text(json.dumps(with_hmac, indent=2))

    tampered = json.loads(json.dumps(bundle, default=str))
    # `passed` is signed; the score's `reason` text is not (sengol ADR-0078).
    tampered["records"][1]["eval_result"]["scores"][0]["passed"] = False
    (out_dir / "bundle_tampered.json").write_text(json.dumps(tampered, indent=2))

    chain_break = json.loads(json.dumps(bundle, default=str))
    chain_break["records"][2]["prev_hash"] = "0" * 64
    (out_dir / "bundle_chain_break.json").write_text(json.dumps(chain_break, indent=2))

    print(f"Wrote fixtures to {out_dir}")


if __name__ == "__main__":
    main()

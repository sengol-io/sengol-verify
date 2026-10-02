"""Regenerates every committed fixture from a sengol checkout.

    cd "$SENGOL" && uv run --with rfc8785 python \
        /path/to/sengol-verify/scripts/generate_fixtures.py "$SENGOL" \
        /path/to/sengol-verify/tests/fixtures

``SENGOL`` is the sengol checkout; the argument may be left out when the
``SENGOL_CHECKOUT`` environment variable names it. Run inside that checkout's
environment (the ``uv run`` above), because every record is built and signed by
sengol's own classes. The HMAC key is a throwaway label, not a secret; the
Ed25519 key is generated per run and only its public half is written.

Writes: ``canonical_fixtures.json`` (every registered family at every version),
``regression_chain_fixture.json``, ``bundle*.json`` (a small chain plus
tampered and broken variants), ``partition_bundle.json`` (every audit family in
one hash-chained partition, with regression evidence),
``judge_evidence_pack.json``, ``trusted_ed25519.pem`` and ``sengol_tables.json``.
Each bundle is checked by sengol's own ``verify_bundle`` before it is written.
"""

# ruff: noqa: I001, E402
# The checkout argument must reach sys.path before sengol is imported, so the
# import order below is deliberate.
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _setup() -> tuple[Path, Path]:
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    checkout = args[0] if args else os.environ.get("SENGOL_CHECKOUT")
    if not checkout:
        sys.exit("usage: generate_fixtures.py SENGOL_CHECKOUT [OUT_DIR]  (or set SENGOL_CHECKOUT)")
    sys.path.insert(0, str(Path(checkout).resolve()))
    sys.path.insert(0, str(HERE))
    out = Path(args[1]) if len(args) > 1 else HERE.parent / "tests" / "fixtures"
    return Path(checkout), out


CHECKOUT, OUT = _setup()

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import _bundles as B
import _families as F
import _tables as TB
import sengol.core.types as T
from sengol.core import payload_registry as P
from sengol.core.merkle import merkle_root
from sengol.governance.offline_verify import verify_bundle as sengol_verify
from sengol.governance.regression_evidence import regression_evidence_section
from sengol.judge_build.digests import JUDGE_CARD_SCOPE_STATEMENT

VERSIONS = P._VERSIONS
REASON_TEXT = "the customer wrote: my SIN is on file"


def _dump(name: str, data) -> None:
    (OUT / name).write_text(json.dumps(data, indent=2, default=str) + "\n")


def _entry(family, signed, version=None, raw=None, case=None) -> dict:
    entry = {
        "family": family,
        "version": version or signed.payload_version,
        "raw": raw if raw is not None else signed.model_dump(mode="json"),
        "canonical": signed._canonical_payload(),
        "hmac_key": F.HMAC_KEY,
    }
    if case:
        entry["case"] = case
    return entry


def canonical_fixtures() -> list[dict]:
    # Highest version first within a family, so a lookup by family finds the current shape.
    built = sorted(F.build_all(T, VERSIONS), key=lambda t: (t[0], -t[2]))
    out = [_entry(f, r, v) for f, r, v in built]
    call = next(r for f, r, v in built if f == "AgentCallRecord" and v == 4)
    out.append(_entry("AgentCallRecord", call, 4, case="manifest_sidecar"))
    audit = F._Filler().model(T.AuditRecord, {"payload_version": 3}).sign(F.HMAC_KEY)
    raw = audit.model_dump(mode="json")
    score = raw["eval_result"]["scores"][0]
    score["reason"], score["reason_status"] = "", "ERASED"
    out.append(_entry("AuditRecord", audit, 3, raw, "reason_erased"))
    scored = F._Filler().model(T.AuditRecord, {"payload_version": 3}).model_copy()
    scored = scored.model_copy(
        update={
            "eval_result": scored.eval_result.model_copy(
                update={
                    "scores": [
                        scored.eval_result.scores[0].model_copy(update={"reason": REASON_TEXT})
                    ]
                }
            )
        }
    ).sign(F.HMAC_KEY)
    out.append(_entry("AuditRecord", scored, 3, case="reason_text"))
    cert = F._Filler().model(T.CertificationRecord, {"payload_version": 4}).sign(F.HMAC_KEY)
    cert = cert.model_copy(update={"anchor_record_id": F._uuid(99)})
    out.append(_entry("CertificationRecord", cert, 4, case="anchor_record_id"))
    return out


def regression_chain() -> dict:
    return {n: _entry(type(r).__name__, r) for n, r in B.regression_chain(T).items()}


def simple_bundles(key, pub_pem) -> dict[str, dict]:
    records = [r.model_copy() for r in B.chained(T, ["AuditRecord"] * 3, {"AuditRecord": (3,)})]
    bundle = {
        "tenant_id": F.TENANT,
        "agent_id": F.AGENT,
        "records": [r.model_dump(mode="json") for r in records],
        "countersignatures": B.countersign(T, records, key),
        "anchor_receipts": [B.anchor(T, merkle_root, records)],
        "public_keys": {B.ED25519_KEY_ID: pub_pem},
        "pending_countersignatures": 0,
    }

    def variant(mutate):
        copy = json.loads(json.dumps(bundle))
        mutate(copy)
        return copy

    return {
        "bundle.json": bundle,
        "bundle_full_pass.json": variant(
            lambda b: b["public_keys"].update({"hmac_material": {F.KEY_ID: F.HMAC_KEY}})
        ),
        # `passed` is signed; the score's `reason` text is not.
        "bundle_tampered.json": variant(
            lambda b: b["records"][1]["eval_result"]["scores"][0].update({"passed": False})
        ),
        "bundle_chain_break.json": variant(
            lambda b: b["records"][2].update({"prev_hash": "0" * 64})
        ),
    }


def partition_bundle(key, pub_pem) -> dict:
    families = B.audit_families(T, VERSIONS)
    records = B.chained(T, families, VERSIONS)
    entries = B.regression_entries(T)
    bundle = {
        "tenant_id": F.TENANT,
        "agent_id": F.AGENT,
        "records": [r.model_dump(mode="json") for r in records],
        "countersignatures": B.countersign(T, records, key),
        "anchor_receipts": [B.anchor(T, merkle_root, records)],
        "public_keys": {B.ED25519_KEY_ID: pub_pem},
        "pending_countersignatures": 0,
        "regression_evidence": regression_evidence_section(F.AGENT, entries),
    }
    return bundle


def judge_pack(key, pub_pem) -> dict:
    # A sparse, portable pack: the card, a promotion decision and a SoD decision,
    # with the partition's intervening sequence numbers deliberately absent.
    cards = []
    for family, seq in (
        ("JudgeModelCard", 1),
        ("PromotionDecisionRecord", 4),
        ("SoDDecisionRecord", 8),
    ):
        cards += B.chained(T, [family], VERSIONS, first_seq=seq, prev="")
    # Make the card a passing one so the pack mirrors one sengol would assemble.
    card = cards[0]
    return {
        "judge_evidence_pack": {
            "schema_version": 1,
            "model_card_record_id": str(card.record_id),
            "agent_id": card.agent_id,
            "generated_at": "2026-09-27T02:28:31+00:00",
            "e23_section_index": {},
            "verdict": "UNVERIFIABLE",
            "scope_statement": JUDGE_CARD_SCOPE_STATEMENT,
        },
        "records": [r.model_dump(mode="json") for r in cards],
        "countersignatures": B.countersign(T, cards, key),
        "anchor_receipts": [B.anchor(T, merkle_root, cards)],
        "public_keys": {B.ED25519_KEY_ID: pub_pem},
    }


def self_check(name: str, bundle: dict, key_pem: str, *, portable: bool = False) -> None:
    """sengol's own verifier must not FAIL a genuine bundle it just exported."""
    expect_fail = name in ("bundle_tampered.json", "bundle_chain_break.json")
    result = sengol_verify(bundle, portable=portable, trusted_keys={B.ED25519_KEY_ID: key_pem})
    print(f"sengol verify_bundle {name}: {result.verdict}")
    if (result.verdict == "FAIL") != expect_fail:
        for step in result.step_results:
            print("  ", step.check, step.result, step.detail[:200])
        sys.exit(f"{name}: sengol's own verifier disagrees with the intended verdict")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = B.public_pem(key)

    _dump("canonical_fixtures.json", canonical_fixtures())
    _dump("regression_chain_fixture.json", regression_chain())
    for name, bundle in simple_bundles(key, pem).items():
        self_check(name, bundle, pem)
        _dump(name, bundle)
    part = partition_bundle(key, pem)
    self_check("partition_bundle.json", part, pem)
    _dump("partition_bundle.json", part)
    pack = judge_pack(key, pem)
    self_check("judge_evidence_pack.json", pack, pem, portable=True)
    _dump("judge_evidence_pack.json", pack)
    (OUT / "trusted_ed25519.pem").write_text(pem)
    tables = TB.sengol_tables(T, P)
    _dump("sengol_tables.json", tables)
    drift = TB.diff(tables, TB.vendored_tables())
    print("table drift vs sengol_verify:", drift or "none")
    print(f"wrote fixtures to {OUT} from {CHECKOUT}")


if __name__ == "__main__":
    main()

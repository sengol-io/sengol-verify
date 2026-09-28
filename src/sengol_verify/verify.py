"""Six-step offline bundle verification, ported from sengol's
``sengol/governance/offline_verify.py``. Recomputes every check over the
exact bytes reconstructed from the bundle's stored JSON — nothing here
normalizes a datetime or otherwise touches what was signed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Literal

import rfc8785

from sengol_verify.bundle import (
    load_bundle,
    reconstruct_anchors,
    reconstruct_countersigs,
    reconstruct_records,
)
from sengol_verify.canonical import Record, UnknownPayloadVersion
from sengol_verify.merkle import merkle_root

ResultStatus = Literal["PASS", "FAIL", "UNVERIFIABLE"]

__all__ = ["StepResult", "BundleResult", "verify_bundle", "verify_bundle_file"]


@dataclass
class StepResult:
    check: str
    scope: str
    result: ResultStatus
    detail: str = ""


@dataclass
class BundleResult:
    step_results: list = field(default_factory=list)

    @property
    def verdict(self) -> ResultStatus:
        if any(s.result == "FAIL" for s in self.step_results):
            return "FAIL"
        if any(s.result == "UNVERIFIABLE" for s in self.step_results):
            return "UNVERIFIABLE"
        return "PASS"


def verify_bundle_file(path) -> BundleResult:
    """Load and verify a bundle from a .json file, directory, or zip."""
    bundle = load_bundle(path)
    portable = "judge_evidence_pack" in bundle
    return verify_bundle(bundle, portable=portable)


def verify_bundle(bundle: dict, *, portable: bool = False) -> BundleResult:
    """Verify all six checks against an export bundle dict.

    ``portable=True`` tolerates the deliberate sequence-number gaps in a
    sparse JudgeEvidencePack instead of treating every gap as a break.
    """
    records = reconstruct_records(bundle)
    countersigs = reconstruct_countersigs(bundle)
    anchors = reconstruct_anchors(bundle)
    public_keys: dict = bundle.get("public_keys", {})

    results = [
        _check_payload_hashes(records, countersigs),
        _check_hmac(records, public_keys),
        _check_chain_continuity(records, portable=portable),
        _check_countersigs(records, countersigs, public_keys),
        _check_anchors(records, anchors),
        _check_field_coverage(records),
    ]
    if bundle.get("regression_evidence") is not None:
        results.append(_check_regression_lineage(bundle["regression_evidence"], public_keys))
    return BundleResult(step_results=results)


def _check_field_coverage(records: list) -> StepResult:
    """Step 6: no record carries a field its payload_version does not sign."""
    failures = []
    for record in records:
        unsigned = record.unsigned_fields()
        if unsigned:
            failures.append(f"{record.record_id}: {sorted(unsigned)}")

    if failures:
        return StepResult(
            check="field_coverage",
            scope=f"{len(records)} records",
            result="FAIL",
            detail=(
                "Record carries a field its payload_version does not sign, so "
                "the value is outside the signature and may have been altered "
                f"at rest: {failures}"
            ),
        )
    return StepResult(
        check="field_coverage",
        scope=f"{len(records)} records",
        result="PASS",
        detail="No record populates a field below the payload_version that signs it.",
    )


def _payload(record) -> str | None:
    """The record's canonical payload, or ``None`` when it has none.

    A record with a value RFC 8785 cannot encode, or a payload version this
    verifier does not know, cannot have been signed as it stands; each step
    counts it as a failure rather than letting the exception end the run.
    """
    try:
        return record.canonical_payload()
    except (rfc8785.CanonicalizationError, UnknownPayloadVersion):
        return None


def _payload_hash(record) -> str | None:
    payload = _payload(record)
    return None if payload is None else hashlib.sha256(payload.encode()).hexdigest()


def _check_payload_hashes(records: list, countersigs: list) -> StepResult:
    """Step 1: each record's live payload hash matches a stored countersig."""
    committed: dict = {}
    for cs in countersigs:
        committed.setdefault(cs.record_id, set()).add(cs.payload_hash)

    failures = []
    uncovered = []

    for record in records:
        live_hash = _payload_hash(record)
        if live_hash is None:
            failures.append(record.record_id)
            continue
        stored = committed.get(record.record_id)
        if stored is None:
            uncovered.append(record.record_id)
            continue
        if live_hash not in stored:
            failures.append(record.record_id)

    if failures:
        return StepResult(
            check="payload_hash_integrity",
            scope=f"{len(records)} records",
            result="FAIL",
            detail=f"Payload hash mismatch: {failures}",
        )
    if uncovered:
        return StepResult(
            check="payload_hash_integrity",
            scope=f"{len(records)} records",
            result="UNVERIFIABLE",
            detail=(
                f"{len(uncovered)} records have no countersignature in this "
                "bundle — often a countersign outbox that had not drained "
                "yet at export time, not tampering. Re-export and re-verify."
            ),
        )
    return StepResult(
        check="payload_hash_integrity",
        scope=f"{len(records)} records",
        result="PASS",
        detail=f"{len(records)} records verified",
    )


def _check_hmac(records: list, public_keys: dict) -> StepResult:
    """Step 2: HMAC verify for records whose key material is in the bundle.

    A bundle never ships HMAC key material by design — only key_id and
    metadata — unless the exporting deployment deliberately embedded it
    under ``public_keys["hmac_material"]``. Absent that, every record here
    is UNVERIFIABLE by HMAC and integrity rests on the Ed25519 countersigs.
    """
    failures = []
    unverifiable = []

    hmac_material: dict = public_keys.get("hmac_material", {})

    for record in records:
        key_material = hmac_material.get(record.key_id)
        if key_material is None:
            unverifiable.append(record.record_id)
            continue
        payload = _payload(record)
        if payload is None:
            failures.append(record.record_id)
            continue
        expected = _hmac.new(
            key_material.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()
        if not _hmac.compare_digest(expected, record.hmac_signature):
            failures.append(record.record_id)

    if failures:
        return StepResult(
            check="hmac_verify",
            scope="all_records",
            result="FAIL",
            detail=f"HMAC mismatch for record_ids: {failures}",
        )
    if unverifiable:
        return StepResult(
            check="hmac_verify",
            scope="all_records",
            result="UNVERIFIABLE",
            detail=(
                f"HMAC key material absent for {len(unverifiable)} records "
                "(key material is not exported for security)"
            ),
        )
    return StepResult(
        check="hmac_verify",
        scope="all_records",
        result="PASS",
        detail=f"{len(records)} records verified",
    )


def _check_chain_continuity(records: list, *, portable: bool = False) -> StepResult:
    """Step 3: sequence_number monotone, prev_hash links correct."""
    partitions: dict = defaultdict(list)
    for r in records:
        if r.sequence_number > 0:
            partitions[(r.tenant_id, r.agent_id)].append(r)

    gaps = []
    hash_mismatches = []
    partial_starts = []
    sparse_boundaries = []

    for (tenant_id, agent_id), chain in partitions.items():
        chain.sort(key=lambda r: r.sequence_number)
        prev_hash = ""
        for idx, record in enumerate(chain):
            if idx == 0:
                if record.sequence_number > 1:
                    prev_hash = record.prev_hash
                    partial_starts.append(f"{tenant_id}/{agent_id}@seq={record.sequence_number}")
                elif record.prev_hash != "":
                    hash_mismatches.append(f"{tenant_id}/{agent_id}@seq={record.sequence_number}")
            else:
                adjacent = record.sequence_number == chain[idx - 1].sequence_number + 1
                if portable and not adjacent:
                    sparse_boundaries.append(f"{tenant_id}/{agent_id}@seq={record.sequence_number}")
                else:
                    if record.prev_hash != prev_hash:
                        hash_mismatches.append(
                            f"{tenant_id}/{agent_id}@seq={record.sequence_number}"
                        )
                    if not adjacent:
                        gaps.append(f"{tenant_id}/{agent_id}: gap at seq {record.sequence_number}")
            prev_hash = _payload_hash(record)

    issues = []
    if gaps:
        issues.append(f"gaps: {gaps}")
    if hash_mismatches:
        issues.append(f"hash_mismatches: {hash_mismatches}")

    if issues:
        return StepResult(
            check="chain_continuity",
            scope="all_partitions",
            result="FAIL",
            detail="; ".join(issues),
        )

    detail = f"{len(partitions)} partition(s) verified"
    if partial_starts:
        detail += f" (partial bundle — chain starts mid-sequence at: {partial_starts})"
    if sparse_boundaries:
        detail += f" (sparse pack — expected gaps at: {sparse_boundaries})"
    return StepResult(
        check="chain_continuity", scope="all_partitions", result="PASS", detail=detail
    )


def _check_countersigs(records: list, countersigs: list, public_keys: dict) -> StepResult:
    """Step 4: verify Ed25519 countersignatures over each record's payload hash."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    if not countersigs:
        if records:
            return StepResult(
                check="ed25519_countersig",
                scope="all_countersigs",
                result="UNVERIFIABLE",
                detail=(
                    f"No countersignatures in bundle for {len(records)} "
                    "record(s) — often a countersign outbox that had not "
                    "drained at export time, not tampering. Re-export and "
                    "re-verify."
                ),
            )
        return StepResult(
            check="ed25519_countersig",
            scope="all_countersigs",
            result="PASS",
            detail="No countersignatures in bundle",
        )

    failures = []
    unverifiable = []
    record_map = {r.record_id: r for r in records}

    for cs in countersigs:
        pem_str = public_keys.get(cs.key_id, "")
        if not pem_str:
            unverifiable.append(cs.countersig_id)
            continue
        try:
            pub_key = load_pem_public_key(pem_str.encode())
            if not isinstance(pub_key, Ed25519PublicKey):
                failures.append(cs.countersig_id)
                continue

            sig_bytes = base64.b64decode(cs.signature)
            hash_bytes = bytes.fromhex(cs.payload_hash)
            pub_key.verify(sig_bytes, hash_bytes)

            record = record_map.get(cs.record_id)
            if record is not None:
                expected_hash = _payload_hash(record)
                if cs.payload_hash != expected_hash:
                    failures.append(cs.countersig_id)
        except InvalidSignature:
            failures.append(cs.countersig_id)
        except Exception:
            failures.append(cs.countersig_id)

    if failures:
        return StepResult(
            check="ed25519_countersig",
            scope="all_countersigs",
            result="FAIL",
            detail=f"Invalid countersigs: {failures}",
        )
    if unverifiable:
        return StepResult(
            check="ed25519_countersig",
            scope="all_countersigs",
            result="UNVERIFIABLE",
            detail=f"Key not in bundle for countersig_ids: {unverifiable}",
        )
    return StepResult(
        check="ed25519_countersig",
        scope="all_countersigs",
        result="PASS",
        detail=f"{len(countersigs)} countersig(s) verified",
    )


def _check_anchors(records: list, anchors: list) -> StepResult:
    """Step 5: Merkle root recomputation + anchor receipt coverage."""
    if not anchors:
        if records:
            return StepResult(
                check="anchor_coverage",
                scope="0 anchors",
                result="UNVERIFIABLE",
                detail="No anchor receipts in bundle — anchoring may be pending or disabled",
            )
        return StepResult(
            check="anchor_coverage", scope="0 anchors", result="PASS", detail="No records to anchor"
        )

    failures = []
    for receipt in anchors:
        try:
            computed_root = merkle_root(receipt.leaf_hashes)
            if computed_root != receipt.merkle_root:
                failures.append(f"anchor {receipt.anchor_id}: merkle_root mismatch")
        except Exception as exc:
            failures.append(f"anchor {receipt.anchor_id}: error computing merkle root: {exc}")

        if len(receipt.leaf_hashes) != receipt.leaf_count:
            failures.append(
                f"anchor {receipt.anchor_id}: leaf_count={receipt.leaf_count} "
                f"but {len(receipt.leaf_hashes)} hashes"
            )

        if receipt.tsa_receipt is not None:
            try:
                base64.b64decode(receipt.tsa_receipt)
            except Exception:
                failures.append(f"anchor {receipt.anchor_id}: tsa_receipt is not valid base64")

    if failures:
        return StepResult(
            check="anchor_coverage", scope="all_anchors", result="FAIL", detail="; ".join(failures)
        )
    return StepResult(
        check="anchor_coverage",
        scope="all_anchors",
        result="PASS",
        detail=f"{len(anchors)} anchor receipt(s) verified",
    )


#: Each regression family's own id field (its records carry no ``record_id``).
# Field each family is labelled by in messages. Retirements and waivers
# carry no id of their own, so they are labelled by what they reference;
# only failures, cases and runs are link targets and must be unique.
_REGRESSION_ID_FIELD = {
    "ProductionFailureRecord": "failure_id",
    "RegressionCaseRecord": "case_id",
    "RegressionCaseRetirementRecord": "case_id",
    "ProductionFailureWaiverRecord": "failure_id",
    "EvaluationRunRecord": "run_id",
    "CertificationRecord": "cert_id",
}
_REGRESSION_LINK_TARGETS = frozenset(
    {"ProductionFailureRecord", "RegressionCaseRecord", "EvaluationRunRecord"}
)
_REGRESSION_FORMAT = "sengol-regression-evidence/v1"
_REGRESSION_SCOPE = (
    "regression_evidence section; records are signed but not chained "
    "(ADR-0019), so deletion of a record is not detectable"
)


def _check_regression_lineage(section: dict, public_keys: dict) -> StepResult:
    """Regression evidence: format, agent, family, signature, field coverage
    and id links."""
    if not isinstance(section, dict):
        return StepResult(
            "regression_lineage", _REGRESSION_SCOPE, "FAIL", "section is not an object"
        )
    if section.get("format") != _REGRESSION_FORMAT:
        return StepResult(
            "regression_lineage",
            _REGRESSION_SCOPE,
            "FAIL",
            f"unsupported format {section.get('format')!r}; expected {_REGRESSION_FORMAT!r}",
        )
    entries = section.get("records", [])
    if not isinstance(entries, list):
        return StepResult("regression_lineage", _REGRESSION_SCOPE, "FAIL", "records is not a list")
    agent_id = section.get("agent_id")
    problems: list = []
    allrecs: list = []
    by_family: dict = defaultdict(list)
    recs: dict = defaultdict(dict)  # link-target family -> id -> Record
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("record"), dict):
            problems.append("malformed entry (not a {family, record} object)")
            continue
        family = entry.get("family")
        if family not in _REGRESSION_ID_FIELD:
            problems.append(f"unknown family {family!r}")
            continue
        rec = Record(entry["record"], family)
        if rec._raw.get("agent_id") != agent_id:
            problems.append(
                f"{family} {rec._raw.get(_REGRESSION_ID_FIELD[family], '')}: agent_id "
                f"{rec._raw.get('agent_id')!r} is not the section's {agent_id!r}"
            )
        allrecs.append(rec)
        by_family[family].append(rec)
        if family in _REGRESSION_LINK_TARGETS:
            rid = str(rec._raw.get(_REGRESSION_ID_FIELD[family], ""))
            if not rid or rid in recs[family]:
                problems.append(f"{family}: missing or duplicate id {rid!r}")
            recs[family][rid] = rec

    material = public_keys.get("hmac_material", {})
    unverifiable = 0
    for r in allrecs:
        rid = f"{r.family} {r._raw.get(_REGRESSION_ID_FIELD[r.family], '')}"
        payload = _payload(r)
        if payload is None:
            problems.append(f"{rid}: no canonical payload")
        elif (key := material.get(r.key_id)) is None:
            unverifiable += 1
        elif not _hmac.compare_digest(
            _hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest(),
            r.hmac_signature,
        ):
            problems.append(f"{rid}: HMAC mismatch")
        if r.unsigned_fields():
            problems.append(f"{rid}: unsigned fields {sorted(r.unsigned_fields())}")

    def dangling(kind, ref_id, owner, target_family):
        if str(ref_id) not in recs[target_family]:
            problems.append(f"{kind} {owner} references missing {target_family} {ref_id}")

    for c in recs["RegressionCaseRecord"].values():
        dangling("case", c.failure_id, c.case_id, "ProductionFailureRecord")
    for x in by_family["RegressionCaseRetirementRecord"]:
        dangling("retirement", x.case_id, "", "RegressionCaseRecord")
    for w in by_family["ProductionFailureWaiverRecord"]:
        dangling("waiver", w.failure_id, "", "ProductionFailureRecord")
    for run in recs["EvaluationRunRecord"].values():
        for cr in run.case_results or []:
            if not isinstance(cr, dict):
                problems.append(f"run {run.run_id}: malformed case_results entry {cr!r}")
                continue
            dangling("run", cr.get("case_id"), run.run_id, "RegressionCaseRecord")
    for cert in by_family["CertificationRecord"]:
        run = recs["EvaluationRunRecord"].get(str(cert.run_id))
        if run is None:
            problems.append(
                f"certification {cert.cert_id} references missing EvaluationRunRecord {cert.run_id}"
            )
        elif cert.run_payload_sha256 and _payload_hash(run) != cert.run_payload_sha256:
            problems.append(
                f"certification {cert.cert_id}: run_payload_sha256 does not match "
                f"EvaluationRunRecord {cert.run_id}"
            )

    scope = f"{len(entries)} records; {_REGRESSION_SCOPE}"
    if problems:
        return StepResult("regression_lineage", scope, "FAIL", "; ".join(problems))
    if unverifiable:
        return StepResult(
            "regression_lineage",
            scope,
            "UNVERIFIABLE",
            f"Links and field coverage verified; HMAC key material absent "
            f"for {unverifiable} records",
        )
    return StepResult(
        "regression_lineage", scope, "PASS", f"{len(entries)} records verified, all links resolve"
    )

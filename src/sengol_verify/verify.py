"""Offline bundle verification, ported from sengol's
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
from sengol_verify.canonical import (
    Record,
    UnknownPayloadVersion,
    UnknownRecordType,
    unsigned_field_paths,
)
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


def verify_bundle_file(path, *, trusted_keys: dict | None = None) -> BundleResult:
    """Load and verify a bundle from a .json file, directory, or zip."""
    bundle = load_bundle(path)
    portable = "judge_evidence_pack" in bundle
    return verify_bundle(bundle, portable=portable, trusted_keys=trusted_keys)


def verify_bundle(
    bundle: dict,
    *,
    portable: bool = False,
    trusted_keys: dict | None = None,
) -> BundleResult:
    """Verify an export bundle dict (the checks named in the README).

    ``portable=True`` tolerates the deliberate sequence-number gaps in a
    sparse JudgeEvidencePack instead of treating every gap as a break.

    ``trusted_keys`` is a ``{key_id: pem}`` map the caller obtained out of
    band, never read from the bundle. Omitted (``None``), the countersignature
    step still checks each signature against the bundle's own embedded key but
    reports at most UNVERIFIABLE: a key the file supplies proves it is
    internally consistent, not where it came from. Supplied (even ``{}``),
    it is the only key material trusted: a countersignature whose ``key_id``
    is absent from it, or whose key does not verify it, FAILs.
    """
    records = reconstruct_records(bundle)
    countersigs = reconstruct_countersigs(bundle)
    anchors = reconstruct_anchors(bundle)
    public_keys: dict = bundle.get("public_keys", {})

    results = [
        _check_canonicalizable(records),
        _check_payload_hashes(records, countersigs),
        _check_hmac(records, public_keys),
        _check_chain_continuity(records, portable=portable),
        _check_countersigs(records, countersigs, public_keys, trusted_keys),
        _check_anchors(records, anchors),
        _check_field_coverage(records),
        _check_signed_field_presence(records),
    ]
    if bundle.get("regression_evidence") is not None:
        results.append(_check_regression_lineage(bundle["regression_evidence"], public_keys))
    return BundleResult(step_results=results)


def _check_canonicalizable(records: list) -> StepResult:
    """Step 0: every record has a canonical payload.

    A value with no RFC 8785 form (NaN, infinity, an integer beyond 2**53), an
    unregistered payload version or an unregistered ``record_type`` cannot
    have been signed as it stands. The failing records are named here; the
    later steps that recompute the payload fail them too.
    """
    failures = []
    for record in records:
        try:
            record.canonical_payload()
        except (rfc8785.CanonicalizationError, UnknownPayloadVersion, UnknownRecordType) as exc:
            failures.append(f"{record.record_id}: {exc}")
    scope = f"{len(records)} records"
    if failures:
        return StepResult(
            "canonical_payload",
            scope,
            "FAIL",
            "record(s) with no canonical payload: " + "; ".join(failures),
        )
    return StepResult("canonical_payload", scope, "PASS")


#: Keys this verifier reads with a default when a record lacks them. A record
#: missing one would otherwise be verified as if it carried the default; the
#: join key ``record_id`` is the sharpest case, since a record without it
#: matches no countersignature and reads as merely "not countersigned yet".
_DEFAULTED_KEYS = (
    "record_id",
    "tenant_id",
    "agent_id",
    "sequence_number",
    "prev_hash",
    "key_id",
    "payload_version",
)


def _check_signed_field_presence(records: list) -> StepResult:
    """Step 7: no key this verifier would fill with a default is missing.

    Nothing here is refilled from a model default: a deleted signed key leaves
    the recomputed bytes short of what was signed, and the payload hash or HMAC
    step fails on it. The exception is a key the verifier itself reads with a
    default (``_DEFAULTED_KEYS``), which this step requires to be present.
    """
    failures = []
    for record in records:
        missing = [k for k in _DEFAULTED_KEYS if record._raw.get(k) is None]
        if missing:
            failures.append(f"{record._raw.get('record_id')!r}: {', '.join(missing)}")
    scope = f"{len(records)} records"
    if failures:
        return StepResult(
            "signed_field_presence",
            scope,
            "FAIL",
            "key(s) missing from the bundle: " + "; ".join(failures),
        )
    return StepResult("signed_field_presence", scope, "PASS")


def _check_field_coverage(records: list) -> StepResult:
    """Step 6: name the set fields that sit outside each record's signature.

    Every set field is signed except the signature fields, a family's
    unsigned fields and the nested paths ``canonical`` leaves out (an
    evaluator score's ``reason`` and ``reason_status``), so steps 1-5 already
    cover everything else. This step reports which by-design unsigned values
    the bundle's records carry, so an examiner knows which values no check
    vouches for. It reports and never fails.
    """
    fields = sorted({path for record in records for path in unsigned_field_paths(record)})
    detail = (
        "Every set field is inside the signature except these, which are "
        f"unsigned by design and not vouched for by any step: {fields}"
    )
    unregistered = sum(1 for record in records if record.family is None)
    if unregistered:
        detail += (
            f". {unregistered} record(s) with a record_type not registered in "
            "this verifier are not assessed"
        )
    return StepResult(
        check="field_coverage",
        scope=f"{len(records)} records",
        result="PASS",
        detail=detail,
    )


def _payload(record) -> str | None:
    """The record's canonical payload, or ``None`` when it has none.

    A record with a value RFC 8785 cannot encode, a payload version this
    verifier does not know, or a ``record_type`` it does not register cannot
    have been signed as it stands; each step counts it as a failure rather
    than letting the exception end the run.
    """
    try:
        return record.canonical_payload()
    except (rfc8785.CanonicalizationError, UnknownPayloadVersion, UnknownRecordType):
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
    unregistered = {}

    for record in records:
        live_hash = _payload_hash(record)
        if live_hash is None:
            failures.append(record.record_id)
            if record.family is None:
                unregistered[record.record_id] = record.record_type
            continue
        stored = committed.get(record.record_id)
        if stored is None:
            uncovered.append(record.record_id)
            continue
        if live_hash not in stored:
            failures.append(record.record_id)

    if failures:
        detail = f"Payload hash mismatch: {failures}"
        if unregistered:
            detail += (
                "; record_type not registered in this verifier, so these records "
                f"have no canonical payload (record_id: record_type): {unregistered}"
            )
        return StepResult(
            check="payload_hash_integrity",
            scope=f"{len(records)} records",
            result="FAIL",
            detail=detail,
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


def _check_countersigs(
    records: list, countersigs: list, public_keys: dict, trusted_keys: dict | None = None
) -> StepResult:
    """Step 4: verify Ed25519 countersignatures over each record's payload hash.

    ``trusted_keys`` supplied (``{}`` counts) is the only key material used,
    looked up by the countersignature's ``key_id``; a ``key_id`` it lacks
    FAILs. Omitted, the bundle's own ``public_keys`` serve as a tamper signal
    and a clean result is capped at UNVERIFIABLE.
    """
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
    untrusted = []
    record_map = {r.record_id: r for r in records}
    has_trust_anchor = trusted_keys is not None

    for cs in countersigs:
        if has_trust_anchor:
            pem_str = trusted_keys.get(cs.key_id, "")  # type: ignore[union-attr]
            if not pem_str:
                failures.append(f"{cs.countersig_id} (key_id {cs.key_id!r} not in trusted keys)")
                continue
        else:
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
                    continue
        except Exception:
            failures.append(cs.countersig_id)
            continue
        if not has_trust_anchor:
            untrusted.append(cs.countersig_id)

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
    if untrusted:
        return StepResult(
            check="ed25519_countersig",
            scope="all_countersigs",
            result="UNVERIFIABLE",
            detail=(
                f"{len(untrusted)} countersig(s) are valid against the public key embedded in "
                "this same bundle, but no trusted key was supplied to check them against: "
                "whoever produced this file could have minted that key. Supply the "
                "appliance's public key from an out-of-band source with --trusted-key "
                "KEY_ID=PEM_PATH or --trusted-keys-file to attribute this evidence."
            ),
        )
    return StepResult(
        check="ed25519_countersig",
        scope="all_countersigs",
        result="PASS",
        detail=f"{len(countersigs)} countersig(s) verified against a trusted key",
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


# Field each signed family is labelled by in messages; only failures, cases
# and runs are link targets and must be unique.
_REGRESSION_ID_FIELD = {
    "ProductionFailureRecord": "failure_id",
    "RegressionCaseRecord": "case_id",
    "EvaluationRunRecord": "run_id",
    "CertificationRecord": "cert_id",
}
# Retirements and waivers are unsigned operator judgements (sengol
# ADR-0024): they carry no HMAC, so only their agent and links are checked.
# The signed retirement and waiver families are not registered, so an entry
# naming one is an unknown family.
_UNSIGNED_REGRESSION_FAMILIES = {
    "RegressionCaseRetirement": "case_id",
    "ProductionFailureWaiver": "failure_id",
}
_REGRESSION_LINK_TARGETS = frozenset(
    {"ProductionFailureRecord", "RegressionCaseRecord", "EvaluationRunRecord"}
)
_REGRESSION_FORMAT = "sengol-regression-evidence/v1"
_REGRESSION_SCOPE = (
    "regression_evidence section; records are signed but not chained "
    "(ADR-0019), so deletion of a record is not detectable; unsigned "
    "retirements and waivers are link-checked only"
)


def _check_regression_lineage(section: dict, public_keys: dict) -> StepResult:
    """Regression evidence: format, agent, family, signature and id links."""
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
        if isinstance(family, str) and family in _UNSIGNED_REGRESSION_FAMILIES:
            raw = entry["record"]
            if raw.get("agent_id") != agent_id:
                problems.append(
                    f"{family} {raw.get(_UNSIGNED_REGRESSION_FAMILIES[family], '')}: "
                    f"agent_id {raw.get('agent_id')!r} is not the section's {agent_id!r}"
                )
            by_family[family].append(raw)
            continue
        if not isinstance(family, str) or family not in _REGRESSION_ID_FIELD:
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
        elif not isinstance(r.hmac_signature, str) or not _hmac.compare_digest(
            _hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest(),
            r.hmac_signature,
        ):
            problems.append(f"{rid}: HMAC mismatch")

    def dangling(kind, ref_id, owner, target_family):
        if str(ref_id) not in recs[target_family]:
            problems.append(f"{kind} {owner} references missing {target_family} {ref_id}")

    for c in recs["RegressionCaseRecord"].values():
        dangling("case", c.failure_id, c.case_id, "ProductionFailureRecord")
    for x in by_family["RegressionCaseRetirement"]:
        dangling("retirement", x.get("case_id"), "", "RegressionCaseRecord")
    for w in by_family["ProductionFailureWaiver"]:
        dangling("waiver", w.get("failure_id"), "", "ProductionFailureRecord")
    for run in recs["EvaluationRunRecord"].values():
        results = run.case_results or []
        if not isinstance(results, list):
            problems.append(f"run {run.run_id}: case_results is not a list")
            continue
        for cr in results:
            if not isinstance(cr, dict):
                problems.append(f"run {run.run_id}: malformed case_results entry {cr!r}")
                continue
            dangling("run", cr.get("case_id"), run.run_id, "RegressionCaseRecord")
    for cert in by_family["CertificationRecord"]:
        if not cert.run_payload_sha256:
            problems.append(
                f"certification {cert.cert_id}: run_payload_sha256 is missing, so it binds no run"
            )
        run = recs["EvaluationRunRecord"].get(str(cert.run_id))
        if run is None:
            problems.append(
                f"certification {cert.cert_id} references missing EvaluationRunRecord {cert.run_id}"
            )
        else:
            if cert.run_payload_sha256 and _payload_hash(run) != cert.run_payload_sha256:
                problems.append(
                    f"certification {cert.cert_id}: run_payload_sha256 does not match "
                    f"EvaluationRunRecord {cert.run_id}"
                )
            if cert._raw.get("agent_version") != run._raw.get("agent_version"):
                problems.append(
                    f"certification {cert.cert_id}: agent_version "
                    f"{cert._raw.get('agent_version')!r} is not the run's "
                    f"{run._raw.get('agent_version')!r}"
                )

    scope = f"{len(entries)} records; {_REGRESSION_SCOPE}"
    if problems:
        return StepResult("regression_lineage", scope, "FAIL", "; ".join(problems))
    if unverifiable:
        return StepResult(
            "regression_lineage",
            scope,
            "UNVERIFIABLE",
            f"Links verified; HMAC key material absent for {unverifiable} records",
        )
    return StepResult(
        "regression_lineage", scope, "PASS", f"{len(entries)} records verified, all links resolve"
    )

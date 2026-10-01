"""Loads a sengol evidence bundle from a JSON file, a directory, or a zip.

``sengol audit export`` writes a single self-contained JSON file:
``{"records": [...], "countersignatures": [...], "anchor_receipts": [...],
"public_keys": {...}}`` (optionally with "pending_countersignatures" and,
for a JudgeEvidencePack, a "judge_evidence_pack" envelope key). This module
accepts that file directly, a zip containing exactly one such JSON file, or
a directory containing one.
"""

from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass
from pathlib import Path

from sengol_verify.canonical import Record, UnknownRecordType, family_for

__all__ = [
    "Countersignature",
    "AnchorReceipt",
    "load_bundle",
    "reconstruct_records",
    "reconstruct_countersigs",
    "reconstruct_anchors",
]


@dataclass(frozen=True)
class Countersignature:
    countersig_id: str
    record_id: str
    tenant_id: str
    agent_id: str
    payload_hash: str
    algorithm: str
    key_id: str
    signature: str


@dataclass(frozen=True)
class AnchorReceipt:
    anchor_id: str
    tenant_id: str
    agent_id: str
    merkle_root: str
    leaf_count: int
    seq_low: int
    seq_high: int
    leaf_hashes: list
    tsa_receipt: str | None = None
    tsa_url: str | None = None
    rekor_log_id: str | None = None


class BundleFormatError(ValueError):
    """The given path does not contain a single, readable bundle JSON."""


def _read_json_bundle(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        raise BundleFormatError(f"{path}: not valid JSON ({exc})") from exc


def load_bundle(path: Path) -> dict:
    """Return the bundle dict for a .json file, a directory, or a zip."""
    if path.is_dir():
        candidates = sorted(path.glob("*.json"))
        if len(candidates) != 1:
            raise BundleFormatError(
                f"{path}: expected exactly one .json file, found {len(candidates)}"
            )
        return _read_json_bundle(candidates[0])

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            names = [n for n in zf.namelist() if n.endswith(".json")]
            if len(names) != 1:
                raise BundleFormatError(
                    f"{path}: expected exactly one .json member, found {len(names)}"
                )
            with zf.open(names[0]) as fh:
                try:
                    return json.loads(fh.read())
                except Exception as exc:
                    raise BundleFormatError(f"{path}: not valid JSON ({exc})") from exc

    return _read_json_bundle(path)


def _record(raw: dict) -> Record:
    try:
        return Record(raw, family_for(raw))
    except UnknownRecordType:
        return Record(raw, None)


def reconstruct_records(bundle: dict) -> list:
    """One ``Record`` per bundle record. A record whose ``record_type`` is not
    registered gets ``family=None``: it is kept, so verification reports it,
    but it has no canonical payload."""
    return [_record(raw) for raw in bundle.get("records", [])]


def reconstruct_countersigs(bundle: dict) -> list:
    out = []
    for raw in bundle.get("countersignatures", []):
        out.append(
            Countersignature(
                countersig_id=str(raw.get("countersig_id", "")),
                record_id=str(raw.get("record_id", "")),
                tenant_id=raw.get("tenant_id", ""),
                agent_id=raw.get("agent_id", ""),
                payload_hash=raw.get("payload_hash", ""),
                algorithm=raw.get("algorithm", "ed25519"),
                key_id=raw.get("key_id", ""),
                signature=raw.get("signature", ""),
            )
        )
    return out


def reconstruct_anchors(bundle: dict) -> list:
    out = []
    for raw in bundle.get("anchor_receipts", []):
        out.append(
            AnchorReceipt(
                anchor_id=str(raw.get("anchor_id", "")),
                tenant_id=raw.get("tenant_id", ""),
                agent_id=raw.get("agent_id", ""),
                merkle_root=raw.get("merkle_root", ""),
                leaf_count=raw.get("leaf_count", 0),
                seq_low=raw.get("seq_low", 0),
                seq_high=raw.get("seq_high", 0),
                leaf_hashes=list(raw.get("leaf_hashes", [])),
                tsa_receipt=raw.get("tsa_receipt"),
                tsa_url=raw.get("tsa_url"),
                rekor_log_id=raw.get("rekor_log_id"),
            )
        )
    return out

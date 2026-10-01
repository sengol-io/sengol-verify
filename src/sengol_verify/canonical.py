"""Canonical signed-payload rule, vendored from sengol's
``sengol/core/payload_registry.py`` (ADR-0019).

One rule signs every record: RFC 8785 (JSON Canonicalization Scheme) over
``{"record": <fields>, "type": "<family>"}``, where ``<fields>`` is the
record's JSON-mode values minus the signature fields and the family's
``UNSIGNED_FIELDS``. The per-family/per-version tables below (``_VERSIONS``,
``_UNSIGNED_FIELDS``, ``_NESTED_UNSIGNED_FIELDS``, ``_UNORDERED_FIELDS``)
mirror ``sengol/core/types.py`` and ``payload_registry.py`` —
changing one here would make this tool disagree with sengol about what a
genuine signature covers.

This module has no import on the ``sengol`` package. ``Record`` duck-types
attribute access over a plain dict reconstructed from stored/exported JSON,
which is what ``canonical_payload`` actually reads (via ``record._raw``).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import rfc8785

__all__ = [
    "Record",
    "canonical_payload",
    "UnknownPayloadVersion",
    "UnknownRecordType",
    "unsigned_fields_below_floor",
    "RECORD_TYPE_TO_FAMILY",
]


class UnknownPayloadVersion(Exception):
    """No canonical function is registered for a record's (type, version)."""


class UnknownRecordType(Exception):
    """A record's ``record_type`` names no family this verifier registers.

    Such a record has no canonical payload here: reading it as a generic
    ``AuditRecord`` would verify bytes sengol never signed under that name.
    """

    def __init__(self, record_type: Any) -> None:
        super().__init__(f"record_type {record_type!r} is not registered in this verifier")
        self.record_type = record_type


# Field names that are datetimes in every canonical function that reads them.
# Any other field is passed through as the raw JSON scalar/list/dict.
_DATETIME_FIELDS = frozenset(
    {
        "timestamp",
        "period_from",
        "period_to",
        "certified_at",
        "valid_until",
        "purged_at",
        "retired_at",
        "decided_at",
        "authorized_until",
    }
)


class _JsonPassthrough:
    """Wraps an already-JSON-shaped dict so ``.model_dump(mode="json")`` is a no-op.

    ``eval_result`` is stored as the exact dict a real ``EvalResult.model_dump``
    call produced, so returning it unchanged reproduces the same bytes.
    """

    def __init__(self, data: dict) -> None:
        self._data = data

    def model_dump(self, mode: str = "json") -> dict:
        return self._data


class Record:
    """Attribute view over one reconstructed record's raw JSON dict.

    ``family`` names which canonical-function family signs this record's
    bytes (e.g. "AuditRecord", "AgentCallRecord") — resolved once, at
    construction, from the record's ``record_type`` string field. It is
    ``None`` for a record whose ``record_type`` is not registered; such a
    record has no canonical payload and ``canonical_payload`` raises
    :exc:`UnknownRecordType`.
    """

    def __init__(self, raw: dict, family: str | None) -> None:
        self._raw = raw
        self.family = family

    def __getattr__(self, name: str) -> Any:
        if name not in self._raw:
            return None
        value = self._raw[name]
        if value is not None and name in _DATETIME_FIELDS and isinstance(value, str):
            return datetime.fromisoformat(value)
        if name == "eval_result" and value is not None:
            return _JsonPassthrough(value)
        return value

    @property
    def payload_version(self) -> int:
        return self._raw.get("payload_version") or 1

    @property
    def record_id(self) -> str:
        return str(self._raw.get("record_id", ""))

    @property
    def hmac_signature(self) -> str:
        return self._raw.get("hmac_signature", "")

    @property
    def key_id(self) -> str:
        return self._raw.get("key_id", "")

    @property
    def tenant_id(self) -> str:
        return self._raw.get("tenant_id", "")

    @property
    def agent_id(self) -> str:
        return self._raw.get("agent_id", "")

    @property
    def sequence_number(self) -> int:
        return self._raw.get("sequence_number", 0)

    @property
    def prev_hash(self) -> str:
        return self._raw.get("prev_hash", "")

    def canonical_payload(self) -> str:
        if self.family is None:
            raise UnknownRecordType(self._raw.get("record_type"))
        return canonical_payload(self.family, self.payload_version, self)

    def unsigned_fields(self) -> dict:
        return unsigned_fields_below_floor(self)


# ---------------------------------------------------------------------------
# record_type string -> canonical-function family name (sengol AUDIT_RECORD_TYPES).
# A record with no record_type field is base AuditRecord; one with a
# record_type missing from this map is refused by ``family_for``.
# ---------------------------------------------------------------------------

RECORD_TYPE_TO_FAMILY: dict[str, str] = {
    "sengol.agent.call": "AgentCallRecord",
    "sengol.agent.tier_change": "AgentTierChangeRecord",
    "sengol.audit.certification_anchor": "CertificationAnchorRecord",
    "sengol.audit.tombstone": "TombstoneRecord",
    "sengol.audit.trace_reveal": "TraceRevealRecord",
    "sengol.authorization.decision": "AuthorizationDecisionRecord",
    "sengol.behaviour.deviation": "BehaviourDeviationRecord",
    "sengol.behaviour.lease": "AcceptedSetLease",
    "sengol.call.started": "CallStartedRecord",
    "sengol.certification.revocation": "CertificationRevocationRecord",
    "sengol.certification.supersession": "CertificationSupersessionRecord",
    "sengol.gateway.usage": "GatewayUsageRecord",
    "sengol.judge.model_card": "JudgeModelCard",
    "sengol.judge.promotion_decision": "PromotionDecisionRecord",
    "sengol.lifecycle.deployment_authorization": "DeploymentAuthorizationRecord",
    "sengol.quarantine.event": "AgentQuarantineRecord",
    "sengol.sod.decision": "SoDDecisionRecord",
}


def family_for(raw: dict) -> str:
    """The canonical-function family for a raw record dict.

    A record with no ``record_type`` (or a null one) is the base
    ``AuditRecord``. Any other value must be a key of
    ``RECORD_TYPE_TO_FAMILY``; otherwise this raises :exc:`UnknownRecordType`
    rather than falling back to ``AuditRecord``.

    ``EvaluationRunRecord``, ``CertificationRecord``, ``GoldScoreRecord``,
    ``SaturationEvent`` and the two signed regression records
    (``ProductionFailureRecord``, ``RegressionCaseRecord``) carry no
    ``record_type`` field at all — each lives outside the audit chain, in its
    own table — so none belongs in ``RECORD_TYPE_TO_FAMILY``. A caller
    reconstructing one of these passes its family to ``Record(raw, family)``
    directly, as ``scripts/crosscheck_canonical.py`` does.
    """
    record_type = raw.get("record_type")
    if record_type is None:
        return "AuditRecord"
    if isinstance(record_type, str) and record_type in RECORD_TYPE_TO_FAMILY:
        return RECORD_TYPE_TO_FAMILY[record_type]
    raise UnknownRecordType(record_type)


# ---------------------------------------------------------------------------
# ADR-0019: one canonical rule signs every record. The payload is RFC 8785
# (JSON Canonicalization Scheme) over {"record": <fields>, "type": <family>},
# where <fields> is the record's JSON-mode field values minus the family's
# UNSIGNED_FIELDS (mirrors sengol/core/payload_registry.py verbatim — do not
# reintroduce a per-(family, version) function here).
# ---------------------------------------------------------------------------

#: Every payload_version each family accepts. Copied verbatim from
#: sengol/core/payload_registry.py::_VERSIONS. This only gates "is this
#: shape known" — every registered version canonicalizes by the one rule.
_VERSIONS: dict[str, tuple[int, ...]] = {
    "AcceptedSetLease": (1,),
    "AgentCallRecord": (1, 3, 4),
    "AgentQuarantineRecord": (1,),
    "AgentTierChangeRecord": (1,),
    "AuditRecord": (1, 2, 3),
    "AuthorizationDecisionRecord": (1, 2),
    "BehaviourDeviationRecord": (1,),
    "BehaviourManifestRecord": (1,),
    "CallSetManifestRecord": (1,),
    "CallStartedRecord": (1,),
    "CertificationAnchorRecord": (1,),
    "CertificationRecord": (2, 3, 4),
    "CertificationRevocationRecord": (1,),
    "CertificationSupersessionRecord": (1,),
    "DeploymentAuthorizationRecord": (1,),
    "EvaluationCaseRecord": (1,),
    "EvaluationRunRecord": (2, 3, 4, 5, 6),
    "GatewayUsageRecord": (1,),
    "GoldScoreRecord": (1, 2),
    "JudgeModelCard": (1, 2),
    "ProductionFailureRecord": (1,),
    "PromotionDecisionRecord": (1, 2),
    "RegressionCaseRecord": (1,),
    "SaturationEvent": (1, 2),
    "SoDDecisionRecord": (1, 2, 3),
    "TombstoneRecord": (1, 2),
    "TraceRevealRecord": (1,),
}

#: The signature itself and the name of the backend that produced it. Every
#: family leaves these out; a family adds its own via `_UNSIGNED_FIELDS`.
ALWAYS_UNSIGNED_FIELDS = frozenset({"hmac_signature", "signing_backend"})

#: Unsigned on the base ``AuditRecord`` and so on every subtype: the
#: transport-only manifest sidecar, stripped before a record is stored.
_AUDIT_UNSIGNED_FIELDS = frozenset({"call_signature_manifests"})
#: Top-level UNSIGNED_FIELDS per family, mirroring sengol/core/types.py's
#: class attributes of the same name (ADR-0019). An ``AuditRecord`` family
#: also leaves out ``_AUDIT_UNSIGNED_FIELDS``; see ``_unsigned_fields``.
_UNSIGNED_FIELDS: dict[str, frozenset[str]] = {
    "AuthorizationDecisionRecord": frozenset(
        {"eval_result", "mcp_server_version", "model", "input_tokens", "output_tokens", "cost_usd"}
    ),
    "SaturationEvent": frozenset({"remediated_at"}),
    "CertificationRecord": frozenset({"anchor_record_id", "evidence_pack_id"}),
}
#: UNSIGNED_FIELDS of the models nested inside a record, keyed by the path of
#: field names from the record root (list positions do not count). A nested
#: model's own exclusions apply only where the path names it:
#: ``EvalScore`` (``reason`` is erasable text bound by the signed
#: ``reason_digest``; ``reason_status`` describes a read) and ``CaseBinding``
#: (raw content bound by its signed ``config_hash`` and ``reference_hash``).
_NESTED_UNSIGNED_FIELDS: dict[tuple[str, ...], frozenset[str]] = {
    ("eval_result", "scores"): frozenset({"reason", "reason_status"}),
    ("bindings",): frozenset({"config", "reference"}),
}
#: Lists whose order carries no meaning; sorted by their own RFC 8785 bytes
#: before signing (ADR-0019), mirroring each family's UNORDERED_FIELDS.
_UNORDERED_FIELDS: dict[str, frozenset[str]] = {
    "AcceptedSetLease": frozenset({"accepted_cert_ids"}),
    "CertificationRecord": frozenset(
        {"acknowledged_unversioned", "endpoint_equivalents", "environment_mounts", "supersedes"}
    ),
    "CertificationSupersessionRecord": frozenset({"supersedes"}),
    "EvaluationCaseRecord": frozenset({"scores", "skipped"}),
    "EvaluationRunRecord": frozenset({"evaluator_manifest"}),
    "TombstoneRecord": frozenset({"purged_trace_ids"}),
}


def _unsigned_fields(family: str) -> frozenset[str]:
    unsigned = ALWAYS_UNSIGNED_FIELDS | _UNSIGNED_FIELDS.get(family, frozenset())
    if family == "AuditRecord" or family in RECORD_TYPE_TO_FAMILY.values():
        unsigned |= _AUDIT_UNSIGNED_FIELDS
    return unsigned


def _strip(value: Any, unsigned: frozenset[str], path: tuple[str, ...] = ()) -> Any:
    """Drop *unsigned* keys and every ``None`` value, recursing into dicts
    and lists so a nested model's own exclusions apply where its path
    from the record root names it."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k in unsigned or v is None:
                continue
            sub = path + (k,)
            out[k] = _strip(v, _NESTED_UNSIGNED_FIELDS.get(sub, frozenset()), sub)
        return out
    if isinstance(value, list):
        return [_strip(v, unsigned, path) for v in value]
    return value


def _element_key(value: Any) -> bytes:
    return rfc8785.dumps(value)


def canonical_payload(family: str, version: int, record: Any) -> str:
    """Return the RFC 8785 canonical JSON string for *record* (ADR-0019).

    Raises :exc:`UnknownPayloadVersion` if *version* is not registered for
    *family*, and lets ``rfc8785.CanonicalizationError`` propagate for a
    signed value with no RFC 8785 form (NaN, Infinity, an integer beyond
    2**53) — the same refusal real sengol makes.
    """
    if version not in _VERSIONS.get(family, ()):
        raise UnknownPayloadVersion(
            f"No canonical payload registered for {family} v{version}. "
            f"Known versions: {_VERSIONS.get(family, ())}"
        )
    fields = _strip(record._raw, _unsigned_fields(family))
    for name in _UNORDERED_FIELDS.get(family, frozenset()):
        if isinstance(fields.get(name), list):
            fields[name] = sorted(fields[name], key=_element_key)
    return rfc8785.dumps({"record": fields, "type": family}).decode("utf-8")


# ---------------------------------------------------------------------------
# Step-6 field coverage (offline_verify.py Step 6). Under ADR-0019 there is
# no per-version floor: a family's UNSIGNED_FIELDS are unsigned at every
# version, and every other populated field is always inside the signature.
# `unsigned_fields_below_floor` keeps its name/contract for callers, but a
# well-formed record can never trip it, so it always reports nothing.
# ---------------------------------------------------------------------------


def unsigned_fields_below_floor(record: Any) -> dict:
    """No-op under ADR-0019 — kept for API stability. Always ``{}``."""
    return {}

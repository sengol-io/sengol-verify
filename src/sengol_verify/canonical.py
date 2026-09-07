"""Canonical signed-payload byte producers, vendored from sengol's
``sengol/core/payload_registry.py``.

Every function below reproduces the exact ``json.dumps(..., sort_keys=True)``
call the original signer used for one ``(record_type, payload_version)`` pair.
Field lists, key names, and the sort-keys/default-separators canonicalization
rule are copied verbatim — changing any of them here would make this tool
disagree with sengol about what a genuine signature covers. Do not "clean up"
a field list; it is a byte contract, not a schema.

This module has no import on the ``sengol`` package. ``Record`` duck-types
attribute access over a plain dict reconstructed from stored/exported JSON,
which is what every canonical function here actually reads.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime
from typing import Any, NamedTuple

__all__ = [
    "Record",
    "canonical_payload",
    "UnknownPayloadVersion",
    "unsigned_fields_below_floor",
    "RECORD_TYPE_TO_FAMILY",
]


class UnknownPayloadVersion(Exception):
    """No canonical function is registered for a record's (type, version)."""


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
    construction, from the record's ``record_type`` string field.
    """

    def __init__(self, raw: dict, family: str) -> None:
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
        return canonical_payload(self.family, self.payload_version, self)

    def unsigned_fields(self) -> dict:
        return unsigned_fields_below_floor(self)


# ---------------------------------------------------------------------------
# record_type string -> canonical-function family name (sengol AUDIT_RECORD_TYPES).
# A record with no record_type field (or an unknown one) is base AuditRecord.
# ---------------------------------------------------------------------------

RECORD_TYPE_TO_FAMILY: dict[str, str] = {
    "sengol.agent.call": "AgentCallRecord",
    "sengol.judge.model_card": "JudgeModelCard",
    "sengol.judge.promotion_decision": "PromotionDecisionRecord",
    "sengol.regulation.update": "RegulationUpdateEvent",
    "sengol.sod.decision": "SoDDecisionRecord",
    "sengol.audit.tombstone": "TombstoneRecord",
    "sengol.authority.model": "AuthorityModelRecord",
    "sengol.authorization.decision": "AuthorizationDecisionRecord",
    "sengol.gateway.usage": "GatewayUsageRecord",
    "sengol.shadow.disposition": "ShadowAgentDispositionRecord",
    "sengol.identity.binding": "AgentIdentityBindingRecord",
    "sengol.quarantine.event": "AgentQuarantineRecord",
    "sengol.retention.retirement": "RetentionRetirementRecord",
    "sengol.legalhold.event": "LegalHoldRecord",
    "sengol.retention.policy_change": "RetentionPolicyChangeRecord",
    "sengol.retention.auto_execute": "RetentionAutoExecuteChangeRecord",
    "sengol.scope.label_change": "AgentLabelChangeRecord",
    "sengol.audit.tenant_status_change": "TenantStatusChangeRecord",
    "sengol.audit.dual_control_change": "ErasureDualControlChangeRecord",
}


def family_for(raw: dict) -> str:
    """The canonical-function family for a raw record dict."""
    return RECORD_TYPE_TO_FAMILY.get(raw.get("record_type"), "AuditRecord")


# ---------------------------------------------------------------------------
# Canonical payload functions. Each name/version pair is FROZEN evidence
# format — see the registry docstring in the sengol repo (ADR-0057).
# ---------------------------------------------------------------------------


def _audit_v1(r: Any) -> str:
    return json.dumps(
        {
            "record_id": str(r.record_id),
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
            "policies": list(r.policies),
            "controlbook_id": r.controlbook_id,
            "controlbook_version": r.controlbook_version,
            "eval_result": r.eval_result.model_dump(mode="json"),
        },
        sort_keys=True,
    )


def _gold_score_v1(r: Any) -> str:
    return json.dumps(
        {
            "record_id": str(r.record_id),
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "tenant_id": r.tenant_id,
            "controlbook_id": r.controlbook_id,
            "controlbook_version": r.controlbook_version,
            "period_from": r.period_from.isoformat(),
            "period_to": r.period_to.isoformat(),
            "score": r.score,
            "breakdown": r.breakdown,
            "formula_type": r.formula_type,
            "compliant": r.compliant,
            "timestamp": r.timestamp.isoformat(),
        },
        sort_keys=True,
    )


def _saturation_v1(r: Any) -> str:
    return json.dumps(
        {
            "event_id": str(r.event_id),
            "suite_name": r.suite_name,
            "agent_id": r.agent_id,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
            "pass_rate": r.pass_rate,
            "consecutive_runs": r.consecutive_runs,
            "threshold": r.threshold,
        },
        sort_keys=True,
    )


def _audit_two(r: Any) -> str:
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "controlbook_id": r.controlbook_id,
            "controlbook_version": r.controlbook_version,
            "eval_result": r.eval_result.model_dump(mode="json"),
            "eval_run_id": r.eval_run_id,
            "key_id": r.key_id,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "prev_hash": r.prev_hash,
            "record_id": str(r.record_id),
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
        },
        sort_keys=True,
    )


def _gold_score_two(r: Any) -> str:
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "breakdown": r.breakdown,
            "compliant": r.compliant,
            "controlbook_id": r.controlbook_id,
            "controlbook_version": r.controlbook_version,
            "formula_type": r.formula_type,
            "key_id": r.key_id,
            "payload_version": r.payload_version,
            "period_from": r.period_from.isoformat(),
            "period_to": r.period_to.isoformat(),
            "record_id": str(r.record_id),
            "score": r.score,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
        },
        sort_keys=True,
    )


def _saturation_two(r: Any) -> str:
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "consecutive_runs": r.consecutive_runs,
            "event_id": str(r.event_id),
            "key_id": r.key_id,
            "pass_rate": r.pass_rate,
            "payload_version": r.payload_version,
            "suite_name": r.suite_name,
            "tenant_id": r.tenant_id,
            "threshold": r.threshold,
            "timestamp": r.timestamp.isoformat(),
        },
        sort_keys=True,
    )


def _eval_run_two(r: Any) -> str:
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "controlbook_id": r.controlbook_id,
            "controlbook_version": r.controlbook_version,
            "dataset_id": r.dataset_id,
            "failure_modes": r.failure_modes,
            "gate_passed": r.gate_passed,
            "key_id": r.key_id,
            "pass_rate": r.pass_rate,
            "passed": r.passed,
            "payload_version": r.payload_version,
            "required_pass_rate": r.required_pass_rate,
            "run_id": str(r.run_id),
            "scores_by_evaluator": r.scores_by_evaluator,
            "suite_name": r.suite_name,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
            "total": r.total,
        },
        sort_keys=True,
    )


def _certification_two(r: Any) -> str:
    # evidence_pack_id is deliberately excluded from every version.
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "cert_id": str(r.cert_id),
            "certified_at": r.certified_at.isoformat(),
            "certified_by": r.certified_by,
            "certified_risk_tier": r.certified_risk_tier,
            "conditions": list(r.conditions),
            "gate_passed": r.gate_passed,
            "key_id": r.key_id,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "run_id": str(r.run_id),
            "valid_until": r.valid_until.isoformat() if r.valid_until else None,
        },
        sort_keys=True,
    )


def _audit_v3(r: Any) -> str:
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "authority_model_version": r.authority_model_version,
            "controlbook_id": r.controlbook_id,
            "controlbook_version": r.controlbook_version,
            "eval_result": r.eval_result.model_dump(mode="json"),
            "eval_run_id": r.eval_run_id,
            "key_id": r.key_id,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "prev_hash": r.prev_hash,
            "record_id": str(r.record_id),
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
        },
        sort_keys=True,
    )


def _certification_v3(r: Any) -> str:
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "cert_id": str(r.cert_id),
            "certified_at": r.certified_at.isoformat(),
            "certified_by": r.certified_by,
            "certified_risk_tier": r.certified_risk_tier,
            "conditions": list(r.conditions),
            "gate_passed": r.gate_passed,
            "key_id": r.key_id,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "run_id": str(r.run_id),
            "tenant_id": r.tenant_id,
            "valid_until": r.valid_until.isoformat() if r.valid_until else None,
        },
        sort_keys=True,
    )


def _agent_call_v1(r: Any) -> str:
    # eval_result is excluded on every AgentCallRecord version by design.
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "authorization_record_id": r.authorization_record_id,
            "caller_agent_id": r.caller_agent_id,
            "callee_agent_id": r.callee_agent_id,
            "declared": r.declared,
            "key_id": r.key_id,
            "payload_version": r.payload_version,
            "prev_hash": r.prev_hash,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "risk_tier_escalation": r.risk_tier_escalation,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
        },
        sort_keys=True,
    )


def _agent_call_v4(r: Any) -> str:
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "authorization_record_id": r.authorization_record_id,
            "caller_agent_id": r.caller_agent_id,
            "callee_agent_id": r.callee_agent_id,
            "declared": r.declared,
            "key_id": r.key_id,
            "mcp_tool_hash": r.mcp_tool_hash,
            "mcp_tool_pinned_hash": r.mcp_tool_pinned_hash,
            "payload_version": r.payload_version,
            "prev_hash": r.prev_hash,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "risk_tier_escalation": r.risk_tier_escalation,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
        },
        sort_keys=True,
    )


def _judge_model_card_v1(r: Any) -> str:
    # FROZEN — released in sengol 1.1.0; a later version adds fields below.
    return json.dumps(
        {
            "adapter_ref": r.adapter_ref,
            "adv_tnr": r.adv_tnr,
            "adv_tpr": r.adv_tpr,
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "base_model": r.base_model,
            "calibration_reviewer_count": r.calibration_reviewer_count,
            "failure_mode": r.failure_mode,
            "gate_passed": r.gate_passed,
            "independence_established": r.independence_established,
            "independent_count": r.independent_count,
            "independent_reviewer_count": r.independent_reviewer_count,
            "adversarial_count": r.adversarial_count,
            "position_pairs_count": r.position_pairs_count,
            "kappa": r.kappa,
            "key_id": r.key_id,
            "payload_version": r.payload_version,
            "policy": r.policy,
            "position_pc": r.position_pc,
            "prev_hash": r.prev_hash,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "test_count": r.test_count,
            "timestamp": r.timestamp.isoformat(),
            "tnr": r.tnr,
            "tpr": r.tpr,
        },
        sort_keys=True,
    )


# JudgeModelCard version-2 keys omitted entirely when unset, so a version-2 card minted
# before any of these fields existed keeps producing its original bytes.
_JUDGE_MODEL_CARD_VERSION2_OPTIONAL_KEYS: tuple[str, ...] = (
    "verdicts_sha256",
    "training_records_sha256",
    "pairs_sha256",
    "reserved_identities_sha256",
    "adapter_sha256",
    "adversarial_labels_authenticated",
    "standard_id",
    "standard_version",
)


def _judge_model_card_two(r: Any) -> str:
    base = json.loads(_judge_model_card_v1(r))
    base["labels_authenticated"] = r.labels_authenticated
    base["authenticated_records"] = r.authenticated_records
    base["divergent_records"] = r.divergent_records
    for key in _JUDGE_MODEL_CARD_VERSION2_OPTIONAL_KEYS:
        value = getattr(r, key, None)
        if value is not None:
            base[key] = value
    return json.dumps(base, sort_keys=True)


def _promotion_decision_v1(r: Any) -> str:
    return json.dumps(
        {
            "adapter_ref": r.adapter_ref,
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "approved": r.approved,
            "approver": r.approver,
            "base_model": r.base_model,
            "gate_passed": r.gate_passed,
            "key_id": r.key_id,
            "model_card_record_id": r.model_card_record_id,
            "model_card_verified": r.model_card_verified,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "prev_hash": r.prev_hash,
            "rationale": r.rationale,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "rejection_reason": r.rejection_reason,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
        },
        sort_keys=True,
    )


def _promotion_decision_two(r: Any) -> str:
    return json.dumps(
        {
            "acr": r.acr,
            "adapter_ref": r.adapter_ref,
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "approved": r.approved,
            "approver": r.approver,
            "base_model": r.base_model,
            "gate_passed": r.gate_passed,
            "key_id": r.key_id,
            "mfa_asserted": r.mfa_asserted,
            "model_card_record_id": r.model_card_record_id,
            "model_card_verified": r.model_card_verified,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "prev_hash": r.prev_hash,
            "rationale": r.rationale,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "rejection_reason": r.rejection_reason,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
        },
        sort_keys=True,
    )


def _regulation_update_v1(r: Any) -> str:
    return json.dumps(
        {
            "affected_agent_count": r.affected_agent_count,
            "affected_agent_ids": list(r.affected_agent_ids),
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "key_id": r.key_id,
            "new_compiled_digest": r.new_compiled_digest,
            "obligation_digests": dict(r.obligation_digests),
            "obligations_added": list(r.obligations_added),
            "obligations_changed": list(r.obligations_changed),
            "obligations_removed": list(r.obligations_removed),
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "policy_id": r.policy_id,
            "prev_hash": r.prev_hash,
            "prior_compiled_digest": r.prior_compiled_digest,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
            "triggered_by": r.triggered_by,
        },
        sort_keys=True,
    )


def _sod_decision_v1(r: Any) -> str:
    return json.dumps(
        {
            "actor_id": r.actor_id,
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "key_id": r.key_id,
            "mfa_asserted": r.mfa_asserted,
            "object_id": r.object_id,
            "object_type": r.object_type,
            "override_applied": r.override_applied,
            "override_by": r.override_by,
            "override_reason": r.override_reason,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "prev_hash": r.prev_hash,
            "prior_actor_id": r.prior_actor_id,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "risk_tier": r.risk_tier,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
            "transition": r.transition,
        },
        sort_keys=True,
    )


def _sod_decision_two(r: Any) -> str:
    return json.dumps(
        {
            "actor_id": r.actor_id,
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "key_id": r.key_id,
            "mfa_asserted": r.mfa_asserted,
            "object_id": r.object_id,
            "object_type": r.object_type,
            "override_applied": r.override_applied,
            "override_by": r.override_by,
            "override_reason": r.override_reason,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "prev_hash": r.prev_hash,
            "prior_actor_id": r.prior_actor_id,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "risk_tier": r.risk_tier,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "tier_source": r.tier_source,
            "timestamp": r.timestamp.isoformat(),
            "transition": r.transition,
        },
        sort_keys=True,
    )


def _sod_decision_v3(r: Any) -> str:
    return json.dumps(
        {
            "actor_id": r.actor_id,
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "finding": r.finding,
            "key_id": r.key_id,
            "mfa_asserted": r.mfa_asserted,
            "note": r.note,
            "object_id": r.object_id,
            "object_type": r.object_type,
            "override_applied": r.override_applied,
            "override_by": r.override_by,
            "override_reason": r.override_reason,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "prev_hash": r.prev_hash,
            "prior_actor_id": r.prior_actor_id,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "risk_tier": r.risk_tier,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "tier_source": r.tier_source,
            "timestamp": r.timestamp.isoformat(),
            "transition": r.transition,
        },
        sort_keys=True,
    )


def _authority_model_v1(r: Any) -> str:
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "authority_version_id": r.authority_version_id,
            "key_id": r.key_id,
            "model_digest": r.model_digest,
            "new_status": r.new_status,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "prev_hash": r.prev_hash,
            "prior_status": r.prior_status,
            "reason": r.reason,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
            "transition_actor": r.transition_actor,
        },
        sort_keys=True,
    )


def _tombstone_v1(r: Any) -> str:
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "key_id": r.key_id,
            "operator_id": r.operator_id,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "prev_hash": r.prev_hash,
            "purged_at": r.purged_at.isoformat(),
            "purged_count": r.purged_count,
            "purged_trace_ids": sorted(r.purged_trace_ids),
            "reason": r.reason,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "sequence_number": r.sequence_number,
            "subject_ref": r.subject_ref,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
        },
        sort_keys=True,
    )


def _tombstone_two(r: Any) -> str:
    # Adds requester_principal_id, included unconditionally on every such row.
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "key_id": r.key_id,
            "operator_id": r.operator_id,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "prev_hash": r.prev_hash,
            "purged_at": r.purged_at.isoformat(),
            "purged_count": r.purged_count,
            "purged_trace_ids": sorted(r.purged_trace_ids),
            "reason": r.reason,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "requester_principal_id": r.requester_principal_id,
            "sequence_number": r.sequence_number,
            "subject_ref": r.subject_ref,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
        },
        sort_keys=True,
    )


def _retention_retirement_v1(r: Any) -> str:
    # initiator/authorization_record_id are omitted when initiator == "manual"
    # so a pre-reshape "manual" record keeps producing identical bytes.
    payload: dict[str, Any] = {
        "agent_id": r.agent_id,
        "agent_version": r.agent_version,
        "bundle_sha256": r.bundle_sha256,
        "bundle_uri": r.bundle_uri,
        "key_id": r.key_id,
        "operator_id": r.operator_id,
        "payload_version": r.payload_version,
        "policies": list(r.policies),
        "prev_hash": r.prev_hash,
        "record_count": r.record_count,
        "record_id": str(r.record_id),
        "record_type": r.record_type,
        "retention_policy_id": r.retention_policy_id,
        "retired_at": r.retired_at.isoformat(),
        "seq_high": r.seq_high,
        "seq_low": r.seq_low,
        "sequence_number": r.sequence_number,
        "tenant_id": r.tenant_id,
        "terminal_chain_digest": r.terminal_chain_digest,
        "timestamp": r.timestamp.isoformat(),
        "window_days": r.window_days,
    }
    if r.initiator != "manual":
        payload["initiator"] = r.initiator
        payload["authorization_record_id"] = r.authorization_record_id
    return json.dumps(payload, sort_keys=True)


def _legal_hold_v1(r: Any) -> str:
    return json.dumps(
        {
            "action": r.action,
            "actor": r.actor,
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "hold_id": r.hold_id,
            "key_id": r.key_id,
            "matter_ref": r.matter_ref,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "prev_hash": r.prev_hash,
            "reason": r.reason,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "scope_key": r.scope_key,
            "scope_type": r.scope_type,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
        },
        sort_keys=True,
    )


def _retention_policy_change_v1(r: Any) -> str:
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "approver": r.approver,
            "change_type": r.change_type,
            "decided_at": r.decided_at.isoformat(),
            "key_id": r.key_id,
            "new_retention_days": r.new_retention_days,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "policy_id": r.policy_id,
            "prev_hash": r.prev_hash,
            "prior_retention_days": r.prior_retention_days,
            "reason": r.reason,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "requester": r.requester,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
        },
        sort_keys=True,
    )


def _erasure_dual_control_change_v1(r: Any) -> str:
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "approver": r.approver,
            "change_type": r.change_type,
            "decided_at": r.decided_at.isoformat(),
            "key_id": r.key_id,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "prev_hash": r.prev_hash,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "requester": r.requester,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
        },
        sort_keys=True,
    )


def _tenant_status_change_v1(r: Any) -> str:
    # FROZEN — seal_posture arrives only in a later version, never add it here.
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "changed_by": r.changed_by,
            "decided_at": r.decided_at.isoformat(),
            "from_status": r.from_status,
            "key_id": r.key_id,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "prev_hash": r.prev_hash,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
            "to_status": r.to_status,
        },
        sort_keys=True,
    )


def _tenant_status_change_two(r: Any) -> str:
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "changed_by": r.changed_by,
            "decided_at": r.decided_at.isoformat(),
            "from_status": r.from_status,
            "key_id": r.key_id,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "prev_hash": r.prev_hash,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "seal_posture": r.seal_posture,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
            "to_status": r.to_status,
        },
        sort_keys=True,
    )


def _authorization_decision_v1(r: Any) -> str:
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "caller_agent_id": r.caller_agent_id,
            "callee_agent_id": r.callee_agent_id,
            "decision": r.decision,
            "enforcement_mode": r.enforcement_mode,
            "key_id": r.key_id,
            "matched_rule": r.matched_rule,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "policy_matched": r.policy_matched,
            "prev_hash": r.prev_hash,
            "reason": r.reason,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "risk_tier_escalation": r.risk_tier_escalation,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
            "tool_id": r.tool_id,
        },
        sort_keys=True,
    )


def _authorization_decision_two(r: Any) -> str:
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "caller_agent_id": r.caller_agent_id,
            "callee_agent_id": r.callee_agent_id,
            "decision": r.decision,
            "delegation_depth": r.delegation_depth,
            "enforcement_mode": r.enforcement_mode,
            "key_id": r.key_id,
            "matched_rule": r.matched_rule,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "policy_matched": r.policy_matched,
            "prev_hash": r.prev_hash,
            "reason": r.reason,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "risk_tier_escalation": r.risk_tier_escalation,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
            "tool_id": r.tool_id,
        },
        sort_keys=True,
    )


def _gateway_usage_v1(r: Any) -> str:
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "caller_agent_id": r.caller_agent_id,
            "cost_usd": r.cost_usd,
            "input_tokens": r.input_tokens,
            "key_id": r.key_id,
            "model": r.model,
            "output_tokens": r.output_tokens,
            "over_quota": r.over_quota,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "prev_hash": r.prev_hash,
            "quota_scope": r.quota_scope,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
        },
        sort_keys=True,
    )


def _shadow_disposition_v1(r: Any) -> str:
    return json.dumps(
        {
            "actor": r.actor,
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "disposition": r.disposition,
            "first_seen_at": r.first_seen_at,
            "key_id": r.key_id,
            "observation_count": r.observation_count,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "prev_hash": r.prev_hash,
            "reason": r.reason,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "sequence_number": r.sequence_number,
            "source": r.source,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
        },
        sort_keys=True,
    )


def _identity_binding_v1(r: Any) -> str:
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "bound_by": r.bound_by,
            "external_identity": r.external_identity,
            "idp_connection_id": r.idp_connection_id,
            "idp_issuer": r.idp_issuer,
            "key_id": r.key_id,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "prev_hash": r.prev_hash,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
        },
        sort_keys=True,
    )


def _label_change_v1(r: Any) -> str:
    return json.dumps(
        {
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "changed_by": r.changed_by,
            "key_id": r.key_id,
            "new_labels": dict(r.new_labels),
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "prev_hash": r.prev_hash,
            "prior_labels": dict(r.prior_labels),
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
        },
        sort_keys=True,
    )


def _quarantine_v1(r: Any) -> str:
    return json.dumps(
        {
            "action": r.action,
            "actor": r.actor,
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "failure_mode": r.failure_mode,
            "key_id": r.key_id,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "prev_hash": r.prev_hash,
            "reason": r.reason,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
            "trigger": r.trigger,
        },
        sort_keys=True,
    )


def _retention_auto_execute_v1(r: Any) -> str:
    return json.dumps(
        {
            "actor": r.actor,
            "agent_id": r.agent_id,
            "agent_version": r.agent_version,
            "authorized_until": r.authorized_until.isoformat()
            if r.authorized_until is not None
            else None,
            "change_type": r.change_type,
            "deployment_capability_permitted": r.deployment_capability_permitted,
            "key_id": r.key_id,
            "payload_version": r.payload_version,
            "policies": list(r.policies),
            "prev_hash": r.prev_hash,
            "reason": r.reason,
            "record_id": str(r.record_id),
            "record_type": r.record_type,
            "sequence_number": r.sequence_number,
            "tenant_id": r.tenant_id,
            "timestamp": r.timestamp.isoformat(),
        },
        sort_keys=True,
    )


# ---------------------------------------------------------------------------
# Registry — (family, payload_version) -> canonical function.
# ---------------------------------------------------------------------------

_REGISTRY: dict[tuple[str, int], Callable[[Any], str]] = {
    ("AuditRecord", 1): _audit_v1,
    ("AuditRecord", 2): _audit_two,
    ("AuditRecord", 3): _audit_v3,
    ("GoldScoreRecord", 1): _gold_score_v1,
    ("GoldScoreRecord", 2): _gold_score_two,
    ("SaturationEvent", 1): _saturation_v1,
    ("SaturationEvent", 2): _saturation_two,
    ("EvaluationRunRecord", 2): _eval_run_two,
    ("CertificationRecord", 2): _certification_two,
    ("CertificationRecord", 3): _certification_v3,
    ("AgentCallRecord", 1): _agent_call_v1,
    ("AgentCallRecord", 3): _agent_call_v1,
    ("AgentCallRecord", 4): _agent_call_v4,
    ("JudgeModelCard", 1): _judge_model_card_v1,
    ("JudgeModelCard", 2): _judge_model_card_two,
    ("PromotionDecisionRecord", 1): _promotion_decision_v1,
    ("PromotionDecisionRecord", 2): _promotion_decision_two,
    ("RegulationUpdateEvent", 1): _regulation_update_v1,
    ("SoDDecisionRecord", 1): _sod_decision_v1,
    ("SoDDecisionRecord", 2): _sod_decision_two,
    ("SoDDecisionRecord", 3): _sod_decision_v3,
    ("TombstoneRecord", 1): _tombstone_v1,
    ("TombstoneRecord", 2): _tombstone_two,
    ("AuthorityModelRecord", 1): _authority_model_v1,
    ("RetentionRetirementRecord", 1): _retention_retirement_v1,
    ("AuthorizationDecisionRecord", 1): _authorization_decision_v1,
    ("AuthorizationDecisionRecord", 2): _authorization_decision_two,
    ("GatewayUsageRecord", 1): _gateway_usage_v1,
    ("ShadowAgentDispositionRecord", 1): _shadow_disposition_v1,
    ("AgentIdentityBindingRecord", 1): _identity_binding_v1,
    ("AgentQuarantineRecord", 1): _quarantine_v1,
    ("LegalHoldRecord", 1): _legal_hold_v1,
    ("RetentionPolicyChangeRecord", 1): _retention_policy_change_v1,
    ("TenantStatusChangeRecord", 1): _tenant_status_change_v1,
    ("TenantStatusChangeRecord", 2): _tenant_status_change_two,
    ("ErasureDualControlChangeRecord", 1): _erasure_dual_control_change_v1,
    ("RetentionAutoExecuteChangeRecord", 1): _retention_auto_execute_v1,
    ("AgentLabelChangeRecord", 1): _label_change_v1,
}


def canonical_payload(family: str, version: int, record: Any) -> str:
    """Canonical JSON string for HMAC signing/verification.

    Raises :exc:`UnknownPayloadVersion` if no function is registered for
    ``(family, version)``.
    """
    fn = _REGISTRY.get((family, version))
    if fn is None:
        raise UnknownPayloadVersion(
            f"No canonical payload registered for {family} v{version}. "
            f"Known: {sorted(_REGISTRY.keys())}"
        )
    return fn(record)


# ---------------------------------------------------------------------------
# Step-6 field coverage: which fields a family's payload does NOT sign below
# a given version. Vendored from PAYLOAD_VERSION_FLOORS (payload_registry.py).
# Resolution here is by record_type string, not class MRO: this tool never
# sees an SDK subclass, so there is no name-collision surface to defend
# against and a family-name lookup is sound.
# ---------------------------------------------------------------------------


class Floor(NamedTuple):
    version: int | None
    populated: Callable[[Any], bool]


NEVER: int | None = None


def _not_none(value: Any) -> bool:
    return value is not None


def _nonzero(value: Any) -> bool:
    return value != 0


def _nonempty(value: Any) -> bool:
    return bool(value)


def _not_default(default: Any) -> Callable[[Any], bool]:
    def _populated(value: Any) -> bool:
        return value is not None and value != default

    return _populated


PAYLOAD_VERSION_FLOORS: dict[str, dict[str, Floor]] = {
    "AuditRecord": {
        "authority_model_version": Floor(3, _not_none),
        "eval_run_id": Floor(2, _not_none),
    },
    "AgentCallRecord": {
        "mcp_tool_hash": Floor(4, _not_none),
        "mcp_tool_pinned_hash": Floor(4, _not_none),
    },
    "AuthorizationDecisionRecord": {"delegation_depth": Floor(2, _not_none)},
    "PromotionDecisionRecord": {
        "acr": Floor(2, _not_none),
        "mfa_asserted": Floor(2, _not_default(False)),
    },
    "SoDDecisionRecord": {
        "finding": Floor(3, _not_none),
        "note": Floor(3, _not_none),
        "tier_source": Floor(2, _not_default("default")),
    },
    "TenantStatusChangeRecord": {"seal_posture": Floor(2, _nonempty)},
    "TombstoneRecord": {"requester_principal_id": Floor(2, _not_none)},
    "JudgeModelCard": {
        **{key: Floor(2, _not_none) for key in _JUDGE_MODEL_CARD_VERSION2_OPTIONAL_KEYS},
        "labels_authenticated": Floor(2, _not_none),
        "authenticated_records": Floor(2, _nonzero),
        "divergent_records": Floor(2, _nonzero),
    },
}

# Base-model provenance fields no derived family's payload signs at all.
_BASE_PROVENANCE_UNSIGNED_ON_SUBTYPES: dict[str, Floor] = {
    "controlbook_id": Floor(NEVER, _not_none),
    "controlbook_version": Floor(NEVER, _not_none),
    "eval_run_id": Floor(NEVER, _not_none),
    "authority_model_version": Floor(NEVER, _not_none),
}

_NON_AUDIT_RECORD_FAMILIES = frozenset(
    {
        "AuditRecord",
        "GoldScoreRecord",
        "SaturationEvent",
        "EvaluationRunRecord",
        "CertificationRecord",
    }
)

for _family in {rt for rt, _ in _REGISTRY} - _NON_AUDIT_RECORD_FAMILIES:
    PAYLOAD_VERSION_FLOORS.setdefault(_family, {}).update(_BASE_PROVENANCE_UNSIGNED_ON_SUBTYPES)

for _family in ("AgentCallRecord", "JudgeModelCard"):
    PAYLOAD_VERSION_FLOORS[_family]["policies"] = Floor(NEVER, _nonempty)


def unsigned_fields_below_floor(record: Any) -> dict:
    """``{field: floor}`` for every floored field this record populates too low."""
    floors = PAYLOAD_VERSION_FLOORS.get(record.family, {})
    if not floors:
        return {}
    version = record.payload_version or 1
    return {
        field: floor.version
        for field, floor in floors.items()
        if (floor.version is None or version < floor.version)
        and floor.populated(getattr(record, field, None))
    }

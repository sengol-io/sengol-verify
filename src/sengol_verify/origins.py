"""Who vouched for an OTLP call record: a read-only id match, not a check.

The server derives a call record's id from its scope, agent, trace and root
span: ``uuid5(OTLP_CALL_NAMESPACE, "<scope>:<agent_id>:<trace_id>:<span_id>")``.
The scope is the install tenant id, or ``<tenant id>|collector=<secret id>``
when a collector's token sent the trace. A match shows which writer the id
was derived for; the signatures are checked by the verification steps.
"""

from __future__ import annotations

from collections.abc import Iterable
from uuid import UUID, uuid5

__all__ = ["OTLP_CALL_NAMESPACE", "otlp_call_origins"]

#: The namespace the server derives call-record ids under.
OTLP_CALL_NAMESPACE = UUID("1b5e830e-c29f-446c-a99a-8d58d9cfb321")


def otlp_call_origins(records: Iterable[dict], collector_ids: Iterable[str] = ()) -> dict[str, str]:
    """``{record_id: origin}`` for each bundle record whose id was derived.

    ``origin`` is ``server`` when the id derives from the record's tenant, and
    ``collector:<secret id>`` when it derives from a supplied collector secret
    id. A record that matches none (an SDK record, or a secret id not
    supplied) is absent.
    """
    collector_ids = list(collector_ids)
    origins: dict[str, str] = {}
    for rec in records:
        tenant, agent = rec.get("tenant_id"), rec.get("agent_id")
        trace, span = rec.get("trace_id"), rec.get("span_id")
        if not (tenant and agent and trace and span and rec.get("record_id")):
            continue
        scopes = [("server", tenant)] + [
            (f"collector:{sid}", f"{tenant}|collector={sid}") for sid in collector_ids
        ]
        for origin, scope in scopes:
            derived = uuid5(OTLP_CALL_NAMESPACE, f"{scope}:{agent}:{trace}:{span}")
            if str(rec["record_id"]) == str(derived):
                origins[str(rec["record_id"])] = origin
                break
    return origins

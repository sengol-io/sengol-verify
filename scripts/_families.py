"""Builds one signed record of every family sengol's payload registry names.

Shared by ``generate_fixtures.py`` and ``crosscheck.py``; both run inside a
sengol checkout's environment (see their docstrings), because every record
here is built and signed by sengol's own classes.

Each record has every model field populated with a deterministic value, so the
unsigned and unordered fields of its family are exercised rather than absent.
``OVERRIDES`` replaces the value of one field where the model constrains it
more tightly than its type says.
"""

from __future__ import annotations

import hashlib
import inspect
import types
import typing
from datetime import UTC, datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel
from pydantic_core import PydanticUndefined

TENANT = "acme-bank"
AGENT = "loan-underwriter-bot"
HMAC_KEY = "not-a-real-secret-do-not-reuse"
KEY_ID = "test-hmac-key-1"
WHEN = datetime(2026, 9, 27, 2, 28, 31, tzinfo=UTC)
SHA = "sha256:" + "a" * 64

#: Fields set by the store or the signer, not by the builder.
_BOOKKEEPING = frozenset({"hmac_signature", "signing_backend"})

#: Per-class field values where the generic filler cannot satisfy a validator.
_MANIFEST_JSON = '{"a":1,"b":[2,1]}'
_MANIFEST = {
    "canonical_json": _MANIFEST_JSON,
    "digest": "sha256:" + hashlib.sha256(_MANIFEST_JSON.encode()).hexdigest(),
}
OVERRIDES: dict[str, object] = {
    "TombstoneRecord": {"reason": "right to erasure"},
    "CertificationRecord": {"evidence_pack_id": "pack-1"},
    "BehaviourManifestRecord": _MANIFEST,
    "CallSetManifestRecord": _MANIFEST,
    "EvaluationRunRecord": lambda version: {
        "pass_rate": 1.0,
        **(
            {}
            if version >= 6
            else {
                f: None
                for f in (
                    "case_count",
                    "dataset_sha256",
                    "dataset_row_count",
                    "evaluator_manifest",
                    "cases_digest",
                    "digest_algorithm",
                )
            }
        ),
    },
    "EvaluationCaseRecord": {"case_index": 2, "case_key": "row:2"},
    "JudgeModelCard": {
        "divergent_records": 0,
        "standard_id": "SENGOL_CALIBRATION_V1",
        "standard_version": "1",
    },
}


def _uuid(n: int) -> UUID:
    return UUID(f"01a0e0ae-9261-7e42-8555-{n:012x}")


class _Filler:
    #: Shared by every filler so no two records of a run get the same id.
    _counter = 0

    def __init__(self) -> None:
        self.current = ""

    def next(self) -> int:
        _Filler._counter += 1
        return _Filler._counter

    def value(self, ann, name: str):
        origin = typing.get_origin(ann)
        args = typing.get_args(ann)
        if origin in (typing.Union, types.UnionType):
            inner = [a for a in args if a is not type(None)]
            return self.value(inner[0], name)
        if origin is typing.Literal:
            return args[0]
        if origin in (list, set, frozenset, tuple):
            item = args[0] if args else str
            if item is str:
                return [f"{name}-b", f"{name}-a"]
            items = [self.value(item, name), self.value(item, name)]
            # Out of order on purpose: an unordered list must sign the same either way.
            return items[::-1] if item is UUID else items
        if origin is dict:
            val = args[1] if len(args) == 2 else str
            return {"k2": self.value(val, name), "k1": self.value(val, name)}
        if ann is str:
            if name == "reason_digest":
                return "hmac-sha256:" + "a" * 64
            if name == "outcome":
                return "completed"
            if self.current == "CaseSkip" and name == "reason":
                return "SKIPPED_X"
            if name == "mode" and self.current == "BehaviourDeviationRecord":
                return "alert"
            if name == "kind" and self.current == "BehaviourDeviationRecord":
                return "artifact_changed"
            if name == "image_config_sha256":
                return SHA
            if name.endswith("sha256") or name == "cases_digest":
                return "a" * 64
            if name == "failure_mode":
                return "FAILURE_MODE_X"
            if name.endswith("digest") or name.endswith("hash") or name.endswith("sha256"):
                return SHA
            return f"{name}-{self.next()}"
        if ann is bool:
            return True
        if ann is int:
            return 2
        if ann is float:
            return 0.5
        if ann is UUID:
            return _uuid(self.next())
        if ann is datetime:
            return WHEN
        if inspect.isclass(ann) and issubclass(ann, Enum):
            return list(ann)[0]
        if inspect.isclass(ann) and issubclass(ann, BaseModel):
            return self.model(ann)
        if ann in (typing.Any, object) or ann is dict:
            return {"k": "v"}
        raise TypeError(f"no filler for {name}: {ann!r}")

    def model(self, cls, extra: dict | None = None):
        kwargs: dict = {}
        outer, self.current = self.current, cls.__name__
        for name, field in cls.model_fields.items():
            if name in _BOOKKEEPING:
                continue
            self.current = cls.__name__
            if name == "payload_version" and field.default is not PydanticUndefined:
                kwargs[name] = field.default
            else:
                kwargs[name] = self.value(field.annotation, name)
        self.current = outer
        override = OVERRIDES.get(cls.__name__, {})
        if callable(override):
            override = override((extra or {}).get("payload_version", 0))
        kwargs.update(override)
        kwargs.update(extra or {})
        return cls(**kwargs)


def build_all(types_module, registry_versions) -> list[tuple[str, object, int]]:
    """``(family, signed record, payload_version)`` for every registered family,
    at every version the registry accepts."""
    out = []
    for family, versions in sorted(registry_versions.items()):
        cls = getattr(types_module, family)
        for version in versions:
            filler = _Filler()
            extra = {"payload_version": version} if "payload_version" in cls.model_fields else {}
            record = filler.model(cls, extra)
            out.append((family, record.sign(HMAC_KEY), version))
    return out

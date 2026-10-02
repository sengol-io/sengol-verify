"""The signing tables of sengol and of the vendored copy, in one comparable shape.

``sengol_tables`` reads them from a sengol checkout's own classes (run inside
that checkout's environment); ``vendored_tables`` reads ``sengol_verify``'s.
``generate_fixtures.py`` snapshots the former into
``tests/fixtures/sengol_tables.json``; ``crosscheck.py`` compares it live, and
``tests/test_sengol_tables.py`` compares the snapshot, so a drift in either
fails without a sengol install.

Shape, every key sorted::

    {"versions": {family: [int]},
     "record_types": {record_type: family},
     "unsigned": {family: [field]},      # signature fields included
     "unordered": {family: [field]},
     "nested_unsigned": {family: {"a.b": [field]}}}
"""

from __future__ import annotations

import inspect
import sys
import typing
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"


def _models_in(annotation) -> list:
    from pydantic import BaseModel

    found = []
    if inspect.isclass(annotation) and issubclass(annotation, BaseModel):
        found.append(annotation)
    for arg in typing.get_args(annotation):
        found += _models_in(arg)
    return found


def _nested(cls, path: tuple, seen: frozenset, out: dict) -> None:
    for name, field in cls.model_fields.items():
        for model in _models_in(field.annotation):
            sub = path + (name,)
            unsigned = getattr(model, "UNSIGNED_FIELDS", frozenset())
            if unsigned:
                out[".".join(sub)] = sorted(unsigned)
            if model not in seen:
                _nested(model, sub, seen | {model}, out)


def _reachable(nested: dict, unsigned: list) -> dict:
    """Drop paths under an unsigned parent: that parent leaves the signature whole."""
    return {
        p: f
        for p, f in nested.items()
        if not any(p == u or p.startswith(u + ".") for u in unsigned)
    }


def sengol_tables(types_module, registry) -> dict:
    """Read the tables from sengol's ``core.types`` and ``core.payload_registry``."""
    always = frozenset(registry.ALWAYS_UNSIGNED_FIELDS)
    tables: dict = {
        "versions": {f: sorted(v) for f, v in sorted(registry._VERSIONS.items())},
        "record_types": {
            rt: cls.__name__ for rt, cls in sorted(types_module.AUDIT_RECORD_TYPES.items())
        },
        "unsigned": {},
        "unordered": {},
        "nested_unsigned": {},
    }
    for family in tables["versions"]:
        cls = getattr(types_module, family)
        tables["unsigned"][family] = sorted(always | getattr(cls, "UNSIGNED_FIELDS", frozenset()))
        unordered = getattr(cls, "UNORDERED_FIELDS", frozenset())
        if unordered:
            tables["unordered"][family] = sorted(unordered)
        nested: dict = {}
        _nested(cls, (), frozenset({cls}), nested)
        nested = _reachable(nested, tables["unsigned"][family])
        if nested:
            tables["nested_unsigned"][family] = dict(sorted(nested.items()))
    return tables


def vendored_tables() -> dict:
    """The same tables as ``sengol_verify.canonical`` applies them."""
    if str(_SRC) not in sys.path:
        sys.path.insert(0, str(_SRC))
    from sengol_verify import canonical as C

    tables: dict = {
        "versions": {f: sorted(v) for f, v in sorted(C._VERSIONS.items())},
        "record_types": dict(sorted(C.RECORD_TYPE_TO_FAMILY.items())),
        "unsigned": {},
        "unordered": {},
        "nested_unsigned": {},
    }
    for family in tables["versions"]:
        tables["unsigned"][family] = sorted(C._unsigned_fields(family))
        if family in C._UNORDERED_FIELDS:
            tables["unordered"][family] = sorted(C._UNORDERED_FIELDS[family])
        nested = _reachable(
            {
                ".".join(path): sorted(fields)
                for path, fields in C.nested_unsigned_fields(family).items()
            },
            tables["unsigned"][family],
        )
        if nested:
            tables["nested_unsigned"][family] = dict(sorted(nested.items()))
    return tables


def diff(sengol: dict, vendored: dict) -> list[str]:
    """Human-readable differences; empty when the tables agree."""
    out = []
    for section in sengol:
        a, b = sengol[section], vendored.get(section)
        if a == b:
            continue
        for key in sorted(set(a) | set(b or {})):
            if a.get(key) != (b or {}).get(key):
                out.append(
                    f"{section}[{key}]: sengol={a.get(key)!r} vendored={(b or {}).get(key)!r}"
                )
    return out

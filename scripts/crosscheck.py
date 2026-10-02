"""Cross-check sengol-verify against a sengol checkout; exits 1 on any divergence.

    cd "$SENGOL" && PYTHONPATH=/path/to/sengol-verify/src uv run --with rfc8785 python \
        /path/to/sengol-verify/scripts/crosscheck.py "$SENGOL"

``SENGOL`` may be left out when ``SENGOL_CHECKOUT`` names it. Not part of the
test suite, which cannot import sengol; ``tests/test_sengol_tables.py`` replays
the table comparison from the committed snapshot instead. This script checks:

1. the signing tables (families, versions, record types, unsigned, unordered
   and nested-unsigned fields), read live from sengol's classes;
2. for every registered family at every version, sengol's canonical bytes and
   HMAC against ``sengol_verify``'s, on a record with every field populated;
3. the ``field_coverage`` step, against sengol's, on every audit family;
4. sengol's own ``verify_bundle`` against ``sengol_verify`` on a hash-chained
   partition of every audit family, a judge evidence pack and the small chains,
   with and without a trusted key, and on a forged re-signed copy.
"""

# ruff: noqa: I001, E402
# The checkout argument must reach sys.path before sengol is imported, so the
# import order below is deliberate.
from __future__ import annotations

import ast
import base64
import copy
import hashlib
import hmac
import sys

import generate_fixtures as G

import _bundles as B
import _families as F
import _tables as TB
import sengol.core.types as T
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sengol.core import payload_registry as P
from sengol.governance.offline_verify import _check_field_coverage as SENGOL_COVERAGE
from sengol.governance.offline_verify import verify_bundle as sengol_verify

from sengol_verify.canonical import Record, family_for
from sengol_verify.verify import _check_field_coverage as VERIFY_COVERAGE
from sengol_verify.verify import verify_bundle as verify_verify

FAILURES: list[str] = []


def fail(message: str) -> None:
    FAILURES.append(message)
    print("MISMATCH:", message)


def check_tables() -> None:
    drift = TB.diff(TB.sengol_tables(T, P), TB.vendored_tables())
    for line in drift:
        fail("table " + line)
    print("tables:", "agree" if not drift else f"{len(drift)} difference(s)")


def _listed(detail: str) -> list[str]:
    return ast.literal_eval(detail[detail.rindex("[") :])


def check_records() -> None:
    for family, real, version in F.build_all(T, P._VERSIONS):
        label = f"{family} v{version}"
        raw = real.model_dump(mode="json")
        name = family_for(raw) if raw.get("record_type") else family
        mine = Record(raw, name)
        if mine.canonical_payload() != real._canonical_payload():
            fail(f"canonical bytes {label}")
            continue
        expected = hmac.new(
            F.HMAC_KEY.encode(), mine.canonical_payload().encode(), hashlib.sha256
        ).hexdigest()
        if raw["hmac_signature"] != expected:
            fail(f"hmac {label}")
            continue
        if isinstance(real, T.AuditRecord):
            theirs = _listed(SENGOL_COVERAGE([real]).detail)
            ours = [n for n in _listed(VERIFY_COVERAGE([mine]).detail) if "." not in n]
            if ours != theirs:
                fail(f"field_coverage {label}: sengol {theirs} vs {ours}")
        print(f"ok {label}")


def _steps(result) -> dict:
    return {s.check: s.result for s in result.step_results}


def check_bundle(name: str, bundle: dict, key_pem: str, *, portable: bool = False) -> None:
    trusted = {B.ED25519_KEY_ID: key_pem}
    # Steps both sides run, with every key supplied and with none.
    for label, keys in (("trusted", trusted), ("no key", None)):
        theirs = _steps(sengol_verify(bundle, portable=portable, trusted_keys=keys))
        mine_result = verify_verify(bundle, portable=portable, trusted_keys=keys)
        mine = _steps(mine_result)
        for step, result in mine.items():
            if step in theirs and theirs[step] != result:
                fail(f"{name} [{label}] {step}: sengol {theirs[step]} vs {result}")
        print(
            f"{name} [{label}]: sengol {sorted(set(theirs.values()))} "
            f"verifier {mine_result.verdict}"
        )
    # A forged, re-signed copy under an attacker key must FAIL when trusted keys are supplied.
    attacker = Ed25519PrivateKey.generate()
    forged = copy.deepcopy(bundle)
    forged["public_keys"][B.ED25519_KEY_ID] = B.public_pem(attacker)
    for cs in forged["countersignatures"]:
        cs["signature"] = base64.b64encode(
            attacker.sign(bytes.fromhex(cs["payload_hash"]))
        ).decode()
    for label, keys in (("trusted", trusted), ("no key", None)):
        theirs = _steps(sengol_verify(forged, portable=portable, trusted_keys=keys))
        mine = _steps(verify_verify(forged, portable=portable, trusted_keys=keys))
        if theirs["ed25519_countersig"] != mine["ed25519_countersig"]:
            fail(f"{name} forged [{label}] ed25519_countersig differs")
    print(f"{name} forged: ok")


def check_deleted_keys(bundle: dict, key_pem: str) -> None:
    """Deleting any signed key of any record FAILs both verifiers."""
    trusted = {B.ED25519_KEY_ID: key_pem}
    unsigned = TB.vendored_tables()["unsigned"]
    count = 0
    for i, raw in enumerate(bundle["records"]):
        family = family_for(raw)
        for name, value in raw.items():
            if name in unsigned[family] or value is None:
                continue
            edited = copy.deepcopy(bundle)
            del edited["records"][i][name]
            try:
                theirs = sengol_verify(edited, trusted_keys=trusted).verdict
            except ValueError:  # pydantic refuses a record missing a required field
                theirs = "FAIL"
            mine = verify_verify(edited, trusted_keys=trusted).verdict
            count += 1
            if theirs != "FAIL" or mine != "FAIL":
                fail(f"deleted {family}.{name}: sengol {theirs}, verifier {mine}")
    print(f"deleted-key check: {count} deletions")


def check_bundles() -> None:
    key = Ed25519PrivateKey.generate()
    pem = B.public_pem(key)
    for name, bundle in G.simple_bundles(key, pem).items():
        check_bundle(name, bundle, pem)
    partition = G.partition_bundle(key, pem)
    check_bundle("partition_bundle", partition, pem)
    check_deleted_keys(partition, pem)
    check_bundle("judge_evidence_pack", G.judge_pack(key, pem), pem, portable=True)


def main() -> int:
    check_tables()
    check_records()
    check_bundles()
    print("RESULT:", "FAIL" if FAILURES else "OK")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())

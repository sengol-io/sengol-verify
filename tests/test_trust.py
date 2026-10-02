"""Countersignature trust, step 0, signed-field presence and exit codes.

A bundle's own ``public_keys`` is part of the file under check, so a forger who
rewrites the records can countersign with a fresh key and embed its public
half. Only a key the caller supplies out of band attributes the evidence.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from helpers import FIXTURES, KEY_ID, TRUST_ARGS, TRUSTED_KEYS, TRUSTED_PEM_PATH

from sengol_verify.bundle import reconstruct_countersigs, reconstruct_records
from sengol_verify.canonical import Record, family_for
from sengol_verify.cli import EXIT_NO_TRUSTED_KEY, main
from sengol_verify.verify import (
    _check_payload_hashes,
    _check_signed_field_presence,
    verify_bundle,
)

_TABLES = json.loads((FIXTURES / "sengol_tables.json").read_text())
_HMAC_KEY = "not-a-real-secret-do-not-reuse"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _steps(result) -> dict:
    return {s.check: s for s in result.step_results}


def _write(tmp_path, bundle: dict, name: str = "bundle.json"):
    path = tmp_path / name
    path.write_text(json.dumps(bundle))
    return path


def _pem(key: Ed25519PrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


def _payload_hash(raw: dict) -> str:
    payload = Record(raw, family_for(raw)).canonical_payload()
    return hashlib.sha256(payload.encode()).hexdigest()


def _forge(bundle: dict, key: Ed25519PrivateKey) -> dict:
    """Edit a record, re-hash the chain after it, countersign everything with
    *key* and embed its public half under the genuine key id."""
    forged = copy.deepcopy(bundle)
    forged["records"][1]["eval_result"]["scores"][0]["passed"] = False
    prev = ""
    for raw in forged["records"]:
        raw["prev_hash"] = prev
        prev = _payload_hash(raw)
    by_record = {r["record_id"]: r for r in forged["records"]}
    for cs in forged["countersignatures"]:
        cs["payload_hash"] = _payload_hash(by_record[cs["record_id"]])
        cs["signature"] = base64.b64encode(key.sign(bytes.fromhex(cs["payload_hash"]))).decode()
    forged["public_keys"][KEY_ID] = _pem(key)
    forged["anchor_receipts"] = []
    return forged


def test_genuine_bundle_countersigs_pass_only_against_a_supplied_key():
    bundle = _load("bundle_full_pass.json")
    without = _steps(verify_bundle(bundle))["ed25519_countersig"]
    assert without.result == "UNVERIFIABLE"
    assert "no trusted key" in without.detail
    with_key = _steps(verify_bundle(bundle, trusted_keys=TRUSTED_KEYS))["ed25519_countersig"]
    assert with_key.result == "PASS"
    assert verify_bundle(bundle).verdict == "UNVERIFIABLE"
    assert verify_bundle(bundle, trusted_keys=TRUSTED_KEYS).verdict == "PASS"


def test_forged_resigned_bundle_with_an_attacker_key_embedded_fails_against_a_trusted_key():
    forged = _forge(_load("bundle_full_pass.json"), Ed25519PrivateKey.generate())
    steps = _steps(verify_bundle(forged, trusted_keys=TRUSTED_KEYS))
    # Internally consistent: the records, hashes and chain all agree with the forger's key.
    assert steps["payload_hash_integrity"].result == "PASS"
    assert steps["chain_continuity"].result == "PASS"
    assert steps["ed25519_countersig"].result == "FAIL"
    assert verify_bundle(forged, trusted_keys=TRUSTED_KEYS).verdict == "FAIL"


def test_forged_bundle_is_never_a_pass_without_a_trusted_key():
    forged = _forge(_load("bundle.json"), Ed25519PrivateKey.generate())
    result = verify_bundle(forged)
    assert _steps(result)["ed25519_countersig"].result == "UNVERIFIABLE"
    assert result.verdict != "PASS"


def test_forged_bundle_cli_exits_2_with_a_key_and_nonzero_without(tmp_path, capsys):
    path = _write(tmp_path, _forge(_load("bundle.json"), Ed25519PrivateKey.generate()))
    assert main([str(path), *TRUST_ARGS]) == 2
    capsys.readouterr()
    code = main([str(path)])
    assert code == EXIT_NO_TRUSTED_KEY != 0
    assert "NO TRUSTED KEY SUPPLIED" in capsys.readouterr().err


def test_empty_trusted_keys_fail_every_countersig():
    steps = _steps(verify_bundle(_load("bundle_full_pass.json"), trusted_keys={}))
    step = steps["ed25519_countersig"]
    assert step.result == "FAIL"
    assert step.detail.count("not in trusted keys") == 3


def test_a_key_id_missing_from_trusted_keys_fails_though_the_bundle_embeds_it():
    bundle = _load("bundle_full_pass.json")
    assert KEY_ID in bundle["public_keys"]
    other = {"some-other-key": TRUSTED_KEYS[KEY_ID]}
    assert _steps(verify_bundle(bundle, trusted_keys=other))["ed25519_countersig"].result == "FAIL"


def test_a_trusted_key_that_does_not_match_the_signature_fails():
    wrong = {KEY_ID: _pem(Ed25519PrivateKey.generate())}
    result = _steps(verify_bundle(_load("bundle_full_pass.json"), trusted_keys=wrong))
    assert result["ed25519_countersig"].result == "FAIL"


def test_a_trusted_key_that_is_not_ed25519_fails():
    assert (
        _steps(verify_bundle(_load("bundle_full_pass.json"), trusted_keys={KEY_ID: "junk"}))[
            "ed25519_countersig"
        ].result
        == "FAIL"
    )


def test_the_bundles_embedded_key_is_ignored_when_trusted_keys_are_supplied():
    bundle = _load("bundle_full_pass.json")
    bundle["public_keys"][KEY_ID] = "junk"
    steps = _steps(verify_bundle(bundle, trusted_keys=TRUSTED_KEYS))
    assert steps["ed25519_countersig"].result == "PASS"


def test_cli_without_a_key_exits_3_and_says_so(capsys):
    assert main([str(FIXTURES / "bundle_full_pass.json")]) == EXIT_NO_TRUSTED_KEY
    captured = capsys.readouterr()
    assert "NO TRUSTED KEY SUPPLIED" in captured.err
    assert "Verdict: UNVERIFIABLE" in captured.out


def test_cli_json_reports_whether_a_key_was_supplied(capsys):
    path = str(FIXTURES / "bundle_full_pass.json")
    assert main([path, "--json"]) == EXIT_NO_TRUSTED_KEY
    assert json.loads(capsys.readouterr().out)["trusted_key_supplied"] is False
    assert main([path, "--json", *TRUST_ARGS]) == 0
    assert json.loads(capsys.readouterr().out)["trusted_key_supplied"] is True


def test_cli_exit_codes_with_a_key():
    assert main([str(FIXTURES / "bundle_full_pass.json"), *TRUST_ARGS]) == 0
    assert main([str(FIXTURES / "bundle.json"), *TRUST_ARGS]) == 1  # HMAC withheld
    assert main([str(FIXTURES / "bundle_tampered.json"), *TRUST_ARGS]) == 2
    assert main([str(FIXTURES / "bundle_chain_break.json"), *TRUST_ARGS]) == 2


def test_cli_fail_is_exit_2_with_or_without_a_key():
    assert main([str(FIXTURES / "bundle_tampered.json")]) == 2


def test_cli_trusted_keys_file_and_repeated_keys(tmp_path):
    path = str(FIXTURES / "bundle_full_pass.json")
    keys_file = tmp_path / "keys.json"
    keys_file.write_text(json.dumps(TRUSTED_KEYS))
    assert main([path, "--trusted-keys-file", str(keys_file)]) == 0
    other = tmp_path / "other.pem"
    other.write_text(_pem(Ed25519PrivateKey.generate()))
    # Repeatable; a --trusted-key overrides the same key id from the file.
    assert main([path, "--trusted-key", f"x={other}", *TRUST_ARGS]) == 0
    assert (
        main([path, "--trusted-keys-file", str(keys_file), "--trusted-key", f"{KEY_ID}={other}"])
        == 2
    )


def test_cli_empty_trusted_keys_file_trusts_nothing(tmp_path):
    keys_file = tmp_path / "keys.json"
    keys_file.write_text("{}")
    assert (
        main([str(FIXTURES / "bundle_full_pass.json"), "--trusted-keys-file", str(keys_file)]) == 2
    )


@pytest.mark.parametrize(
    "argv",
    [
        ["--trusted-key", "no-equals-sign"],
        ["--trusted-key", f"{KEY_ID}=/nonexistent/key.pem"],
        ["--trusted-keys-file", "/nonexistent/keys.json"],
    ],
)
def test_cli_unreadable_trust_arguments_exit_2(argv, capsys):
    assert main([str(FIXTURES / "bundle_full_pass.json"), *argv]) == 2
    assert "sengol-verify:" in capsys.readouterr().err


def test_cli_trusted_keys_file_must_be_an_object(tmp_path):
    keys_file = tmp_path / "keys.json"
    keys_file.write_text("[]")
    assert (
        main([str(FIXTURES / "bundle_full_pass.json"), "--trusted-keys-file", str(keys_file)]) == 2
    )


# --- step 0 -----------------------------------------------------------------


def test_a_value_with_no_rfc8785_form_fails_the_canonical_payload_step():
    bundle = _load("bundle_full_pass.json")
    victim = bundle["records"][0]
    victim["extra_signed_value"] = 2**60
    step = _steps(verify_bundle(bundle, trusted_keys=TRUSTED_KEYS))["canonical_payload"]
    assert step.result == "FAIL"
    assert victim["record_id"] in step.detail


def test_an_unregistered_payload_version_fails_the_canonical_payload_step():
    bundle = _load("bundle_full_pass.json")
    bundle["records"][0]["payload_version"] = 99
    step = _steps(verify_bundle(bundle, trusted_keys=TRUSTED_KEYS))["canonical_payload"]
    assert step.result == "FAIL"
    assert "99" in step.detail


def test_canonical_payload_passes_on_a_genuine_bundle():
    step = _steps(verify_bundle(_load("partition_bundle.json")))["canonical_payload"]
    assert step.result == "PASS"


# --- signed-field presence ---------------------------------------------------
# sengol rebuilds a record with model_validate, where a deleted key is refilled
# by its default and can reproduce the signed bytes. This verifier does not
# refill: it hashes the keys the bundle carries, so a deleted signed key changes
# the bytes and fails the payload hash. Keys it reads with a default are
# required by the signed_field_presence step.


def test_deleting_any_signed_field_of_any_record_fails_the_bundle():
    bundle = _load("partition_bundle.json")
    checked = 0
    for i, raw in enumerate(bundle["records"]):
        family = family_for(raw)
        unsigned = set(_TABLES["unsigned"][family])
        for name, value in raw.items():
            if name in unsigned or value is None:
                continue
            edited = copy.deepcopy(bundle)
            del edited["records"][i][name]
            records = reconstruct_records(edited)
            results = {
                _check_payload_hashes(records, reconstruct_countersigs(edited)).result,
                _check_signed_field_presence(records).result,
            }
            assert "FAIL" in results, (family, name)
            checked += 1
    assert checked > 200


def test_a_record_without_record_id_fails_signed_field_presence():
    bundle = _load("bundle_full_pass.json")
    del bundle["records"][2]["record_id"]
    steps = _steps(verify_bundle(bundle, trusted_keys=TRUSTED_KEYS))
    # Without the join key it reads as uncountersigned, which alone is only UNVERIFIABLE.
    assert steps["payload_hash_integrity"].result == "UNVERIFIABLE"
    assert steps["signed_field_presence"].result == "FAIL"
    assert "record_id" in steps["signed_field_presence"].detail


def test_signed_field_presence_passes_on_genuine_bundles():
    for name in ("bundle.json", "partition_bundle.json", "judge_evidence_pack.json"):
        step = _steps(verify_bundle(_load(name)))["signed_field_presence"]
        assert step.result == "PASS", name


# --- regression evidence: a certification must bind its run -------------------


def _regression_bundle(mutate=None) -> dict:
    bundle = _load("partition_bundle.json")
    bundle["public_keys"]["hmac_material"] = {"test-hmac-key-1": _HMAC_KEY}
    if mutate:
        mutate(bundle["regression_evidence"]["records"])
    return bundle


def test_regression_lineage_passes_on_the_genuine_section():
    step = _steps(verify_bundle(_regression_bundle()))["regression_lineage"]
    assert step.result == "PASS", step.detail


@pytest.mark.parametrize("value", [None, ""])
def test_certification_without_run_payload_sha256_fails(value):
    def drop(entries):
        cert = next(e for e in entries if e["family"] == "CertificationRecord")
        if value is None:
            del cert["record"]["run_payload_sha256"]
        else:
            cert["record"]["run_payload_sha256"] = value

    step = _steps(verify_bundle(_regression_bundle(drop)))["regression_lineage"]
    assert step.result == "FAIL"
    assert "run_payload_sha256 is missing" in step.detail


def test_certification_with_a_wrong_run_hash_still_fails():
    def wrong(entries):
        cert = next(e for e in entries if e["family"] == "CertificationRecord")
        cert["record"]["run_payload_sha256"] = "0" * 64

    step = _steps(verify_bundle(_regression_bundle(wrong)))["regression_lineage"]
    assert step.result == "FAIL"
    assert "does not match" in step.detail


def test_trusted_key_fixture_is_the_one_the_bundles_embed():
    assert _load("bundle.json")["public_keys"][KEY_ID] == TRUSTED_PEM_PATH.read_text()

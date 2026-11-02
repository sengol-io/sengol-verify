"""``--collector-secret-id`` names OTLP call records by their derived id."""

from __future__ import annotations

import json
from uuid import uuid5

from sengol_verify import cli
from sengol_verify.origins import OTLP_CALL_NAMESPACE, otlp_call_origins
from sengol_verify.verify import BundleResult, StepResult

TENANT, AGENT, TRACE, SPAN = "acme", "bot", "a" * 32, "b" * 16


def _rec(scope: str) -> dict:
    rid = uuid5(OTLP_CALL_NAMESPACE, f"{scope}:{AGENT}:{TRACE}:{SPAN}")
    return {
        "record_id": str(rid),
        "tenant_id": TENANT,
        "agent_id": AGENT,
        "trace_id": TRACE,
        "span_id": SPAN,
    }


def test_the_server_derived_id_reads_server():
    rec = _rec(TENANT)
    assert otlp_call_origins([rec]) == {rec["record_id"]: "server"}


def test_a_collector_id_needs_the_secret_id_to_be_named():
    rec = _rec(f"{TENANT}|collector=s1")
    assert otlp_call_origins([rec]) == {}
    assert otlp_call_origins([rec], ["s0", "s1"]) == {rec["record_id"]: "collector:s1"}


def test_an_sdk_record_and_a_record_without_a_span_are_absent():
    sdk = {**_rec(TENANT), "record_id": "00000000-0000-0000-0000-000000000001"}
    bare = {**_rec(TENANT), "span_id": None}
    assert otlp_call_origins([sdk, bare], ["s1"]) == {}


def _patch(monkeypatch, result: str, records: list):
    step = StepResult("ed25519_countersig", "bundle", result, "")
    monkeypatch.setattr(cli, "verify_bundle", lambda *a, **k: BundleResult([step]))
    monkeypatch.setattr(cli, "load_bundle", lambda p: {"records": records})


def test_the_cli_prints_the_attribution_when_nothing_failed(tmp_path, monkeypatch, capsys):
    rec = _rec(f"{TENANT}|collector=s1")
    _patch(monkeypatch, "PASS", [rec])
    bundle = tmp_path / "b.json"
    bundle.write_text("{}")
    code = cli.main([str(bundle), "--json", "--collector-secret-id", "s1"])
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["otlp_call_origins"] == {rec["record_id"]: "collector:s1"}


def test_the_cli_names_nobody_when_a_step_failed(tmp_path, monkeypatch, capsys):
    _patch(monkeypatch, "FAIL", [_rec(f"{TENANT}|collector=s1")])
    bundle = tmp_path / "b.json"
    bundle.write_text("{}")
    code = cli.main([str(bundle), "--json", "--collector-secret-id", "s1"])
    assert code == 1
    assert json.loads(capsys.readouterr().out)["otlp_call_origins"] == {}

# sengol-verify

A standalone, offline verifier for [Sengol](https://github.com/sengol) signed
evidence bundles — the file `sengol audit export` produces.

## What it verifies

Given a bundle (records, Ed25519 countersignatures, Merkle anchor receipts,
and public key material), it recomputes these checks entirely from the bytes
in the file. Step 0 and step 7 are named for the checks of the same name in
sengol's own verifier; the rest are numbered as before:

0. **Canonical payload** — every record has a canonical payload at all. A
   value with no RFC 8785 form (NaN, infinity, an integer beyond 2^53), a
   payload version the family does not register, or a `record_type` this
   tool does not register FAILs here, naming the record.
1. **Payload hash integrity** — each record's canonical payload still
   hashes to the value its countersignature committed to.
2. **HMAC verification** — if the bundle embeds HMAC key material (rare;
   normally withheld for security), the symmetric signature is checked too.
3. **Hash-chain continuity** — `sequence_number` is monotone per
   `(tenant_id, agent_id)` partition and every `prev_hash` links to the
   previous record's canonical-payload hash.
4. **Ed25519 countersignature verification** — each countersignature is
   checked against its record's payload hash. The key it is checked against
   decides what a pass means; see "Trusting the countersignature key" below.
5. **Merkle anchor coverage** — each anchor receipt's Merkle root is
   recomputed from its leaf hashes and compared.
6. **Field coverage** — a report, not a check: it never FAILs. Every set
   field is signed except the signature fields, the family's unsigned fields
   and a few nested ones (an evaluator score's `reason` and `reason_status`,
   a regression case binding's `config` and `reference`; all listed under
   "How"), so steps 1-5 already cover everything else. This step names
   which of those by-design unsigned fields the bundle's records actually
   carry (for example `hmac_signature`, `eval_result.scores.reason`), so you
   know which values no check vouches for. Its row always reads PASS; it does
   not detect an edit to an unsigned field, and a record with an unregistered
   `record_type` is not assessed (the detail says how many).
7. **Signed-field presence** — the keys this tool would otherwise read with a
   default (`record_id`, `tenant_id`, `agent_id`, `sequence_number`,
   `prev_hash`, `key_id`, `payload_version`) are present on every record.
   Nothing is refilled from a default here, so deleting any other signed key
   changes the recomputed bytes and fails step 1 or 2; a record with no
   `record_id` matches no countersignature and would otherwise read as merely
   "not countersigned yet".

If the bundle has an optional top-level `regression_evidence` section
(`{"format": "sengol-regression-evidence/v1", "agent_id": ..., "records":
[{"family": ..., "record": {...}}]}`), a seventh step, **`regression_lineage`**,
is added. Any other `format` FAILs, and every record's signed `agent_id` must
equal the section's `agent_id`. Every family is one of the six regression
families (failure, case, run, certification, and the unsigned retirement and
waiver; unknown = FAIL), each record's canonical payload / HMAC (UNVERIFIABLE without
`public_keys["hmac_material"]`) checks out, and every link
resolves (case -> failure, retirement -> case, waiver -> failure, run
`case_results` -> case, certification `run_id` -> a run in the section, and
its `run_payload_sha256` -> that run's canonical-payload hash, with the same
`agent_version` as the run). A certification with no `run_payload_sha256`
FAILs, because it binds no run (sengol's deploy gate refuses it the same way).
Dangling ids and hash mismatches FAIL and are named. The signed records are not chained, so a deleted
record is not detectable. Retirements and waivers are exported unsigned (sengol
ADR-0024, families `RegressionCaseRetirement` and `ProductionFailureWaiver`),
so they have no HMAC to check; only their `agent_id` and links are verified.
The old signed families `RegressionCaseRetirementRecord` and
`ProductionFailureWaiverRecord` are not registered and FAIL as unknown.
Bundles without the section, or with it set to `null`, verify exactly as
before.

The verdict is **PASS**, **FAIL** (tampering or a broken chain), or
**UNVERIFIABLE** (the bundle honestly doesn't carry enough — e.g. no
countersignatures yet, no anchor receipts, or no trusted key).

## How

Nothing here is normalized, coerced, or "cleaned up" before verification:
this tool recomputes over the bytes exactly as stored, which is what makes
offline verification meaningful months after the evidence was written. The
canonical payload is built by the same rule sengol signs with (RFC 8785 over
`{"record": <set fields>, "type": <family>}`, minus each family's unsigned
fields, with unordered lists sorted), using signing tables vendored from
sengol's `payload_registry.py` and `types.py`. They are not imported from
sengol, so they can drift. Two things keep them honest: `scripts/crosscheck.py`
compares them with a sengol checkout's own classes and bytes (every registered
family at every payload version, a hash-chained partition of every audit
family, a judge evidence pack), and the committed fixtures, which sengol itself
signed, are replayed by the tests; `tests/test_sengol_tables.py` fails when a
vendored table differs from the snapshot of sengol's. A sengol release newer
than the snapshot is not covered until the fixtures are regenerated
(`scripts/generate_fixtures.py`).

Some fields of an exported record are outside the signature by design
(sengol's `UNSIGNED_FIELDS`), so no check here covers them; the
`field_coverage` row lists the ones a bundle's records carry:

- an evaluator score's `reason` text and `reason_status` (sengol ADR-0078).
  The signed `reason_digest` is a keyed HMAC under an install key this tool
  never holds, so the text can be edited or erased without failing a check,
  and this tool does not verify it. The digest itself is signed;
- `CertificationRecord.evidence_pack_id` and `.anchor_record_id`,
  `SaturationEvent.remediated_at`, the raw `config` and `reference` of a
  regression case binding (their hashes are signed), and the `eval_result`,
  `mcp_server_version`, `model`, token and cost fields of an
  `AuthorizationDecisionRecord`;
- `call_signature_manifests`, a transport-only field sengol removes before
  storing a record.

```bash
pip install sengol-verify
sengol-verify bundle.json --trusted-key appliance-key-1=appliance.pub.pem
sengol-verify path/to/bundle-dir/ --trusted-keys-file trusted.json
sengol-verify bundle.zip --trusted-key appliance-key-1=appliance.pub.pem
sengol-verify bundle.json --trusted-key ... --json   # machine-readable
```

### Trusting the countersignature key

A bundle's own `public_keys` is part of the file being checked: someone who
rewrites every record can mint a new Ed25519 key, countersign with it, and embed
its public half, and every check above still passes against that key. A
countersignature that verifies against a key from the bundle proves the file is
internally consistent, not which appliance produced it. Give the verifier the
appliance's public key from outside the bundle (the operator, or the key you
recorded at commissioning):

- `--trusted-key KEY_ID=PEM_PATH`, repeatable: the Ed25519 public key (PEM
  file) for countersignatures whose `key_id` is `KEY_ID`.
- `--trusted-keys-file PATH`: a JSON object `{"key_id": "<pem>"}`. Applied
  first, so a `--trusted-key` overrides one of its entries.

With no trusted key, the `ed25519_countersig` step still checks each signature
against the embedded key as a tamper signal but reports at most UNVERIFIABLE,
and the command exits 3 with a message saying so. With any trusted key supplied
(even an empty file, meaning "trust nothing"), only those keys are used: a
countersignature whose `key_id` is not among them, or that does not verify
against it, FAILs. The embedded key is then ignored.

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0`  | PASS, with a trusted key supplied. |
| `1`  | UNVERIFIABLE, with a trusted key supplied (for example the HMAC secret is withheld, or anchors are pending). |
| `2`  | FAIL, whether or not a key was supplied; also a usage, unreadable-file or unreadable-key error. |
| `3`  | No trusted key supplied and no step FAILed. The bundle may be internally consistent but is not attributed to any appliance; treat it as not verified. |

## What it never does

`sengol-verify` never contacts Sengol, any Sengol-operated service, or any
network endpoint at all. It reads one local file and prints a verdict. It
requires no license, no API key, and no account — verification is a
property of the bytes, not a service call.

It also has **zero runtime dependency on the `sengol` package**. Its only
third-party dependencies are [`cryptography`](https://cryptography.io) (for
Ed25519) and [`rfc8785`](https://pypi.org/project/rfc8785/) (for the canonical
JSON the signatures are computed over). This is enforced by a test that imports `sengol_verify` with
`sengol` absent from `sys.modules` and asserts nothing named `sengol` or
`sengol.*` gets imported as a side effect.

## Scope

This tool implements the offline bundle format as of `payload_registry.py`
in sengol at the time it was vendored, including the call-start and
accepted-set-lease families. It registers only families sengol signs: the
families sengol has stopped signing (agent registration and secret records,
retention and legal-hold records, signed regression retirements and waivers,
and the like) are not registered. A bundle record whose `record_type` is not
registered, whether one of those or a type this tool has never heard of, has
no canonical payload here: `payload_hash_integrity` FAILs and names the
record and its `record_type`, and the other steps that need its payload fail
with it. It is never verified as a generic record. A `regression_evidence`
entry naming a family that is not one of the six regression families FAILs as
an unknown family. An export of such a record from an older sengol therefore cannot be
verified with this version. It does not verify anything Sengol didn't sign —
trace IDs, span IDs, and other fields documented as outside every canonical
payload are not assessed by design.

## License

Apache-2.0. See `LICENSE`.

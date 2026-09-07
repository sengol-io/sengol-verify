# sengol-verify

A standalone, offline verifier for [Sengol](https://github.com/sengol) signed
evidence bundles — the file `sengol audit export` produces.

## What it verifies

Given a bundle (records, Ed25519 countersignatures, Merkle anchor receipts,
and public key material), it recomputes six checks entirely from the bytes
in the file:

1. **Payload hash integrity** — each record's canonical payload still
   hashes to the value its countersignature committed to.
2. **HMAC verification** — if the bundle embeds HMAC key material (rare;
   normally withheld for security), the symmetric signature is checked too.
3. **Hash-chain continuity** — `sequence_number` is monotone per
   `(tenant_id, agent_id)` partition and every `prev_hash` links to the
   previous record's canonical-payload hash.
4. **Ed25519 countersignature verification** — each countersignature is
   checked against its record's payload hash using the embedded public key.
5. **Merkle anchor coverage** — each anchor receipt's Merkle root is
   recomputed from its leaf hashes and compared.
6. **Field coverage** — no record carries a field outside what its
   `payload_version` actually signs (a version-skew forgery surface).

The verdict is **PASS**, **FAIL** (tampering or a broken chain), or
**UNVERIFIABLE** (the bundle honestly doesn't carry enough — e.g. no
countersignatures yet, or no anchor receipts).

## How

Nothing here is normalized, coerced, or "cleaned up" before verification —
every canonical-payload function is byte-for-byte the same one Sengol used
to sign the record, and this tool recomputes over the bytes exactly as
stored. That is what makes offline verification meaningful months after the
evidence was written.

```bash
pip install sengol-verify
sengol-verify bundle.json
sengol-verify path/to/bundle-dir/
sengol-verify bundle.zip
sengol-verify bundle.json --json   # machine-readable
```

Exit codes: `0` PASS, `1` UNVERIFIABLE, `2` FAIL or a usage/read error.

## What it never does

`sengol-verify` never contacts Sengol, any Sengol-operated service, or any
network endpoint at all. It reads one local file and prints a verdict. It
requires no license, no API key, and no account — verification is a
property of the bytes, not a service call.

It also has **zero runtime dependency on the `sengol` package** — the only
third-party dependency is [`cryptography`](https://cryptography.io) (for
Ed25519). This is enforced by a test that imports `sengol_verify` with
`sengol` absent from `sys.modules` and asserts nothing named `sengol` or
`sengol.*` gets imported as a side effect.

## Scope

This tool implements the offline bundle format as of `payload_registry.py`
in sengol at the time it was vendored. It covers every record family that
format defines. It does not verify anything Sengol didn't sign — trace IDs,
span IDs, and other fields documented as outside every canonical payload are
not assessed by design (see check 6's detail text).

## License

Apache-2.0. See `LICENSE`.

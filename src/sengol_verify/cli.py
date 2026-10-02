"""``sengol-verify`` — verify a sengol evidence bundle completely offline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sengol_verify import __version__
from sengol_verify.bundle import BundleFormatError
from sengol_verify.verify import verify_bundle_file

#: Exit codes, identical to ``sengol audit verify --offline``.
EXIT_OK = 0
#: Any step FAILed. Always wins over every other outcome.
EXIT_FAIL = 1
#: Usage error, unreadable bundle or keys file, malformed --trusted-key.
EXIT_USAGE = 2
#: Nothing FAILed, but the ``ed25519_countersig`` step is not PASS: the
#: bundle is not attributed to a trusted appliance key.
EXIT_TRUST_NOT_ESTABLISHED = 3

_COUNTERSIG_STEP = "ed25519_countersig"

_UNPINNED_NOTICE = (
    "COUNTERSIGNATURE TRUST NOT ESTABLISHED (no trusted key supplied): "
    "countersignatures were checked only against the public key embedded in "
    "this same bundle, so they prove internal consistency, not which "
    "appliance produced it. Fix: pass the appliance's public key from an "
    "out-of-band source with --trusted-key KEY_ID=PEM_PATH (repeatable) or "
    "--trusted-keys-file PATH. A bundle with no countersignatures at all "
    "cannot reach PASS even with a key; re-export it with countersigning. "
    "Exiting 3."
)
_UNCOUNTERSIGNED_NOTICE = (
    "COUNTERSIGNATURE TRUST NOT ESTABLISHED (trusted key supplied, but the "
    "bundle carries no countersignatures): the countersignatures were "
    "stripped, or countersigning was never enabled, so nothing in the bundle "
    "can be attributed to the appliance and it is NOT accepted. Fix: "
    "re-export the bundle from the appliance after its countersign outbox "
    "has drained (sengol audit export --wait-for-countersign), with "
    "countersigning enabled, and verify that file. Exiting 3."
)


class TrustedKeyError(ValueError):
    """A --trusted-key or --trusted-keys-file argument cannot be read."""


def load_trusted_keys(trusted_key: list, trusted_keys_file: Path | None) -> dict | None:
    """Build ``{key_id: pem}`` from CLI input, never from the bundle.

    ``trusted_key`` entries are ``KEY_ID=PEM_PATH``; ``trusted_keys_file`` is
    a JSON object of the same shape, applied first so a ``--trusted-key``
    overrides one of its entries. Returns ``None`` (not ``{}``) when neither is
    given: "no trusted key" and "trust nothing" are different requests.
    """
    if not trusted_key and trusted_keys_file is None:
        return None
    keys: dict = {}
    if trusted_keys_file is not None:
        try:
            loaded = json.loads(trusted_keys_file.read_text())
        except Exception as exc:
            raise TrustedKeyError(
                f"cannot read --trusted-keys-file ({type(exc).__name__})"
            ) from exc
        if not isinstance(loaded, dict):
            raise TrustedKeyError(
                "--trusted-keys-file must contain a JSON object of {key_id: pem_string}"
            )
        keys.update(loaded)
    for entry in trusted_key:
        key_id, sep, path_str = entry.partition("=")
        if not sep:
            raise TrustedKeyError("--trusted-key must be KEY_ID=PEM_PATH")
        try:
            keys[key_id] = Path(path_str).read_text()
        except Exception as exc:
            raise TrustedKeyError(
                f"cannot read trusted key file {path_str!r} ({type(exc).__name__})"
            ) from exc
    return keys


def _countersig_established(result) -> bool:
    """True when the ``ed25519_countersig`` step is PASS."""
    return any(s.check == _COUNTERSIG_STEP and s.result == "PASS" for s in result.step_results)


def _exit_code(result) -> int:
    """Map step results to an exit code: FAIL, else trust, else OK.

    An overall UNVERIFIABLE verdict from hmac_verify or anchor_coverage does
    not change the code; only the countersignature step does.
    """
    if any(s.result == "FAIL" for s in result.step_results):
        return EXIT_FAIL
    if not _countersig_established(result):
        return EXIT_TRUST_NOT_ESTABLISHED
    return EXIT_OK


def _trust_notice(result, trusted: bool) -> str | None:
    """The stderr message naming why exit 3 was chosen, or None."""
    if _exit_code(result) != EXIT_TRUST_NOT_ESTABLISHED:
        return None
    return _UNCOUNTERSIGNED_NOTICE if trusted else _UNPINNED_NOTICE


def _print_human(path: Path, result, trusted: bool) -> None:
    print(f"sengol-verify: {path}")
    for step in result.step_results:
        print(f"  [{step.result:12}] {step.check} ({step.scope})")
        if step.detail:
            print(f"               {step.detail}")
    notice = _trust_notice(result, trusted)
    if notice:
        print(f"\n{notice}", file=sys.stderr)
    print(f"\nVerdict: {result.verdict}")


def _print_json(path: Path, result, trusted: bool) -> None:
    print(
        json.dumps(
            {
                "bundle": str(path),
                "verdict": result.verdict,
                "trusted_key_supplied": trusted,
                "countersignature_trust_established": _countersig_established(result),
                "steps": [
                    {
                        "check": s.check,
                        "scope": s.scope,
                        "result": s.result,
                        "detail": s.detail,
                    }
                    for s in result.step_results
                ],
            },
            indent=2,
        )
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sengol-verify",
        description=(
            "Verify a sengol evidence bundle (HMAC/Ed25519 signatures, hash "
            "chain, Merkle anchors) entirely offline. Never contacts Sengol "
            "or any network endpoint, and needs no license."
        ),
        epilog=(
            "exit codes: 0 no step failed and countersignatures verified against a "
            "trusted key; 1 a step FAILed; 2 usage error or unreadable input; 3 "
            "countersignature trust not established (no trusted key, or the bundle "
            "carries no countersignatures). Same as `sengol audit verify --offline`."
        ),
    )
    parser.add_argument(
        "bundle",
        type=Path,
        help="Path to a bundle .json file, a directory holding one, or a .zip containing one",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of a human-readable report",
    )
    parser.add_argument(
        "--trusted-key",
        action="append",
        default=[],
        metavar="KEY_ID=PEM_PATH",
        help=(
            "Ed25519 public key (PEM file) obtained out of band, for the countersignature "
            "key_id KEY_ID. Repeatable. Never taken from the bundle."
        ),
    )
    parser.add_argument(
        "--trusted-keys-file",
        type=Path,
        help="JSON object {key_id: pem} of trusted Ed25519 public keys, obtained out of band",
    )
    parser.add_argument("--version", action="version", version=f"sengol-verify {__version__}")
    return parser


def main(argv: list = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.bundle.exists():
        print(f"sengol-verify: {args.bundle}: no such file or directory", file=sys.stderr)
        return EXIT_USAGE

    try:
        trusted_keys = load_trusted_keys(args.trusted_key, args.trusted_keys_file)
    except TrustedKeyError as exc:
        print(f"sengol-verify: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        result = verify_bundle_file(args.bundle, trusted_keys=trusted_keys)
    except BundleFormatError as exc:
        print(f"sengol-verify: {exc}", file=sys.stderr)
        return EXIT_USAGE

    trusted = trusted_keys is not None
    if args.json:
        _print_json(args.bundle, result, trusted)
        notice = _trust_notice(result, trusted)
        if notice:
            print(notice, file=sys.stderr)
    else:
        _print_human(args.bundle, result, trusted)

    return _exit_code(result)


if __name__ == "__main__":
    sys.exit(main())

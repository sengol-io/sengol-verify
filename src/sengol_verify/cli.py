"""``sengol-verify`` — verify a sengol evidence bundle completely offline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sengol_verify import __version__
from sengol_verify.bundle import BundleFormatError
from sengol_verify.verify import verify_bundle_file

_EXIT_BY_VERDICT = {"PASS": 0, "UNVERIFIABLE": 1, "FAIL": 2}
#: No trusted key was supplied and nothing FAILed: the bundle may be internally
#: consistent, but nothing outside the file attributes it to an appliance.
EXIT_NO_TRUSTED_KEY = 3

_NO_TRUSTED_KEY_MESSAGE = (
    "NO TRUSTED KEY SUPPLIED: countersignatures were checked only against the "
    "public key embedded in this same bundle, so they prove internal consistency, "
    "not which appliance produced it. Pass the appliance's public key from an "
    "out-of-band source with --trusted-key KEY_ID=PEM_PATH (repeatable) or "
    "--trusted-keys-file PATH. Exiting 3."
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
            raise TrustedKeyError(f"cannot read --trusted-keys-file: {exc}") from exc
        if not isinstance(loaded, dict):
            raise TrustedKeyError(
                "--trusted-keys-file must contain a JSON object of {key_id: pem_string}"
            )
        keys.update(loaded)
    for entry in trusted_key:
        key_id, sep, path_str = entry.partition("=")
        if not sep:
            raise TrustedKeyError(f"--trusted-key must be KEY_ID=PEM_PATH, got {entry!r}")
        try:
            keys[key_id] = Path(path_str).read_text()
        except Exception as exc:
            raise TrustedKeyError(f"cannot read trusted key file {path_str!r}: {exc}") from exc
    return keys


def _print_human(path: Path, result, trusted: bool) -> None:
    print(f"sengol-verify: {path}")
    for step in result.step_results:
        print(f"  [{step.result:12}] {step.check} ({step.scope})")
        if step.detail:
            print(f"               {step.detail}")
    if not trusted and result.verdict != "FAIL":
        print(f"\n{_NO_TRUSTED_KEY_MESSAGE}", file=sys.stderr)
    print(f"\nVerdict: {result.verdict}")


def _print_json(path: Path, result, trusted: bool) -> None:
    print(
        json.dumps(
            {
                "bundle": str(path),
                "verdict": result.verdict,
                "trusted_key_supplied": trusted,
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
        return 2

    try:
        trusted_keys = load_trusted_keys(args.trusted_key, args.trusted_keys_file)
    except TrustedKeyError as exc:
        print(f"sengol-verify: {exc}", file=sys.stderr)
        return 2

    try:
        result = verify_bundle_file(args.bundle, trusted_keys=trusted_keys)
    except BundleFormatError as exc:
        print(f"sengol-verify: {exc}", file=sys.stderr)
        return 2

    trusted = trusted_keys is not None
    if args.json:
        _print_json(args.bundle, result, trusted)
        if not trusted and result.verdict != "FAIL":
            print(_NO_TRUSTED_KEY_MESSAGE, file=sys.stderr)
    else:
        _print_human(args.bundle, result, trusted)

    if result.verdict == "FAIL":
        return _EXIT_BY_VERDICT["FAIL"]
    if not trusted:
        return EXIT_NO_TRUSTED_KEY
    return _EXIT_BY_VERDICT[result.verdict]


if __name__ == "__main__":
    sys.exit(main())

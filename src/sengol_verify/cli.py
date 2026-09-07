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


def _print_human(path: Path, result) -> None:
    print(f"sengol-verify: {path}")
    for step in result.step_results:
        print(f"  [{step.result:12}] {step.check} ({step.scope})")
        if step.detail:
            print(f"               {step.detail}")
    print(f"\nVerdict: {result.verdict}")


def _print_json(path: Path, result) -> None:
    print(
        json.dumps(
            {
                "bundle": str(path),
                "verdict": result.verdict,
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
    parser.add_argument("--version", action="version", version=f"sengol-verify {__version__}")
    return parser


def main(argv: list = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.bundle.exists():
        print(f"sengol-verify: {args.bundle}: no such file or directory", file=sys.stderr)
        return 2

    try:
        result = verify_bundle_file(args.bundle)
    except BundleFormatError as exc:
        print(f"sengol-verify: {exc}", file=sys.stderr)
        return 2

    if args.json:
        _print_json(args.bundle, result)
    else:
        _print_human(args.bundle, result)

    return _EXIT_BY_VERDICT[result.verdict]


if __name__ == "__main__":
    sys.exit(main())

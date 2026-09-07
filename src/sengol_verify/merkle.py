"""SHA-256 binary Merkle tree, vendored verbatim from sengol's
``sengol/core/merkle.py`` (ADR-0072). Leaves are payload_hash hex strings;
an odd node at each level is promoted (duplicated with its left sibling).
"""

from __future__ import annotations

import hashlib

__all__ = ["merkle_root"]


def merkle_root(leaf_hashes_hex: list[str]) -> str:
    """Compute a SHA-256 binary Merkle root over the given leaf hashes.

    Raises ``ValueError`` if the list is empty.
    """
    if not leaf_hashes_hex:
        raise ValueError("Cannot compute Merkle root of empty list")

    layer = [bytes.fromhex(h) for h in leaf_hashes_hex]

    while len(layer) > 1:
        next_layer: list[bytes] = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else left
            next_layer.append(hashlib.sha256(left + right).digest())
        layer = next_layer

    return layer[0].hex()

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())

"""Small statistics helpers for benchmark reporting."""

from __future__ import annotations

import math


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion (95% by default)."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (max(0.0, centre - half), min(1.0, centre + half))


def rate(k: int, n: int) -> dict[str, float | int]:
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": (k / n) if n else 0.0, "ci95_low": lo, "ci95_high": hi}


def fmt_rate(r: dict[str, float | int]) -> str:
    if not r["n"]:
        return "n/a"
    return f"{100 * r['rate']:.0f}% [{100 * r['ci95_low']:.0f}-{100 * r['ci95_high']:.0f}] (n={r['n']})"

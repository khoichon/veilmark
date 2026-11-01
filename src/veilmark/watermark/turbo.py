"""Rate-1/3 parallel concatenated (turbo) code with iterative max-log-MAP decoding.

Structure follows the 3GPP UMTS turbo code: two identical 8-state recursive
systematic convolutional (RSC) encoders with feedback polynomial 13 and feedforward
polynomial 15 (octal), separated by an interleaver, each terminated with three tail
steps. Output layout: ``[systematic(k), parity1(k), parity2(k), tail1(6), tail2(6)]``.

The interleaver is a fixed pseudo-random permutation derived with SHAKE-256 from a
public constant (it is part of the format, not a secret), so it is identical across
platforms and library versions.

Max-log-MAP is invariant to a common scaling of the input soft values, which suits
the watermark channel where soft values are SNR-weighted but un-calibrated.
Extrinsic information is damped by 0.75, the usual correction for max-log-MAP.
"""

from __future__ import annotations

import functools
from collections.abc import Callable

import numpy as np

from veilmark.crypto import kdf

N_STATES = 8
MEMORY = 3
TAIL_BITS = 12
EXTRINSIC_SCALE = 0.75
_INTERLEAVER_KEY = b"veilmark/turbo-interleaver/v1\x00\x00\x00"


def _tables() -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """next_state[s, u], parity[s, u], and the tail input that drives s towards 0."""
    nxt = np.zeros((N_STATES, 2), dtype=np.int64)
    par = np.zeros((N_STATES, 2), dtype=np.int64)
    tail_u = np.zeros(N_STATES, dtype=np.int64)
    for s in range(N_STATES):
        s1, s2, s3 = (s >> 2) & 1, (s >> 1) & 1, s & 1  # s1 = most recent
        fb = s2 ^ s3  # feedback taps of g0 = 1011 (excluding the input term)
        for u in (0, 1):
            a = u ^ fb
            p = a ^ s1 ^ s3  # g1 = 1101
            nxt[s, u] = (a << 2) | (s1 << 1) | s2
            par[s, u] = p
        tail_u[s] = fb  # makes a == 0, shifting zeros in
    return nxt, par, tail_u


NEXT, PARITY, TAIL_U = _tables()
# Predecessor tables: for each state, the two (prev_state, input) pairs leading to it.
_PRED = [[(s, u) for s in range(N_STATES) for u in (0, 1) if NEXT[s, u] == t] for t in range(N_STATES)]
PRED_S = np.array([[p[0] for p in row] for row in _PRED])  # (8, 2)
PRED_U = np.array([[p[1] for p in row] for row in _PRED])
PRED_P = PARITY[PRED_S, PRED_U]
SYM_U = 1.0 - 2.0 * PRED_U  # BPSK symbols on each incoming branch
SYM_P = 1.0 - 2.0 * PRED_P
NEXT_SYM_U = 1.0 - 2.0 * np.array([[0, 1]] * N_STATES, dtype=np.float64)
NEXT_SYM_P = 1.0 - 2.0 * PARITY.astype(np.float64)


@functools.cache
def interleaver(k: int) -> np.ndarray:
    return kdf.permutation(_INTERLEAVER_KEY, "turbo.interleaver", k, n=k)


def coded_length(k: int) -> int:
    return 3 * k + TAIL_BITS


def _rsc_encode(bits: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    s = 0
    par = np.empty(len(bits), dtype=np.uint8)
    for i, u in enumerate(bits):
        par[i] = PARITY[s, u]
        s = NEXT[s, u]
    tail = []
    for _ in range(MEMORY):
        u = TAIL_U[s]
        tail += [u, PARITY[s, u]]
        s = NEXT[s, u]
    assert s == 0
    return bits.astype(np.uint8), par, np.array(tail, dtype=np.uint8)


def encode(bits: np.ndarray) -> np.ndarray:
    bits = np.asarray(bits, dtype=np.int64)
    k = len(bits)
    sys_, p1, t1 = _rsc_encode(bits)
    _, p2, t2 = _rsc_encode(bits[interleaver(k)])
    return np.concatenate([sys_, p1, p2, t1, t2]).astype(np.uint8)


def _bcjr(lu: np.ndarray, lp: np.ndarray, tail: np.ndarray) -> np.ndarray:
    """Max-log-MAP a-posteriori LLRs of the k information bits.

    ``lu``: systematic + a-priori LLRs (k); ``lp``: parity LLRs (k); ``tail``: the six
    tail LLRs (u, p) * 3. Positive LLR favours bit 0.
    """
    k = len(lu)
    n = k + MEMORY
    LU = np.concatenate([lu, tail[0::2]])
    LP = np.concatenate([lp, tail[1::2]])
    neg = -1e30
    alpha = np.full((n + 1, N_STATES), neg)
    alpha[0, 0] = 0.0
    for t in range(n):
        g = 0.5 * (SYM_U * LU[t] + SYM_P * LP[t])  # (8, 2) incoming branch metrics
        cand = alpha[t][PRED_S] + g
        a = cand.max(axis=1)
        alpha[t + 1] = a - a.max()
    beta = np.full(N_STATES, neg)
    beta[0] = 0.0  # terminated trellis
    llr = np.empty(k)
    for t in range(n - 1, -1, -1):
        g = 0.5 * (NEXT_SYM_U * LU[t] + NEXT_SYM_P * LP[t])  # (8, 2) outgoing branches
        m = alpha[t][:, None] + g + beta[NEXT]  # (8, 2)
        if t < k:
            llr[t] = m[:, 0].max() - m[:, 1].max()
        b = (g + beta[NEXT]).max(axis=1)
        beta = b - b.max()
    return llr


def decode(
    soft: np.ndarray,
    k: int,
    iterations: int = 8,
    check: Callable[[np.ndarray], bool] | None = None,
) -> tuple[np.ndarray, int]:
    """Iteratively decode; returns (bits, iterations used).

    ``check`` (e.g. a CRC test) enables early termination as soon as it passes.
    """
    soft = np.asarray(soft, dtype=np.float64)
    if len(soft) != coded_length(k):
        raise ValueError("soft vector length does not match the code")
    ls, lp1, lp2 = soft[:k], soft[k : 2 * k], soft[2 * k : 3 * k]
    t1, t2 = soft[3 * k : 3 * k + 6], soft[3 * k + 6 :]
    pi = interleaver(k)
    inv = np.argsort(pi)
    la1 = np.zeros(k)
    bits = (ls < 0).astype(np.uint8)
    for it in range(1, iterations + 1):
        l1 = _bcjr(ls + la1, lp1, t1)
        le1 = l1 - ls - la1
        la2 = EXTRINSIC_SCALE * le1[pi]
        l2 = _bcjr(ls[pi] + la2, lp2, t2)
        le2 = l2 - ls[pi] - la2
        la1 = EXTRINSIC_SCALE * le2[inv]
        post = l2[inv]
        bits = (post < 0).astype(np.uint8)
        if check is not None and check(bits):
            return bits, it
    return bits, iterations

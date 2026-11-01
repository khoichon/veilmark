"""Forward error correction: terminated convolutional codes with soft-decision Viterbi.

The watermark channel produces *soft* observations (signed correlation values), so
a soft-decision decoder recovers several dB compared to hard-decision codes such as
Reed-Solomon. We use the industry-standard constraint-length-7 codes (the same
generators used by 802.11 / CCSDS) and terminate the trellis with K-1 zero tail
bits so the decoder can force the final state to zero.

This is standard coding theory, not cryptography; integrity is enforced separately
by CRCs and Ed25519 signatures.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


def _parity(x: np.ndarray) -> np.ndarray:
    x = x.copy()
    out = np.zeros_like(x)
    while np.any(x):
        out ^= x & 1
        x >>= 1
    return out


@dataclass(frozen=True)
class ConvCode:
    """A rate 1/n terminated convolutional code with constraint length ``k``."""

    generators: tuple[int, ...]
    k: int = 7

    @property
    def rate_inv(self) -> int:
        return len(self.generators)

    @property
    def tail(self) -> int:
        return self.k - 1

    @property
    def n_states(self) -> int:
        return 1 << (self.k - 1)

    def coded_length(self, n_bits: int) -> int:
        return (n_bits + self.tail) * self.rate_inv

    # Trellis tables: for each (state, input) the next state and the output symbols.
    def _tables(self) -> tuple[np.ndarray, np.ndarray]:
        states = np.arange(self.n_states)
        next_state = np.empty((self.n_states, 2), dtype=np.int64)
        outputs = np.empty((self.n_states, 2, self.rate_inv), dtype=np.int8)
        for bit in (0, 1):
            reg = (bit << (self.k - 1)) | states  # newest bit in MSB position
            next_state[:, bit] = reg >> 1
            for i, g in enumerate(self.generators):
                outputs[:, bit, i] = _parity(reg & g)
        return next_state, outputs

    def encode(self, bits: np.ndarray) -> np.ndarray:
        """Encode 0/1 bits; returns 0/1 coded bits including the zero tail."""
        bits = np.concatenate([np.asarray(bits, dtype=np.int64), np.zeros(self.tail, np.int64)])
        next_state, outputs = _TABLE_CACHE.get(self)
        state = 0
        out = np.empty((len(bits), self.rate_inv), dtype=np.uint8)
        for t, b in enumerate(bits):
            out[t] = outputs[state, b]
            state = next_state[state, b]
        return out.reshape(-1)

    def decode(self, soft: np.ndarray) -> tuple[np.ndarray, float]:
        """Soft-decision Viterbi decoding.

        ``soft`` holds one real value per coded bit; positive values favour bit 0,
        negative favour bit 1 (i.e. the BPSK mapping 0 -> +1, 1 -> -1). Values may be
        arbitrarily scaled. Returns (decoded 0/1 bits without tail, path metric).
        """
        n = self.rate_inv
        soft = np.asarray(soft, dtype=np.float64).reshape(-1, n)
        steps = soft.shape[0]
        next_state, outputs = _TABLE_CACHE.get(self)
        # Branch symbols in BPSK form: +1 for 0, -1 for 1.
        sym = 1.0 - 2.0 * outputs.astype(np.float64)  # (S, 2, n)

        # Every state has exactly two predecessors, both reached with the same input
        # bit (the input bit becomes the MSB of the new state).
        ns_count = self.n_states
        prev_states = np.empty((ns_count, 2), dtype=np.int64)
        prev_bits = np.empty(ns_count, dtype=np.int64)
        counts = np.zeros(ns_count, dtype=np.int64)
        for s in range(ns_count):
            for b in (0, 1):
                ns = next_state[s, b]
                prev_states[ns, counts[ns]] = s
                prev_bits[ns] = b
                counts[ns] += 1
        p0 = prev_states[:, 0]
        p1 = prev_states[:, 1]
        sym0 = sym[p0, prev_bits]  # (S, n): symbols on the branch p0 -> s
        sym1 = sym[p1, prev_bits]

        metric = np.full(ns_count, -np.inf)
        metric[0] = 0.0
        decisions = np.empty((steps, ns_count), dtype=np.bool_)
        for t in range(steps):
            r = soft[t]
            m0 = metric[p0] + sym0 @ r
            m1 = metric[p1] + sym1 @ r
            choose1 = m1 > m0
            decisions[t] = choose1
            metric = np.where(choose1, m1, m0)
        # Traceback from the zero state (trellis is terminated).
        state = 0
        bits = np.empty(steps, dtype=np.uint8)
        for t in range(steps - 1, -1, -1):
            bits[t] = prev_bits[state]
            state = p1[state] if decisions[t, state] else p0[state]
        return bits[: steps - self.tail], float(metric[0])


class _TableCache:
    def __init__(self) -> None:
        self._cache: dict[ConvCode, tuple[np.ndarray, np.ndarray]] = {}

    def get(self, code: ConvCode) -> tuple[np.ndarray, np.ndarray]:
        if code not in self._cache:
            self._cache[code] = code._tables()
        return self._cache[code]


_TABLE_CACHE = _TableCache()

# Standard maximum-free-distance generators (octal): K=7 rate 1/2 (171, 133) as in
# 802.11/CCSDS, K=7 rate 1/3 (133, 171, 165), and K=9 rate 1/3 (557, 663, 711) as in
# 3GPP, which gains roughly 0.5-1 dB over K=7 at a 4x decoding cost.
RATE_1_2 = ConvCode((0o171, 0o133))
RATE_1_3 = ConvCode((0o133, 0o171, 0o165))
RATE_1_3_K9 = ConvCode((0o557, 0o663, 0o711), k=9)


def bytes_to_bits(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def bits_to_bytes(bits: np.ndarray) -> bytes:
    return np.packbits(np.asarray(bits, dtype=np.uint8)).tobytes()


def bpsk(bits: np.ndarray) -> np.ndarray:
    """Map 0/1 bits to +1/-1."""
    return 1.0 - 2.0 * np.asarray(bits, dtype=np.float64)

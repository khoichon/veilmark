"""Progress reporting and cooperative cancellation shared by every front-end."""

from __future__ import annotations

import threading
from collections.abc import Callable

ProgressFn = Callable[[float, str], None]


class Cancelled(Exception):
    """Raised inside an operation when its cancel token has been triggered."""


class CancelToken:
    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def check(self) -> None:
        if self._event.is_set():
            raise Cancelled("operation cancelled")


def no_progress(_fraction: float, _message: str) -> None:
    return None


class Reporter:
    """Bundles progress + cancellation and maps sub-steps into a parent range."""

    def __init__(
        self,
        progress: ProgressFn | None = None,
        cancel: CancelToken | None = None,
        lo: float = 0.0,
        hi: float = 1.0,
    ) -> None:
        self.progress = progress or no_progress
        self.cancel = cancel or CancelToken()
        self.lo, self.hi = lo, hi

    def __call__(self, fraction: float, message: str = "") -> None:
        self.cancel.check()
        f = min(max(fraction, 0.0), 1.0)
        self.progress(self.lo + (self.hi - self.lo) * f, message)

    def sub(self, lo: float, hi: float) -> Reporter:
        span = self.hi - self.lo
        return Reporter(self.progress, self.cancel, self.lo + span * lo, self.lo + span * hi)

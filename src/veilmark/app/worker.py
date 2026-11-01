"""Background task runner: keeps the UI responsive and supports cancellation."""

from __future__ import annotations

import traceback
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QThread, Signal

from veilmark.core.tasks import Cancelled, CancelToken, Reporter


class _Job(QObject):
    progress = Signal(float, str)
    done = Signal(object)
    failed = Signal(str)
    cancelled = Signal()

    def __init__(self, fn: Callable[[Reporter], Any]) -> None:
        super().__init__()
        self.fn = fn
        self.token = CancelToken()

    def run(self) -> None:
        rep = Reporter(lambda f, m: self.progress.emit(f, m), self.token)
        try:
            self.done.emit(self.fn(rep))
        except Cancelled:
            self.cancelled.emit()
        except Exception as e:
            msg = str(e) or type(e).__name__
            if not isinstance(e, ValueError | OSError):
                msg += "\n\n" + traceback.format_exc(limit=4)
            self.failed.emit(msg)


class TaskRunner(QObject):
    """Run one callable at a time on a worker thread.

    ``fn`` receives a :class:`Reporter`; it must call it periodically so progress
    and cancellation work.
    """

    progress = Signal(float, str)
    finished = Signal(object)
    failed = Signal(str)
    cancelled = Signal()
    busy_changed = Signal(bool)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._thread: QThread | None = None
        self._job: _Job | None = None

    @property
    def busy(self) -> bool:
        return self._thread is not None

    def start(self, fn: Callable[[Reporter], Any]) -> bool:
        if self.busy:
            return False
        self._thread = QThread()
        self._job = _Job(fn)
        self._job.moveToThread(self._thread)
        self._thread.started.connect(self._job.run)
        self._job.progress.connect(self.progress)
        self._job.done.connect(self._on_done)
        self._job.failed.connect(self._on_failed)
        self._job.cancelled.connect(self._on_cancelled)
        self.busy_changed.emit(True)
        self._thread.start()
        return True

    def cancel(self) -> None:
        if self._job is not None:
            self._job.token.cancel()

    def _cleanup(self) -> None:
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait()
        self._thread = None
        self._job = None
        self.busy_changed.emit(False)

    def _on_done(self, result: object) -> None:
        self._cleanup()
        self.finished.emit(result)

    def _on_failed(self, msg: str) -> None:
        self._cleanup()
        self.failed.emit(msg)

    def _on_cancelled(self) -> None:
        self._cleanup()
        self.cancelled.emit()

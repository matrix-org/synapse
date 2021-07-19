import logging
import time
from logging import Handler, LogRecord
from logging.handlers import MemoryHandler
from threading import Thread
from typing import Optional

from twisted.internet import reactor


class PeriodicallyFlushingMemoryHandler(MemoryHandler):
    """
    This is a subclass of MemoryHandler that additionally spawns a background
    thread to periodically flush the buffer.

    This prevents messages from being buffered for too long.
    """

    def __init__(
        self,
        capacity: int,
        flushLevel: int = logging.ERROR,
        target: Optional[Handler] = None,
        flushOnClose: bool = True,
        period: float = 5.0,
    ) -> None:
        super().__init__(capacity, flushLevel, target, flushOnClose)

        self._flush_period: float = period
        self._active: bool = True
        self._reactor_started = False

        self._flushing_thread: Thread = Thread(
            name="PeriodicallyFlushingMemoryHandler flushing thread",
            target=self._flush_periodically,
        )
        self._flushing_thread.start()

        def on_reactor_running():
            self._reactor_started = True

        # call our hook when the reactor start up
        reactor.callWhenRunning(on_reactor_running)  # type: ignore[attr-defined]

    def shouldFlush(self, record: LogRecord) -> bool:
        """
        Before reactor start-up, log everything immediately.
        Otherwise, fall back to original behaviour of waiting for the buffer to fill.
        """

        if self._reactor_started:
            return super().shouldFlush(record)
        else:
            return True

    def _flush_periodically(self):
        """
        Whilst this handler is active, flush the handler periodically.
        """

        while self._active:
            # flush is thread-safe; it acquires and releases the lock internally
            self.flush()
            time.sleep(self._flush_period)

    def close(self) -> None:
        self._active = False
        super().close()

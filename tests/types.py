try:
    from twisted.internet.testing import MemoryReactor, MemoryReactorClock
except ImportError:
    # Twisted 19.7 moved stuff from twisted.test.proto_helpers to
    # twisted.internet.testing. Let's do the import once rather than doing it
    # in lots of different files.
    from twisted.test.proto_helpers import MemoryReactor, MemoryReactorClock

__all__ = ["MemoryReactor", "MemoryReactorClock"]

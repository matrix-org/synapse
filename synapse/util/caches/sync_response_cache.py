import logging
from typing import Any, Callable, Dict

from twisted.internet import defer

from synapse.util import Clock
from synapse.util.async_helpers import ObservableDeferred
from synapse.util.caches.response_cache import ResponseCache, T

logger = logging.getLogger(__name__)


# A special class for /sync responses, to conditionally cache these.
class SyncResponseCache(ResponseCache[T]):
    def __init__(self, clock: Clock, name: str, timeout_ms: float = 0):
        super().__init__(clock, name, timeout_ms)

        self.conditionals = {}  # type: Dict[T, Callable[[Any], bool]]

    def run_conditional(self, key: T, result: Any) -> bool:
        """Runs a conditional set on key T, defaults to True"""
        cond = self.conditionals.get(key, None)
        if cond is None:
            return True
        else:
            try:
                # Below type annotation is needed for mypy to shush about some statements being unreachable,
                # we essentially have to not trust other functions to be able to correctly recover from any fallout
                # (and log it)
                res = cond(result)  # type: Any
            except Exception:
                logger.exception(
                    "[%s]: Executing conditional %r on %s raised an exception.",
                    self._name,
                    cond,
                    key,
                )
                # Evict cache out of caution.
                return False
            else:
                if not isinstance(res, bool):
                    logger.warning(
                        "[%s]: Conditional %r returned non-bool value %r (for key %r)",
                        self._name,
                        cond,
                        res,
                        key,
                    )
                    # Return concrete boolean value based on falsy or truthiness.
                    # If this raises, then so be it, then this value wasn't ever supposed to be true" or "false"
                    # anyways, then have it be a scream test.
                    return bool(res)
                else:
                    return res

    # Copy this method wholesale from ResponseCache to be able to alter the inner `remove` function
    def set(self, key: T, deferred: defer.Deferred) -> defer.Deferred:
        """Same as ResponseCache.set, but is conditional-aware"""
        result = ObservableDeferred(deferred, consumeErrors=True)
        self.pending_result_cache[key] = result

        def remove(r):
            if self.timeout_sec and (
                not isinstance(r, BaseException) and self.run_conditional(key, r)
            ):
                self.clock.call_later(
                    self.timeout_sec, self.pending_result_cache.pop, key, None
                )
            else:
                self.pending_result_cache.pop(key, None)

            self.conditionals.pop(key, None)

            return r

        result.addBoth(remove)
        return result.observe()

    def wrap_conditional(
        self,
        key: T,
        conditional: "Callable[[Any], bool]",
        callback: "Callable[..., Any]",
        *args: Any,
        **kwargs: Any
    ) -> defer.Deferred:
        """Same as wrap(), but adds a conditional to be executed on completion.

        Only the very first caller with this key, between both wrap() and wrap_conditional(), will set the
        conditional function, otherwise the 'conditional' argument will be ignored."""

        if self.get(key) is None:  # we are the first caller
            logger.debug(
                "[%s]: We are the very first caller for [%s], setting conditional %r...",
                self._name,
                key,
                conditional,
            )
            self.conditionals[key] = conditional

        return self.wrap(key, callback, *args, **kwargs)

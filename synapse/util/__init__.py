# Copyright 2014-2016 OpenMarket Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import logging
import typing
from typing import Any, Callable, Dict, Generator, Optional

import attr
from frozendict import frozendict
from matrix_common.versionstring import get_distribution_version_string
from typing_extensions import ParamSpec

from twisted.internet import defer, task
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IDelayedCall, IReactorTime
from twisted.internet.task import LoopingCall
from twisted.python.failure import Failure

from synapse.logging import context

if typing.TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


def _reject_invalid_json(val: Any) -> None:
    """Do not allow Infinity, -Infinity, or NaN values in JSON."""
    raise ValueError("Invalid JSON value: '%s'" % val)


def _handle_frozendict(obj: Any) -> Dict[Any, Any]:
    """Helper for json_encoder. Makes frozendicts serializable by returning
    the underlying dict
    """
    if type(obj) is frozendict:
        # fishing the protected dict out of the object is a bit nasty,
        # but we don't really want the overhead of copying the dict.
        try:
            # Safety: we catch the AttributeError immediately below.
            # See https://github.com/matrix-org/python-canonicaljson/issues/36#issuecomment-927816293
            # for discussion on how frozendict's internals have changed over time.
            return obj._dict  # type: ignore[attr-defined]
        except AttributeError:
            # When the C implementation of frozendict is used,
            # there isn't a `_dict` attribute with a dict
            # so we resort to making a copy of the frozendict
            return dict(obj)
    raise TypeError(
        "Object of type %s is not JSON serializable" % obj.__class__.__name__
    )


# A custom JSON encoder which:
#   * handles frozendicts
#   * produces valid JSON (no NaNs etc)
#   * reduces redundant whitespace
json_encoder = json.JSONEncoder(
    allow_nan=False, separators=(",", ":"), default=_handle_frozendict
)

# Create a custom decoder to reject Python extensions to JSON.
json_decoder = json.JSONDecoder(parse_constant=_reject_invalid_json)


def unwrapFirstError(failure: Failure) -> Failure:
    # Deprecated: you probably just want to catch defer.FirstError and reraise
    # the subFailure's value, which will do a better job of preserving stacktraces.
    # (actually, you probably want to use yieldable_gather_results anyway)
    failure.trap(defer.FirstError)
    return failure.value.subFailure  # type: ignore[union-attr]  # Issue in Twisted's annotations


P = ParamSpec("P")


@attr.s(slots=True)
class Clock:
    """
    A Clock wraps a Twisted reactor and provides utilities on top of it.

    Args:
        reactor: The Twisted reactor to use.
    """

    _reactor: IReactorTime = attr.ib()

    @defer.inlineCallbacks  # type: ignore[arg-type]  # Issue in Twisted's type annotations
    def sleep(self, seconds: float) -> "Generator[Deferred[float], Any, Any]":
        d: defer.Deferred[float] = defer.Deferred()
        with context.PreserveLoggingContext():
            self._reactor.callLater(seconds, d.callback, seconds)
            res = yield d
        return res

    def time(self) -> float:
        """Returns the current system time in seconds since epoch."""
        return self._reactor.seconds()

    def time_msec(self) -> int:
        """Returns the current system time in milliseconds since epoch."""
        return int(self.time() * 1000)

    def looping_call(
        self, f: Callable[P, object], msec: float, *args: P.args, **kwargs: P.kwargs
    ) -> LoopingCall:
        """Call a function repeatedly.

        Waits `msec` initially before calling `f` for the first time.

        Note that the function will be called with no logcontext, so if it is anything
        other than trivial, you probably want to wrap it in run_as_background_process.

        Args:
            f: The function to call repeatedly.
            msec: How long to wait between calls in milliseconds.
            *args: Postional arguments to pass to function.
            **kwargs: Key arguments to pass to function.
        """
        call = task.LoopingCall(f, *args, **kwargs)
        call.clock = self._reactor
        d = call.start(msec / 1000.0, now=False)
        d.addErrback(log_failure, "Looping call died", consumeErrors=False)
        return call

    def call_later(
        self, delay: float, callback: Callable, *args: Any, **kwargs: Any
    ) -> IDelayedCall:
        """Call something later

        Note that the function will be called with no logcontext, so if it is anything
        other than trivial, you probably want to wrap it in run_as_background_process.

        Args:
            delay: How long to wait in seconds.
            callback: Function to call
            *args: Postional arguments to pass to function.
            **kwargs: Key arguments to pass to function.
        """

        def wrapped_callback(*args: Any, **kwargs: Any) -> None:
            with context.PreserveLoggingContext():
                callback(*args, **kwargs)

        with context.PreserveLoggingContext():
            return self._reactor.callLater(delay, wrapped_callback, *args, **kwargs)

    def cancel_call_later(self, timer: IDelayedCall, ignore_errs: bool = False) -> None:
        try:
            timer.cancel()
        except Exception:
            if not ignore_errs:
                raise


def log_failure(
    failure: Failure, msg: str, consumeErrors: bool = True
) -> Optional[Failure]:
    """Creates a function suitable for passing to `Deferred.addErrback` that
    logs any failures that occur.

    Args:
        failure: The Failure to log
        msg: Message to log
        consumeErrors: If true consumes the failure, otherwise passes on down
            the callback chain

    Returns:
        The Failure if consumeErrors is false. None, otherwise.
    """

    logger.error(
        msg, exc_info=(failure.type, failure.value, failure.getTracebackObject())  # type: ignore[arg-type]
    )

    if not consumeErrors:
        return failure
    return None


# Version string with git info. Computed here once so that we don't invoke git multiple
# times.
SYNAPSE_VERSION = get_distribution_version_string("matrix-synapse", __file__)

# Copyright 2018 New Vector Ltd
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

import functools
import sys
from typing import Any, Callable, List

from twisted.internet import defer
from twisted.internet.defer import Deferred
from twisted.python.failure import Failure

# Tracks if we've already patched inlineCallbacks
_already_patched = False


def do_patch():
    """
    Patch defer.inlineCallbacks so that it checks the state of the logcontext on exit
    """

    from synapse.logging.context import current_context

    global _already_patched

    orig_inline_callbacks = defer.inlineCallbacks
    if _already_patched:
        return

    def new_inline_callbacks(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            start_context = current_context()
            changes = []  # type: List[str]
            orig = orig_inline_callbacks(_check_yield_points(f, changes))

            try:
                res = orig(*args, **kwargs)
            except Exception:
                if current_context() != start_context:
                    for err in changes:
                        print(err, file=sys.stderr)

                    err = "%s changed context from %s to %s on exception" % (
                        f,
                        start_context,
                        current_context(),
                    )
                    print(err, file=sys.stderr)
                    raise Exception(err)
                raise

            if not isinstance(res, Deferred) or res.called:
                if current_context() != start_context:
                    for err in changes:
                        print(err, file=sys.stderr)

                    err = "Completed %s changed context from %s to %s" % (
                        f,
                        start_context,
                        current_context(),
                    )
                    # print the error to stderr because otherwise all we
                    # see in travis-ci is the 500 error
                    print(err, file=sys.stderr)
                    raise Exception(err)
                return res

            if current_context():
                err = (
                    "%s returned incomplete deferred in non-sentinel context "
                    "%s (start was %s)"
                ) % (f, current_context(), start_context)
                print(err, file=sys.stderr)
                raise Exception(err)

            def check_ctx(r):
                if current_context() != start_context:
                    for err in changes:
                        print(err, file=sys.stderr)
                    err = "%s completion of %s changed context from %s to %s" % (
                        "Failure" if isinstance(r, Failure) else "Success",
                        f,
                        start_context,
                        current_context(),
                    )
                    print(err, file=sys.stderr)
                    raise Exception(err)
                return r

            res.addBoth(check_ctx)
            return res

        return wrapped

    defer.inlineCallbacks = new_inline_callbacks
    _already_patched = True


def _check_yield_points(f: Callable, changes: List[str]):
    """Wraps a generator that is about to be passed to defer.inlineCallbacks
    checking that after every yield the log contexts are correct.

    It's perfectly valid for log contexts to change within a function, e.g. due
    to new Measure blocks, so such changes are added to the given `changes`
    list instead of triggering an exception.

    Args:
        f: generator function to wrap
        changes: A list of strings detailing how the contexts
            changed within a function.

    Returns:
        function
    """

    from synapse.logging.context import current_context

    @functools.wraps(f)
    def check_yield_points_inner(*args, **kwargs):
        gen = f(*args, **kwargs)

        last_yield_line_no = gen.gi_frame.f_lineno
        result = None  # type: Any
        while True:
            expected_context = current_context()

            try:
                isFailure = isinstance(result, Failure)
                if isFailure:
                    d = result.throwExceptionIntoGenerator(gen)
                else:
                    d = gen.send(result)
            except (StopIteration, defer._DefGen_Return) as e:
                if current_context() != expected_context:
                    # This happens when the context is lost sometime *after* the
                    # final yield and returning. E.g. we forgot to yield on a
                    # function that returns a deferred.
                    #
                    # We don't raise here as it's perfectly valid for contexts to
                    # change in a function, as long as it sets the correct context
                    # on resolving (which is checked separately).
                    err = (
                        "Function %r returned and changed context from %s to %s,"
                        " in %s between %d and end of func"
                        % (
                            f.__qualname__,
                            expected_context,
                            current_context(),
                            f.__code__.co_filename,
                            last_yield_line_no,
                        )
                    )
                    changes.append(err)
                return getattr(e, "value", None)

            frame = gen.gi_frame

            if isinstance(d, defer.Deferred) and not d.called:
                # This happens if we yield on a deferred that doesn't follow
                # the log context rules without wrapping in a `make_deferred_yieldable`.
                # We raise here as this should never happen.
                if current_context():
                    err = (
                        "%s yielded with context %s rather than sentinel,"
                        " yielded on line %d in %s"
                        % (
                            frame.f_code.co_name,
                            current_context(),
                            frame.f_lineno,
                            frame.f_code.co_filename,
                        )
                    )
                    raise Exception(err)

            # the wrapped function yielded a Deferred: yield it back up to the parent
            # inlineCallbacks().
            try:
                result = yield d
            except Exception:
                # this will fish an earlier Failure out of the stack where possible, and
                # thus is preferable to passing in an exception to the Failure
                # constructor, since it results in less stack-mangling.
                result = Failure()

            if current_context() != expected_context:

                # This happens because the context is lost sometime *after* the
                # previous yield and *after* the current yield. E.g. the
                # deferred we waited on didn't follow the rules, or we forgot to
                # yield on a function between the two yield points.
                #
                # We don't raise here as its perfectly valid for contexts to
                # change in a function, as long as it sets the correct context
                # on resolving (which is checked separately).
                err = "%s changed context from %s to %s, happened between lines %d and %d in %s" % (
                    frame.f_code.co_name,
                    expected_context,
                    current_context(),
                    last_yield_line_no,
                    frame.f_lineno,
                    frame.f_code.co_filename,
                )
                changes.append(err)

            last_yield_line_no = frame.f_lineno

    return check_yield_points_inner

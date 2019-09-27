# -*- coding: utf-8 -*-
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

from __future__ import print_function

import inspect
import functools
import sys

from twisted.internet import defer
from twisted.internet.defer import Deferred
from twisted.python.failure import Failure


def do_patch():
    """
    Patch defer.inlineCallbacks so that it checks the state of the logcontext on exit
    """

    from synapse.logging.context import LoggingContext

    orig_inline_callbacks = defer.inlineCallbacks

    def new_inline_callbacks(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            start_context = LoggingContext.current_context()
            changes = []
            orig = orig_inline_callbacks(_check_yield_points(f, changes, start_context))

            try:
                res = orig(*args, **kwargs)
            except Exception:
                if LoggingContext.current_context() != start_context:
                    for err in changes:
                        print(err, file=sys.stderr)

                    err = "%s changed context from %s to %s on exception" % (
                        f,
                        start_context,
                        LoggingContext.current_context(),
                    )
                    print(err, file=sys.stderr)
                    raise Exception(err)
                raise

            if not isinstance(res, Deferred) or res.called:
                if LoggingContext.current_context() != start_context:
                    for err in changes:
                        print(err, file=sys.stderr)

                    err = "Completed %s changed context from %s to %s" % (
                        f,
                        start_context,
                        LoggingContext.current_context(),
                    )
                    # print the error to stderr because otherwise all we
                    # see in travis-ci is the 500 error
                    print(err, file=sys.stderr)
                    raise Exception(err)
                return res

            if LoggingContext.current_context() != LoggingContext.sentinel:
                err = (
                    "%s returned incomplete deferred in non-sentinel context "
                    "%s (start was %s)"
                ) % (f, LoggingContext.current_context(), start_context)
                print(err, file=sys.stderr)
                raise Exception(err)

            def check_ctx(r):
                if LoggingContext.current_context() != start_context:
                    for err in changes:
                        print(err, file=sys.stderr)
                    err = "%s completion of %s changed context from %s to %s" % (
                        "Failure" if isinstance(r, Failure) else "Success",
                        f,
                        start_context,
                        LoggingContext.current_context(),
                    )
                    print(err, file=sys.stderr)
                    raise Exception(err)
                return r

            res.addBoth(check_ctx)
            return res

        return wrapped

    defer.inlineCallbacks = new_inline_callbacks


def _check_yield_points(f, changes, start_context):
    from synapse.logging.context import LoggingContext

    @functools.wraps(f)
    def check_yield_points_inner(*args, **kwargs):
        gen = f(*args, **kwargs)

        last_yield_line_no = 1
        result = None
        while True:
            try:
                isFailure = isinstance(result, Failure)
                if isFailure:
                    d = result.throwExceptionIntoGenerator(gen)
                else:
                    d = gen.send(result)
            except (StopIteration, defer._DefGen_Return) as e:
                if LoggingContext.current_context() != start_context:
                    # This happens when the context is lost sometime *after* the
                    # final yield and returning. E.g. we forgot to yield on a
                    # function that returns a deferred.
                    err = (
                        "%s returned and changed context from %s to %s, in %s between %d and end of func"
                        % (
                            f.__qualname__,
                            start_context,
                            LoggingContext.current_context(),
                            f.__code__.co_filename,
                            last_yield_line_no,
                        )
                    )
                    changes.append(err)
                    # print(err, file=sys.stderr)
                    # raise Exception(err)
                return getattr(e, "value", None)

            try:
                result = yield d
            except Exception as e:
                result = Failure(e)

            frame = gen.gi_frame
            if frame.f_code.co_name == "check_yield_points_inner":
                frame = inspect.getgeneratorlocals(gen)["gen"].gi_frame

            if LoggingContext.current_context() != start_context:
                # This happens because the context is lost sometime *after* the
                # previous yield and *after* the current yield. E.g. the
                # deferred we waited on didn't follow the rules, or we forgot to
                # yield on a function between the two yield points.
                err = (
                    "%s changed context from %s to %s, happened between lines %d and %d in %s"
                    % (
                        frame.f_code.co_name,
                        start_context,
                        LoggingContext.current_context(),
                        last_yield_line_no,
                        frame.f_lineno,
                        frame.f_code.co_filename,
                    )
                )
                changes.append(err)
                # print(err, file=sys.stderr)
                # raise Exception(err)

            last_yield_line_no = frame.f_lineno

    return check_yield_points_inner

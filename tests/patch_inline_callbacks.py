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

import functools
import sys

from twisted.internet import defer
from twisted.internet.defer import Deferred
from twisted.python.failure import Failure


def do_patch():
    """
    Patch defer.inlineCallbacks so that it checks the state of the logcontext on exit
    """

    from synapse.util.logcontext import LoggingContext

    orig_inline_callbacks = defer.inlineCallbacks

    def new_inline_callbacks(f):

        orig = orig_inline_callbacks(f)

        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            start_context = LoggingContext.current_context()

            try:
                res = orig(*args, **kwargs)
            except Exception:
                if LoggingContext.current_context() != start_context:
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
                    err = "%s changed context from %s to %s" % (
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

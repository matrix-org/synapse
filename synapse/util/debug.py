# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

from twisted.internet import defer, reactor
from functools import wraps
from synapse.util.logcontext import LoggingContext, PreserveLoggingContext


def debug_deferreds():
    """Cause all deferreds to wait for a reactor tick before running their
    callbacks. This increases the chance of getting a stack trace out of
    a defer.inlineCallback since the code waiting on the deferred will get
    a chance to add an errback before the deferred runs."""

    # Helper method for retrieving and restoring the current logging context
    # around a callback.
    def with_logging_context(fn):
        context = LoggingContext.current_context()

        def restore_context_callback(x):
            with PreserveLoggingContext(context):
                return fn(x)

        return restore_context_callback

    # We are going to modify the __init__ method of defer.Deferred so we
    # need to get a copy of the old method so we can still call it.
    old__init__ = defer.Deferred.__init__

    # We need to create a deferred to bounce the callbacks through the reactor
    # but we don't want to add a callback when we create that deferred so we
    # we create a new type of deferred that uses the old __init__ method.
    # This is safe as long as the old __init__ method doesn't invoke an
    # __init__ using super.
    class Bouncer(defer.Deferred):
        __init__ = old__init__

    # We'll add this as a callback to all Deferreds. Twisted will wait until
    # the bouncer deferred resolves before calling the callbacks of the
    # original deferred.
    def bounce_callback(x):
        bouncer = Bouncer()
        reactor.callLater(0, with_logging_context(bouncer.callback), x)
        return bouncer

    # We'll add this as an errback to all Deferreds. Twisted will wait until
    # the bouncer deferred resolves before calling the errbacks of the
    # original deferred.
    def bounce_errback(x):
        bouncer = Bouncer()
        reactor.callLater(0, with_logging_context(bouncer.errback), x)
        return bouncer

    @wraps(old__init__)
    def new__init__(self, *args, **kargs):
        old__init__(self, *args, **kargs)
        self.addCallbacks(bounce_callback, bounce_errback)

    defer.Deferred.__init__ = new__init__

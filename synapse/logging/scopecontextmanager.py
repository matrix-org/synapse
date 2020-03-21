# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
# limitations under the License.import logging

import logging

from opentracing import Scope, ScopeManager

import twisted

from synapse.logging.context import current_context, nested_logging_context

logger = logging.getLogger(__name__)


class LogContextScopeManager(ScopeManager):
    """
    The LogContextScopeManager tracks the active scope in opentracing
    by using the log contexts which are native to synapse. This is so
    that the basic opentracing api can be used across twisted defereds.
    (I would love to break logcontexts and this into an OS package. but
    let's wait for twisted's contexts to be released.)
    """

    def __init__(self, config):
        pass

    @property
    def active(self):
        """
        Returns the currently active Scope which can be used to access the
        currently active Scope.span.
        If there is a non-null Scope, its wrapped Span
        becomes an implicit parent of any newly-created Span at
        Tracer.start_active_span() time.

        Return:
            (Scope) : the Scope that is active, or None if not
            available.
        """
        ctx = current_context()
        return ctx.scope

    def activate(self, span, finish_on_close):
        """
        Makes a Span active.
        Args
            span (Span): the span that should become active.
            finish_on_close (Boolean): whether Span should be automatically
                finished when Scope.close() is called.

        Returns:
            Scope to control the end of the active period for
            *span*. It is a programming error to neglect to call
            Scope.close() on the returned instance.
        """

        enter_logcontext = False
        ctx = current_context()

        if not ctx:
            # We don't want this scope to affect.
            logger.error("Tried to activate scope outside of loggingcontext")
            return Scope(None, span)
        elif ctx.scope is not None:
            # We want the logging scope to look exactly the same so we give it
            # a blank suffix
            ctx = nested_logging_context("")
            enter_logcontext = True

        scope = _LogContextScope(self, span, ctx, enter_logcontext, finish_on_close)
        ctx.scope = scope
        return scope


class _LogContextScope(Scope):
    """
    A custom opentracing scope. The only significant difference is that it will
    close the log context it's related to if the logcontext was created specifically
    for this scope.
    """

    def __init__(self, manager, span, logcontext, enter_logcontext, finish_on_close):
        """
        Args:
            manager (LogContextScopeManager):
                the manager that is responsible for this scope.
            span (Span):
                the opentracing span which this scope represents the local
                lifetime for.
            logcontext (LogContext):
                the logcontext to which this scope is attached.
            enter_logcontext (Boolean):
                if True the logcontext will be entered and exited when the scope
                is entered and exited respectively
            finish_on_close (Boolean):
                if True finish the span when the scope is closed
        """
        super(_LogContextScope, self).__init__(manager, span)
        self.logcontext = logcontext
        self._finish_on_close = finish_on_close
        self._enter_logcontext = enter_logcontext

    def __enter__(self):
        if self._enter_logcontext:
            self.logcontext.__enter__()

    def __exit__(self, type, value, traceback):
        if type == twisted.internet.defer._DefGen_Return:
            super(_LogContextScope, self).__exit__(None, None, None)
        else:
            super(_LogContextScope, self).__exit__(type, value, traceback)
        if self._enter_logcontext:
            self.logcontext.__exit__(type, value, traceback)
        else:  # the logcontext existed before the creation of the scope
            self.logcontext.scope = None

    def close(self):
        if self.manager.active is not self:
            logger.error("Tried to close a non-active scope!")
            return

        if self._finish_on_close:
            self.span.finish()

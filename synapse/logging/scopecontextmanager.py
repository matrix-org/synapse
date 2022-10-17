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
from types import TracebackType
from typing import Optional, Type

from opentracing import Scope, ScopeManager, Span

import twisted

from synapse.logging.context import (
    LoggingContext,
    current_context,
    nested_logging_context,
)

logger = logging.getLogger(__name__)


class LogContextScopeManager(ScopeManager):
    """
    The LogContextScopeManager tracks the active scope in opentracing
    by using the log contexts which are native to synapse. This is so
    that the basic opentracing api can be used across twisted defereds.

    It would be nice just to use opentracing's ContextVarsScopeManager,
    but currently that doesn't work due to https://twistedmatrix.com/trac/ticket/10301.
    """

    def __init__(self) -> None:
        pass

    @property
    def active(self) -> Optional[Scope]:
        """
        Returns the currently active Scope which can be used to access the
        currently active Scope.span.
        If there is a non-null Scope, its wrapped Span
        becomes an implicit parent of any newly-created Span at
        Tracer.start_active_span() time.

        Return:
            The Scope that is active, or None if not available.
        """
        ctx = current_context()
        return ctx.scope

    def activate(self, span: Span, finish_on_close: bool) -> Scope:
        """
        Makes a Span active.
        Args
            span: the span that should become active.
            finish_on_close: whether Span should be automatically finished when
                Scope.close() is called.

        Returns:
            Scope to control the end of the active period for
            *span*. It is a programming error to neglect to call
            Scope.close() on the returned instance.
        """

        ctx = current_context()

        if not ctx:
            logger.error("Tried to activate scope outside of loggingcontext")
            return Scope(None, span)  # type: ignore[arg-type]

        if ctx.scope is not None:
            # start a new logging context as a child of the existing one.
            # Doing so -- rather than updating the existing logcontext -- means that
            # creating several concurrent spans under the same logcontext works
            # correctly.
            ctx = nested_logging_context("")
            enter_logcontext = True
        else:
            # if there is no span currently associated with the current logcontext, we
            # just store the scope in it.
            #
            # This feels a bit dubious, but it does hack around a problem where a
            # span outlasts its parent logcontext (which would otherwise lead to
            # "Re-starting finished log context" errors).
            enter_logcontext = False

        scope = _LogContextScope(self, span, ctx, enter_logcontext, finish_on_close)
        ctx.scope = scope
        if enter_logcontext:
            ctx.__enter__()

        return scope


class _LogContextScope(Scope):
    """
    A custom opentracing scope, associated with a LogContext

      * filters out _DefGen_Return exceptions which arise from calling
        `defer.returnValue` in Twisted code

      * When the scope is closed, the logcontext's active scope is reset to None.
        and - if enter_logcontext was set - the logcontext is finished too.
    """

    def __init__(
        self,
        manager: LogContextScopeManager,
        span: Span,
        logcontext: LoggingContext,
        enter_logcontext: bool,
        finish_on_close: bool,
    ):
        """
        Args:
            manager:
                the manager that is responsible for this scope.
            span:
                the opentracing span which this scope represents the local
                lifetime for.
            logcontext:
                the log context to which this scope is attached.
            enter_logcontext:
                if True the log context will be exited when the scope is finished
            finish_on_close:
                if True finish the span when the scope is closed
        """
        super().__init__(manager, span)
        self.logcontext = logcontext
        self._finish_on_close = finish_on_close
        self._enter_logcontext = enter_logcontext

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        if exc_type == twisted.internet.defer._DefGen_Return:
            # filter out defer.returnValue() calls
            exc_type = value = traceback = None
        super().__exit__(exc_type, value, traceback)

    def __str__(self) -> str:
        return f"Scope<{self.span}>"

    def close(self) -> None:
        active_scope = self.manager.active
        if active_scope is not self:
            logger.error(
                "Closing scope %s which is not the currently-active one %s",
                self,
                active_scope,
            )

        if self._finish_on_close:
            self.span.finish()

        self.logcontext.scope = None

        if self._enter_logcontext:
            self.logcontext.__exit__(None, None, None)

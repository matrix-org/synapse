from .logcontext import LoggingContext
from opentracing import ScopeManager, Scope
import logging

logger = logging.getLogger(__name__)

class LogContextScopeManager(ScopeManager):

    _homeserver_whitelist = ["*"]
    _user_whitelist = ["*"]

    def __init__(self, config):
        # Set the whitelists
        logger.info(config.tracer_config)
        _homeserver_whitelist = config.tracer_config["homeserver_whitelist"]
        _user_whitelist = config.tracer_config["user_whitelist"]

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
        ctx = LoggingContext.current_context()
        if ctx is LoggingContext.sentinel or ctx.active_scope is None:
            return None
        else:
            return ctx.active_scope

    def activate(self, span, finish_on_close):
        """
        Makes a Span active.
        Args
            span (Span): the span that should become active.
            finish_on_close (Boolean): whether Span should be automatically
                finished when Scope.close() is called.
        
        Return: 
            Scope to control the end of the active period for
            *span*. It is a programming error to neglect to call
            Scope.close() on the returned instance.
        """
        logger.info("activating scope")
        ctx = LoggingContext.current_context()
        if ctx is LoggingContext.sentinel:
            # We don't want this scope to affect.
            logger.warning("Tried to activate scope outside of loggingcontext")
            return Scope(None, span)

        scope = _LogContextScope(self, span, finish_on_close)
        self._set_logcontext_scope(scope, ctx)
        return scope

    def _set_logcontext_scope(self, scope, ctx=None):
        if ctx is None:
            ctx = LoggingContext.current_context()

        ctx.active_scope = scope

    def request_from_whitelisted_homeserver(self, request):
        pass

    def user_whitelisted(self, request):
        pass

class _LogContextScope(Scope):
    def __init__(self, manager, span, finish_on_close):
        super(_LogContextScope, self).__init__(manager, span)
        self._finish_on_close = finish_on_close
        self._to_restore = manager.active

    def close(self):
        if self.manager.active is not self:
            logger.warning("Tried to close a none active scope!")
            return

        self.manager._set_logcontext_scope(self._to_restore)

        if self._finish_on_close:
            self.span.finish()
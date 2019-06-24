from .logcontext import LoggingContext, nested_logging_context
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
        if ctx is LoggingContext.sentinel:
            return None
        else:
            return ctx.scope

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

        enter_logcontext = False
        ctx = LoggingContext.current_context()

        if ctx is LoggingContext.sentinel:
            # We don't want this scope to affect.
            logger.warning("Tried to activate scope outside of loggingcontext")
            return Scope(None, span)
        elif ctx.scope is not None:
            # We want the logging scope to look exactly the same so we give it
            # a blank suffix
            ctx = nested_logging_context("")
            enter_logcontext = True

        scope = _LogContextScope(self, span, ctx, enter_logcontext, finish_on_close)
        ctx.scope = scope
        return scope

    def request_from_whitelisted_homeserver(self, request):
        pass

    def user_whitelisted(self, request):
        pass

class _LogContextScope(Scope):
    def __init__(self, manager, span, logcontext, enter_logcontext, finish_on_close):
        super(_LogContextScope, self).__init__(manager, span)
        self.logcontext = logcontext
        self._finish_on_close = finish_on_close
        self._enter_logcontext = enter_logcontext

    def __enter__(self):
        if self._enter_logcontext:
            self.logcontext.__enter__()

    def __exit__(self, type, value, traceback):
        super(_LogContextScope, self).__exit__(type, value, traceback)
        if self._enter_logcontext:
            self.logcontext.__exit__(type, value, traceback)
        else: # the logcontext existed before the creation of the scope
            self.logcontext.scope = None

    def close(self):
        if self.manager.active is not self:
            logger.warning("Tried to close a none active scope!")
            return

        if self._finish_on_close:
            self.span.finish()
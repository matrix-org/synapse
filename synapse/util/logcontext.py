from functools import wraps

import threading
import logging

class LoggingContext(object):
    __slots__ = ["parent_context", "name", "__dict__"]

    thread_local = threading.local()

    class Sentinel(object):
        __slots__ = []
        def copy_to(self, record):
            pass

    sentinel = Sentinel()

    def __init__(self, name=None):
        self.parent_context = None
        self.name = name

    def __str__(self):
        return "%s@%x" % (self.name, id(self)) 

    @classmethod
    def current_context(cls):
        return getattr(cls.thread_local, "current_context", cls.sentinel)

    def __enter__(self):
        if self.parent_context is not None:
            raise Exception("Attempt to enter logging context multiple times")
        self.parent_context = self.current_context()
        self.thread_local.current_context = self
        return self

    def __exit__(self, type, value, traceback):
        if self.thread_local.current_context is not self:
            logging.error(
                "Current logging context %s is not the expected context %s",
                self.thread_local.current_context,
                self
            )
        self.thread_local.current_context = self.parent_context
        self.parent_context = None

    def __getattr__(self, name):
        return getattr(self.parent_context, name)

    def copy_to(self, record):
        if self.parent_context is not None:
            self.parent_context.copy_to(record)
        for key, value in self.__dict__.items():
            setattr(record, key, value)

    @classmethod
    def wrap_callback(cls, callback):
        context = cls.current_context()
        @wraps(callback)
        def wrapped(*args, **kargs):
            cls.thread_local.current_context = context
            return callback(*args, **kargs)
        return wrapped


class LoggingContextFilter(logging.Filter):
    def __init__(self, **defaults):
        self.defaults = defaults

    def filter(self, record):
        context = LoggingContext.current_context()
        for key, value in self.defaults.items():
            setattr(record, key, value)
        context.copy_to(record)
        return True


class PreserveLoggingContext(object):
    __slots__ = ["current_context"]
    def __enter__(self):
        self.current_context = LoggingContext.current_context()

    def __exit__(self, type, value, traceback):
        LoggingContext.thread_local.current_context = self.current_context



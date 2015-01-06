# Copyright 2014, 2015 OpenMarket Ltd
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

import threading
import logging

logger = logging.getLogger(__name__)


class LoggingContext(object):
    """Additional context for log formatting. Contexts are scoped within a
    "with" block. Contexts inherit the state of their parent contexts.
    Args:
        name (str): Name for the context for debugging.
    """

    __slots__ = ["parent_context", "name", "__dict__"]

    thread_local = threading.local()

    class Sentinel(object):
        """Sentinel to represent the root context"""

        __slots__ = []

        def __str__(self):
            return "sentinel"

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
        """Get the current logging context from thread local storage"""
        return getattr(cls.thread_local, "current_context", cls.sentinel)

    def __enter__(self):
        """Enters this logging context into thread local storage"""
        if self.parent_context is not None:
            raise Exception("Attempt to enter logging context multiple times")
        self.parent_context = self.current_context()
        self.thread_local.current_context = self
        return self

    def __exit__(self, type, value, traceback):
        """Restore the logging context in thread local storage to the state it
        was before this context was entered.
        Returns:
            None to avoid suppressing any exeptions that were thrown.
        """
        if self.thread_local.current_context is not self:
            if self.thread_local.current_context is self.sentinel:
                logger.debug("Expected logging context %s has been lost", self)
            else:
                logger.warn(
                    "Current logging context %s is not expected context %s",
                    self.thread_local.current_context,
                    self
                )
        self.thread_local.current_context = self.parent_context
        self.parent_context = None

    def __getattr__(self, name):
        """Delegate member lookup to parent context"""
        return getattr(self.parent_context, name)

    def copy_to(self, record):
        """Copy fields from this context and its parents to the record"""
        if self.parent_context is not None:
            self.parent_context.copy_to(record)
        for key, value in self.__dict__.items():
            setattr(record, key, value)


class LoggingContextFilter(logging.Filter):
    """Logging filter that adds values from the current logging context to each
    record.
    Args:
        **defaults: Default values to avoid formatters complaining about
            missing fields
    """
    def __init__(self, **defaults):
        self.defaults = defaults

    def filter(self, record):
        """Add each fields from the logging contexts to the record.
        Returns:
            True to include the record in the log output.
        """
        context = LoggingContext.current_context()
        for key, value in self.defaults.items():
            setattr(record, key, value)
        context.copy_to(record)
        return True


class PreserveLoggingContext(object):
    """Captures the current logging context and restores it when the scope is
    exited. Used to restore the context after a function using
    @defer.inlineCallbacks is resumed by a callback from the reactor."""

    __slots__ = ["current_context"]

    def __enter__(self):
        """Captures the current logging context"""
        self.current_context = LoggingContext.current_context()
        LoggingContext.thread_local.current_context = LoggingContext.sentinel

    def __exit__(self, type, value, traceback):
        """Restores the current logging context"""
        LoggingContext.thread_local.current_context = self.current_context

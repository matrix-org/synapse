# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

import logging

import twisted
import twisted.logger
from twisted.trial import unittest

from synapse.util.logcontext import LoggingContextFilter

# Set up putting Synapse's logs into Trial's.
rootLogger = logging.getLogger()

log_format = (
    "%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(request)s - %(message)s"
)


class ToTwistedHandler(logging.Handler):
    tx_log = twisted.logger.Logger()

    def emit(self, record):
        log_entry = self.format(record)
        log_level = record.levelname.lower().replace('warning', 'warn')
        self.tx_log.emit(twisted.logger.LogLevel.levelWithName(log_level), log_entry)


handler = ToTwistedHandler()
formatter = logging.Formatter(log_format)
handler.setFormatter(formatter)
handler.addFilter(LoggingContextFilter(request=""))
rootLogger.addHandler(handler)


def around(target):
    """A CLOS-style 'around' modifier, which wraps the original method of the
    given instance with another piece of code.

    @around(self)
    def method_name(orig, *args, **kwargs):
        return orig(*args, **kwargs)
    """
    def _around(code):
        name = code.__name__
        orig = getattr(target, name)

        def new(*args, **kwargs):
            return code(orig, *args, **kwargs)

        setattr(target, name, new)

    return _around


class TestCase(unittest.TestCase):
    """A subclass of twisted.trial's TestCase which looks for 'loglevel'
    attributes on both itself and its individual test methods, to override the
    root logger's logging level while that test (case|method) runs."""

    def __init__(self, methodName, *args, **kwargs):
        super(TestCase, self).__init__(methodName, *args, **kwargs)

        method = getattr(self, methodName)

        level = getattr(method, "loglevel", getattr(self, "loglevel", logging.ERROR))

        @around(self)
        def setUp(orig):
            # enable debugging of delayed calls - this means that we get a
            # traceback when a unit test exits leaving things on the reactor.
            twisted.internet.base.DelayedCall.debug = True

            old_level = logging.getLogger().level

            if old_level != level:
                @around(self)
                def tearDown(orig):
                    ret = orig()
                    logging.getLogger().setLevel(old_level)
                    return ret

            logging.getLogger().setLevel(level)
            return orig()

    def assertObjectHasAttributes(self, attrs, obj):
        """Asserts that the given object has each of the attributes given, and
        that the value of each matches according to assertEquals."""
        for (key, value) in attrs.items():
            if not hasattr(obj, key):
                raise AssertionError("Expected obj to have a '.%s'" % key)
            try:
                self.assertEquals(attrs[key], getattr(obj, key))
            except AssertionError as e:
                raise (type(e))(e.message + " for '.%s'" % key)


def DEBUG(target):
    """A decorator to set the .loglevel attribute to logging.DEBUG.
    Can apply to either a TestCase or an individual test method."""
    target.loglevel = logging.DEBUG
    return target

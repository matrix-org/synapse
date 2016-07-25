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

from twisted.trial import unittest

import logging

# logging doesn't have a "don't log anything at all EVARRRR setting,
# but since the highest value is 50, 1000000 should do ;)
NEVER = 1000000

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(
    "%(levelname)s:%(name)s:%(message)s  [%(pathname)s:%(lineno)d]"
))
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(NEVER)
logging.getLogger("synapse.storage.SQL").setLevel(NEVER)
logging.getLogger("synapse.storage.txn").setLevel(NEVER)


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

        level = getattr(method, "loglevel", getattr(self, "loglevel", NEVER))

        @around(self)
        def setUp(orig):
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

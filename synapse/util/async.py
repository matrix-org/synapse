# -*- coding: utf-8 -*-
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


from twisted.internet import defer, reactor

from .logcontext import PreserveLoggingContext


@defer.inlineCallbacks
def sleep(seconds):
    d = defer.Deferred()
    reactor.callLater(seconds, d.callback, seconds)
    with PreserveLoggingContext():
        yield d


def run_on_reactor():
    """ This will cause the rest of the function to be invoked upon the next
    iteration of the main loop
    """
    return sleep(0)


class ObservableDeferred(object):
    """Wraps a deferred object so that we can add observer deferreds. These
    observer deferreds do not affect the callback chain of the original
    deferred.

    If consumeErrors is true errors will be captured from the origin deferred.
    """

    __slots__ = ["_deferred", "_observers", "_result"]

    def __init__(self, deferred, consumeErrors=False):
        object.__setattr__(self, "_deferred", deferred)
        object.__setattr__(self, "_result", None)
        object.__setattr__(self, "_observers", [])

        def callback(r):
            self._result = (True, r)
            while self._observers:
                try:
                    self._observers.pop().callback(r)
                except:
                    pass
            return r

        def errback(f):
            self._result = (False, f)
            while self._observers:
                try:
                    self._observers.pop().errback(f)
                except:
                    pass

            if consumeErrors:
                return None
            else:
                return f

        deferred.addCallbacks(callback, errback)

    def observe(self):
        if not self._result:
            d = defer.Deferred()
            self._observers.append(d)
            return d
        else:
            success, res = self._result
            return defer.succeed(res) if success else defer.fail(res)

    def __getattr__(self, name):
        return getattr(self._deferred, name)

    def __setattr__(self, name, value):
        setattr(self._deferred, name, value)

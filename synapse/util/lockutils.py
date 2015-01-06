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


from twisted.internet import defer

import logging


logger = logging.getLogger(__name__)


class Lock(object):

    def __init__(self, deferred, key):
        self._deferred = deferred
        self.released = False
        self.key = key

    def release(self):
        self.released = True
        self._deferred.callback(None)

    def __del__(self):
        if not self.released:
            logger.critical("Lock was destructed but never released!")
            self.release()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        logger.debug("Releasing lock for key=%r", self.key)
        self.release()


class LockManager(object):
    """ Utility class that allows us to lock based on a `key` """

    def __init__(self):
        self._lock_deferreds = {}

    @defer.inlineCallbacks
    def lock(self, key):
        """ Allows us to block until it is our turn.
        Args:
            key (str)
        Returns:
            Lock
        """
        new_deferred = defer.Deferred()
        old_deferred = self._lock_deferreds.get(key)
        self._lock_deferreds[key] = new_deferred

        if old_deferred:
            logger.debug("Queueing on lock for key=%r", key)
            yield old_deferred
            logger.debug("Obtained lock for key=%r", key)
        else:
            logger.debug("Entering uncontended lock for key=%r", key)

        defer.returnValue(Lock(new_deferred, key))

# -*- coding: utf-8 -*-
# Copyright 2017 New Vector Ltd.
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

from synapse.crypto import keyring
from synapse.util.logcontext import LoggingContext
from tests import utils, unittest
from twisted.internet import defer


class KeyringTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield utils.setup_test_homeserver(handlers=None)

    @defer.inlineCallbacks
    def test_wait_for_previous_lookups(self):
        sentinel_context = LoggingContext.current_context()

        kr = keyring.Keyring(self.hs)

        def check_context(_, expected):
            self.assertEquals(
                LoggingContext.current_context().test_key, expected
            )

        lookup_1_deferred = defer.Deferred()
        lookup_2_deferred = defer.Deferred()

        with LoggingContext("one") as context_one:
            context_one.test_key = "one"

            wait_1_deferred = kr.wait_for_previous_lookups(
                ["server1"],
                {"server1": lookup_1_deferred},
            )

            # there were no previous lookups, so the deferred should be ready
            self.assertTrue(wait_1_deferred.called)
            # ... so we should have preserved the LoggingContext.
            self.assertIs(LoggingContext.current_context(), context_one)
            wait_1_deferred.addBoth(check_context, "one")

        with LoggingContext("two") as context_two:
            context_two.test_key = "two"

            # set off another wait. It should block because the first lookup
            # hasn't yet completed.
            wait_2_deferred = kr.wait_for_previous_lookups(
                ["server1"],
                {"server1": lookup_2_deferred},
            )
            self.assertFalse(wait_2_deferred.called)
            # ... so we should have reset the LoggingContext.
            self.assertIs(LoggingContext.current_context(), sentinel_context)
            wait_2_deferred.addBoth(check_context, "two")

            # let the first lookup complete (in the sentinel context)
            lookup_1_deferred.callback(None)

            # now the second wait should complete and restore our
            # loggingcontext.
            yield wait_2_deferred

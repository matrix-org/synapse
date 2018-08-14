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
import time

from mock import Mock

import signedjson.key
import signedjson.sign

from twisted.internet import defer, reactor

from synapse.api.errors import SynapseError
from synapse.crypto import keyring
from synapse.util import Clock, logcontext
from synapse.util.logcontext import LoggingContext

from tests import unittest, utils


class MockPerspectiveServer(object):
    def __init__(self):
        self.server_name = "mock_server"
        self.key = signedjson.key.generate_signing_key(0)

    def get_verify_keys(self):
        vk = signedjson.key.get_verify_key(self.key)
        return {"%s:%s" % (vk.alg, vk.version): vk}

    def get_signed_key(self, server_name, verify_key):
        key_id = "%s:%s" % (verify_key.alg, verify_key.version)
        res = {
            "server_name": server_name,
            "old_verify_keys": {},
            "valid_until_ts": time.time() * 1000 + 3600,
            "verify_keys": {
                key_id: {"key": signedjson.key.encode_verify_key_base64(verify_key)}
            },
        }
        signedjson.sign.sign_json(res, self.server_name, self.key)
        return res


class KeyringTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.mock_perspective_server = MockPerspectiveServer()
        self.http_client = Mock()
        self.hs = yield utils.setup_test_homeserver(
            self.addCleanup, handlers=None, http_client=self.http_client
        )
        keys = self.mock_perspective_server.get_verify_keys()
        self.hs.config.perspectives = {self.mock_perspective_server.server_name: keys}

    def check_context(self, _, expected):
        self.assertEquals(
            getattr(LoggingContext.current_context(), "request", None), expected
        )

    @defer.inlineCallbacks
    def test_wait_for_previous_lookups(self):
        sentinel_context = LoggingContext.current_context()

        kr = keyring.Keyring(self.hs)

        lookup_1_deferred = defer.Deferred()
        lookup_2_deferred = defer.Deferred()

        with LoggingContext("one") as context_one:
            context_one.request = "one"

            wait_1_deferred = kr.wait_for_previous_lookups(
                ["server1"], {"server1": lookup_1_deferred}
            )

            # there were no previous lookups, so the deferred should be ready
            self.assertTrue(wait_1_deferred.called)
            # ... so we should have preserved the LoggingContext.
            self.assertIs(LoggingContext.current_context(), context_one)
            wait_1_deferred.addBoth(self.check_context, "one")

        with LoggingContext("two") as context_two:
            context_two.request = "two"

            # set off another wait. It should block because the first lookup
            # hasn't yet completed.
            wait_2_deferred = kr.wait_for_previous_lookups(
                ["server1"], {"server1": lookup_2_deferred}
            )
            self.assertFalse(wait_2_deferred.called)
            # ... so we should have reset the LoggingContext.
            self.assertIs(LoggingContext.current_context(), sentinel_context)
            wait_2_deferred.addBoth(self.check_context, "two")

            # let the first lookup complete (in the sentinel context)
            lookup_1_deferred.callback(None)

            # now the second wait should complete and restore our
            # loggingcontext.
            yield wait_2_deferred

    @defer.inlineCallbacks
    def test_verify_json_objects_for_server_awaits_previous_requests(self):
        clock = Clock(reactor)
        key1 = signedjson.key.generate_signing_key(1)

        kr = keyring.Keyring(self.hs)
        json1 = {}
        signedjson.sign.sign_json(json1, "server10", key1)

        persp_resp = {
            "server_keys": [
                self.mock_perspective_server.get_signed_key(
                    "server10", signedjson.key.get_verify_key(key1)
                )
            ]
        }
        persp_deferred = defer.Deferred()

        @defer.inlineCallbacks
        def get_perspectives(**kwargs):
            self.assertEquals(LoggingContext.current_context().request, "11")
            with logcontext.PreserveLoggingContext():
                yield persp_deferred
            defer.returnValue(persp_resp)

        self.http_client.post_json.side_effect = get_perspectives

        with LoggingContext("11") as context_11:
            context_11.request = "11"

            # start off a first set of lookups
            res_deferreds = kr.verify_json_objects_for_server(
                [("server10", json1), ("server11", {})]
            )

            # the unsigned json should be rejected pretty quickly
            self.assertTrue(res_deferreds[1].called)
            try:
                yield res_deferreds[1]
                self.assertFalse("unsigned json didn't cause a failure")
            except SynapseError:
                pass

            self.assertFalse(res_deferreds[0].called)
            res_deferreds[0].addBoth(self.check_context, None)

            # wait a tick for it to send the request to the perspectives server
            # (it first tries the datastore)
            yield clock.sleep(1)  # XXX find out why this takes so long!
            self.http_client.post_json.assert_called_once()

            self.assertIs(LoggingContext.current_context(), context_11)

            context_12 = LoggingContext("12")
            context_12.request = "12"
            with logcontext.PreserveLoggingContext(context_12):
                # a second request for a server with outstanding requests
                # should block rather than start a second call
                self.http_client.post_json.reset_mock()
                self.http_client.post_json.return_value = defer.Deferred()

                res_deferreds_2 = kr.verify_json_objects_for_server(
                    [("server10", json1)]
                )
                yield clock.sleep(1)
                self.http_client.post_json.assert_not_called()
                res_deferreds_2[0].addBoth(self.check_context, None)

            # complete the first request
            with logcontext.PreserveLoggingContext():
                persp_deferred.callback(persp_resp)
            self.assertIs(LoggingContext.current_context(), context_11)

            with logcontext.PreserveLoggingContext():
                yield res_deferreds[0]
                yield res_deferreds_2[0]

    @defer.inlineCallbacks
    def test_verify_json_for_server(self):
        kr = keyring.Keyring(self.hs)

        key1 = signedjson.key.generate_signing_key(1)
        yield self.hs.datastore.store_server_verify_key(
            "server9", "", time.time() * 1000, signedjson.key.get_verify_key(key1)
        )
        json1 = {}
        signedjson.sign.sign_json(json1, "server9", key1)

        sentinel_context = LoggingContext.current_context()

        with LoggingContext("one") as context_one:
            context_one.request = "one"

            defer = kr.verify_json_for_server("server9", {})
            try:
                yield defer
                self.fail("should fail on unsigned json")
            except SynapseError:
                pass
            self.assertIs(LoggingContext.current_context(), context_one)

            defer = kr.verify_json_for_server("server9", json1)
            self.assertFalse(defer.called)
            self.assertIs(LoggingContext.current_context(), sentinel_context)
            yield defer

            self.assertIs(LoggingContext.current_context(), context_one)

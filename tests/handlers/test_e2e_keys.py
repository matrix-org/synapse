# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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

import mock
from twisted.internet import defer

import synapse.api.errors
import synapse.handlers.e2e_keys

import synapse.storage
from tests import unittest, utils


class E2eKeysHandlerTestCase(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(E2eKeysHandlerTestCase, self).__init__(*args, **kwargs)
        self.hs = None       # type: synapse.server.HomeServer
        self.handler = None  # type: synapse.handlers.e2e_keys.E2eKeysHandler

    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield utils.setup_test_homeserver(
            handlers=None,
            replication_layer=mock.Mock(),
        )
        self.handler = synapse.handlers.e2e_keys.E2eKeysHandler(self.hs)

    @defer.inlineCallbacks
    def test_query_local_devices_no_devices(self):
        """If the user has no devices, we expect an empty list.
        """
        local_user = "@boris:" + self.hs.hostname
        res = yield self.handler.query_local_devices({local_user: None})
        self.assertDictEqual(res, {local_user: {}})

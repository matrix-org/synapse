# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
# Copyright 2017 New Vector Ltd
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
from synapse.api import errors
from twisted.internet import defer

import synapse.api.errors
import synapse.handlers.e2e_room_keys

import synapse.storage
from tests import unittest, utils


class E2eRoomKeysHandlerTestCase(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(E2eRoomKeysHandlerTestCase, self).__init__(*args, **kwargs)
        self.hs = None       # type: synapse.server.HomeServer
        self.handler = None  # type: synapse.handlers.e2e_keys.E2eRoomKeysHandler

    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield utils.setup_test_homeserver(
            handlers=None,
            replication_layer=mock.Mock(),
        )
        self.handler = synapse.handlers.e2e_room_keys.E2eRoomKeysHandler(self.hs)

    @defer.inlineCallbacks
    def test_get_missing_current_version_info(self):
        """Check that we get a 404 if we ask for info about the current version
        if there is no version.
        """
        local_user = "@boris:" + self.hs.hostname
        res = None
        try:
            res = yield self.handler.get_version_info(local_user)
        except errors.SynapseError as e:
            self.assertEqual(e.code, 404)
        self.assertEqual(res, None)

    @defer.inlineCallbacks
    def test_get_missing_version_info(self):
        """Check that we get a 404 if we ask for info about a specific version
        if it doesn't exist.
        """
        local_user = "@boris:" + self.hs.hostname
        res = None
        try:
            res = yield self.handler.get_version_info(local_user, "mrflibble")
        except errors.SynapseError as e:
            self.assertEqual(e.code, 404)
        self.assertEqual(res, None)

    @defer.inlineCallbacks
    def test_create_version(self):
        """Check that we can create and then retrieve versions.
        """
        local_user = "@boris:" + self.hs.hostname
        res = yield self.handler.create_version(local_user, {
            "algorithm": "m.megolm_backup.v1",
            "auth_data": "first_version_auth_data",
        })
        self.assertEqual(res, "1")

        # check we can retrieve it as the current version
        res = yield self.handler.get_version_info(local_user)
        self.assertDictEqual(res, {
            "version": "1",
            "algorithm": "m.megolm_backup.v1",
            "auth_data": "first_version_auth_data",
        })

        # check we can retrieve it as a specific version
        res = yield self.handler.get_version_info(local_user, "1")
        self.assertDictEqual(res, {
            "version": "1",
            "algorithm": "m.megolm_backup.v1",
            "auth_data": "first_version_auth_data",
        })

        # upload a new one...
        res = yield self.handler.create_version(local_user, {
            "algorithm": "m.megolm_backup.v1",
            "auth_data": "second_version_auth_data",
        })
        self.assertEqual(res, "2")

        # check we can retrieve it as the current version
        res = yield self.handler.get_version_info(local_user)
        self.assertDictEqual(res, {
            "version": "2",
            "algorithm": "m.megolm_backup.v1",
            "auth_data": "second_version_auth_data",
        })

    @defer.inlineCallbacks
    def test_delete_version(self):
        """Check that we can create and then delete versions.
        """
        local_user = "@boris:" + self.hs.hostname
        res = yield self.handler.create_version(local_user, {
            "algorithm": "m.megolm_backup.v1",
            "auth_data": "first_version_auth_data",
        })
        self.assertEqual(res, "1")

        # check we can delete it
        yield self.handler.delete_version(local_user, "1")

        # check that it's gone
        res = None
        try:
            res = yield self.handler.get_version_info(local_user, "1")
        except errors.SynapseError as e:
            self.assertEqual(e.code, 404)
        self.assertEqual(res, None)

    @defer.inlineCallbacks
    def test_get_room_keys(self):
        yield None

    @defer.inlineCallbacks
    def test_upload_room_keys(self):
        yield None

    @defer.inlineCallbacks
    def test_delete_room_keys(self):
        yield None
